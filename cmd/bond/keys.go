package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/backup"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/ui"
)

func runKeys(args []string) error {
	if len(args) == 0 {
		keysUsage()
		return badUsage("keys needs a subcommand: list, add, remove or rotate-passphrase")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runKeysList(rest)
	case "add":
		return runKeysAdd(rest)
	case "remove":
		return runKeysRemove(rest)
	case "rotate-passphrase":
		return runKeysRotate(rest)
	case "-h", "--help", "help":
		keysUsage()
		return nil
	default:
		keysUsage()
		return badUsage("unknown keys subcommand %q", sub)
	}
}

func keysUsage() {
	fmt.Fprintf(os.Stderr, `usage: bond keys list              <container.bond>
       bond keys add               <container.bond> [what to add]
       bond keys remove            <container.bond> --slot <label|index|uuid>
       bond keys rotate-passphrase <container.bond>

Every slot wraps the same master key, so all of these rewrite 128 KiB of key
slots and leave the payload untouched – the same work on a one-gigabyte
container as on a one-terabyte one. To replace the master key itself, which
does rewrite everything, use "bond rekey".

what to add:
      --new-passphrase        ask for another passphrase
      --new-keyfile <path>    a key file made by "bond keygen --keyfile"
      --new-recipient <key>   a public key from "bond keygen --recovery-card"
      --label <text>          a note shown by "bond keys list"

opening the container (any existing key):
%s
`, keyFlagHelp)
}

func runKeysList(args []string) error {
	fs := newFlagSet("keys list")
	var keys keyFlags
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = keysUsage

	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("keys list needs exactly one container")
	}

	r, err := container.Open(operands[0])
	if err != nil {
		return err
	}
	defer r.Close()

	// Nothing is unlocked here, so what follows is the slot table as stored and
	// not as authenticated. It says so, because "bond keys list" is what an
	// operator looks at to decide which key to fetch from the safe.
	fmt.Printf("%s\n", operands[0])
	fmt.Printf("%s, as stored – not authenticated without a key\n", ui.Items(len(r.Slots()), "key slot", "key slots"))
	for i, s := range r.Slots() {
		fmt.Printf("\n  [%d] %s\n", i, s.Type)
		fmt.Printf("      id       %x\n", s.UUID[:8])
		if s.Label != "" {
			fmt.Printf("      label    %s\n", s.DisplayLabel())
		}
		if s.Type == crypto.SlotPassphrase {
			fmt.Printf("      argon2id %s memory, %d passes, %d lanes\n",
				ui.Bytes(int64(s.KDF.MemoryKiB)*1024), s.KDF.Iterations, s.KDF.Parallelism)
		}
		if s.Type == crypto.SlotRecipient {
			fmt.Printf("      hybrid   X25519 + ML-KEM-1024\n")
		}
	}
	return nil
}

func runKeysAdd(args []string) error {
	fs := newFlagSet("keys add")
	var (
		newPassphrase bool
		newKeyfile    string
		newRecipient  string
		label         string
		keys          keyFlags
	)
	fs.BoolVar(&newPassphrase, "new-passphrase", false, "")
	fs.StringVar(&newKeyfile, "new-keyfile", "", "")
	fs.StringVar(&newRecipient, "new-recipient", "", "")
	fs.StringVar(&label, "label", "", "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = keysUsage

	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("keys add needs exactly one container")
	}
	chosen := 0
	for _, on := range []bool{newPassphrase, newKeyfile != "", newRecipient != ""} {
		if on {
			chosen++
		}
	}
	if chosen != 1 {
		return badUsage("name exactly one thing to add: --new-passphrase, --new-keyfile or --new-recipient")
	}

	path := operands[0]
	r, err := openContainer(path, &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	slot, err := buildSlot(r, newPassphrase, newKeyfile, newRecipient, label)
	if err != nil {
		return err
	}

	before, err := container.PayloadDigest(r.Paths())
	if err != nil {
		return err
	}
	updated := append(append([]*crypto.Slot(nil), r.Slots()...), slot)
	if err := container.UpdateSlots(r.Paths()[0], r.Keys(), updated); err != nil {
		return err
	}
	if err := confirmPayloadUntouched(r.Paths(), before); err != nil {
		return err
	}
	if err := refreshChecksum(r.Paths()[0]); err != nil {
		return err
	}

	fmt.Printf("added         %s slot to %s\n", slot.Type, path)
	fmt.Printf("key slots     %d\n", len(updated))
	fmt.Printf("payload       untouched – %s of it was not read or rewritten\n",
		ui.Bytes(int64(r.Superblock().PayloadBytes())))
	return nil
}

func buildSlot(r *container.Reader, passphrase bool, keyfile, recipient, label string) (*crypto.Slot, error) {
	sb := r.Superblock()
	fmk := r.Keys().FMK()

	switch {
	case passphrase:
		pass, err := ui.ReadPassphrase("New passphrase", true)
		if err != nil {
			return nil, err
		}
		if err := checkNewPassphrase(pass); err != nil {
			crypto.Wipe(pass)
			return nil, err
		}
		if label == "" {
			label = "passphrase"
		}
		defer crypto.Wipe(pass)
		return crypto.NewSlot(sb.Cipher, sb.ContainerUUID, fmk, crypto.Passphrase(pass), crypto.DefaultKDF, label)

	case keyfile != "":
		data, err := os.ReadFile(keyfile)
		if err != nil {
			return nil, err
		}
		if len(data) != crypto.KeyLen {
			return nil, fmt.Errorf("%s is %d bytes; a key file is exactly %d", keyfile, len(data), crypto.KeyLen)
		}
		defer crypto.Wipe(data)
		if label == "" {
			label = filepath.Base(keyfile)
		}
		return crypto.NewSlot(sb.Cipher, sb.ContainerUUID, fmk, crypto.KeyfileSecret(data), crypto.KDFParams{}, label)

	default:
		pub, err := decodeRecipientPublic(recipient)
		if err != nil {
			return nil, err
		}
		if label == "" {
			label = "recovery key"
		}
		return crypto.NewRecipientSlot(sb.Cipher, sb.ContainerUUID, fmk, pub, label)
	}
}

func runKeysRemove(args []string) error {
	fs := newFlagSet("keys remove")
	var (
		which string
		yes   bool
		keys  keyFlags
	)
	fs.StringVar(&which, "slot", "", "")
	fs.BoolVar(&yes, "yes", false, "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = keysUsage

	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("keys remove needs exactly one container")
	}
	if which == "" {
		return badUsage("name the slot to remove with --slot (a label, an index or the start of its id)")
	}

	path := operands[0]
	r, err := openContainer(path, &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	slots := r.Slots()
	index, err := findSlot(slots, which)
	if err != nil {
		return err
	}
	if len(slots) == 1 {
		return fmt.Errorf("this is the only key slot; removing it would leave the container permanently unopenable")
	}

	// Removing the plaintext slot looks like "encrypt this backup now" and is
	// not: every byte was written with a key stored in the file, and anyone who
	// took a copy before today still holds it. The header would also keep
	// advertising NONE, because a key change rewrites the slot table and never
	// the header. Rekey is the operation that actually changes who can read it.
	if slots[index].Type == crypto.SlotPlaintext {
		return fmt.Errorf("this is the plaintext slot of an unencrypted container, and removing it does not make the container encrypted: "+
			"the master key was stored in it when it was written, so anyone who already has a copy can still open it. "+
			"Use: bond rekey %s --allow-unencrypted --out <new file>", path)
	}

	// Removing the slot you are holding is a way to lock yourself out of a
	// backup you can currently read, so it takes an explicit yes.
	remaining := append(append([]*crypto.Slot(nil), slots[:index]...), slots[index+1:]...)
	fmt.Printf("removing      [%d] %s", index, slots[index].Type)
	if slots[index].Label != "" {
		fmt.Printf(" (%s)", slots[index].DisplayLabel())
	}
	fmt.Printf("\nleaving       %s\n", describeRemaining(remaining))
	if !yes && !ui.Confirm("Remove it?") {
		return fmt.Errorf("cancelled; pass --yes to remove a key slot without being asked")
	}

	before, err := container.PayloadDigest(r.Paths())
	if err != nil {
		return err
	}
	if err := container.UpdateSlots(r.Paths()[0], r.Keys(), remaining); err != nil {
		return err
	}
	if err := confirmPayloadUntouched(r.Paths(), before); err != nil {
		return err
	}
	if err := refreshChecksum(r.Paths()[0]); err != nil {
		return err
	}

	fmt.Printf("removed       key slots now %d\n", len(remaining))
	return nil
}

func runKeysRotate(args []string) error {
	fs := newFlagSet("keys rotate-passphrase")
	var keys keyFlags
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = keysUsage

	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("keys rotate-passphrase needs exactly one container")
	}
	path := operands[0]

	r, err := openContainer(path, &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	slots := r.Slots()
	index := -1
	for i, s := range slots {
		if s.Type == crypto.SlotPassphrase {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("this container has no passphrase slot; add one with: bond keys add %s --new-passphrase", path)
	}

	pass, err := ui.ReadPassphrase("New passphrase", true)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	if err := checkNewPassphrase(pass); err != nil {
		return err
	}
	sb := r.Superblock()
	replacement, err := crypto.NewSlot(sb.Cipher, sb.ContainerUUID, r.Keys().FMK(),
		crypto.Passphrase(pass), crypto.DefaultKDF, slots[index].Label)
	if err != nil {
		return err
	}

	updated := append([]*crypto.Slot(nil), slots...)
	updated[index] = replacement

	before, err := container.PayloadDigest(r.Paths())
	if err != nil {
		return err
	}
	if err := container.UpdateSlots(r.Paths()[0], r.Keys(), updated); err != nil {
		return err
	}
	if err := confirmPayloadUntouched(r.Paths(), before); err != nil {
		return err
	}
	if err := refreshChecksum(r.Paths()[0]); err != nil {
		return err
	}

	fmt.Printf("rotated       the passphrase slot of %s\n", path)
	fmt.Printf("payload       untouched – the master key is unchanged, so nothing was re-encrypted\n")
	return nil
}

// refreshChecksum brings the first volume's checksum file up to date after a
// key change rewrote its key-slot tables. The key change itself has succeeded
// by the time this runs, so a failure here says exactly that.
func refreshChecksum(first string) error {
	sidecar, err := backup.RefreshSidecar(first)
	if err != nil {
		return fmt.Errorf("the key slots were changed, but the checksum file next to %s could not be rewritten; "+
			"\"bond verify --quick\" will report a mismatch until it is: %w", filepath.Base(first), err)
	}
	if sidecar != "" {
		fmt.Printf("checksum      %s rewritten\n", filepath.Base(sidecar))
	}
	return nil
}

// confirmPayloadUntouched proves the claim rather than making it. A key
// operation that quietly rewrote payload would be a bug worth catching in the
// field, not only in a test.
func confirmPayloadUntouched(paths []string, before []byte) error {
	after, err := container.PayloadDigest(paths)
	if err != nil {
		return err
	}
	if string(before) != string(after) {
		return fmt.Errorf("the payload changed during a key operation; this is a bug – the container may be damaged")
	}
	return nil
}

func findSlot(slots []*crypto.Slot, which string) (int, error) {
	// By index.
	if n, err := parseIndex(which); err == nil {
		if n < 0 || n >= len(slots) {
			return 0, fmt.Errorf("there is no slot %d; this container has %d", n, len(slots))
		}
		return n, nil
	}

	var matches []int
	for i, s := range slots {
		id := fmt.Sprintf("%x", s.UUID)
		if strings.EqualFold(s.Label, which) || strings.HasPrefix(id, strings.ToLower(which)) {
			matches = append(matches, i)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("no key slot matches %q; run: bond keys list", which)
	case 1:
		return matches[0], nil
	default:
		return 0, fmt.Errorf("%q matches %d slots; name one by index instead", which, len(matches))
	}
}

func parseIndex(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func describeRemaining(slots []*crypto.Slot) string {
	parts := make([]string, len(slots))
	for i, s := range slots {
		parts[i] = s.Type.String()
		if s.Label != "" {
			parts[i] += " (" + s.DisplayLabel() + ")"
		}
	}
	return strings.Join(parts, ", ")
}

func runRekey(args []string) error {
	fs := newFlagSet("rekey")
	var (
		out            string
		workDir        string
		newPassphrase  bool
		newKeyfile     string
		newRecipients  stringList
		maxVolumeBytes int64
		signingKey     string
		keys           keyFlags
	)
	fs.StringVar(&signingKey, "signing-key", "", "")
	fs.StringVar(&out, "out", "", "")
	fs.StringVar(&workDir, "work-dir", "", "")
	fs.BoolVar(&newPassphrase, "new-passphrase", false, "")
	fs.StringVar(&newKeyfile, "new-keyfile", "", "")
	fs.Var(&newRecipients, "new-recipient", "")
	fs.Int64Var(&maxVolumeBytes, "max-volume-bytes", -1, "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond rekey <container.bond> --out <new.bond>

Writes a copy under a brand new master key. Every shard is sealed again, so
this rewrites the whole container – hours for a large backup.

This is almost never the operation you want. A passphrase that may have been
seen is answered by "bond keys rotate-passphrase", which rewrites 128 KiB.
Rekeying is for when the master key itself may be exposed, which in practice
means a restore happened on a machine you no longer trust.

The new container shares no key with the old one, so its keys are named here.
With none of the three given, a new passphrase is asked for.

options:
      --out <file>             where to write the re-encrypted copy
      --work-dir <dir>         where to assemble it (default: beside --out)
      --new-passphrase         ask for a passphrase for the new container
      --new-keyfile <path>     a key file made by "bond keygen --keyfile"
      --new-recipient <key>    a public key from "bond keygen --recovery-card";
                               repeat for several
      --max-volume-bytes <n>   split the copy into volumes of this size; 0 writes
                               one file (default: no volume larger than the
                               largest of the container being read)
      --signing-key <path>     sign the copy with this writer key. A signature
                               cannot be carried over: the copy is a new container

opening the container being read (any existing key):
%s
`, keyFlagHelp)
	}

	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("rekey needs exactly one container")
	}
	if out == "" {
		return badUsage("name the destination with --out")
	}
	for _, taken := range []string{out, out + container.VolumeSuffix(0)} {
		if _, err := os.Stat(taken); err == nil {
			return fmt.Errorf("%s already exists", taken)
		}
	}

	r, err := openContainer(operands[0], &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	// A rekey used to answer every container with one passphrase slot and one
	// file: a recipient-only backup came out with a secret it never had, and a
	// set split for an object store came out as a single file that store would
	// refuse. What the copy opens with is now said, and its shape follows the
	// original unless something else is asked for.
	var specs []container.KeySpec
	defer func() { wipeKeySpecs(specs) }()
	if newKeyfile != "" {
		data, err := os.ReadFile(newKeyfile)
		if err != nil {
			return fmt.Errorf("reading the new key file: %w", err)
		}
		if len(data) != crypto.KeyLen {
			crypto.Wipe(data)
			return fmt.Errorf("%s is %d bytes; a key file is exactly %d", newKeyfile, len(data), crypto.KeyLen)
		}
		specs = append(specs, container.KeySpec{Secret: crypto.KeyfileSecret(data), Label: filepath.Base(newKeyfile)})
	}
	for _, key := range newRecipients {
		pub, err := decodeRecipientPublic(key)
		if err != nil {
			return err
		}
		specs = append(specs, container.KeySpec{Recipient: pub, Label: "recovery key"})
	}
	if newPassphrase || len(specs) == 0 {
		pass, err := ui.ReadPassphrase("Passphrase for the re-encrypted container", true)
		if err != nil {
			return err
		}
		if err := checkNewPassphrase(pass); err != nil {
			crypto.Wipe(pass)
			return err
		}
		specs = append(specs, container.KeySpec{Secret: crypto.Passphrase(pass), KDF: crypto.DefaultKDF, Label: "passphrase"})
	}

	if maxVolumeBytes < 0 {
		maxVolumeBytes = 0
		if paths := r.Paths(); len(paths) > 1 {
			for _, p := range paths {
				maxVolumeBytes = max(maxVolumeBytes, fileSize(p))
			}
		}
	}

	if workDir == "" {
		workDir = filepath.Dir(out)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}

	fmt.Printf("container     %s\n", operands[0])
	fmt.Printf("payload       %s to re-encrypt\n", ui.Bytes(int64(r.Superblock().PayloadBytes())))

	var signer *crypto.WriterPrivate
	if signingKey != "" {
		if signer, err = loadWriterKey(signingKey); err != nil {
			return err
		}
		defer signer.Wipe()
	} else if r.Signer() != nil {
		fmt.Fprintf(os.Stderr, "warning: the container being read is signed by writer %s, and the copy will not be; "+
			"give --signing-key to sign it\n", shortID(r.Signer()))
	}

	result, err := backup.Rekey(rootCtx, r, out, specs, false, workDir, maxVolumeBytes, signer)
	if err != nil {
		return err
	}

	fmt.Printf("written       %s (%s) in %s\n", result.Path, ui.Bytes(result.Size), result.Elapsed.Round(time.Millisecond))
	if result.Volumes > 1 {
		fmt.Printf("volumes       %s\n", ui.Items(result.Volumes, "file", "files"))
	}
	if n := r.RecoveredShards(); n > 0 {
		fmt.Printf("damaged       %s of the old container were rebuilt from its recovery data while reading\n", ui.Items(n, "shard", "shards"))
	}
	// The copy gets checksum files when the original had them, one per volume.
	if algorithm := backup.SidecarAlgorithm(r.Paths()[0]); algorithm != "" {
		for _, p := range result.Paths {
			sidecar, err := backup.WriteSidecar(p, algorithm)
			if err != nil {
				return fmt.Errorf("writing the checksum file: %w", err)
			}
			fmt.Printf("checksum      %s\n", filepath.Base(sidecar))
		}
	}
	fmt.Printf("\nThe old container still opens with its old keys. Delete it only once the\n")
	fmt.Printf("new one has been verified and restored from at least once.\n")
	return nil
}
