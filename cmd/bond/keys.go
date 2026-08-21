package main

import (
	"context"
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

Every slot wraps the same master key, so all of these rewrite 64 KiB of key
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

	fmt.Printf("%s\n", operands[0])
	fmt.Printf("%s\n", ui.Items(len(r.Slots()), "key slot", "key slots"))
	for i, s := range r.Slots() {
		fmt.Printf("\n  [%d] %s\n", i, s.Type)
		fmt.Printf("      id       %x\n", s.UUID[:8])
		if s.Label != "" {
			fmt.Printf("      label    %s\n", s.Label)
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
			"Use: bond rekey %s --to <new file>", path)
	}

	// Removing the slot you are holding is a way to lock yourself out of a
	// backup you can currently read, so it takes an explicit yes.
	remaining := append(append([]*crypto.Slot(nil), slots[:index]...), slots[index+1:]...)
	fmt.Printf("removing      [%d] %s", index, slots[index].Type)
	if slots[index].Label != "" {
		fmt.Printf(" (%s)", slots[index].Label)
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

	fmt.Printf("rotated       the passphrase slot of %s\n", path)
	fmt.Printf("payload       untouched – the master key is unchanged, so nothing was re-encrypted\n")
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
			parts[i] += " (" + s.Label + ")"
		}
	}
	return strings.Join(parts, ", ")
}

func runRekey(args []string) error {
	fs := newFlagSet("rekey")
	var (
		out     string
		workDir string
		keys    keyFlags
	)
	fs.StringVar(&out, "out", "", "")
	fs.StringVar(&workDir, "work-dir", "", "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond rekey <container.bond> --out <new.bond>

Writes a copy under a brand new master key. Every shard is sealed again, so
this rewrites the whole container – hours for a large backup.

This is almost never the operation you want. A passphrase that may have been
seen is answered by "bond keys rotate-passphrase", which rewrites 64 KiB.
Rekeying is for when the master key itself may be exposed, which in practice
means a restore happened on a machine you no longer trust.

The new container is asked for a new passphrase.

options:
      --out <file>      where to write the re-encrypted copy
      --work-dir <dir>  where to assemble it (default: beside --out)
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
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("%s already exists", out)
	}

	r, err := openContainer(operands[0], &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	pass, err := ui.ReadPassphrase("Passphrase for the re-encrypted container", true)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	specs := []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: crypto.DefaultKDF, Label: "passphrase"}}

	if workDir == "" {
		workDir = filepath.Dir(out)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return err
	}

	fmt.Printf("container     %s\n", operands[0])
	fmt.Printf("payload       %s to re-encrypt\n", ui.Bytes(int64(r.Superblock().PayloadBytes())))

	result, err := backup.Rekey(context.Background(), r, out, specs, false, workDir, 0)
	if err != nil {
		return err
	}

	fmt.Printf("written       %s (%s) in %s\n", result.Path, ui.Bytes(result.Size), result.Elapsed.Round(time.Millisecond))
	fmt.Printf("\nThe old container still opens with its old keys. Delete it only once the\n")
	fmt.Printf("new one has been verified and restored from at least once.\n")
	return nil
}
