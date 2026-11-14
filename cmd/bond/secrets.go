package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/ui"
)

// keyFlags collects the ways a secret can reach BOND. They are shared by every
// command that opens or creates a container.
type keyFlags struct {
	passphrase        string
	passphraseFile    string
	passphraseEnv     string
	keyfile           string
	recoveryKey       string
	recoveryFile      string
	allowExpensiveKDF bool
	allowUnencrypted  bool
	expectWriter      string

	// newBackup holds the passphrase for new backups once it has been read, so
	// a run over several targets asks once. See backupPassphrase.
	newBackup []byte
}

func (k *keyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&k.passphrase, "passphrase", "", "passphrase on the command line (discouraged; see --passphrase-file)")
	fs.StringVar(&k.passphraseFile, "passphrase-file", "", "read the passphrase from the first line of this file")
	fs.StringVar(&k.passphraseEnv, "passphrase-env", "", "read the passphrase from this environment variable")
	fs.StringVar(&k.keyfile, "keyfile", "", "32-byte key file to unlock with")
	fs.StringVar(&k.recoveryKey, "recovery-key", "", "printed recovery key, as written on the card")
	fs.StringVar(&k.recoveryFile, "recovery-key-file", "", "read the recovery key from a file")
	fs.BoolVar(&k.allowExpensiveKDF, "allow-expensive-kdf", false, "allow Argon2 costs above the local safety policy")
	fs.BoolVar(&k.allowUnencrypted, "allow-unencrypted", false, "open an unencrypted container through the key stored inside it")
	fs.StringVar(&k.expectWriter, "expect-writer", "", "refuse a container not signed by this writer key (a bondwp1… key or a .pub file)")
}

const keyFlagHelp = `  -p, --passphrase <text>        passphrase on the command line (discouraged)
      --passphrase-file <path>   read the passphrase from a file's first line
      --passphrase-env <name>    read the passphrase from an environment variable
      --keyfile <path>           32-byte key file
      --recovery-key <text>      printed recovery key (BOND-R1-...)
      --recovery-key-file <path> read the recovery key from a file
      --allow-expensive-kdf      allow unusually costly Argon2 slots (resource risk)
      --allow-unencrypted        open an unencrypted container (encryptionMethod NONE);
                                 its contents are not protected against tampering
      --expect-writer <key>      refuse a container not signed by this writer
                                 (a bondwp1… public key, or the .pub file holding it)`

// registerShorthand adds the single-letter aliases, kept separate so the long
// forms stay the ones documented.
func (k *keyFlags) registerShorthand(fs *flag.FlagSet) {
	fs.StringVar(&k.passphrase, "p", "", "")
}

// minNewPassphrase is the shortest passphrase a new slot is made with, counted
// in characters. It applies where a passphrase is chosen and never where one is
// only used: a container opens with whatever it was written with.
//
// Argon2id makes every guess expensive and cannot make a short secret long.
// Twelve characters is where a passphrase of random words or mixed characters
// starts to outlast the hardware an attacker can rent, and well below it is
// where a backup that sits in someone else's storage for twenty years is
// decided by a dictionary.
const minNewPassphrase = 12

// checkNewPassphrase refuses a passphrase that is too short to protect anything.
func checkNewPassphrase(pass []byte) error {
	if n := utf8.RuneCount(pass); n < minNewPassphrase {
		return fmt.Errorf("a new passphrase needs at least %d characters, and this one has %d; four or five unrelated words are easy to type and hard to guess",
			minNewPassphrase, n)
	}
	return nil
}

// backupPassphrase is the passphrase new backups are written with. It is read
// once per run, however many targets the run has.
//
// Reading it per target asked an operator at a terminal for the same secret
// twice per target, and on a pipe it failed outright: the first read took the
// only line there was, so the second target found standard input empty. Each
// caller gets a copy of its own, because key specs are wiped after use.
func (k *keyFlags) backupPassphrase() ([]byte, error) {
	if k.newBackup == nil {
		pass, err := k.readPassphrase("Passphrase for the new backups", !k.passphraseGiven())
		if err != nil {
			return nil, err
		}
		if err := checkNewPassphrase(pass); err != nil {
			crypto.Wipe(pass)
			return nil, err
		}
		k.newBackup = pass
	}
	return append([]byte(nil), k.newBackup...), nil
}

// forget wipes what backupPassphrase kept.
func (k *keyFlags) forget() {
	crypto.Wipe(k.newBackup)
	k.newBackup = nil
}

// passphraseGiven reports whether a passphrase arrived without prompting.
func (k *keyFlags) passphraseGiven() bool {
	return k.passphrase != "" || k.passphraseFile != "" || k.passphraseEnv != ""
}

// readPassphrase resolves a passphrase from whichever source was named, or
// asks for one.
func (k *keyFlags) readPassphrase(prompt string, confirm bool) ([]byte, error) {
	switch {
	case k.passphrase != "":
		// Supported because automation needs it, warned about because a
		// command line is visible to every other process on the machine and
		// is written to shell history and CI logs.
		fmt.Fprintln(os.Stderr, "warning: a passphrase on the command line is visible to other processes and is recorded in shell history; --passphrase-file is safer")
		return []byte(k.passphrase), nil

	case k.passphraseFile != "":
		data, err := os.ReadFile(k.passphraseFile)
		if err != nil {
			return nil, fmt.Errorf("reading the passphrase file: %w", err)
		}
		defer crypto.Wipe(data)
		line, _, _ := strings.Cut(string(data), "\n")
		line = strings.TrimRight(line, "\r")
		if line == "" {
			return nil, fmt.Errorf("%s is empty", k.passphraseFile)
		}
		return []byte(line), nil

	case k.passphraseEnv != "":
		value, ok := os.LookupEnv(k.passphraseEnv)
		if !ok {
			return nil, fmt.Errorf("the environment variable %s is not set", k.passphraseEnv)
		}
		if value == "" {
			return nil, fmt.Errorf("the environment variable %s is empty", k.passphraseEnv)
		}
		return []byte(value), nil

	default:
		return ui.ReadPassphrase(prompt, confirm)
	}
}

func (k *keyFlags) readKeyfile() ([]byte, error) {
	data, err := os.ReadFile(k.keyfile)
	if err != nil {
		return nil, fmt.Errorf("reading the key file: %w", err)
	}
	if len(data) != crypto.KeyLen {
		crypto.Wipe(data)
		return nil, fmt.Errorf("%s is %d bytes; a key file is exactly %d", k.keyfile, len(data), crypto.KeyLen)
	}
	return data, nil
}

// recoveryGiven reports whether a recovery key was named.
func (k *keyFlags) recoveryGiven() bool { return k.recoveryKey != "" || k.recoveryFile != "" }

// readRecovery turns a printed recovery key back into the recipient it stands
// for. The file form accepts a whole recovery card: the key is found in it, so
// the operator does not have to extract the line by hand.
func (k *keyFlags) readRecovery() (*crypto.RecipientPrivate, error) {
	text := k.recoveryKey
	if k.recoveryFile != "" {
		data, err := os.ReadFile(k.recoveryFile)
		if err != nil {
			return nil, fmt.Errorf("reading the recovery key: %w", err)
		}
		defer crypto.Wipe(data)
		found, err := findRecoveryKey(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.recoveryFile, err)
		}
		text = found
	}

	seed, err := crypto.DecodeRecoveryKey(text)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(seed)
	return crypto.RecipientFromSeed(seed)
}

// findRecoveryKey picks the key out of a recovery card, which also holds
// instructions, a date and the public key.
func findRecoveryKey(text string) (string, error) {
	for line := range strings.SplitSeq(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), crypto.CardPrefix) {
			continue
		}
		// The card repeats the key inside a restore command; the bare line is
		// the one to take.
		if strings.Contains(trimmed, " ") {
			continue
		}
		return trimmed, nil
	}
	return "", fmt.Errorf("no line starting with %s was found", crypto.CardPrefix)
}

// unlockersFor offers exactly the kinds of secret this container can use, so
// an operator is never asked for a passphrase by a container that has no
// passphrase slot.
func (k *keyFlags) unlockersFor(slots []*crypto.Slot) ([]crypto.Unlocker, error) {
	kinds := map[crypto.SlotType]bool{}
	for _, s := range slots {
		kinds[s.Type] = true
	}

	var out []crypto.Unlocker
	success := false
	defer func() {
		if !success {
			wipeUnlockers(out)
		}
	}()
	// The plaintext slot is never offered on the container's say-so. The slot
	// table is read before anything authenticates it, so whoever stores the
	// file decides whether it lists one – and a container that opens through it
	// proves nothing about who wrote it. Offering it unasked let a substituted
	// container restore under any passphrase the operator typed, or under none.
	// It takes the operator saying that an unencrypted container is expected,
	// and it is never mixed with a real key.
	if k.allowUnencrypted {
		if k.keyfile != "" || k.recoveryGiven() || k.passphraseGiven() {
			return nil, badUsage("--allow-unencrypted opens a container through the key stored inside it and cannot be combined with a key; give one or the other")
		}
		if !kinds[crypto.SlotPlaintext] {
			return nil, fmt.Errorf("--allow-unencrypted was given, but this container is not unencrypted; it opens with %s", listKinds(slots))
		}
		out = append(out, crypto.PlaintextSecret{})
		success = true
		return out, nil
	}
	if k.keyfile != "" {
		if !kinds[crypto.SlotKeyfile] {
			return nil, wrongKind("a key file", slots)
		}
		data, err := k.readKeyfile()
		if err != nil {
			return nil, err
		}
		out = append(out, crypto.KeyfileSecret(data))
	}
	if k.recoveryGiven() {
		if !kinds[crypto.SlotRecipient] {
			return nil, wrongKind("a recovery key", slots)
		}
		priv, err := k.readRecovery()
		if err != nil {
			return nil, err
		}
		out = append(out, crypto.RecipientSecret{Private: priv})
	}
	if k.passphraseGiven() && !kinds[crypto.SlotPassphrase] {
		return nil, wrongKind("a passphrase", slots)
	}
	if kinds[crypto.SlotPassphrase] && (k.passphraseGiven() || len(out) == 0) {
		pass, err := k.readPassphrase("Passphrase", false)
		if err != nil {
			return nil, err
		}
		out = append(out, crypto.Passphrase(pass))
	}

	if len(out) == 0 {
		if kinds[crypto.SlotPlaintext] {
			return nil, fmt.Errorf("this container is unencrypted: its key is stored inside it, so anyone holding the file can read it " +
				"and can replace its contents. If that is what this backup was written as (encryptionMethod NONE), open it with --allow-unencrypted")
		}
		return nil, fmt.Errorf("no key was given for a container that opens with %s", listKinds(slots))
	}
	success = true
	return out, nil
}

func (k *keyFlags) unlockOptions() (container.UnlockOptions, error) {
	policy := crypto.DefaultKDFPolicy
	policy.AllowExpensive = k.allowExpensiveKDF
	opts := container.UnlockOptions{KDFPolicy: policy}
	if k.expectWriter != "" {
		pub, err := loadWriterPublic(k.expectWriter)
		if err != nil {
			return opts, badUsage("--expect-writer: %v", err)
		}
		opts.ExpectWriter = pub
	}
	return opts, nil
}

func wipeUnlockers(unlockers []crypto.Unlocker) {
	for _, unlocker := range unlockers {
		switch secret := unlocker.(type) {
		case crypto.Passphrase:
			crypto.Wipe(secret)
		case crypto.KeyfileSecret:
			crypto.Wipe(secret)
		case crypto.RecipientSecret:
			if secret.Private != nil {
				secret.Private.Wipe()
			}
		}
	}
}

// wrongKind explains that the secret offered is not one this container takes,
// and names what it does take. Being told "no key was given" while holding the
// key one just typed is the kind of message that ends a recovery early.
func wrongKind(given string, slots []*crypto.Slot) error {
	return fmt.Errorf("%s was given, but this container has no slot of that kind; it opens with %s",
		given, listKinds(slots))
}

func listKinds(slots []*crypto.Slot) string {
	var (
		seen  = map[crypto.SlotType]bool{}
		names []string
	)
	for _, s := range slots {
		if !seen[s.Type] {
			seen[s.Type] = true
			names = append(names, s.Type.String())
		}
	}
	switch len(names) {
	case 0:
		return "no key at all, which means it cannot be opened"
	case 1:
		return names[0]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
	}
}

// createSpecs turns the control file's settings into the key slots a new
// container gets.
func (k *keyFlags) createSpecs(settings config.Resolved, kdf crypto.KDFParams) ([]container.KeySpec, bool, error) {
	var (
		specs       []container.KeySpec
		unencrypted bool
	)
	success := false
	defer func() {
		if !success {
			wipeKeySpecs(specs)
		}
	}()

	switch settings.EncryptionMethod {
	case config.EncryptionNone:
		unencrypted = true
		specs = append(specs, container.KeySpec{Secret: crypto.PlaintextSecret{}, Label: "unencrypted"})

	case config.EncryptionPassphrase:
		pass, err := k.backupPassphrase()
		if err != nil {
			return nil, false, err
		}
		specs = append(specs, container.KeySpec{Secret: crypto.Passphrase(pass), KDF: kdf, Label: "passphrase"})

	case config.EncryptionKeyfile:
		if k.keyfile == "" {
			return nil, false, badUsage("encryptionMethod is KEYFILE; name the key file with --keyfile")
		}
		data, err := k.readKeyfile()
		if err != nil {
			return nil, false, err
		}
		specs = append(specs, container.KeySpec{Secret: crypto.KeyfileSecret(data), Label: "key file"})

	case config.EncryptionRecipient:
		// Nothing to add here: the recipients come from keySlots below, and
		// this method exists to say that no secret is needed at backup time.
		if !hasRecipient(settings.KeySlots) {
			return nil, false, fmt.Errorf("encryptionMethod is RECIPIENT; add at least one recipient to keySlots")
		}

	default:
		return nil, false, fmt.Errorf("unknown encryptionMethod %q", settings.EncryptionMethod)
	}

	// Extra slots from the control file, so one backup can be opened by a
	// passphrase today and by a key kept somewhere else entirely.
	for _, slot := range settings.KeySlots {
		switch slot.Type {
		case config.SlotKeyfile:
			data, err := os.ReadFile(slot.Path)
			if err != nil {
				return nil, false, fmt.Errorf("reading the key file for slot %q: %w", slot.Label, err)
			}
			if len(data) != crypto.KeyLen {
				crypto.Wipe(data)
				return nil, false, fmt.Errorf("%s is %d bytes; a key file is exactly %d", slot.Path, len(data), crypto.KeyLen)
			}
			specs = append(specs, container.KeySpec{
				Secret: crypto.KeyfileSecret(data),
				Label:  labelOr(slot.Label, "key file"),
			})

		case config.SlotRecipient:
			pub, err := decodeRecipientPublic(slot.PublicKey)
			if err != nil {
				return nil, false, fmt.Errorf("the recipient %q: %w", slot.Label, err)
			}
			specs = append(specs, container.KeySpec{
				Recipient: pub,
				Label:     labelOr(slot.Label, "recovery key"),
			})

		case config.SlotPassphrase:
			return nil, false, fmt.Errorf("a second passphrase slot cannot be created unattended; add it afterwards with: bond keys add <container> --new-passphrase")
		}
	}

	if len(specs) == 0 {
		return nil, false, fmt.Errorf("no key slots would be created; the container would be unopenable")
	}
	success = true
	return specs, unencrypted, nil
}

func hasRecipient(slots []config.KeySlot) bool {
	for _, s := range slots {
		if s.Type == config.SlotRecipient {
			return true
		}
	}
	return false
}

func labelOr(label, fallback string) string {
	if label == "" {
		return fallback
	}
	return label
}
