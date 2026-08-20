package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/ui"
)

func runKeygen(args []string) error {
	fs := newFlagSet("keygen")
	var (
		keyfile   string
		card      string
		recipient string
		label     string
	)
	fs.StringVar(&keyfile, "keyfile", "", "")
	fs.StringVar(&card, "recovery-card", "", "")
	fs.StringVar(&recipient, "recipient", "", "")
	fs.StringVar(&label, "label", "", "")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: bond keygen --keyfile <path>
       bond keygen --recovery-card <path>
       bond keygen --recipient <path>

Creates key material. Nothing is overwritten: if the file exists, keygen stops.

  --keyfile <path>        32 random bytes to keep on a device you plug in.
                          Whoever holds this file can open the backups it unlocks.

  --recovery-card <path>  A printable recovery key, and the public key that
                          goes in the control file. The card is the only thing
                          that can open the backup, and it never has to be on
                          the machine making it – print it, put it in a safe.

  --recipient <path>      The same key pair, written for a script rather than
                          for a person.

  --label <text>          A note stored beside the slot, shown by "bond keys list".
`)
	}
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	switch {
	case keyfile != "":
		return writeKeyfile(keyfile)
	case card != "":
		return writeRecoveryCard(card, label, true)
	case recipient != "":
		return writeRecoveryCard(recipient, label, false)
	default:
		fs.Usage()
		return badUsage("name what to create: --keyfile, --recovery-card or --recipient")
	}
}

func writeKeyfile(path string) error {
	key, err := crypto.RandomBytes(crypto.KeyLen)
	if err != nil {
		return err
	}
	if err := writeSecret(path, key, 0o600); err != nil {
		return err
	}
	fmt.Printf("key file      %s (%d bytes)\n", path, crypto.KeyLen)
	fmt.Printf("\nThis file is the key. Anyone who has it can open every backup it unlocks,\n")
	fmt.Printf("and losing it loses those backups. Keep it off the machine being backed up.\n")
	fmt.Printf("\nTo use it, set encryptionMethod to KEYFILE, or add it to keySlots:\n")
	fmt.Printf("  { \"type\": \"keyfile\", \"path\": %q }\n", filepath.ToSlash(path))
	return nil
}

func writeRecoveryCard(path, label string, printable bool) error {
	seed, err := crypto.NewRecipientSeed()
	if err != nil {
		return err
	}
	defer crypto.Wipe(seed)

	priv, err := crypto.RecipientFromSeed(seed)
	if err != nil {
		return err
	}
	defer priv.Wipe()

	key, err := crypto.EncodeRecoveryKey(seed)
	if err != nil {
		return err
	}
	public := encodeRecipientPublic(priv.Public().Bytes())

	body := key + "\n"
	if printable {
		body = recoveryCardText(key, public, label)
	}
	if err := writeSecret(path, []byte(body), 0o600); err != nil {
		return err
	}

	// An ML-KEM-1024 public key is a couple of kilobytes, which is no use on a
	// terminal. It goes in a file ready to paste into the control file.
	snippet := fmt.Sprintf("{ \"type\": \"recipient\", \"publicKey\": %q", public)
	if label != "" {
		snippet += fmt.Sprintf(", \"label\": %q", label)
	}
	snippet += " }\n"

	pubPath := path + ".pub"
	if err := writeSecret(pubPath, []byte(snippet), 0o644); err != nil {
		return err
	}

	if printable {
		fmt.Printf("recovery card %s\n\n", path)
		fmt.Print(body)
		fmt.Println()
	} else {
		fmt.Printf("recovery key  %s\n", path)
	}
	fmt.Printf("public key    %s\n", pubPath)
	fmt.Printf("              bondpk1%s… (%s)\n", public[len(recipientPublicPrefix):len(recipientPublicPrefix)+16], ui.Bytes(int64(len(public))))
	fmt.Printf("\nThe public key is not a secret: it can lock a backup and never open one,\n")
	fmt.Printf("which is why a backup job can run with nothing else on the machine.\n")
	fmt.Printf("Paste the line from %s into the control file's keySlots.\n", filepath.Base(pubPath))
	if printable {
		fmt.Printf("\nPrint the card, put it somewhere a fire will not reach it, and delete\n")
		fmt.Printf("%s from this machine. It is the only thing that can open these backups.\n", path)
	}
	return nil
}

// recoveryCardText is what gets printed and put in a safe. It says what the
// thing is, because the person reading it may not be the person who made it
// and may be reading it in a bad week.
func recoveryCardText(key, public, label string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BOND RECOVERY KEY\n")
	fmt.Fprintf(&b, "=================\n\n")
	if label != "" {
		fmt.Fprintf(&b, "For:     %s\n", label)
	}
	fmt.Fprintf(&b, "Created: %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "  %s\n\n", key)
	fmt.Fprintf(&b, "This key opens the backups it was made for, and nothing else can.\n")
	fmt.Fprintf(&b, "Anyone holding it can read them. Losing it loses them.\n\n")
	fmt.Fprintf(&b, "To restore:\n")
	fmt.Fprintf(&b, "  bond restore <backup.bond> --to <directory> --recovery-key \"%s\"\n\n", key)
	fmt.Fprintf(&b, "Case and hyphens do not matter when typing it back, and the letters\n")
	fmt.Fprintf(&b, "I, L, O and U never appear – read them as 1, 1, 0 and nothing.\n\n")
	// A fingerprint rather than the key itself: the public half is two
	// kilobytes of base64, which has no business on a printed card. This is
	// enough to tell which backups the card belongs to.
	fmt.Fprintf(&b, "Public key fingerprint (what \"bond keys list\" shows for this slot):\n")
	fmt.Fprintf(&b, "  %s\n", publicFingerprint(public))
	return b.String()
}

// publicFingerprint is a short, stable name for a recipient public key.
func publicFingerprint(public string) string {
	sum := sha256.Sum256([]byte(public))
	return fmt.Sprintf("%x", sum[:8])
}

// writeSecret refuses to overwrite. Key material that is silently replaced is
// key material that silently stops opening old backups.
func writeSecret(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; refusing to overwrite key material", path)
		}
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// recipientPublicPrefix marks a public key so it is recognisable in a config
// file and cannot be confused with a secret.
const recipientPublicPrefix = "bondpk1"

func encodeRecipientPublic(b []byte) string {
	return recipientPublicPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeRecipientPublic(s string) (*crypto.RecipientPublic, error) {
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, recipientPublicPrefix) {
		return nil, fmt.Errorf("a recipient public key starts with %q", recipientPublicPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(trimmed[len(recipientPublicPrefix):])
	if err != nil {
		return nil, fmt.Errorf("the public key is not valid: %w", err)
	}
	return crypto.ParseRecipientPublic(raw)
}
