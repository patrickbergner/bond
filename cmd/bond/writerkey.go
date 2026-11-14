package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/patrickbergner/bond/internal/crypto"
)

// A writer key is two files. The secret one holds the seed both signing keys
// are derived from, and stays on the machine that writes backups; the public
// one goes wherever restores happen, beside the recovery card. Both are text,
// so a key is recognisable for what it is when someone finds it in a directory
// years later.
const (
	writerSecretPrefix = "bondws1"
	writerPublicPrefix = "bondwp1"
)

func encodeWriterSecret(seed []byte) string {
	return writerSecretPrefix + base64.RawURLEncoding.EncodeToString(seed)
}

func encodeWriterPublic(pub *crypto.WriterPublic) string {
	return writerPublicPrefix + base64.RawURLEncoding.EncodeToString(pub.Bytes())
}

// firstToken is the first line of a key file that is not empty or a comment.
func firstToken(text string) string {
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

// loadWriterKey reads a writer key file written by "bond keygen --signing-key".
func loadWriterKey(path string) (*crypto.WriterPrivate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the signing key: %w", err)
	}
	defer crypto.Wipe(data)
	token := firstToken(string(data))
	if strings.HasPrefix(token, writerPublicPrefix) {
		return nil, fmt.Errorf("%s is the public half of a writer key; signing needs the secret file it was made with", path)
	}
	body, ok := strings.CutPrefix(token, writerSecretPrefix)
	if !ok {
		return nil, fmt.Errorf("%s is not a writer key; one starts with %q", path, writerSecretPrefix)
	}
	seed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("%s is damaged: %w", path, err)
	}
	defer crypto.Wipe(seed)
	return crypto.WriterFromSeed(seed)
}

// loadWriterPublic accepts a writer public key as text, or the path of a file
// holding one.
func loadWriterPublic(value string) (*crypto.WriterPublic, error) {
	token := strings.TrimSpace(value)
	if !strings.HasPrefix(token, writerPublicPrefix) {
		data, err := os.ReadFile(value)
		if err != nil {
			return nil, fmt.Errorf("neither a %s… key nor a readable file: %w", writerPublicPrefix, err)
		}
		token = firstToken(string(data))
		if strings.HasPrefix(token, writerSecretPrefix) {
			return nil, fmt.Errorf("%s is the secret half of a writer key; a restore needs only the .pub file", value)
		}
	}
	body, ok := strings.CutPrefix(token, writerPublicPrefix)
	if !ok {
		return nil, fmt.Errorf("a writer public key starts with %q", writerPublicPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("the writer public key is not valid: %w", err)
	}
	return crypto.ParseWriterPublic(raw)
}

// writeWriterKey creates a writer key pair: path holds the secret, path.pub
// the public half.
func writeWriterKey(path string) error {
	seed, err := crypto.NewWriterSeed()
	if err != nil {
		return err
	}
	defer crypto.Wipe(seed)
	w, err := crypto.WriterFromSeed(seed)
	if err != nil {
		return err
	}
	defer w.Wipe()

	secret := "# BOND writer key – secret. It signs backups and opens none.\n" +
		"# Keep it on the machine that writes them; anyone holding it can sign containers in its name.\n" +
		encodeWriterSecret(seed) + "\n"
	if err := writeSecret(path, []byte(secret), 0o600); err != nil {
		return err
	}
	public := "# BOND writer key – public. Give it to \"bond restore --expect-writer\".\n" +
		encodeWriterPublic(w.Public()) + "\n"
	if err := writeSecret(path+".pub", []byte(public), 0o644); err != nil {
		return err
	}

	fmt.Printf("signing key   %s\n", path)
	fmt.Printf("public key    %s.pub\n", path)
	fmt.Printf("fingerprint   %s\n", shortID(w.Fingerprint()))
	fmt.Printf("\nThe signing key stays on the machine that writes backups. Put it in the control file:\n")
	fmt.Printf("  \"signingKey\": %q\n", path)
	fmt.Printf("\nThe public key goes wherever backups are restored, beside the recovery card. A restore\n")
	fmt.Printf("with --expect-writer refuses any container this key did not sign – including one built by\n")
	fmt.Printf("someone who knows the recovery card's public key, which nothing else can tell apart.\n")
	return nil
}
