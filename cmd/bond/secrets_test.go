package main

import (
	"bytes"
	"testing"

	"github.com/patrickbergner/bond/internal/crypto"
)

func TestWipeUnlockersClearsCLIOwnedSecrets(t *testing.T) {
	passphrase := crypto.Passphrase(bytes.Repeat([]byte{0x41}, 24))
	keyfile := crypto.KeyfileSecret(bytes.Repeat([]byte{0x42}, crypto.KeyLen))
	seed := bytes.Repeat([]byte{0x43}, crypto.SeedLen)
	private, err := crypto.RecipientFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	wipeUnlockers([]crypto.Unlocker{
		passphrase,
		keyfile,
		crypto.RecipientSecret{Private: private},
	})
	if !bytes.Equal(passphrase, make([]byte, len(passphrase))) {
		t.Error("passphrase was not wiped")
	}
	if !bytes.Equal(keyfile, make([]byte, len(keyfile))) {
		t.Error("keyfile was not wiped")
	}
	if private.Seed() != nil || private.X25519 != nil || private.MLKEM != nil {
		t.Error("recovery private key was not released")
	}
}
