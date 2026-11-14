package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/crypto"
)

// The loader accepts placeholders in a key slot's path, and the sample control
// file uses one. They have to reach the filesystem expanded.
func TestKeySlotPathsAreExpanded(t *testing.T) {
	home := t.TempDir()
	key := bytes.Repeat([]byte{0x5a}, crypto.KeyLen)
	if err := os.WriteFile(filepath.Join(home, "offline.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}

	settings := config.Defaults()
	settings.EncryptionMethod = config.EncryptionNone
	settings.KeySlots = []config.KeySlot{{Type: config.SlotKeyfile, Path: "{{HOME}}/offline.key", Label: "offline copy"}}
	vars := config.Vars{config.VarHome: home}

	specs, err := keySpecsFor(&keyFlags{}, settings, vars)
	if err != nil {
		t.Fatalf("a key slot path with a placeholder was not resolved: %v", err)
	}
	if len(specs.slots) != 2 {
		t.Fatalf("got %d key specs, want the plaintext slot and the key file", len(specs.slots))
	}
	if secret, ok := specs.slots[1].Secret.(crypto.KeyfileSecret); !ok || !bytes.Equal(secret, key) {
		t.Error("the key file slot does not hold the bytes of the file the path names")
	}
	if settings.KeySlots[0].Path != "{{HOME}}/offline.key" {
		t.Error("expanding the path changed the caller's settings")
	}

	if _, err := keySpecsFor(&keyFlags{}, settings, config.Vars{}); err == nil || !strings.Contains(err.Error(), "HOME") {
		t.Errorf("a placeholder that cannot be resolved: got %v, want an error naming it", err)
	}
}
