package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVolumeFilesIncludesFourDigitSuffixes(t *testing.T) {
	base := filepath.Join(t.TempDir(), "large.bond")
	for i := 1; i <= 1001; i++ {
		if err := os.WriteFile(base+fmt.Sprintf(".%03d", i), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := volumeFiles(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1001 || !strings.HasSuffix(files[999], ".1000") || !strings.HasSuffix(files[1000], ".1001") {
		t.Fatalf("four-digit volumes were not enumerated numerically: count=%d tail=%v", len(files), files[len(files)-2:])
	}
}

func TestVolumeFilesRejectsGapsZeroAndAmbiguity(t *testing.T) {
	t.Run("gap", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "gap.bond")
		os.WriteFile(base+".001", nil, 0o600)
		os.WriteFile(base+".003", nil, 0o600)
		if _, err := volumeFiles(base); err == nil {
			t.Fatal("a volume gap was accepted")
		}
	})
	t.Run("zero", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "zero.bond")
		os.WriteFile(base+".000", nil, 0o600)
		if _, err := volumeFiles(base); err == nil {
			t.Fatal("volume .000 was accepted")
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "both.bond")
		os.WriteFile(base, nil, 0o600)
		os.WriteFile(base+".001", nil, 0o600)
		if _, err := volumeFiles(base); err == nil {
			t.Fatal("an unnumbered file and numbered set were accepted together")
		}
	})
}
