package backup

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/sevenzip"
)

// The recovery data sits in the file being read, so a restore uses it. Stopping
// at the first damaged shard meant writing a repaired copy of the whole
// container before a single file could come back.
func TestRestoreRebuildsDamagedShardsFromTheRecoveryData(t *testing.T) {
	root, files := fixture(t)
	s := settings(t, 1)
	s.RecoveryPercent = 20
	created := createContainer(t, root, s, []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

	f, err := os.OpenFile(created.Path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Inside the first shard: the header, key slots and manifest stay intact.
	if _, err := f.WriteAt([]byte("tampered with"), 140_000); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tool, err := sevenzip.Extract(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer tool.Close()
	r, err := container.Open(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if _, err := Restore(context.Background(), r, RestoreOptions{Dest: dest, Tool: tool}); err != nil {
		t.Fatalf("a restore the recovery data covers failed: %v", err)
	}
	compare(t, dest, "src", files)
	if r.RecoveredShards() == 0 {
		t.Error("the restore succeeded without reporting that it had to rebuild a shard")
	}
}

// A volume never splits a shard, so a shard larger than a volume's budget used
// to make every volume larger than the limit it was written under.
func TestVolumesStayUnderTheLimitWhateverTheShardSize(t *testing.T) {
	root, _ := fixture(t)
	noise := make([]byte, 3<<20)
	rand.Read(noise)
	if err := os.WriteFile(filepath.Join(root, "large.bin"), noise, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, percent := range []int{0, 10} {
		s := settings(t, 0)
		s.RecoveryPercent = percent
		s.ShardBytes = 4 << 20
		s.MaxVolumeBytes = 1 << 20
		s.HashAlgorithm = config.HashNone
		created := createContainer(t, root, s, []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

		if len(created.VolumePaths) < 3 {
			t.Fatalf("recovery %d%%: %d volumes for more than 3 MiB under a 1 MiB limit", percent, len(created.VolumePaths))
		}
		for _, path := range created.VolumePaths {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() > s.MaxVolumeBytes {
				t.Errorf("recovery %d%%: %s is %d bytes, over the limit of %d", percent, filepath.Base(path), info.Size(), s.MaxVolumeBytes)
			}
		}
		restoreContainer(t, created.VolumePaths[0], t.TempDir(), crypto.Passphrase(pass))
	}
}

// A key change rewrites part of the first volume. Its checksum file has to
// follow, or the quick check reports an intact container as damaged.
func TestRefreshSidecarFollowsAChangeInPlace(t *testing.T) {
	root, _ := fixture(t)
	created := createContainer(t, root, settings(t, 0), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

	f, err := os.OpenFile(created.Path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xff}, 5000); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := CheckSidecar(created.Path); err == nil {
		t.Fatal("the checksum file still matches a file that was changed")
	}

	sidecar, err := RefreshSidecar(created.Path)
	if err != nil || sidecar != created.SidecarPath {
		t.Fatalf("RefreshSidecar = %q, %v; want %q", sidecar, err, created.SidecarPath)
	}
	if _, err := CheckSidecar(created.Path); err != nil {
		t.Errorf("after the refresh: %v", err)
	}

	// No checksum file, none invented.
	s := settings(t, 0)
	s.HashAlgorithm = config.HashNone
	bare := createContainer(t, root, s, []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})
	if sidecar, err := RefreshSidecar(bare.Path); err != nil || sidecar != "" {
		t.Errorf("RefreshSidecar on a container without a checksum file = %q, %v", sidecar, err)
	}
}

// An interrupted backup comes back through the ordinary failure path: nothing
// is published and nothing is left in the working directory.
func TestCancelledBackupLeavesNoPartial(t *testing.T) {
	root, _ := fixture(t)
	dir := t.TempDir()
	tool, err := sevenzip.Extract(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer tool.Close()

	// Cancelled in the middle of the run, with the compressor started and the
	// staging file open, which is where an interrupt usually lands.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := &config.Target{ID: "test", Sources: []config.Source{{Path: root}}}
	_, err = Create(ctx, CreateOptions{
		Target:     target,
		Settings:   settings(t, 1),
		Keys:       []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}},
		WorkDir:    filepath.Join(dir, "work"),
		OutputPath: filepath.Join(dir, "out", "test.bond"),
		Tool:       tool,
		OnEntry:    func(archive.Entry) { cancel() },
	})
	if err == nil {
		t.Fatal("a cancelled backup reported success")
	}
	for _, sub := range []string{"work", "out"} {
		left, _ := os.ReadDir(filepath.Join(dir, sub))
		if len(left) != 0 {
			t.Errorf("%s still holds %s after a cancelled backup", sub, left[0].Name())
		}
	}
}

// Two names are one file where the filesystem folds case and normalizes, and
// lower-casing is not how it decides.
func TestFoldNameFollowsTheFilesystemNotToLower(t *testing.T) {
	same := [][2]string{
		{"Report.TXT", "report.txt"},
		{"STRASSE", "straße"},
		{"ΌΣΟΣ", "όσος"},
		{"Grüße", "GRÜSSE"}, // precomposed ü against u + combining diaeresis
	}
	for _, pair := range same {
		if foldName(pair[0]) != foldName(pair[1]) {
			t.Errorf("%q and %q fold differently, and are the same name", pair[0], pair[1])
		}
	}
	if foldName("a/b.txt") == foldName("a/c.txt") {
		t.Error("different names fold to the same one")
	}
}
