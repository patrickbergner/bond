package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/sevenzip"
)

// This is the test that matters: the whole pipeline, both ways, over the
// awkward cases. Everything below runs the real 7-Zip and writes real
// containers.

var fastKDF = crypto.KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1}

const pass = "a passphrase for the test"

// fixture writes a tree covering the cases that break archivers: an empty
// file, non-ASCII names, a deep path, something incompressible and something
// that compresses to almost nothing.
func fixture(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "src")

	noise := make([]byte, 300_000)
	rand.Read(noise)

	files := map[string][]byte{
		"readme.md":                    []byte("hello\n"),
		"empty.txt":                    {},
		"Grüße/Kapitel 1.txt":          bytes.Repeat([]byte("Wiederholung schrumpft schön. "), 4000),
		"docs/deep/a/b/c/d/noise.bin":  noise,
		"docs/notes.txt":               []byte("plain\n"),
		"docs/ünïcödé and spaces.json": []byte(`{"ok":true}`),
	}
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, files
}

func settings(t *testing.T, level int) config.Resolved {
	s := config.Defaults()
	s.CompressionLevel = level
	s.RecoveryPercent = 0
	s.HashAlgorithm = config.HashSHA384
	s.ShardBytes = 64 << 10 // small, so the tests exercise several shards
	return s
}

func createContainer(t *testing.T, root string, s config.Resolved, keys []container.KeySpec) *CreateResult {
	t.Helper()
	dir := t.TempDir()
	tool, err := sevenzip.Extract(dir)
	if err != nil {
		t.Fatalf("7-Zip: %v", err)
	}
	t.Cleanup(func() { tool.Close() })

	target := &config.Target{ID: "test", Sources: []config.Source{{Path: root}}}
	result, err := Create(context.Background(), CreateOptions{
		Target:     target,
		Settings:   s,
		Keys:       keys,
		WorkDir:    filepath.Join(dir, "work"),
		OutputPath: filepath.Join(dir, "out", "test.bond"),
		Tool:       tool,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return result
}

func restoreContainer(t *testing.T, path, dest string, secret crypto.Unlocker) *RestoreResult {
	t.Helper()
	tool, err := sevenzip.Extract(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer tool.Close()

	r, err := container.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if err := r.Unlock(secret); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	result, err := Restore(context.Background(), r, RestoreOptions{Dest: dest, Tool: tool})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	return result
}

// compare fails unless every file came back byte for byte.
func compare(t *testing.T, dest, prefix string, want map[string][]byte) {
	t.Helper()
	for rel, content := range want {
		abs := filepath.Join(dest, prefix, filepath.FromSlash(rel))
		got, err := os.ReadFile(abs)
		if err != nil {
			t.Errorf("%s was not restored: %v", rel, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("%s came back as %d bytes, want %d", rel, len(got), len(content))
		}
	}
}

func TestRoundTripCompressed(t *testing.T) {
	root, files := fixture(t)
	keys := []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF, Label: "test"}}

	created := createContainer(t, root, settings(t, 5), keys)
	if created.Stats.Files != len(files) {
		t.Errorf("stored %d files, want %d", created.Stats.Files, len(files))
	}
	if created.SidecarPath == "" {
		t.Error("no checksum file was written")
	}
	if _, err := CheckSidecar(created.Path); err != nil {
		t.Errorf("the checksum file does not match the container: %v", err)
	}

	dest := t.TempDir()
	restored := restoreContainer(t, created.Path, dest, crypto.Passphrase(pass))
	if restored.Stats.Files != len(files) {
		t.Errorf("restored %d files, want %d", restored.Stats.Files, len(files))
	}
	if restored.Verified != len(files) {
		t.Errorf("verified %d files against their recorded digests, want %d", restored.Verified, len(files))
	}
	compare(t, dest, filepath.Base(root), files)
}

// Level 0 skips 7-Zip completely, which is the mode for trees of video or
// music. The container has to round-trip identically without it.
func TestRoundTripUncompressed(t *testing.T) {
	root, files := fixture(t)
	keys := []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}}

	created := createContainer(t, root, settings(t, 0), keys)
	if created.Manifest.Compression.Format != "none" {
		t.Errorf("compression format = %q, want none", created.Manifest.Compression.Format)
	}

	dest := t.TempDir()
	restoreContainer(t, created.Path, dest, crypto.Passphrase(pass))
	compare(t, dest, filepath.Base(root), files)
}

func TestCompressionActuallyCompresses(t *testing.T) {
	root, _ := fixture(t)
	keys := []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}}

	plain := createContainer(t, root, settings(t, 0), keys)
	packed := createContainer(t, root, settings(t, 5), keys)
	if packed.Size >= plain.Size {
		t.Errorf("compressed container is %d bytes, uncompressed is %d", packed.Size, plain.Size)
	}
	t.Logf("%d bytes of content: %d stored, %d compressed", plain.Stats.Bytes, plain.Size, packed.Size)
}

func TestKeyfileRoundTrip(t *testing.T) {
	root, files := fixture(t)
	keyfile := make([]byte, crypto.KeyLen)
	rand.Read(keyfile)

	created := createContainer(t, root, settings(t, 1), []container.KeySpec{
		{Secret: crypto.KeyfileSecret(keyfile), Label: "usb stick"},
	})

	dest := t.TempDir()
	restoreContainer(t, created.Path, dest, crypto.KeyfileSecret(keyfile))
	compare(t, dest, filepath.Base(root), files)
}

func TestFileIndexCanBeTurnedOff(t *testing.T) {
	root, _ := fixture(t)
	s := settings(t, 1)
	s.StoreFileIndex = false
	created := createContainer(t, root, s, []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

	if len(created.Manifest.Index) != 0 {
		t.Error("the file index was stored even though it was switched off")
	}

	r, err := container.Open(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	// Listing must say why it cannot answer rather than claim the container is
	// empty.
	if _, err := ListEntries(r); err == nil {
		t.Error("ListEntries succeeded on a container with no index")
	} else if !strings.Contains(err.Error(), "storeFileIndex") {
		t.Errorf("error = %v, want it to name the setting", err)
	}
}

func TestListReadsTheIndexWithoutDecompressing(t *testing.T) {
	root, files := fixture(t)
	created := createContainer(t, root, settings(t, 5), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

	r, err := container.Open(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
		t.Fatal(err)
	}

	entries, err := ListEntries(r)
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Path] = true
	}
	base := filepath.Base(root)
	for rel := range files {
		if !names[base+"/"+rel] {
			t.Errorf("%s is missing from the index", rel)
		}
	}
}

func TestListDistinguishesAnIndexedEmptyArchive(t *testing.T) {
	root, _ := fixture(t)
	created := createContainer(t, root, settings(t, 0), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})
	r, err := container.Open(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	r.Manifest().IndexStored = true
	r.Manifest().Index = nil
	r.Manifest().Files, r.Manifest().Dirs, r.Manifest().Bytes = 0, 0, 0
	entries, err := ListEntries(r)
	if err != nil {
		t.Fatalf("indexed empty archive returned entries=%v, err=%v", entries, err)
	}
	if len(entries) != 0 {
		t.Fatalf("indexed empty archive returned %d entries", len(entries))
	}
}

func TestRestoreReconcilesManifestForPartialAndUnindexedRestores(t *testing.T) {
	root, _ := fixture(t)
	keys := []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}}

	t.Run("indexed partial restore", func(t *testing.T) {
		created := createContainer(t, root, settings(t, 0), keys)
		r, err := container.Open(created.Path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
			t.Fatal(err)
		}
		r.Manifest().Index[0].Path = "manifest-does-not-match"
		_, err = Restore(context.Background(), r, RestoreOptions{
			Dest:    t.TempDir(),
			Include: func(string) bool { return false },
		})
		if err == nil || !strings.Contains(err.Error(), "manifest index") {
			t.Fatalf("partial restore mismatch error = %v", err)
		}
	})

	t.Run("partial restore verifies excluded file digests", func(t *testing.T) {
		created := createContainer(t, root, settings(t, 0), keys)
		r, err := container.Open(created.Path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
			t.Fatal(err)
		}
		for i := range r.Manifest().Index {
			if r.Manifest().Index[i].Kind == archive.KindFile {
				r.Manifest().Index[i].SHA256 = strings.Repeat("0", 64)
				break
			}
		}
		_, err = Restore(context.Background(), r, RestoreOptions{
			Dest:    t.TempDir(),
			Include: func(string) bool { return false },
		})
		if err == nil || !strings.Contains(err.Error(), "digests") {
			t.Fatalf("excluded digest mismatch error = %v", err)
		}
	})

	t.Run("unindexed aggregate", func(t *testing.T) {
		s := settings(t, 0)
		s.StoreFileIndex = false
		created := createContainer(t, root, s, keys)
		r, err := container.Open(created.Path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
			t.Fatal(err)
		}
		r.Manifest().Files++
		_, err = Restore(context.Background(), r, RestoreOptions{Dest: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), "archive totals") {
			t.Fatalf("aggregate mismatch error = %v", err)
		}
	})
}

func TestRestoreRejectsUnknownCompression(t *testing.T) {
	root, _ := fixture(t)
	created := createContainer(t, root, settings(t, 0), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})
	r, err := container.Open(created.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	r.Manifest().Compression.Format = "future"
	if _, err := Restore(context.Background(), r, RestoreOptions{Dest: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "unsupported compression") {
		t.Fatalf("unknown compression error = %v", err)
	}
}

func TestIncompleteRestoreErrorIsTyped(t *testing.T) {
	err := &IncompleteRestoreError{Issues: []archive.MetadataIssue{{Path: "dir", Operation: "permissions", Err: errors.New("denied")}}}
	if !errors.Is(err, ErrIncompleteRestore) || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete restore error = %v", err)
	}
}

// Damage after the container was written must be caught before anything is
// restored from it.
func TestDamageIsCaughtOnRestore(t *testing.T) {
	root, _ := fixture(t)
	created := createContainer(t, root, settings(t, 1), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

	f, err := os.OpenFile(created.Path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A shard well into the payload, so the header and manifest stay intact.
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
		t.Fatalf("the container should still unlock; only the payload is damaged: %v", err)
	}

	report, err := r.Verify(nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Healthy() {
		t.Error("Verify called a damaged container healthy")
	}

	if _, err := Restore(context.Background(), r, RestoreOptions{Dest: t.TempDir(), Tool: tool}); err == nil {
		t.Error("Restore succeeded from a damaged container")
	}
}

func TestSidecarDetectsAChangedContainer(t *testing.T) {
	root, _ := fixture(t)
	created := createContainer(t, root, settings(t, 1), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

	if _, err := CheckSidecar(created.Path); err != nil {
		t.Fatalf("a fresh container does not match its own checksum: %v", err)
	}

	f, _ := os.OpenFile(created.Path, os.O_RDWR, 0)
	f.WriteAt([]byte{0xff}, 140_000)
	f.Close()

	if _, err := CheckSidecar(created.Path); err == nil {
		t.Error("the checksum file did not notice a changed container")
	}
}

func TestSidecarIsNoClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "container.bond")
	if err := os.WriteFile(path, []byte("container"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSidecar(path, config.HashSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSidecar(path, config.HashSHA256); err == nil {
		t.Fatal("WriteSidecar replaced an existing checksum")
	}
}

func TestEmptyTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "empty-src")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	created := createContainer(t, root, settings(t, 5), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})
	if created.Stats.Files != 0 {
		t.Errorf("stored %d files from an empty tree", created.Stats.Files)
	}

	dest := t.TempDir()
	restoreContainer(t, created.Path, dest, crypto.Passphrase(pass))
}

func TestModificationTimesSurvive(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The comparison below is exact; Windows timestamps are, too, but the
		// fixture's directories are created by the test itself.
		t.Log("running the exact timestamp comparison on Windows")
	}
	root, _ := fixture(t)
	created := createContainer(t, root, settings(t, 1), []container.KeySpec{{Secret: crypto.Passphrase(pass), KDF: fastKDF}})

	dest := t.TempDir()
	restoreContainer(t, created.Path, dest, crypto.Passphrase(pass))

	base := filepath.Base(root)
	for _, rel := range []string{"readme.md", "docs/notes.txt", "Grüße/Kapitel 1.txt"} {
		want, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.Stat(filepath.Join(dest, base, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if !got.ModTime().Equal(want.ModTime()) {
			t.Errorf("%s: modification time %v, want %v", rel, got.ModTime(), want.ModTime())
		}
	}
}
