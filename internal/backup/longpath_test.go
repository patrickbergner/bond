package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
)

// Windows has a 260-character limit on paths that predates most of the files
// anyone wants to back up, and tooling that trips over it tends to do so
// silently – a few files missing from an archive nobody looks inside until the
// day it matters.
//
// BOND has one structural advantage here and it is worth naming: 7-Zip is fed
// the archive through a pipe and is never handed a path at all, so the limit
// only ever applies to Go's own file access. These tests cover both ends of it.

// deepPath builds a path at least depth characters long below root.
func deepPath(t *testing.T, root string, depth int) (dir string, archiveRel string) {
	t.Helper()
	// Components short enough to stay under the 255-byte per-component limit,
	// long enough that a handful of them clear 260 in total.
	const component = "a-directory-with-a-fairly-long-name"

	dir = root
	var parts []string
	for len(dir) < depth {
		dir = filepath.Join(dir, component)
		parts = append(parts, component)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating a %d-character path: %v", len(dir), err)
	}
	return dir, strings.Join(parts, "/")
}

func TestLongPathsRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}

	// Comfortably past Windows' 260, and past it again once the restore
	// destination's own prefix is added.
	dir, rel := deepPath(t, src, 320)
	content := bytes.Repeat([]byte("deep\n"), 500)
	deepFile := filepath.Join(dir, "buried.txt")
	if err := os.WriteFile(deepFile, content, 0o644); err != nil {
		t.Fatalf("writing into a %d-character path: %v", len(dir), err)
	}
	t.Logf("source path is %d characters", len(deepFile))

	// A component near the per-component limit, which is a different limit and
	// a different failure.
	longName := strings.Repeat("n", 200) + ".txt"
	if err := os.WriteFile(filepath.Join(src, longName), []byte("wide"), 0o644); err != nil {
		t.Fatalf("writing a %d-character file name: %v", len(longName), err)
	}

	key := make([]byte, crypto.KeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	created := createContainer(t, src, settings(t, 1), []container.KeySpec{{Secret: crypto.KeyfileSecret(key)}})
	if created.Stats.Files != 2 {
		t.Fatalf("stored %d files, want 2 – something in the deep tree was skipped", created.Stats.Files)
	}

	dest := t.TempDir()
	restoreContainer(t, created.Path, dest, crypto.KeyfileSecret(key))

	base := filepath.Base(src)
	restored := filepath.Join(dest, base, filepath.FromSlash(rel), "buried.txt")
	t.Logf("restored path is %d characters", len(restored))

	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatalf("the deeply nested file was not restored: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("the deeply nested file came back as %d bytes, want %d", len(got), len(content))
	}
	if _, err := os.Stat(filepath.Join(dest, base, longName)); err != nil {
		t.Errorf("the file with a 200-character name was not restored: %v", err)
	}
}

// A path long enough that the archive name itself exceeds the 100 characters a
// tar header's name field holds. PAX records carry the rest; the point is that
// nothing truncates on the way through, on any platform.
//
// This runs on Windows too. Go prefixes absolute paths with \\?\ before handing
// them to the API, so 600 characters is reachable without the machine having
// long path support switched on system-wide.
func TestVeryLongArchiveNamesSurvive(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, rel := deepPath(t, src, 600)
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("still here"), 0o644); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, crypto.KeyLen)
	created := createContainer(t, src, settings(t, 1), []container.KeySpec{{Secret: crypto.KeyfileSecret(key)}})

	dest := t.TempDir()
	restoreContainer(t, created.Path, dest, crypto.KeyfileSecret(key))

	got, err := os.ReadFile(filepath.Join(dest, filepath.Base(src), filepath.FromSlash(rel), "x.txt"))
	if err != nil {
		t.Fatalf("a file under a %d-character archive name was lost: %v", len(rel), err)
	}
	if string(got) != "still here" {
		t.Errorf("content = %q", got)
	}
}
