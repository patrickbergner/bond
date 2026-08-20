package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// safepath_test.go proves the checker refuses the right names. This file proves
// the extractor actually consults it – with tars written by hand, because BOND's
// own writer would never produce one of these, and a restore reads archives it
// did not write.

// hostile builds a tar from raw headers, bypassing everything BOND would
// normally impose on a name.
func hostile(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range headers {
		hdr := h
		if hdr.ModTime.IsZero() {
			hdr.ModTime = time.Unix(1_600_000_000, 0)
		}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Mode == 0 {
			hdr.Mode = 0o644
		}
		body := []byte("payload")
		if hdr.Typeflag != tar.TypeReg {
			body = nil
		}
		hdr.Size = int64(len(body))
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("writing header %q: %v", hdr.Name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// arena gives a destination with a canary beside it, so "nothing escaped" is
// checked rather than assumed.
func arena(t *testing.T) (dest string, outside func()) {
	t.Helper()
	base := t.TempDir()
	dest = filepath.Join(base, "restore-here")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	return dest, func() {
		t.Helper()
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == base || strings.HasPrefix(path, dest) {
				return nil
			}
			t.Errorf("the restore created %s, which is outside the destination", path)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestExtractRefusesEscapingNames(t *testing.T) {
	names := []string{
		"../escaped.txt",
		"../../escaped.txt",
		"ok/../../escaped.txt",
		"/etc/passwd",
		`\\server\share\escaped.txt`,
		"C:/Windows/System32/escaped.txt",
		"..",
		"a/./b",
		"a//b",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			dest, checkOutside := arena(t)
			_, err := Extract(context.Background(), bytes.NewReader(hostile(t, tar.Header{Name: name})),
				ExtractOptions{Dest: dest})
			if err == nil {
				t.Fatalf("Extract accepted %q", name)
			}
			if !strings.Contains(err.Error(), "refusing to restore") {
				t.Errorf("error = %v, want it to say what was refused", err)
			}
			checkOutside()
		})
	}
}

func TestExtractRefusesWindowsSpecificNames(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("these names are legal on POSIX and are stored as given")
	}
	for _, name := range []string{"con", "NUL.txt", "docs/lpt9", "trailing.", "has:colon"} {
		dest, checkOutside := arena(t)
		_, err := Extract(context.Background(), bytes.NewReader(hostile(t, tar.Header{Name: name})),
			ExtractOptions{Dest: dest})
		if err == nil {
			t.Errorf("Extract accepted %q on Windows", name)
		}
		checkOutside()
	}
}

// A bad name is not one bad entry to be skipped: it means the archive is not
// what it claims to be, and the restore stops there.
func TestExtractAbortsOnTheFirstBadName(t *testing.T) {
	dest, checkOutside := arena(t)
	data := hostile(t,
		tar.Header{Name: "good/first.txt"},
		tar.Header{Name: "../escaped.txt"},
		tar.Header{Name: "good/third.txt"},
	)

	stats, err := Extract(context.Background(), bytes.NewReader(data), ExtractOptions{Dest: dest})
	if err == nil {
		t.Fatal("Extract carried on past a name that escapes the destination")
	}
	checkOutside()

	if stats.Files != 1 {
		t.Errorf("restored %d files before stopping, want 1", stats.Files)
	}
	if _, err := os.Stat(filepath.Join(dest, "good", "third.txt")); err == nil {
		t.Error("an entry after the bad one was restored")
	}
}

// Filtering must not be a way in: the name is judged before Include is asked,
// so "it would have been skipped anyway" is never the reason a hostile archive
// is accepted.
func TestExtractChecksNamesBeforeFiltering(t *testing.T) {
	dest, checkOutside := arena(t)
	data := hostile(t, tar.Header{Name: "../escaped.txt"})

	_, err := Extract(context.Background(), bytes.NewReader(data), ExtractOptions{
		Dest:    dest,
		Include: func(string) bool { return false },
	})
	if err == nil {
		t.Fatal("an escaping name was tolerated because a filter would have skipped it")
	}
	checkOutside()
}

func TestExtractRefusesUnsupportedEntryTypes(t *testing.T) {
	types := map[string]byte{
		"hard link":        tar.TypeLink,
		"character device": tar.TypeChar,
		"block device":     tar.TypeBlock,
		"fifo":             tar.TypeFifo,
	}
	for label, flag := range types {
		t.Run(label, func(t *testing.T) {
			dest, checkOutside := arena(t)
			data := hostile(t, tar.Header{Name: "thing", Typeflag: flag, Linkname: "elsewhere"})
			if _, err := Extract(context.Background(), bytes.NewReader(data), ExtractOptions{Dest: dest}); err == nil {
				t.Errorf("Extract accepted a %s", label)
			}
			checkOutside()
		})
	}
}

func TestExtractRefusesEscapingSymlinks(t *testing.T) {
	targets := []string{"../outside", "/etc/passwd", "C:/Windows", `\\server\share`, ""}
	for _, target := range targets {
		dest, checkOutside := arena(t)
		data := hostile(t, tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: target})
		_, err := Extract(context.Background(), bytes.NewReader(data), ExtractOptions{
			Dest:          dest,
			AllowSymlinks: true,
		})
		if err == nil {
			t.Errorf("Extract accepted a symlink to %q", target)
		}
		checkOutside()
	}
}

// A symlink is the one entry that still points somewhere after the restore has
// finished, so it takes an explicit decision to restore one at all.
func TestExtractSkipsSymlinksByDefault(t *testing.T) {
	dest, _ := arena(t)
	data := hostile(t, tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "inside.txt"})

	stats, err := Extract(context.Background(), bytes.NewReader(data), ExtractOptions{Dest: dest})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Symlinks != 0 || stats.Skipped != 1 {
		t.Errorf("stats = %+v, want the link skipped", stats)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); err == nil {
		t.Error("the symlink was created even though symlinks were off")
	}
}

func TestExtractRefusesToOverwriteWithoutBeingTold(t *testing.T) {
	dest, _ := arena(t)
	existing := filepath.Join(dest, "keep.txt")
	if err := os.WriteFile(existing, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := hostile(t, tar.Header{Name: "keep.txt"})

	_, err := Extract(context.Background(), bytes.NewReader(data), ExtractOptions{Dest: dest})
	if err == nil {
		t.Fatal("Extract overwrote a file without --overwrite")
	}
	if got, _ := os.ReadFile(existing); string(got) != "mine" {
		t.Errorf("the file was changed anyway: %q", got)
	}

	if _, err := Extract(context.Background(), bytes.NewReader(data), ExtractOptions{Dest: dest, Overwrite: true}); err != nil {
		t.Fatalf("Extract with Overwrite: %v", err)
	}
	if got, _ := os.ReadFile(existing); string(got) != "payload" {
		t.Errorf("after --overwrite the file holds %q, want the archived content", got)
	}
}
