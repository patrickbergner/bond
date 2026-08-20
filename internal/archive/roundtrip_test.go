package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, dir, rel, content string) string {
	t.Helper()
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestWriteAndExtractRoundTrip(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{
		"readme.md":              "hello",
		"conf/app.json":          `{"a":1}`,
		"Café/Chapter 1.txt":     "Héllo, this is a tëst",
		"empty.txt":              "",
		"deep/a/b/c/d/e/f/g.txt": "deep",
	}
	var entries []Entry
	entries = append(entries, Entry{Path: "conf", Kind: KindDir, Mode: 0o755, ModTime: time.Now()})
	for rel, content := range files {
		abs := write(t, src, rel, content)
		info, err := os.Stat(abs)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, Entry{Path: rel, Disk: abs, Kind: KindFile, Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime()})
	}

	var buf bytes.Buffer
	w := NewWriter(&buf)
	for _, e := range entries {
		if err := w.Add(e); err != nil {
			t.Fatalf("Add(%s): %v", e.Path, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	index := w.Index()
	if len(index) != len(entries) {
		t.Fatalf("index has %d entries, want %d", len(index), len(entries))
	}
	for _, info := range index {
		if info.Kind != KindFile {
			continue
		}
		want := sha256.Sum256([]byte(files[info.Path]))
		if info.SHA256 != hex.EncodeToString(want[:]) {
			t.Errorf("%s: index digest does not match the content", info.Path)
		}
	}

	dest := t.TempDir()
	stats, err := Extract(context.Background(), bytes.NewReader(buf.Bytes()), ExtractOptions{Dest: dest})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Files != len(files) {
		t.Errorf("restored %d files, want %d", stats.Files, len(files))
	}

	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
}

func TestExtractPreservesModTime(t *testing.T) {
	src := t.TempDir()
	abs := write(t, src, "a.txt", "content")
	stamp := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := os.Chtimes(abs, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(abs)

	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Add(Entry{Path: "a.txt", Disk: abs, Kind: KindFile, Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime()}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	dest := t.TempDir()
	if _, err := Extract(context.Background(), &buf, ExtractOptions{Dest: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.Stat(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.ModTime().Equal(stamp) {
		t.Errorf("modification time = %v, want %v", got.ModTime().UTC(), stamp)
	}
}

func TestExtractRefusesEscapingEntry(t *testing.T) {
	// Hand-built: BOND's own writer cannot produce this, which is exactly why
	// the reader has to be the thing that refuses it.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "innocent.txt", Typeflag: tar.TypeReg, Size: 2, Mode: 0o644})
	tw.Write([]byte("ok"))
	tw.WriteHeader(&tar.Header{Name: "../escaped.txt", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644})
	tw.Write([]byte("bad"))
	tw.Close()

	dest := t.TempDir()
	_, err := Extract(context.Background(), &buf, ExtractOptions{Dest: dest})
	if err == nil {
		t.Fatal("Extract accepted an entry that climbs out of the destination")
	}
	if !strings.Contains(err.Error(), "refusing to restore") {
		t.Errorf("error = %v, want it to name the refusal", err)
	}
	parent := filepath.Dir(dest)
	if _, err := os.Stat(filepath.Join(parent, "escaped.txt")); err == nil {
		t.Fatal("the escaping entry was written outside the destination")
	}
}

func TestExtractRefusesUnsupportedTypes(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeLink, Linkname: "other", Mode: 0o644})
	tw.Close()

	if _, err := Extract(context.Background(), &buf, ExtractOptions{Dest: t.TempDir()}); err == nil {
		t.Fatal("Extract accepted a hard link, which BOND never writes")
	}
}

func TestExtractSymlinkPolicy(t *testing.T) {
	build := func(target string) *bytes.Buffer {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		tw.WriteHeader(&tar.Header{Name: "dir/link", Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777})
		tw.Close()
		return &buf
	}

	// Off by default, and saying so rather than silently dropping it.
	var skipped string
	stats, err := Extract(context.Background(), build("file.txt"), ExtractOptions{
		Dest:      t.TempDir(),
		OnWarning: func(p, msg string) { skipped = p },
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Symlinks != 0 || stats.Skipped != 1 || skipped != "dir/link" {
		t.Errorf("stats = %+v, skipped = %q; want the link skipped and reported", stats, skipped)
	}

	// Enabled, but a target that leaves the destination is still refused.
	if _, err := Extract(context.Background(), build("../../../etc/passwd"), ExtractOptions{
		Dest:          t.TempDir(),
		AllowSymlinks: true,
	}); err == nil {
		t.Error("Extract accepted a symlink pointing outside the destination")
	}

	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege Windows does not grant by default")
	}
	dest := t.TempDir()
	if _, err := Extract(context.Background(), build("file.txt"), ExtractOptions{Dest: dest, AllowSymlinks: true}); err != nil {
		t.Fatalf("Extract with symlinks enabled: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "dir", "link")); err != nil {
		t.Errorf("the symlink was not restored: %v", err)
	}
}

func TestExtractRefusesToOverwriteByDefault(t *testing.T) {
	src := t.TempDir()
	abs := write(t, src, "a.txt", "new")
	info, _ := os.Stat(abs)

	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.Add(Entry{Path: "a.txt", Disk: abs, Kind: KindFile, Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime()})
	w.Close()
	archived := buf.Bytes()

	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Extract(context.Background(), bytes.NewReader(archived), ExtractOptions{Dest: dest}); err == nil {
		t.Error("Extract overwrote an existing file without being asked to")
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "a.txt")); string(got) != "existing" {
		t.Errorf("the existing file was changed to %q", got)
	}

	if _, err := Extract(context.Background(), bytes.NewReader(archived), ExtractOptions{Dest: dest, Overwrite: true}); err != nil {
		t.Fatalf("Extract with Overwrite: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "a.txt")); string(got) != "new" {
		t.Errorf("after an overwriting restore the file is %q, want %q", got, "new")
	}
}

func TestExtractInclude(t *testing.T) {
	src := t.TempDir()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for _, rel := range []string{"a.txt", "keep/b.txt", "skip/c.txt"} {
		abs := write(t, src, rel, rel)
		info, _ := os.Stat(abs)
		w.Add(Entry{Path: rel, Disk: abs, Kind: KindFile, Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime()})
	}
	w.Close()

	dest := t.TempDir()
	stats, err := Extract(context.Background(), &buf, ExtractOptions{
		Dest:    dest,
		Include: func(p string) bool { return strings.HasPrefix(p, "keep/") },
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Files != 1 || stats.Skipped != 2 {
		t.Errorf("stats = %+v, want 1 file restored and 2 skipped", stats)
	}
	if _, err := os.Stat(filepath.Join(dest, "skip", "c.txt")); err == nil {
		t.Error("an excluded file was restored")
	}
}

// A backup runs against a live tree, so a file can be rewritten while it is
// being read – the writer stats the open handle, which closes most of that
// window but not the part between the stat and the last byte. tar demands
// exactly the promised byte count, so both directions have to leave a readable
// stream behind and say what happened.
func TestWriterSurvivesFileChangingUnderneathIt(t *testing.T) {
	const promised = 4096

	t.Run("shrank", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		var warned string
		w.OnWarning = func(p, msg string) { warned = msg }

		short := strings.Repeat("x", 100)
		if err := w.writeRegular("rotating.log", strings.NewReader(short), promised, 0o644, time.Now()); err != nil {
			t.Fatalf("writeRegular: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !strings.Contains(warned, "shrank") {
			t.Errorf("warning = %q, want it to report the file shrinking", warned)
		}

		// The point of padding: the stream stays readable.
		dest := t.TempDir()
		if _, err := Extract(context.Background(), &buf, ExtractOptions{Dest: dest}); err != nil {
			t.Fatalf("the archive did not survive a file changing underneath it: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(dest, "rotating.log"))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != promised {
			t.Errorf("restored %d bytes, want the %d the header promised", len(got), promised)
		}
		if string(got[:100]) != short {
			t.Error("the bytes that were read did not survive")
		}

		// The index digest must describe what is stored, padding included,
		// or a later verification would report damage that is not there.
		want := sha256.Sum256(append([]byte(short), make([]byte, promised-100)...))
		if w.Index()[0].SHA256 != hex.EncodeToString(want[:]) {
			t.Error("the index digest does not cover what was actually written")
		}
	})

	t.Run("grew", func(t *testing.T) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		var warned string
		w.OnWarning = func(p, msg string) { warned = msg }

		long := strings.Repeat("y", promised*2)
		if err := w.writeRegular("growing.log", strings.NewReader(long), promised, 0o644, time.Now()); err != nil {
			t.Fatalf("writeRegular: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !strings.Contains(warned, "grew") {
			t.Errorf("warning = %q, want it to report the file growing", warned)
		}

		dest := t.TempDir()
		if _, err := Extract(context.Background(), &buf, ExtractOptions{Dest: dest}); err != nil {
			t.Fatalf("the archive did not survive a file changing underneath it: %v", err)
		}
		got, _ := os.ReadFile(filepath.Join(dest, "growing.log"))
		if len(got) != promised {
			t.Errorf("restored %d bytes, want %d", len(got), promised)
		}
	})
}

func TestExtractRestoresIntoNestedDirectories(t *testing.T) {
	// Parent directory entries are not always present – with include filters
	// only the matching leaves are stored – so extraction has to create them.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "a/b/c/d.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644, Format: tar.FormatPAX})
	tw.Write([]byte("x"))
	tw.Close()

	dest := t.TempDir()
	if _, err := Extract(context.Background(), &buf, ExtractOptions{Dest: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "a", "b", "c", "d.txt")); err != nil {
		t.Errorf("the nested file was not restored: %v", err)
	}
}

func TestWriterLargeFile(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "big.bin")
	content := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	if err := os.WriteFile(abs, content, 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(abs)

	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Add(Entry{Path: "big.bin", Disk: abs, Kind: KindFile, Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime()}); err != nil {
		t.Fatal(err)
	}
	w.Close()

	if w.Bytes() != int64(len(content)) {
		t.Errorf("Bytes = %d, want %d", w.Bytes(), len(content))
	}
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(tr)
	if !bytes.Equal(got, content) || hdr.Size != int64(len(content)) {
		t.Error("the large file did not survive the round trip")
	}
}
