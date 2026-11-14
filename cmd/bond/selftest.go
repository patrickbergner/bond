package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/sevenzip"
	"github.com/patrickbergner/bond/internal/ui"
)

// runSelftest exercises the embedded toolchain end to end on the machine it is
// running on.
//
// BOND is cross-compiled for five platforms from one of them, so most of what
// it ships can never be run by whoever built it. This command is how a
// platform gets confirmed: it extracts the embedded 7-Zip, pushes a real tar
// stream through the xz pipe and back, restores it, and compares digests.
func runSelftest(args []string) error {
	fs := newFlagSet("selftest")
	var keep bool
	fs.BoolVar(&keep, "keep", false, "leave the temporary files behind for inspection")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: bond selftest [options]

Checks that the embedded 7-Zip runs here and that a tar stream survives a full
compress, decompress and restore.

options:
      --keep    leave the temporary files behind for inspection
`)
	}
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	ctx := rootCtx
	fmt.Printf("bond %s  %s/%s\n\n", Version, runtime.GOOS, runtime.GOARCH)

	tool, err := sevenzip.Extract("")
	if err != nil {
		return fmt.Errorf("the embedded 7-Zip could not be unpacked: %w", err)
	}
	defer tool.Close()

	version, err := tool.Version(ctx)
	if err != nil {
		return fmt.Errorf("the embedded 7-Zip does not run on this platform: %w", err)
	}
	info, _ := os.Stat(tool.Path())
	fmt.Printf("7-Zip helper\n")
	fmt.Printf("  embedded    %s\n", version)
	fmt.Printf("  extracted   %s", tool.Path())
	if info != nil {
		fmt.Printf(" (%s)", ui.Bytes(info.Size()))
	}
	fmt.Println()

	work, err := os.MkdirTemp("", "bond-selftest-")
	if err != nil {
		return err
	}
	if keep {
		fmt.Printf("  workspace   %s\n", work)
	} else {
		defer os.RemoveAll(work)
	}

	src := filepath.Join(work, "source")
	entries, err := buildFixture(src)
	if err != nil {
		return err
	}

	// tar -> xz, exactly as a backup does it.
	fmt.Printf("\narchive\n")
	var compressed bytes.Buffer
	start := time.Now()

	xz, err := tool.XZWriter(ctx, &compressed, sevenzip.Options{Level: 5})
	if err != nil {
		return err
	}
	w := archive.NewWriter(xz)
	w.OnWarning = func(path, msg string) { fmt.Printf("  warning     %s: %s\n", path, msg) }
	for _, e := range entries {
		if err := w.Add(e); err != nil {
			return fmt.Errorf("adding %s: %w", e.Path, err)
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := xz.Close(); err != nil {
		return err
	}
	elapsed := time.Since(start)

	index := w.Index()
	fmt.Printf("  written     %s, %s of content\n", ui.Items(len(index), "entry", "entries"), ui.Bytes(w.Bytes()))
	fmt.Printf("  compressed  %s -> %s in %s\n", ui.Bytes(w.Bytes()), ui.Bytes(int64(compressed.Len())), elapsed.Round(time.Millisecond))

	// xz -> tar -> disk, exactly as a restore does it.
	dest := filepath.Join(work, "restored")
	start = time.Now()

	reader, err := tool.XZReader(ctx, bytes.NewReader(compressed.Bytes()))
	if err != nil {
		return err
	}
	restored := make(map[string]archive.FileInfo)
	stats, err := archive.Extract(ctx, reader, archive.ExtractOptions{
		Dest:    dest,
		OnEntry: func(fi archive.FileInfo) { restored[fi.Path] = fi },
	})
	if err != nil {
		return fmt.Errorf("restoring: %w", err)
	}
	if err := reader.Close(); err != nil {
		return fmt.Errorf("the xz stream did not end cleanly: %w", err)
	}
	fmt.Printf("  restored    %s, %s in %s\n",
		ui.Items(stats.Files+stats.Dirs, "entry", "entries"), ui.Bytes(stats.Bytes), time.Since(start).Round(time.Millisecond))

	// The digests are what make this a real check rather than a smoke test.
	var problems []string
	for _, want := range index {
		got, ok := restored[want.Path]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s was not restored", want.Path))
			continue
		}
		if want.Kind != archive.KindFile {
			continue
		}
		if got.SHA256 != want.SHA256 {
			problems = append(problems, fmt.Sprintf("%s came back with a different digest", want.Path))
		}
		if got.Size != want.Size {
			problems = append(problems, fmt.Sprintf("%s came back as %d bytes, want %d", want.Path, got.Size, want.Size))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the round trip did not come back intact:\n  %s", strings.Join(problems, "\n  "))
	}
	fmt.Printf("  verified    every digest matches\n")

	fmt.Printf("\nOK – the embedded toolchain works on %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return nil
}

// buildFixture writes the awkward cases: an empty file, a non-ASCII name, a
// nested path, and enough incompressible data to prove the pipe streams rather
// than buffering.
func buildFixture(root string) ([]archive.Entry, error) {
	noise := make([]byte, 2<<20)
	if _, err := rand.Read(noise); err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"readme.md":            []byte("BOND selftest\n"),
		"empty.txt":            {},
		"Grüße/Kapitel 1.txt":  []byte(strings.Repeat("Wiederholung schrumpft schön. ", 4000)),
		"deep/a/b/c/noise.bin": noise,
	}

	entries := []archive.Entry{{Path: "deep", Kind: archive.KindDir, Mode: 0o755, ModTime: time.Now()}}
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(abs, content, 0o644); err != nil {
			return nil, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, err
		}
		entries = append(entries, archive.Entry{
			Path:    rel,
			Disk:    abs,
			Kind:    archive.KindFile,
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		})
	}
	return entries, nil
}
