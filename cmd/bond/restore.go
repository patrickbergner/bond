package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/backup"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/sevenzip"
	"github.com/patrickbergner/bond/internal/ui"
)

func runRestore(args []string) error {
	fs := newFlagSet("restore")
	var (
		dest      string
		includes  stringList
		symlinks  bool
		overwrite bool
		verbose   bool
		keys      keyFlags
	)
	fs.StringVar(&dest, "to", "", "")
	fs.Var(&includes, "include", "")
	fs.BoolVar(&symlinks, "symlinks", false, "")
	fs.BoolVar(&overwrite, "overwrite", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond restore <container.bond> --to <directory>

Writes a container's contents back to disk.

options:
      --to <dir>          directory to restore into
      --include <prefix>  restore only paths starting with this; repeat for several
      --symlinks          restore symbolic links (off by default)
      --overwrite         replace files that already exist
  -v, --verbose           name every file as it is written
%s
`, keyFlagHelp)
	}
	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("restore needs exactly one container to read")
	}
	if dest == "" {
		return badUsage("name a destination with --to")
	}

	r, err := openContainer(operands[0], &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	m := r.Manifest()

	var tool *sevenzip.Tool
	if m.Compression.Format == "xz" {
		tool, err = sevenzip.Shared()
		if err != nil {
			return err
		}
		defer tool.Close()
	}

	var include func(string) bool
	if len(includes) > 0 {
		prefixes := []string(includes)
		include = func(p string) bool {
			for _, prefix := range prefixes {
				if p == prefix || strings.HasPrefix(p, strings.TrimSuffix(prefix, "/")+"/") {
					return true
				}
			}
			return false
		}
	}

	fmt.Printf("container   %s\n", operands[0])
	fmt.Printf("holds       %s, %s, %s\n",
		ui.Items(m.Files, "file", "files"), ui.Items(m.Dirs, "directory", "directories"), ui.Bytes(m.Bytes))
	fmt.Printf("restoring   into %s\n", dest)

	progress := ui.NewProgress(os.Stderr)
	result, err := backup.Restore(context.Background(), r, backup.RestoreOptions{
		Dest:          dest,
		Include:       include,
		AllowSymlinks: symlinks,
		Overwrite:     overwrite,
		Tool:          tool,
		OnEntry: func(fi archive.FileInfo) {
			progress.Add(fi.Size)
			if verbose {
				progress.Clear()
				fmt.Printf("  %s\n", fi.Path)
			}
		},
		OnWarning: func(path, msg string) {
			progress.Clear()
			fmt.Printf("  warning   %s: %s\n", path, msg)
		},
	})
	progress.Clear()
	if err != nil {
		return err
	}

	fmt.Printf("restored    %s, %s, %s in %s\n",
		ui.Items(result.Stats.Files, "file", "files"),
		ui.Items(result.Stats.Dirs, "directory", "directories"),
		ui.Bytes(result.Stats.Bytes),
		result.Elapsed.Round(time.Millisecond))
	if result.Stats.Skipped > 0 {
		fmt.Printf("skipped     %s\n", ui.Items(result.Stats.Skipped, "entry", "entries"))
	}
	if result.Verified > 0 {
		fmt.Printf("verified    %s match the digests recorded at backup time\n", ui.Items(result.Verified, "file", "files"))
	}
	return nil
}

func runList(args []string) error {
	fs := newFlagSet("list")
	var (
		long bool
		keys keyFlags
	)
	fs.BoolVar(&long, "long", false, "")
	fs.BoolVar(&long, "l", false, "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond list <container.bond>

Lists what a container holds, from the manifest – nothing is decompressed.

options:
  -l, --long   show size and modification time
%s
`, keyFlagHelp)
	}
	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("list needs exactly one container to read")
	}

	r, err := openContainer(operands[0], &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	entries, err := backup.ListEntries(r)
	if err != nil {
		return err
	}
	for _, e := range entries {
		switch {
		case !long:
			fmt.Println(e.Path)
		case e.Kind == archive.KindDir:
			fmt.Printf("%-10s  %-19s  %s/\n", "", e.ModTime.Format(time.DateTime), e.Path)
		case e.Kind == archive.KindSymlink:
			fmt.Printf("%-10s  %-19s  %s -> %s\n", "", e.ModTime.Format(time.DateTime), e.Path, e.Link)
		default:
			fmt.Printf("%10s  %-19s  %s\n", ui.Bytes(e.Size), e.ModTime.Format(time.DateTime), e.Path)
		}
	}
	return nil
}

// openContainer opens and unlocks a container, asking only for the kinds of
// key it actually has.
func openContainer(path string, keys *keyFlags) (*container.Reader, error) {
	r, err := container.Open(path)
	if err != nil {
		return nil, err
	}
	secrets, err := keys.unlockersFor(r.Slots())
	if err != nil {
		r.Close()
		return nil, err
	}
	if err := r.Unlock(secrets...); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}
