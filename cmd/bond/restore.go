package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/backup"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/sevenzip"
	"github.com/patrickbergner/bond/internal/ui"
)

func runRestore(args []string) error {
	fs := newFlagSet("restore")
	var (
		dest      string
		includes  stringList
		overwrite bool
		verbose   bool
		keys      keyFlags
	)
	fs.StringVar(&dest, "to", "", "")
	fs.Var(&includes, "include", "")
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
	result, err := backup.Restore(rootCtx, r, backup.RestoreOptions{
		Dest:      dest,
		Include:   include,
		Overwrite: overwrite,
		Tool:      tool,
		OnEntry: func(fi archive.FileInfo) {
			progress.Add(fi.Size)
			if verbose {
				progress.Clear()
				fmt.Printf("  %s\n", ui.Path(fi.Path))
			}
		},
		OnWarning: func(path, msg string) {
			progress.Clear()
			fmt.Printf("  warning   %s: %s\n", path, msg)
		},
	})
	progress.Clear()
	if err != nil && result == nil {
		return err
	}

	// The summary is printed even when the restore failed, because what did
	// land on disk is worth knowing. The first word must not say otherwise:
	// "restored 40,000 files" above an error about digests that do not match is
	// the sentence someone remembers and the error the one they scroll past.
	status := "restored"
	switch {
	case errors.Is(err, backup.ErrIncompleteRestore):
		status = "incomplete"
	case err != nil:
		status = "FAILED"
	}
	fmt.Printf("%-11s %s, %s, %s in %s\n", status,
		ui.Items(result.Stats.Files, "file", "files"),
		ui.Items(result.Stats.Dirs, "directory", "directories"),
		ui.Bytes(result.Stats.Bytes),
		result.Elapsed.Round(time.Millisecond))
	if result.Stats.Skipped > 0 {
		fmt.Printf("skipped     %s\n", ui.Items(result.Stats.Skipped, "entry", "entries"))
	}
	if result.Verified > 0 {
		fmt.Printf("verified    %s the digests recorded at backup time\n", matches(result.Verified))
	}
	// The restore is whole, but the container it came from is not. Saying so
	// here is the only notice an operator gets before the next shard goes.
	if n := r.RecoveredShards(); n > 0 {
		fmt.Printf("damaged     %s could not be read and were rebuilt from the recovery data;\n", ui.Items(n, "shard", "shards"))
		fmt.Printf("            the container itself is still damaged – run: bond repair %s\n", operands[0])
	}
	return err
}

// matches agrees the verb with its count: "1 file matches", "2 files match".
func matches(n int) string {
	if n == 1 {
		return ui.Items(n, "file", "files") + " matches"
	}
	return ui.Items(n, "file", "files") + " match"
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
			fmt.Println(ui.Path(e.Path))
		case e.Kind == archive.KindDir:
			fmt.Printf("%-10s  %-19s  %s/\n", "", e.ModTime.Format(time.DateTime), ui.Path(e.Path))
		default:
			fmt.Printf("%10s  %-19s  %s\n", ui.Bytes(e.Size), e.ModTime.Format(time.DateTime), ui.Path(e.Path))
		}
	}
	return nil
}

// reportProvenance says on standard error what is known about who wrote a
// container that has just been unlocked. It is quiet only where the key used
// itself proves something: a passphrase or key file cannot be used to write a
// container without being known.
func reportProvenance(r *container.Reader, keys *keyFlags) {
	switch {
	case r.WriterChecked():
		fmt.Fprintf(os.Stderr, "note: signed by the expected writer %s\n", shortID(r.Signer()))
	case keys.allowUnencrypted:
		fmt.Fprintln(os.Stderr, "note: opened with the key stored in the container; it is unencrypted, and nothing proves who wrote it")
	case r.OpenedWith() == crypto.SlotRecipient && r.Signer() != nil:
		fmt.Fprintf(os.Stderr, "note: opened with a recovery key; the container says it is signed by writer %s, "+
			"which was not checked – give --expect-writer to check it\n", shortID(r.Signer()))
	case r.OpenedWith() == crypto.SlotRecipient:
		fmt.Fprintln(os.Stderr, "warning: opened with a recovery key, and the container is not signed. Anyone who has the "+
			"public key could have written it; restore it only if you trust where it came from")
	}
}

// shortID is the part of a writer fingerprint a person compares.
func shortID(id []byte) string {
	if len(id) < 8 {
		return fmt.Sprintf("%x", id)
	}
	return fmt.Sprintf("%x", id[:8])
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
	defer wipeUnlockers(secrets)
	if keys.allowExpensiveKDF {
		fmt.Fprintln(os.Stderr, "warning: --allow-expensive-kdf permits unauthenticated container data to request extreme memory or CPU")
	}
	opts, err := keys.unlockOptions()
	if err != nil {
		r.Close()
		return nil, err
	}
	if err := r.UnlockWithOptions(opts, secrets...); err != nil {
		r.Close()
		return nil, err
	}
	reportProvenance(r, keys)
	return r, nil
}
