package backup

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/sevenzip"
)

// RestoreOptions describe one restore.
type RestoreOptions struct {
	Dest string

	Include       func(archivePath string) bool
	AllowSymlinks bool
	Overwrite     bool
	Tool          *sevenzip.Tool

	OnEntry   func(archive.FileInfo)
	OnWarning func(path, msg string)
}

// RestoreResult reports what came back.
type RestoreResult struct {
	Stats    archive.ExtractStats
	Elapsed  time.Duration
	Verified int
	Mismatch []string
}

// Restore writes a container's contents to disk.
//
// The order is the reverse of Create and just as strict: every shard is
// authenticated as it is read, so nothing that failed its tag ever reaches the
// decompressor, and every archive name is checked before a single file is
// created.
func Restore(ctx context.Context, r *container.Reader, opts RestoreOptions) (*RestoreResult, error) {
	started := time.Now()
	if !r.Unlocked() {
		return nil, fmt.Errorf("the container is locked")
	}

	if opts.Dest == "" {
		return nil, fmt.Errorf("no destination was given")
	}

	stream, err := r.Stream()
	if err != nil {
		return nil, err
	}

	source := stream
	var closer io.Closer
	if r.Manifest().Compression.Format == "xz" {
		if opts.Tool == nil {
			return nil, fmt.Errorf("this container is compressed but no 7-Zip is available")
		}
		decompressor, err := opts.Tool.XZReader(ctx, stream)
		if err != nil {
			return nil, err
		}
		source, closer = decompressor, decompressor
	}

	if err := checkCaseCollisions(r.Manifest().Index); err != nil {
		return nil, err
	}

	// Digests recorded at backup time are checked against what lands on disk,
	// which turns a restore into a verification of the same data path.
	want := make(map[string]string)
	for _, f := range r.Manifest().Index {
		if f.SHA256 != "" {
			want[f.Path] = f.SHA256
		}
	}

	result := &RestoreResult{}
	stats, err := archive.Extract(ctx, source, archive.ExtractOptions{
		Dest:          opts.Dest,
		Include:       opts.Include,
		AllowSymlinks: opts.AllowSymlinks,
		Overwrite:     opts.Overwrite,
		OnWarning:     opts.OnWarning,
		OnEntry: func(fi archive.FileInfo) {
			if opts.OnEntry != nil {
				opts.OnEntry(fi)
			}
			if expected, ok := want[fi.Path]; ok && fi.Kind == archive.KindFile {
				if expected == fi.SHA256 {
					result.Verified++
				} else {
					result.Mismatch = append(result.Mismatch, fi.Path)
				}
			}
		},
	})
	if err != nil {
		if closer != nil {
			closer.Close()
		}
		return nil, err
	}
	if closer != nil {
		if err := closer.Close(); err != nil {
			return nil, fmt.Errorf("the compressed stream did not end cleanly: %w", err)
		}
	}

	result.Stats = stats
	result.Elapsed = time.Since(started)
	if len(result.Mismatch) > 0 {
		return result, fmt.Errorf("%d restored files do not match the digests recorded when they were backed up: %s",
			len(result.Mismatch), strings.Join(truncate(result.Mismatch, 5), ", "))
	}
	return result, nil
}

// checkCaseCollisions refuses a restore whose entries cannot all coexist on this
// filesystem.
//
// A container written on Linux can hold Report.txt and report.txt. On Windows
// they are one file: without --overwrite the second one fails with "already
// exists", which is safe but says nothing about why, and with --overwrite the
// second silently wins and the restore reports two files where one exists. That
// is the quiet wrong answer this tool is built not to give, so it is refused
// before anything is written, which is the same rule the extraction path applies
// to a name that tries to escape.
//
// It needs the file index; a container written with storeFileIndex off is
// restored as before and the collision surfaces as the "already exists" error.
func checkCaseCollisions(index []archive.FileInfo) error {
	if !caseInsensitiveFS || len(index) == 0 {
		return nil
	}
	seen := make(map[string]string, len(index))
	for _, f := range index {
		folded := strings.ToLower(f.Path)
		if first, clash := seen[folded]; clash && first != f.Path {
			return fmt.Errorf("this container holds both %q and %q, which are the same file on this system; "+
				"restore it somewhere case is significant, or use --include to take one of them", first, f.Path)
		}
		seen[folded] = f.Path
	}
	return nil
}

// caseInsensitiveFS is where two names differing only in case are one file.
const caseInsensitiveFS = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

func truncate(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
}

// ListEntries returns the file index recorded in the manifest.
//
// It answers from a few hundred kilobytes of metadata rather than by
// decompressing the payload, which is the reason the index is stored at all.
func ListEntries(r *container.Reader) ([]archive.FileInfo, error) {
	if !r.Unlocked() {
		return nil, fmt.Errorf("the container is locked")
	}
	m := r.Manifest()
	if len(m.Index) == 0 && m.Files > 0 {
		return nil, fmt.Errorf("this container was written without a file index (storeFileIndex was off); restore it to see what is inside")
	}
	return m.Index, nil
}
