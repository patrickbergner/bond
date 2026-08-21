package backup

import (
	"context"
	"errors"
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

	Include   func(archivePath string) bool
	Overwrite bool
	Tool      *sevenzip.Tool

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

// ErrIncompleteRestore identifies a restore whose file data completed but
// whose directory metadata could not be reproduced exactly.
var ErrIncompleteRestore = errors.New("restore completed with metadata omissions")

type IncompleteRestoreError struct {
	Issues []archive.MetadataIssue
}

func (e *IncompleteRestoreError) Error() string {
	return fmt.Sprintf("%d directory metadata operations failed; restored data is present but the restore is incomplete", len(e.Issues))
}

func (e *IncompleteRestoreError) Unwrap() error { return ErrIncompleteRestore }

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
	switch r.Manifest().Compression.Format {
	case "xz":
		if opts.Tool == nil {
			return nil, fmt.Errorf("this container is compressed but no 7-Zip is available")
		}
		decompressor, err := opts.Tool.XZReader(ctx, stream)
		if err != nil {
			return nil, err
		}
		source, closer = decompressor, decompressor
	case "none":
		// The authenticated manifest says the stream is raw tar.
	default:
		return nil, fmt.Errorf("unsupported compression format %q", r.Manifest().Compression.Format)
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
	indexPosition := 0
	stats, err := archive.Extract(ctx, source, archive.ExtractOptions{
		Dest:      opts.Dest,
		Include:   opts.Include,
		Overwrite: opts.Overwrite,
		OnWarning: opts.OnWarning,
		OnArchiveEntry: func(actual archive.FileInfo) error {
			if !r.Manifest().IndexStored {
				return nil
			}
			if indexPosition >= len(r.Manifest().Index) {
				return fmt.Errorf("archive contains unexpected entry %q beyond the manifest index", actual.Path)
			}
			expected := r.Manifest().Index[indexPosition]
			indexPosition++
			if actual.Path != expected.Path || actual.Kind != expected.Kind || actual.Size != expected.Size ||
				actual.Mode.Perm() != expected.Mode.Perm() || !actual.ModTime.Equal(expected.ModTime) {
				return fmt.Errorf("archive entry %q does not match manifest index entry %q", actual.Path, expected.Path)
			}
			return nil
		},
		// Every file in the stream is hashed, including the ones a partial
		// restore excludes: a container is one sealed object and checking only
		// the slice asked for would leave the rest unexamined. A mismatch
		// anywhere is worth reporting.
		//
		// Verified counts only what was written, though. It is printed as
		// "N files match the digests recorded at backup time", and a file that
		// was never restored has nothing on disk to match.
		OnArchiveFile: func(fi archive.FileInfo) error {
			expected, ok := want[fi.Path]
			if !ok {
				return nil
			}
			if expected != fi.SHA256 {
				result.Mismatch = append(result.Mismatch, fi.Path)
				return nil
			}
			if opts.Include == nil || opts.Include(fi.Path) {
				result.Verified++
			}
			return nil
		},
		OnEntry: func(fi archive.FileInfo) {
			if opts.OnEntry != nil {
				opts.OnEntry(fi)
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
	if r.Manifest().IndexStored && indexPosition != len(r.Manifest().Index) {
		return result, fmt.Errorf("archive ended after %d entries, manifest index records %d", indexPosition, len(r.Manifest().Index))
	}
	if !r.Manifest().IndexStored && (stats.ArchiveFiles != r.Manifest().Files || stats.ArchiveDirs != r.Manifest().Dirs || stats.ArchiveBytes != r.Manifest().Bytes) {
		return result, fmt.Errorf("archive totals are %d files, %d directories and %d bytes; manifest records %d, %d and %d",
			stats.ArchiveFiles, stats.ArchiveDirs, stats.ArchiveBytes,
			r.Manifest().Files, r.Manifest().Dirs, r.Manifest().Bytes)
	}
	if len(result.Mismatch) > 0 {
		return result, fmt.Errorf("%d restored files do not match the digests recorded when they were backed up: %s",
			len(result.Mismatch), strings.Join(truncate(result.Mismatch, 5), ", "))
	}
	if len(stats.MetadataIssues) > 0 {
		return result, &IncompleteRestoreError{Issues: stats.MetadataIssues}
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
	if !m.IndexStored {
		return nil, fmt.Errorf("this container was written without a file index (storeFileIndex was off); restore it to see what is inside")
	}
	return m.Index, nil
}
