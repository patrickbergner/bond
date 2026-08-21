package archive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ExtractOptions govern a restore.
type ExtractOptions struct {
	// Dest is the lexical root for archive entry names. Existing filesystem
	// links or redirections below it retain their ordinary operating-system
	// semantics.
	Dest string

	// Include, when set, selects which entries to restore. Everything else is
	// skipped without being read.
	Include func(archivePath string) bool

	// Overwrite replaces files that already exist at the destination.
	Overwrite bool

	// OnEntry, if set, is called for each entry restored.
	OnEntry func(FileInfo)

	// OnArchiveEntry observes every validated tar header, including entries
	// excluded from a partial restore.
	OnArchiveEntry func(FileInfo) error

	// OnArchiveFile observes every file after its bytes have been read and
	// hashed, including files excluded from a partial restore.
	OnArchiveFile func(FileInfo) error

	// OnWarning reports an entry that was skipped for a reason worth naming.
	OnWarning func(path, msg string)
}

// ExtractStats summarises a restore.
type ExtractStats struct {
	Files          int
	Dirs           int
	Skipped        int
	Bytes          int64
	MetadataIssues []MetadataIssue
	ArchiveFiles   int
	ArchiveDirs    int
	ArchiveBytes   int64
}

// MetadataIssue records directory metadata that could not be restored after
// all content had been extracted.
type MetadataIssue struct {
	Path      string
	Operation string
	Err       error
}

// Variables make the two best-effort directory metadata operations available
// to deterministic failure-injection tests. File metadata deliberately uses
// os directly because a file metadata failure must remain immediately fatal.
var (
	chmodDirectory   = os.Chmod
	chtimesDirectory = os.Chtimes
)

// Extract writes a tar stream into opts.Dest.
//
// Every name is checked before anything is created, and any name that fails
// aborts the whole restore rather than being skipped: an archive containing a
// path that tries to escape is not a backup with one bad entry, it is a
// backup that cannot be trusted.
func Extract(ctx context.Context, r io.Reader, opts ExtractOptions) (ExtractStats, error) {
	var stats ExtractStats

	dest, err := filepath.Abs(opts.Dest)
	if err != nil {
		return stats, err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return stats, err
	}

	// Directory modes and times are applied at the end, deepest first: a
	// directory restored read-only cannot have files written into it, and
	// creating a file updates its parent's mtime.
	type pending struct {
		path    string
		archive string
		mode    fs.FileMode
		modTime time.Time
	}
	var dirs []pending

	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return stats, fmt.Errorf("reading the archive: %w", err)
		}

		name := hdr.Name
		clean := trimSlash(name)

		target, err := SafeJoin(dest, name)
		if err != nil {
			return stats, fmt.Errorf("refusing to restore %q: %w", clean, err)
		}

		var archived FileInfo
		switch hdr.Typeflag {
		case tar.TypeDir:
			archived = FileInfo{Path: clean, Kind: KindDir, Mode: hdr.FileInfo().Mode(), ModTime: hdr.ModTime}
			stats.ArchiveDirs++
		case tar.TypeReg:
			archived = FileInfo{Path: clean, Kind: KindFile, Size: hdr.Size, Mode: hdr.FileInfo().Mode(), ModTime: hdr.ModTime}
			stats.ArchiveFiles++
			stats.ArchiveBytes += hdr.Size
		default:
			return stats, fmt.Errorf("refusing to restore %q: unsupported entry type %q", clean, hdr.Typeflag)
		}
		if opts.OnArchiveEntry != nil {
			if err := opts.OnArchiveEntry(archived); err != nil {
				return stats, err
			}
		}

		if opts.Include != nil && !opts.Include(clean) {
			stats.Skipped++
			if hdr.Typeflag == tar.TypeReg {
				digest := sha256.New()
				n, err := io.Copy(digest, tr)
				if err != nil {
					return stats, fmt.Errorf("reading excluded file %q: %w", clean, err)
				}
				archived.Size = n
				archived.SHA256 = hex.EncodeToString(digest.Sum(nil))
				if opts.OnArchiveFile != nil {
					if err := opts.OnArchiveFile(archived); err != nil {
						return stats, err
					}
				}
			}
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return stats, err
			}
			dirs = append(dirs, pending{target, clean, hdr.FileInfo().Mode(), hdr.ModTime})
			stats.Dirs++
			opts.entry(FileInfo{Path: clean, Kind: KindDir, Mode: hdr.FileInfo().Mode(), ModTime: hdr.ModTime})

		case tar.TypeReg:
			info, err := writeFile(target, tr, hdr, opts)
			if err != nil {
				return stats, err
			}
			info.Path = clean
			if opts.OnArchiveFile != nil {
				if err := opts.OnArchiveFile(info); err != nil {
					return stats, err
				}
			}
			stats.Files++
			stats.Bytes += info.Size
			opts.entry(info)

		}
	}

	// Both operations are attempted and reported separately: the restore is
	// marked incomplete rather than passing silently, which is the whole point.
	//
	// There is deliberately no "the archive recorded no value" guard. It reads
	// like one is needed and it would be dead code: a tar directory header
	// always carries ModeDir, so Mode is never zero, and a tar mtime round-trips
	// through a Unix timestamp, so an unset one comes back as the epoch rather
	// than the zero Time. Both guards existed here once and neither ever fired.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i].path) > len(dirs[j].path) })
	for _, d := range dirs {
		if err := chmodDirectory(d.path, d.mode.Perm()); err != nil {
			stats.MetadataIssues = append(stats.MetadataIssues, MetadataIssue{Path: d.archive, Operation: "permissions", Err: err})
			opts.warn(d.archive, "directory permissions were not restored: "+err.Error())
		}
		if err := chtimesDirectory(d.path, d.modTime, d.modTime); err != nil {
			stats.MetadataIssues = append(stats.MetadataIssues, MetadataIssue{Path: d.archive, Operation: "timestamps", Err: err})
			opts.warn(d.archive, "directory timestamps were not restored: "+err.Error())
		}
	}
	return stats, nil
}

func writeFile(target string, r io.Reader, hdr *tar.Header, opts ExtractOptions) (FileInfo, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return FileInfo{}, err
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if opts.Overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	mode := hdr.FileInfo().Mode().Perm()
	if mode == 0 {
		mode = 0o644
	}
	// Written with permissions that always allow the write itself; the
	// recorded mode is applied once the content is in place, so a read-only
	// file restores read-only without blocking its own restore.
	f, err := os.OpenFile(target, flags, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return FileInfo{}, fmt.Errorf("%s already exists; restore into an empty directory or allow overwriting", target)
		}
		return FileInfo{}, err
	}

	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, digest), r)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return FileInfo{}, fmt.Errorf("%s: %w", hdr.Name, err)
	}

	if err := os.Chmod(target, mode); err != nil {
		return FileInfo{}, err
	}
	if !hdr.ModTime.IsZero() {
		if err := os.Chtimes(target, hdr.ModTime, hdr.ModTime); err != nil {
			return FileInfo{}, err
		}
	}

	return FileInfo{
		Kind:    KindFile,
		Size:    n,
		Mode:    mode,
		ModTime: hdr.ModTime,
		SHA256:  hex.EncodeToString(digest.Sum(nil)),
	}, nil
}

func (o ExtractOptions) entry(info FileInfo) {
	if o.OnEntry != nil {
		o.OnEntry(info)
	}
}

func (o ExtractOptions) warn(path, msg string) {
	if o.OnWarning != nil {
		o.OnWarning(path, msg)
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
