package source

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/config"
)

// Kind is what a walked entry is.
type Kind uint8

const (
	KindFile Kind = iota
	KindDir
)

func (k Kind) String() string {
	switch k {
	case KindDir:
		return "directory"
	default:
		return "file"
	}
}

// Entry is one materialized file or directory that will go into the container.
type Entry struct {
	Source   int    // index into the target's sources
	Abs      string // path on disk
	Rel      string // path relative to the source root, '/' separated
	Archive  string // path inside the archive, '/' separated
	Kind     Kind
	Size     int64
	Mode     fs.FileMode
	ModTime  time.Time
	Expected fs.FileInfo // identity the archive writer must observe after opening
}

// Spec is one prepared source: where to read, where it lands in the archive,
// and what to leave out.
type Spec struct {
	Index  int
	Root   string
	Prefix string
	Filter *Filter
}

// Stats summarises a walk.
type Stats struct {
	Files           int
	Dirs            int
	SkippedSymlinks int
	Bytes           int64

	ExcludedFiles int
	ExcludedDirs  int
}

// Total is the number of entries that will be stored.
func (s Stats) Total() int { return s.Files + s.Dirs }

// Walker enumerates the files a target contributes, in a stable order: sources
// in the order the control file lists them, and each tree sorted by name.
type Walker struct {
	// FollowSymlinks materializes what a link points at instead of omitting it.
	FollowSymlinks bool

	// OnDecision, if set, is called for every path considered, including the
	// ones filtered out. This is what --dry-run --verbose prints.
	OnDecision func(abs string, kind Kind, v Verdict)

	// OnProblem, if set, is consulted for every unreadable path. Returning nil
	// continues the walk; returning an error aborts it. A nil OnProblem aborts
	// on the first problem, because a backup that silently skips what it could
	// not read is worse than one that stops.
	OnProblem func(abs string, err error) error

	// OnWarning reports a link intentionally omitted by policy or loop cutoff.
	OnWarning func(path, msg string)
}

// Prepare turns a target into the specs a Walker consumes.
func Prepare(target *config.Target) ([]Spec, *Layout, error) {
	paths := make([]string, len(target.Sources))
	for i, s := range target.Sources {
		paths[i] = s.Path
	}
	layout, err := BuildLayout(paths)
	if err != nil {
		return nil, nil, err
	}

	specs := make([]Spec, len(target.Sources))
	for i, s := range target.Sources {
		filter, err := NewFilter(s)
		if err != nil {
			return nil, nil, fmt.Errorf("source %d (%s): %w", i+1, s.Path, err)
		}
		specs[i] = Spec{Index: i, Root: layout.Roots[i], Prefix: layout.Prefixes[i], Filter: filter}
	}
	return specs, layout, nil
}

// Walk calls fn for every entry that survives filtering.
func (w *Walker) Walk(specs []Spec, fn func(Entry) error) (Stats, error) {
	var stats Stats

	for _, spec := range specs {
		info, err := os.Lstat(spec.Root)
		if err != nil {
			if perr := w.problem(spec.Root, err); perr != nil {
				return stats, perr
			}
			continue
		}

		link := info.Mode()&fs.ModeSymlink != 0
		if link && !w.FollowSymlinks {
			stats.SkippedSymlinks++
			w.warn(spec.Root, "symlink skipped because followSymlinks is false")
			continue
		}
		if link {
			info, err = os.Stat(spec.Root)
			if err != nil {
				if isSymlinkLoop(err) {
					stats.SkippedSymlinks++
					w.warn(spec.Root, "symlink loop cut off; no archive entry was written")
					continue
				}
				if perr := w.problem(spec.Root, err); perr != nil {
					return stats, perr
				}
				stats.SkippedSymlinks++
				w.warn(spec.Root, "symlink target could not be read and was skipped")
				continue
			}
		}

		// A source may name a single file rather than a tree. A source-root link
		// goes through the same materialization decision as a nested one.
		if !info.IsDir() {
			info, err = snapshotFileInfo(spec.Root)
			if err != nil {
				if perr := w.problem(spec.Root, err); perr != nil {
					return stats, perr
				}
				continue
			}
			entry := Entry{
				Source:   spec.Index,
				Abs:      spec.Root,
				Rel:      "",
				Archive:  spec.Prefix,
				Kind:     KindFile,
				Size:     info.Size(),
				Mode:     info.Mode(),
				ModTime:  info.ModTime(),
				Expected: info,
			}
			stats.Files++
			stats.Bytes += info.Size()
			if err := fn(entry); err != nil {
				return stats, err
			}
			continue
		}

		root := Entry{
			Source:  spec.Index,
			Abs:     spec.Root,
			Rel:     "",
			Archive: spec.Prefix,
			Kind:    KindDir,
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}
		if root.Archive != "" {
			stats.Dirs++
			if err := fn(root); err != nil {
				return stats, err
			}
		}
		if err := w.walkDir(spec, spec.Root, "", []fs.FileInfo{info}, &stats, fn); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func (w *Walker) walkDir(spec Spec, absDir, relDir string, ancestry []fs.FileInfo, stats *Stats, fn func(Entry) error) error {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return w.problem(absDir, err)
	}

	for _, de := range entries {
		abs := filepath.Join(absDir, de.Name())
		rel := de.Name()
		if relDir != "" {
			rel = relDir + "/" + de.Name()
		}

		info, err := os.Lstat(abs)
		if err != nil {
			if perr := w.problem(abs, err); perr != nil {
				return perr
			}
			continue
		}

		link := info.Mode()&fs.ModeSymlink != 0
		if link {
			target, err := os.Stat(abs)
			if err != nil {
				// A dangling link has no resolved kind. Treat it as a file for
				// filtering so an explicit exclusion remains an ordinary exclusion.
				verdict := spec.Filter.File(rel)
				w.decide(abs, KindFile, verdict)
				if !verdict.Include {
					stats.ExcludedFiles++
					continue
				}
				if isSymlinkLoop(err) {
					stats.SkippedSymlinks++
					w.warn(abs, "symlink loop cut off; no archive entry was written")
					continue
				}
				if w.FollowSymlinks {
					if perr := w.problem(abs, err); perr != nil {
						return perr
					}
				}
				stats.SkippedSymlinks++
				w.warn(abs, "symlink target could not be read and was skipped")
				continue
			}
			info = target
		}
		kind := KindFile
		if info.IsDir() {
			kind = KindDir
		}

		if kind == KindDir {
			verdict := spec.Filter.Dir(rel)
			w.decide(abs, KindDir, verdict)
			if !verdict.Include {
				stats.ExcludedDirs++
				continue
			}
			if link && !w.FollowSymlinks {
				stats.SkippedSymlinks++
				w.warn(abs, "symlink skipped because followSymlinks is false")
				continue
			}
			loop := false
			for _, ancestor := range ancestry {
				if os.SameFile(info, ancestor) {
					loop = true
					break
				}
			}
			if loop {
				if link {
					stats.SkippedSymlinks++
				}
				w.warn(abs, "directory loop cut off; no archive entry was written")
				continue
			}
			stats.Dirs++
			if err := fn(Entry{
				Source:   spec.Index,
				Abs:      abs,
				Rel:      rel,
				Archive:  archivePath(spec.Prefix, rel),
				Kind:     KindDir,
				Mode:     info.Mode(),
				ModTime:  info.ModTime(),
				Expected: info,
			}); err != nil {
				return err
			}
			if err := w.walkDir(spec, abs, rel, append(append([]fs.FileInfo(nil), ancestry...), info), stats, fn); err != nil {
				return err
			}
			continue
		}

		verdict := spec.Filter.File(rel)
		w.decide(abs, kind, verdict)
		if !verdict.Include {
			stats.ExcludedFiles++
			continue
		}
		if link && !w.FollowSymlinks {
			stats.SkippedSymlinks++
			w.warn(abs, "symlink skipped because followSymlinks is false")
			continue
		}
		info, err = snapshotFileInfo(abs)
		if err != nil {
			if perr := w.problem(abs, err); perr != nil {
				return perr
			}
			continue
		}

		entry := Entry{
			Source:   spec.Index,
			Abs:      abs,
			Rel:      rel,
			Archive:  archivePath(spec.Prefix, rel),
			Kind:     kind,
			Mode:     info.Mode(),
			ModTime:  info.ModTime(),
			Expected: info,
		}
		entry.Size = info.Size()
		stats.Files++
		stats.Bytes += info.Size()
		if err := fn(entry); err != nil {
			return err
		}
	}
	return nil
}

// snapshotFileInfo obtains identity from an open handle. On Windows, path Stat
// defers loading the file ID until os.SameFile is called; the path could have
// been replaced by then. Handle-derived FileInfo freezes the enumerated target.
func snapshotFileInfo(path string) (fs.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func (w *Walker) warn(path, msg string) {
	if w.OnWarning != nil {
		w.OnWarning(path, msg)
	}
}

func (w *Walker) decide(abs string, kind Kind, v Verdict) {
	if w.OnDecision != nil {
		w.OnDecision(abs, kind, v)
	}
}

func (w *Walker) problem(abs string, err error) error {
	if w.OnProblem == nil {
		return fmt.Errorf("%s: %w", abs, err)
	}
	return w.OnProblem(abs, err)
}

func archivePath(prefix, rel string) string {
	switch {
	case prefix == "":
		return rel
	case rel == "":
		return prefix
	default:
		return prefix + "/" + strings.TrimPrefix(rel, "/")
	}
}
