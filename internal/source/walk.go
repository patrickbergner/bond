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
	KindSymlink
)

func (k Kind) String() string {
	switch k {
	case KindDir:
		return "directory"
	case KindSymlink:
		return "symlink"
	default:
		return "file"
	}
}

// Entry is one file, directory or symlink that will go into the container.
type Entry struct {
	Source  int    // index into the target's sources
	Abs     string // path on disk
	Rel     string // path relative to the source root, '/' separated
	Archive string // path inside the archive, '/' separated
	Kind    Kind
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
	Link    string // symlink target, when Kind is KindSymlink
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
	Files    int
	Dirs     int
	Symlinks int
	Bytes    int64

	ExcludedFiles int
	ExcludedDirs  int
}

// Total is the number of entries that will be stored.
func (s Stats) Total() int { return s.Files + s.Dirs + s.Symlinks }

// Walker enumerates the files a target contributes, in a stable order: sources
// in the order the control file lists them, and each tree sorted by name.
type Walker struct {
	// FollowSymlinks stores what a link points at instead of the link itself.
	FollowSymlinks bool

	// OnDecision, if set, is called for every path considered, including the
	// ones filtered out. This is what --dry-run --verbose prints.
	OnDecision func(abs string, kind Kind, v Verdict)

	// OnProblem, if set, is consulted for every unreadable path. Returning nil
	// continues the walk; returning an error aborts it. A nil OnProblem aborts
	// on the first problem, because a backup that silently skips what it could
	// not read is worse than one that stops.
	OnProblem func(abs string, err error) error

	visited map[string]bool
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
	w.visited = make(map[string]bool)

	for _, spec := range specs {
		info, err := os.Lstat(spec.Root)
		if err != nil {
			if perr := w.problem(spec.Root, err); perr != nil {
				return stats, perr
			}
			continue
		}

		// A source may name a single file rather than a tree.
		if !info.IsDir() {
			entry := Entry{
				Source:  spec.Index,
				Abs:     spec.Root,
				Rel:     "",
				Archive: spec.Prefix,
				Kind:    KindFile,
				Size:    info.Size(),
				Mode:    info.Mode(),
				ModTime: info.ModTime(),
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
		if err := w.walkDir(spec, spec.Root, "", &stats, fn); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func (w *Walker) walkDir(spec Spec, absDir, relDir string, stats *Stats, fn func(Entry) error) error {
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

		info, err := de.Info()
		if err != nil {
			if perr := w.problem(abs, err); perr != nil {
				return perr
			}
			continue
		}

		kind := KindFile
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			kind = KindSymlink
		case info.IsDir():
			kind = KindDir
		}

		if kind == KindSymlink && w.FollowSymlinks {
			// The exclusion is checked against the link itself before it is
			// resolved: a link excluded by name is excluded whether or not it
			// even points at anything, and a dangling link that was never
			// going to be stored should not fail the backup just because
			// following it is impossible.
			verdict := spec.Filter.File(rel)
			if !verdict.Include {
				w.decide(abs, KindSymlink, verdict)
				stats.ExcludedFiles++
				continue
			}

			target, err := os.Stat(abs)
			if err != nil {
				if perr := w.problem(abs, err); perr != nil {
					return perr
				}
				continue
			}
			info = target
			if target.IsDir() {
				kind = KindDir
			} else {
				kind = KindFile
			}
		}

		if kind == KindDir {
			verdict := spec.Filter.Dir(rel)
			w.decide(abs, KindDir, verdict)
			if !verdict.Include {
				stats.ExcludedDirs++
				continue
			}
			// Following links can turn a tree into a graph; each real directory
			// is walked once.
			if w.FollowSymlinks {
				real, err := filepath.EvalSymlinks(abs)
				if err == nil {
					if w.visited[real] {
						continue
					}
					w.visited[real] = true
				}
			}
			stats.Dirs++
			if err := fn(Entry{
				Source:  spec.Index,
				Abs:     abs,
				Rel:     rel,
				Archive: archivePath(spec.Prefix, rel),
				Kind:    KindDir,
				Mode:    info.Mode(),
				ModTime: info.ModTime(),
			}); err != nil {
				return err
			}
			if err := w.walkDir(spec, abs, rel, stats, fn); err != nil {
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

		entry := Entry{
			Source:  spec.Index,
			Abs:     abs,
			Rel:     rel,
			Archive: archivePath(spec.Prefix, rel),
			Kind:    kind,
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}
		if kind == KindSymlink {
			link, err := os.Readlink(abs)
			if err != nil {
				if perr := w.problem(abs, err); perr != nil {
					return perr
				}
				continue
			}
			entry.Link = link
			stats.Symlinks++
		} else {
			entry.Size = info.Size()
			stats.Files++
			stats.Bytes += info.Size()
		}
		if err := fn(entry); err != nil {
			return err
		}
	}
	return nil
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
