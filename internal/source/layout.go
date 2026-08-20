package source

import (
	"fmt"
	"runtime"
	"strings"
)

// Layout is the archive namespace for one target: where every source's files
// land inside the container.
//
// The rule is to keep the shape the operator sees on disk. Sources are stored
// relative to the longest common ancestor of their parent directories, so
// D:\Apps\Foo and D:\Apps\Bar become Foo/… and Bar/…, and a
// lone D:\Photos becomes Photos/… rather than losing its name.
//
// When the sources span Windows drives or UNC shares there is no common
// ancestor, and each root turns into a synthetic one – c_drive/…, d_drive/…,
// unc_server_share/… – so a restore can still tell them apart.
type Layout struct {
	Root      string   // common ancestor the prefixes are relative to; empty when Synthetic
	Synthetic bool     // true when sources span volumes and synthetic roots were used
	Roots     []string // cleaned absolute path per source
	Prefixes  []string // archive prefix per source, '/' separated, possibly ""
}

// BuildLayout computes the archive namespace for a target's source paths.
func BuildLayout(paths []string) (*Layout, error) {
	return buildLayout(paths, runtime.GOOS == "windows")
}

func buildLayout(paths []string, win bool) (*Layout, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no sources")
	}

	roots := make([]string, len(paths))
	vols := make([]string, len(paths))
	parts := make([][]string, len(paths))
	for i, p := range paths {
		clean, err := cleanAbs(p, win)
		if err != nil {
			return nil, err
		}
		roots[i] = clean
		vols[i], parts[i] = splitPath(clean, win)
	}

	if err := checkOverlap(roots, vols, parts, win); err != nil {
		return nil, err
	}

	l := &Layout{Roots: roots, Prefixes: make([]string, len(paths))}

	if sameVolume(vols, win) {
		parents := make([][]string, len(parts))
		for i, p := range parts {
			if len(p) > 0 {
				parents[i] = p[:len(p)-1]
			}
		}
		common := commonPrefix(parents, win)
		l.Root = joinPath(vols[0], common, win)
		for i := range parts {
			l.Prefixes[i] = strings.Join(parts[i][len(common):], "/")
		}
	} else {
		l.Synthetic = true
		for i := range parts {
			l.Prefixes[i] = joinArchive(syntheticRoot(vols[i]), parts[i])
		}
	}

	seen := make(map[string]int, len(l.Prefixes))
	for i, p := range l.Prefixes {
		key := p
		if win {
			key = strings.ToLower(key)
		}
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("sources %q and %q would both be stored at %q in the archive", roots[prev], roots[i], p)
		}
		seen[key] = i
	}
	return l, nil
}

func joinArchive(root string, parts []string) string {
	if len(parts) == 0 {
		return root
	}
	return root + "/" + strings.Join(parts, "/")
}

// checkOverlap refuses sources that contain one another. Backing a tree up
// twice under two names is never what was meant, and it would quietly double
// the container's size.
func checkOverlap(roots []string, vols []string, parts [][]string, win bool) error {
	for i := range roots {
		for j := range roots {
			if i == j || !eqPath(vols[i], vols[j], win) {
				continue
			}
			if len(parts[i]) == len(parts[j]) {
				if i < j && hasPrefixParts(parts[j], parts[i], win) {
					return fmt.Errorf("sources %q and %q are the same directory", roots[i], roots[j])
				}
				continue
			}
			if len(parts[i]) < len(parts[j]) && hasPrefixParts(parts[j], parts[i], win) {
				return fmt.Errorf("source %q is inside source %q; back it up once, or narrow one of them with filters", roots[j], roots[i])
			}
		}
	}
	return nil
}

func hasPrefixParts(p, prefix []string, win bool) bool {
	if len(prefix) > len(p) {
		return false
	}
	for i := range prefix {
		if !eqPath(p[i], prefix[i], win) {
			return false
		}
	}
	return true
}

func sameVolume(vols []string, win bool) bool {
	for _, v := range vols[1:] {
		if !eqPath(v, vols[0], win) {
			return false
		}
	}
	return true
}

func commonPrefix(lists [][]string, win bool) []string {
	if len(lists) == 0 {
		return nil
	}
	common := lists[0]
	for _, l := range lists[1:] {
		n := 0
		for n < len(common) && n < len(l) && eqPath(common[n], l[n], win) {
			n++
		}
		common = common[:n]
	}
	return common
}

func eqPath(a, b string, win bool) bool {
	if win {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// cleanAbs normalises a path without consulting the filesystem, so a control
// file can be inspected on a machine that does not have the tree.
func cleanAbs(p string, win bool) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("empty source path")
	}
	if win {
		q := strings.ReplaceAll(p, "/", `\`)
		vol := volumeName(q)
		rest := q[len(vol):]
		if !strings.HasPrefix(rest, `\`) {
			return "", fmt.Errorf("source path %q must be absolute", p)
		}
		// A rooted path with no volume, "/data/tools", is not absolute on
		// Windows: it silently binds to whatever the current drive happens to
		// be. A control file written for another machine would then back up
		// something nobody asked for, so it has to be named explicitly.
		if vol == "" {
			return "", fmt.Errorf("source path %q has no drive letter; on Windows a source must name its volume, as in C:\\data\\tools", p)
		}
		// rest is already backslash-separated windows-style, and the goal is
		// windows-style cleaning regardless of the OS this runs on, so slashes
		// are swapped by hand rather than with filepath.ToSlash, which converts
		// based on the runtime GOOS instead of the win flag.
		cleaned := strings.ReplaceAll(rest, `\`, "/")
		cleaned = cleanSlashPath(cleaned)
		return vol + strings.ReplaceAll(cleaned, "/", `\`), nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("source path %q must be absolute", p)
	}
	return cleanSlashPath(p), nil
}

// cleanSlashPath collapses separators and resolves . and .. lexically. It works
// on '/'-separated absolute paths only.
func cleanSlashPath(p string) string {
	var out []string
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, part)
		}
	}
	return "/" + strings.Join(out, "/")
}

// volumeName returns "C:" or `\\server\share`, matching filepath.VolumeName's
// Windows behaviour but available on every host.
func volumeName(p string) string {
	if len(p) >= 2 && p[1] == ':' {
		c := p[0] | 0x20
		if c >= 'a' && c <= 'z' {
			return p[:2]
		}
	}
	if len(p) >= 2 && (p[0] == '\\' || p[0] == '/') && (p[1] == '\\' || p[1] == '/') {
		rest := p[2:]
		sep := func(r byte) bool { return r == '\\' || r == '/' }
		i := 0
		for i < len(rest) && !sep(rest[i]) {
			i++
		}
		if i == 0 || i == len(rest) {
			return p
		}
		host := rest[:i]
		rest = rest[i+1:]
		j := 0
		for j < len(rest) && !sep(rest[j]) {
			j++
		}
		if j == 0 {
			return p
		}
		return `\\` + host + `\` + rest[:j]
	}
	return ""
}

func splitPath(clean string, win bool) (vol string, parts []string) {
	if win {
		vol = volumeName(clean)
		clean = clean[len(vol):]
	} else {
		vol = "/"
	}
	for _, part := range strings.FieldsFunc(clean, func(r rune) bool { return r == '/' || r == '\\' }) {
		parts = append(parts, part)
	}
	return vol, parts
}

func joinPath(vol string, parts []string, win bool) string {
	if win {
		if len(parts) == 0 {
			return vol + `\`
		}
		return vol + `\` + strings.Join(parts, `\`)
	}
	return "/" + strings.Join(parts, "/")
}

// syntheticRoot names a volume in a way that survives being restored onto a
// different machine: C: becomes c_drive, \\server\share becomes
// unc_server_share.
func syntheticRoot(vol string) string {
	if len(vol) == 2 && vol[1] == ':' {
		return strings.ToLower(vol[:1]) + "_drive"
	}
	name := strings.Trim(vol, `\/`)
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		default:
			return '_'
		}
	}, name)
	if name == "" {
		return "root"
	}
	return "unc_" + name
}
