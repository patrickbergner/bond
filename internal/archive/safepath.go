package archive

import (
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// A restore reads names that were written somewhere else, possibly years ago,
// possibly by someone who wanted them to land outside the destination
// directory. Everything below treats an archive name as untrusted input and
// decides, before a single byte is written, whether it may exist at all.
//
// The rule is absolute: a restore writes inside its destination or it fails.
// There is no sanitising fallback that quietly renames an unacceptable path,
// because a backup silently restoring to the wrong place is worse than one
// that stops and says why.

// windowsReserved are device names MS-DOS still reserves. Creating one on
// Windows opens a device rather than a file.
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// CheckName rejects any archive name a restore must not act on. It is
// deliberately independent of the destination and of the filesystem, so it can
// be run over a whole index before anything is created.
func CheckName(name string) error {
	return checkName(name, runtime.GOOS == "windows")
}

func checkName(name string, windows bool) error {
	switch {
	case name == "":
		return fmt.Errorf("empty name")
	case strings.ContainsRune(name, 0):
		return fmt.Errorf("name contains a NUL byte")
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("absolute path")
	case strings.HasPrefix(name, `\\`):
		return fmt.Errorf("UNC path")
	}
	if len(name) >= 2 && name[1] == ':' {
		return fmt.Errorf("path names a drive")
	}

	for _, part := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		switch part {
		case "":
			return fmt.Errorf("empty path component")
		case ".":
			return fmt.Errorf("path component %q", ".")
		case "..":
			return fmt.Errorf("path escapes upwards with %q", "..")
		}
		if !windows {
			continue
		}
		// A backslash is an ordinary character on POSIX and a separator on
		// Windows, so a name holding one cannot be restored faithfully here.
		if strings.ContainsRune(part, '\\') {
			return fmt.Errorf("component %q contains a backslash, which is a separator on this platform", part)
		}
		if i := strings.IndexAny(part, `:*?"<>|`); i >= 0 {
			return fmt.Errorf("component %q contains %q, which Windows does not allow in a file name", part, part[i])
		}
		if strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") {
			return fmt.Errorf("component %q ends in a space or dot, which Windows silently strips", part)
		}
		stem, _, _ := strings.Cut(part, ".")
		if windowsReserved[strings.ToLower(stem)] {
			return fmt.Errorf("component %q is a reserved device name on Windows", part)
		}
	}
	return nil
}

// SafeJoin turns an archive name into a path under dest, or explains why it
// cannot. dest must already be absolute and cleaned.
func SafeJoin(dest, name string) (string, error) {
	if err := CheckName(name); err != nil {
		return "", err
	}
	full := filepath.Join(dest, filepath.FromSlash(strings.TrimSuffix(name, "/")))

	// Belt and braces: CheckName has already refused everything that could
	// climb out, but the answer here is what actually gets written, so it is
	// the thing worth proving.
	rel, err := filepath.Rel(dest, full)
	if err != nil {
		return "", fmt.Errorf("path escapes the destination")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the destination")
	}
	return full, nil
}

// CheckLink rejects a symlink whose target would point outside the
// destination. linkPath is the archive name of the link itself; target is what
// it points at, as stored.
//
// The check is lexical on purpose. Resolving through the filesystem would
// depend on what happens to exist at restore time, and an attacker who can
// choose both a link and its target can otherwise walk a restore out of its
// directory one component at a time.
func CheckLink(linkPath, target string) error {
	if target == "" {
		return fmt.Errorf("empty symlink target")
	}

	// Backslash is a separator on Windows and an ordinary character on POSIX,
	// and the target is normalised before anything is decided about it. Doing
	// this the other way round is a hole: on Windows a target of `\..` is
	// rooted at the current drive, and normalising it *after* the absolute
	// check turns it into "/.." – which path.Join then cleans to "/", quietly
	// absorbing the very component that made it dangerous.
	//
	// The rule is applied on every platform, not only on Windows. A container
	// travels, and a target that escapes on one system is not something to
	// restore faithfully on another.
	t := strings.ReplaceAll(target, `\`, "/")

	if strings.HasPrefix(t, "/") {
		return fmt.Errorf("symlink target %q is absolute", target)
	}
	if len(t) >= 2 && t[1] == ':' {
		return fmt.Errorf("symlink target %q names a drive", target)
	}

	dir := path.Dir(strings.TrimSuffix(linkPath, "/"))
	if dir == "." {
		dir = ""
	}
	resolved := path.Join(dir, t)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("symlink target %q points outside the destination", target)
	}
	return nil
}
