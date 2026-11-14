package archive

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

// A restore reads names that were written somewhere else, possibly years ago,
// possibly by someone who wanted them to land outside the destination
// directory. Everything below treats an archive name as untrusted input and
// decides, before a single byte is written, whether it may exist at all.
//
// The rule is lexical: an archive name must be below the selected destination.
// Existing filesystem redirections retain ordinary operating-system behavior.
// There is no sanitising fallback that quietly renames an unacceptable path.

// windowsReserved are device names MS-DOS still reserves. Creating one on
// Windows opens a device rather than a file.
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true,
	"com0": true, "com¹": true, "com²": true, "com³": true,
	"lpt0": true, "lpt¹": true, "lpt²": true, "lpt³": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// CheckName rejects any archive name a restore must not act on. It is
// deliberately independent of the destination and of the filesystem, so it can
// be run over a whole index before anything is created.
//
// It is a *restore* policy, not a format rule, because half of it depends on
// where the restore is happening: `com1` and `a:b` are ordinary names on POSIX
// and unusable on Windows. Nothing that decides whether a container can be
// opened may call this – see CheckPortableName.
func CheckName(name string) error {
	return checkName(name, runtime.GOOS == "windows")
}

// CheckPortableName applies only the rules that hold on every platform: a name
// that fails here is malformed wherever it is read.
//
// The distinction earns its keep in Manifest.Validate. Validating an index with
// CheckName would make a container's *openability* depend on the reader's
// operating system: a backup written on Linux containing `com1` would fail to
// unlock on Windows, so inspect, verify and list would all report the manifest
// as invalid rather than the one entry as unrestorable. A name Windows cannot
// create is a thing to refuse when creating it, which SafeJoin does, one entry
// at a time, with a message that names it.
func CheckPortableName(name string) error {
	return checkName(name, false)
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
		// Windows takes a device name whatever follows its first dot, and
		// ignores spaces before that dot: "NUL .txt" opens the device just as
		// "NUL.txt" does.
		stem, _, _ := strings.Cut(part, ".")
		if windowsReserved[strings.ToLower(strings.TrimRight(stem, " "))] {
			return fmt.Errorf("component %q is a reserved device name on Windows", part)
		}
	}
	return nil
}

// namesAreBytes is where a file name may be any byte string.
const namesAreBytes = runtime.GOOS == "linux"

// SafeJoin turns an archive name into a path under dest, or explains why it
// cannot. dest must already be absolute and cleaned.
func SafeJoin(dest, name string) (string, error) {
	if err := CheckName(name); err != nil {
		return "", err
	}
	// A name that is not UTF-8 exists as written only where names are bytes.
	// Windows would store something else under it and macOS refuses it, so it
	// is refused here by name rather than restored as a different file.
	if !namesAreBytes && !utf8.ValidString(name) {
		return "", fmt.Errorf("the name is not valid UTF-8, which this system cannot store; restore it on Linux, or leave it out with --include")
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
