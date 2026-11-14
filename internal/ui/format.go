// Package ui formats numbers and progress for the command line.
package ui

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/term"

	"github.com/patrickbergner/bond/internal/crypto"
)

// Path renders a file name for the terminal. Names in a backup are whatever was
// on the disk it came from, control characters included; on a terminal those
// are replaced, and in a pipe the name is passed through exactly, because a
// script reading "bond list" needs the real one.
func Path(name string) string {
	if !stdoutIsTerminal() {
		return name
	}
	return crypto.Printable(name)
}

var stdoutIsTerminal = sync.OnceValue(func() bool { return term.IsTerminal(int(os.Stdout.Fd())) })

// Bytes renders a size the way a person reads it: exact below a kibibyte,
// three significant digits above.
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	var suffix string
	for _, u := range units {
		value /= unit
		suffix = u
		if value < unit {
			break
		}
	}
	switch {
	case value < 10:
		return fmt.Sprintf("%.2f %s", value, suffix)
	case value < 100:
		return fmt.Sprintf("%.1f %s", value, suffix)
	default:
		return fmt.Sprintf("%.0f %s", value, suffix)
	}
}

// Count groups thousands so six-digit file counts stay readable.
func Count(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")

	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// Plural picks a suffix for n, for messages like "3 files" and "1 file".
func Plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// Items renders a count with its noun, e.g. "1 file" or "1,234 files".
func Items(n int, singular, plural string) string {
	return Count(n) + " " + Plural(n, singular, plural)
}
