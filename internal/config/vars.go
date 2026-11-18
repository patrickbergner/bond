package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Path variables usable in outputPath, workPath and key-slot paths.
const (
	VarToolDir   = "TOOL_DIR"   // directory holding the bond executable
	VarConfigDir = "CONFIG_DIR" // directory holding the control file
	VarHome      = "HOME"       // the user's home directory
	VarTargetID  = "TARGET_ID"  // id of the target being backed up
	VarDate      = "DATE"       // 2006-01-02
	VarTimestamp = "TIMESTAMP"  // 20060102-150405
)

// DateLayout and TimestampLayout are the formats behind {{DATE}} and
// {{TIMESTAMP}}. TimestampLayout sorts lexically and survives every filesystem.
const (
	DateLayout      = "2006-01-02"
	TimestampLayout = "20060102-150405"
)

var knownVars = []string{VarToolDir, VarConfigDir, VarHome, VarTargetID, VarDate, VarTimestamp}

// Vars are the values substituted into {{NAME}} placeholders.
type Vars map[string]string

// BaseVars resolves the variables that are the same for every target in a run,
// controlFile being the path of the control file read, or "" when there is none
// yet. Missing values are left out rather than guessed, so expanding a path that
// needs one reports a clear error instead of silently producing a wrong
// directory.
//
// TOOL_DIR follows symlinks to the real binary, so a link on the PATH does not
// move the portable layout. CONFIG_DIR deliberately does not: a control file
// linked in from a dotfiles repository should put its output where the operator
// sees the file, not inside that repository.
func BaseVars(controlFile string) Vars {
	v := Vars{}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		v[VarToolDir] = filepath.Dir(exe)
	}
	if controlFile != "" {
		if abs, err := filepath.Abs(controlFile); err == nil {
			v[VarConfigDir] = filepath.Dir(abs)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		v[VarHome] = home
	}
	return v
}

// ForTarget copies v with the per-target variables filled in.
func (v Vars) ForTarget(id string, at time.Time) Vars {
	out := make(Vars, len(v)+3)
	for k, val := range v {
		out[k] = val
	}
	out[VarTargetID] = id
	out[VarDate] = at.Format(DateLayout)
	out[VarTimestamp] = at.Format(TimestampLayout)
	return out
}

// CheckVars reports placeholders that BOND does not know, without needing any
// values. Load uses it so a misspelled {{TOOLDIR}} fails at parse time rather
// than halfway through a backup.
func CheckVars(s string) error {
	_, err := expand(s, nil, false)
	return err
}

// Expand substitutes every {{NAME}} placeholder in s.
func Expand(s string, vars Vars) (string, error) {
	return expand(s, vars, true)
}

func expand(s string, vars Vars, substitute bool) (string, error) {
	var b strings.Builder
	for {
		start := strings.Index(s, "{{")
		if start < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		end := strings.Index(s[start:], "}}")
		if end < 0 {
			return "", fmt.Errorf("unterminated %q placeholder", "{{")
		}
		end += start

		name := strings.TrimSpace(s[start+2 : end])
		if !oneOf(name, knownVars) {
			return "", fmt.Errorf("unknown placeholder {{%s}}; known: %s", name, strings.Join(sortedVars(), ", "))
		}
		b.WriteString(s[:start])
		if substitute {
			value, ok := vars[name]
			if !ok {
				return "", fmt.Errorf("{{%s}} cannot be resolved on this machine", name)
			}
			b.WriteString(value)
		}
		s = s[end+2:]
	}
}

func sortedVars() []string {
	out := append([]string(nil), knownVars...)
	sort.Strings(out)
	return out
}
