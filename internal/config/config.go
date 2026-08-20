// Package config loads and validates the BOND control file.
//
// Every field is optional except the targets and their source paths; anything
// left out falls back to Defaults. Settings resolve in three layers – built-in
// defaults, the global settings block, then a target's own settings – so a
// target can say compressionLevel 0 for a tree of video files without
// restating the rest.
//
// Unknown JSON keys are a load error. A typo in a filter name would otherwise
// silently widen a backup, which is the one class of mistake nobody notices
// until a restore.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Encryption methods, the primary key slot of a container.
const (
	EncryptionNone       = "NONE"
	EncryptionPassphrase = "PROMPT_KEYPHRASE"
	EncryptionKeyfile    = "KEYFILE"
	EncryptionRecipient  = "RECIPIENT"
)

// Sidecar hash algorithms.
const (
	HashNone   = "NONE"
	HashSHA256 = "SHA256"
	HashSHA384 = "SHA384"
	HashSHA512 = "SHA512"
)

// Key slot types.
const (
	SlotPassphrase = "passphrase"
	SlotKeyfile    = "keyfile"
	SlotRecipient  = "recipient"
)

// DefaultFileName is looked for when --config is not given.
const DefaultFileName = "config.json"

var (
	encryptionMethods = []string{EncryptionNone, EncryptionPassphrase, EncryptionKeyfile, EncryptionRecipient}
	hashAlgorithms    = []string{HashNone, HashSHA256, HashSHA384, HashSHA512}
	slotTypes         = []string{SlotPassphrase, SlotKeyfile, SlotRecipient}

	targetIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Config is the whole control file.
type Config struct {
	Schema   string   `json:"$schema,omitempty"`
	Targets  []Target `json:"targets"`
	Settings Settings `json:"settings"`
}

// Target is one container: a set of source trees backed up together.
type Target struct {
	ID       string    `json:"id"`
	Skip     bool      `json:"skip,omitempty"`
	Sources  []Source  `json:"sources"`
	Settings *Settings `json:"settings,omitempty"`

	effective Resolved
}

// Effective returns the target's settings with defaults and the global block
// already folded in. Valid only on a Config that came from Parse or Load.
func (t *Target) Effective() Resolved { return t.effective }

// Source is one directory tree plus the filters applied to it. Every filter
// matches the source-relative path with '/' separators.
type Source struct {
	Path                   string   `json:"path"`
	IncludedPaths          []string `json:"includedPaths,omitempty"`
	ExcludedPaths          []string `json:"excludedPaths,omitempty"`
	IncludedPathPrefixes   []string `json:"includedPathPrefixes,omitempty"`
	ExcludedPathPrefixes   []string `json:"excludedPathPrefixes,omitempty"`
	IncludedPathPatterns   []string `json:"includedPathPatterns,omitempty"`
	ExcludedPathPatterns   []string `json:"excludedPathPatterns,omitempty"`
	ExcludedFileNames      []string `json:"excludedFileNames,omitempty"`
	ExcludedDirectoryNames []string `json:"excludedDirectoryNames,omitempty"`
}

// Settings is the raw settings block. Every field is a pointer so that "absent"
// stays distinguishable from an explicit zero – a target override of
// compressionLevel 0 has to survive the merge.
type Settings struct {
	CompressionLevel *int      `json:"compressionLevel,omitempty"`
	EncryptionMethod *string   `json:"encryptionMethod,omitempty"`
	KeySlots         []KeySlot `json:"keySlots,omitempty"`
	RecoveryPercent  *int      `json:"recoveryPercent,omitempty"`
	ShardBytes       *int64    `json:"shardBytes,omitempty"`
	MaxVolumeBytes   *int64    `json:"maxVolumeBytes,omitempty"`
	HashAlgorithm    *string   `json:"hashAlgorithm,omitempty"`
	StoreFileIndex   *bool     `json:"storeFileIndex,omitempty"`
	FollowSymlinks   *bool     `json:"followSymlinks,omitempty"`
	OutputPath       *string   `json:"outputPath,omitempty"`
	WorkPath         *string   `json:"workPath,omitempty"`
}

// KeySlot is an additional way to unlock a container.
type KeySlot struct {
	Type      string `json:"type"`
	Path      string `json:"path,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	Label     string `json:"label,omitempty"`
}

// Resolved is a settings block with every value present.
type Resolved struct {
	CompressionLevel int
	EncryptionMethod string
	KeySlots         []KeySlot
	RecoveryPercent  int
	ShardBytes       int64
	MaxVolumeBytes   int64
	HashAlgorithm    string
	StoreFileIndex   bool
	FollowSymlinks   bool
	OutputPath       string
	WorkPath         string
}

// Defaults are the built-in settings, used for anything the control file omits.
func Defaults() Resolved {
	return Resolved{
		CompressionLevel: 5,
		EncryptionMethod: EncryptionPassphrase,
		RecoveryPercent:  10,
		ShardBytes:       4 << 20,
		MaxVolumeBytes:   0,
		HashAlgorithm:    HashSHA384,
		StoreFileIndex:   true,
		FollowSymlinks:   false,
		OutputPath:       "{{TOOL_DIR}}/output",
		WorkPath:         "{{TOOL_DIR}}/work",
	}
}

// Error reports every problem found in one control file rather than only the
// first, so a bad config can be fixed in a single pass.
type Error struct {
	Path     string
	Problems []string
}

func (e *Error) Error() string {
	var b strings.Builder
	if e.Path != "" {
		fmt.Fprintf(&b, "%s: ", e.Path)
	}
	fmt.Fprintf(&b, "%d problem", len(e.Problems))
	if len(e.Problems) != 1 {
		b.WriteByte('s')
	}
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p)
	}
	return b.String()
}

// Load reads and validates a control file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		var ve *Error
		if errors.As(err, &ve) {
			ve.Path = path
		}
		return nil, err
	}
	return cfg, nil
}

// Parse validates control-file bytes and resolves every target's settings.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing control file: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err == nil {
		return nil, fmt.Errorf("parsing control file: trailing content after the top-level object")
	}

	var problems []string
	if len(cfg.Targets) == 0 {
		problems = append(problems, "targets: at least one target is required")
	}

	base := Defaults()
	problems = append(problems, validateSettings("settings", &cfg.Settings)...)
	global := merge(base, &cfg.Settings)

	seen := make(map[string]int, len(cfg.Targets))
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		where := fmt.Sprintf("targets[%d]", i)
		if t.ID != "" {
			where = fmt.Sprintf("target %q", t.ID)
		}

		switch {
		case t.ID == "":
			problems = append(problems, fmt.Sprintf("targets[%d]: id is required", i))
		case !targetIDPattern.MatchString(t.ID):
			problems = append(problems, fmt.Sprintf("%s: id must start with a letter or digit and hold only letters, digits, '.', '_' or '-' (it becomes a file name)", where))
		default:
			if prev, dup := seen[strings.ToLower(t.ID)]; dup {
				problems = append(problems, fmt.Sprintf("%s: duplicate id, already used by targets[%d]", where, prev))
			} else {
				seen[strings.ToLower(t.ID)] = i
			}
		}

		if len(t.Sources) == 0 {
			problems = append(problems, fmt.Sprintf("%s: at least one source is required", where))
		}
		for j := range t.Sources {
			problems = append(problems, validateSource(fmt.Sprintf("%s: sources[%d]", where, j), &t.Sources[j])...)
		}

		problems = append(problems, validateSettings(where+": settings", t.Settings)...)
		t.effective = merge(global, t.Settings)
	}

	if len(problems) > 0 {
		return nil, &Error{Problems: problems}
	}
	return &cfg, nil
}

// Target finds a target by id, case-insensitively.
func (c *Config) Target(id string) (*Target, bool) {
	for i := range c.Targets {
		if strings.EqualFold(c.Targets[i].ID, id) {
			return &c.Targets[i], true
		}
	}
	return nil, false
}

// Selected returns the targets to run: those named in ids, or every target not
// marked skip when ids is empty. Order follows the control file.
func (c *Config) Selected(ids []string) ([]*Target, error) {
	if len(ids) == 0 {
		var out []*Target
		for i := range c.Targets {
			if !c.Targets[i].Skip {
				out = append(out, &c.Targets[i])
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("every target is marked skip; name one explicitly with --target")
		}
		return out, nil
	}

	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[strings.ToLower(id)] = true
	}
	var out []*Target
	for i := range c.Targets {
		if wanted[strings.ToLower(c.Targets[i].ID)] {
			out = append(out, &c.Targets[i])
			delete(wanted, strings.ToLower(c.Targets[i].ID))
		}
	}
	if len(wanted) > 0 {
		missing := make([]string, 0, len(wanted))
		for id := range wanted {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("no such target: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

func validateSource(where string, s *Source) []string {
	var problems []string
	if strings.TrimSpace(s.Path) == "" {
		problems = append(problems, where+": path is required")
	} else if !isAbs(s.Path) {
		problems = append(problems, fmt.Sprintf("%s: path %q must be absolute", where, s.Path))
	}

	for _, f := range []struct {
		name string
		list []string
	}{
		{"includedPathPatterns", s.IncludedPathPatterns},
		{"excludedPathPatterns", s.ExcludedPathPatterns},
	} {
		for _, pat := range f.list {
			if _, err := regexp.Compile(pat); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s: %q is not a valid regular expression: %v", where, f.name, pat, err))
			}
		}
	}

	for _, f := range []struct {
		name string
		list []string
	}{
		{"excludedFileNames", s.ExcludedFileNames},
		{"excludedDirectoryNames", s.ExcludedDirectoryNames},
	} {
		for _, n := range f.list {
			if n == "" {
				problems = append(problems, fmt.Sprintf("%s: %s: empty name", where, f.name))
			} else if strings.ContainsAny(n, `/\`) {
				problems = append(problems, fmt.Sprintf("%s: %s: %q is a path, not a name – use excludedPaths or excludedPathPrefixes", where, f.name, n))
			}
		}
	}

	for _, f := range []struct {
		name string
		list []string
	}{
		{"includedPaths", s.IncludedPaths},
		{"excludedPaths", s.ExcludedPaths},
		{"includedPathPrefixes", s.IncludedPathPrefixes},
		{"excludedPathPrefixes", s.ExcludedPathPrefixes},
	} {
		for _, p := range f.list {
			if strings.TrimSpace(p) == "" {
				problems = append(problems, fmt.Sprintf("%s: %s: empty entry", where, f.name))
				continue
			}
			if isAbs(p) {
				problems = append(problems, fmt.Sprintf("%s: %s: %q must be relative to the source path", where, f.name, p))
			}
		}
	}
	return problems
}

// isAbs accepts a path that is absolute under either convention, so a control
// file written for one platform still validates on another. Checking a Windows
// backup plan from a Linux box is a normal thing to want to do.
func isAbs(p string) bool {
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return strings.HasPrefix(p, `\\`)
}

func validateSettings(where string, s *Settings) []string {
	if s == nil {
		return nil
	}
	var problems []string

	if s.CompressionLevel != nil && (*s.CompressionLevel < 0 || *s.CompressionLevel > 9) {
		problems = append(problems, fmt.Sprintf("%s: compressionLevel %d is outside 0..9", where, *s.CompressionLevel))
	}
	if s.EncryptionMethod != nil && !oneOf(*s.EncryptionMethod, encryptionMethods) {
		problems = append(problems, fmt.Sprintf("%s: encryptionMethod %q must be one of %s", where, *s.EncryptionMethod, strings.Join(encryptionMethods, ", ")))
	}
	if s.HashAlgorithm != nil && !oneOf(*s.HashAlgorithm, hashAlgorithms) {
		problems = append(problems, fmt.Sprintf("%s: hashAlgorithm %q must be one of %s", where, *s.HashAlgorithm, strings.Join(hashAlgorithms, ", ")))
	}
	if s.RecoveryPercent != nil && (*s.RecoveryPercent < 0 || *s.RecoveryPercent > 50) {
		problems = append(problems, fmt.Sprintf("%s: recoveryPercent %d is outside 0..50", where, *s.RecoveryPercent))
	}
	if s.ShardBytes != nil {
		v := *s.ShardBytes
		switch {
		case v < 64<<10 || v > 256<<20:
			problems = append(problems, fmt.Sprintf("%s: shardBytes %d is outside 65536..268435456", where, v))
		case v%4096 != 0:
			problems = append(problems, fmt.Sprintf("%s: shardBytes %d must be a multiple of 4096", where, v))
		}
	}
	if s.MaxVolumeBytes != nil {
		v := *s.MaxVolumeBytes
		if v != 0 && v < 1<<20 {
			problems = append(problems, fmt.Sprintf("%s: maxVolumeBytes %d is too small; use 0 for a single file or at least 1 MiB", where, v))
		}
	}
	for i, slot := range s.KeySlots {
		at := fmt.Sprintf("%s: keySlots[%d]", where, i)
		if !oneOf(slot.Type, slotTypes) {
			problems = append(problems, fmt.Sprintf("%s: type %q must be one of %s", at, slot.Type, strings.Join(slotTypes, ", ")))
			continue
		}
		switch slot.Type {
		case SlotKeyfile:
			if slot.Path == "" {
				problems = append(problems, at+": type keyfile needs a path")
			}
			if slot.PublicKey != "" {
				problems = append(problems, at+": type keyfile takes no publicKey")
			}
		case SlotRecipient:
			if slot.PublicKey == "" {
				problems = append(problems, at+": type recipient needs a publicKey")
			}
			if slot.Path != "" {
				problems = append(problems, at+": type recipient takes no path")
			}
		case SlotPassphrase:
			if slot.Path != "" || slot.PublicKey != "" {
				problems = append(problems, at+": type passphrase takes neither path nor publicKey")
			}
		}
	}

	for _, f := range []struct {
		name  string
		value *string
	}{
		{"outputPath", s.OutputPath},
		{"workPath", s.WorkPath},
	} {
		if f.value == nil {
			continue
		}
		if strings.TrimSpace(*f.value) == "" {
			problems = append(problems, fmt.Sprintf("%s: %s must not be empty", where, f.name))
			continue
		}
		if err := CheckVars(*f.value); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %s: %v", where, f.name, err))
		}
	}
	for i, slot := range s.KeySlots {
		if slot.Path == "" {
			continue
		}
		if err := CheckVars(slot.Path); err != nil {
			problems = append(problems, fmt.Sprintf("%s: keySlots[%d]: path: %v", where, i, err))
		}
	}
	return problems
}

func oneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func merge(base Resolved, s *Settings) Resolved {
	if s == nil {
		return base
	}
	out := base
	if s.CompressionLevel != nil {
		out.CompressionLevel = *s.CompressionLevel
	}
	if s.EncryptionMethod != nil {
		out.EncryptionMethod = *s.EncryptionMethod
	}
	if s.KeySlots != nil {
		out.KeySlots = append([]KeySlot(nil), s.KeySlots...)
	}
	if s.RecoveryPercent != nil {
		out.RecoveryPercent = *s.RecoveryPercent
	}
	if s.ShardBytes != nil {
		out.ShardBytes = *s.ShardBytes
	}
	if s.MaxVolumeBytes != nil {
		out.MaxVolumeBytes = *s.MaxVolumeBytes
	}
	if s.HashAlgorithm != nil {
		out.HashAlgorithm = *s.HashAlgorithm
	}
	if s.StoreFileIndex != nil {
		out.StoreFileIndex = *s.StoreFileIndex
	}
	if s.FollowSymlinks != nil {
		out.FollowSymlinks = *s.FollowSymlinks
	}
	if s.OutputPath != nil {
		out.OutputPath = *s.OutputPath
	}
	if s.WorkPath != nil {
		out.WorkPath = *s.WorkPath
	}
	return out
}
