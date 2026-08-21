// Package source turns a target's source specifications into the exact list of
// files that go into a container: filtering, the archive namespace, and the
// walk itself.
package source

import (
	"fmt"
	"path"
	"regexp"
	"runtime"
	"strings"

	"github.com/patrickbergner/bond/internal/config"
)

// Filter decides what a single source contributes. Every rule matches the
// source-relative path with '/' separators and no leading slash; the source
// root itself is the empty string.
//
// Precedence: an exclusion always wins. If any include list is non-empty the
// default flips to deny, so includes and excludes can be combined to mean
// "this subtree, except these bits".
type Filter struct {
	incPaths    []rule
	excPaths    []rule
	incPrefixes []rule
	excPrefixes []rule
	incPatterns []rule
	excPatterns []rule
	excFiles    []rule
	excDirs     []rule

	hasIncludes bool
	fold        bool
}

type rule struct {
	kind  string
	index int
	text  string // as written by the operator, for messages
	match string // normalised, for comparison
	re    *regexp.Regexp
}

func (r rule) String() string { return fmt.Sprintf("%s[%d] %q", r.kind, r.index, r.text) }

// Verdict is a filter decision plus the rule that produced it, so --dry-run can
// explain itself. On a directory, Include false means the whole subtree is
// pruned.
type Verdict struct {
	Include bool
	Reason  string
}

// Options tunes matching. The zero value follows the host platform.
type Options struct {
	// CaseInsensitive folds case before comparing, as Windows filesystems do.
	CaseInsensitive bool
}

// DefaultOptions matches the behaviour of the filesystem BOND is running on.
func DefaultOptions() Options {
	return Options{CaseInsensitive: runtime.GOOS == "windows"}
}

// NewFilter compiles one source's filter rules.
func NewFilter(spec config.Source) (*Filter, error) {
	return NewFilterWith(spec, DefaultOptions())
}

// NewFilterWith compiles one source's filter rules with explicit options.
func NewFilterWith(spec config.Source, opts Options) (*Filter, error) {
	f := &Filter{fold: opts.CaseInsensitive}

	f.incPaths = f.literalRules("includedPaths", spec.IncludedPaths)
	f.excPaths = f.literalRules("excludedPaths", spec.ExcludedPaths)
	f.incPrefixes = f.prefixRules("includedPathPrefixes", spec.IncludedPathPrefixes)
	f.excPrefixes = f.prefixRules("excludedPathPrefixes", spec.ExcludedPathPrefixes)
	f.excFiles = f.nameRules("excludedFileNames", spec.ExcludedFileNames)
	f.excDirs = f.nameRules("excludedDirectoryNames", spec.ExcludedDirectoryNames)

	var err error
	if f.incPatterns, err = f.patternRules("includedPathPatterns", spec.IncludedPathPatterns); err != nil {
		return nil, err
	}
	if f.excPatterns, err = f.patternRules("excludedPathPatterns", spec.ExcludedPathPatterns); err != nil {
		return nil, err
	}

	f.hasIncludes = len(f.incPaths)+len(f.incPrefixes)+len(f.incPatterns) > 0
	return f, nil
}

func (f *Filter) literalRules(kind string, list []string) []rule {
	out := make([]rule, 0, len(list))
	for i, text := range list {
		clean := path.Clean(toSlash(text))
		clean = strings.TrimPrefix(clean, "/")
		if clean == "." || clean == "" {
			continue
		}
		out = append(out, rule{kind: kind, index: i, text: text, match: f.key(clean)})
	}
	return out
}

// prefixRules keeps the operator's text verbatim apart from separators and
// case: a prefix is a string comparison, so "widget/conf" deliberately also
// covers "widget/config". Cleaning it would silently change that meaning.
func (f *Filter) prefixRules(kind string, list []string) []rule {
	out := make([]rule, 0, len(list))
	for i, text := range list {
		p := strings.TrimPrefix(toSlash(text), "./")
		if p == "" {
			continue
		}
		out = append(out, rule{kind: kind, index: i, text: text, match: f.key(p)})
	}
	return out
}

func (f *Filter) nameRules(kind string, list []string) []rule {
	out := make([]rule, 0, len(list))
	for i, text := range list {
		if text == "" {
			continue
		}
		out = append(out, rule{kind: kind, index: i, text: text, match: f.key(text)})
	}
	return out
}

func (f *Filter) patternRules(kind string, list []string) ([]rule, error) {
	out := make([]rule, 0, len(list))
	for i, text := range list {
		expr := text
		if f.fold {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("%s[%d] %q: %w", kind, i, text, err)
		}
		out = append(out, rule{kind: kind, index: i, text: text, re: re})
	}
	return out, nil
}

func toSlash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func (f *Filter) key(s string) string {
	if f.fold {
		return strings.ToLower(s)
	}
	return s
}

// File decides whether one resolved non-directory is stored.
func (f *Filter) File(rel string) Verdict {
	k := f.key(rel)
	if r, hit := f.excluded(k, false); hit {
		return Verdict{Include: false, Reason: "excluded by " + r.String()}
	}
	if !f.hasIncludes {
		return Verdict{Include: true, Reason: "no include rules, everything not excluded is taken"}
	}
	if r, hit := f.included(k); hit {
		return Verdict{Include: true, Reason: "included by " + r.String()}
	}
	return Verdict{Include: false, Reason: "no include rule matches"}
}

// Dir decides whether a directory is entered and stored. A false verdict
// prunes the whole subtree, so nothing inside is even looked at.
func (f *Filter) Dir(rel string) Verdict {
	if rel == "" {
		return Verdict{Include: true, Reason: "source root"}
	}
	k := f.key(rel)
	if r, hit := f.excluded(k, true); hit {
		return Verdict{Include: false, Reason: "excluded by " + r.String()}
	}
	if !f.hasIncludes {
		return Verdict{Include: true, Reason: "no include rules, everything not excluded is taken"}
	}
	if r, hit := f.included(k); hit {
		return Verdict{Include: true, Reason: "included by " + r.String()}
	}
	if r, hit := f.mayContainInclude(k); hit {
		return Verdict{Include: true, Reason: "may contain matches for " + r.String()}
	}
	return Verdict{Include: false, Reason: "no include rule can match anything below it"}
}

func (f *Filter) excluded(k string, isDir bool) (rule, bool) {
	for _, r := range f.excPaths {
		if k == r.match || strings.HasPrefix(k, r.match+"/") {
			return r, true
		}
	}
	for _, r := range f.excPrefixes {
		if strings.HasPrefix(k, r.match) {
			return r, true
		}
	}
	for _, r := range f.excPatterns {
		if r.re.MatchString(k) {
			return r, true
		}
	}
	names := f.excFiles
	if isDir {
		names = f.excDirs
	}
	if len(names) > 0 {
		base := k
		if i := strings.LastIndexByte(k, '/'); i >= 0 {
			base = k[i+1:]
		}
		for _, r := range names {
			if base == r.match {
				return r, true
			}
		}
	}
	return rule{}, false
}

func (f *Filter) included(k string) (rule, bool) {
	for _, r := range f.incPaths {
		if k == r.match || strings.HasPrefix(k, r.match+"/") {
			return r, true
		}
	}
	for _, r := range f.incPrefixes {
		if strings.HasPrefix(k, r.match) {
			return r, true
		}
	}
	for _, r := range f.incPatterns {
		if r.re.MatchString(k) {
			return r, true
		}
	}
	return rule{}, false
}

// mayContainInclude asks whether descending into a directory could still turn
// up a match. Without it, an include of "a/b/c.txt" would prune "a" before
// ever reaching the file it names.
func (f *Filter) mayContainInclude(dir string) (rule, bool) {
	under := dir + "/"
	for _, r := range f.incPaths {
		if strings.HasPrefix(r.match, under) {
			return r, true
		}
	}
	for _, r := range f.incPrefixes {
		if strings.HasPrefix(r.match, under) || strings.HasPrefix(under, r.match) {
			return r, true
		}
	}
	// A regular expression says nothing about the paths that could match it, so
	// the only safe answer is to look.
	if len(f.incPatterns) > 0 {
		return f.incPatterns[0], true
	}
	return rule{}, false
}
