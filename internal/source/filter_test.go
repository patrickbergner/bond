package source

import (
	"testing"

	"github.com/patrickbergner/bond/internal/config"
)

func mustFilter(t *testing.T, spec config.Source, opts Options) *Filter {
	t.Helper()
	f, err := NewFilterWith(spec, opts)
	if err != nil {
		t.Fatalf("NewFilterWith: %v", err)
	}
	return f
}

func TestFilterDefaultIsAllow(t *testing.T) {
	f := mustFilter(t, config.Source{Path: "/x"}, Options{})
	if v := f.File("a/b.txt"); !v.Include {
		t.Errorf("File(a/b.txt) = %+v, want included when no rules are set", v)
	}
	if v := f.Dir("a"); !v.Include {
		t.Errorf("Dir(a) = %+v, want included when no rules are set", v)
	}
}

func TestFilterIncludesFlipTheDefault(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:          "/x",
		IncludedPaths: []string{"conf/app.json"},
	}, Options{})

	if v := f.File("conf/app.json"); !v.Include {
		t.Errorf("the named file must be included: %+v", v)
	}
	if v := f.File("conf/other.json"); v.Include {
		t.Errorf("File(conf/other.json) = %+v, want excluded once an include list exists", v)
	}
	// The walk has to reach conf/ to find conf/app.json at all.
	if v := f.Dir("conf"); !v.Include {
		t.Errorf("Dir(conf) = %+v, want entered because it can contain the included file", v)
	}
	if v := f.Dir("logs"); v.Include {
		t.Errorf("Dir(logs) = %+v, want pruned because nothing under it can match", v)
	}
}

func TestFilterLiteralPathCoversSubtree(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:          "/x",
		ExcludedPaths: []string{"Docs/Archive"},
	}, Options{})

	if v := f.Dir("Docs/Archive"); v.Include {
		t.Errorf("the named directory must be pruned: %+v", v)
	}
	if v := f.File("Docs/Archive/notes.pdf"); v.Include {
		t.Errorf("everything under the named directory must be excluded: %+v", v)
	}
	if v := f.File("Docs/Archiveplan.pdf"); !v.Include {
		t.Errorf("a literal path must not act as a prefix: %+v", v)
	}
	if v := f.File("Docs/Video/a.mkv"); !v.Include {
		t.Errorf("an unrelated sibling must survive: %+v", v)
	}
}

func TestFilterPrefixIsAStringComparison(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:                 "/x",
		IncludedPathPrefixes: []string{"widget/conf"},
	}, Options{})

	if v := f.File("widget/conf/logging.properties"); !v.Include {
		t.Errorf("want included: %+v", v)
	}
	// Documented behaviour: a prefix is not path-aware.
	if v := f.File("widget/config.txt"); !v.Include {
		t.Errorf("a prefix must match on string boundaries, not path boundaries: %+v", v)
	}
	if v := f.File("widget/lib/x.so"); v.Include {
		t.Errorf("want excluded: %+v", v)
	}
	if v := f.Dir("widget"); !v.Include {
		t.Errorf("Dir(widget) = %+v, want entered on the way to the prefix", v)
	}
}

func TestFilterExclusionBeatsInclusion(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:                 "/x",
		IncludedPathPrefixes: []string{"widget/conf"},
		ExcludedPathPrefixes: []string{"widget/conf/management"},
	}, Options{})

	if v := f.File("widget/conf/logging.properties"); !v.Include {
		t.Errorf("want included: %+v", v)
	}
	if v := f.File("widget/conf/management/jmx.access"); v.Include {
		t.Errorf("an exclusion must win over an include: %+v", v)
	}
}

func TestFilterNameRules(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:                   "/x",
		ExcludedFileNames:      []string{"sound.properties"},
		ExcludedDirectoryNames: []string{"security"},
	}, Options{})

	if v := f.File("conf/sound.properties"); v.Include {
		t.Errorf("an excluded file name must match anywhere in the tree: %+v", v)
	}
	if v := f.File("deep/nested/conf/sound.properties"); v.Include {
		t.Errorf("an excluded file name must match at any depth: %+v", v)
	}
	if v := f.File("conf/sound.properties.bak"); !v.Include {
		t.Errorf("a name rule matches whole names only: %+v", v)
	}
	if v := f.Dir("conf/security"); v.Include {
		t.Errorf("an excluded directory name must prune: %+v", v)
	}
	if v := f.File("conf/security"); !v.Include {
		t.Errorf("excludedDirectoryNames must not touch files of the same name: %+v", v)
	}
}

func TestFilterPatterns(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:                 "/x",
		ExcludedPathPatterns: []string{`widget/legal/java\.base/[^/]+\.md$`},
	}, Options{})

	if v := f.File("widget/legal/java.base/LICENSE.md"); v.Include {
		t.Errorf("want excluded by pattern: %+v", v)
	}
	if v := f.File("widget/legal/java.base/LICENSE"); !v.Include {
		t.Errorf("want kept: %+v", v)
	}
	if v := f.File("widget/legal/java.base/sub/x.md"); !v.Include {
		t.Errorf("[^/]+ must not cross a path separator: %+v", v)
	}
}

func TestFilterPatternIncludesAlwaysDescend(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:                 "/x",
		IncludedPathPatterns: []string{`^\[2022-`},
	}, Options{})

	if v := f.File("[2022-07] Trip/img.jpg"); !v.Include {
		t.Errorf("want included: %+v", v)
	}
	if v := f.File("[2021-07] Trip/img.jpg"); v.Include {
		t.Errorf("want excluded: %+v", v)
	}
	// A regexp says nothing about where matches can live, so every directory
	// has to be looked at.
	if v := f.Dir("[2021-07] Trip"); !v.Include {
		t.Errorf("Dir must be entered when include patterns are in play: %+v", v)
	}
}

func TestFilterCaseInsensitive(t *testing.T) {
	spec := config.Source{
		Path:                 "/x",
		ExcludedPaths:        []string{"Café"},
		ExcludedFileNames:    []string{"Thumbs.db"},
		ExcludedPathPatterns: []string{`\.TMP$`},
	}

	ci := mustFilter(t, spec, Options{CaseInsensitive: true})
	if v := ci.Dir("café"); v.Include {
		t.Errorf("Windows matching must fold case: %+v", v)
	}
	if v := ci.File("a/thumbs.db"); v.Include {
		t.Errorf("name rules must fold case too: %+v", v)
	}
	if v := ci.File("a/b.tmp"); v.Include {
		t.Errorf("patterns must fold case too: %+v", v)
	}

	cs := mustFilter(t, spec, Options{CaseInsensitive: false})
	if v := cs.Dir("café"); !v.Include {
		t.Errorf("POSIX matching must stay case-sensitive: %+v", v)
	}
	if v := cs.File("a/b.tmp"); !v.Include {
		t.Errorf("POSIX pattern matching must stay case-sensitive: %+v", v)
	}
}

func TestFilterAcceptsBackslashesInRules(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:          "/x",
		ExcludedPaths: []string{`Docs\Video`},
	}, Options{})
	if v := f.File("Docs/Video/a.mkv"); v.Include {
		t.Errorf("a rule written with Windows separators must still match: %+v", v)
	}
}

func TestFilterReasonsNameTheRule(t *testing.T) {
	f := mustFilter(t, config.Source{
		Path:          "/x",
		ExcludedPaths: []string{"tmp"},
	}, Options{})
	v := f.File("tmp/a.txt")
	if v.Include {
		t.Fatalf("want excluded: %+v", v)
	}
	if want := `excludedPaths[0] "tmp"`; v.Reason != "excluded by "+want {
		t.Errorf("Reason = %q, want it to name %s", v.Reason, want)
	}
}

func TestNewFilterRejectsBadPattern(t *testing.T) {
	_, err := NewFilterWith(config.Source{Path: "/x", IncludedPathPatterns: []string{"("}}, Options{})
	if err == nil {
		t.Fatal("NewFilterWith succeeded on an invalid regular expression")
	}
}
