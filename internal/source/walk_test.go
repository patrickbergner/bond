package source

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/config"
)

// tree writes a small fixture and returns its root.
func tree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "tools")
	files := map[string]string{
		"readme.md":                  "hello",
		"conf/app.json":              "{}",
		"conf/sound.properties":      "x",
		"conf/management/jmx.access": "y",
		"conf/security/keystore":     "z",
		"lib/native.so":              "binary",
	}
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func walk(t *testing.T, spec config.Source, w *Walker) ([]Entry, Stats) {
	t.Helper()
	target := &config.Target{ID: "test", Sources: []config.Source{spec}}
	specs, _, err := Prepare(target)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if w == nil {
		w = &Walker{}
	}
	var got []Entry
	stats, err := w.Walk(specs, func(e Entry) error {
		got = append(got, e)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return got, stats
}

func archivePaths(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Archive
		if e.Kind == KindDir {
			out[i] += "/"
		}
	}
	return out
}

func TestWalkUnfiltered(t *testing.T) {
	root := tree(t)
	entries, stats := walk(t, config.Source{Path: root}, nil)

	want := []string{
		"tools/",
		"tools/conf/",
		"tools/conf/app.json",
		"tools/conf/management/",
		"tools/conf/management/jmx.access",
		"tools/conf/security/",
		"tools/conf/security/keystore",
		"tools/conf/sound.properties",
		"tools/empty/",
		"tools/lib/",
		"tools/lib/native.so",
		"tools/readme.md",
	}
	got := archivePaths(entries)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("walked:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if stats.Files != 6 {
		t.Errorf("Files = %d, want 6", stats.Files)
	}
	if stats.Dirs != 6 {
		t.Errorf("Dirs = %d, want 6 (the source root, conf, management, security, empty, lib)", stats.Dirs)
	}
	if stats.Bytes != int64(len("hello")+len("{}")+len("x")+len("y")+len("z")+len("binary")) {
		t.Errorf("Bytes = %d, want the sum of the fixture's file sizes", stats.Bytes)
	}
}

func TestWalkIsDeterministic(t *testing.T) {
	root := tree(t)
	first, _ := walk(t, config.Source{Path: root}, nil)
	second, _ := walk(t, config.Source{Path: root}, nil)
	if strings.Join(archivePaths(first), "\n") != strings.Join(archivePaths(second), "\n") {
		t.Error("two walks of the same tree produced different orders")
	}
	if !sort.SliceIsSorted(first, func(i, j int) bool { return first[i].Archive < first[j].Archive }) {
		t.Errorf("entries are not in lexical order: %v", archivePaths(first))
	}
}

func TestWalkPrunesExcludedDirectories(t *testing.T) {
	root := tree(t)
	entries, stats := walk(t, config.Source{
		Path:                   root,
		ExcludedDirectoryNames: []string{"security"},
		ExcludedFileNames:      []string{"sound.properties"},
	}, nil)

	for _, e := range entries {
		if strings.Contains(e.Archive, "security") || strings.Contains(e.Archive, "sound.properties") {
			t.Errorf("%q should have been filtered out", e.Archive)
		}
	}
	if stats.ExcludedDirs != 1 {
		t.Errorf("ExcludedDirs = %d, want 1", stats.ExcludedDirs)
	}
	// The pruned directory's contents are never visited, so they are not
	// counted as excluded files – only sound.properties is.
	if stats.ExcludedFiles != 1 {
		t.Errorf("ExcludedFiles = %d, want 1", stats.ExcludedFiles)
	}
}

func TestWalkWithIncludesReachesNestedMatches(t *testing.T) {
	root := tree(t)
	entries, _ := walk(t, config.Source{
		Path:                 root,
		IncludedPathPrefixes: []string{"conf"},
		ExcludedPathPrefixes: []string{"conf/management"},
	}, nil)

	want := []string{
		"tools/",
		"tools/conf/",
		"tools/conf/app.json",
		"tools/conf/security/",
		"tools/conf/security/keystore",
		"tools/conf/sound.properties",
	}
	got := archivePaths(entries)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("walked:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWalkSingleFileSource(t *testing.T) {
	root := tree(t)
	file := filepath.Join(root, "readme.md")
	entries, stats := walk(t, config.Source{Path: file}, nil)

	if len(entries) != 1 {
		t.Fatalf("walked %d entries, want 1", len(entries))
	}
	if entries[0].Archive != "readme.md" {
		t.Errorf("Archive = %q, want %q", entries[0].Archive, "readme.md")
	}
	if stats.Files != 1 || stats.Bytes != 5 {
		t.Errorf("stats = %+v, want one file of 5 bytes", stats)
	}
}

func TestWalkMultipleSourcesShareTheirParent(t *testing.T) {
	root := tree(t)
	target := &config.Target{ID: "t", Sources: []config.Source{
		{Path: filepath.Join(root, "conf")},
		{Path: filepath.Join(root, "lib")},
	}}
	specs, layout, err := Prepare(target)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if layout.Prefixes[0] != "conf" || layout.Prefixes[1] != "lib" {
		t.Fatalf("prefixes = %q, want [conf lib]", layout.Prefixes)
	}

	var got []string
	if _, err := (&Walker{}).Walk(specs, func(e Entry) error {
		if e.Kind != KindDir {
			got = append(got, e.Archive)
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	want := []string{"conf/app.json", "conf/management/jmx.access", "conf/security/keystore", "conf/sound.properties", "lib/native.so"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("walked %q, want %q", got, want)
	}
}

func TestWalkReportsDecisions(t *testing.T) {
	root := tree(t)
	var excluded []string
	w := &Walker{OnDecision: func(abs string, kind Kind, v Verdict) {
		if !v.Include {
			excluded = append(excluded, filepath.Base(abs)+": "+v.Reason)
		}
	}}
	walk(t, config.Source{Path: root, ExcludedDirectoryNames: []string{"security"}}, w)

	if len(excluded) != 1 || !strings.HasPrefix(excluded[0], "security: excluded by excludedDirectoryNames[0]") {
		t.Errorf("decisions = %q, want one naming the rule that pruned security", excluded)
	}
}

func TestWalkMissingSourceIsAProblem(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	target := &config.Target{ID: "t", Sources: []config.Source{{Path: missing}}}
	specs, _, err := Prepare(target)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// The default is to stop: a backup that silently skips an unreadable
	// source is worse than one that fails.
	if _, err := (&Walker{}).Walk(specs, func(Entry) error { return nil }); err == nil {
		t.Error("Walk succeeded on a missing source, want an error")
	}

	var seen int
	w := &Walker{OnProblem: func(string, error) error { seen++; return nil }}
	if _, err := w.Walk(specs, func(Entry) error { return nil }); err != nil {
		t.Errorf("Walk with an OnProblem that continues: %v", err)
	}
	if seen != 1 {
		t.Errorf("OnProblem called %d times, want 1", seen)
	}
}

func TestWalkSymlinks(t *testing.T) {
	root := tree(t)
	link := filepath.Join(root, "link.md")
	if err := os.Symlink(filepath.Join(root, "readme.md"), link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	entries, stats := walk(t, config.Source{Path: root}, nil)
	var found *Entry
	for i := range entries {
		if entries[i].Archive == "tools/link.md" {
			found = &entries[i]
		}
	}
	if found == nil {
		t.Fatal("the symlink was not walked")
	}
	if found.Kind != KindSymlink {
		t.Errorf("Kind = %v, want a symlink when followSymlinks is off", found.Kind)
	}
	if found.Link == "" {
		t.Error("the link target was not recorded")
	}
	if stats.Symlinks != 1 {
		t.Errorf("Symlinks = %d, want 1", stats.Symlinks)
	}

	entries, _ = walk(t, config.Source{Path: root}, &Walker{FollowSymlinks: true})
	for _, e := range entries {
		if e.Archive == "tools/link.md" {
			if e.Kind != KindFile {
				t.Errorf("Kind = %v, want a plain file when followSymlinks is on", e.Kind)
			}
			if e.Size != 5 {
				t.Errorf("Size = %d, want the target's 5 bytes", e.Size)
			}
		}
	}
}

func TestWalkFollowedSymlinkLoopTerminates(t *testing.T) {
	root := tree(t)
	if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if _, err := walkNoFatal(t, config.Source{Path: root}, &Walker{FollowSymlinks: true}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
}

func walkNoFatal(t *testing.T, spec config.Source, w *Walker) (Stats, error) {
	t.Helper()
	specs, _, err := Prepare(&config.Target{ID: "t", Sources: []config.Source{spec}})
	if err != nil {
		return Stats{}, err
	}
	return w.Walk(specs, func(Entry) error { return nil })
}
