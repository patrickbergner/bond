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

	var warnings int
	entries, stats := walk(t, config.Source{Path: root}, &Walker{OnWarning: func(string, string) { warnings++ }})
	for i := range entries {
		if entries[i].Archive == "tools/link.md" {
			t.Fatal("a symlink entry was emitted when followSymlinks is off")
		}
	}
	if stats.SkippedSymlinks != 1 || warnings != 1 {
		t.Errorf("skipped symlinks = %d, warnings = %d; want one of each", stats.SkippedSymlinks, warnings)
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
	warnings := 0
	w := &Walker{FollowSymlinks: true, OnWarning: func(string, string) { warnings++ }}
	stats, err := walkNoFatal(t, config.Source{Path: root}, w)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if stats.SkippedSymlinks != 1 || warnings != 1 {
		t.Fatalf("loop cutoff: stats=%+v warnings=%d", stats, warnings)
	}
}

func TestWalkFollowedSelfSymlinkIsCutOff(t *testing.T) {
	root := t.TempDir()
	self := filepath.Join(root, "self")
	if err := os.Symlink("self", self); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	warnings := 0
	entries, stats := walk(t, config.Source{Path: root}, &Walker{
		FollowSymlinks: true,
		OnWarning:      func(string, string) { warnings++ },
	})
	for _, entry := range entries {
		if strings.HasSuffix(entry.Archive, "/self") {
			t.Fatalf("self loop emitted archive entry %+v", entry)
		}
	}
	if stats.SkippedSymlinks != 1 || warnings != 1 {
		t.Fatalf("self-loop stats=%+v warnings=%d", stats, warnings)
	}
}

func TestFollowedDirectoryTargetOutsideSourceRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside.txt"), []byte("included"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "external")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	entries, _ := walk(t, config.Source{Path: root}, &Walker{FollowSymlinks: true})
	want := filepath.Base(root) + "/external/outside.txt"
	for _, entry := range entries {
		if entry.Archive == want && entry.Kind == KindFile {
			return
		}
	}
	t.Fatalf("outside-root target was not materialized at %q: %+v", want, entries)
}

func TestFollowedDirectoryAliasesAreMaterializedIndependently(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "content.txt"), []byte("same"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alias-a", "alias-b"} {
		if err := os.Symlink(real, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks are not available here: %v", err)
		}
	}
	entries, _ := walk(t, config.Source{Path: root}, &Walker{FollowSymlinks: true})
	want := map[string]bool{
		filepath.Base(root) + "/real/content.txt":    false,
		filepath.Base(root) + "/alias-a/content.txt": false,
		filepath.Base(root) + "/alias-b/content.txt": false,
	}
	for _, entry := range entries {
		if _, ok := want[entry.Archive]; ok {
			want[entry.Archive] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("materialized path %q is missing", path)
		}
	}
}

func TestSourceRootSymlinkUsesTheSamePolicy(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target.txt")
	if err := os.WriteFile(target, []byte("root link"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "source-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	entries, stats := walk(t, config.Source{Path: link}, &Walker{FollowSymlinks: true})
	if len(entries) != 1 || entries[0].Kind != KindFile || entries[0].Size != int64(len("root link")) {
		t.Fatalf("followed root link = %+v", entries)
	}
	if stats.Files != 1 || stats.SkippedSymlinks != 0 {
		t.Fatalf("followed root stats = %+v", stats)
	}
	entries, stats = walk(t, config.Source{Path: link}, &Walker{})
	if len(entries) != 0 || stats.SkippedSymlinks != 1 {
		t.Fatalf("skipped root link entries=%+v stats=%+v", entries, stats)
	}
}

func TestSymlinkFiltersUseArchivePathAndResolvedKind(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real-dir")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "inside.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(root, "excluded-alias")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "excluded-dangling")); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	sourceSpec := config.Source{
		Path:                   root,
		ExcludedDirectoryNames: []string{"excluded-alias"},
		ExcludedFileNames:      []string{"excluded-dangling"},
	}
	for _, follow := range []bool{false, true} {
		warnings := 0
		entries, stats := walk(t, sourceSpec, &Walker{
			FollowSymlinks: follow,
			OnWarning:      func(string, string) { warnings++ },
		})
		for _, entry := range entries {
			if strings.Contains(entry.Archive, "excluded-") {
				t.Errorf("follow=%v emitted filtered link path %q", follow, entry.Archive)
			}
		}
		if warnings != 0 || stats.SkippedSymlinks != 0 || stats.ExcludedDirs != 1 || stats.ExcludedFiles != 1 {
			t.Errorf("follow=%v stats=%+v warnings=%d; filtered links should be ordinary exclusions", follow, stats, warnings)
		}
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
