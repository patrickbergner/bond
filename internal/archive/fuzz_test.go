package archive

import (
	"path/filepath"
	"strings"
	"testing"
)

// The path policy is the last thing standing between an archive somebody else
// wrote and the filesystem, and it is exactly the kind of code where a case
// nobody thought of is the whole bug. So the property is stated once and thrown
// at whatever the fuzzer can invent: if SafeJoin returns a path, that path is
// inside the destination. No exceptions, no platform, no encoding.

func FuzzSafeJoin(f *testing.F) {
	f.Add("a/b.txt")
	f.Add("../escape")
	f.Add("/etc/passwd")
	f.Add(`\\server\share\x`)
	f.Add("C:/Windows")
	f.Add("a/../../b")
	f.Add("con")
	f.Add("trailing ")
	f.Add("ünïcödé/naïve")
	f.Add(strings.Repeat("a/", 200) + "deep")

	dest := filepath.Join(string(filepath.Separator), "restore", "destination")
	f.Fuzz(func(t *testing.T, name string) {
		got, err := SafeJoin(dest, name)
		if err != nil {
			return
		}

		// It was accepted, so this is the path a file is about to be created
		// at. It has to be under dest, and it has to be clean – a path that
		// still contains a ".." component would be resolved by the operating
		// system, not by us.
		rel, relErr := filepath.Rel(dest, got)
		switch {
		case relErr != nil:
			t.Fatalf("SafeJoin(%q) = %q, which is not even relative to %q", name, got, dest)
		case rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)):
			t.Fatalf("SafeJoin(%q) = %q, which is outside %q", name, got, dest)
		case got != filepath.Clean(got):
			t.Fatalf("SafeJoin(%q) = %q, which is not a clean path", name, got)
		case !strings.HasPrefix(got, dest+string(filepath.Separator)):
			t.Fatalf("SafeJoin(%q) = %q, which does not start with %q", name, got, dest)
		}
	})
}
