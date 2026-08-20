package archive

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckNameRejectsEscapes(t *testing.T) {
	// These are the names a restore must never act on, whichever platform it
	// is running on.
	bad := []string{
		"",
		"/etc/passwd",
		"../outside",
		"a/../../outside",
		"a/b/../../../outside",
		"..",
		"a/./b",
		"a//b",
		`\\server\share\x`,
		"C:/Windows/System32/drivers/etc/hosts",
		"c:relative",
		"a/b\x00c",
	}
	for _, name := range bad {
		for _, windows := range []bool{true, false} {
			if err := checkName(name, windows); err == nil {
				t.Errorf("checkName(%q, windows=%v) accepted it", name, windows)
			}
		}
	}
}

func TestCheckNameAcceptsOrdinaryNames(t *testing.T) {
	good := []string{
		"readme.md",
		"a/b/c.txt",
		"tools/",
		"Café/Chapter 1.pdf",
		"d_drive/Files/x",
		"a.b.c/..d", // a leading dot-dot inside a longer name is fine
		"deep/" + strings.Repeat("x/", 40) + "file",
	}
	for _, name := range good {
		for _, windows := range []bool{true, false} {
			if err := checkName(name, windows); err != nil {
				t.Errorf("checkName(%q, windows=%v) = %v, want it accepted", name, windows, err)
			}
		}
	}
}

func TestCheckNameWindowsSpecifics(t *testing.T) {
	// Legal on POSIX, unrepresentable or dangerous on Windows. Refusing is
	// better than restoring something with a different name than it had.
	cases := []string{
		`weird\name`,
		"con",
		"NUL.txt",
		"com1",
		"a/lpt9",
		"has:colon",
		"star*",
		"question?",
		"trailing ",
		"trailing.",
	}
	for _, name := range cases {
		if err := checkName(name, true); err == nil {
			t.Errorf("checkName(%q, windows=true) accepted it", name)
		}
		if err := checkName(name, false); err != nil {
			t.Errorf("checkName(%q, windows=false) = %v, want it accepted on POSIX", name, err)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	dest, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	got, err := SafeJoin(dest, "a/b.txt")
	if err != nil {
		t.Fatalf("SafeJoin: %v", err)
	}
	if want := filepath.Join(dest, "a", "b.txt"); got != want {
		t.Errorf("SafeJoin = %q, want %q", got, want)
	}

	for _, name := range []string{"../x", "/x", "a/../../x"} {
		if _, err := SafeJoin(dest, name); err == nil {
			t.Errorf("SafeJoin(%q) succeeded, want a refusal", name)
		}
	}
}

func TestCheckLink(t *testing.T) {
	ok := []struct{ link, target string }{
		{"a/b/link", "c.txt"},
		{"a/b/link", "../c.txt"},
		{"a/b/link", "../../a/c.txt"},
		{"link", "dir/file"},
	}
	for _, tc := range ok {
		if err := CheckLink(tc.link, tc.target); err != nil {
			t.Errorf("CheckLink(%q, %q) = %v, want it accepted", tc.link, tc.target, err)
		}
	}

	bad := []struct{ link, target string }{
		{"link", ""},
		{"link", "/etc/passwd"},
		{"link", "C:/Windows"},
		{"link", `\\server\share`},
		{"link", "../outside"},              // at the root, one level up is already out
		{"a/link", "../../outside"},         // two levels up from depth one
		{"a/b/link", "../../../../outside"}, // deeper attempt

		// Found by FuzzCheckLink. A single leading backslash is rooted on
		// Windows, and normalising the target after the absolute check turned
		// this into "/..", which path.Join then cleaned to "/" – losing the
		// component that made it an escape.
		{"0", `\..`},
		{"a/link", `\..\..\outside`},
		{"link", `..\outside`},
	}
	for _, tc := range bad {
		if err := CheckLink(tc.link, tc.target); err == nil {
			t.Errorf("CheckLink(%q, %q) accepted it, want a refusal", tc.link, tc.target)
		}
	}
}
