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
		"COM0",
		"lpt0.log",
		"com¹",
		"LPT³.txt",
		"conin$",
		"CONOUT$.txt",
		"nul .txt",
		"a/aux  .tar.gz",
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
		// The same names read the same way everywhere, which is what lets the
		// manifest validate an index without the reader's platform deciding
		// whether the container opens at all.
		if err := CheckPortableName(name); err != nil {
			t.Errorf("CheckPortableName(%q) = %v, want it accepted on every platform", name, err)
		}
	}
}

func TestCheckPortableNameStillRefusesEscapes(t *testing.T) {
	for _, name := range []string{"", "/etc/passwd", "../outside", "..", "a/./b", "a//b", `\\server\share`, "C:/Windows", "a\x00b"} {
		if err := CheckPortableName(name); err == nil {
			t.Errorf("CheckPortableName(%q) accepted it", name)
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
