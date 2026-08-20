package source

import (
	"strings"
	"testing"
)

func TestLayoutWindows(t *testing.T) {
	cases := []struct {
		name      string
		paths     []string
		root      string
		synthetic bool
		prefixes  []string
	}{
		{
			name:     "one source keeps its own name",
			paths:    []string{`D:\Photos`},
			root:     `D:\`,
			prefixes: []string{"Photos"},
		},
		{
			name:     "siblings share their parent",
			paths:    []string{`D:\Apps\Foo`, `D:\Apps\Bar`},
			root:     `D:\Apps`,
			prefixes: []string{"Foo", "Bar"},
		},
		{
			name:     "different depths fall back to the deepest shared parent",
			paths:    []string{`D:\Apps\Chromium\cookies`, `D:\Apps\Chromium-dev\profile`},
			root:     `D:\Apps`,
			prefixes: []string{"Chromium/cookies", "Chromium-dev/profile"},
		},
		{
			name:      "two drives get synthetic roots",
			paths:     []string{`D:\Files`, `C:\Users\jsmith\Desktop`, `D:\dev\widget`},
			synthetic: true,
			prefixes:  []string{"d_drive/Files", "c_drive/Users/jsmith/Desktop", "d_drive/dev/widget"},
		},
		{
			name:      "a UNC share is a volume of its own",
			paths:     []string{`\\server\share\data`, `D:\Files`},
			synthetic: true,
			prefixes:  []string{"unc_server_share/data", "d_drive/Files"},
		},
		{
			name:     "a drive root stores at the archive root",
			paths:    []string{`F:\`},
			root:     `F:\`,
			prefixes: []string{""},
		},
		{
			name:     "forward slashes and redundant separators are normalised",
			paths:    []string{`D:/Apps//Foo`, `D:\Apps\.\Bar`},
			root:     `D:\Apps`,
			prefixes: []string{"Foo", "Bar"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := buildLayout(tc.paths, true)
			if err != nil {
				t.Fatalf("buildLayout: %v", err)
			}
			if l.Synthetic != tc.synthetic {
				t.Errorf("Synthetic = %v, want %v", l.Synthetic, tc.synthetic)
			}
			if !tc.synthetic && l.Root != tc.root {
				t.Errorf("Root = %q, want %q", l.Root, tc.root)
			}
			if strings.Join(l.Prefixes, "|") != strings.Join(tc.prefixes, "|") {
				t.Errorf("Prefixes = %q, want %q", l.Prefixes, tc.prefixes)
			}
		})
	}
}

func TestLayoutPOSIX(t *testing.T) {
	cases := []struct {
		name     string
		paths    []string
		root     string
		prefixes []string
	}{
		{
			name:     "one source keeps its own name",
			paths:    []string{"/data/tools"},
			root:     "/data",
			prefixes: []string{"tools"},
		},
		{
			name:     "top-level sources meet at the filesystem root",
			paths:    []string{"/etc", "/home/alice"},
			root:     "/",
			prefixes: []string{"etc", "home/alice"},
		},
		{
			name:     "trailing slashes and dots do not matter",
			paths:    []string{"/data/tools/", "/data/./work"},
			root:     "/data",
			prefixes: []string{"tools", "work"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := buildLayout(tc.paths, false)
			if err != nil {
				t.Fatalf("buildLayout: %v", err)
			}
			if l.Synthetic {
				t.Error("POSIX paths always share the filesystem root, so synthetic roots are never needed")
			}
			if l.Root != tc.root {
				t.Errorf("Root = %q, want %q", l.Root, tc.root)
			}
			if strings.Join(l.Prefixes, "|") != strings.Join(tc.prefixes, "|") {
				t.Errorf("Prefixes = %q, want %q", l.Prefixes, tc.prefixes)
			}
		})
	}
}

func TestLayoutRejectsOverlap(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		win   bool
		want  string
	}{
		{
			name:  "nested sources",
			paths: []string{`D:\Files`, `D:\Files\Books`},
			win:   true,
			want:  "is inside source",
		},
		{
			name:  "nested sources, deeper one first",
			paths: []string{"/data/tools/widget", "/data/tools"},
			want:  "is inside source",
		},
		{
			name:  "the same source twice",
			paths: []string{"/data/tools", "/data/tools/"},
			want:  "the same directory",
		},
		{
			name:  "the same source twice, differing only in case on Windows",
			paths: []string{`D:\Photos`, `D:\photos`},
			win:   true,
			want:  "the same directory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildLayout(tc.paths, tc.win)
			if err == nil {
				t.Fatalf("buildLayout succeeded, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLayoutRejectsCollidingPrefixes(t *testing.T) {
	// Same trailing name on two drives, but they are kept apart by the
	// synthetic roots, so this must succeed.
	l, err := buildLayout([]string{`C:\Data`, `D:\Data`}, true)
	if err != nil {
		t.Fatalf("buildLayout: %v", err)
	}
	if l.Prefixes[0] == l.Prefixes[1] {
		t.Errorf("prefixes collided: %q", l.Prefixes)
	}
}

func TestLayoutRejectsRelativePath(t *testing.T) {
	if _, err := buildLayout([]string{"data/tools"}, false); err == nil {
		t.Error("buildLayout accepted a relative path")
	}
	if _, err := buildLayout([]string{`Photos`}, true); err == nil {
		t.Error("buildLayout accepted a relative Windows path")
	}
}

// A POSIX-style path on Windows names no volume, so the OS resolves it against
// whichever drive happens to be current. Backing up C:\data because the
// control file said /data is exactly the kind of quiet wrong answer a backup
// tool must not give.
func TestLayoutRejectsDrivelessWindowsPath(t *testing.T) {
	_, err := buildLayout([]string{"/data/tools"}, true)
	if err == nil {
		t.Fatal("buildLayout accepted a Windows path with no drive letter")
	}
	if !strings.Contains(err.Error(), "drive letter") {
		t.Errorf("error = %v, want it to explain the missing drive letter", err)
	}
	if _, err := buildLayout([]string{"/data/tools"}, false); err != nil {
		t.Errorf("the same path must stay valid on POSIX: %v", err)
	}
}

func TestSyntheticRoot(t *testing.T) {
	cases := map[string]string{
		"C:":                  "c_drive",
		"d:":                  "d_drive",
		`\\server\share`:      "unc_server_share",
		`\\FILESERVER\backup`: "unc_fileserver_backup",
	}
	for in, want := range cases {
		if got := syntheticRoot(in); got != want {
			t.Errorf("syntheticRoot(%q) = %q, want %q", in, got, want)
		}
	}
}
