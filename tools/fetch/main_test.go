package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func testManifest() *manifest {
	return &manifest{Tools: map[string]*tool{
		"7-zip": {
			Version: "1.0",
			BinDir:  "bin",
			Packages: map[string]*pkg{
				"extra":     {URL: "https://example.org/extra.7z"},
				"linux-x64": {URL: "https://example.org/linux-x64.tar.xz"},
				"linux-arm": {URL: "https://example.org/linux-arm64.tar.xz"},
			},
			Binaries: []*binary{
				{Target: "windows/amd64", File: "7za-windows-amd64.exe", Package: "extra"},
				{Target: "windows/arm64", File: "7za-windows-arm64.exe", Package: "extra"},
				{Target: "linux/amd64", File: "7zz-linux-amd64", Package: "linux-x64"},
				{Target: "linux/arm64", File: "7zz-linux-arm64", Package: "linux-arm"},
			},
		},
	}}
}

// A build for one platform needs that platform's binaries and only the packages
// they come from: that is what keeps a distribution package from downloading
// every other platform's 7-Zip.
func TestOnly(t *testing.T) {
	for _, tc := range []struct {
		target   string
		files    []string
		packages []string
	}{
		{"linux/amd64", []string{"7zz-linux-amd64"}, []string{"linux-x64"}},
		{"linux/arm64", []string{"7zz-linux-arm64"}, []string{"linux-arm"}},
		{"windows/amd64", []string{"7za-windows-amd64.exe"}, []string{"extra"}},
	} {
		m, err := testManifest().only(tc.target)
		if err != nil {
			t.Errorf("only(%s): %v", tc.target, err)
			continue
		}
		got := m.Tools["7-zip"]
		var files, packages []string
		for _, b := range got.Binaries {
			files = append(files, b.File)
		}
		for name := range got.Packages {
			packages = append(packages, name)
		}
		sort.Strings(packages)
		if !reflect.DeepEqual(files, tc.files) || !reflect.DeepEqual(packages, tc.packages) {
			t.Errorf("only(%s) = binaries %v, packages %v; want %v, %v", tc.target, files, packages, tc.files, tc.packages)
		}
		if got.BinDir != "bin" || got.Version != "1.0" {
			t.Errorf("only(%s) lost the tool's binDir or version: %+v", tc.target, got)
		}
	}

	// A platform nothing is pinned for has to fail here, naming what is pinned,
	// not later at a go:embed.
	_, err := testManifest().only("linux/riscv64")
	if err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Errorf("only(linux/riscv64) = %v; want an error listing the pinned targets", err)
	}

	// Narrowing leaves the manifest it came from whole.
	m := testManifest()
	if _, err := m.only("linux/amd64"); err != nil {
		t.Fatal(err)
	}
	if len(m.Tools["7-zip"].Binaries) != 4 || len(m.Tools["7-zip"].Packages) != 3 {
		t.Error("only changed the manifest it narrowed")
	}
}

// --update-hashes saves the manifest, so with --target it would write back one
// platform's pins and drop the rest.
func TestTargetRefusesUpdateHashes(t *testing.T) {
	err := run(t.TempDir(), "linux/amd64", false, false, true)
	if err == nil || !strings.Contains(err.Error(), "--update-hashes") {
		t.Errorf("run with --target and --update-hashes = %v; want it refused", err)
	}
}
