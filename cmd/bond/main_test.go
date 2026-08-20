package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/patrickbergner/bond/internal/config"
)

func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{nil, exitUsage},
		{[]string{"version"}, exitOK},
		{[]string{"help"}, exitOK},
		{[]string{"nonsense"}, exitUsage},
		{[]string{"keygen"}, exitUsage}, // implemented, but needs to be told what to make
		{[]string{"keys"}, exitUsage},
		{[]string{"restore"}, exitUsage}, // implemented, but needs a container
		{[]string{"repair"}, exitUsage},
		{[]string{"backup", "extra-argument"}, exitUsage},
	}
	for _, tc := range cases {
		if got := run(tc.args); got != tc.want {
			t.Errorf("run(%q) = %d, want %d", tc.args, got, tc.want)
		}
	}
}

func TestFindConfig(t *testing.T) {
	dir := t.TempDir()
	named := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(named, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := findConfig(named)
	if err != nil {
		t.Fatalf("findConfig(%q): %v", named, err)
	}
	if got != named {
		t.Errorf("findConfig = %q, want %q", got, named)
	}

	if _, err := findConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("findConfig accepted a control file that does not exist")
	}

	// With nothing named and no config.json anywhere, the error has to say where
	// it looked – otherwise the operator is left guessing.
	t.Chdir(dir)
	_, err = findConfig("")
	if err == nil {
		t.Fatal("findConfig succeeded with no control file present")
	}
	if !strings.Contains(err.Error(), config.DefaultFileName) {
		t.Errorf("error = %v, want it to name %s and the directories searched", err, config.DefaultFileName)
	}

	// A config.json in the working directory is found without being named.
	fallback := filepath.Join(dir, config.DefaultFileName)
	if err := os.WriteFile(fallback, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := findConfig(""); err != nil || got != config.DefaultFileName {
		t.Errorf("findConfig(\"\") = %q, %v; want %q", got, err, config.DefaultFileName)
	}
}

func TestContainerPath(t *testing.T) {
	settings := config.Defaults()
	settings.OutputPath = "/backups/{{TARGET_ID}}"
	vars := config.Vars{}.ForTarget("photos", time.Date(2026, 8, 18, 21, 30, 5, 0, time.UTC))

	got, err := containerPath(settings, vars, "")
	if err != nil {
		t.Fatalf("containerPath: %v", err)
	}
	want := filepath.Join("/backups/photos", "photos-20260818-213005.bond")
	if got != want {
		t.Errorf("containerPath = %q, want %q", got, want)
	}
}

// The repaired copy of a split container is a set in its own right, and
// container.Repair numbers its own volumes. Keeping the suffix from the name the
// operator typed produced backup.bond.repaired.001.001.
func TestRepairedName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"backup.bond", "backup.repaired.bond"},
		{"backup.bond.001", "backup.repaired.bond"},
		{"backup.bond.003", "backup.repaired.bond"},
		{"/tmp/a/backup.bond.012", "/tmp/a/backup.repaired.bond"},
	} {
		if got := repairedName(tc.in); got != tc.want {
			t.Errorf("repairedName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
