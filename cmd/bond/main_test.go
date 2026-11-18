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

	// With nothing named and no control file anywhere, the error has to say where
	// it looked – otherwise the operator is left guessing.
	t.Chdir(dir)
	setUserConfigDir(t)
	_, err = findConfig("")
	if err == nil {
		t.Fatal("findConfig succeeded with no control file present")
	}
	if !strings.Contains(err.Error(), config.WorkingDirFileName) {
		t.Errorf("error = %v, want it to name %s and the directories searched", err, config.WorkingDirFileName)
	}

	// A bond.config.json in the working directory is found without being named.
	writeFile(t, filepath.Join(dir, config.WorkingDirFileName), "{}")
	if got, err := findConfig(""); err != nil || got != config.WorkingDirFileName {
		t.Errorf("findConfig(\"\") = %q, %v; want %q", got, err, config.WorkingDirFileName)
	}
}

// An installed binary sits in a directory like /usr/bin, so the control file is
// also looked for in the user's config directory – but only when no nearer one
// exists.
func TestFindConfigUserDir(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	userConfig := filepath.Join(setUserConfigDir(t), "bond", config.DefaultFileName)

	_, err := findConfig("")
	if err == nil {
		t.Fatal("findConfig succeeded with no control file present")
	}
	if !strings.Contains(err.Error(), userConfig) {
		t.Errorf("error = %v, want it to name %s", err, userConfig)
	}

	writeFile(t, userConfig, "{}")
	if got, err := findConfig(""); err != nil || got != userConfig {
		t.Errorf("findConfig(\"\") = %q, %v; want %q", got, err, userConfig)
	}

	// A config.json in the working directory that is not BOND's is none of its business.
	writeFile(t, filepath.Join(work, config.DefaultFileName), `{"name": "some other project"}`)
	if got, err := findConfig(""); err != nil || got != userConfig {
		t.Errorf("findConfig(\"\") = %q, %v; want %q", got, err, userConfig)
	}

	// A bond.config.json in the working directory wins.
	writeFile(t, filepath.Join(work, config.WorkingDirFileName), "{}")
	if got, err := findConfig(""); err != nil || got != config.WorkingDirFileName {
		t.Errorf("findConfig(\"\") = %q, %v; want %q", got, err, config.WorkingDirFileName)
	}
}

// The working directory was once searched for config.json. Passing over a BOND
// control file still named that way would quietly run another file's targets, so
// it is refused – unless it is the very file the search finds anyway.
func TestFindConfigStrayConfigJSON(t *testing.T) {
	sample, err := os.ReadFile("../../config.sample.json")
	if err != nil {
		t.Fatal(err)
	}
	// Broken, but declaring BOND's schema: still meant for BOND.
	broken := `{"$schema": "https://raw.githubusercontent.com/patrickbergner/bond/main/schema/bond-config.schema.json", "targets": 1}`

	for _, content := range []string{string(sample), broken} {
		work := t.TempDir()
		t.Chdir(work)
		userConfig := filepath.Join(setUserConfigDir(t), "bond", config.DefaultFileName)
		writeFile(t, filepath.Join(work, config.DefaultFileName), content)

		// Alone, it is refused with a message saying what to do.
		_, err := findConfig("")
		if err == nil || !isUsageError(err) || !strings.Contains(err.Error(), config.WorkingDirFileName) {
			t.Errorf("findConfig(\"\") with only a stray config.json: %v; want a usage error naming %s", err, config.WorkingDirFileName)
		}

		// With another control file to fall back on, it is refused too, naming that file.
		writeFile(t, userConfig, "{}")
		_, err = findConfig("")
		if err == nil || !strings.Contains(err.Error(), userConfig) {
			t.Errorf("findConfig(\"\") with a stray config.json and %s: %v; want a refusal naming it", userConfig, err)
		}

		// Run from the user's config directory, it is the file found: nothing is switched.
		t.Chdir(filepath.Dir(userConfig))
		writeFile(t, userConfig, content)
		if got, err := findConfig(""); err != nil || got != userConfig {
			t.Errorf("findConfig(\"\") from %s = %q, %v; want %q", filepath.Dir(userConfig), got, err, userConfig)
		}
	}
}

// writeFile writes content to path, creating its directory.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// setUserConfigDir points os.UserConfigDir into a fresh directory, so a control
// file in the real one cannot change what a test finds, and returns where it now points.
func setUserConfigDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// os.UserConfigDir reads AppData on Windows, HOME on macOS and XDG_CONFIG_HOME elsewhere.
	t.Setenv("AppData", root)
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", root)
	dir, err := os.UserConfigDir()
	if err != nil || !strings.HasPrefix(dir, root) {
		t.Fatalf("os.UserConfigDir() = %q, %v; want it inside %s", dir, err, root)
	}
	return dir
}

// The built-in outputPath and workPath sit beside the binary. That is the
// portable layout when the control file is there too, and /usr/bin for an
// installed binary, where the run has to stop before the first target.
func TestCheckDefaultPaths(t *testing.T) {
	toolDir, configDir := t.TempDir(), t.TempDir()
	parse := func(settings string) []*config.Target {
		t.Helper()
		cfg, err := config.Parse([]byte(`{"settings": {` + settings + `},
			"targets": [ { "id": "docs", "sources": [ { "path": "/data/docs" } ] } ]}`))
		if err != nil {
			t.Fatal(err)
		}
		targets, err := cfg.Selected(nil)
		if err != nil {
			t.Fatal(err)
		}
		return targets
	}
	unset := parse(`"encryptionMethod": "NONE"`)
	vars := config.Vars{config.VarToolDir: toolDir, config.VarConfigDir: configDir}

	err := checkDefaultPaths(unset, vars, "")
	if err == nil {
		t.Fatal("checkDefaultPaths accepted the defaults with the control file away from the binary")
	}
	for _, want := range []string{"outputPath", "workPath", toolDir, configDir, "{{CONFIG_DIR}}/output"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v; want it to name %s", err, want)
		}
	}

	// --work-dir takes the place of workPath, so only outputPath is missing.
	err = checkDefaultPaths(unset, vars, filepath.Join(configDir, "work"))
	if err == nil || strings.Contains(err.Error(), "workPath") {
		t.Errorf("with --work-dir: %v; want an error about outputPath alone", err)
	}

	set := parse(`"outputPath": "{{CONFIG_DIR}}/output", "workPath": "{{CONFIG_DIR}}/work"`)
	if err := checkDefaultPaths(set, vars, ""); err != nil {
		t.Errorf("with both paths set: %v", err)
	}

	// The portable layout: the control file beside the binary keeps its defaults.
	same := config.Vars{config.VarToolDir: toolDir, config.VarConfigDir: toolDir}
	if err := checkDefaultPaths(unset, same, ""); err != nil {
		t.Errorf("with the control file beside the binary: %v", err)
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
