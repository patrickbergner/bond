package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/backup"
	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/parity"
	"github.com/patrickbergner/bond/internal/sevenzip"
	"github.com/patrickbergner/bond/internal/source"
	"github.com/patrickbergner/bond/internal/ui"
)

func runBackup(args []string) error {
	fs := newFlagSet("backup")
	var (
		configPath   string
		targets      stringList
		dryRun       bool
		verbose      bool
		workDir      string
		ignoreErrors bool
		keys         keyFlags
	)
	fs.StringVar(&configPath, "config", "", "")
	fs.StringVar(&configPath, "c", "", "")
	fs.Var(&targets, "target", "")
	fs.Var(&targets, "t", "")
	fs.BoolVar(&dryRun, "dry-run", false, "")
	fs.BoolVar(&dryRun, "n", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	fs.StringVar(&workDir, "work-dir", "", "")
	fs.BoolVar(&ignoreErrors, "ignore-errors", false, "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond backup [options]

Creates one container per selected target.

options:
  -c, --config <path>   control file to read
                        (default: bond.config.json in the current directory, else
                        config.json beside the binary or in the user's config
                        directory, such as ~/.config/bond)
  -t, --target <id>     back up only this target; repeat for several
                        (default: every target not marked skip)
  -n, --dry-run         enumerate and report what would be backed up, writing nothing
  -v, --verbose         list every file as it is stored, and every filter decision on a dry run
      --work-dir <dir>  override the control file's workPath
      --ignore-errors   carry on past paths that cannot be read (the run still fails)
%s
`, keyFlagHelp)
	}
	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) > 0 {
		return badUsage("backup takes no positional arguments; use --target to pick targets (got %q)", operands[0])
	}

	path, err := findConfig(configPath)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	selected, err := cfg.Selected(targets)
	if err != nil {
		return err
	}
	if err := checkDefaultPaths(selected, config.BaseVars(path), workDir); err != nil {
		return err
	}

	if dryRun {
		return dryRunBackup(cfg, selected, path, workDir, verbose)
	}
	return createBackups(cfg, selected, path, workDir, verbose, ignoreErrors, &keys)
}

func createBackups(cfg *config.Config, targets []*config.Target, configPath, workDir string, verbose, ignoreErrors bool, keys *keyFlags) error {
	ctx := rootCtx
	now := time.Now()
	base := config.BaseVars(configPath)

	fmt.Printf("control file  %s\n", configPath)
	fmt.Printf("targets       %d of %s selected\n", len(targets), ui.Items(len(cfg.Targets), "target", "targets"))

	// One 7-Zip for the whole run, unpacked once and removed at the end.
	tool, err := sevenzip.Shared()
	if err != nil {
		return err
	}
	defer tool.Close()
	defer keys.forget()

	var (
		totalSize  int64
		totalBytes int64
		failures   int
	)

	for _, target := range targets {
		settings := target.Effective()
		vars := base.ForTarget(target.ID, now)

		fmt.Printf("\n%s\n", target.ID)

		outPath, err := containerPath(settings, vars, "")
		if err != nil {
			failures++
			fmt.Printf("  ! %v\n", err)
			continue
		}
		work, err := workPath(settings, vars, workDir)
		if err != nil {
			failures++
			fmt.Printf("  ! %v\n", err)
			continue
		}
		if err := os.MkdirAll(work, 0o700); err != nil {
			failures++
			fmt.Printf("  ! %v\n", err)
			continue
		}

		// One interrupt ends the run, not just the target it arrived in.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// A key that cannot be had fails this target like anything else about
		// it would. Another target may use a different key, or none.
		specs, err := keySpecsFor(keys, settings, vars)
		if err != nil {
			failures++
			fmt.Printf("  ! %v\n", err)
			continue
		}

		var signer *crypto.WriterPrivate
		if settings.SigningKey != "" {
			keyPath, err := config.Expand(settings.SigningKey, vars)
			if err == nil {
				signer, err = loadWriterKey(keyPath)
			}
			if err != nil {
				wipeKeySpecs(specs.slots)
				failures++
				fmt.Printf("  ! signingKey: %v\n", err)
				continue
			}
		}

		describeSettings(settings)
		if signer != nil {
			fmt.Printf("  signed by     writer %s\n", shortID(signer.Fingerprint()))
		}

		progress := ui.NewProgress(os.Stderr)
		unreadable := 0
		result, err := backup.Create(ctx, backup.CreateOptions{
			Target:      target,
			Settings:    settings,
			Keys:        specs.slots,
			Unencrypted: specs.unencrypted,
			WorkDir:     work,
			OutputPath:  outPath,
			Tool:        tool,
			Signer:      signer,
			OnEntry: func(e archive.Entry) {
				progress.Add(e.Size)
				if verbose {
					progress.Clear()
					fmt.Printf("    %s\n", ui.Path(e.Path))
				}
			},
			OnWarning: func(path, msg string) {
				progress.Clear()
				fmt.Printf("  warning       %s: %s\n", path, msg)
			},
			// A path that cannot be read stops the backup. Writing a container
			// that quietly lacks a whole source, under a name that looks like
			// every other backup, is the failure mode that only shows up years
			// later during a restore. --ignore-errors is how an operator
			// decides otherwise, and even then the run reports failure.
			OnProblem: func(path string, err error) error {
				progress.Clear()
				unreadable++
				fmt.Printf("  ! %s: %v\n", path, err)
				if ignoreErrors {
					return nil
				}
				return fmt.Errorf("%s could not be read; use --ignore-errors to back up what is readable anyway", path)
			},
		})
		wipeKeySpecs(specs.slots)
		signer.Wipe()
		progress.Clear()
		if err != nil {
			failures++
			fmt.Printf("  failed        %v\n", err)
			continue
		}

		fmt.Printf("  contents      %s, %s, %s\n",
			ui.Items(result.Stats.Files, "file", "files"),
			ui.Items(result.Stats.Dirs, "directory", "directories"),
			ui.Bytes(result.Stats.Bytes))
		// A backup that left links out must say so in its summary, not only in
		// per-path warnings that scroll away. "It looked complete" is how a
		// missing subtree survives until the restore that needed it.
		if result.Stats.SkippedSymlinks > 0 {
			fmt.Printf("  links skipped %s\n", ui.Items(result.Stats.SkippedSymlinks, "symlink", "symlinks"))
		}
		if result.Stats.SkippedSpecial > 0 {
			fmt.Printf("  not archived  %s (pipes, sockets, devices)\n", ui.Items(result.Stats.SkippedSpecial, "special file", "special files"))
		}
		fmt.Printf("  written       %s\n", result.Path)
		fmt.Printf("                %s", ui.Bytes(result.Size))
		if result.Stats.Bytes > 0 {
			fmt.Printf("  (%.0f%% of %s)", result.Ratio()*100, ui.Bytes(result.Stats.Bytes))
		}
		fmt.Printf("  in %s\n", result.Elapsed.Round(time.Millisecond))
		fmt.Printf("  shards        %s of %s\n", ui.Count(int(result.Shards)), ui.Bytes(result.ShardSize))
		if result.Volumes() > 1 {
			fmt.Printf("  volumes       %s, %s to %s\n", ui.Items(result.Volumes(), "file", "files"),
				filepath.Base(result.VolumePaths[0]), filepath.Base(result.VolumePaths[result.Volumes()-1]))
		}
		if len(result.Sidecars) > 0 {
			fmt.Printf("  checksums     %s\n", ui.Items(len(result.Sidecars), "file", "files"))
		}
		if unreadable > 0 {
			// The container was still written, but it is incomplete and the
			// operator has to know that before they rely on it.
			failures++
			fmt.Printf("  incomplete    %s could not be read and are missing from this backup\n",
				ui.Items(unreadable, "path", "paths"))
		}

		totalSize += result.Size
		totalBytes += result.Stats.Bytes
	}

	fmt.Printf("\ntotal  %s written from %s\n",
		ui.Bytes(totalSize), ui.Bytes(totalBytes))

	if failures > 0 {
		return fmt.Errorf("%s failed", ui.Items(failures, "target", "targets"))
	}
	return nil
}

// keySpecs is what the control file's encryption settings resolve to.
type keySpecs struct {
	slots       []container.KeySpec
	unencrypted bool
}

func wipeKeySpecs(specs []container.KeySpec) {
	unlockers := make([]crypto.Unlocker, 0, len(specs))
	for _, spec := range specs {
		if spec.Secret != nil {
			unlockers = append(unlockers, spec.Secret)
		}
	}
	wipeUnlockers(unlockers)
}

func keySpecsFor(keys *keyFlags, settings config.Resolved, vars config.Vars) (*keySpecs, error) {
	// Key-slot paths take the same placeholders as outputPath and workPath. The
	// loader has always accepted them there, and the sample control file uses
	// {{HOME}} for one; they were then handed to the filesystem unexpanded.
	slotList := append([]config.KeySlot(nil), settings.KeySlots...)
	for i := range slotList {
		if slotList[i].Path == "" {
			continue
		}
		expanded, err := config.Expand(slotList[i].Path, vars)
		if err != nil {
			return nil, fmt.Errorf("keySlots[%d]: path: %w", i, err)
		}
		slotList[i].Path = expanded
	}
	settings.KeySlots = slotList
	slots, unencrypted, err := keys.createSpecs(settings, crypto.DefaultKDF)
	if err != nil {
		return nil, err
	}
	return &keySpecs{slots: slots, unencrypted: unencrypted}, nil
}

func describeSettings(s config.Resolved) {
	compression := fmt.Sprintf("level %d", s.CompressionLevel)
	if s.CompressionLevel == 0 {
		compression = "stored, not compressed"
	}
	plan, err := parity.For(s.RecoveryPercent)
	recovery := plan.String()
	if err != nil {
		recovery = err.Error()
	}
	fmt.Printf("  settings      %s, %s, shards of up to %s, recovery %s\n",
		compression, s.EncryptionMethod, ui.Bytes(s.ShardBytes), recovery)
}

func dryRunBackup(cfg *config.Config, targets []*config.Target, configPath, workDir string, verbose bool) error {
	now := time.Now()
	base := config.BaseVars(configPath)

	fmt.Printf("control file  %s\n", configPath)
	fmt.Printf("targets       %d of %s selected\n", len(targets), ui.Items(len(cfg.Targets), "target", "targets"))

	var (
		totalFiles int
		totalBytes int64
		problems   int
	)

	for _, target := range targets {
		fmt.Printf("\n%s\n", target.ID)
		settings := target.Effective()

		specs, layout, err := source.Prepare(target)
		if err != nil {
			problems++
			fmt.Printf("  %v\n", err)
			continue
		}

		if layout.Synthetic {
			fmt.Printf("  archive root  synthetic; the sources span volumes\n")
		} else {
			fmt.Printf("  archive root  %s\n", layout.Root)
		}
		describeSettings(settings)

		fmt.Printf("  sources\n")
		for i, spec := range specs {
			prefix := spec.Prefix
			if prefix == "" {
				prefix = "(archive root)"
			} else {
				prefix += "/"
			}
			fmt.Printf("    %s  ->  %s\n", target.Sources[i].Path, prefix)
		}

		walker := &source.Walker{
			FollowSymlinks: settings.FollowSymlinks,
			OnWarning: func(path, msg string) {
				fmt.Printf("    ! %s: %s\n", path, msg)
			},
			OnProblem: func(abs string, err error) error {
				problems++
				fmt.Printf("    ! %s: %v\n", abs, err)
				return nil
			},
		}
		if verbose {
			walker.OnDecision = func(abs string, kind source.Kind, v source.Verdict) {
				mark := "-"
				if v.Include {
					mark = "+"
				}
				fmt.Printf("    %s %s (%s)\n", mark, abs, v.Reason)
			}
		}

		stats, err := walker.Walk(specs, func(source.Entry) error { return nil })
		if err != nil {
			problems++
			fmt.Printf("  %v\n", err)
			continue
		}

		fmt.Printf("  contents      %s, %s, %s\n",
			ui.Items(stats.Files, "file", "files"),
			ui.Items(stats.Dirs, "directory", "directories"),
			ui.Bytes(stats.Bytes))
		if stats.SkippedSymlinks > 0 {
			fmt.Printf("  links skipped %s\n", ui.Items(stats.SkippedSymlinks, "symlink", "symlinks"))
		}
		if stats.SkippedSpecial > 0 {
			fmt.Printf("  not archived  %s (pipes, sockets, devices)\n", ui.Items(stats.SkippedSpecial, "special file", "special files"))
		}
		if stats.ExcludedFiles > 0 || stats.ExcludedDirs > 0 {
			fmt.Printf("  filtered out  %s, %s\n",
				ui.Items(stats.ExcludedFiles, "file", "files"),
				ui.Items(stats.ExcludedDirs, "directory", "directories"))
		}

		vars := base.ForTarget(target.ID, now)
		out, err := containerPath(settings, vars, "")
		if err != nil {
			problems++
			fmt.Printf("  ! %v\n", err)
		} else {
			fmt.Printf("  output        %s\n", out)
		}

		totalFiles += stats.Files
		totalBytes += stats.Bytes
	}

	fmt.Printf("\ntotal  %s, %s\n", ui.Items(totalFiles, "file", "files"), ui.Bytes(totalBytes))
	fmt.Printf("\nnothing was written; this was a dry run\n")

	if problems > 0 {
		return fmt.Errorf("%s while enumerating", ui.Items(problems, "problem", "problems"))
	}
	return nil
}

func containerPath(settings config.Resolved, vars config.Vars, override string) (string, error) {
	dir := override
	if dir == "" {
		expanded, err := config.Expand(settings.OutputPath, vars)
		if err != nil {
			return "", fmt.Errorf("outputPath: %w", err)
		}
		dir = expanded
	}
	name, err := config.Expand("{{TARGET_ID}}-{{TIMESTAMP}}.bond", vars)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func workPath(settings config.Resolved, vars config.Vars, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	dir, err := config.Expand(settings.WorkPath, vars)
	if err != nil {
		return "", fmt.Errorf("workPath: %w", err)
	}
	return dir, nil
}

// checkDefaultPaths refuses a run that would put containers or work files at
// their built-in defaults beside the binary although the control file is not
// there. The defaults are made for the portable layout, where the two share a
// directory. For an installed binary they point into something like /usr/bin:
// a backup there fails on permissions at best, and run as root it litters a
// system directory. Either way the operator is better served by being told,
// before the first target, which setting to add.
func checkDefaultPaths(targets []*config.Target, base config.Vars, workDir string) error {
	toolDir, configDir := base[config.VarToolDir], base[config.VarConfigDir]
	if toolDir == "" || configDir == "" || sameDir(toolDir, configDir) {
		return nil
	}

	var output, work bool
	for _, t := range targets {
		s := t.Effective()
		output = output || s.DefaultOutputPath
		work = work || (s.DefaultWorkPath && workDir == "")
	}

	var unset, examples []string
	if output {
		unset = append(unset, "outputPath")
		examples = append(examples, `"outputPath": "{{CONFIG_DIR}}/output"`)
	}
	if work {
		unset = append(unset, "workPath")
		examples = append(examples, `"workPath": "{{CONFIG_DIR}}/work"`)
	}
	if len(unset) == 0 {
		return nil
	}
	return fmt.Errorf("the control file does not set %s, and the default would put files beside the binary in %s"+
		" rather than beside the control file in %s; add to its settings, for example, %s",
		strings.Join(unset, " or "), toolDir, configDir, strings.Join(examples, " and "))
}

// sameDir reports whether a and b name the same directory, however each is
// spelled; one that cannot be read counts as different.
func sameDir(a, b string) bool {
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ia, ib)
}

// findConfig resolves the control file: the one named on the command line, or
// bond.config.json in the working directory, or config.json beside the binary
// or in the user's config directory, in that order.
//
// The user's config directory ($XDG_CONFIG_HOME/bond on Linux) is for an
// installed binary, whose own directory is something like /usr/bin. It comes
// last so that a portable setup keeps the control file it always had.
//
// The working directory was once searched for config.json. A BOND control file
// still lying there under that name is refused rather than passed over: the
// search would otherwise move on to another file, and a backup run from that
// directory would quietly switch to that file's targets.
func findConfig(given string) (string, error) {
	if given != "" {
		if _, err := os.Stat(given); err != nil {
			return "", fmt.Errorf("control file %s: %w", given, err)
		}
		return given, nil
	}

	if _, err := os.Stat(config.WorkingDirFileName); err == nil {
		return config.WorkingDirFileName, nil
	}
	looked := []string{absOrSelf(config.WorkingDirFileName)}

	var candidates []string
	if vars := config.BaseVars(""); vars[config.VarToolDir] != "" {
		candidates = append(candidates, filepath.Join(vars[config.VarToolDir], config.DefaultFileName))
	}
	if dir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates, filepath.Join(dir, "bond", config.DefaultFileName))
	}

	// The old name in the working directory, if what it holds is BOND's. It is
	// fine when it is the very file found next, as when bond runs from its own
	// directory.
	var stray os.FileInfo
	if data, err := os.ReadFile(config.DefaultFileName); err == nil && config.IsControlFile(data) {
		stray, _ = os.Stat(config.DefaultFileName)
	}
	refuse := func(instead string) error {
		msg := "%[1]s in the working directory is a BOND control file, but there BOND reads only %[2]s;" +
			" rename it to %[2]s to use it, or name the control file to use with --config"
		if instead != "" {
			return badUsage(msg+" (left as it is, it would be passed over for %[3]s)", config.DefaultFileName, config.WorkingDirFileName, instead)
		}
		return badUsage(msg, config.DefaultFileName, config.WorkingDirFileName)
	}

	for _, c := range candidates {
		info, err := os.Stat(c)
		if err != nil {
			looked = append(looked, absOrSelf(c))
			continue
		}
		if stray != nil && !os.SameFile(stray, info) {
			return "", refuse(absOrSelf(c))
		}
		return c, nil
	}
	if stray != nil {
		return "", refuse("")
	}
	return "", badUsage("no control file found; looked for %v – name one with --config", looked)
}

// absOrSelf is path made absolute for a message, or path itself if that fails.
func absOrSelf(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
