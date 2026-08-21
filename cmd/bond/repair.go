package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/backup"
	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/ui"
)

func runRepair(args []string) error {
	fs := newFlagSet("repair")
	var (
		out  string
		keys keyFlags
	)
	fs.StringVar(&out, "out", "", "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond repair <container.bond> [--out <file>]

Rebuilds damaged shards from the container's recovery data, writing a repaired
copy. The damaged container is never modified.

options:
      --out <file>   where to write the repaired copy
                     (default: the container's name with .repaired before the extension)
%s
`, keyFlagHelp)
	}
	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("repair needs exactly one container to work on")
	}
	path := operands[0]

	if out == "" {
		out = repairedName(path)
	}
	// A split set is written as out.001, out.002, …, so the plain name existing
	// is not the only way the destination can be occupied.
	for _, taken := range []string{out, out + container.VolumeSuffix(0)} {
		if _, err := os.Stat(taken); err == nil {
			return fmt.Errorf("%s already exists; name a different destination with --out", taken)
		}
	}

	r, err := openContainer(path, &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	sb := r.Superblock()
	fmt.Printf("%s\n", path)
	fmt.Printf("  recovery      %s\n", sb.Plan())
	fmt.Printf("  shards        %s data, %s parity\n",
		ui.Count(int(sb.DataShardCount)), ui.Count(sb.Layout().ParityShardCount()))

	progress := ui.NewProgress(os.Stderr)
	report, err := r.Verify(func(shard, total uint64) { progress.Add(int64(sb.ShardSize)) })
	progress.Clear()
	if err != nil {
		return err
	}

	// Damage the reader already worked around counts as damage. The container
	// opened, but it did so on its last copy of something.
	for _, notice := range r.Notices() {
		fmt.Printf("  damaged       %s\n", notice)
	}

	if !report.Damaged() {
		if len(r.Notices()) == 0 {
			fmt.Printf("  nothing to do – this container is not damaged\n")
			return nil
		}
	} else {
		fmt.Printf("  damaged       %s", ui.Items(len(report.DamagedShards), "data shard", "data shards"))
		if len(report.DamagedParity) > 0 {
			fmt.Printf(", %s", ui.Items(len(report.DamagedParity), "parity shard", "parity shards"))
		}
		fmt.Println()

		if !report.Repairable {
			if len(report.Unrepairable) > 0 {
				fmt.Printf("  unrepairable  %s lost more shards than the parity covers: %v\n",
					ui.Items(len(report.Unrepairable), "stripe", "stripes"), summariseInts(report.Unrepairable))
			}
			return fmt.Errorf("this damage cannot be repaired from the recovery data in the container; restore from another copy")
		}
	}

	started := time.Now()
	stripes := ui.NewProgress(os.Stderr)
	result, err := container.Repair(r, out, report, func(s, total int) { stripes.Add(int64(sb.ShardSize)) })
	stripes.Clear()
	if err != nil {
		return err
	}

	fmt.Printf("  rebuilt       %s in %s\n",
		ui.Items(result.Repaired(), "shard", "shards"), time.Since(started).Round(time.Millisecond))
	for _, region := range result.Metadata {
		fmt.Printf("  rewritten     %s\n", region)
	}

	// A repaired container is worth nothing until it has been checked as a
	// whole, so the check is not optional.
	fixed, err := container.Open(out)
	if err != nil {
		return fmt.Errorf("the repaired container cannot be opened: %w", err)
	}
	defer fixed.Close()
	secrets, err := keys.unlockersFor(fixed.Slots())
	if err != nil {
		return err
	}
	defer wipeUnlockers(secrets)
	if err := fixed.UnlockWithOptions(keys.unlockOptions(), secrets...); err != nil {
		return fmt.Errorf("the repaired container does not unlock: %w", err)
	}
	after, err := fixed.Verify(nil)
	if err != nil {
		return err
	}
	if !after.Healthy() {
		return fmt.Errorf("the repaired container is still damaged; the recovery data was not enough")
	}

	fmt.Printf("  written       %s\n", out)
	fmt.Printf("  verified      every shard authenticates and the stream matches its digest\n")

	// The checksum file belonged to the damaged bytes; the repaired copy needs
	// its own or the next --quick check will report a mismatch. One per volume,
	// as a backup writes them: they are uploaded and checked a file at a time.
	if algorithm := sidecarAlgorithm(r.Paths()[0]); algorithm != "" {
		for _, p := range result.Paths {
			sidecar, err := backup.WriteSidecar(p, algorithm)
			if err != nil {
				return fmt.Errorf("writing the checksum file: %w", err)
			}
			fmt.Printf("  checksum      %s\n", filepath.Base(sidecar))
		}
	}
	return nil
}

// repairedName puts ".repaired" before the extension, so the result sorts next
// to the original and is obviously not it.
//
// A volume suffix comes off first. The repaired copy of backup.bond.001 is a
// set in its own right and numbers its own volumes, so keeping the suffix would
// produce backup.bond.repaired.001.001.
func repairedName(path string) string {
	base := container.VolumeBase(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext) + ".repaired" + ext
}

// sidecarAlgorithm reports which checksum file, if any, sits next to a
// container.
func sidecarAlgorithm(path string) string {
	for _, c := range []struct{ ext, alg string }{
		{".sha256", config.HashSHA256},
		{".sha384", config.HashSHA384},
		{".sha512", config.HashSHA512},
	} {
		if _, err := os.Stat(path + c.ext); err == nil {
			return c.alg
		}
	}
	return ""
}

func summariseInts(v []int) string {
	const show = 8
	if len(v) <= show {
		return fmt.Sprint(v)
	}
	return fmt.Sprintf("%v and %d more", v[:show], len(v)-show)
}
