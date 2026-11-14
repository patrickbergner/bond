package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/ui"
)

// runBenchKDF measures how long passphrase hardening takes on this machine.
//
// The parameters are a trade nobody can make from a distance: every guess an
// attacker makes costs them what one unlock costs here, so the right answer is
// the most this machine can bear. Defaults that were generous in 2020 are
// cheap now, which is why the numbers are stored per slot and why this command
// exists.
func runBenchKDF(args []string) error {
	fs := newFlagSet("bench-kdf")
	var target time.Duration
	fs.DurationVar(&target, "target", time.Second, "")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: bond bench-kdf [options]

Times Argon2id on this machine at several cost profiles.

BOND writes every passphrase slot with the default profile; this shows what
that costs here, and what a stronger one would. It does not change a setting.

options:
      --target <duration>   how long one unlock should take (default 1s)
`)
	}
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	lanes := uint32(runtime.NumCPU())
	if lanes > 8 {
		lanes = 8
	}
	fmt.Printf("machine     %s/%s, %d cores\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("target      %s per unlock\n\n", target)

	profiles := []struct {
		name   string
		params crypto.KDFParams
	}{
		{"low memory", crypto.LowMemoryKDF},
		{"default", crypto.DefaultKDF},
		{"1 GiB", crypto.KDFParams{MemoryKiB: 1024 * 1024, Iterations: 3, Parallelism: lanes}},
		{"2 GiB", crypto.KDFParams{MemoryKiB: 2048 * 1024, Iterations: 3, Parallelism: lanes}},
	}

	fmt.Printf("  %-12s %10s %8s %6s %10s\n", "profile", "memory", "passes", "lanes", "time")
	var best *crypto.KDFParams
	for _, p := range profiles {
		elapsed, err := timeKDF(p.params)
		if err != nil {
			fmt.Printf("  %-12s %10s %8d %6d  %v\n", p.name, ui.Bytes(int64(p.params.MemoryKiB)*1024), p.params.Iterations, p.params.Parallelism, err)
			continue
		}
		mark := " "
		if elapsed <= target {
			mark = "*"
			params := p.params
			best = &params
		}
		fmt.Printf("%s %-12s %10s %8d %6d %10s\n", mark, p.name,
			ui.Bytes(int64(p.params.MemoryKiB)*1024), p.params.Iterations, p.params.Parallelism,
			elapsed.Round(time.Millisecond))
	}

	fmt.Println()
	if best == nil {
		fmt.Printf("Nothing came in under %s. BOND writes passphrase slots with the default\n", target)
		fmt.Printf("profile regardless; on this machine a key file or a recipient key may suit better.\n")
		return nil
	}
	fmt.Printf("The strongest profile that fits: %s memory, %d passes, %d lanes.\n",
		ui.Bytes(int64(best.MemoryKiB)*1024), best.Iterations, best.Parallelism)
	fmt.Printf("This is a measurement, not a setting: BOND writes every passphrase slot with the\n")
	fmt.Printf("default profile (%s memory, %d passes, %d lanes).\n",
		ui.Bytes(int64(crypto.DefaultKDF.MemoryKiB)*1024), crypto.DefaultKDF.Iterations, crypto.DefaultKDF.Parallelism)
	return nil
}

func timeKDF(p crypto.KDFParams) (time.Duration, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return 0, err
	}
	slot := &crypto.Slot{Salt: salt, KDF: p}

	start := time.Now()
	if _, err := crypto.Passphrase("benchmark").Derive(slot); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
