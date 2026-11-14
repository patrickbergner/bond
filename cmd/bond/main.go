// Command bond creates and restores backup containers for storage that cannot
// be trusted to keep a secret or to keep every byte.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// Version is stamped by build.sh; the default marks an ad-hoc build.
var Version = "dev"

// Exit codes. Anything scripted around bond can rely on these.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

type command struct {
	name    string
	summary string
	run     func(args []string) error
}

func commands() []command {
	return []command{
		{name: "backup", summary: "create containers for the targets in the control file", run: runBackup},
		{name: "restore", summary: "write a container's files back to disk", run: runRestore},
		{name: "list", summary: "show what a container holds", run: runList},
		{name: "verify", summary: "check a container for damage", run: runVerify},
		{name: "repair", summary: "rebuild damaged shards from the recovery data", run: runRepair},
		{name: "inspect", summary: "show a container's format and settings", run: runInspect},
		{name: "keygen", summary: "create a key file, recovery card or recipient key", run: runKeygen},
		{name: "keys", summary: "add, remove or rotate a container's keys", run: runKeys},
		{name: "rekey", summary: "re-encrypt a container under a new master key", run: runRekey},
		{name: "bench-kdf", summary: "calibrate the passphrase hardening parameters", run: runBenchKDF},
		{name: "selftest", summary: "check that the embedded 7-Zip works on this machine", run: runSelftest},
		{name: "version", summary: "print the version", run: runVersion},
	}
}

// rootCtx is cancelled by Ctrl-C and by SIGTERM.
//
// Every command that writes runs under it, so an interrupted run comes back
// through the same error paths as any other failure: the half-written
// container is removed from the working directory, the unpacked 7-Zip helper
// is deleted, and nothing is published. Without it the process simply died,
// and because container names carry a timestamp every interrupted backup left
// a partial of up to full size behind that no later run would ever touch.
var rootCtx = context.Background()

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	rootCtx = ctx
	go func() {
		// After the first signal the default behaviour comes back, so a second
		// one ends a process that is not winding down.
		<-ctx.Done()
		stop()
	}()
	code := run(os.Args[1:])
	stop()
	os.Exit(code)
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitUsage
	}

	name := args[0]
	switch name {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return exitOK
	case "-v", "--version":
		return dispatch(runVersion, nil)
	}

	for _, c := range commands() {
		if c.name == name {
			return dispatch(c.run, args[1:])
		}
	}

	fmt.Fprintf(os.Stderr, "bond: unknown command %q\n\n", name)
	usage(os.Stderr)
	return exitUsage
}

func dispatch(fn func([]string) error, args []string) int {
	switch err := fn(args); {
	case err == nil:
		return exitOK
	case err == flag.ErrHelp:
		return exitOK
	case isUsageError(err):
		fmt.Fprintf(os.Stderr, "bond: %v\n", err)
		return exitUsage
	default:
		if rootCtx.Err() != nil {
			fmt.Fprintf(os.Stderr, "bond: interrupted; nothing was published and the working files were removed (%v)\n", err)
			return exitFailure
		}
		fmt.Fprintf(os.Stderr, "bond: %v\n", err)
		return exitFailure
	}
}

// usageError marks a mistake in how bond was invoked, as opposed to a failure
// while doing the work.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func badUsage(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

func isUsageError(err error) bool {
	var u usageError
	return errors.As(err, &u)
}

func usage(w *os.File) {
	fmt.Fprint(w, `BOND – Backups on Non-Trusted Destinations

usage: bond <command> [options]

commands:
`)
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, "\nRun \"bond <command> --help\" for a command's options.\n")
}

func runVersion(args []string) error {
	fs := newFlagSet("version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("bond %s\n", Version)
	return nil
}

// newFlagSet builds a flag set that reports errors through the caller instead
// of printing its own usage twice.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("bond "+name, flag.ContinueOnError)
	return fs
}

// parseFlags parses options that appear before or after the positional
// arguments, and returns the positional ones.
//
// Go's flag package stops at the first non-flag argument, which would make
// "bond restore backup.bond --to /tmp/x" fail on the --to it never looked at.
// That is the order people actually type, so the arguments are permuted here
// rather than the operator being told to hold it differently.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var operands []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return operands, nil
		}
		// "--" ends option parsing; everything after it is positional.
		if rest[0] == "--" {
			return append(operands, rest[1:]...), nil
		}
		operands = append(operands, rest[0])
		args = rest[1:]
	}
}

// stringList collects a flag that may be repeated.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }
