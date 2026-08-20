// Package sevenzip runs the 7-Zip binary that is embedded in this executable.
//
// BOND ships 7-Zip inside itself so a backup can be made or restored on a
// machine with nothing installed on it. The binary for the current platform is
// written to a private temporary directory on first use, checked against the
// bytes it was built from, and removed when the process is done with it.
//
// 7-Zip is used as an xz codec on a pipe, never as an archiver: BOND builds
// the tar stream itself. That is not a stylistic choice – a .7z file cannot be
// written to a pipe at all, because its signature header at offset 0 records
// the offset, size and CRC of a header that only exists once the archive is
// finished, so the writer has to seek back to byte 0. 7-Zip's own -so switch
// reflects this and supports only bzip2, gzip, tar and xz with the "a"
// command.
package sevenzip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// Tool is an extracted 7-Zip ready to run. It is safe for concurrent use; the
// binary is written to disk once.
type Tool struct {
	dir  string
	path string
}

var (
	shared     *Tool
	sharedErr  error
	sharedOnce sync.Once
)

// Shared returns the process-wide 7-Zip, extracting it on first use. Callers
// that want to control the lifetime should use Extract instead.
func Shared() (*Tool, error) {
	sharedOnce.Do(func() { shared, sharedErr = Extract("") })
	return shared, sharedErr
}

// Extract writes the embedded binary into a fresh private directory under
// parent (or the system temporary directory when parent is empty).
func Extract(parent string) (*Tool, error) {
	dir, err := os.MkdirTemp(parent, "bond-7z-")
	if err != nil {
		return nil, fmt.Errorf("creating a directory for the 7-Zip helper: %w", err)
	}
	// Owner-only: the helper is executable, and a world-writable copy of it
	// would be a way to have BOND run someone else's code.
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	path := filepath.Join(dir, binaryName)
	if err := os.WriteFile(path, binary, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("writing the 7-Zip helper: %w", err)
	}

	// Read it back: a short write or a filesystem that mangled the bytes has
	// to surface here rather than as a corrupt backup later.
	written, err := os.ReadFile(path)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if sha256.Sum256(written) != sha256.Sum256(binary) {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("the 7-Zip helper written to %s does not match the embedded copy", path)
	}

	return &Tool{dir: dir, path: path}, nil
}

// Path is the extracted binary's location on disk.
func (t *Tool) Path() string { return t.path }

// Version asks the helper to identify itself, which doubles as a check that it
// can actually run on this machine.
func (t *Tool) Version(ctx context.Context) (string, error) {
	cmd := t.Command(ctx)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// 7-Zip with no arguments prints its banner and exits non-zero, so the
	// output matters more than the status.
	_ = cmd.Run()
	for line := range bytes.Lines(out.Bytes()) {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("7-Zip")) {
			return string(trimmed), nil
		}
	}
	return "", fmt.Errorf("the embedded 7-Zip did not run: %s", bytes.TrimSpace(out.Bytes()))
}

// Close removes the extracted binary.
func (t *Tool) Close() error {
	if t == nil || t.dir == "" {
		return nil
	}
	return os.RemoveAll(t.dir)
}

// Command builds an invocation of the helper. Arguments are passed as an argv
// array and never through a shell, so a file name holding quotes, spaces or
// semicolons is just a file name.
func (t *Tool) Command(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, t.path, args...)
}
