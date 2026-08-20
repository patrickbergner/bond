package sevenzip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// Options control the xz encoder.
type Options struct {
	// Level is the LZMA2 preset, 0 to 9. 0 stores; BOND's backup path skips
	// 7-Zip entirely at that level, so it mostly matters for tests.
	Level int

	// Threads caps the encoder. Zero lets 7-Zip decide, which is one thread
	// per core. Multithreaded xz splits the stream into independent blocks, so
	// it trades a little ratio for a lot of wall clock.
	Threads int

	// DictionaryBytes overrides the preset's dictionary size. Zero keeps the
	// preset's own choice.
	DictionaryBytes int64
}

func (o Options) args() []string {
	level := o.Level
	if level < 0 {
		level = 0
	}
	if level > 9 {
		level = 9
	}
	args := []string{"-mx=" + strconv.Itoa(level)}
	if o.Threads > 0 {
		args = append(args, "-mmt="+strconv.Itoa(o.Threads))
	} else {
		args = append(args, "-mmt=on")
	}
	if o.DictionaryBytes > 0 {
		args = append(args, "-md="+strconv.FormatInt(o.DictionaryBytes, 10)+"b")
	}
	return args
}

// quiet turns off every message 7-Zip would otherwise print and pins errors to
// stderr. This is not cosmetic: with -so the archive itself comes out of
// stdout, so anything else written there would corrupt the stream. The
// trailing digit of -bs is the destination stream – 0 off, 1 stdout, 2 stderr
// – and 7-Zip rightly refuses -bse1 while stdout carries the archive.
var quiet = []string{"-bso0", "-bsp0", "-bse2"}

// XZWriter compresses everything written to it and sends the xz stream to dst.
// Closing it flushes 7-Zip and reports what it had to say if it failed.
//
// This is the compression half of the backup pipeline: a tar stream goes in,
// an xz stream comes out, and nothing touches the disk on the way.
func (t *Tool) XZWriter(ctx context.Context, dst io.Writer, opts Options) (io.WriteCloser, error) {
	args := append([]string{"a", "bond.xz", "-txz", "-si", "-so"}, opts.args()...)
	cmd := t.Command(ctx, append(args, quiet...)...)
	cmd.Stdout = dst

	w := &xzPipe{cmd: cmd}
	cmd.Stderr = &w.stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	w.stdin = stdin

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the embedded 7-Zip: %w", err)
	}
	return w, nil
}

type xzPipe struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stderr bytes.Buffer

	once sync.Once
	err  error
}

func (w *xzPipe) Write(p []byte) (int, error) {
	n, err := w.stdin.Write(p)
	if err != nil {
		// A failed write almost always means 7-Zip already exited. Its own
		// complaint is far more useful than "broken pipe", so wait for it and
		// report that instead.
		if waitErr := w.wait(); waitErr != nil {
			return n, waitErr
		}
		return n, err
	}
	return n, nil
}

func (w *xzPipe) Close() error {
	if err := w.stdin.Close(); err != nil {
		w.wait()
		return err
	}
	return w.wait()
}

func (w *xzPipe) wait() error {
	w.once.Do(func() {
		err := w.cmd.Wait()
		if err != nil {
			w.err = commandError("compressing", err, w.stderr.Bytes())
		}
	})
	return w.err
}

// XZReader decompresses an xz stream, producing the bytes that went in. Close
// must be called; it reports a failure the reader itself could not see, such
// as a stream that ended early.
func (t *Tool) XZReader(ctx context.Context, src io.Reader) (io.ReadCloser, error) {
	// No archive name here, unlike the writer, which requires one. With -si on
	// an extract command 7-Zip reads any positional argument as a filter
	// naming files *inside* the archive: passing one matches nothing, and it
	// then writes zero bytes and exits successfully. On a restore path that
	// reads as an empty backup, so the argument list has to stay exactly this.
	cmd := t.Command(ctx, append([]string{"e", "-txz", "-si", "-so"}, quiet...)...)
	cmd.Stdin = src

	r := &xzOut{cmd: cmd}
	cmd.Stderr = &r.stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	r.stdout = stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the embedded 7-Zip: %w", err)
	}
	return r, nil
}

type xzOut struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr bytes.Buffer

	once sync.Once
	err  error
}

func (r *xzOut) Read(p []byte) (int, error) {
	n, err := r.stdout.Read(p)
	if err == io.EOF {
		// The stream ended: fold in 7-Zip's exit status, so a truncated or
		// corrupt archive is an error rather than a short read.
		if waitErr := r.wait(); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (r *xzOut) Close() error {
	// Closing first matters when the caller gave up early: 7-Zip then gets a
	// broken pipe and exits, instead of blocking forever on a reader nobody is
	// draining. The error is ignored because Wait closes this pipe itself, so
	// a drained stream reports "already closed" and means nothing.
	_ = r.stdout.Close()
	return r.wait()
}

func (r *xzOut) wait() error {
	r.once.Do(func() {
		err := r.cmd.Wait()
		if err != nil {
			r.err = commandError("decompressing", err, r.stderr.Bytes())
		}
	})
	return r.err
}

func commandError(what string, err error, stderr []byte) error {
	msg := strings.TrimSpace(string(stderr))
	if msg == "" {
		return fmt.Errorf("7-Zip failed while %s: %w", what, err)
	}
	return fmt.Errorf("7-Zip failed while %s: %w\n%s", what, err, msg)
}
