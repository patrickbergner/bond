package sevenzip

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

func tool(t *testing.T) *Tool {
	t.Helper()
	tl, err := Extract(t.TempDir())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	t.Cleanup(func() { tl.Close() })
	return tl
}

func TestVersion(t *testing.T) {
	v, err := tool(t).Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !strings.Contains(v, "7-Zip") {
		t.Errorf("Version = %q, want it to name 7-Zip", v)
	}
	t.Logf("embedded: %s", v)
}

func TestExtractIsSelfChecking(t *testing.T) {
	tl := tool(t)
	if tl.Path() == "" {
		t.Fatal("no path")
	}
	if err := tl.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Close must be safe to call more than once, and on a nil tool, because it
	// is always deferred.
	if err := tl.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	var nilTool *Tool
	if err := nilTool.Close(); err != nil {
		t.Errorf("Close on a nil tool: %v", err)
	}
}

func TestXZRoundTrip(t *testing.T) {
	tl := tool(t)
	ctx := context.Background()

	// Two copies of the same random block: incompressible on its own, so a
	// ratio near half proves the encoder saw both halves as one stream. That
	// is the property BOND relies on instead of 7-Zip's solid mode.
	block := make([]byte, 1<<20)
	rand.Read(block)
	input := append(append([]byte(nil), block...), block...)

	var compressed bytes.Buffer
	w, err := tl.XZWriter(ctx, &compressed, Options{Level: 5})
	if err != nil {
		t.Fatalf("XZWriter: %v", err)
	}
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := compressed.Bytes()[:6]; !bytes.Equal(got, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}) {
		t.Errorf("output does not start with the xz magic: % x", got)
	}
	if ratio := float64(compressed.Len()) / float64(len(input)); ratio > 0.6 {
		t.Errorf("compressed to %.0f%% of the input; the duplicate half should have collapsed", ratio*100)
	}

	r, err := tl.XZReader(ctx, bytes.NewReader(compressed.Bytes()))
	if err != nil {
		t.Fatalf("XZReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("round trip changed the data: got %d bytes, want %d", len(got), len(input))
	}
}

func TestXZEmptyStream(t *testing.T) {
	tl := tool(t)
	ctx := context.Background()

	var compressed bytes.Buffer
	w, err := tl.XZWriter(ctx, &compressed, Options{Level: 1})
	if err != nil {
		t.Fatalf("XZWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close on an empty stream: %v", err)
	}

	r, err := tl.XZReader(ctx, bytes.NewReader(compressed.Bytes()))
	if err != nil {
		t.Fatalf("XZReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes back from an empty stream", len(got))
	}
}

func TestXZLevels(t *testing.T) {
	tl := tool(t)
	ctx := context.Background()
	input := bytes.Repeat([]byte("bond backs up on non-trusted destinations. "), 20000)

	for _, level := range []int{0, 1, 5, 9} {
		var compressed bytes.Buffer
		w, err := tl.XZWriter(ctx, &compressed, Options{Level: level})
		if err != nil {
			t.Fatalf("level %d: XZWriter: %v", level, err)
		}
		if _, err := w.Write(input); err != nil {
			t.Fatalf("level %d: Write: %v", level, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("level %d: Close: %v", level, err)
		}

		r, _ := tl.XZReader(ctx, bytes.NewReader(compressed.Bytes()))
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("level %d: ReadAll: %v", level, err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("level %d: Close: %v", level, err)
		}
		if !bytes.Equal(got, input) {
			t.Errorf("level %d: round trip changed the data", level)
		}
		t.Logf("level %d: %d -> %d bytes", level, len(input), compressed.Len())
	}
}

// A stream that is not xz at all has to be reported as an error rather than
// silently producing nothing, because on the restore path that would look like
// an empty backup.
func TestXZReaderRejectsGarbage(t *testing.T) {
	tl := tool(t)
	r, err := tl.XZReader(context.Background(), strings.NewReader("this is not an xz stream"))
	if err != nil {
		t.Fatalf("XZReader: %v", err)
	}
	_, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr == nil && closeErr == nil {
		t.Fatal("garbage input produced no error")
	}
}

// A truncated stream is the shape corruption takes in practice. It must not
// look like a clean end of file.
func TestXZReaderRejectsTruncation(t *testing.T) {
	tl := tool(t)
	ctx := context.Background()

	var compressed bytes.Buffer
	w, _ := tl.XZWriter(ctx, &compressed, Options{Level: 1})
	w.Write(bytes.Repeat([]byte("payload "), 10000))
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cut := compressed.Bytes()[:compressed.Len()/2]
	r, err := tl.XZReader(ctx, bytes.NewReader(cut))
	if err != nil {
		t.Fatalf("XZReader: %v", err)
	}
	_, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr == nil && closeErr == nil {
		t.Fatal("a truncated stream produced no error")
	}
}

func TestXZWriterStreamsWithoutBuffering(t *testing.T) {
	tl := tool(t)
	ctx := context.Background()

	// Feed a lot more than any pipe buffer could hold, in small writes, to
	// prove the writer really streams instead of collecting the input.
	var compressed bytes.Buffer
	w, err := tl.XZWriter(ctx, &compressed, Options{Level: 1})
	if err != nil {
		t.Fatalf("XZWriter: %v", err)
	}
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	const chunks = 128 // 8 MiB
	for i := 0; i < chunks; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, _ := tl.XZReader(ctx, bytes.NewReader(compressed.Bytes()))
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if want := int64(chunks) * int64(len(chunk)); n != want {
		t.Errorf("round trip produced %d bytes, want %d", n, want)
	}
}
