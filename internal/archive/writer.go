package archive

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// Writer streams entries into a tar. Nothing is buffered: the bytes go
// straight through to whatever the tar was opened on, which in a backup is the
// xz encoder and then the container.
type Writer struct {
	tw    *tar.Writer
	index []FileInfo
	bytes int64

	// OnWarning reports something worth telling the operator that is not bad
	// enough to abandon the backup, such as a file that changed while it was
	// being read.
	OnWarning func(path string, msg string)
}

// NewWriter starts a tar stream on w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{tw: tar.NewWriter(w)}
}

// Index is what was stored, in the order it was written.
func (w *Writer) Index() []FileInfo { return w.index }

// Bytes is the total file content written, excluding tar overhead.
func (w *Writer) Bytes() int64 { return w.bytes }

// Add stores one entry.
func (w *Writer) Add(e Entry) error {
	switch e.Kind {
	case KindDir:
		return w.addDir(e)
	default:
		return w.addFile(e)
	}
}

func (w *Writer) addDir(e Entry) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     e.Path + "/",
		Mode:     int64(e.Mode.Perm()),
		ModTime:  e.ModTime,
		Format:   tar.FormatPAX,
	}
	if err := w.tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	w.index = append(w.index, FileInfo{Path: e.Path, Kind: KindDir, Mode: e.Mode, ModTime: e.ModTime})
	return nil
}

func (w *Writer) addFile(e Entry) error {
	f, err := os.Open(e.Disk)
	if err != nil {
		return err
	}
	defer f.Close()

	// The size is taken from the open handle rather than from enumeration: a
	// backup runs against a live tree, and minutes can pass between walking a
	// directory and reaching this file. That closes most of the window but not
	// all of it, which is what writeRegular has to survive.
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	if e.Expected != nil && !os.SameFile(e.Expected, info) {
		return fmt.Errorf("%s changed identity between enumeration and opening; refusing to archive a substituted path", e.Path)
	}
	return w.writeRegular(e.Path, f, info.Size(), info.Mode(), info.ModTime())
}

// writeRegular streams exactly size bytes from r, whatever r actually holds.
func (w *Writer) writeRegular(name string, r io.Reader, size int64, mode fs.FileMode, modTime time.Time) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     size,
		Mode:     int64(mode.Perm()),
		ModTime:  modTime,
		Format:   tar.FormatPAX,
	}
	if err := w.tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	digest := sha256.New()
	written, err := io.CopyN(io.MultiWriter(w.tw, digest), r, size)
	switch {
	case err == io.EOF || (err == nil && written < size):
		// The file shrank after the header promised a length. tar demands
		// exactly that many bytes, so pad and say so; the digest covers the
		// padding, which keeps a later verification honest about what is
		// actually stored.
		if err := w.pad(digest, size-written); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		w.warn(name, fmt.Sprintf("shrank while being read (%d of %d bytes); the rest was stored as zeros", written, size))
	case err != nil:
		return fmt.Errorf("%s: %w", name, err)
	default:
		// Still more to read means it grew. The header is already committed,
		// so the tail is left out rather than corrupting the stream.
		if n, _ := io.Copy(io.Discard, io.LimitReader(r, 1)); n > 0 {
			w.warn(name, fmt.Sprintf("grew while being read; stored the first %d bytes", size))
		}
	}

	w.bytes += size
	w.index = append(w.index, FileInfo{
		Path:    name,
		Kind:    KindFile,
		Size:    size,
		Mode:    mode,
		ModTime: modTime,
		SHA256:  hex.EncodeToString(digest.Sum(nil)),
	})
	return nil
}

func (w *Writer) pad(digest io.Writer, n int64) error {
	if n <= 0 {
		return nil
	}
	zeros := make([]byte, 32<<10)
	for n > 0 {
		chunk := int64(len(zeros))
		if n < chunk {
			chunk = n
		}
		if _, err := w.tw.Write(zeros[:chunk]); err != nil {
			return err
		}
		if _, err := digest.Write(zeros[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

func (w *Writer) warn(path, msg string) {
	if w.OnWarning != nil {
		w.OnWarning(path, msg)
	}
}

// Close finishes the tar stream. It does not close the underlying writer.
func (w *Writer) Close() error { return w.tw.Close() }
