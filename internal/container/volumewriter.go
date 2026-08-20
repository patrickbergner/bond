package container

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/patrickbergner/bond/internal/format"
)

// volumeWriter lays the payload down across one or more files.
//
// A volume is closed and the next one begun only between shards, never inside
// one, so every shard stays readable from a single file. That costs a little
// unused space at the end of each volume and buys a reader that never has to
// stitch a shard back together.
type volumeWriter struct {
	base  string // path without any numbered suffix
	split bool
	limit int64 // payload bytes allowed in one volume

	files   []*volumeFile
	cur     *volumeFile
	logical int64 // payload bytes written across the whole set
}

type volumeFile struct {
	path         string
	f            *os.File
	index        int
	payloadStart int64
	logicalStart int64
	payloadBytes int64
	tailBytes    int64
}

// newVolumeWriter starts a set. maxVolumeBytes of zero means one file.
func newVolumeWriter(base string, maxVolumeBytes int64) (*volumeWriter, error) {
	w := &volumeWriter{base: base, split: maxVolumeBytes > 0}
	if w.split {
		// The head of a volume and the metadata at the end of it are not
		// payload, so they come off the budget.
		w.limit = maxVolumeBytes - format.PayloadOffset - tailReserve

		// The reserve is a courtesy, not a rule: it keeps the last volume
		// under the limit in the ordinary case. When the limit is small enough
		// that reserving would leave no room at all, it is given up and the
		// final volume is simply allowed to run over by the size of the
		// manifest. The mirrored header is not given up with it – every volume
		// carries one, so it is part of the floor rather than part of the
		// courtesy.
		if w.limit < minVolumePayload {
			w.limit = maxVolumeBytes - format.PayloadOffset - format.SuperblockSize
		}
		if w.limit < minVolumePayload {
			return nil, fmt.Errorf("maxVolumeBytes of %d leaves no room for payload; use at least %d",
				maxVolumeBytes, format.PayloadOffset+format.SuperblockSize+minVolumePayload)
		}
	}
	if err := w.roll(); err != nil {
		return nil, err
	}
	return w, nil
}

const (
	// tailReserve keeps room in every volume for the mirrored header it carries
	// and for the manifest that the last one adds. A file index of a million
	// files can exceed it, in which case the final volume is simply a little
	// larger than asked for – better than refusing to finish a backup over it.
	tailReserve = 4 << 20

	// minVolumePayload stops a limit so small that the set would be mostly
	// headers. One shard is the floor: a volume that cannot hold one is not a
	// volume.
	minVolumePayload = 64 << 10
)

// roll starts a new volume.
func (w *volumeWriter) roll() error {
	index := len(w.files)
	path := w.base
	if w.split {
		path = w.base + VolumeSuffix(index)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	// Volume 1 carries the key slots as well as the header; the rest start
	// their payload straight after their header copy.
	start := int64(format.SuperblockSize)
	if index == 0 {
		start = format.PayloadOffset
	}
	if err := f.Truncate(start); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Seek(start, 0); err != nil {
		f.Close()
		return err
	}

	vf := &volumeFile{path: path, f: f, index: index, payloadStart: start, logicalStart: w.logical}
	w.files = append(w.files, vf)
	w.cur = vf
	return nil
}

// WriteShard appends one shard, moving to a new volume first if this one is
// full.
func (w *volumeWriter) WriteShard(b []byte) error {
	if w.split && w.cur.payloadBytes > 0 && w.cur.payloadBytes+int64(len(b)) > w.limit {
		if err := w.roll(); err != nil {
			return err
		}
	}
	if _, err := w.cur.f.Write(b); err != nil {
		return err
	}
	w.cur.payloadBytes += int64(len(b))
	w.logical += int64(len(b))
	return nil
}

// WriteTail appends the metadata that closes the last volume.
func (w *volumeWriter) WriteTail(b []byte) error {
	if _, err := w.cur.f.Write(b); err != nil {
		return err
	}
	w.cur.tailBytes += int64(len(b))
	return nil
}

// Count is how many volumes the set has.
func (w *volumeWriter) Count() int { return len(w.files) }

// Logical is how much payload has been written.
func (w *volumeWriter) Logical() int64 { return w.logical }

// TailOffset is where the trailing metadata begins in the last volume.
func (w *volumeWriter) TailOffset() int64 { return w.cur.payloadStart + w.cur.payloadBytes }

// headerFor renders the shared superblock as one volume's own: the copies
// differ only in which slice of the payload they describe.
//
// Both the leading header and the mirror come through here, so the two copies
// of a volume's header cannot drift apart – which is what lets a reader treat
// byte-identity between them as "there is nothing to choose between these".
func (w *volumeWriter) headerFor(sb *format.Superblock, vf *volumeFile) format.Superblock {
	vs := *sb
	vs.VolumeIndex = uint32(vf.index)
	vs.VolumeCount = uint32(len(w.files))
	vs.VolumeLogicalStart = uint64(vf.logicalStart)
	vs.VolumeLogicalLen = uint64(vf.payloadBytes)
	return vs
}

// PatchHeaders writes each volume's own superblock at the front of it.
func (w *volumeWriter) PatchHeaders(sb *format.Superblock, sign func(*format.Superblock)) error {
	for _, vf := range w.files {
		vs := w.headerFor(sb, vf)
		sign(&vs)
		if _, err := vf.f.WriteAt(vs.Marshal(), 0); err != nil {
			return err
		}
	}
	return nil
}

// WriteMirrors closes every volume with a mirror of its own header.
//
// The mirror used to close only the last file, which left volume 1 and every
// middle volume holding a single copy of their header: one flipped bit there
// and the whole set was unopenable from any entry point, because openSet always
// re-reads volume 1 and there was no second opinion anywhere in the set. Four
// kilobytes per file buys back the promise the rest of the format keeps, that
// everything outside the payload is stored twice.
//
// It cannot be done when the volume is rolled: the tail offset, shard count and
// key commitment are only settled at Finish.
func (w *volumeWriter) WriteMirrors(sb *format.Superblock, sign func(*format.Superblock)) error {
	for _, vf := range w.files {
		vs := w.headerFor(sb, vf)
		sign(&vs)
		at := vf.payloadStart + vf.payloadBytes + vf.tailBytes
		if _, err := vf.f.WriteAt(vs.Marshal(), at); err != nil {
			return err
		}
	}
	return nil
}

// WriteHead writes the key-slot tables, which live only in volume 1.
func (w *volumeWriter) WriteHead(slotsA, slotsB []byte) error {
	first := w.files[0].f
	if _, err := first.WriteAt(slotsA, format.SlotTableAOffset); err != nil {
		return err
	}
	_, err := first.WriteAt(slotsB, format.SlotTableBOffset)
	return err
}

// Sync flushes every volume.
func (w *volumeWriter) Sync() error {
	for _, vf := range w.files {
		if err := vf.f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes every volume.
func (w *volumeWriter) Close() error {
	var err error
	for _, vf := range w.files {
		if closeErr := vf.f.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

// Remove deletes every volume, for an abandoned backup.
func (w *volumeWriter) Remove() {
	w.Close()
	for _, vf := range w.files {
		os.Remove(vf.path)
	}
}

// Paths lists the files written.
func (w *volumeWriter) Paths() []string {
	out := make([]string, len(w.files))
	for i, vf := range w.files {
		out[i] = vf.path
	}
	return out
}

// Publish moves the set to its destination, keeping the numbering.
func (w *volumeWriter) Publish(dst string) ([]string, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	published := make([]string, 0, len(w.files))
	for _, vf := range w.files {
		target := dst
		if w.split {
			target = dst + VolumeSuffix(vf.index)
		}
		if err := os.Rename(vf.path, target); err != nil {
			return published, err
		}
		published = append(published, target)
	}
	if d, err := os.Open(filepath.Dir(dst)); err == nil {
		d.Sync()
		d.Close()
	}
	return published, nil
}
