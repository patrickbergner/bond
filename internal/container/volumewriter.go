package container

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// Publish moves the set to its destination without replacing any existing
// container or checksum namespace. For split sets volume 1 is the commit point:
// every other volume and its directory entry are durable before it appears.
func (w *volumeWriter) Publish(dst string) ([]string, error) {
	if err := validatePublication(filepath.Dir(w.base), dst, w.Paths()); err != nil {
		return nil, err
	}
	targets := make([]string, len(w.files))
	for i := range w.files {
		target := dst
		if w.split {
			target = dst + VolumeSuffix(i)
		}
		targets[i] = target
	}

	order := make([]int, 0, len(w.files))
	if w.split {
		for i := 1; i < len(w.files); i++ {
			order = append(order, i)
		}
		order = append(order, 0)
	} else {
		order = append(order, 0)
	}

	var moved []int
	rollback := func(cause error) error {
		var rollbackErrs []error
		for i := len(moved) - 1; i >= 0; i-- {
			index := moved[i]
			if err := moveNoReplace(targets[index], w.files[index].path); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("returning %s to staging: %w", filepath.Base(targets[index]), err))
			}
		}
		return errors.Join(append([]error{cause}, rollbackErrs...)...)
	}

	for _, index := range order {
		if w.split && index == 0 {
			if err := syncDirectory(filepath.Dir(dst)); err != nil {
				return nil, rollback(err)
			}
		}
		if err := moveNoReplace(w.files[index].path, targets[index]); err != nil {
			return nil, rollback(fmt.Errorf("publishing %s without replacement: %w", filepath.Base(targets[index]), err))
		}
		moved = append(moved, index)
	}
	if err := syncDirectory(filepath.Dir(dst)); err != nil {
		return nil, rollback(err)
	}
	if filepath.Clean(filepath.Dir(w.base)) != filepath.Clean(filepath.Dir(dst)) {
		if err := syncDirectory(filepath.Dir(w.base)); err != nil {
			return nil, fmt.Errorf("syncing the staging directory after publication: %w", err)
		}
	}
	return targets, nil
}

var (
	moveNoReplace          = renameNoReplace
	syncDirectory          = syncDir
	validateMoveFilesystem = validateSameFilesystem
)

// ValidatePublication proves the staging and destination directories can use
// one-filesystem atomic moves, and that no part of the requested output
// namespace already exists. Callers do this before writing the payload;
// Publish repeats it to close ordinary races.
func ValidatePublication(stagingDir, dst string) error {
	return validatePublication(stagingDir, dst, nil)
}

// validatePublication takes the paths the caller is about to move, so the
// recheck inside Publish does not mistake the writer's own staging files for a
// competing container. That happens whenever workPath and outputPath name the
// same directory: the split staging volumes are called <base>.partial.001, and
// a rule that only looked at the trailing digits matched them. The preflight
// then passed, because nothing existed yet, and the recheck failed after the
// whole backup had been written.
func validatePublication(stagingDir, dst string, ours []string) error {
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := outputNamespaceAvailable(dst, ours); err != nil {
		return err
	}
	if err := validateMoveFilesystem(stagingDir, filepath.Dir(dst)); err != nil {
		return fmt.Errorf("publication requires atomic moves within one filesystem: %w", err)
	}
	return nil
}

// sidecarSuffixes are the checksum files WriteSidecar can produce. They are part
// of the namespace a publication claims, because a stale digest beside a new
// container is worse than no digest at all.
var sidecarSuffixes = []string{".sha256", ".sha384", ".sha512"}

// numberedVolumeOf reports whether name is base plus a volume suffix, by the
// same rule VolumeFiles uses to discover a set. Matching the trailing digits
// alone is not that rule: backup.bond.old.001 ends in a volume suffix but
// belongs to backup.bond.old, and VolumeFiles correctly ignores it.
func numberedVolumeOf(base, name string) bool {
	match := volumePattern.FindString(name)
	return match != "" && strings.TrimSuffix(name, match) == base
}

func occupiesNamespace(base, name string) bool {
	if name == base || numberedVolumeOf(base, name) {
		return true
	}
	for _, ext := range sidecarSuffixes {
		if stem := strings.TrimSuffix(name, ext); stem != name {
			if stem == base || numberedVolumeOf(base, stem) {
				return true
			}
		}
	}
	return false
}

func outputNamespaceAvailable(dst string, ours []string) error {
	dir := filepath.Dir(dst)
	base := filepath.Base(dst)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	staging := make(map[string]bool, len(ours))
	for _, p := range ours {
		staging[filepath.Clean(p)] = true
	}

	var taken []string
	for _, entry := range entries {
		full := filepath.Join(dir, entry.Name())
		if occupiesNamespace(base, entry.Name()) && !staging[filepath.Clean(full)] {
			taken = append(taken, entry.Name())
		}
	}
	if len(taken) == 0 {
		return nil
	}
	// Name them. BOND will not replace an existing backup, so the operator has
	// to decide what happens to these files, and they cannot do that from a
	// message that mentions only the first one it happened to see. A previous
	// split set can be a thousand files, though, and a thousand-name error is
	// no more usable than a one-name one.
	them, listed := "it", taken
	if len(taken) > 1 {
		them = "them"
	}
	const show = 8
	suffix := ""
	if len(listed) > show {
		suffix = fmt.Sprintf(" and %d more", len(listed)-show)
		listed = listed[:show]
	}
	return fmt.Errorf("%s already holds %s%s, which is the namespace this container would be published into; "+
		"BOND never replaces an existing backup, so move or delete %s first, or publish under another name",
		dir, strings.Join(listed, ", "), suffix, them)
}
