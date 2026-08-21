package container

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

// A container may be split across several files, because a cloud object store
// that is happy with a hundred 5 GB files may refuse one 500 GB file.
//
// The split is purely physical. The payload is one logical byte range whatever
// it is stored in, and every volume records which slice of it that volume
// holds. Volume 1 carries the header and both key-slot tables; the last carries
// the manifest; and every volume has an authenticated leading header plus a
// required mirror at EOF so any one file can identify the set it belongs to.
//
// Volumes never split a shard, so any single shard is always readable from one
// file.

// VolumeSuffix formats the numbered extension: name.bond.001, .002, …
func VolumeSuffix(index int) string { return fmt.Sprintf(".%03d", index+1) }

var volumePattern = regexp.MustCompile(`\.(\d{3,})$`)

// VolumeBase strips a numbered suffix, giving the name the set is known by.
// backup.bond.003 and backup.bond both answer to backup.bond.
func VolumeBase(path string) string {
	if m := volumePattern.FindString(path); m != "" {
		n, err := strconv.ParseUint(m[1:], 10, 64)
		if err != nil || n == 0 {
			return path
		}
		return strings.TrimSuffix(path, m)
	}
	return path
}

// VolumeFiles discovers a container set by name without trusting a header.
// It is shared with quick verification so readers and checksum checks accept
// exactly the same numeric suffixes.
func VolumeFiles(path string) ([]string, error) {
	base := VolumeBase(path)
	dir := filepath.Dir(base)
	name := filepath.Base(base)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type numbered struct {
		n    uint64
		path string
	}
	var found []numbered
	for _, entry := range entries {
		candidate := entry.Name()
		if !numberedVolumeOf(name, candidate) {
			continue
		}
		match := volumePattern.FindString(candidate)
		n, parseErr := strconv.ParseUint(match[1:], 10, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("volume suffix %q is too large", match)
		}
		if n == 0 {
			return nil, fmt.Errorf("%s uses invalid volume number .000", candidate)
		}
		found = append(found, numbered{n: n, path: filepath.Join(dir, candidate)})
	}
	_, baseErr := os.Stat(base)
	baseExists := baseErr == nil
	if baseErr != nil && !os.IsNotExist(baseErr) {
		return nil, baseErr
	}
	if baseExists && len(found) > 0 {
		return nil, fmt.Errorf("both %s and a numbered set with the same base exist", filepath.Base(base))
	}
	if baseExists {
		return []string{base}, nil
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%s does not exist", path)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].n < found[j].n })
	paths := make([]string, len(found))
	for i, volume := range found {
		want := uint64(i + 1)
		if volume.n != want {
			return nil, fmt.Errorf("numbered volume set is not contiguous: found .%03d where .%03d is required", volume.n, want)
		}
		paths[i] = volume.path
	}
	return paths, nil
}

// headerPos is which of a volume's two header positions a copy came from.
type headerPos int

const (
	headerLeading headerPos = iota
	headerMirror
)

// headerCopy is one parsed copy of a volume's superblock, and where it was
// found.
type headerCopy struct {
	sb     *format.Superblock
	source string
	at     headerPos
}

// headerScan is what both of a volume's header positions yielded.
//
// The surviving copies alone cannot say what happened: a healthy volume yields
// one entry, because the mirror is identical and is dropped as no second
// opinion – and so does a volume whose mirror is unreadable, and so does one
// whose leading header is unreadable. Telling those three apart is what lets
// the reader say a container is down to its last copy of something, and what
// lets repair believe it and put the copy back.
type headerScan struct {
	copies []headerCopy // every copy that parsed, the leading position first
	twin   bool         // the mirror parsed and matched the leading copy byte for byte
}

// volume is one file of a set.
type volume struct {
	path string
	f    *os.File
	size int64

	// scan holds the header copies that parsed, leading one first. Both are
	// kept rather than one being chosen at open time, because the choice cannot
	// be made yet: a header that parses is not the same as a header that is
	// right, and which one is authentic is only knowable once a key is in hand.
	scan  headerScan
	using int

	sb *format.Superblock // copies[using].sb, for convenience

	// payloadStart is where this volume's slice of the payload begins inside
	// the file; logicalStart is where that slice begins in the payload as a
	// whole.
	payloadStart int64
	logicalStart int64
	logicalLen   int64
}

// use adopts one of the header copies and recomputes everything derived from
// it, so switching copies cannot leave the volume half-described.
func (v *volume) use(i int) {
	v.using = i
	v.sb = v.scan.copies[i].sb
	v.payloadStart = format.SuperblockSize
	if v.sb.VolumeIndex == 0 {
		v.payloadStart = format.PayloadOffset
	}
	v.logicalStart = int64(v.sb.VolumeLogicalStart)
	v.logicalLen = int64(v.sb.VolumeLogicalLen)
}

func (v *volume) source() string { return v.scan.copies[v.using].source }

// headerNotice says what had to be worked around for this volume's header, or
// "" when both copies were intact. It means anything only after authenticate
// has settled which copy is real.
//
// A second copy needs no MAC of its own to be judged: the copy in use has
// authenticated, so one that differs from it by a single byte cannot also be
// authentic – that would be an HMAC collision. Missing, unparseable and
// unauthentic therefore collapse into one message, which is the right grain.
// The operator needs to know the volume is down to one header, not which of the
// three ways it got there.
func (v *volume) headerNotice(volumes int) string {
	where := ""
	if volumes > 1 {
		where = " of " + filepath.Base(v.path)
	}
	switch {
	case v.scan.copies[v.using].at != headerLeading:
		return "the header at the front" + where + " is damaged; the mirror at the end was used"
	case !v.scan.twin:
		return "the mirrored header at the end" + where + " is damaged; only one copy of it is left"
	}
	return ""
}

// authenticate finds the copy of this volume's header that carries a valid MAC,
// preferring the one already in use.
//
// This is the reason both copies are carried this far. A single flipped bit in
// the leading header often leaves it perfectly parseable and merely
// unauthentic, and refusing the container then – with an intact mirror sitting
// at the end of the same file – would throw away a backup over one bad byte.
func (v *volume) authenticate(keys *crypto.Keys) error {
	inUse := v.sb.Verify(keys)
	if inUse == nil {
		return nil
	}
	for i := range v.scan.copies {
		if i == v.using {
			continue
		}
		if v.scan.copies[i].sb.Verify(keys) == nil {
			v.use(i)
			return nil
		}
	}
	return inUse
}

// volumeSet presents a whole container, however many files it is in.
type volumeSet struct {
	vols []*volume
}

// openVolumes opens the container that path belongs to.
//
// Any file of the set will do: each carries a header copy saying how many
// there are, so a restore started from volume 7 finds the rest.
func openVolumes(path string) (*volumeSet, *format.Superblock, string, error) {
	if match := volumePattern.FindString(path); match != "" {
		if n, err := strconv.ParseUint(match[1:], 10, 64); err != nil || n == 0 {
			return nil, nil, "", fmt.Errorf("invalid numbered volume suffix %q", match)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		// A set written with splitting on is named .001 even when it turned
		// out to need only one file, so the obvious name is tried too.
		if os.IsNotExist(err) {
			if alt, altErr := os.Open(path + VolumeSuffix(0)); altErr == nil {
				f, path = alt, path+VolumeSuffix(0)
			} else {
				return nil, nil, "", err
			}
		} else {
			return nil, nil, "", err
		}
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, "", err
	}
	if info.Size() < format.SuperblockSize {
		f.Close()
		return nil, nil, "", fmt.Errorf("%s is too small to be a container", path)
	}

	scan, err := readSuperblocks(f, info.Size())
	if err != nil {
		f.Close()
		return nil, nil, "", err
	}

	// Every copy of the header gets a turn at saying what this container is. The
	// volume count decides whether one file or twenty are opened, and a flipped
	// bit in it would otherwise send the reader hunting for volumes that were
	// never written – with the right answer sitting in the mirror all along.
	var firstErr error
	for i := range scan.copies {
		if scan.copies[i].sb.VolumeCount <= 1 {
			// No contiguity check here on purpose: with one file there is
			// nothing to line up, and refusing on a number nobody has
			// authenticated yet would throw away a container whose other header
			// copy is perfectly good. verifyAll checks it once the key has
			// settled which copy is real.
			v := &volume{path: path, f: f, size: info.Size(), scan: scan}
			v.use(i)
			return &volumeSet{vols: []*volume{v}}, v.sb, v.source(), nil
		}
		set, err := openSet(path, scan.copies[i].sb)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		f.Close()
		return set, set.First().sb, set.First().source(), nil
	}
	f.Close()
	return nil, nil, "", firstErr
}

// openSet opens every file of a split container, with sb as the description of
// what the set should look like.
func openSet(path string, sb *format.Superblock) (*volumeSet, error) {
	base := VolumeBase(path)
	set := &volumeSet{}

	for i := range int(sb.VolumeCount) {
		vp := base + VolumeSuffix(i)
		vf, err := os.Open(vp)
		if err != nil {
			set.Close()
			return nil, fmt.Errorf("this container is in %d volumes and %s is missing: %w",
				sb.VolumeCount, filepath.Base(vp), err)
		}
		vi, err := vf.Stat()
		if err != nil {
			vf.Close()
			set.Close()
			return nil, err
		}
		scan, err := readSuperblocks(vf, vi.Size())
		if err != nil {
			vf.Close()
			set.Close()
			return nil, fmt.Errorf("%s: %w", filepath.Base(vp), err)
		}

		// Any copy that agrees with the set will do. Which one is authentic
		// still needs a key, so all that can be ruled out here are the copies
		// that cannot be – and committing to the leading one would refuse a
		// volume whose mirror says exactly the right thing. Volumes of two
		// different containers can have identical geometry, so the identity is
		// checked rather than inferred from the file names lining up.
		chosen := -1
		for j, c := range scan.copies {
			if c.sb.VolumeIndex == uint32(i) && c.sb.VolumeCount == sb.VolumeCount &&
				bytes.Equal(c.sb.ContainerUUID, sb.ContainerUUID) {
				chosen = j
				break
			}
		}
		if chosen < 0 {
			vsb := scan.copies[0].sb
			vf.Close()
			set.Close()
			if !bytes.Equal(vsb.ContainerUUID, sb.ContainerUUID) {
				return nil, fmt.Errorf("%s belongs to a different container (%x, not %x)",
					filepath.Base(vp), vsb.ContainerUUID[:8], sb.ContainerUUID[:8])
			}
			return nil, fmt.Errorf("%s says it is volume %d of %d, expected %d of %d",
				filepath.Base(vp), vsb.VolumeIndex+1, vsb.VolumeCount, i+1, sb.VolumeCount)
		}

		v := &volume{path: vp, f: vf, size: vi.Size(), scan: scan}
		v.use(chosen)
		set.vols = append(set.vols, v)
	}

	// A set whose volumes still carry a second header copy cannot be judged on
	// contiguity yet: the numbers come from copies nobody has authenticated, and
	// refusing here would throw away a container whose mirrors are perfectly
	// good. verifyAll checks it again once the key has settled which copy is
	// real – the same reasoning as the single-volume case in openVolumes.
	if err := set.checkContiguous(); err != nil && !set.hasSpareHeaders() {
		set.Close()
		return nil, err
	}
	return set, nil
}

// hasSpareHeaders reports whether any volume carries a second header copy that
// could still change the set's shape once a key is available.
func (vs *volumeSet) hasSpareHeaders() bool {
	for _, v := range vs.vols {
		if len(v.scan.copies) > 1 {
			return true
		}
	}
	return false
}

// readSuperblocks returns every copy of a volume's header that parses: the one
// at the front of the file, and the mirror at its end.
//
// It does not choose between them. Which copy is authentic needs a key, so the
// decision belongs to Unlock; all this can say is which copies are structurally
// a header at all.
func readSuperblocks(f *os.File, size int64) (headerScan, error) {
	var (
		scan     headerScan
		problems []error
	)

	head := make([]byte, format.SuperblockSize)
	if _, err := f.ReadAt(head, 0); err != nil {
		problems = append(problems, err)
	} else if sb, err := format.Unmarshal(head); err != nil {
		problems = append(problems, err)
	} else {
		scan.copies = append(scan.copies, headerCopy{sb, "header", headerLeading})
	}

	if size >= 2*format.SuperblockSize {
		mirror := make([]byte, format.SuperblockSize)
		if _, err := f.ReadAt(mirror, size-format.SuperblockSize); err != nil {
			problems = append(problems, err)
		} else if sb, err := format.Unmarshal(mirror); err != nil {
			problems = append(problems, err)
		} else if len(scan.copies) > 0 && scan.copies[0].sb.IdenticalTo(sb) {
			// An identical mirror is no second opinion, so it is not kept as
			// one. The comparison is on the bytes as they were read rather than
			// on a re-marshal: two copies that differ only in a region this
			// build does not interpret are still different headers, and one of
			// them is about to fail its MAC. Dropping it as a twin would leave
			// the reader holding the damaged one with nowhere to go.
			scan.twin = true
		} else {
			scan.copies = append(scan.copies, headerCopy{sb, "mirror at the end of the file", headerMirror})
		}
	}

	if len(scan.copies) > 0 {
		return scan, nil
	}
	if allNotContainer(problems) {
		return headerScan{}, format.ErrNotContainer
	}
	return headerScan{}, fmt.Errorf("both copies of the container header are damaged: %w", errors.Join(problems...))
}

func allNotContainer(errs []error) bool {
	for _, err := range errs {
		if err != format.ErrNotContainer {
			return false
		}
	}
	return len(errs) > 0
}

// checkContiguous makes the volumes describe one unbroken payload. A gap or an
// overlap means the files do not belong together, whatever their names say.
func (vs *volumeSet) checkContiguous() error {
	var next int64
	for _, v := range vs.vols {
		if v.logicalStart != next {
			return fmt.Errorf("%s covers the payload from %d, but %d was expected; these volumes are not one container",
				filepath.Base(v.path), v.logicalStart, next)
		}
		if v.payloadStart+v.logicalLen > v.size {
			return fmt.Errorf("%s claims %s of payload but is only %d bytes",
				filepath.Base(v.path), formatBytes(v.logicalLen), v.size)
		}
		next += v.logicalLen
	}
	return nil
}

func formatBytes(n int64) string { return strconv.FormatInt(n, 10) + " bytes" }

// ReadPayload reads from the payload as though it were one file.
func (vs *volumeSet) ReadPayload(p []byte, logical int64) error {
	for len(p) > 0 {
		v := vs.find(logical)
		if v == nil {
			return io.ErrUnexpectedEOF
		}
		within := logical - v.logicalStart
		n := min(int64(len(p)), v.logicalLen-within)
		if n <= 0 {
			return io.ErrUnexpectedEOF
		}
		if _, err := v.f.ReadAt(p[:n], v.payloadStart+within); err != nil {
			return err
		}
		p = p[n:]
		logical += n
	}
	return nil
}

func (vs *volumeSet) find(logical int64) *volume {
	for _, v := range vs.vols {
		if logical >= v.logicalStart && logical < v.logicalStart+v.logicalLen {
			return v
		}
	}
	return nil
}

// First is the volume holding the header and key slots.
func (vs *volumeSet) First() *volume { return vs.vols[0] }

// Last is the volume holding the manifest and the mirrored header.
func (vs *volumeSet) Last() *volume { return vs.vols[len(vs.vols)-1] }

// Count is how many files the container is in.
func (vs *volumeSet) Count() int { return len(vs.vols) }

// Paths lists the files, in order.
func (vs *volumeSet) Paths() []string {
	out := make([]string, len(vs.vols))
	for i, v := range vs.vols {
		out[i] = v.path
	}
	return out
}

// PayloadBytes is how much payload the set holds.
func (vs *volumeSet) PayloadBytes() int64 {
	var total int64
	for _, v := range vs.vols {
		total += v.logicalLen
	}
	return total
}

func (vs *volumeSet) Close() error {
	var err error
	for _, v := range vs.vols {
		if v.f != nil {
			if closeErr := v.f.Close(); err == nil {
				err = closeErr
			}
		}
	}
	return err
}

// verifyAll authenticates every volume's own header, falling back to a mirror
// where one survives.
//
// The container UUID check at open time catches a volume from a different
// backup, but only this proves each file is the one that was written: the MAC
// is over that volume's own header, under the key only this container has.
func (vs *volumeSet) verifyAll(keys *crypto.Keys) error {
	for i, v := range vs.vols {
		if err := v.authenticate(keys); err != nil {
			return fmt.Errorf("%s (volume %d of %d): %w", filepath.Base(v.path), i+1, len(vs.vols), err)
		}
	}
	return vs.checkContiguous()
}
