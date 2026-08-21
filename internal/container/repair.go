package container

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
)

// RepairResult reports what a repair did.
type RepairResult struct {
	Path          string
	Paths         []string // every file written, which is more than one for a split set
	RepairedData  []uint64
	RepairedParit []ParityRef
	Stripes       int
	Report        Report // the verification of the repaired copy

	// Metadata names the regions rewritten from their spare copy: the header,
	// the key-slot tables.
	Metadata []string
}

// Repaired is how many shards were rebuilt.
func (r *RepairResult) Repaired() int { return len(r.RepairedData) + len(r.RepairedParit) }

// Repair rebuilds a damaged container into a new file.
//
// It never writes to the original. A repair works from a container that is by
// definition already suspect, and an in-place rebuild that failed halfway
// would turn recoverable damage into a total loss – so the damaged copy stays
// exactly as it is until the repaired one has been written and verified.
//
// The arithmetic runs on the stored ciphertext, because that is what the
// parity covers. Every rebuilt shard is then decrypted and authenticated: Reed-
// Solomon says the bytes were reconstructed, and only the authentication tag
// says they are the right ones.
func Repair(r *Reader, dst string, report Report, progress func(stripe, total int)) (*RepairResult, error) {
	if !r.unlocked {
		return nil, fmt.Errorf("the container is locked")
	}
	l := r.sb.Layout()

	// Damage the reader already worked around – a header taken from the mirror,
	// key slots taken from the spare table – still has to be repaired. The copy
	// below is byte for byte, so without this it would be faithfully reproduced
	// in the "repaired" container, and the next flip in the surviving copy would
	// be the one that lost the backup.
	metadata := len(r.Notices()) > 0

	switch {
	case report.Damaged() && !l.Plan.Enabled():
		return nil, fmt.Errorf("this container carries no recovery data, so the damaged shards cannot be rebuilt; restore from another copy")
	case report.Damaged() && !report.Repairable:
		return nil, fmt.Errorf("the damage is beyond what the recovery data covers: %s",
			describeUnrepairable(report.Unrepairable, l))
	case !report.Damaged() && !metadata:
		return nil, fmt.Errorf("nothing to repair: every shard authenticates and no spare copy had to be used")
	}

	aead, err := crypto.AEAD(r.sb.Cipher, r.keys.Data)
	if err != nil {
		return nil, err
	}

	// Start from a copy: everything that is intact stays byte for byte what it
	// was, including the header, the key slots and the manifest. A split
	// container is copied volume for volume, keeping the numbering.
	out, err := copySet(r.vols, dst)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	result := &RepairResult{Path: dst, Paths: out.Paths(), Stripes: l.Stripes()}
	if metadata {
		names, err := out.healMetadata(r)
		if err != nil {
			return nil, err
		}
		result.Metadata = names
	}
	if !report.Damaged() {
		if err := out.Sync(); err != nil {
			return nil, err
		}
		return result, nil
	}

	coder, err := parity.NewCoder(l.Plan)
	if err != nil {
		return nil, err
	}

	damagedData := make(map[uint64]bool, len(report.DamagedShards))
	for _, i := range report.DamagedShards {
		damagedData[i] = true
	}
	damagedParity := make(map[ParityRef]bool, len(report.DamagedParity))
	for _, p := range report.DamagedParity {
		damagedParity[p] = true
	}

	for s := range l.Stripes() {
		if progress != nil {
			progress(s+1, l.Stripes())
		}
		if !stripeNeedsWork(l, s, damagedData, damagedParity) {
			continue
		}

		width := l.DataInStripe(s)
		first := uint64(s) * uint64(l.Plan.Data)
		shardLen := l.ShardLen(s)

		data := make([][]byte, width)
		lengths := make([]uint32, width)
		for j := range width {
			index := first + uint64(j)
			lengths[j] = l.DataLen(index)
			if damagedData[index] {
				continue
			}
			raw, err := r.rawShard(index)
			if err != nil {
				return nil, fmt.Errorf("reading shard %d: %w", index, err)
			}
			// Which shards were damaged was decided by an earlier pass, and the
			// container has been sitting on untrusted storage in between. A
			// shard that rotted since then would go into the arithmetic as
			// though it were sound, and Reed-Solomon cannot tell the difference:
			// it would rebuild the missing shards out of it and produce bytes
			// that are wrong everywhere instead of missing in one place.
			if !shardAuthenticates(aead, r.sb, index, raw) {
				return nil, fmt.Errorf(
					"shard %d authenticated when the container was checked and does not now; run bond verify again", index)
			}
			data[j] = raw
		}

		parityShards := make([][]byte, l.ParityInStripe(s))
		for q := range parityShards {
			if damagedParity[ParityRef{Stripe: s, Index: q}] {
				continue
			}
			raw, err := r.readParity(aead, s, q)
			if err != nil {
				return nil, fmt.Errorf("reading parity: %w", err)
			}
			parityShards[q] = raw
		}

		if err := coder.Reconstruct(data, parityShards, lengths, shardLen); err != nil {
			return nil, fmt.Errorf("stripe %d: %w", s, err)
		}

		// Write back only what was missing, and only after proving it.
		for j := range width {
			index := first + uint64(j)
			if !damagedData[index] {
				continue
			}
			if err := verifyRebuiltShard(aead, r.sb, index, data[j]); err != nil {
				return nil, err
			}
			if err := out.WritePayload(data[j], int64(l.DataOffset(index))); err != nil {
				return nil, err
			}
			result.RepairedData = append(result.RepairedData, index)
		}
		for q := range parityShards {
			ref := ParityRef{Stripe: s, Index: q}
			if !damagedParity[ref] {
				continue
			}
			index := parity.ParityNonceIndex(s, q)
			nonce := crypto.ShardNonce(r.sb.NoncePrefix, index)
			aad := crypto.ShardAAD(r.sb.ContainerUUID, index, r.sb.ShardSize)
			sealed := aead.Seal(nil, nonce, parityShards[q], aad)
			if err := out.WritePayload(sealed, int64(l.ParityOffset(s, q))); err != nil {
				return nil, err
			}
			result.RepairedParit = append(result.RepairedParit, ref)
		}
	}

	if err := out.Sync(); err != nil {
		return nil, err
	}
	return result, nil
}

// shardAuthenticates reports whether sealed really is the shard that belongs at
// index in this container.
func shardAuthenticates(aead interface {
	Open(dst, nonce, ct, ad []byte) ([]byte, error)
}, sb *format.Superblock, index uint64, sealed []byte) bool {
	nonce := crypto.ShardNonce(sb.NoncePrefix, index)
	aad := crypto.ShardAAD(sb.ContainerUUID, index, sb.ShardSize)
	_, err := aead.Open(nil, nonce, sealed, aad)
	return err == nil
}

// verifyRebuiltShard is the check that makes a repair trustworthy. Reed-Solomon
// will happily produce bytes from bad input; only the tag knows whether they
// are the bytes that were lost.
func verifyRebuiltShard(aead interface {
	Open(dst, nonce, ct, ad []byte) ([]byte, error)
}, sb *format.Superblock, index uint64, sealed []byte) error {
	if !shardAuthenticates(aead, sb, index, sealed) {
		return fmt.Errorf("shard %d was rebuilt but does not authenticate; the recovery data cannot restore it", index)
	}
	return nil
}

func stripeNeedsWork(l parity.Layout, s int, data map[uint64]bool, par map[ParityRef]bool) bool {
	first := uint64(s) * uint64(l.Plan.Data)
	for j := range l.DataInStripe(s) {
		if data[first+uint64(j)] {
			return true
		}
	}
	for q := range l.ParityInStripe(s) {
		if par[ParityRef{Stripe: s, Index: q}] {
			return true
		}
	}
	return false
}

func describeUnrepairable(stripes []int, l parity.Layout) string {
	if len(stripes) == 0 {
		return "the damage could not be located to a stripe"
	}
	const show = 5
	shown := stripes
	suffix := ""
	if len(shown) > show {
		shown, suffix = shown[:show], fmt.Sprintf(" and %d more", len(stripes)-show)
	}
	return fmt.Sprintf("%d of %d stripes lost more than the %d parity shards protecting them (%v%s)",
		len(stripes), l.Stripes(), l.Plan.Parity, shown, suffix)
}

// copySet copies every volume of a container to a new set of files, and hands
// back something that writes into the right one by payload offset.
func copySet(src *volumeSet, dst string) (*repairTarget, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}

	t := &repairTarget{}
	split := src.Count() > 1
	for i, v := range src.vols {
		target := dst
		if split {
			target = dst + VolumeSuffix(i)
		}
		out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Close()
			return nil, err
		}
		if _, err := v.f.Seek(0, io.SeekStart); err != nil {
			out.Close()
			t.Close()
			return nil, err
		}
		if _, err := io.Copy(out, v.f); err != nil {
			out.Close()
			t.Close()
			return nil, err
		}
		t.files = append(t.files, out)
		t.paths = append(t.paths, target)
		t.starts = append(t.starts, v.payloadStart)
		t.logical = append(t.logical, v.logicalStart)
		t.lens = append(t.lens, v.logicalLen)
		t.sizes = append(t.sizes, v.size)
	}
	return t, nil
}

// repairTarget is the set being written, addressed by payload offset so the
// caller never has to know which volume a shard landed in.
type repairTarget struct {
	files   []*os.File
	paths   []string
	starts  []int64
	logical []int64
	lens    []int64
	sizes   []int64
}

// healMetadata writes the regions the reader had to fall back on back to full
// strength, from the copy that authenticated.
//
// Every byte written here is one the container already proved it owns: the
// header carries its own MAC and the slot table is re-signed under the same
// header key, so this restores redundancy rather than inventing anything.
func (t *repairTarget) healMetadata(r *Reader) ([]string, error) {
	var done []string

	// Each volume's leading header, and the mirror that closes it.
	for i, v := range r.vols.vols {
		// The bytes as they were read, not a re-marshal: the MAC covers what is
		// actually on disk, so re-rendering a header written by a version that
		// used the reserved region would strip the field and invalidate it.
		header := v.sb.Raw()
		if _, err := t.files[i].WriteAt(header, 0); err != nil {
			return nil, err
		}
		mirrorAt := v.payloadStart + v.logicalLen
		if i == len(r.vols.vols)-1 {
			mirrorAt += int64(2 * v.sb.TailLength)
		}
		if err := t.files[i].Truncate(mirrorAt + format.SuperblockSize); err != nil {
			return nil, err
		}
		t.sizes[i] = mirrorAt + format.SuperblockSize
		if _, err := t.files[i].WriteAt(header, mirrorAt); err != nil {
			return nil, err
		}
	}
	done = append(done, "both copies of the container header")

	table, err := r.table().Marshal(r.keys.Header)
	if err != nil {
		return nil, err
	}
	if _, err := t.files[0].WriteAt(table, format.SlotTableAOffset); err != nil {
		return nil, err
	}
	if _, err := t.files[0].WriteAt(table, format.SlotTableBOffset); err != nil {
		return nil, err
	}
	done = append(done, "both key-slot tables")
	return done, nil
}

func (t *repairTarget) WritePayload(p []byte, logical int64) error {
	for len(p) > 0 {
		index := -1
		for i := range t.files {
			if logical >= t.logical[i] && logical < t.logical[i]+t.lens[i] {
				index = i
				break
			}
		}
		if index < 0 {
			return io.ErrUnexpectedEOF
		}
		within := logical - t.logical[index]
		n := min(int64(len(p)), t.lens[index]-within)
		if _, err := t.files[index].WriteAt(p[:n], t.starts[index]+within); err != nil {
			return err
		}
		p = p[n:]
		logical += n
	}
	return nil
}

func (t *repairTarget) Paths() []string { return t.paths }

func (t *repairTarget) Sync() error {
	for _, f := range t.files {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func (t *repairTarget) Close() error {
	var err error
	for _, f := range t.files {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}
