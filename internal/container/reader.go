package container

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
)

// Reader opens a container. Nothing it reports is trustworthy until Unlock has
// succeeded: the superblock's own MAC cannot be checked without a key, so
// everything before that point is treated as a claim rather than a fact.
type Reader struct {
	vols *volumeSet

	sb       *format.Superblock
	sbSource string // which copy of the header was used

	tables []format.TableCopy // parseable key-slot tables, newest first
	using  int                // index into tables

	keys     *crypto.Keys
	manifest *format.Manifest
	unlocked bool

	// notices records what had to be worked around to open this container. An
	// empty list means every first choice was intact.
	notices []string
}

// Open reads a container's header and key slots.
//
// Any file of a split set will do: each volume carries a header copy saying
// how many there are, so a restore started from the wrong one still finds the
// rest.
func Open(path string) (*Reader, error) {
	vols, sb, source, err := openVolumes(path)
	if err != nil {
		return nil, err
	}

	r := &Reader{vols: vols, sb: sb, sbSource: source}
	if err := r.readSlotTables(); err != nil {
		vols.Close()
		return nil, err
	}
	return r, nil
}

// Volumes is how many files the container is stored in.
func (r *Reader) Volumes() int { return r.vols.Count() }

// Paths lists the container's files, in order.
func (r *Reader) Paths() []string { return r.vols.Paths() }

func (r *Reader) readSlotTables() error {
	first := r.vols.First().f
	a := make([]byte, format.SlotTableSize)
	b := make([]byte, format.SlotTableSize)
	if _, err := first.ReadAt(a, format.SlotTableAOffset); err != nil {
		return fmt.Errorf("reading key slots: %w", err)
	}
	if _, err := first.ReadAt(b, format.SlotTableBOffset); err != nil {
		return fmt.Errorf("reading key slots: %w", err)
	}
	tables, err := format.PickTables(a, b)
	if err != nil {
		return err
	}
	r.tables = tables
	return nil
}

func (r *Reader) table() *format.SlotTable { return r.tables[r.using].Table }

// Notices lists what had to be worked around to open the container: a header
// read from the mirror, a key-slot table taken from the spare copy. They are
// worth printing – the container opened, but something about it is damaged and
// the next copy of it may not be so lucky.
func (r *Reader) Notices() []string { return r.notices }

// Superblock is the header as read, authenticated only after Unlock.
func (r *Reader) Superblock() *format.Superblock { return r.sb }

// HeaderSource says which copy of the header was used.
func (r *Reader) HeaderSource() string { return r.sbSource }

// Slots lists the ways this container can be opened.
func (r *Reader) Slots() []*crypto.Slot { return r.table().Slots }

// Unlocked reports whether the container has been opened.
func (r *Reader) Unlocked() bool { return r.unlocked }

// Manifest is available once unlocked.
func (r *Reader) Manifest() *format.Manifest { return r.manifest }

// Keys are the container's subkeys, available once unlocked.
func (r *Reader) Keys() *crypto.Keys { return r.keys }

// Unlock tries each secret against each slot, then authenticates everything
// the header claims.
//
// The order matters: the key comes first, then the header MAC and the key
// commitment, then the manifest. Only after all three does any offset in the
// header get acted on, so a container that has been tampered with is refused
// before it can steer a single read.
//
// The whole sequence is attempted against every combination of the header
// copies and the key-slot tables. Both regions are stored twice precisely so
// that damage to one is survivable, and both have the same trap: a flipped bit
// usually leaves the copy parseable and merely unauthentic. Choosing between
// the copies before a key is available would therefore be choosing blind, and a
// flip in the container UUID or the nonce prefix derails the key derivation
// itself – so the switch has to happen around the whole sequence rather than at
// the point where the MAC fails.
//
// Four attempts at worst, and only ever more than one when something is
// actually damaged.
func (r *Reader) Unlock(secrets ...crypto.Unlocker) error {
	if r.unlocked {
		return nil
	}
	if len(secrets) == 0 {
		return errors.New("no key was offered")
	}

	first := r.vols.First()
	var firstErr error
	for h := range first.scan.copies {
		first.use(h)
		r.sb, r.sbSource = first.sb, first.source()

		for t := range r.tables {
			r.using = t
			err := r.unlockWith(secrets)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			r.noteMetadata()
			r.unlocked = true
			return nil
		}
	}

	// Nothing opened it. The reader goes back to describing what is actually at
	// the front of the file, so "bond inspect" still reports that.
	first.use(0)
	r.sb, r.sbSource = first.sb, first.source()
	r.using = 0
	return firstErr
}

func (r *Reader) note(msg string) { r.notices = append(r.notices, msg) }

// noteMetadata records what had to be worked around, once the key has settled
// which copies are real.
//
// The rule is that a notice fires whenever the redundancy is not intact, not
// merely when the reader had to fall back. Those are different: a container
// whose *spare* copy is the damaged one opens on its first choice and looks
// perfectly healthy, while being one flip from unopenable. Repair reads the
// presence of any notice as "there is redundancy to put back", so a region that
// stays quiet here is a region that never gets healed.
func (r *Reader) noteMetadata() {
	for _, v := range r.vols.vols {
		if msg := v.headerNotice(r.vols.Count()); msg != "" {
			r.note(msg)
		}
	}
	if msg := r.slotNotice(); msg != "" {
		r.note(msg)
	}
}

// slotNotice is the same judgement for the key-slot tables.
//
// They need the MAC that the header copies did not: after a key change the two
// tables legitimately differ, so unlike a header and its mirror, byte-identity
// says nothing about which of them is intact.
func (r *Reader) slotNotice() string {
	switch {
	case len(r.tables) == 1:
		return "one of the two key-slot tables is unreadable; only one copy of this container's keys is left"
	case r.using > 0:
		return "the current key-slot table is damaged; the spare copy was used, which may not list the newest keys"
	case r.tables[1].Table.Verify(r.keys.Header) != nil:
		return "the spare key-slot table is damaged; only one copy of this container's keys is left"
	}
	return ""
}

func (r *Reader) unlockWith(secrets []crypto.Unlocker) error {
	var fmk crypto.FMK
	for _, slot := range r.table().Slots {
		for _, secret := range secrets {
			key, err := slot.Unwrap(r.sb.Cipher, r.sb.ContainerUUID, secret)
			if errors.Is(err, crypto.ErrWrongKey) {
				continue
			}
			if err != nil {
				return err
			}
			fmk = key
			break
		}
		if fmk != nil {
			break
		}
	}
	if fmk == nil {
		return fmt.Errorf("%w; this container has %s", crypto.ErrWrongKey, describeSlots(r.table().Slots))
	}

	keys, err := crypto.Derive(fmk, r.sb.ContainerUUID)
	if err != nil {
		return err
	}
	if err := r.sb.Verify(keys); err != nil {
		keys.Wipe()
		return err
	}
	if err := r.vols.verifyAll(keys); err != nil {
		keys.Wipe()
		return err
	}
	if err := r.table().Verify(keys.Header); err != nil {
		keys.Wipe()
		return err
	}
	r.keys = keys

	if err := r.readManifest(); err != nil {
		r.keys = nil
		keys.Wipe()
		return err
	}
	if err := r.crossCheck(); err != nil {
		r.keys, r.manifest = nil, nil
		keys.Wipe()
		return err
	}
	return nil
}

// readManifest takes whichever of the two tail copies is intact.
func (r *Reader) readManifest() error {
	// The tail sits in the last volume, so its offset is a position in that
	// file. Bounding it against the size of the whole set would let a truncated
	// last volume through, to fail further down as a bare read error instead of
	// as the truncation this check exists to name.
	last := r.vols.Last()
	end := r.sb.TailOffset + 2*r.sb.TailLength + format.SuperblockSize
	if end < r.sb.TailOffset || end > uint64(last.size) {
		return fmt.Errorf("%s is truncated: its manifest should end at byte %d but the file is %d bytes",
			filepath.Base(last.path), r.sb.TailOffset+2*r.sb.TailLength, last.size)
	}

	var problems []error
	for copyIndex := range 2 {
		buf := make([]byte, r.sb.TailLength)
		off := int64(r.sb.TailOffset + uint64(copyIndex)*r.sb.TailLength)
		if _, err := r.vols.Last().f.ReadAt(buf, off); err != nil {
			problems = append(problems, err)
			continue
		}
		if sum := sha256.Sum256(buf); subtle.ConstantTimeCompare(sum[:], r.sb.TailSHA256) != 1 {
			problems = append(problems, fmt.Errorf("copy %d does not match the digest in the header", copyIndex+1))
			continue
		}
		m, err := format.OpenManifest(buf, r.sb.Cipher, r.keys.Manifest, r.sb.ContainerUUID)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		r.manifest = m
		return nil
	}
	return fmt.Errorf("both copies of the manifest are unusable: %v", errors.Join(problems...))
}

// crossCheck makes the manifest and the header agree. They are written
// together and sealed separately; a disagreement means one of them is not what
// it was.
func (r *Reader) crossCheck() error {
	m := r.manifest
	switch {
	case m.StreamLength != int64(r.sb.StreamLength):
		return fmt.Errorf("the manifest says the stream is %d bytes, the header says %d", m.StreamLength, r.sb.StreamLength)
	case m.DataShardCount != int64(r.sb.DataShardCount):
		return fmt.Errorf("the manifest counts %d shards, the header counts %d", m.DataShardCount, r.sb.DataShardCount)
	case m.ShardSize != int64(r.sb.ShardSize):
		return fmt.Errorf("the manifest says shards are %d bytes, the header says %d", m.ShardSize, r.sb.ShardSize)
	}
	// The manifest sits directly after the payload in the last volume, so the
	// check is against that file's own layout rather than the payload total.
	last := r.vols.Last()
	if end := uint64(last.payloadStart + last.logicalLen); end != r.sb.TailOffset {
		return fmt.Errorf("the payload ends at %d in the last volume but the manifest is recorded at %d",
			end, r.sb.TailOffset)
	}
	// And the volumes together must hold exactly the payload the header
	// describes: a set that is short or long is not this container.
	if got := uint64(r.vols.PayloadBytes()); got != r.sb.PayloadBytes() {
		return fmt.Errorf("the volumes hold %d bytes of payload, the header describes %d", got, r.sb.PayloadBytes())
	}
	return nil
}

func describeSlots(slots []*crypto.Slot) string {
	if len(slots) == 0 {
		return "no key slots at all"
	}
	out := ""
	for i, s := range slots {
		if i > 0 {
			out += ", "
		}
		out += s.Type.String()
		if s.Label != "" {
			out += " (" + s.Label + ")"
		}
	}
	return "these key slots: " + out
}

// Stream returns the compressed payload, decrypted and authenticated shard by
// shard. A shard that fails its tag stops the read: handing on bytes that
// failed authentication would defeat the point of having it.
func (r *Reader) Stream() (io.Reader, error) {
	if !r.unlocked {
		return nil, errors.New("the container is locked")
	}
	aead, err := crypto.AEAD(r.sb.Cipher, r.keys.Data)
	if err != nil {
		return nil, err
	}
	return &shardReader{
		r:         r,
		aead:      aead,
		remaining: int64(r.sb.StreamLength),
	}, nil
}

type shardReader struct {
	r    *Reader
	aead interface {
		Open(dst, nonce, ct, ad []byte) ([]byte, error)
	}
	index   uint64
	buf     []byte
	scratch []byte
	pos     int

	remaining int64
	err       error
}

func (s *shardReader) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.remaining == 0 {
		return 0, io.EOF
	}
	if s.pos >= len(s.buf) {
		if err := s.next(); err != nil {
			s.err = err
			return 0, err
		}
	}
	n := copy(p, s.buf[s.pos:])
	if int64(n) > s.remaining {
		n = int(s.remaining)
	}
	s.pos += n
	s.remaining -= int64(n)
	return n, nil
}

func (s *shardReader) next() error {
	if s.index >= s.r.sb.DataShardCount {
		return io.ErrUnexpectedEOF
	}
	plain, sealed, err := s.r.readShard(s.aead, s.index, s.scratch)
	if err != nil {
		return err
	}
	s.scratch = sealed
	s.buf, s.pos = plain, 0
	s.index++
	return nil
}

// readShard reads one sealed data shard and authenticates it.
//
// buf is a scratch buffer the caller keeps across calls: the ciphertext is
// read into it and decrypted in place, using the aliasing the AEAD interface
// documents (dst == ciphertext[:0]). Without this, a stream of many shards –
// a restore does one per ShardBytes of payload – would allocate two new
// buffers per shard, and Go only reclaims the previous ones on its own
// schedule, so the live heap tracks how far through the payload the read has
// got rather than staying flat at one shard.
func (r *Reader) readShard(aead interface {
	Open(dst, nonce, ct, ad []byte) ([]byte, error)
}, index uint64, buf []byte) (plain, sealed []byte, err error) {
	l := r.sb.Layout()
	n := int(l.DataLen(index))
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	sealed = buf[:n]
	if err := r.vols.ReadPayload(sealed, int64(l.DataOffset(index))); err != nil {
		return nil, sealed, fmt.Errorf("shard %d: %w", index, err)
	}
	nonce := crypto.ShardNonce(r.sb.NoncePrefix, index)
	aad := crypto.ShardAAD(r.sb.ContainerUUID, index, r.sb.ShardSize)
	plain, err = aead.Open(sealed[:0], nonce, sealed, aad)
	if err != nil {
		return nil, sealed, fmt.Errorf("shard %d fails authentication; the container is damaged or has been altered", index)
	}
	return plain, sealed, nil
}

// rawShard reads a data shard without decrypting it. Reed-Solomon works on the
// stored ciphertext, so repair needs the bytes exactly as they sit on disk.
func (r *Reader) rawShard(index uint64) ([]byte, error) {
	l := r.sb.Layout()
	buf := make([]byte, l.DataLen(index))
	if err := r.vols.ReadPayload(buf, int64(l.DataOffset(index))); err != nil {
		return nil, err
	}
	return buf, nil
}

// readParity reads one parity shard and authenticates it, returning the raw
// coding bytes.
func (r *Reader) readParity(aead interface {
	Open(dst, nonce, ct, ad []byte) ([]byte, error)
}, stripe, q int) ([]byte, error) {
	l := r.sb.Layout()
	sealed := make([]byte, l.ParitySlot(stripe))
	if err := r.vols.ReadPayload(sealed, int64(l.ParityOffset(stripe, q))); err != nil {
		return nil, fmt.Errorf("stripe %d parity %d: %w", stripe, q, err)
	}
	index := parity.ParityNonceIndex(stripe, q)
	nonce := crypto.ShardNonce(r.sb.NoncePrefix, index)
	aad := crypto.ShardAAD(r.sb.ContainerUUID, index, r.sb.ShardSize)
	plain, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("stripe %d parity %d fails authentication", stripe, q)
	}
	return plain, nil
}

// Report is what a verification found.
type Report struct {
	Shards        uint64
	DamagedShards []uint64
	StreamSHA256  string
	StreamMatches bool

	// ParityShards is how many recovery shards the container carries, and
	// DamagedParity names the ones that are themselves unreadable.
	ParityShards  int
	DamagedParity []ParityRef

	// Repairable is set when every damaged stripe has enough surviving shards
	// to be rebuilt.
	Repairable bool

	// Unrepairable lists the stripes that lost more than their parity covers.
	Unrepairable []int
}

// ParityRef names one parity shard.
type ParityRef struct {
	Stripe int
	Index  int
}

// Healthy reports whether nothing was found wrong.
func (rep Report) Healthy() bool {
	return len(rep.DamagedShards) == 0 && len(rep.DamagedParity) == 0 && rep.StreamMatches
}

// Damaged reports whether anything at all needs repair.
func (rep Report) Damaged() bool {
	return len(rep.DamagedShards) > 0 || len(rep.DamagedParity) > 0
}

// Verify authenticates every shard and re-hashes the compressed stream.
//
// It reads the whole payload but decompresses nothing, so it can be run
// against a copy fetched back from cloud storage without unpacking anything.
// Damaged shards are collected rather than fatal, because the useful answer is
// how much is wrong, not merely that something is.
func (r *Reader) Verify(progress func(shard, total uint64)) (Report, error) {
	if !r.unlocked {
		return Report{}, errors.New("the container is locked")
	}
	aead, err := crypto.AEAD(r.sb.Cipher, r.keys.Data)
	if err != nil {
		return Report{}, err
	}

	l := r.sb.Layout()
	rep := Report{Shards: r.sb.DataShardCount, ParityShards: l.ParityShardCount()}
	digest := sha256.New()
	remaining := int64(r.sb.StreamLength)

	var scratch []byte
	for i := uint64(0); i < r.sb.DataShardCount; i++ {
		plain, sealed, err := r.readShard(aead, i, scratch)
		scratch = sealed
		if err != nil {
			rep.DamagedShards = append(rep.DamagedShards, i)
			// The stream digest is meaningless once a shard is missing, but
			// the scan continues so the report can say how much is damaged.
			remaining -= min(remaining, int64(r.sb.PlaintextPerShard()))
			if progress != nil {
				progress(i+1, r.sb.DataShardCount)
			}
			continue
		}
		n := min(remaining, int64(len(plain)))
		digest.Write(plain[:n])
		remaining -= n
		if progress != nil {
			progress(i+1, r.sb.DataShardCount)
		}
	}

	// Recovery data can be the thing that rotted, and a repair has to know
	// which parity shards it may actually use.
	for s := range l.Stripes() {
		for q := range l.ParityInStripe(s) {
			if _, err := r.readParity(aead, s, q); err != nil {
				rep.DamagedParity = append(rep.DamagedParity, ParityRef{Stripe: s, Index: q})
			}
		}
	}

	rep.StreamSHA256 = fmt.Sprintf("%x", digest.Sum(nil))
	rep.StreamMatches = len(rep.DamagedShards) == 0 && rep.StreamSHA256 == r.manifest.StreamSHA256
	r.assess(&rep)
	return rep, nil
}

// assess decides, stripe by stripe, whether what survives is enough.
//
// Reed-Solomon recovers any combination of losses up to the number of parity
// shards in a stripe – but the count that matters is per stripe, not over the
// container. Ten losses spread across ten stripes are repairable; three in one
// stripe protected by two parity shards are not.
func (r *Reader) assess(rep *Report) {
	if !rep.Damaged() {
		rep.Repairable = false
		return
	}
	l := r.sb.Layout()
	if !l.Plan.Enabled() {
		return
	}

	lost := make(map[int]int)
	for _, i := range rep.DamagedShards {
		s, _ := l.StripeOf(i)
		lost[s]++
	}
	for _, p := range rep.DamagedParity {
		lost[p.Stripe]++
	}

	rep.Repairable = true
	for s, n := range lost {
		if n > l.ParityInStripe(s) {
			rep.Unrepairable = append(rep.Unrepairable, s)
			rep.Repairable = false
		}
	}
	sort.Ints(rep.Unrepairable)
}

// Close releases every volume and wipes the keys.
func (r *Reader) Close() error {
	if r.keys != nil {
		r.keys.Wipe()
	}
	return r.vols.Close()
}
