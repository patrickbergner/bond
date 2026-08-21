// Package format is the on-disk shape of a BOND container: the superblock, the
// key-slot tables and the manifest. It only marshals and unmarshals – reading
// and writing containers is internal/container's job, and this package stays
// free of I/O so the byte layout can be tested directly.
package format

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/parity"
)

// Sizes and fixed offsets. The regions before the payload have a constant
// length so that changing a key rewrites a known 64 KiB and never moves a byte
// of payload.
const (
	SuperblockSize = 4096
	SlotTableSize  = 65536

	SuperblockOffset = 0
	SlotTableAOffset = SuperblockOffset + SuperblockSize
	SlotTableBOffset = SlotTableAOffset + SlotTableSize

	// PayloadOffset is where the first shard begins, in every container.
	PayloadOffset = SlotTableBOffset + SlotTableSize

	VersionMajor = 1
	VersionMinor = 0
)

// Magic opens every container and every mirror. The CR-LF-EOF tail is the same
// trick PNG uses: it catches a transfer that translated line endings, and
// stops the file being printed to a terminal.
var Magic = [8]byte{'B', 'O', 'N', 'D', 0x00, '\r', 0x1a, '\n'}

// Field offsets inside the superblock.
const (
	offMagic           = 0
	offVersionMajor    = 8
	offVersionMinor    = 10
	offHeaderSize      = 12
	offFlags           = 16
	offCipherID        = 24
	offKDFID           = 28
	offParityID        = 32
	offShardSize       = 36
	offDataShards      = 40
	offParityShards    = 44
	offDataShardCount  = 48
	offStreamLength    = 56
	offCreated         = 64
	offContainerUUID   = 72
	offNoncePrefix     = 88
	offTailOffset      = 104
	offTailLength      = 112
	offTailSHA256      = 120
	offVolumeIndex     = 152
	offVolumeCount     = 156
	offVolumeLogOffset = 160
	offVolumeLogLength = 168
	offKeyCommitment   = 176
	offHeaderMAC       = 208
	offLastShardBytes  = 240
	offReserved        = 248
)

// Flags describing a container without needing its key.
const (
	// FlagUnencrypted marks a container whose master key is stored inside it.
	// It is advisory – the plaintext key slot is the truth – but it lets
	// "bond inspect" say so before anything is unlocked.
	FlagUnencrypted uint64 = 1 << 0
)

// ParityScheme identifies how recovery data was computed.
type ParityScheme uint32

const (
	ParityNone ParityScheme = 0
	ParityRS   ParityScheme = 1 // Reed-Solomon over ciphertext shards
)

// KDFID identifies the password hardening function.
type KDFID uint32

const KDFArgon2id KDFID = 1

// Superblock is the fixed 4 KiB header. A copy opens every volume and a mirror
// closes the last one.
type Superblock struct {
	VersionMajor uint16
	VersionMinor uint16
	Flags        uint64

	Cipher crypto.Cipher
	KDF    KDFID
	Parity ParityScheme

	ShardSize      uint32
	DataShards     uint32 // stripe geometry; zero when there is no parity
	ParityShards   uint32
	DataShardCount uint64
	StreamLength   uint64 // exact length of the compressed stream

	// LastShardBytes is the on-disk size of the final shard, which is the only
	// one allowed to be short. Padding it to a full shard would cost up to a
	// whole shard on every container – nearly ten times over for a small one –
	// and buys nothing: parity pads in memory when it computes a stripe.
	LastShardBytes uint32

	Created       time.Time
	ContainerUUID []byte // 16
	NoncePrefix   []byte // 16

	TailOffset uint64
	TailLength uint64
	TailSHA256 []byte // 32

	VolumeIndex        uint32
	VolumeCount        uint32
	VolumeLogicalStart uint64
	VolumeLogicalLen   uint64

	KeyCommitment []byte // 32
	HeaderMAC     []byte // 32

	// raw is the 4096 bytes this superblock was parsed from, kept so the MAC
	// can be checked against what is on disk rather than against a re-rendering
	// of the fields this build happened to understand. Nil for a superblock
	// built in memory, which is only ever the writer's.
	raw []byte
}

// Marshal renders the superblock. The MAC field is left zero; Sign fills it.
func (s *Superblock) Marshal() []byte {
	b := make([]byte, SuperblockSize)
	copy(b[offMagic:], Magic[:])
	binary.LittleEndian.PutUint16(b[offVersionMajor:], s.VersionMajor)
	binary.LittleEndian.PutUint16(b[offVersionMinor:], s.VersionMinor)
	binary.LittleEndian.PutUint32(b[offHeaderSize:], SuperblockSize)
	binary.LittleEndian.PutUint64(b[offFlags:], s.Flags)
	binary.LittleEndian.PutUint32(b[offCipherID:], uint32(s.Cipher))
	binary.LittleEndian.PutUint32(b[offKDFID:], uint32(s.KDF))
	binary.LittleEndian.PutUint32(b[offParityID:], uint32(s.Parity))
	binary.LittleEndian.PutUint32(b[offShardSize:], s.ShardSize)
	binary.LittleEndian.PutUint32(b[offDataShards:], s.DataShards)
	binary.LittleEndian.PutUint32(b[offParityShards:], s.ParityShards)
	binary.LittleEndian.PutUint64(b[offDataShardCount:], s.DataShardCount)
	binary.LittleEndian.PutUint64(b[offStreamLength:], s.StreamLength)
	binary.LittleEndian.PutUint64(b[offCreated:], uint64(s.Created.UnixNano()))
	copy(b[offContainerUUID:], s.ContainerUUID)
	copy(b[offNoncePrefix:], s.NoncePrefix)
	binary.LittleEndian.PutUint64(b[offTailOffset:], s.TailOffset)
	binary.LittleEndian.PutUint64(b[offTailLength:], s.TailLength)
	copy(b[offTailSHA256:], s.TailSHA256)
	binary.LittleEndian.PutUint32(b[offVolumeIndex:], s.VolumeIndex)
	binary.LittleEndian.PutUint32(b[offVolumeCount:], s.VolumeCount)
	binary.LittleEndian.PutUint64(b[offVolumeLogOffset:], s.VolumeLogicalStart)
	binary.LittleEndian.PutUint64(b[offVolumeLogLength:], s.VolumeLogicalLen)
	copy(b[offKeyCommitment:], s.KeyCommitment)
	copy(b[offHeaderMAC:], s.HeaderMAC)
	binary.LittleEndian.PutUint32(b[offLastShardBytes:], s.LastShardBytes)
	return b
}

// ErrNotContainer means the bytes are not a BOND container at all.
var ErrNotContainer = fmt.Errorf("not a BOND container")

// Unmarshal parses a superblock without authenticating it.
//
// Nothing here may be trusted yet: the MAC cannot be checked until a key slot
// has been opened, so every field is treated as attacker-controlled until
// Verify says otherwise. That is why the checks below are about internal
// consistency and sane bounds rather than about what the numbers mean.
func Unmarshal(b []byte) (*Superblock, error) {
	if len(b) < SuperblockSize {
		return nil, ErrNotContainer
	}
	if !bytes.Equal(b[offMagic:offMagic+8], Magic[:]) {
		return nil, ErrNotContainer
	}

	s := &Superblock{
		raw:                append([]byte(nil), b[:SuperblockSize]...),
		VersionMajor:       binary.LittleEndian.Uint16(b[offVersionMajor:]),
		VersionMinor:       binary.LittleEndian.Uint16(b[offVersionMinor:]),
		Flags:              binary.LittleEndian.Uint64(b[offFlags:]),
		Cipher:             crypto.Cipher(binary.LittleEndian.Uint32(b[offCipherID:])),
		KDF:                KDFID(binary.LittleEndian.Uint32(b[offKDFID:])),
		Parity:             ParityScheme(binary.LittleEndian.Uint32(b[offParityID:])),
		ShardSize:          binary.LittleEndian.Uint32(b[offShardSize:]),
		DataShards:         binary.LittleEndian.Uint32(b[offDataShards:]),
		ParityShards:       binary.LittleEndian.Uint32(b[offParityShards:]),
		DataShardCount:     binary.LittleEndian.Uint64(b[offDataShardCount:]),
		StreamLength:       binary.LittleEndian.Uint64(b[offStreamLength:]),
		Created:            time.Unix(0, int64(binary.LittleEndian.Uint64(b[offCreated:]))),
		ContainerUUID:      append([]byte(nil), b[offContainerUUID:offContainerUUID+16]...),
		NoncePrefix:        append([]byte(nil), b[offNoncePrefix:offNoncePrefix+16]...),
		TailOffset:         binary.LittleEndian.Uint64(b[offTailOffset:]),
		TailLength:         binary.LittleEndian.Uint64(b[offTailLength:]),
		TailSHA256:         append([]byte(nil), b[offTailSHA256:offTailSHA256+32]...),
		VolumeIndex:        binary.LittleEndian.Uint32(b[offVolumeIndex:]),
		VolumeCount:        binary.LittleEndian.Uint32(b[offVolumeCount:]),
		VolumeLogicalStart: binary.LittleEndian.Uint64(b[offVolumeLogOffset:]),
		VolumeLogicalLen:   binary.LittleEndian.Uint64(b[offVolumeLogLength:]),
		KeyCommitment:      append([]byte(nil), b[offKeyCommitment:offKeyCommitment+32]...),
		HeaderMAC:          append([]byte(nil), b[offHeaderMAC:offHeaderMAC+32]...),
		LastShardBytes:     binary.LittleEndian.Uint32(b[offLastShardBytes:]),
	}

	if got := binary.LittleEndian.Uint32(b[offHeaderSize:]); got != SuperblockSize {
		return nil, fmt.Errorf("header claims to be %d bytes, want %d", got, SuperblockSize)
	}
	if s.VersionMajor != VersionMajor || s.VersionMinor != VersionMinor {
		return nil, fmt.Errorf("container format version %d.%d; this build understands %d.%d",
			s.VersionMajor, s.VersionMinor, VersionMajor, VersionMinor)
	}
	if unknown := s.Flags &^ FlagUnencrypted; unknown != 0 {
		return nil, fmt.Errorf("container uses unsupported feature flags %#x", unknown)
	}
	if err := s.checkBounds(); err != nil {
		return nil, err
	}
	return s, nil
}

// checkBounds rejects a header whose numbers cannot describe a real container.
// It runs before the MAC can be checked, so its job is to make sure nothing
// downstream allocates or seeks based on a hostile number.
func (s *Superblock) checkBounds() error {
	const maxShardSize = 256 << 20
	switch {
	case s.ShardSize < 4096 || s.ShardSize > maxShardSize:
		return fmt.Errorf("shard size %d is outside the supported range", s.ShardSize)
	case s.ShardSize%4096 != 0:
		return fmt.Errorf("shard size %d is not a multiple of 4096", s.ShardSize)
	case uint64(s.ShardSize) <= crypto.TagLen:
		return fmt.Errorf("shard size %d leaves no room for content", s.ShardSize)
	}

	// The stripe geometry steers every offset once parity is in play, so it is
	// bounded here rather than trusted.
	switch s.Parity {
	case ParityNone:
		if s.DataShards != 0 || s.ParityShards != 0 {
			return fmt.Errorf("no parity scheme, but the header records a %d+%d stripe", s.DataShards, s.ParityShards)
		}
	case ParityRS:
		switch {
		case s.DataShards < 1 || s.ParityShards < 1:
			return fmt.Errorf("parity stripe %d+%d has no shards on one side", s.DataShards, s.ParityShards)
		case int(s.DataShards)+int(s.ParityShards) > parity.MaxShards:
			return fmt.Errorf("parity stripe %d+%d is wider than the %d-shard limit", s.DataShards, s.ParityShards, parity.MaxShards)
		}
	default:
		return fmt.Errorf("unknown recovery scheme %d", uint32(s.Parity))
	}

	plaintextPerShard := uint64(s.ShardSize) - crypto.TagLen

	// Both factors are attacker-controlled and both are large: 2^40 shards of
	// 256 MiB multiply out to 2^68 and wrap, which is how a header describing
	// no real container could pass a consistency check that looks airtight.
	// The product is taken with the overflow left visible instead of silently
	// discarded, and every case below reuses it rather than multiplying again.
	capacityHi, capacity := bits.Mul64(s.DataShardCount, plaintextPerShard)

	// The volume fields come first because the tail floor depends on them.
	switch {
	case s.VolumeCount == 0:
		return fmt.Errorf("volume count is zero")
	case s.VolumeIndex >= s.VolumeCount:
		return fmt.Errorf("volume %d of %d", s.VolumeIndex+1, s.VolumeCount)
	case s.DataShardCount > 1<<40:
		return fmt.Errorf("shard count %d is implausible", s.DataShardCount)
	case capacityHi != 0:
		return fmt.Errorf("%d shards of %d bytes describe more data than could ever exist",
			s.DataShardCount, plaintextPerShard)
	case s.StreamLength > capacity:
		return fmt.Errorf("stream length %d does not fit in %d shards", s.StreamLength, s.DataShardCount)
	case s.DataShardCount > 0 && s.StreamLength <= capacity-plaintextPerShard:
		return fmt.Errorf("stream length %d leaves shard %d empty", s.StreamLength, s.DataShardCount-1)
	case s.DataShardCount > 0 && uint64(s.LastShardBytes) != s.StreamLength-(capacity-plaintextPerShard)+crypto.TagLen:
		return fmt.Errorf("the final shard is recorded as %d bytes, which does not match a stream of %d", s.LastShardBytes, s.StreamLength)
	case s.DataShardCount == 0 && s.LastShardBytes != 0:
		return fmt.Errorf("a container with no shards records a final shard of %d bytes", s.LastShardBytes)
	case s.TailLength > 1<<32:
		return fmt.Errorf("tail metadata length %d is implausible", s.TailLength)
	case s.TailOffset < s.tailFloor():
		return fmt.Errorf("tail metadata overlaps the header region")
	case !s.Layout().OffsetsFit():
		return fmt.Errorf("%d shards of %d bytes describe a payload larger than any storage",
			s.DataShardCount, s.ShardSize)
	}
	return nil
}

// tailFloor is the lowest offset the trailing metadata can legitimately have.
//
// The tail is written at the end of the last volume's payload, and every
// volume's header carries the same offset – so in a split container the floor
// is that volume's own 4 KiB header, not the 132 KiB head that only volume 1
// has. Requiring PayloadOffset here refused every copy of every header in a set
// whose last volume held less than 128 KiB of payload: a container the writer
// had just reported as written, unopenable by any of BOND's own tools. The
// exact position is checked in Reader.crossCheck, once a key has made the
// numbers worth believing.
func (s *Superblock) tailFloor() uint64 {
	if s.VolumeCount == 1 {
		return PayloadOffset
	}
	return SuperblockSize
}

// Layout describes where every shard sits in the payload region.
func (s *Superblock) Layout() parity.Layout {
	return parity.Layout{
		ShardSize:      s.ShardSize,
		LastShardBytes: s.LastShardBytes,
		DataShards:     s.DataShardCount,
		Plan:           s.Plan(),
	}
}

// Plan is the stripe geometry recorded in the header.
func (s *Superblock) Plan() parity.Plan {
	if s.Parity != ParityRS {
		return parity.Plan{}
	}
	return parity.Plan{Data: int(s.DataShards), Parity: int(s.ParityShards)}
}

// PayloadBytes is the on-disk size of the shard region, parity included.
func (s *Superblock) PayloadBytes() uint64 { return s.Layout().TotalBytes() }

// ShardBytes is the on-disk size of one data shard.
func (s *Superblock) ShardBytes(index uint64) uint32 { return s.Layout().DataLen(index) }

// ShardOffset is where a data shard begins, relative to the payload.
func (s *Superblock) ShardOffset(index uint64) uint64 { return s.Layout().DataOffset(index) }

// PlaintextPerShard is how much of the compressed stream one shard carries.
func (s *Superblock) PlaintextPerShard() uint64 { return uint64(s.ShardSize) - crypto.TagLen }

// signable is what the header MAC is computed over: the whole 4096 bytes with
// the MAC field zeroed.
//
// For a header that came off disk those are the bytes as they were read, not a
// re-marshal of the fields this build understood. The difference is the whole
// point. Re-marshalling renders the reserved region as zeros, so whatever is
// really written there was covered by nothing at all – 3.8 KiB per header copy
// that passed Open, Unlock and a full Verify without a notice, against a
// document promising the opposite. Exact-byte authentication catches damage in
// that region even though format 1.0 assigns it no semantics. Slot tables use
// the same raw-byte rule for their unused padding.
func (s *Superblock) signable() []byte {
	b := s.Marshal()
	if s.raw != nil {
		b = append([]byte(nil), s.raw...)
	}
	for i := offHeaderMAC; i < offHeaderMAC+32; i++ {
		b[i] = 0
	}
	return b
}

// Raw is the header exactly as it was read, or its canonical rendering for one
// built in memory.
//
// Repair writes this rather than a re-marshal: the MAC covers the bytes as they
// were, so re-rendering them would strip a field a later version had put in the
// reserved region and invalidate a header that is perfectly good.
func (s *Superblock) Raw() []byte {
	if s.raw != nil {
		return append([]byte(nil), s.raw...)
	}
	return s.Marshal()
}

// IdenticalTo reports whether two superblocks came from the same bytes.
//
// It compares what is on disk rather than what was understood, so a difference
// in a region this build does not interpret still counts. That is what makes a
// mirror worth keeping as a second opinion: two copies differing only in their
// padding are not the same header, and one of them is about to fail its MAC.
func (s *Superblock) IdenticalTo(other *Superblock) bool {
	return bytes.Equal(s.Raw(), other.Raw())
}

// Sign fills in the header MAC.
//
// Signing means this header is about to be written, so its canonical rendering
// is the truth and any bytes it was parsed from are stale. Dropping them here is
// what keeps PatchHeaders – which copies a superblock and edits its volume
// fields before signing – from authenticating the copy it came from.
func (s *Superblock) Sign(headerKey []byte) {
	s.raw = nil
	s.HeaderMAC = crypto.MAC(headerKey, s.signable())
}

// Verify checks the header MAC and the key commitment together.
//
// The commitment answers "is this the key this container was built with", the
// MAC answers "is this header the one that was written". Both have to hold
// before any offset in the header is worth acting on.
func (s *Superblock) Verify(keys *crypto.Keys) error {
	if !crypto.CheckMAC(keys.Header, s.signable(), s.HeaderMAC) {
		return fmt.Errorf("the container header fails authentication; it has been damaged or altered")
	}
	if !keys.CheckCommitment(s.ContainerUUID, s.KeyCommitment) {
		return fmt.Errorf("the key opens a slot but is not the key this container was built with")
	}
	return nil
}
