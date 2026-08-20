package format

import (
	"testing"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/parity"
)

// Every parser in this package reads bytes that came back from storage nobody
// controls. Unmarshal in particular runs *before* a key is available, so it
// cannot check a MAC – all it can do is refuse numbers that could not describe
// a real container. Fuzzing is how that gets tested against inputs nobody
// thought to write down.
//
// The property is the same in each case: never panic, and never return a
// structure whose own numbers contradict each other. A header that survives
// parsing steers later reads, so "it parsed" has to mean "its offsets are sane".
//
// The header and slot-table targets patch a *valid* structure rather than
// taking raw bytes. Random bytes almost never survive a magic number, so a
// blind target spends its whole budget on the first four lines of the parser
// and never reaches the arithmetic, which is where anything interesting could
// go wrong. Patching also keeps the inputs small, which the fuzzing engine
// handles far better than the 4 KiB blobs a raw target would need.

// patch splices data into a copy of base at offset, wrapping rather than
// refusing so no input is wasted.
func patch(base []byte, offset uint32, data []byte) []byte {
	out := append([]byte(nil), base...)
	if len(out) == 0 {
		return out
	}
	at := int(offset) % len(out)
	for i, b := range data {
		out[(at+i)%len(out)] = b
	}
	return out
}

func validSuperblock() []byte {
	sb := &Superblock{
		VersionMajor:   VersionMajor,
		VersionMinor:   VersionMinor,
		Cipher:         crypto.CipherXChaCha20Poly1305,
		KDF:            KDFArgon2id,
		Parity:         ParityRS,
		ShardSize:      8192,
		DataShards:     20,
		ParityShards:   2,
		DataShardCount: 3,
		StreamLength:   3 * (8192 - crypto.TagLen),
		LastShardBytes: 8192,
		Created:        time.Unix(1_700_000_000, 0),
		ContainerUUID:  make([]byte, 16),
		NoncePrefix:    make([]byte, 16),
		TailOffset:     PayloadOffset + 3*8192,
		TailLength:     512,
		TailSHA256:     make([]byte, 32),
		VolumeCount:    1,
		KeyCommitment:  make([]byte, 32),
		HeaderMAC:      make([]byte, 32),
	}
	return sb.Marshal()
}

func FuzzUnmarshal(f *testing.F) {
	f.Add(uint32(0), []byte{})
	f.Add(uint32(offShardSize), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(uint32(offDataShardCount), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(uint32(offStreamLength), []byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(uint32(offVolumeCount), []byte{0, 0, 0, 0})
	f.Add(uint32(offDataShards), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(uint32(offTailOffset), []byte{1, 0, 0, 0, 0, 0, 0, 0})
	// The largest shard count and the largest shard size the bounds allow,
	// whose product is what used to wrap.
	f.Add(uint32(offDataShardCount), []byte{0, 0, 0, 0, 0, 1, 0, 0})
	f.Add(uint32(offShardSize), []byte{0, 0, 0, 16, 0, 0, 0, 0})

	base := validSuperblock()
	f.Fuzz(func(t *testing.T, offset uint32, data []byte) {
		if len(data) > SuperblockSize {
			data = data[:SuperblockSize]
		}
		sb, err := Unmarshal(patch(base, offset, data))
		if err != nil {
			return
		}

		// It parsed, so every number it carries is about to be used as an
		// offset or a length. They have to hold together.
		if sb.Layout().ShardSize == 0 {
			t.Fatal("a parsed header has a zero shard size")
		}

		var previousEnd uint64
		for i := uint64(0); i < sb.DataShardCount && i < 64; i++ {
			off := sb.ShardOffset(i)
			length := uint64(sb.ShardBytes(i))
			switch {
			case length == 0 || length > uint64(sb.ShardSize):
				t.Fatalf("shard %d is %d bytes, the shard size is %d", i, length, sb.ShardSize)
			case off < previousEnd:
				t.Fatalf("shard %d starts at %d, inside the previous shard which ends at %d", i, off, previousEnd)
			case off+length < off:
				t.Fatalf("shard %d overflows: offset %d plus %d bytes", i, off, length)
			}
			previousEnd = off + length
		}
		if total := sb.PayloadBytes(); sb.DataShardCount > 0 && total < previousEnd {
			t.Fatalf("the payload is %d bytes but its shards reach %d", total, previousEnd)
		}

		// The loop above stops at 64 shards, so it never reaches the products
		// that wrap. This is the same claim made about the whole payload, and it
		// is the one bond inspect leans on: it prints PayloadBytes for a header
		// nobody has authenticated.
		if !sb.Layout().OffsetsFit() {
			t.Fatal("a parsed header computes offsets that overflow a uint64")
		}
		if total := sb.PayloadBytes(); total > parity.MaxPayloadBytes {
			t.Fatalf("a parsed header describes a payload of %d bytes", total)
		}
	})
}

func validSlotTable(t *testing.T) []byte {
	table := &SlotTable{Generation: 1, Slots: []*crypto.Slot{{
		Type:    crypto.SlotPassphrase,
		UUID:    make([]byte, 16),
		Nonce:   make([]byte, crypto.NonceLen),
		Salt:    make([]byte, 16),
		Wrapped: make([]byte, crypto.KeyLen+crypto.TagLen),
		Label:   "seed",
	}}}
	b, err := table.Marshal(nil)
	if err != nil {
		t.Fatalf("building the seed table: %v", err)
	}
	return b
}

func FuzzParseSlotTable(f *testing.F) {
	f.Add(uint32(0), []byte{})
	f.Add(uint32(offSlotCount), []byte{0xff, 0xff})
	f.Add(uint32(offSlotUsedBytes), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(uint32(slotTableHeaderSize+offRecSize), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(uint32(slotTableHeaderSize+offRecWrapLen), []byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, offset uint32, data []byte) {
		if len(data) > 512 {
			data = data[:512]
		}
		parsed, err := ParseSlotTable(patch(validSlotTable(t), offset, data))
		if err != nil {
			return
		}
		if len(parsed.Slots) > maxSlots {
			t.Fatalf("parsed %d slots, the format allows %d", len(parsed.Slots), maxSlots)
		}
		for i, s := range parsed.Slots {
			switch {
			case len(s.UUID) != 16:
				t.Fatalf("slot %d has a %d-byte uuid", i, len(s.UUID))
			case len(s.Nonce) != crypto.NonceLen:
				t.Fatalf("slot %d has a %d-byte nonce", i, len(s.Nonce))
			case len(s.Salt) != 16:
				t.Fatalf("slot %d has a %d-byte salt", i, len(s.Salt))
			case len(s.Label) > maxLabelLen:
				t.Fatalf("slot %d has a %d-byte label", i, len(s.Label))
			}
		}
	})
}

// The manifest arrives encrypted, so what is fuzzed here is the framing and the
// length field in front of it – the part that is read before anything has been
// authenticated, and the one place an absurd number could become an absurd
// allocation.
func FuzzOpenManifest(f *testing.F) {
	key := make([]byte, crypto.KeyLen)
	uuid := make([]byte, 16)
	if sealed, err := SealManifest(&Manifest{FormatVersion: 1}, crypto.CipherXChaCha20Poly1305, key, uuid); err == nil {
		f.Add(sealed)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 8+crypto.NonceLen))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Only the outcome matters: a manifest that opens under this key is
		// authentic, and anything else has to be an error rather than a panic.
		if _, err := OpenManifest(data, crypto.CipherXChaCha20Poly1305, key, uuid); err != nil {
			return
		}
	})
}
