package format

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/parity"
)

// header builds a superblock that is valid apart from whatever the caller
// changes, so each test can say exactly what it is about.
func header(edit func(*Superblock)) *Superblock {
	sb := &Superblock{
		VersionMajor:   VersionMajor,
		VersionMinor:   VersionMinor,
		Cipher:         crypto.CipherXChaCha20Poly1305,
		KDF:            KDFArgon2id,
		Parity:         ParityNone,
		ShardSize:      8192,
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
	if edit != nil {
		edit(sb)
	}
	return sb
}

// The trailing metadata sits at the end of the last volume's payload, and only
// the first volume of a set carries the key-slot tables. Demanding that the tail
// begin past the whole 132 KiB head refused every header of every volume in a
// set whose last file held less than 128 KiB – a container the writer had just
// reported as written, which no tool could then open.
func TestTailFloorIsVolumeAware(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Superblock)
		ok   bool
	}{
		{"a single volume's tail follows the whole head", func(sb *Superblock) {}, true},
		{"a single volume's tail cannot precede it", func(sb *Superblock) {
			sb.TailOffset = PayloadOffset - 1
		}, false},
		{"a later volume's tail follows only its own header", func(sb *Superblock) {
			sb.VolumeCount, sb.VolumeIndex = 3, 2
			sb.TailOffset = SuperblockSize + 116
		}, true},
		{"no volume's tail may reach into its header", func(sb *Superblock) {
			sb.VolumeCount, sb.VolumeIndex = 3, 2
			sb.TailOffset = SuperblockSize - 1
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Unmarshal(header(tc.edit).Marshal())
			if tc.ok && err != nil {
				t.Errorf("a valid header was refused: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("a header whose tail overlaps its own head was accepted")
			}
		})
	}
}

// checkBounds runs before any key exists, so every number in it is
// attacker-chosen. Multiplying the shard count by the shard size overflowed a
// uint64 and wrapped, which let a header describing no possible container pass
// a check that reads as though it were airtight.
func TestHostileGeometryIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Superblock)
	}{
		{"a shard count and size that multiply past a uint64", func(sb *Superblock) {
			sb.ShardSize = 256 << 20
			sb.DataShardCount = 1 << 40
			sb.StreamLength = 1 << 63
			sb.LastShardBytes = 256 << 20
		}},
		{"a payload larger than any storage", func(sb *Superblock) {
			sb.ShardSize = 256 << 20
			sb.DataShardCount = 1 << 39
			sb.StreamLength = 1 << 40
			sb.LastShardBytes = 256 << 20
		}},
		{"a shard count beyond what is plausible", func(sb *Superblock) {
			sb.DataShardCount = 1<<40 + 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb, err := Unmarshal(header(tc.edit).Marshal())
			if err != nil {
				return
			}
			// If it parsed at all, its offsets have to be usable: this is the
			// header that is about to steer every read.
			if !sb.Layout().OffsetsFit() {
				t.Fatalf("a parsed header computes offsets that overflow")
			}
			if total := sb.PayloadBytes(); total > parity.MaxPayloadBytes {
				t.Fatalf("a parsed header describes a %d-byte payload", total)
			}
		})
	}
}

// The MAC is over the bytes as they were read, so the round trip has to be
// exact: if Marshal and Unmarshal disagreed by a single byte, every container
// ever written would stop authenticating.
func TestCanonicalHeaderRoundTrips(t *testing.T) {
	original := header(nil).Marshal()
	parsed, err := Unmarshal(original)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(parsed.Marshal(), original) {
		t.Error("a header does not survive being parsed and rendered again")
	}
	if !bytes.Equal(parsed.Raw(), original) {
		t.Error("Raw does not return the bytes the header was parsed from")
	}
}

// The reserved region is part of the signed structure. It used to be signed
// only in principle: the MAC was taken over a re-marshal of the understood
// fields, which renders the region as zeros, so whatever was really there was
// covered by nothing at all.
func TestReservedBytesAreCoveredByTheMAC(t *testing.T) {
	keys, err := crypto.Derive(bytes.Repeat([]byte{9}, crypto.KeyLen), make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	sb := header(nil)
	sb.KeyCommitment = keys.Commitment(sb.ContainerUUID)
	sb.Sign(keys.Header)
	signed := sb.Marshal()

	if parsed, err := Unmarshal(signed); err != nil {
		t.Fatal(err)
	} else if err := parsed.Verify(keys); err != nil {
		t.Fatalf("an untouched header does not verify: %v", err)
	}

	// 244 is the gap between the last named field and where the reserved region
	// was documented to begin, which nothing looked at from either end.
	for _, at := range []int{244, 300, SuperblockSize - 1} {
		edited := append([]byte(nil), signed...)
		edited[at] ^= 0xff

		parsed, err := Unmarshal(edited)
		if err != nil {
			continue // refusing to parse is a fine answer too
		}
		if err := parsed.Verify(keys); err == nil {
			t.Errorf("a byte written at offset %d in the padding passed authentication", at)
		}
	}
}

// A header field that this build does not interpret still has to be covered,
// or a later minor version could not add one without every older reader
// refusing the container.
func TestUnknownFieldsStayAuthenticated(t *testing.T) {
	keys, err := crypto.Derive(bytes.Repeat([]byte{11}, crypto.KeyLen), make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	// Stand in for a later version: a field in the reserved region, signed by
	// the writer that understood it.
	future := header(func(sb *Superblock) { sb.VersionMinor = VersionMinor + 1 }).Marshal()
	binary.LittleEndian.PutUint64(future[offReserved:], 0xDEADBEEF)

	parsed, err := Unmarshal(future)
	if err != nil {
		t.Fatalf("a later minor version was refused outright: %v", err)
	}
	parsed.KeyCommitment = keys.Commitment(parsed.ContainerUUID)
	parsed.Sign(keys.Header)

	// Signing renders the header canonically, which is what a writer does. What
	// matters is that a reader can then authenticate the bytes it finds.
	reread, err := Unmarshal(parsed.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := reread.Verify(keys); err != nil {
		t.Errorf("a signed header did not verify after a round trip: %v", err)
	}
}
