package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher identifies the AEAD a container uses. It is a header field so the
// format can move on without a new version number.
type Cipher uint32

const (
	CipherXChaCha20Poly1305 Cipher = 1
)

func (c Cipher) String() string {
	switch c {
	case CipherXChaCha20Poly1305:
		return "XChaCha20-Poly1305"
	default:
		return fmt.Sprintf("unknown cipher %d", uint32(c))
	}
}

// TagLen is the authentication tag every sealed block carries.
const TagLen = chacha20poly1305.Overhead

// NonceLen is the nonce size of the v1 cipher. Twenty-four bytes is what makes
// the payload nonce schedule safe: a 16-byte random per-container prefix
// leaves a 64-bit counter that a single container can never exhaust.
const NonceLen = chacha20poly1305.NonceSizeX

// AEAD builds the authenticated cipher for a key.
func AEAD(c Cipher, key []byte) (cipher.AEAD, error) {
	switch c {
	case CipherXChaCha20Poly1305:
		return chacha20poly1305.NewX(key)
	default:
		return nil, fmt.Errorf("this build does not know %s", c)
	}
}

// Domain strings that go into associated data, keeping every use of the same
// key distinguishable from every other.
const (
	adData     = "BOND-DATA-V2"
	adSlot     = "BOND-SLOT-V2"
	adManifest = "BOND-MANIFEST-V2"
	adCommit   = "BOND-COMMIT-V2"
)

// Tuple encodes several values as one byte string that cannot be read as any
// other sequence of values: each is preceded by its length as a little-endian
// uint32.
//
// Every associated data, MAC input and combined secret in the format goes
// through it. Plain concatenation is only unambiguous while every field has a
// fixed length, and it stops being so – silently, with every test still
// passing – the day a variable-length field is put next to another one. With
// the lengths written down there is nothing to get wrong later.
func Tuple(fields ...[]byte) []byte {
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	for _, f := range fields {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

// ShardNonce is the nonce for one payload shard: a random per-container prefix
// followed by the shard's index.
//
// Deriving it rather than storing one per shard saves nothing in space but a
// great deal in doubt – an index is unique within a container by construction,
// so the same nonce cannot be used twice under the same key.
func ShardNonce(prefix []byte, index uint64) []byte {
	nonce := make([]byte, NonceLen)
	copy(nonce, prefix)
	binary.LittleEndian.PutUint64(nonce[NonceLen-8:], index)
	return nonce
}

// ShardAAD binds a sealed shard to its container and its position.
//
// Without the index, a shard could be moved or repeated elsewhere in the same
// container and still authenticate; without the container UUID, a shard from
// another container encrypted under the same key would too. Neither is
// something the tag alone would notice.
func ShardAAD(containerUUID []byte, index uint64, shardSize uint32) []byte {
	return Tuple(
		[]byte(adData),
		containerUUID,
		binary.LittleEndian.AppendUint64(nil, index),
		binary.LittleEndian.AppendUint32(nil, shardSize),
	)
}

// SlotAAD binds a wrapped master key to its container, its slot and the
// parameters its key-encryption key was made with.
func SlotAAD(containerUUID, slotUUID []byte, slotType uint8, salt, params []byte) []byte {
	return Tuple([]byte(adSlot), containerUUID, slotUUID, []byte{slotType}, salt, params)
}

// ManifestAAD binds the manifest to its container.
func ManifestAAD(containerUUID []byte) []byte {
	return Tuple([]byte(adManifest), containerUUID)
}
