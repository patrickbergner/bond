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
	adData     = "BOND-DATA-V1"
	adSlot     = "BOND-SLOT-V1"
	adManifest = "BOND-MANIFEST-V1"
)

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
	aad := make([]byte, 0, len(adData)+len(containerUUID)+12)
	aad = append(aad, adData...)
	aad = append(aad, containerUUID...)
	aad = binary.LittleEndian.AppendUint64(aad, index)
	aad = binary.LittleEndian.AppendUint32(aad, shardSize)
	return aad
}

// SlotAAD binds a wrapped master key to its container and its slot.
func SlotAAD(containerUUID, slotUUID []byte, slotType uint8, params []byte) []byte {
	aad := make([]byte, 0, len(adSlot)+len(containerUUID)+len(slotUUID)+1+len(params))
	aad = append(aad, adSlot...)
	aad = append(aad, containerUUID...)
	aad = append(aad, slotUUID...)
	aad = append(aad, slotType)
	aad = append(aad, params...)
	return aad
}

// ManifestAAD binds the manifest to its container.
func ManifestAAD(containerUUID []byte) []byte {
	aad := make([]byte, 0, len(adManifest)+len(containerUUID))
	aad = append(aad, adManifest...)
	aad = append(aad, containerUUID...)
	return aad
}
