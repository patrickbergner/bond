package format

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/crypto"
)

// Manifest is everything about a container that is not raw payload: what was
// backed up, how, and what it should hash to.
//
// It holds the file index, which the p7e sketch deliberately kept out. The
// reasoning there was that names are sensitive – but the manifest is sealed
// with a key derived from the same master key as the payload, so a name here
// is exactly as protected as a name inside the archive. Keeping it means
// "bond list" answers from a few hundred kilobytes instead of decompressing
// half a terabyte.
type Manifest struct {
	FormatVersion int       `json:"formatVersion"`
	Created       time.Time `json:"created"`
	TargetID      string    `json:"targetId,omitempty"`
	Tool          string    `json:"tool,omitempty"`

	Compression Compression `json:"compression"`

	StreamLength   int64  `json:"streamLength"`
	StreamSHA256   string `json:"streamSha256"`
	ShardSize      int64  `json:"shardSize"`
	DataShardCount int64  `json:"dataShardCount"`

	RecoveryPercent int `json:"recoveryPercent"`
	DataShards      int `json:"dataShards,omitempty"`
	ParityShards    int `json:"parityShards,omitempty"`

	ArchiveRoot    string `json:"archiveRoot,omitempty"`
	SyntheticRoots bool   `json:"syntheticRoots,omitempty"`
	FollowSymlinks bool   `json:"followSymlinks,omitempty"`

	Files    int   `json:"files"`
	Dirs     int   `json:"dirs"`
	Symlinks int   `json:"symlinks"`
	Bytes    int64 `json:"bytes"`

	// Index is the file list. Absent when storeFileIndex is off.
	Index []archive.FileInfo `json:"index,omitempty"`
}

// Compression records how the payload was produced.
type Compression struct {
	Format string `json:"format"` // "xz" or "none"
	Level  int    `json:"level"`
	Solid  bool   `json:"solid"`
}

// maxManifestSize bounds what a reader will decompress. The length comes from
// an unauthenticated header on the first read, so an absurd value must not
// become an absurd allocation.
const maxManifestSize = 1 << 31

// SealManifest compresses, encrypts and frames the manifest.
//
// The framing is [8-byte length][24-byte nonce][ciphertext], and the whole
// thing is written twice in the container's tail. Duplication costs a few
// hundred kilobytes and covers the one region that has no parity of its own –
// losing it would mean holding a payload nobody can interpret.
func SealManifest(m *Manifest, c crypto.Cipher, manifestKey, containerUUID []byte) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encoding the manifest: %w", err)
	}

	var packed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&packed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(plain); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	nonce, err := crypto.RandomBytes(crypto.NonceLen)
	if err != nil {
		return nil, err
	}
	aead, err := crypto.AEAD(c, manifestKey)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, packed.Bytes(), crypto.ManifestAAD(containerUUID))

	out := make([]byte, 0, 8+len(nonce)+len(sealed))
	out = binary.LittleEndian.AppendUint64(out, uint64(len(sealed)))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// OpenManifest reverses SealManifest.
func OpenManifest(framed []byte, c crypto.Cipher, manifestKey, containerUUID []byte) (*Manifest, error) {
	if len(framed) < 8+crypto.NonceLen {
		return nil, fmt.Errorf("the manifest is truncated")
	}
	length := binary.LittleEndian.Uint64(framed)
	if length > maxManifestSize || int(length) != len(framed)-8-crypto.NonceLen {
		return nil, fmt.Errorf("the manifest claims %d bytes but %d are present", length, len(framed)-8-crypto.NonceLen)
	}
	nonce := framed[8 : 8+crypto.NonceLen]
	sealed := framed[8+crypto.NonceLen:]

	aead, err := crypto.AEAD(c, manifestKey)
	if err != nil {
		return nil, err
	}
	packed, err := aead.Open(nil, nonce, sealed, crypto.ManifestAAD(containerUUID))
	if err != nil {
		return nil, fmt.Errorf("the manifest fails authentication; it has been damaged or altered")
	}

	zr, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("the manifest is not readable: %w", err)
	}
	defer zr.Close()

	plain, err := io.ReadAll(io.LimitReader(zr, maxManifestSize))
	if err != nil {
		return nil, fmt.Errorf("the manifest is not readable: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(plain, &m); err != nil {
		return nil, fmt.Errorf("the manifest is not readable: %w", err)
	}
	return &m, nil
}
