package format

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/parity"
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

	// StreamLength is the exact length of the compressed stream. PaddedLength
	// is what the shards hold – the stream followed by zeros up to its Padmé
	// length – and is the number the header carries in the clear.
	StreamLength   int64  `json:"streamLength"`
	PaddedLength   int64  `json:"paddedLength"`
	StreamSHA256   string `json:"streamSha256"`
	ShardSize      int64  `json:"shardSize"`
	DataShardCount int64  `json:"dataShardCount"`

	RecoveryPercent int `json:"recoveryPercent"`
	DataShards      int `json:"dataShards,omitempty"`
	ParityShards    int `json:"parityShards,omitempty"`

	ArchiveRoot    string `json:"archiveRoot,omitempty"`
	SyntheticRoots bool   `json:"syntheticRoots,omitempty"`
	FollowSymlinks bool   `json:"followSymlinks,omitempty"`

	Files           int   `json:"files"`
	Dirs            int   `json:"dirs"`
	SkippedSymlinks int   `json:"skippedSymlinks"`
	Bytes           int64 `json:"bytes"`

	IndexStored bool               `json:"indexStored"`
	Index       []archive.FileInfo `json:"index,omitempty"`
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
	// The compressed manifest is length-prefixed and padded before it is
	// sealed, for the same reason the payload is: its size follows the number
	// of files and the length of their names, and that is not the storage
	// provider's business.
	inner := make([]byte, Padme(uint64(8+packed.Len())))
	binary.LittleEndian.PutUint64(inner, uint64(packed.Len()))
	copy(inner[8:], packed.Bytes())
	sealed := aead.Seal(nil, nonce, inner, crypto.ManifestAAD(containerUUID))

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
	inner, err := aead.Open(nil, nonce, sealed, crypto.ManifestAAD(containerUUID))
	if err != nil {
		return nil, fmt.Errorf("the manifest fails authentication; it has been damaged or altered")
	}
	if len(inner) < 8 {
		return nil, fmt.Errorf("the manifest is not readable: it is shorter than its own length field")
	}
	packedLen := binary.LittleEndian.Uint64(inner)
	if packedLen > uint64(len(inner)-8) || Padme(8+packedLen) != uint64(len(inner)) {
		return nil, fmt.Errorf("the manifest is not readable: its length field does not match its padding")
	}
	packed := inner[8 : 8+packedLen]
	for _, b := range inner[8+packedLen:] {
		if b != 0 {
			return nil, fmt.Errorf("the manifest is not readable: its padding is not empty")
		}
	}

	zr, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("the manifest is not readable: %w", err)
	}
	defer zr.Close()

	plain, err := io.ReadAll(io.LimitReader(zr, maxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("the manifest is not readable: %w", err)
	}

	if len(plain) > maxManifestSize {
		return nil, fmt.Errorf("the manifest expands beyond the %d-byte limit", maxManifestSize)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("the manifest is not readable: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("more than one JSON value is present")
		}
		return nil, fmt.Errorf("the manifest has trailing data: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("the manifest is invalid: %w", err)
	}
	return &m, nil
}

// Padme is the padded length of n bytes (Nikitin et al., "Reducing Metadata
// Leakage from Encrypted Files and Communication with PURBs", 2019).
//
// It keeps the top bits of a length and rounds the rest up, so the padded
// length says roughly how large something is and not exactly: for a length
// with bit length E+1 the low E − ⌊log₂E⌋ − 1 bits are rounded away. The cost
// falls in steps: at most 12.5% below 256 bytes, 6.3% up to 64 KiB, 3.2% from
// there to 4 GiB and 1.6% above, where padding to a power of two would cost up
// to 100%.
func Padme(n uint64) uint64 {
	if n < 2 {
		return n
	}
	e := uint(bits.Len64(n) - 1)     // ⌊log₂ n⌋
	s := uint(bits.Len64(uint64(e))) // ⌊log₂ e⌋ + 1
	mask := uint64(1)<<(e-s) - 1     // the bits rounded away
	return (n + mask) &^ mask
}

// Validate checks the authenticated manifest's semantic contract. Strict
// validation turns future format drift into a clear version error instead of a
// late restore failure or an accidental fallback to raw tar.
func (m *Manifest) Validate() error {
	if m.FormatVersion != VersionMajor {
		return fmt.Errorf("format version %d is unsupported; want %d", m.FormatVersion, VersionMajor)
	}
	if m.Created.IsZero() {
		return fmt.Errorf("creation time is missing")
	}
	switch m.Compression.Format {
	case "none":
		if m.Compression.Level != 0 {
			return fmt.Errorf("uncompressed stream records compression level %d", m.Compression.Level)
		}
	case "xz":
		if m.Compression.Level < 1 || m.Compression.Level > 9 {
			return fmt.Errorf("xz compression level %d is outside 1..9", m.Compression.Level)
		}
	default:
		return fmt.Errorf("compression format %q is unsupported", m.Compression.Format)
	}
	if !m.Compression.Solid {
		return fmt.Errorf("the payload is not recorded as a solid stream")
	}
	if m.StreamLength < 0 || m.PaddedLength < 0 || m.ShardSize < 0 || m.DataShardCount < 0 ||
		m.RecoveryPercent < 0 || m.DataShards < 0 || m.ParityShards < 0 ||
		m.Files < 0 || m.Dirs < 0 || m.SkippedSymlinks < 0 || m.Bytes < 0 {
		return fmt.Errorf("manifest counts and sizes must not be negative")
	}
	if m.ShardSize <= crypto.TagLen || m.ShardSize%4096 != 0 {
		return fmt.Errorf("shardSize %d is not a positive multiple of 4096 with room for an authentication tag", m.ShardSize)
	}
	if uint64(m.PaddedLength) != Padme(uint64(m.StreamLength)) {
		return fmt.Errorf("paddedLength is %d, a stream of %d bytes pads to %d", m.PaddedLength, m.StreamLength, Padme(uint64(m.StreamLength)))
	}
	plainPerShard := m.ShardSize - crypto.TagLen
	expectedShards := int64(0)
	if m.PaddedLength > 0 {
		expectedShards = (m.PaddedLength + plainPerShard - 1) / plainPerShard
	}
	if m.DataShardCount != expectedShards {
		return fmt.Errorf("dataShardCount is %d, stream length and shard size require %d", m.DataShardCount, expectedShards)
	}
	digest, err := hex.DecodeString(m.StreamSHA256)
	if err != nil || len(digest) != 32 || strings.ToLower(m.StreamSHA256) != m.StreamSHA256 {
		return fmt.Errorf("streamSha256 is not a lowercase SHA-256 digest")
	}
	plan, err := parity.For(m.RecoveryPercent)
	if err != nil {
		return err
	}
	if m.DataShards != plan.Data || m.ParityShards != plan.Parity {
		return fmt.Errorf("recovery percent %d requires a %d+%d stripe, manifest records %d+%d",
			m.RecoveryPercent, plan.Data, plan.Parity, m.DataShards, m.ParityShards)
	}
	if !m.IndexStored {
		if len(m.Index) != 0 {
			return fmt.Errorf("indexStored is false but an index is present")
		}
		return nil
	}

	seen := make(map[string]bool, len(m.Index))
	var files, dirs int
	var bytesTotal int64
	for i, entry := range m.Index {
		// Portable rules only. A name Windows cannot create is still a valid
		// thing for a container to hold, and refusing it here would make the
		// container unopenable on Windows rather than making one entry
		// unrestorable there. The restore path judges it, per entry, in SafeJoin.
		if err := archive.CheckPortableName(entry.Path); err != nil {
			return fmt.Errorf("index entry %d path %q: %w", i, entry.Path, err)
		}
		if seen[entry.Path] {
			return fmt.Errorf("index path %q appears more than once", entry.Path)
		}
		seen[entry.Path] = true
		if entry.ModTime.IsZero() {
			return fmt.Errorf("index entry %q has no modification time", entry.Path)
		}
		switch entry.Kind {
		case archive.KindDir:
			dirs++
			if entry.Size != 0 || entry.SHA256 != "" {
				return fmt.Errorf("directory %q carries file size or digest data", entry.Path)
			}
		case archive.KindFile:
			files++
			if entry.Size < 0 {
				return fmt.Errorf("file %q has negative size", entry.Path)
			}
			digest, err := hex.DecodeString(entry.SHA256)
			if err != nil || len(digest) != 32 || strings.ToLower(entry.SHA256) != entry.SHA256 {
				return fmt.Errorf("file %q has an invalid SHA-256 digest", entry.Path)
			}
			if entry.Size > int64(^uint64(0)>>1)-bytesTotal {
				return fmt.Errorf("indexed file sizes overflow their aggregate")
			}
			bytesTotal += entry.Size
		default:
			return fmt.Errorf("index entry %q has unsupported kind %d", entry.Path, entry.Kind)
		}
	}
	if files != m.Files || dirs != m.Dirs || bytesTotal != m.Bytes {
		return fmt.Errorf("index totals are %d files, %d directories and %d bytes; manifest records %d, %d and %d",
			files, dirs, bytesTotal, m.Files, m.Dirs, m.Bytes)
	}
	return nil
}
