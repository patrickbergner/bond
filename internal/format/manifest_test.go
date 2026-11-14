package format

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/crypto"
)

func validManifest() Manifest {
	empty := sha256.Sum256(nil)
	return Manifest{
		FormatVersion: VersionMajor,
		Created:       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Compression:   Compression{Format: "none", Solid: true},
		StreamSHA256:  hex.EncodeToString(empty[:]),
		ShardSize:     4096,
		IndexStored:   true,
	}
}

func TestManifestValidateRejectsInvalidSemantics(t *testing.T) {
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	digest := strings.Repeat("0", 64)
	tests := map[string]func(*Manifest){
		"version":            func(m *Manifest) { m.FormatVersion = VersionMajor + 1 },
		"created":            func(m *Manifest) { m.Created = time.Time{} },
		"compression":        func(m *Manifest) { m.Compression.Format = "future" },
		"compression level":  func(m *Manifest) { m.Compression.Level = 1 },
		"negative count":     func(m *Manifest) { m.Files = -1 },
		"digest syntax":      func(m *Manifest) { m.StreamSHA256 = "ABC" },
		"shard geometry":     func(m *Manifest) { m.ShardSize = 4097 },
		"stream shard count": func(m *Manifest) { m.DataShardCount = 1 },
		"recovery geometry":  func(m *Manifest) { m.RecoveryPercent, m.DataShards, m.ParityShards = 10, 8, 2 },
		"unstored index": func(m *Manifest) {
			m.IndexStored = false
			m.Index = []archive.FileInfo{{Path: "x", Kind: archive.KindDir, ModTime: stamp}}
		},
		"unsafe index path": func(m *Manifest) {
			m.Index = []archive.FileInfo{{Path: "../x", Kind: archive.KindDir, ModTime: stamp}}
			m.Dirs = 1
		},
		"duplicate path": func(m *Manifest) {
			m.Index = []archive.FileInfo{{Path: "x", Kind: archive.KindDir, ModTime: stamp}, {Path: "x", Kind: archive.KindDir, ModTime: stamp}}
			m.Dirs = 2
		},
		"unsupported kind":   func(m *Manifest) { m.Index = []archive.FileInfo{{Path: "x", Kind: archive.Kind(99), ModTime: stamp}} },
		"missing entry time": func(m *Manifest) { m.Index = []archive.FileInfo{{Path: "x", Kind: archive.KindDir}}; m.Dirs = 1 },
		"bad file digest": func(m *Manifest) {
			m.Index = []archive.FileInfo{{Path: "x", Kind: archive.KindFile, ModTime: stamp, SHA256: "bad"}}
			m.Files = 1
		},
		"index count mismatch": func(m *Manifest) {
			m.Index = []archive.FileInfo{{Path: "x", Kind: archive.KindFile, ModTime: stamp, SHA256: digest}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			mutate(&m)
			if err := m.Validate(); err == nil {
				t.Fatalf("invalid manifest was accepted: %+v", m)
			}
		})
	}
}

// A container written on one platform has to open on every platform. Names that
// only Windows refuses – device names, colons, backslashes, a trailing dot –
// are legitimate content, and validating the index against the local host's
// naming rules would make a Linux-made backup fail to unlock on Windows: not
// "this entry cannot be restored here", but "the manifest is invalid", reported
// by inspect, verify and list alike.
func TestManifestValidateAcceptsNamesOnlyWindowsRefuses(t *testing.T) {
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, name := range []string{"com1", "aux", "report:2024.txt", `back\slash`, "trailing.", "trailing "} {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			m.Index = []archive.FileInfo{{Path: name, Kind: archive.KindDir, ModTime: stamp}}
			m.Dirs = 1
			if err := m.Validate(); err != nil {
				t.Fatalf("a portable-but-not-Windows name made the container unopenable: %v", err)
			}
			// The restore path still refuses it, which is where the refusal belongs.
			if archive.CheckPortableName(name) != nil {
				t.Errorf("CheckPortableName rejected %q", name)
			}
		})
	}
}

func TestOpenManifestRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, crypto.KeyLen)
	uuid := bytes.Repeat([]byte{0x24}, 16)
	m := validManifest()
	plain, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), plain[:len(plain)-1]...), []byte(`,"unknown":true}`)...)
	for name, candidate := range map[string][]byte{
		"unknown field": unknown,
		"trailing JSON": append(append([]byte(nil), plain...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			framed := sealManifestPlain(t, candidate, key, uuid)
			if _, err := OpenManifest(framed, crypto.CipherXChaCha20Poly1305, key, uuid); err == nil {
				t.Fatal("malformed manifest was accepted")
			}
		})
	}
}

func sealManifestPlain(t *testing.T, plain, key, uuid []byte) []byte {
	t.Helper()
	var packed bytes.Buffer
	zw := gzip.NewWriter(&packed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	aead, err := crypto.AEAD(crypto.CipherXChaCha20Poly1305, key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, crypto.NonceLen)
	sealed := aead.Seal(nil, nonce, packed.Bytes(), crypto.ManifestAAD(uuid))
	out := make([]byte, 8+len(nonce), 8+len(nonce)+len(sealed))
	binary.LittleEndian.PutUint64(out, uint64(len(sealed)))
	copy(out[8:], nonce)
	return append(out, sealed...)
}
