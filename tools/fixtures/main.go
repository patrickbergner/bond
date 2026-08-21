// Command fixtures creates candidate format-1.0 compatibility artifacts.
// Generated files are reviewed and committed; ordinary builds never run it.
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bondarchive "github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
)

const fixturePassphrase = "bond-v1-fixture-passphrase"

type vectors struct {
	FMK                 string   `json:"fmk"`
	ContainerUUID       string   `json:"containerUuid"`
	DataKey             string   `json:"dataKey"`
	HeaderKey           string   `json:"headerKey"`
	ManifestKey         string   `json:"manifestKey"`
	CommitKey           string   `json:"commitKey"`
	Commitment          string   `json:"commitment"`
	ShardNonce          string   `json:"shardNonce"`
	ShardAAD            string   `json:"shardAad"`
	SlotAAD             string   `json:"slotAad"`
	ManifestAAD         string   `json:"manifestAad"`
	HeaderMAC           string   `json:"headerMac"`
	HeaderSHA256        string   `json:"headerSha256"`
	SlotTableMAC        string   `json:"slotTableMac"`
	SlotTableSHA256     string   `json:"slotTableSha256"`
	RecipientSeed       string   `json:"recipientSeed"`
	RecipientPublic     string   `json:"recipientPublic"`
	RecipientPublicHash string   `json:"recipientPublicSha256"`
	RecoveryKey         string   `json:"recoveryKey"`
	ManifestFrame       string   `json:"manifestFrame"`
	ManifestFrameHash   string   `json:"manifestFrameSha256"`
	Parity              []string `json:"parity"`
}

func main() {
	root, err := os.Getwd()
	must(err)
	must(writeGolden(filepath.Join(root, "internal", "container", "testdata", "v1-golden.bond")))
	must(writeVectors(filepath.Join(root, "internal", "format", "testdata", "v1-vectors.json")))
}

func writeGolden(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	w, err := container.Create(path, container.Options{
		ShardSize: 4096,
		Keys: []container.KeySpec{{
			Secret: crypto.Passphrase([]byte(fixturePassphrase)),
			KDF:    crypto.KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1},
			Label:  "documented fixture",
		}},
	})
	if err != nil {
		return err
	}
	defer w.Destroy()

	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: "fixture/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: stamp}); err != nil {
		return err
	}
	content := []byte("BOND format 1.0 compatibility fixture\n")
	if err := tw.WriteHeader(&tar.Header{Name: "fixture/hello.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)), ModTime: stamp}); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	fileDigest := sha256.Sum256(content)
	m := &format.Manifest{
		TargetID:       "format-v1-golden",
		Tool:           "tools/fixtures",
		Compression:    format.Compression{Format: "none", Solid: true},
		ArchiveRoot:    "fixture",
		FollowSymlinks: true,
		Files:          1,
		Dirs:           1,
		Bytes:          int64(len(content)),
		IndexStored:    true,
		Index: []bondarchive.FileInfo{
			{Path: "fixture", Kind: bondarchive.KindDir, Mode: 0o755, ModTime: stamp},
			{Path: "fixture/hello.txt", Kind: bondarchive.KindFile, Size: int64(len(content)), Mode: 0o644, ModTime: stamp, SHA256: hex.EncodeToString(fileDigest[:])},
		},
	}
	return w.Finish(m)
}

func writeVectors(path string) error {
	fmk := sequence(0x00, crypto.KeyLen)
	uuid := sequence(0x20, 16)
	noncePrefix := sequence(0x40, 16)
	keys, err := crypto.Derive(fmk, uuid)
	if err != nil {
		return err
	}
	defer keys.Wipe()

	slotUUID := sequence(0x50, 16)
	params := crypto.KDFParams{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4}
	slotAADParams := make([]byte, 12)
	put32(slotAADParams[0:4], params.MemoryKiB)
	put32(slotAADParams[4:8], params.Iterations)
	put32(slotAADParams[8:12], params.Parallelism)

	sb := &format.Superblock{
		VersionMajor: format.VersionMajor, VersionMinor: format.VersionMinor,
		Cipher: crypto.CipherXChaCha20Poly1305, KDF: format.KDFArgon2id, Parity: format.ParityRS,
		ShardSize: 4096, DataShards: 8, ParityShards: 2, DataShardCount: 9,
		StreamLength: 32000, LastShardBytes: 1280,
		Created:       time.Date(2025, 12, 31, 23, 59, 58, 0, time.UTC),
		ContainerUUID: uuid, NoncePrefix: noncePrefix,
		TailOffset: 54321, TailLength: 777, TailSHA256: sequence(0x60, 32),
		VolumeIndex: 1, VolumeCount: 3, VolumeLogicalStart: 12345, VolumeLogicalLen: 23456,
		KeyCommitment: keys.Commitment(uuid),
	}
	sb.Sign(keys.Header)
	header := sb.Marshal()

	slot := &crypto.Slot{
		Type: crypto.SlotPassphrase, UUID: slotUUID, Label: "known answer",
		Nonce: sequence(0x80, crypto.NonceLen), Wrapped: sequence(0xa0, crypto.KeyLen+crypto.TagLen),
		Salt: sequence(0xd0, 16), KDF: params,
	}
	table := &format.SlotTable{Generation: 7, Slots: []*crypto.Slot{slot}}
	tableBytes, err := table.Marshal(keys.Header)
	if err != nil {
		return err
	}

	seed := sequence(0x11, crypto.SeedLen)
	priv, err := crypto.RecipientFromSeed(seed)
	if err != nil {
		return err
	}
	defer priv.Wipe()
	public := priv.Public().Bytes()
	recoveryKey, err := crypto.EncodeRecoveryKey(seed)
	if err != nil {
		return err
	}

	emptyDigest := sha256.Sum256(nil)
	manifest := &format.Manifest{
		FormatVersion: format.VersionMajor,
		Created:       time.Date(2025, 12, 31, 23, 59, 58, 0, time.UTC),
		Compression:   format.Compression{Format: "none", Solid: true},
		StreamSHA256:  hex.EncodeToString(emptyDigest[:]),
		ShardSize:     4096,
		IndexStored:   true,
	}
	frame, err := format.SealManifest(manifest, crypto.CipherXChaCha20Poly1305, keys.Manifest, uuid)
	if err != nil {
		return err
	}

	coder, err := parity.NewCoder(parity.Plan{Data: 8, Parity: 2})
	if err != nil {
		return err
	}
	parityBytes, err := coder.Encode([][]byte{{0, 1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11}}, 4, 2)
	if err != nil {
		return err
	}

	v := vectors{
		FMK: hexOf(fmk), ContainerUUID: hexOf(uuid),
		DataKey: hexOf(keys.Data), HeaderKey: hexOf(keys.Header), ManifestKey: hexOf(keys.Manifest), CommitKey: hexOf(keys.Commit),
		Commitment:  hexOf(keys.Commitment(uuid)),
		ShardNonce:  hexOf(crypto.ShardNonce(noncePrefix, 0x0102030405060708)),
		ShardAAD:    hexOf(crypto.ShardAAD(uuid, 0x0102030405060708, 4096)),
		SlotAAD:     hexOf(crypto.SlotAAD(uuid, slotUUID, uint8(crypto.SlotPassphrase), slotAADParams)),
		ManifestAAD: hexOf(crypto.ManifestAAD(uuid)),
		HeaderMAC:   hexOf(sb.HeaderMAC), HeaderSHA256: hashOf(header),
		SlotTableMAC: hexOf(table.MAC), SlotTableSHA256: hashOf(tableBytes),
		RecipientSeed: hexOf(seed), RecipientPublic: hexOf(public), RecipientPublicHash: hashOf(public), RecoveryKey: recoveryKey,
		ManifestFrame: hexOf(frame), ManifestFrameHash: hashOf(frame),
	}
	for _, p := range parityBytes {
		v.Parity = append(v.Parity, hexOf(p))
	}
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o644)
}

func sequence(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func put32(dst []byte, value uint32) {
	dst[0], dst[1], dst[2], dst[3] = byte(value), byte(value>>8), byte(value>>16), byte(value>>24)
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
