// Command fixtures creates candidate format-2.0 compatibility artifacts.
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

const fixturePassphrase = "bond-v2-fixture-passphrase"

type vectors struct {
	Tuple               string            `json:"tuple"`
	Padme               map[string]uint64 `json:"padme"`
	FMK                 string            `json:"fmk"`
	ContainerUUID       string            `json:"containerUuid"`
	DataKey             string            `json:"dataKey"`
	HeaderKey           string            `json:"headerKey"`
	ManifestKey         string            `json:"manifestKey"`
	CommitKey           string            `json:"commitKey"`
	Commitment          string            `json:"commitment"`
	ShardNonce          string            `json:"shardNonce"`
	ShardAAD            string            `json:"shardAad"`
	ShardSealed         string            `json:"shardSealed"`
	SlotAAD             string            `json:"slotAad"`
	ManifestAAD         string            `json:"manifestAad"`
	PassphraseKEK       string            `json:"passphraseKek"`
	KeyfileSlotCommit   string            `json:"keyfileSlotCommitment"`
	KeyfileSlotWrapped  string            `json:"keyfileSlotWrapped"`
	HeaderMAC           string            `json:"headerMac"`
	HeaderSHA256        string            `json:"headerSha256"`
	SlotTableMAC        string            `json:"slotTableMac"`
	SlotTableSHA256     string            `json:"slotTableSha256"`
	RecipientSeed       string            `json:"recipientSeed"`
	RecipientPublic     string            `json:"recipientPublic"`
	RecipientPublicHash string            `json:"recipientPublicSha256"`
	RecoveryKey         string            `json:"recoveryKey"`
	ManifestFrame       string            `json:"manifestFrame"`
	ManifestFrameHash   string            `json:"manifestFrameSha256"`
	Parity              []string          `json:"parity"`
	WriterSeed          string            `json:"writerSeed"`
	WriterPublicHash    string            `json:"writerPublicSha256"`
	WriterFingerprint   string            `json:"writerFingerprint"`
	SignedHeaderSHA256  string            `json:"signedHeaderSha256"`
	SignatureSHA256     string            `json:"writerSignatureSha256"`
}

func main() {
	root, err := os.Getwd()
	must(err)
	must(writeGolden(filepath.Join(root, "internal", "container", "testdata", "v2-golden.bond")))
	must(writeVectors(filepath.Join(root, "internal", "format", "testdata", "v2-vectors.json")))
}

func writeGolden(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Create truncates, so the fixture this replaces goes first and visibly.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	signer, err := crypto.WriterFromSeed(sequence(0x60, crypto.WriterSeedLen))
	if err != nil {
		return err
	}
	defer signer.Wipe()
	w, err := container.Create(path, container.Options{
		ShardSize:       4096,
		RecoveryPercent: 50,
		Signer:          signer,
		Keys: []container.KeySpec{
			{
				Secret: crypto.Passphrase([]byte(fixturePassphrase)),
				KDF:    crypto.KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1},
				Label:  "documented fixture",
			},
			{
				Secret: crypto.KeyfileSecret(sequence(0x30, crypto.KeyLen)),
				Label:  "fixture key file",
			},
		},
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
	content := []byte("BOND format 2.0 compatibility fixture\n")
	if err := tw.WriteHeader(&tar.Header{Name: "fixture/hello.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)), ModTime: stamp}); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}
	// A second file large enough that the payload spans several shards and more
	// than one stripe, so the shard offsets of NERDME §11 are exercised.
	filler := sequenceLong(40_000)
	if err := tw.WriteHeader(&tar.Header{Name: "fixture/pattern.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(filler)), ModTime: stamp}); err != nil {
		return err
	}
	if _, err := tw.Write(filler); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	fileDigest := sha256.Sum256(content)
	fillerDigest := sha256.Sum256(filler)
	m := &format.Manifest{
		TargetID:       "format-v2-golden",
		Tool:           "tools/fixtures",
		Compression:    format.Compression{Format: "none", Solid: true},
		ArchiveRoot:    "fixture",
		FollowSymlinks: true,
		Files:          2,
		Dirs:           1,
		Bytes:          int64(len(content) + len(filler)),
		IndexStored:    true,
		Index: []bondarchive.FileInfo{
			{Path: "fixture", Kind: bondarchive.KindDir, Mode: 0o755, ModTime: stamp},
			{Path: "fixture/hello.txt", Kind: bondarchive.KindFile, Size: int64(len(content)), Mode: 0o644, ModTime: stamp, SHA256: hex.EncodeToString(fileDigest[:])},
			{Path: "fixture/pattern.bin", Kind: bondarchive.KindFile, Size: int64(len(filler)), Mode: 0o644, ModTime: stamp, SHA256: hex.EncodeToString(fillerDigest[:])},
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
	salt := sequence(0xd0, 16)
	params := crypto.KDFParams{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4}
	slotAADParams := make([]byte, 12)
	put32(slotAADParams[0:4], params.MemoryKiB)
	put32(slotAADParams[4:8], params.Iterations)
	put32(slotAADParams[8:12], params.Parallelism)

	// One shard sealed with every input fixed: the data key, the derived nonce
	// and the associated data are all above, so this is checked byte for byte.
	const shardIndex = 0x0102030405060708
	dataAEAD, err := crypto.AEAD(crypto.CipherXChaCha20Poly1305, keys.Data)
	if err != nil {
		return err
	}
	shardSealed := dataAEAD.Seal(nil, crypto.ShardNonce(noncePrefix, shardIndex), sequence(0x70, 48),
		crypto.ShardAAD(uuid, shardIndex, 4096))

	// A passphrase written in decomposed form: "Gru" + combining diaeresis +
	// "sse". The key is that of its NFC form.
	passphraseSlot := &crypto.Slot{Salt: salt, KDF: crypto.KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1}}
	passphraseKEK, err := crypto.Passphrase("Grüsse aus dem Tresor").Derive(passphraseSlot)
	if err != nil {
		return err
	}

	// A key-file slot with its nonce, salt and identifiers fixed.
	keyfileSlot := &crypto.Slot{
		Type: crypto.SlotKeyfile, UUID: slotUUID,
		Nonce: sequence(0x80, crypto.NonceLen), Salt: salt,
	}
	if err := keyfileSlot.Reseal(crypto.CipherXChaCha20Poly1305, uuid, fmk, crypto.KeyfileSecret(sequence(0x30, crypto.KeyLen))); err != nil {
		return err
	}

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
		Commitment: sequence(0x10, crypto.CommitmentLen),
		Salt:       salt, KDF: params,
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

	padme := map[string]uint64{}
	for _, n := range []uint64{0, 1, 2, 3, 9, 100, 1000, 4096, 65537, 1_000_000, 123_456_789, 5_000_000_000} {
		padme[fmt.Sprint(n)] = format.Padme(n)
	}

	v := vectors{
		Tuple: hexOf(crypto.Tuple([]byte("abc"), nil, []byte{0xff, 0x00})),
		Padme: padme,
		FMK:   hexOf(fmk), ContainerUUID: hexOf(uuid),
		DataKey: hexOf(keys.Data), HeaderKey: hexOf(keys.Header), ManifestKey: hexOf(keys.Manifest), CommitKey: hexOf(keys.Commit),
		Commitment:         hexOf(keys.Commitment(uuid)),
		ShardNonce:         hexOf(crypto.ShardNonce(noncePrefix, shardIndex)),
		ShardAAD:           hexOf(crypto.ShardAAD(uuid, shardIndex, 4096)),
		ShardSealed:        hexOf(shardSealed),
		SlotAAD:            hexOf(crypto.SlotAAD(uuid, slotUUID, uint8(crypto.SlotPassphrase), salt, slotAADParams)),
		ManifestAAD:        hexOf(crypto.ManifestAAD(uuid)),
		PassphraseKEK:      hexOf(passphraseKEK),
		KeyfileSlotCommit:  hexOf(keyfileSlot.Commitment),
		KeyfileSlotWrapped: hexOf(keyfileSlot.Wrapped),
		HeaderMAC:          hexOf(sb.HeaderMAC), HeaderSHA256: hashOf(header),
		SlotTableMAC: hexOf(table.MAC), SlotTableSHA256: hashOf(tableBytes),
		RecipientSeed: hexOf(seed), RecipientPublic: hexOf(public), RecipientPublicHash: hashOf(public), RecoveryKey: recoveryKey,
		ManifestFrame: hexOf(frame), ManifestFrameHash: hashOf(frame),
	}
	for _, p := range parityBytes {
		v.Parity = append(v.Parity, hexOf(p))
	}

	// The same header, signed by a writer with deterministic ML-DSA, so the
	// signature is checked byte for byte.
	writerSeed := sequence(0x60, crypto.WriterSeedLen)
	writer, err := crypto.WriterFromSeed(writerSeed)
	if err != nil {
		return err
	}
	defer writer.Wipe()
	signed := *sb
	if err := signed.SignWriter(writer.Deterministic()); err != nil {
		return err
	}
	signed.Sign(keys.Header)
	v.WriterSeed = hexOf(writerSeed)
	v.WriterPublicHash = hashOf(writer.Public().Bytes())
	v.WriterFingerprint = hexOf(writer.Fingerprint())
	v.SignedHeaderSHA256 = hashOf(signed.Marshal())
	v.SignatureSHA256 = hashOf(signed.Signature)
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

// sequenceLong is a longer pattern that does not repeat every 256 bytes, so a
// shard read from the wrong offset does not happen to hold the right bytes.
func sequenceLong(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i) ^ byte(i>>8) ^ byte(i>>16)
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
