package format_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
)

type v2Vectors struct {
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

func TestFormatV2KnownAnswerVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v v2Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	checkHex(t, "tuple", crypto.Tuple([]byte("abc"), nil, []byte{0xff, 0x00}), v.Tuple)
	if len(v.Padme) == 0 {
		t.Fatal("no Padmé vectors")
	}
	for input, want := range v.Padme {
		var n uint64
		if _, err := fmt.Sscan(input, &n); err != nil {
			t.Fatal(err)
		}
		if got := format.Padme(n); got != want {
			t.Errorf("Padme(%d) = %d, want %d", n, got, want)
		}
	}

	fmk, uuid := decode(t, v.FMK), decode(t, v.ContainerUUID)
	keys, err := crypto.Derive(fmk, uuid)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Wipe()
	checkHex(t, "data key", keys.Data, v.DataKey)
	checkHex(t, "header key", keys.Header, v.HeaderKey)
	checkHex(t, "manifest key", keys.Manifest, v.ManifestKey)
	checkHex(t, "commit key", keys.Commit, v.CommitKey)
	checkHex(t, "commitment", keys.Commitment(uuid), v.Commitment)

	noncePrefix := sequence(0x40, 16)
	slotUUID := sequence(0x50, 16)
	salt := sequence(0xd0, 16)
	params := []byte{0, 0, 1, 0, 3, 0, 0, 0, 4, 0, 0, 0}
	const shardIndex = 0x0102030405060708
	checkHex(t, "shard nonce", crypto.ShardNonce(noncePrefix, shardIndex), v.ShardNonce)
	checkHex(t, "shard AAD", crypto.ShardAAD(uuid, shardIndex, 4096), v.ShardAAD)
	checkHex(t, "slot AAD", crypto.SlotAAD(uuid, slotUUID, uint8(crypto.SlotPassphrase), salt, params), v.SlotAAD)
	checkHex(t, "manifest AAD", crypto.ManifestAAD(uuid), v.ManifestAAD)

	// Encryption, not only decryption: every input of this shard is fixed.
	dataAEAD, err := crypto.AEAD(crypto.CipherXChaCha20Poly1305, keys.Data)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, "sealed shard", dataAEAD.Seal(nil, crypto.ShardNonce(noncePrefix, shardIndex), sequence(0x70, 48),
		crypto.ShardAAD(uuid, shardIndex, 4096)), v.ShardSealed)

	// The passphrase is hashed in NFC, whichever form it was typed in.
	fast := crypto.KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1}
	for name, typed := range map[string]string{
		"decomposed":  "Grüsse aus dem Tresor",
		"precomposed": "Grüsse aus dem Tresor",
	} {
		kek, err := crypto.Passphrase(typed).Derive(&crypto.Slot{Salt: salt, KDF: fast})
		if err != nil {
			t.Fatal(err)
		}
		checkHex(t, "passphrase KEK, "+name, kek, v.PassphraseKEK)
	}

	keyfile := crypto.KeyfileSecret(sequence(0x30, crypto.KeyLen))
	keyfileSlot := &crypto.Slot{Type: crypto.SlotKeyfile, UUID: slotUUID, Nonce: sequence(0x80, crypto.NonceLen), Salt: salt}
	if err := keyfileSlot.Reseal(crypto.CipherXChaCha20Poly1305, uuid, fmk, keyfile); err != nil {
		t.Fatal(err)
	}
	checkHex(t, "key-file slot commitment", keyfileSlot.Commitment, v.KeyfileSlotCommit)
	checkHex(t, "key-file slot wrapped key", keyfileSlot.Wrapped, v.KeyfileSlotWrapped)
	stored := &crypto.Slot{
		Type: crypto.SlotKeyfile, UUID: slotUUID, Nonce: sequence(0x80, crypto.NonceLen), Salt: salt,
		Commitment: decode(t, v.KeyfileSlotCommit), Wrapped: decode(t, v.KeyfileSlotWrapped),
	}
	opened, err := stored.Unwrap(crypto.CipherXChaCha20Poly1305, uuid, keyfile)
	if err != nil {
		t.Fatalf("the recorded key-file slot no longer opens: %v", err)
	}
	checkHex(t, "master key from the key-file slot", opened, v.FMK)

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
	checkHex(t, "header MAC", sb.HeaderMAC, v.HeaderMAC)
	checkHash(t, "header", sb.Marshal(), v.HeaderSHA256)

	slot := &crypto.Slot{
		Type: crypto.SlotPassphrase, UUID: slotUUID, Label: "known answer",
		Nonce: sequence(0x80, crypto.NonceLen), Wrapped: sequence(0xa0, crypto.KeyLen+crypto.TagLen),
		Commitment: sequence(0x10, crypto.CommitmentLen),
		Salt:       salt, KDF: crypto.KDFParams{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4},
	}
	table := &format.SlotTable{Generation: 7, Slots: []*crypto.Slot{slot}}
	tableBytes, err := table.Marshal(keys.Header)
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, "slot table MAC", table.MAC, v.SlotTableMAC)
	checkHash(t, "slot table", tableBytes, v.SlotTableSHA256)

	seed := decode(t, v.RecipientSeed)
	priv, err := crypto.RecipientFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Wipe()
	public := priv.Public().Bytes()
	checkHex(t, "recipient public material", public, v.RecipientPublic)
	checkHash(t, "recipient public material", public, v.RecipientPublicHash)
	encoded, err := crypto.EncodeRecoveryKey(seed)
	if err != nil || encoded != v.RecoveryKey {
		t.Fatalf("recovery encoding = %q, %v; want %q", encoded, err, v.RecoveryKey)
	}

	frame := decode(t, v.ManifestFrame)
	checkHash(t, "manifest frame", frame, v.ManifestFrameHash)
	m, err := format.OpenManifest(frame, crypto.CipherXChaCha20Poly1305, keys.Manifest, uuid)
	if err != nil {
		t.Fatalf("known manifest frame no longer opens: %v", err)
	}
	if m.FormatVersion != 2 || m.Compression.Format != "none" || !m.IndexStored {
		t.Fatalf("unexpected known manifest: %+v", m)
	}

	coder, err := parity.NewCoder(parity.Plan{Data: 8, Parity: 2})
	if err != nil {
		t.Fatal(err)
	}
	gotParity, err := coder.Encode([][]byte{{0, 1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11}}, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	wantParity := make([][]byte, len(v.Parity))
	for i := range v.Parity {
		wantParity[i] = decode(t, v.Parity[i])
	}
	if !reflect.DeepEqual(gotParity, wantParity) {
		t.Fatalf("parity = %x, want %x", gotParity, wantParity)
	}

	writer, err := crypto.WriterFromSeed(decode(t, v.WriterSeed))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Wipe()
	checkHash(t, "writer public key", writer.Public().Bytes(), v.WriterPublicHash)
	checkHex(t, "writer fingerprint", writer.Fingerprint(), v.WriterFingerprint)
	signed := *sb
	if err := signed.SignWriter(writer.Deterministic()); err != nil {
		t.Fatal(err)
	}
	signed.Sign(keys.Header)
	checkHash(t, "writer signature", signed.Signature, v.SignatureSHA256)
	checkHash(t, "signed header", signed.Marshal(), v.SignedHeaderSHA256)

	// It verifies under the right key only, and not once a field it covers has
	// changed. (This header is a set of patterned values, not one a reader would
	// accept, so it is checked as built rather than parsed back.)
	if err := signed.VerifyWriter(writer.Public()); err != nil {
		t.Fatalf("the signed header does not verify: %v", err)
	}
	other, err := crypto.WriterFromSeed(sequence(0x61, crypto.WriterSeedLen))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Wipe()
	if signed.VerifyWriter(other.Public()) == nil {
		t.Error("the signature verified under another writer's key")
	}
	tampered := signed
	tampered.TailLength++
	if tampered.VerifyWriter(writer.Public()) == nil {
		t.Error("the signature still verified after the header changed")
	}
}

func sequence(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func decode(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func checkHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if encoded := hex.EncodeToString(got); encoded != want {
		t.Fatalf("%s = %s, want %s", name, encoded, want)
	}
}

func checkHash(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	sum := sha256.Sum256(got)
	checkHex(t, name+" SHA-256", sum[:], want)
}
