package format_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
)

type v1Vectors struct {
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

func TestFormatV1KnownAnswerVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v v1Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
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
	params := []byte{0, 0, 1, 0, 3, 0, 0, 0, 4, 0, 0, 0}
	checkHex(t, "shard nonce", crypto.ShardNonce(noncePrefix, 0x0102030405060708), v.ShardNonce)
	checkHex(t, "shard AAD", crypto.ShardAAD(uuid, 0x0102030405060708, 4096), v.ShardAAD)
	checkHex(t, "slot AAD", crypto.SlotAAD(uuid, slotUUID, uint8(crypto.SlotPassphrase), params), v.SlotAAD)
	checkHex(t, "manifest AAD", crypto.ManifestAAD(uuid), v.ManifestAAD)

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
		Salt: sequence(0xd0, 16), KDF: crypto.KDFParams{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4},
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
	if m.FormatVersion != 1 || m.Compression.Format != "none" || !m.IndexStored {
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
