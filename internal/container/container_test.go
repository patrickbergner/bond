package container

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

// fastKDF keeps these tests quick; production parameters are slow on purpose.
var fastKDF = crypto.KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1}

const testPass = "open sesame"

func build(t *testing.T, payload []byte, opts Options) string {
	t.Helper()
	if opts.Keys == nil {
		opts.Keys = []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF, Label: "test"}}
	}
	path := filepath.Join(t.TempDir(), "test.bond")

	w, err := Create(path, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		w.Abort()
		t.Fatalf("Write: %v", err)
	}
	if err := w.Finish(&format.Manifest{TargetID: "test"}); err != nil {
		w.Abort()
		t.Fatalf("Finish: %v", err)
	}
	return path
}

func openUnlocked(t *testing.T, path string) *Reader {
	t.Helper()
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return r
}

func readAll(t *testing.T, r *Reader) []byte {
	t.Helper()
	s, err := r.Stream()
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("reading the stream: %v", err)
	}
	return got
}

func TestRoundTripSizes(t *testing.T) {
	// The sizes that break a shard-based layout: nothing, a fraction of a
	// shard, exactly one, one byte over, and several.
	const shard = 8192
	plainPerShard := int64(shard - crypto.TagLen)

	cases := []struct {
		name string
		size int64
	}{
		{"empty", 0},
		{"one byte", 1},
		{"part of a shard", plainPerShard / 3},
		{"one byte short of a shard", plainPerShard - 1},
		{"exactly one shard", plainPerShard},
		{"one byte over a shard", plainPerShard + 1},
		{"several shards", plainPerShard*3 + 17},
		{"exactly three shards", plainPerShard * 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			rand.Read(payload)

			path := build(t, payload, Options{ShardSize: shard})
			r := openUnlocked(t, path)

			if got := int64(r.Superblock().StreamLength); got != tc.size {
				t.Errorf("stream length = %d, want %d", got, tc.size)
			}
			wantShards := (tc.size + plainPerShard - 1) / plainPerShard
			if got := int64(r.Superblock().DataShardCount); got != wantShards {
				t.Errorf("shard count = %d, want %d", got, wantShards)
			}
			if got := readAll(t, r); !bytes.Equal(got, payload) {
				t.Errorf("payload came back as %d bytes, want %d", len(got), len(payload))
			}

			// Full shards except the last, which carries only what it holds.
			// Nothing is rounded up, so a small backup costs a small file.
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			sb := r.Superblock()
			var payloadBytes int64
			if wantShards > 0 {
				lastPlain := tc.size - (wantShards-1)*plainPerShard
				payloadBytes = (wantShards-1)*shard + lastPlain + crypto.TagLen
			}
			want := int64(format.PayloadOffset) + payloadBytes + 2*int64(sb.TailLength) + format.SuperblockSize
			if info.Size() != want {
				t.Errorf("file is %d bytes, want %d", info.Size(), want)
			}
			if wantShards > 0 && int64(sb.LastShardBytes) != tc.size-(wantShards-1)*plainPerShard+crypto.TagLen {
				t.Errorf("last shard is recorded as %d bytes", sb.LastShardBytes)
			}
		})
	}
}

func TestVerifyOnAHealthyContainer(t *testing.T) {
	payload := bytes.Repeat([]byte("verify me "), 5000)
	r := openUnlocked(t, build(t, payload, Options{ShardSize: 8192}))

	rep, err := r.Verify(nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Healthy() {
		t.Errorf("a freshly written container is not healthy: %+v", rep)
	}
	if len(rep.DamagedShards) != 0 {
		t.Errorf("damaged shards = %v, want none", rep.DamagedShards)
	}
}

func TestWrongKeyIsRefusedBeforeAnyPayloadWork(t *testing.T) {
	path := build(t, []byte("secret"), Options{ShardSize: 8192})
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	err = r.Unlock(crypto.Passphrase("not the passphrase"))
	if !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("Unlock with a wrong passphrase gave %v, want ErrWrongKey", err)
	}
	// The message should tell the operator what kind of key would work.
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error = %v, want it to describe the container's key slots", err)
	}
	if _, err := r.Stream(); err == nil {
		t.Error("a locked container handed out its payload")
	}
}

func TestUnlockKDFPolicyCanBeOverriddenExplicitly(t *testing.T) {
	path := build(t, []byte("policy"), Options{ShardSize: 8192})
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	strict := crypto.DefaultKDFPolicy
	strict.MaxMemoryKiB = fastKDF.MemoryKiB - 1
	derivations := 0
	options := UnlockOptions{KDFPolicy: strict, OnKDFDerivation: func(crypto.KDFParams) { derivations++ }}
	if err := r.UnlockWithOptions(options, crypto.Passphrase(testPass)); !errors.Is(err, crypto.ErrKDFPolicy) {
		t.Fatalf("strict policy error = %v, want ErrKDFPolicy", err)
	}
	if derivations != 0 {
		t.Fatalf("rejected KDF invoked Argon2 %d times", derivations)
	}
	strict.AllowExpensive = true
	options.KDFPolicy = strict
	if err := r.UnlockWithOptions(options, crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("explicit override: %v", err)
	}
	if derivations != 1 {
		t.Fatalf("override invoked Argon2 %d times, want once", derivations)
	}
}

func TestExpensivePassphraseSlotDoesNotBlockSafeKeyfile(t *testing.T) {
	keyfile := bytes.Repeat([]byte{7}, crypto.KeyLen)
	path := build(t, []byte("alternate"), Options{ShardSize: 8192, Keys: []KeySpec{
		{Secret: crypto.Passphrase(testPass), KDF: fastKDF},
		{Secret: crypto.KeyfileSecret(keyfile)},
	}})
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	strict := crypto.DefaultKDFPolicy
	strict.MaxMemoryKiB = fastKDF.MemoryKiB - 1
	if err := r.UnlockWithOptions(UnlockOptions{KDFPolicy: strict}, crypto.Passphrase(testPass), crypto.KeyfileSecret(keyfile)); err != nil {
		t.Fatalf("safe alternate slot was blocked: %v", err)
	}
}

func TestDuplicateSlotTablesDoNotMultiplyKDFWork(t *testing.T) {
	path := build(t, []byte("deduplicate"), Options{ShardSize: 8192})
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// One derivation is all the budget allows, so if the four header-copy ×
	// slot-table combinations each started their own, the wrong passphrase
	// would come back as a policy refusal instead of a wrong key.
	policy := crypto.DefaultKDFPolicy
	policy.MaxDerivations = 1
	derivations := 0
	options := UnlockOptions{KDFPolicy: policy, OnKDFDerivation: func(crypto.KDFParams) { derivations++ }}
	if err := r.UnlockWithOptions(options, crypto.Passphrase("wrong")); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("duplicate tables consumed the budget: %v", err)
	}
	if derivations != 1 {
		t.Fatalf("equivalent table/header attempts invoked Argon2 %d times, want once", derivations)
	}
}

func TestUnlockBudgetCapsDerivationCount(t *testing.T) {
	budget := &unlockBudget{policy: crypto.DefaultKDFPolicy}
	for i := range int(crypto.DefaultKDFPolicy.MaxDerivations) {
		if err := budget.admit(crypto.DefaultKDF); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if err := budget.admit(crypto.DefaultKDF); !errors.Is(err, crypto.ErrKDFPolicy) {
		t.Fatalf("derivation past the limit = %v, want ErrKDFPolicy", err)
	}
}

// The arithmetic the eight-slot round trip below is too cheap to exercise: with
// a test KDF profile any ceiling passes. The property that has to hold is that
// a container using BOND's own default profile in every slot the format allows
// is admitted in full, so no legitimate container is ever refused for asking
// too much in total.
func TestBudgetAdmitsAFullTableOfDefaultProfileSlots(t *testing.T) {
	const maxSlots = 32 // internal/format.maxSlots
	budget := &unlockBudget{policy: crypto.DefaultKDFPolicy}
	for i := range maxSlots {
		if err := budget.admit(crypto.DefaultKDF); err != nil {
			t.Fatalf("slot %d of a full default-profile table was refused: %v", i, err)
		}
	}
}

// The limit exists for hostile input and must never fire on a container BOND
// itself wrote. The format allows maxSlots slots; a container using more than a
// handful of them with the default profile is unusual but entirely legitimate,
// and the passphrase that opens it may well be the last one tried.
func TestManyDefaultPassphraseSlotsStillOpen(t *testing.T) {
	specs := make([]KeySpec, 0, 8)
	for i := range 8 {
		specs = append(specs, KeySpec{
			Secret: crypto.Passphrase(fmt.Sprintf("passphrase-%d", i)),
			KDF:    fastKDF,
			Label:  fmt.Sprintf("slot %d", i),
		})
	}
	path := build(t, []byte("many slots"), Options{ShardSize: 8192, Keys: specs})
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	derivations := 0
	options := UnlockOptions{
		KDFPolicy:       crypto.DefaultKDFPolicy,
		OnKDFDerivation: func(crypto.KDFParams) { derivations++ },
	}
	// The last slot: every earlier one is derived and rejected first.
	if err := r.UnlockWithOptions(options, crypto.Passphrase("passphrase-7")); err != nil {
		t.Fatalf("a container with eight default passphrase slots did not open: %v", err)
	}
	if derivations != len(specs) {
		t.Errorf("Argon2 ran %d times for %d slots", derivations, len(specs))
	}
}

func TestSeveralKeysOpenOneContainer(t *testing.T) {
	keyfile := make([]byte, crypto.KeyLen)
	rand.Read(keyfile)

	payload := []byte("two ways in")
	path := build(t, payload, Options{
		ShardSize: 8192,
		Keys: []KeySpec{
			{Secret: crypto.Passphrase(testPass), KDF: fastKDF, Label: "passphrase"},
			{Secret: crypto.KeyfileSecret(keyfile), Label: "usb stick"},
		},
	})

	for _, secret := range []crypto.Unlocker{
		crypto.Passphrase(testPass),
		crypto.KeyfileSecret(keyfile),
	} {
		r, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Unlock(secret); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		if got := readAll(t, r); !bytes.Equal(got, payload) {
			t.Error("the payload differs depending on which key opened it")
		}
		r.Close()
	}
}

// FlagUnencrypted records what was true when the container was written and no
// key change may rewrite it, because the superblock does not authenticate the
// slot tables. So it drifts, and a reader that refused the drift would take a
// container whose headers, slots, manifest and payload all authenticate and
// make it unopenable over an advisory bit.
func TestUnencryptedFlagMayDisagreeWithTheSlots(t *testing.T) {
	payload := []byte("the flag says NONE, the slots say otherwise")
	path := build(t, payload, Options{
		ShardSize:   8192,
		Unencrypted: true,
		Keys: []KeySpec{
			{Secret: crypto.PlaintextSecret{}, Label: "none"},
			{Secret: crypto.Passphrase(testPass), KDF: fastKDF, Label: "added later"},
		},
	})

	// What "bond keys add --new-passphrase" then "bond keys remove" once did:
	// the plaintext slot goes, the header keeps saying it is there.
	r := openUnlocked(t, path)
	remaining := []*crypto.Slot{}
	for _, slot := range r.Slots() {
		if slot.Type != crypto.SlotPlaintext {
			remaining = append(remaining, slot)
		}
	}
	if len(remaining) != 1 {
		t.Fatalf("expected one non-plaintext slot, got %d", len(remaining))
	}
	if err := UpdateSlots(path, r.Keys(), remaining); err != nil {
		t.Fatal(err)
	}
	r.Close()

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("a container whose advisory flag outlived its plaintext slot did not open: %v", err)
	}
	if again.HasPlaintextSlot() {
		t.Error("HasPlaintextSlot reported a slot that was removed")
	}
	if again.Superblock().Flags&format.FlagUnencrypted == 0 {
		t.Error("the test did not reproduce the disagreement: the flag is gone too")
	}
	if got := readAll(t, again); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back")
	}
}

func TestUnencryptedContainerOpensWithoutASecret(t *testing.T) {
	payload := []byte("no confidentiality, still authenticated")
	path := build(t, payload, Options{
		ShardSize:   8192,
		Unencrypted: true,
		Keys:        []KeySpec{{Secret: crypto.PlaintextSecret{}, Label: "none"}},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Superblock().Flags&format.FlagUnencrypted == 0 {
		t.Error("the container does not advertise that it is unencrypted")
	}
	if err := r.Unlock(crypto.PlaintextSecret{}); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got := readAll(t, r); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back")
	}

	// Authentication still applies, which is the whole reason for doing it
	// this way rather than writing the payload in the clear.
	corrupt(t, path, int64(format.PayloadOffset)+10, 1)
	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if err := r2.Unlock(crypto.PlaintextSecret{}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(mustStream(t, r2)); err == nil {
		t.Error("a flipped bit in an unencrypted container went unnoticed")
	}
}

func mustStream(t *testing.T, r *Reader) io.Reader {
	t.Helper()
	s, err := r.Stream()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// corrupt flips bits at an offset, standing in for the bit rot a
// non-trusted destination is expected to produce.
func corrupt(t *testing.T, path string, offset int64, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, offset); err != nil {
		t.Fatal(err)
	}
	for i := range buf {
		buf[i] ^= 0xff
	}
	if _, err := f.WriteAt(buf, offset); err != nil {
		t.Fatal(err)
	}
}

func TestDamagedShardIsReportedNotReturned(t *testing.T) {
	const shard = 8192
	payload := make([]byte, shard*4)
	rand.Read(payload)
	path := build(t, payload, Options{ShardSize: shard})

	// Damage the second shard.
	corrupt(t, path, int64(format.PayloadOffset)+shard+100, 4)

	r := openUnlocked(t, path)
	rep, err := r.Verify(nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Healthy() {
		t.Fatal("Verify called a damaged container healthy")
	}
	if len(rep.DamagedShards) != 1 || rep.DamagedShards[0] != 1 {
		t.Errorf("damaged shards = %v, want [1]", rep.DamagedShards)
	}

	// Reading must stop rather than hand on bytes that failed their tag.
	if _, err := io.ReadAll(mustStream(t, r)); err == nil {
		t.Error("the stream returned data from a shard that failed authentication")
	}
}

// A header field that is changed but still internally consistent is what the
// MAC is for: the structural checks cannot tell, and every offset in the header
// steers a later read.
//
// One tampered copy is survivable, because the other one is right there. Both
// tampered is not, and that is the line the MAC draws.
func TestTamperedHeaderIsRefused(t *testing.T) {
	payload := bytes.Repeat([]byte("tamper "), 2000)

	// The nonce prefix passes every bounds check, so nothing but the MAC
	// stands between this edit and a container that decrypts to nonsense.
	const noncePrefix = 88

	t.Run("one copy", func(t *testing.T) {
		path := build(t, payload, Options{ShardSize: 8192})
		corrupt(t, path, noncePrefix, 4)

		r, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer r.Close()
		if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
			t.Fatalf("a container with one altered header copy did not open: %v", err)
		}
		if !strings.Contains(r.HeaderSource(), "mirror") {
			t.Errorf("header source = %q, want the mirror", r.HeaderSource())
		}
		if got := readAll(t, r); !bytes.Equal(got, payload) {
			t.Error("the payload did not come back through the mirror")
		}
	})

	t.Run("both copies", func(t *testing.T) {
		path := build(t, payload, Options{ShardSize: 8192})
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		corrupt(t, path, noncePrefix, 4)
		corrupt(t, path, info.Size()-format.SuperblockSize+noncePrefix, 4)

		r, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer r.Close()
		err = r.Unlock(crypto.Passphrase(testPass))
		if err == nil {
			t.Fatal("a container with both header copies altered unlocked")
		}
		if !strings.Contains(err.Error(), "authentication") {
			t.Errorf("error = %v, want it to name the failed authentication", err)
		}
	})
}

// A header edit that breaks the structural checks is not fatal, because the
// mirror at the end of the file is still there.
func TestStructurallyBrokenHeaderFallsBackToTheMirror(t *testing.T) {
	payload := bytes.Repeat([]byte("fallback "), 2000)
	path := build(t, payload, Options{ShardSize: 8192})

	// Claim a stream far longer than the shards could hold.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xff, 0xff, 0xff, 0xff}, 56); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if !strings.Contains(r.HeaderSource(), "mirror") {
		t.Errorf("header source = %q, want the mirror", r.HeaderSource())
	}
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("Unlock through the mirror: %v", err)
	}
	if got := readAll(t, r); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back through the mirror")
	}
}

func TestMirrorHeaderCarriesADamagedContainer(t *testing.T) {
	payload := bytes.Repeat([]byte("mirror "), 2000)
	path := build(t, payload, Options{ShardSize: 8192})

	// Destroy the magic at the front so only the mirror is usable.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0}, 8), 0); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if !strings.Contains(r.HeaderSource(), "mirror") {
		t.Errorf("header source = %q, want the mirror to have been used", r.HeaderSource())
	}
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("Unlock through the mirror: %v", err)
	}
	if got := readAll(t, r); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back through the mirror header")
	}
}

func TestBothHeadersDestroyedFailsClearly(t *testing.T) {
	path := build(t, []byte("payload"), Options{ShardSize: 8192})
	info, _ := os.Stat(path)

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt(bytes.Repeat([]byte{0}, 8), 0)
	f.WriteAt(bytes.Repeat([]byte{0}, 8), info.Size()-format.SuperblockSize)
	f.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("a container with both headers destroyed opened anyway")
	}
}

func TestTruncatedContainerIsRefused(t *testing.T) {
	payload := make([]byte, 40000)
	rand.Read(payload)
	path := build(t, payload, Options{ShardSize: 8192})

	info, _ := os.Stat(path)
	if err := os.Truncate(path, info.Size()-1000); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		// Losing the mirror outright is an acceptable way to fail here.
		return
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(testPass)); err == nil {
		t.Error("a truncated container unlocked as if it were whole")
	}
}

// The key-slot table is written twice for the same reason the header is, and
// behaves the same way: one damaged copy is carried by the other, and only
// damage to both is fatal.
func TestAlteredSlotTableIsRefused(t *testing.T) {
	// The generation counter is the interesting byte: the wrapped key's own tag
	// does not cover it, but the table MAC does.
	const generation = 8

	t.Run("one table", func(t *testing.T) {
		path := build(t, []byte("payload"), Options{ShardSize: 8192})
		corrupt(t, path, format.SlotTableAOffset+generation, 1)

		r, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
			t.Fatalf("a container with one damaged key-slot table did not open: %v", err)
		}
		if len(r.Notices()) == 0 {
			t.Error("the container opened from the spare table without saying so")
		}
	})

	t.Run("both tables", func(t *testing.T) {
		path := build(t, []byte("payload"), Options{ShardSize: 8192})
		corrupt(t, path, format.SlotTableAOffset+generation, 1)
		corrupt(t, path, format.SlotTableBOffset+generation, 1)

		r, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := r.Unlock(crypto.Passphrase(testPass)); err == nil {
			t.Error("a container with both key-slot tables altered unlocked")
		}
	})
}

// A fresh container has to carry a usable spare table straight away. Reserving
// the space and leaving it blank until the first key change would mean the
// redundancy only starts protecting a backup after someone happens to rotate a
// key.
func TestSpareSlotTableIsUsableFromTheStart(t *testing.T) {
	path := build(t, []byte("payload"), Options{ShardSize: 8192})

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, format.SlotTableSize)
	if _, err := f.ReadAt(b, format.SlotTableBOffset); err != nil {
		t.Fatal(err)
	}
	f.Close()

	table, err := format.ParseSlotTable(b)
	if err != nil {
		t.Fatalf("the spare key-slot table does not parse: %v", err)
	}
	if len(table.Slots) == 0 {
		t.Error("the spare key-slot table holds no slots, so it could never open the container")
	}
}

func TestUpdateSlotsPreservesTheOnlyAuthenticTable(t *testing.T) {
	path := build(t, []byte("slots"), Options{ShardSize: 8192})
	r := openUnlocked(t, path)
	defer r.Close()

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	damaged := make([]byte, format.SlotTableSize)
	if _, err := f.ReadAt(damaged, format.SlotTableAOffset); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(damaged[8:], 1000) // parseable, but the old MAC is now wrong
	if _, err := f.WriteAt(damaged, format.SlotTableAOffset); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := UpdateSlots(path, r.Keys(), r.Slots()); err != nil {
		t.Fatalf("UpdateSlots overwrote or rejected the sole authentic table: %v", err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("updated container no longer opens: %v", err)
	}
}

func TestUpdateSlotsRejectsGenerationOverflow(t *testing.T) {
	path := build(t, []byte("slots"), Options{ShardSize: 8192})
	r := openUnlocked(t, path)
	defer r.Close()
	table := &format.SlotTable{Generation: math.MaxUint64, Slots: r.Slots()}
	encoded, err := table.Marshal(r.Keys().Header)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(encoded, format.SlotTableAOffset); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(encoded, format.SlotTableBOffset); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := UpdateSlots(path, r.Keys(), r.Slots()); err == nil {
		t.Fatal("generation overflow was accepted")
	}
}

func TestUpdateSlotsRejectsEqualGenerationConflict(t *testing.T) {
	path := build(t, []byte("slots"), Options{ShardSize: 8192})
	r := openUnlocked(t, path)
	defer r.Close()
	conflicting := append([]*crypto.Slot(nil), r.Slots()...)
	copySlot := *conflicting[0]
	copySlot.Label = "different but authentic"
	conflicting[0] = &copySlot
	table := &format.SlotTable{Generation: 1, Slots: conflicting}
	encoded, err := table.Marshal(r.Keys().Header)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(encoded, format.SlotTableBOffset); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if err := UpdateSlots(path, r.Keys(), r.Slots()); err == nil || !strings.Contains(err.Error(), "different contents") {
		t.Fatalf("equal-generation conflict error = %v", err)
	}
}

func TestManifestSurvivesOneDamagedCopy(t *testing.T) {
	payload := bytes.Repeat([]byte("manifest "), 3000)
	path := build(t, payload, Options{ShardSize: 8192})

	r := openUnlocked(t, path)
	tailOffset := int64(r.Superblock().TailOffset)
	r.Close()

	// Wreck the first copy; the second must carry the container.
	corrupt(t, path, tailOffset+20, 16)

	r2 := openUnlocked(t, path)
	if r2.Manifest().TargetID != "test" {
		t.Error("the manifest did not come back from its second copy")
	}
	if got := readAll(t, r2); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back")
	}
}

func TestPublishIsAtomic(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work", "new.bond")
	final := filepath.Join(dir, "out", "backup.bond")

	w, err := Create(work, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}}})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("hello"))

	// Nothing may appear at the destination before the container is complete.
	if _, err := os.Stat(final); err == nil {
		t.Fatal("the destination exists while the container is still being written")
	}
	if _, err := w.Publish(final); err == nil {
		t.Error("Publish succeeded on an unfinished container")
	}

	if err := w.Finish(&format.Manifest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Publish(final); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := os.Stat(work); err == nil {
		t.Error("the working file is still there after Publish")
	}
	published, err := Open(final)
	if err != nil {
		t.Fatalf("the published container does not open: %v", err)
	}
	published.Close()
}

func TestPublishNeverClobbersAnExistingNamespace(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work", "new.bond")
	final := filepath.Join(dir, "out", "backup.bond")
	w, err := Create(work, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	w.Write([]byte("new"))
	if err := w.Finish(&format.Manifest{}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(final, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Publish(final); err == nil {
		t.Fatal("Publish replaced an existing destination")
	}
	if got, _ := os.ReadFile(final); string(got) != "old" {
		t.Fatalf("existing destination changed to %q", got)
	}
}

func TestSplitPublishFailureRollsBackEveryMove(t *testing.T) {
	for failAt := 1; failAt <= 3; failAt++ {
		t.Run(fmt.Sprintf("move-%d", failAt), func(t *testing.T) {
			dir := t.TempDir()
			w := finishedSplitWriter(t, filepath.Join(dir, "work"))
			defer w.Abort()
			if len(w.vols.files) < 3 {
				t.Fatalf("test needs at least three volumes, got %d", len(w.vols.files))
			}
			final := filepath.Join(dir, "out", "backup.bond")
			originalMove := moveNoReplace
			calls := 0
			moveNoReplace = func(oldPath, newPath string) error {
				calls++
				if calls == failAt {
					return errors.New("injected move failure")
				}
				return originalMove(oldPath, newPath)
			}
			t.Cleanup(func() { moveNoReplace = originalMove })

			if _, err := w.Publish(final); err == nil {
				t.Fatal("Publish succeeded despite injected failure")
			}
			if _, err := os.Stat(final + ".001"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("leading commit volume exists after rollback: %v", err)
			}
			for _, staged := range w.vols.Paths() {
				if _, err := os.Stat(staged); err != nil {
					t.Errorf("staged volume was not restored: %s: %v", staged, err)
				}
			}
		})
	}
}

func TestSplitPublishMovesLeadingVolumeLast(t *testing.T) {
	dir := t.TempDir()
	w := finishedSplitWriter(t, filepath.Join(dir, "work"))
	defer w.Abort()
	final := filepath.Join(dir, "out", "backup.bond")
	originalMove := moveNoReplace
	var published []string
	moveNoReplace = func(oldPath, newPath string) error {
		if filepath.Dir(newPath) == filepath.Dir(final) {
			published = append(published, newPath)
		}
		return originalMove(oldPath, newPath)
	}
	t.Cleanup(func() { moveNoReplace = originalMove })
	if _, err := w.Publish(final); err != nil {
		t.Fatal(err)
	}
	if len(published) != len(w.vols.files) || published[len(published)-1] != final+".001" {
		t.Fatalf("publication order = %v; leading volume was not the commit point", published)
	}
}

func TestPublishNoClobberClosesNamespaceRace(t *testing.T) {
	dir := t.TempDir()
	w := finishedSplitWriter(t, filepath.Join(dir, "work"))
	defer w.Abort()
	final := filepath.Join(dir, "out", "backup.bond")
	originalMove := moveNoReplace
	var racedPath string
	moveNoReplace = func(oldPath, newPath string) error {
		if racedPath == "" {
			racedPath = newPath
			if err := os.WriteFile(newPath, []byte("racer"), 0o600); err != nil {
				return err
			}
		}
		return originalMove(oldPath, newPath)
	}
	t.Cleanup(func() { moveNoReplace = originalMove })
	if _, err := w.Publish(final); err == nil {
		t.Fatal("Publish won a no-clobber race by replacing the competing file")
	}
	if got, err := os.ReadFile(racedPath); err != nil || string(got) != "racer" {
		t.Fatalf("competing destination was modified: %q, %v", got, err)
	}
}

func TestPublicationRefusesCrossFilesystemPreflight(t *testing.T) {
	dir := t.TempDir()
	original := validateMoveFilesystem
	validateMoveFilesystem = func(string, string) error { return errors.New("injected cross-filesystem layout") }
	t.Cleanup(func() { validateMoveFilesystem = original })
	err := ValidatePublication(filepath.Join(dir, "work"), filepath.Join(dir, "out", "backup.bond"))
	if err == nil || !strings.Contains(err.Error(), "atomic moves") {
		t.Fatalf("ValidatePublication error = %v, want an atomic-move refusal", err)
	}
}

func TestPublicationRejectsEveryOccupiedOutputNamespace(t *testing.T) {
	for _, occupied := range []string{
		"backup.bond",
		"backup.bond.001",
		"backup.bond.1000",
		"backup.bond.sha384",
		"backup.bond.001.sha384",
	} {
		t.Run(occupied, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "out")
			if err := os.MkdirAll(out, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, occupied), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := ValidatePublication(filepath.Join(dir, "work"), filepath.Join(out, "backup.bond"))
			if err == nil {
				t.Fatalf("occupied namespace %q was accepted", occupied)
			}
			if got, readErr := os.ReadFile(filepath.Join(out, occupied)); readErr != nil || string(got) != "keep" {
				t.Fatalf("occupied path changed: %q, %v", got, readErr)
			}
		})
	}
}

// The namespace test has to be the same one VolumeFiles uses, or publication
// refuses names that could never be read back as part of this set.
func TestPublicationIgnoresNeighboursThatAreNotThisSet(t *testing.T) {
	for _, neighbour := range []string{
		"backup.bond.old.001", // belongs to backup.bond.old
		"backup.bond.log",
		"backup.bond.old.001.sha256",
		"backup.bondage.001",
		"other.bond.001",
	} {
		t.Run(neighbour, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "out")
			if err := os.MkdirAll(out, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, neighbour), []byte("unrelated"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidatePublication(filepath.Join(dir, "work"), filepath.Join(out, "backup.bond")); err != nil {
				t.Fatalf("an unrelated neighbour blocked publication: %v", err)
			}
		})
	}
}

// workPath and outputPath may name one directory, and the same-filesystem rule
// makes that a natural thing to configure. The writer's own split staging files
// end in a volume suffix, so a recheck that did not know they were its own
// refused the publication it was about to perform – after the whole backup had
// been written.
func TestSplitPublishSucceedsWhenStagingSharesTheOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "backup.bond")

	// backup.Create's staging name, verbatim: the destination's base name plus
	// ".partial". Split, that is backup.bond.partial.001 sitting in the very
	// directory whose namespace is being claimed.
	w, err := Create(final+".partial", Options{
		ShardSize:      8192,
		MaxVolumeBytes: 200 << 10,
		Keys:           []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	if _, err := w.Write(bytes.Repeat([]byte("staging beside the output"), 16<<10)); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(&format.Manifest{}); err != nil {
		t.Fatal(err)
	}
	if len(w.vols.files) < 2 {
		t.Fatalf("test needs a split set, got %d volumes", len(w.vols.files))
	}

	published, err := w.Publish(final)
	if err != nil {
		t.Fatalf("publishing into the staging directory: %v", err)
	}
	for _, p := range published {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was not published: %v", p, err)
		}
	}
}

func TestOccupiedNamespaceErrorNamesEveryFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"backup.bond.001", "backup.bond.002", "backup.bond.001.sha384"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := ValidatePublication(filepath.Join(dir, "work"), filepath.Join(out, "backup.bond"))
	if err == nil {
		t.Fatal("an occupied namespace was accepted")
	}
	for _, name := range []string{"backup.bond.001", "backup.bond.002", "backup.bond.001.sha384"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %s, so the operator cannot act on it: %v", name, err)
		}
	}
}

func finishedSplitWriter(t *testing.T, workDir string) *Writer {
	t.Helper()
	w, err := Create(filepath.Join(workDir, "new.bond"), Options{
		ShardSize:      8192,
		MaxVolumeBytes: 200 << 10,
		Keys:           []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("split publication"), 16<<10)); err != nil {
		w.Abort()
		t.Fatal(err)
	}
	if err := w.Finish(&format.Manifest{}); err != nil {
		w.Abort()
		t.Fatal(err)
	}
	return w
}

func TestAbortLeavesNothingBehind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aborted.bond")
	w, err := Create(path, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}}})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("half a backup"))
	w.Abort()

	if _, err := os.Stat(path); err == nil {
		t.Error("Abort left the partial container on disk")
	}
}

func TestWriterAuthenticatedReadbackCoversEveryMetadataCopy(t *testing.T) {
	tests := map[string]func(*Writer, string) int64{
		"leading header":    func(_ *Writer, _ string) int64 { return 300 },
		"header commitment": func(_ *Writer, _ string) int64 { return 176 },
		"mirror header": func(_ *Writer, path string) int64 {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			return info.Size() - format.SuperblockSize + 300
		},
		"slot table A": func(_ *Writer, _ string) int64 { return format.SlotTableAOffset + format.SlotTableSize - 1 },
		"slot table B": func(_ *Writer, _ string) int64 { return format.SlotTableBOffset + format.SlotTableSize - 1 },
		"manifest A":   func(w *Writer, _ string) int64 { return int64(w.sb.TailOffset) + 20 },
		"manifest B": func(w *Writer, _ string) int64 {
			return int64(w.sb.TailOffset + w.sb.TailLength + 20)
		},
	}
	for name, offset := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "readback.bond")
			w, err := Create(path, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}}})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Destroy()
			if _, err := w.Write([]byte("authenticated writer readback")); err != nil {
				t.Fatal(err)
			}
			if err := w.Finish(&format.Manifest{}); err != nil {
				t.Fatal(err)
			}
			corrupt(t, path, offset(w, path), 1)
			if err := w.Validate(path); err == nil {
				t.Fatal("writer readback accepted damaged metadata")
			}
		})
	}
}

func TestRecipientOnlyWriterReadbackIsAuthenticated(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5a}, crypto.SeedLen)
	priv, err := crypto.RecipientFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Wipe()
	path := filepath.Join(t.TempDir(), "recipient.bond")
	w, err := Create(path, Options{ShardSize: 8192, Keys: []KeySpec{{Recipient: priv.Public(), Label: "fixture recipient"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if _, err := w.Write([]byte("recipient-only")); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(&format.Manifest{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Validate(path); err != nil {
		t.Fatalf("recipient-only writer readback failed: %v", err)
	}
}

func TestWriterDestroyWipesKeysAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "destroy.bond")
	w, err := Create(path, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}}})
	if err != nil {
		t.Fatal(err)
	}
	keys := w.keys
	w.Destroy()
	w.Destroy()
	for name, material := range map[string][]byte{
		"FMK": keys.FMK(), "data": keys.Data, "header": keys.Header, "manifest": keys.Manifest, "commit": keys.Commit,
	} {
		if !bytes.Equal(material, make([]byte, len(material))) {
			t.Errorf("%s was not wiped", name)
		}
	}
}

func TestNotAContainer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "random.bin")
	junk := make([]byte, format.PayloadOffset+format.SuperblockSize)
	rand.Read(junk)
	if err := os.WriteFile(path, junk, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, format.ErrNotContainer) {
		t.Errorf("Open on random bytes gave %v, want ErrNotContainer", err)
	}
}
