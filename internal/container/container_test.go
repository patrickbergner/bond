package container

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
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
