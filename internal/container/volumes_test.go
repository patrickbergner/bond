package container

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

// buildSplit writes a container across several files and returns the base path
// it was published under, plus the payload it should hold.
func buildSplit(t *testing.T, payloadSize int, maxVolume int64, recovery int) (string, []byte) {
	t.Helper()

	payload := make([]byte, payloadSize)
	rand.Read(payload)

	dir := t.TempDir()
	work := filepath.Join(dir, "work.bond")
	w, err := Create(work, Options{
		ShardSize:       64 << 10,
		MaxVolumeBytes:  maxVolume,
		RecoveryPercent: recovery,
		Keys:            []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		w.Abort()
		t.Fatal(err)
	}
	if err := w.Finish(&format.Manifest{TargetID: "split"}); err != nil {
		w.Abort()
		t.Fatal(err)
	}

	final := filepath.Join(dir, "out", "backup.bond")
	if _, err := w.Publish(final); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return final, payload
}

func TestSplitAcrossVolumes(t *testing.T) {
	// A limit that forces several volumes, with the head and tail reserve
	// taken into account by the writer itself.
	const limit = format.PayloadOffset + (600 << 10)
	base, payload := buildSplit(t, 3<<20, limit, 0)

	// The files are numbered, and the unnumbered name does not exist.
	if _, err := os.Stat(base); err == nil {
		t.Error("a split container also wrote the unnumbered name")
	}
	var found int
	for i := range 20 {
		if _, err := os.Stat(base + VolumeSuffix(i)); err == nil {
			found++
		}
	}
	if found < 3 {
		t.Fatalf("the container is in %d volumes; the limit should have forced more", found)
	}
	t.Logf("3 MiB payload written to %d volumes", found)

	// Opening by the base name finds the set.
	r, err := Open(base)
	if err != nil {
		t.Fatalf("Open by base name: %v", err)
	}
	defer r.Close()
	if r.Volumes() != found {
		t.Errorf("Open found %d volumes, want %d", r.Volumes(), found)
	}
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got := readAll(t, r); !bytes.Equal(got, payload) {
		t.Error("the payload did not survive being split")
	}
}

// Whichever volume is at hand should be enough to find the rest: someone
// restoring may well reach for the last file they downloaded.
func TestOpenFromAnyVolume(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, payload := buildSplit(t, 2<<20, limit, 0)

	count := 0
	for i := range 20 {
		if _, err := os.Stat(base + VolumeSuffix(i)); err == nil {
			count++
		}
	}
	if count < 3 {
		t.Fatalf("expected several volumes, got %d", count)
	}

	for i := range count {
		r, err := Open(base + VolumeSuffix(i))
		if err != nil {
			t.Fatalf("opening volume %d: %v", i+1, err)
		}
		if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
			r.Close()
			t.Fatalf("volume %d: Unlock: %v", i+1, err)
		}
		if got := readAll(t, r); !bytes.Equal(got, payload) {
			t.Errorf("volume %d: the payload came back wrong", i+1)
		}
		r.Close()
	}
}

func TestMissingVolumeIsReportedClearly(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, _ := buildSplit(t, 2<<20, limit, 0)

	// Take away the second file, as a half-finished download would.
	if err := os.Remove(base + VolumeSuffix(1)); err != nil {
		t.Fatal(err)
	}

	_, err := Open(base)
	if err == nil {
		t.Fatal("Open succeeded with a volume missing")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error = %v, want it to name the missing volume", err)
	}
	if !strings.Contains(err.Error(), "002") {
		t.Errorf("error = %v, want it to say which volume is gone", err)
	}
}

func TestVolumesFromDifferentContainersAreRefused(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	a, _ := buildSplit(t, 2<<20, limit, 0)
	b, _ := buildSplit(t, 2<<20, limit, 0)

	// Swap a volume from the other container in. The header MAC would catch
	// it later, but it should not even get that far: the set does not describe
	// one contiguous payload.
	stolen, err := os.ReadFile(b + VolumeSuffix(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a+VolumeSuffix(1), stolen, 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := Open(a)
	if err != nil {
		return // refused at open time, which is the better outcome
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(testPass)); err == nil {
		t.Error("a container built from two different sets unlocked")
	}
}

// Splitting must not change what a container is: the same payload, the same
// parity, the same guarantees.
func TestSplitContainerRepairs(t *testing.T) {
	const limit = format.PayloadOffset + (500 << 10)
	base, payload := buildSplit(t, 3<<20, limit, 10)

	probe, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	sb := probe.Superblock()
	volumes := probe.Volumes()
	probe.Close()
	if volumes < 2 {
		t.Fatalf("expected a split container, got %d volume", volumes)
	}

	// Damage one shard in the first volume and one in a later one.
	l := sb.Layout()
	if l.DataShards < 4 {
		t.Fatalf("not enough shards to place damage: %d", l.DataShards)
	}
	damageInVolume(t, base, sb, 1)
	damageInVolume(t, base, sb, l.DataShards-1)

	r, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	report, err := r.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Damaged() {
		t.Fatal("the damage was not noticed")
	}
	if !report.Repairable {
		t.Fatalf("damage spread over volumes was called unrepairable: %+v", report)
	}

	repaired := filepath.Join(t.TempDir(), "repaired.bond")
	if _, err := Repair(r, repaired, report, nil); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	fixed, err := Open(repaired)
	if err != nil {
		t.Fatalf("the repaired set does not open: %v", err)
	}
	defer fixed.Close()
	if fixed.Volumes() != volumes {
		t.Errorf("the repaired container has %d volumes, want %d", fixed.Volumes(), volumes)
	}
	if err := fixed.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	after, err := fixed.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Healthy() {
		t.Errorf("the repaired split container is still damaged: %+v", after)
	}
	if got := readAll(t, fixed); !bytes.Equal(got, payload) {
		t.Error("the repaired payload is not what was backed up")
	}
}

// damageInVolume wrecks one data shard, finding the volume it landed in.
func damageInVolume(t *testing.T, base string, sb *format.Superblock, index uint64) {
	t.Helper()
	l := sb.Layout()
	logical := int64(l.DataOffset(index))

	// Walk the volumes to find the one holding this offset.
	var start int64
	for i := range int(sb.VolumeCount) {
		path := base + VolumeSuffix(i)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := f.Stat()
		scan, err := readSuperblocks(f, info.Size())
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		length := int64(scan.copies[0].sb.VolumeLogicalLen)
		if logical >= start && logical < start+length {
			payloadStart := int64(format.SuperblockSize)
			if i == 0 {
				payloadStart = format.PayloadOffset
			}
			corrupt(t, path, payloadStart+(logical-start), int(min(uint32(64), l.DataLen(index))))
			return
		}
		start += length
	}
	t.Fatalf("shard %d was not found in any volume", index)
}

// A last volume holding nothing but the short final shard is the case that made
// every header copy in a set unparseable: the tail offset is a position in that
// volume, a few kilobytes in, and the header check demanded it be past the
// 132 KiB head that only volume 1 has. The writer reported success and no tool
// could open what it wrote.
func TestSplitWithATinyFinalVolume(t *testing.T) {
	const shard = 64 << 10
	// One shard of payload per volume, so the remainder lands alone in the last.
	const limit = format.PayloadOffset + format.SuperblockSize + shard
	base, payload := buildSplit(t, 2*(shard-crypto.TagLen)+100, limit, 0)

	r, err := Open(base)
	if err != nil {
		t.Fatalf("a container whose last volume holds one short shard did not open: %v", err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if r.Volumes() != 3 {
		t.Errorf("volumes = %d, want 3", r.Volumes())
	}
	if got := readAll(t, r); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back")
	}

	// The point of the test is that the last volume is smaller than the head of
	// the first one; if it is not, the case being guarded has not been built.
	last := base + VolumeSuffix(r.Volumes()-1)
	info, err := os.Stat(last)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() >= format.PayloadOffset {
		t.Errorf("the last volume is %d bytes, which does not exercise a short one", info.Size())
	}
}

// One flipped bit in a middle volume's header used to lose the whole set: every
// entry point re-reads volume 1, and no volume but the last carried a spare
// copy of its own header. Each of these fields is fatal in a different place –
// the geometry check at open, the volume-agreement check, and the MAC.
func TestSplitSurvivesADamagedVolumeHeader(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)

	for _, tc := range []struct {
		name string
		at   int64
	}{
		{"magic", 0},
		{"volume index", 152},
		{"payload length", 168},
		{"nonce prefix", 88},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, payload := buildSplit(t, 2<<20, limit, 0)
			corrupt(t, base+VolumeSuffix(1), tc.at, 4)

			r, err := Open(base)
			if err != nil {
				t.Fatalf("the set did not open from the mirrored header: %v", err)
			}
			defer r.Close()
			if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			if got := readAll(t, r); !bytes.Equal(got, payload) {
				t.Error("the payload did not come back through the mirror")
			}
			if len(r.Notices()) == 0 {
				t.Error("the set opened on a spare header copy without saying so")
			}
		})
	}
}

func TestVolumeLimitTooSmall(t *testing.T) {
	dir := t.TempDir()
	_, err := Create(filepath.Join(dir, "x.bond"), Options{
		ShardSize:      64 << 10,
		MaxVolumeBytes: 1000,
		Keys:           []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}},
	})
	if err == nil {
		t.Fatal("a volume limit smaller than the header was accepted")
	}
	if !strings.Contains(err.Error(), "no room for payload") {
		t.Errorf("error = %v, want it to explain the limit", err)
	}
}

// A container that fits in one volume still works when splitting was asked
// for; it is simply a set of one.
func TestSplitThatFitsInOneVolume(t *testing.T) {
	base, payload := buildSplit(t, 100<<10, 64<<20, 0)

	if _, err := os.Stat(base + VolumeSuffix(0)); err != nil {
		t.Fatalf("the single volume is not numbered: %v", err)
	}
	r, err := Open(base)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if r.Volumes() != 1 {
		t.Errorf("volumes = %d, want 1", r.Volumes())
	}
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, r); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back")
	}
}

// Every volume must be identifiable on its own, and must agree with the rest
// about how many there are.
func TestEveryVolumeCarriesAHeader(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, _ := buildSplit(t, 2<<20, limit, 0)

	for i := range 20 {
		path := base + VolumeSuffix(i)
		f, err := os.Open(path)
		if err != nil {
			break
		}
		info, _ := f.Stat()
		scan, err := readSuperblocks(f, info.Size())
		f.Close()
		if err != nil {
			t.Fatalf("volume %d has no readable header: %v", i+1, err)
		}
		if sb := scan.copies[0].sb; int(sb.VolumeIndex) != i {
			t.Errorf("volume %d says it is number %d", i+1, sb.VolumeIndex+1)
		}
		// Every volume closes with a mirror of its own header, so no single
		// file of a set is one flipped bit from being unopenable.
		if !scan.twin {
			t.Errorf("volume %d does not carry a mirrored copy of its header", i+1)
		}
	}
}

// The corruption matrix claims a truncated volume is refused. Nothing tested it:
// the truncation tests all ran on single-file containers.
func TestTruncatedVolumeIsRefused(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, _ := buildSplit(t, 2<<20, limit, 0)

	victim := base + VolumeSuffix(1)
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(victim, info.Size()/2); err != nil {
		t.Fatal(err)
	}

	r, err := Open(base)
	if err == nil {
		err = r.Unlock(crypto.Passphrase(testPass))
		if err == nil {
			_, err = io.ReadAll(mustStream(t, r))
		}
		r.Close()
	}
	if err == nil {
		t.Fatal("a set with a truncated volume was read as though it were whole")
	}
}

// A volume carrying a forged header is the case the per-volume MAC exists for:
// the container UUID check at open catches a file from another backup, but only
// the MAC catches one built to look like a member of this set.
func TestVolumeWithAForgedHeaderIsRefused(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, _ := buildSplit(t, 2<<20, limit, 0)

	// Re-sign nothing: just edit a field the MAC covers, in both copies, so the
	// volume is structurally perfect and cryptographically wrong.
	victim := base + VolumeSuffix(1)
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	corrupt(t, victim, 88, 4)                                   // nonce prefix, leading copy
	corrupt(t, victim, info.Size()-format.SuperblockSize+88, 4) // and its mirror

	r, err := Open(base)
	if err == nil {
		err = r.Unlock(crypto.Passphrase(testPass))
		r.Close()
	}
	if err == nil {
		t.Fatal("a volume whose header fails its MAC was accepted into the set")
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Errorf("error = %v, want it to say the header failed authentication", err)
	}
}

// The key slots live in the first volume, and every slot wraps the same master
// key, so a key change is 64 KiB of writing whatever the container is stored in.
// The proof that the payload was untouched has to cover every volume of it.
func TestKeyChangeOnASplitContainerLeavesThePayloadAlone(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, payload := buildSplit(t, 2<<20, limit, 0)

	r, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	if r.Volumes() < 2 {
		t.Fatalf("expected a split container, got %d volume", r.Volumes())
	}

	before, err := PayloadDigest(r.Paths())
	if err != nil {
		t.Fatal(err)
	}

	extra, err := crypto.NewSlot(r.Superblock().Cipher, r.Superblock().ContainerUUID,
		r.Keys().FMK(), crypto.KeyfileSecret(make([]byte, crypto.KeyLen)), crypto.KDFParams{}, "spare")
	if err != nil {
		t.Fatal(err)
	}
	if err := UpdateSlots(r.Paths()[0], r.Keys(), append(append([]*crypto.Slot(nil), r.Slots()...), extra)); err != nil {
		t.Fatalf("UpdateSlots on a split container: %v", err)
	}
	r.Close()

	// Re-open and prove both the new key works and nothing else moved.
	again, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.Unlock(crypto.KeyfileSecret(make([]byte, crypto.KeyLen))); err != nil {
		t.Fatalf("the slot added to a split container does not open it: %v", err)
	}
	nowDigest, err := PayloadDigest(again.Paths())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, nowDigest) {
		t.Error("a key change rewrote payload in a split container")
	}
	if got := readAll(t, again); !bytes.Equal(got, payload) {
		t.Error("the payload did not survive a key change")
	}
}

// Naming a later volume should say so, rather than reading payload at the slot
// table offsets and complaining about a missing magic number.
func TestKeyChangeAgainstTheWrongVolumeSaysSo(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, _ := buildSplit(t, 2<<20, limit, 0)

	r := openUnlockedSplit(t, base)
	err := UpdateSlots(base+VolumeSuffix(1), r.Keys(), r.Slots())
	if err == nil {
		t.Fatal("the key slots were written to a volume that does not have any")
	}
	if !strings.Contains(err.Error(), "001") {
		t.Errorf("error = %v, want it to name the volume to use instead", err)
	}
}

func openUnlockedSplit(t *testing.T, base string) *Reader {
	t.Helper()
	r, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	return r
}

// Format 1.0 requires every volume to carry a mirror. Losing one is reported
// as degraded metadata and repair appends the exact authenticated header again.
func TestRepairRestoresRequiredMirrors(t *testing.T) {
	const limit = format.PayloadOffset + (400 << 10)
	base, payload := buildSplit(t, 2<<20, limit, 20)

	probe, err := Open(base)
	if err != nil {
		t.Fatal(err)
	}
	volumes := probe.Volumes()
	probe.Close()
	if volumes < 3 {
		t.Fatalf("expected several volumes, got %d", volumes)
	}

	// Cut the required mirror off the first, every middle and the last volume.
	for i := 0; i < volumes; i++ {
		path := base + VolumeSuffix(i)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, info.Size()-format.SuperblockSize); err != nil {
			t.Fatal(err)
		}
	}

	r, err := Open(base)
	if err != nil {
		t.Fatalf("a container with degraded mirrors did not open: %v", err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	if n := r.Notices(); len(n) != volumes {
		t.Errorf("reported %d missing mirrors, want %d: %v", len(n), volumes, n)
	}

	// Heal the metadata and prove the mirrors are appended without eating payload.
	fixed := filepath.Join(t.TempDir(), "fixed.bond")
	out, err := copySet(r.vols, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.healMetadata(r); err != nil {
		out.Close()
		t.Fatalf("healMetadata: %v", err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		t.Fatal(err)
	}
	out.Close()

	again, err := Open(fixed)
	if err != nil {
		t.Fatalf("the healed container does not open: %v", err)
	}
	defer again.Close()
	if err := again.Unlock(crypto.Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	if len(again.Notices()) != 0 {
		t.Errorf("healed container is still degraded: %v", again.Notices())
	}
	if got := readAll(t, again); !bytes.Equal(got, payload) {
		t.Error("healing the headers of an older container destroyed payload")
	}
}
