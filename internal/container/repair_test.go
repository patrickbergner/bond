package container

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
)

// buildWithParity writes a container carrying recovery data and returns its
// path along with the payload it should hold.
func buildWithParity(t *testing.T, shards int, percent int) (string, []byte) {
	t.Helper()
	const shard = 8192
	plainPerShard := shard - crypto.TagLen

	payload := make([]byte, shards*plainPerShard)
	rand.Read(payload)

	path := filepath.Join(t.TempDir(), "test.bond")
	w, err := Create(path, Options{
		ShardSize:       shard,
		RecoveryPercent: percent,
		Keys:            []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		w.Abort()
		t.Fatal(err)
	}
	if err := w.Finish(&format.Manifest{TargetID: "parity"}); err != nil {
		w.Abort()
		t.Fatal(err)
	}
	return path, payload
}

// wreckData destroys one shard by overwriting part of it, which is what a lost
// storage range looks like. The damage stays strictly inside the shard –
// running past its end would hit whatever comes next and quietly test
// something else.
func wreckData(t *testing.T, path string, sb *format.Superblock, index uint64) {
	t.Helper()
	l := sb.Layout()
	off := int64(format.PayloadOffset + l.DataOffset(index))
	corrupt(t, path, off, damageLen(l.DataLen(index)))
}

func wreckParity(t *testing.T, path string, sb *format.Superblock, stripe, q int) {
	t.Helper()
	l := sb.Layout()
	off := int64(format.PayloadOffset + l.ParityOffset(stripe, q))
	corrupt(t, path, off, damageLen(uint32(l.ParitySlot(stripe))))
}

func damageLen(shard uint32) int {
	return int(min(shard, 64))
}

func TestParityIsWritten(t *testing.T) {
	path, _ := buildWithParity(t, 25, 10)
	r := openUnlocked(t, path)

	sb := r.Superblock()
	if sb.Parity != format.ParityRS {
		t.Fatalf("parity scheme = %v, want Reed-Solomon", sb.Parity)
	}
	plan := sb.Plan()
	if plan.Data != 20 || plan.Parity != 2 {
		t.Errorf("stripe geometry = %d+%d, want 20+2 for 10%%", plan.Data, plan.Parity)
	}

	l := sb.Layout()
	if l.Stripes() != 2 {
		t.Errorf("stripes = %d, want 2 for 25 shards of 20", l.Stripes())
	}
	// 20 data + 2 parity, then 5 data + 2 parity.
	if got := l.ParityShardCount(); got != 4 {
		t.Errorf("parity shards = %d, want 4", got)
	}

	report, err := r.Verify(nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.Healthy() {
		t.Errorf("a fresh container with parity is not healthy: %+v", report)
	}
	if report.ParityShards != 4 {
		t.Errorf("report counts %d parity shards, want 4", report.ParityShards)
	}
}

// The percentage is of the payload, not of the file: the fixed 132 KiB head
// and the manifest are not what recovery data protects against losing.
func TestParityOverheadIsCloseToWhatWasAsked(t *testing.T) {
	for _, percent := range []int{10, 20, 30} {
		withParity, _ := buildWithParity(t, 40, percent)
		withNone, _ := buildWithParity(t, 40, 0)

		a, err := Open(withParity)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Open(withNone)
		if err != nil {
			t.Fatal(err)
		}
		payload := int64(b.Superblock().PayloadBytes())
		extra := float64(int64(a.Superblock().PayloadBytes())-payload) / float64(payload) * 100
		a.Close()
		b.Close()

		if extra < float64(percent)*0.9 || extra > float64(percent)*1.2 {
			t.Errorf("%d%% recovery added %.1f%% to the payload", percent, extra)
		}
	}
}

// The heart of phase 4: damage up to the recovery capacity is repaired, and
// the repaired container is byte-for-byte what it was.
func TestRepairRebuildsDamagedShards(t *testing.T) {
	cases := []struct {
		name    string
		shards  int
		percent int
		damage  func(t *testing.T, path string, sb *format.Superblock)
	}{
		{
			name: "one data shard", shards: 25, percent: 10,
			damage: func(t *testing.T, p string, sb *format.Superblock) { wreckData(t, p, sb, 3) },
		},
		{
			name: "two data shards in one stripe", shards: 25, percent: 10,
			damage: func(t *testing.T, p string, sb *format.Superblock) {
				wreckData(t, p, sb, 3)
				wreckData(t, p, sb, 11)
			},
		},
		{
			name: "one shard in each stripe", shards: 25, percent: 10,
			damage: func(t *testing.T, p string, sb *format.Superblock) {
				wreckData(t, p, sb, 5)
				wreckData(t, p, sb, 22)
			},
		},
		{
			name: "the short final shard", shards: 25, percent: 10,
			damage: func(t *testing.T, p string, sb *format.Superblock) {
				wreckData(t, p, sb, sb.DataShardCount-1)
			},
		},
		{
			name: "the first shard", shards: 21, percent: 10,
			damage: func(t *testing.T, p string, sb *format.Superblock) { wreckData(t, p, sb, 0) },
		},
		{
			name: "a parity shard", shards: 25, percent: 10,
			damage: func(t *testing.T, p string, sb *format.Superblock) { wreckParity(t, p, sb, 0, 1) },
		},
		{
			name: "one data and one parity shard in a stripe", shards: 25, percent: 10,
			damage: func(t *testing.T, p string, sb *format.Superblock) {
				wreckData(t, p, sb, 7)
				wreckParity(t, p, sb, 0, 0)
			},
		},
		{
			name: "three shards with 30% recovery", shards: 25, percent: 30,
			damage: func(t *testing.T, p string, sb *format.Superblock) {
				wreckData(t, p, sb, 1)
				wreckData(t, p, sb, 2)
				wreckData(t, p, sb, 3)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, payload := buildWithParity(t, tc.shards, tc.percent)

			// The header has to be read before the damage, to know the layout.
			probe, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			sb := probe.Superblock()
			probe.Close()

			tc.damage(t, path, sb)

			r := openUnlocked(t, path)
			report, err := r.Verify(nil)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !report.Damaged() {
				t.Fatal("Verify found nothing wrong with a damaged container")
			}
			if !report.Repairable {
				t.Fatalf("damage within capacity was called unrepairable: %+v", report)
			}

			repaired := filepath.Join(t.TempDir(), "repaired.bond")
			result, err := Repair(r, repaired, report, nil)
			if err != nil {
				t.Fatalf("Repair: %v", err)
			}
			if result.Repaired() == 0 {
				t.Error("Repair rebuilt nothing")
			}

			// The repaired container must be whole, and its payload must be
			// exactly what went in.
			fixed, err := Open(repaired)
			if err != nil {
				t.Fatal(err)
			}
			defer fixed.Close()
			if err := fixed.Unlock(crypto.Passphrase(testPass)); err != nil {
				t.Fatalf("the repaired container does not unlock: %v", err)
			}
			after, err := fixed.Verify(nil)
			if err != nil {
				t.Fatal(err)
			}
			if !after.Healthy() {
				t.Errorf("the repaired container is still damaged: %+v", after)
			}
			if got := readAll(t, fixed); !bytes.Equal(got, payload) {
				t.Error("the repaired payload is not what was backed up")
			}
		})
	}
}

// Beyond the recovery capacity, a repair must refuse rather than produce
// plausible-looking rubbish.
func TestRepairRefusesDamageBeyondCapacity(t *testing.T) {
	path, _ := buildWithParity(t, 25, 10)

	probe, _ := Open(path)
	sb := probe.Superblock()
	probe.Close()

	// Three losses in one stripe, protected by two parity shards.
	wreckData(t, path, sb, 1)
	wreckData(t, path, sb, 2)
	wreckData(t, path, sb, 3)

	r := openUnlocked(t, path)
	report, err := r.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Repairable {
		t.Fatal("three losses in a stripe with two parity shards were called repairable")
	}
	if len(report.Unrepairable) != 1 || report.Unrepairable[0] != 0 {
		t.Errorf("unrepairable stripes = %v, want [0]", report.Unrepairable)
	}

	dst := filepath.Join(t.TempDir(), "attempt.bond")
	if _, err := Repair(r, dst, report, nil); err == nil {
		t.Fatal("Repair claimed to rebuild more than the parity covers")
	} else if !strings.Contains(err.Error(), "beyond what the recovery data covers") {
		t.Errorf("error = %v, want it to explain the limit", err)
	}
}

// Losses spread across stripes are repairable even when there are more of them
// than any single stripe's parity, because the capacity is per stripe.
func TestRepairCapacityIsPerStripe(t *testing.T) {
	path, payload := buildWithParity(t, 60, 10) // 3 stripes of 20

	probe, _ := Open(path)
	sb := probe.Superblock()
	probe.Close()

	// Two in each of three stripes: six losses, all recoverable.
	for _, i := range []uint64{0, 1, 20, 21, 40, 41} {
		wreckData(t, path, sb, i)
	}

	r := openUnlocked(t, path)
	report, err := r.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.DamagedShards) != 6 {
		t.Fatalf("found %d damaged shards, want 6", len(report.DamagedShards))
	}
	if !report.Repairable {
		t.Fatalf("six losses spread two per stripe were called unrepairable: %+v", report)
	}

	repaired := filepath.Join(t.TempDir(), "repaired.bond")
	if _, err := Repair(r, repaired, report, nil); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	fixed, err := Open(repaired)
	if err != nil {
		t.Fatal(err)
	}
	defer fixed.Close()
	fixed.Unlock(crypto.Passphrase(testPass))
	if got := readAll(t, fixed); !bytes.Equal(got, payload) {
		t.Error("the repaired payload is not what was backed up")
	}
}

func TestRepairRefusedWithoutRecoveryData(t *testing.T) {
	path, _ := buildWithParity(t, 4, 0)

	probe, _ := Open(path)
	sb := probe.Superblock()
	probe.Close()
	wreckData(t, path, sb, 1)

	r := openUnlocked(t, path)
	report, _ := r.Verify(nil)
	if report.Repairable {
		t.Error("a container without recovery data was called repairable")
	}

	dst := filepath.Join(t.TempDir(), "attempt.bond")
	if _, err := Repair(r, dst, report, nil); err == nil {
		t.Fatal("Repair succeeded on a container with no recovery data")
	} else if !strings.Contains(err.Error(), "no recovery data") {
		t.Errorf("error = %v, want it to say there is nothing to rebuild from", err)
	}
}

// A repair works from a container that is already suspect. It must never write
// to the original.
func TestRepairLeavesTheOriginalAlone(t *testing.T) {
	path, _ := buildWithParity(t, 25, 10)

	probe, _ := Open(path)
	sb := probe.Superblock()
	probe.Close()
	wreckData(t, path, sb, 4)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	r := openUnlocked(t, path)
	report, _ := r.Verify(nil)
	dst := filepath.Join(t.TempDir(), "repaired.bond")
	if _, err := Repair(r, dst, report, nil); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("Repair modified the damaged container it was reading from")
	}
}

// Bit rot in the wild is scattered, not hand-placed. This flips bits at random
// positions and requires that every repairable case actually repairs.
func TestRepairAgainstRandomDamage(t *testing.T) {
	const rounds = 12
	for round := range rounds {
		path, payload := buildWithParity(t, 25, 10)

		probe, _ := Open(path)
		sb := probe.Superblock()
		l := sb.Layout()
		probe.Close()

		// One or two shards per stripe, chosen at random.
		hit := map[uint64]bool{}
		for s := range l.Stripes() {
			width := l.DataInStripe(s)
			count := 1 + round%2
			for range count {
				var b [1]byte
				rand.Read(b[:])
				index := uint64(s*l.Plan.Data) + uint64(int(b[0])%width)
				if !hit[index] {
					hit[index] = true
					wreckData(t, path, sb, index)
				}
			}
		}

		r := openUnlocked(t, path)
		report, err := r.Verify(nil)
		if err != nil {
			t.Fatalf("round %d: Verify: %v", round, err)
		}
		if !report.Repairable {
			t.Fatalf("round %d: damage of %d shards within capacity was called unrepairable",
				round, len(report.DamagedShards))
		}

		repaired := filepath.Join(t.TempDir(), "repaired.bond")
		if _, err := Repair(r, repaired, report, nil); err != nil {
			t.Fatalf("round %d: Repair: %v", round, err)
		}
		fixed, err := Open(repaired)
		if err != nil {
			t.Fatal(err)
		}
		fixed.Unlock(crypto.Passphrase(testPass))
		if got := readAll(t, fixed); !bytes.Equal(got, payload) {
			t.Errorf("round %d: the repaired payload differs", round)
		}
		fixed.Close()
	}
}

// A single-shard container is the degenerate case: one short shard and one
// parity shard the same size.
func TestParityOnATinyContainer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tiny.bond")
	payload := []byte("small enough to fit in one shard")

	w, err := Create(path, Options{
		ShardSize:       4 << 20,
		RecoveryPercent: 10,
		Keys:            []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}},
	})
	if err != nil {
		t.Fatal(err)
	}
	w.Write(payload)
	if err := w.Finish(&format.Manifest{}); err != nil {
		t.Fatal(err)
	}

	info, _ := os.Stat(path)
	// One data shard and one parity shard, both tiny – not two 4 MiB ones.
	if info.Size() > format.PayloadOffset+64<<10 {
		t.Errorf("a %d-byte payload produced a %d-byte container", len(payload), info.Size())
	}

	probe, _ := Open(path)
	sb := probe.Superblock()
	l := sb.Layout()
	probe.Close()
	if got := l.ParityInStripe(0); got != 1 {
		t.Errorf("parity shards = %d, want 1 for a single-shard container", got)
	}

	// And it still repairs.
	wreckData(t, path, sb, 0)
	r := openUnlocked(t, path)
	report, _ := r.Verify(nil)
	if !report.Repairable {
		t.Fatalf("a one-shard container with one parity shard was called unrepairable: %+v", report)
	}
	repaired := filepath.Join(t.TempDir(), "repaired.bond")
	if _, err := Repair(r, repaired, report, nil); err != nil {
		t.Fatalf("Repair: %v", err)
	}
	fixed, _ := Open(repaired)
	defer fixed.Close()
	fixed.Unlock(crypto.Passphrase(testPass))
	if got := readAll(t, fixed); !bytes.Equal(got, payload) {
		t.Error("the tiny container did not come back")
	}
}

func TestParityGeometryIsRecordedInTheHeader(t *testing.T) {
	for _, percent := range []int{5, 10, 20, 30} {
		path, _ := buildWithParity(t, 45, percent)
		probe, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		plan := probe.Superblock().Plan()
		want, _ := parity.For(percent)
		if plan != want {
			t.Errorf("%d%%: header records %v, want %v", percent, plan, want)
		}
		probe.Close()
	}
}

// A repair works from a verification made at some earlier point, on a container
// that has been sitting on storage nobody trusts in the meantime. The shards it
// believes are intact are read back raw and fed straight to Reed-Solomon, which
// cannot tell a good shard from a rotten one – so a shard that failed since the
// check would be used to rebuild the missing ones, and the result would be wrong
// everywhere instead of missing in one place.
func TestRepairRefusesAShardThatChangedSinceTheCheck(t *testing.T) {
	path, _ := buildWithParity(t, 12, 20)

	probe, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sb := probe.Superblock()
	wreckData(t, path, sb, 0)
	probe.Close()

	r := openUnlocked(t, path)
	report, err := r.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Repairable {
		t.Fatalf("one lost shard should be repairable at 20%%")
	}

	// Rot arrives between the check and the repair.
	wreckData(t, path, r.Superblock(), 1)

	fixed := filepath.Join(t.TempDir(), "fixed.bond")
	_, err = Repair(r, fixed, report, nil)
	if err == nil {
		t.Fatal("a repair ran on a shard that no longer authenticates")
	}
	if !strings.Contains(err.Error(), "shard 1") {
		t.Errorf("error = %v, want it to name the shard that changed", err)
	}
}
