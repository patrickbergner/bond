package container

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

// The individual corruption cases each prove one thing about one field. This
// file makes the claim the format actually has to live up to, which is stronger
// and much less flattering: whatever a single flipped bit lands on, the reader
// either refuses the container or hands back exactly the bytes that went in.
// Never a panic, never a plausible-looking wrong answer.
//
// A flip is allowed to change nothing at all. That is not a hole – it is the
// redundancy doing its job: the inactive key-slot table, the second copy of the
// manifest and the mirror superblock exist precisely so that damage there costs
// nothing. What matters is that "tolerated" always means "and the data is
// still right".

// outcome is what a damaged container did when it was read.
type outcome int

const (
	refused  outcome = iota // the reader said no, at some stage
	survived                // it opened and returned the correct payload
	silent                  // it opened and returned something else – a bug
)

// attempt reads a container all the way through, turning any panic into a
// failure rather than taking the test binary down with it.
func attempt(path string, key []byte, want []byte) (result outcome, detail string) {
	defer func() {
		if p := recover(); p != nil {
			result, detail = silent, fmt.Sprintf("panic: %v", p)
		}
	}()

	r, err := Open(path)
	if err != nil {
		return refused, err.Error()
	}
	defer r.Close()

	if err := r.Unlock(crypto.KeyfileSecret(key)); err != nil {
		return refused, err.Error()
	}
	s, err := r.Stream()
	if err != nil {
		return refused, err.Error()
	}
	got, err := io.ReadAll(s)
	if err != nil {
		return refused, err.Error()
	}
	if !bytes.Equal(got, want) {
		return silent, fmt.Sprintf("%d bytes back, want %d", len(got), len(want))
	}
	return survived, ""
}

// region names the part of the container an offset falls in, so the summary
// says something more useful than a count.
func region(sb *format.Superblock, size, off int64) string {
	tailStart := int64(sb.TailOffset)
	tailLen := int64(sb.TailLength)
	switch {
	case off < format.SuperblockSize:
		return "superblock"
	case off < format.SlotTableBOffset:
		return "key slots A"
	case off < format.PayloadOffset:
		return "key slots B"
	case off < tailStart:
		return "payload"
	case off < tailStart+tailLen:
		return "manifest copy 1"
	case off < tailStart+2*tailLen:
		return "manifest copy 2"
	case off < size:
		return "mirror superblock"
	}
	return "past the end"
}

// sweepOffsets walks the whole container, densely where every byte has a
// meaning and by stride where it does not.
//
// Every region is walked by a fixed count rather than by a stride running to a
// variable end, so the totals this test reports are the same on every run. They
// are quoted in NERDME §9, and a sample that drifts is not a measurement: the
// sealed manifest changes length by a byte or two from one container to the
// next, because the creation time it carries renders shorter when its
// nanoseconds end in a zero. That was enough to move the count.
func sweepOffsets(sb *format.Superblock, size int64) []int64 {
	seen := make(map[int64]bool)
	var offsets []int64
	add := func(from, to, step int64) {
		for off := from; off < to && off < size; off += step {
			if off >= 0 && !seen[off] {
				seen[off] = true
				offsets = append(offsets, off)
			}
		}
	}
	// count evenly spaced offsets across a region of any size.
	addCount := func(from, to, count int64) {
		if to <= from || count <= 0 {
			return
		}
		step := max((to-from)/count, 1)
		add(from, to, step)
	}

	tail, tailLen := int64(sb.TailOffset), int64(sb.TailLength)

	add(0, 256, 1)                         // every named superblock field
	add(256, format.SuperblockSize, 128)   // its reserved tail
	add(format.SlotTableAOffset, 6144, 16) // the slot records themselves
	add(format.SlotTableAOffset, format.SlotTableBOffset, 4096)
	add(format.SlotTableBOffset, format.PayloadOffset, 4096)
	addCount(format.PayloadOffset, tail, 80) // the payload, which has no second copy

	// The tail is small and matters out of all proportion to its size, so both
	// manifest copies and the mirrored header are walked properly.
	addCount(tail, tail+tailLen, 20)
	addCount(tail+tailLen, tail+2*tailLen, 20)
	addCount(size-format.SuperblockSize, size, 64)

	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	return offsets
}

func TestSingleBitFlipIsNeverSilent(t *testing.T) {
	payload := make([]byte, 40_000)
	rand.New(rand.NewSource(7)).Read(payload)

	key := make([]byte, crypto.KeyLen)
	rand.New(rand.NewSource(11)).Read(key)

	// No parity: this test is about what the reader refuses, not about what
	// Reed-Solomon can rebuild. Repair has its own tests.
	path := build(t, payload, Options{
		ShardSize: 8192,
		Keys:      []KeySpec{{Secret: crypto.KeyfileSecret(key), Label: "sweep"}},
	})
	pristine, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Unlock(crypto.KeyfileSecret(key)); err != nil {
		t.Fatal(err)
	}
	sb := r.Superblock()
	size := int64(len(pristine))
	r.Close()

	damaged := filepath.Join(t.TempDir(), "damaged.bond")
	caught := map[string]int{}
	tolerated := map[string]int{}

	for _, off := range sweepOffsets(sb, size) {
		bytesCopy := append([]byte(nil), pristine...)
		bytesCopy[off] ^= 0x40
		if err := os.WriteFile(damaged, bytesCopy, 0o644); err != nil {
			t.Fatal(err)
		}

		where := region(sb, size, off)
		switch result, detail := attempt(damaged, key, payload); result {
		case silent:
			t.Errorf("byte %d (%s): the container was read as healthy but gave back different data – %s", off, where, detail)
		case refused:
			caught[where]++
		case survived:
			tolerated[where]++
		}
	}

	total := 0
	for _, where := range []string{"superblock", "key slots A", "key slots B", "payload", "manifest copy 1", "manifest copy 2", "mirror superblock"} {
		if caught[where]+tolerated[where] == 0 {
			continue
		}
		total += caught[where] + tolerated[where]
		t.Logf("%-18s %4d flips: %4d refused, %4d absorbed without harm", where, caught[where]+tolerated[where], caught[where], tolerated[where])
	}
	t.Logf("%-18s %4d flips, none silent", "total", total)

	// The payload is the one region with no second copy – parity is off in this
	// test – so every flip there has to be caught. If one ever were not, the
	// invariant above would be all that stood between a damaged backup and a
	// confident wrong restore.
	if tolerated["payload"] > 0 {
		t.Errorf("%d flips in the payload changed nothing, but nothing there is stored twice", tolerated["payload"])
	}

	// Everything else is duplicated, and has to behave like it. A region that
	// never absorbs a flip is a region whose second copy is not being used, and
	// the space it costs is being paid for nothing.
	for _, where := range []string{"superblock", "key slots B", "manifest copy 1", "manifest copy 2", "mirror superblock"} {
		if caught[where]+tolerated[where] == 0 {
			t.Errorf("no flip landed in the %s; the sweep is not covering it", where)
			continue
		}
		if tolerated[where] == 0 {
			t.Errorf("every flip in the %s was fatal, but it is stored twice; the spare copy is not being used", where)
		}
	}
}

// Truncation is what a failed upload looks like. Every prefix of a container is
// either refused or, where only redundancy was lost, still exactly right.
func TestTruncationIsNeverSilent(t *testing.T) {
	payload := make([]byte, 40_000)
	rand.New(rand.NewSource(13)).Read(payload)
	key := make([]byte, crypto.KeyLen)
	rand.New(rand.NewSource(17)).Read(key)

	path := build(t, payload, Options{
		ShardSize: 8192,
		Keys:      []KeySpec{{Secret: crypto.KeyfileSecret(key)}},
	})
	pristine, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	cut := filepath.Join(t.TempDir(), "cut.bond")
	survivors := 0
	for length := int64(0); length < int64(len(pristine)); length += 997 {
		if err := os.WriteFile(cut, pristine[:length], 0o644); err != nil {
			t.Fatal(err)
		}
		switch result, detail := attempt(cut, key, payload); result {
		case silent:
			t.Errorf("truncated to %d of %d bytes: read as healthy but gave back different data – %s", length, len(pristine), detail)
		case survived:
			survivors++
			t.Errorf("truncated to %d of %d bytes: read as healthy, which cannot be right", length, len(pristine))
		}
	}
	if survivors == 0 {
		t.Logf("every truncation of the container was refused")
	}
}

// The superblock's reserved region is signed like everything else in it. It
// used to be signed only in principle: the MAC was taken over a re-marshal of
// the fields the reader understood, which renders that region as zeros, so
// whatever was really written there was covered by nothing. Several kilobytes
// per header copy could be used by anyone holding the container, and no amount
// of verifying would mention it.
func TestSmuggledPaddingIsCaughtAndScrubbed(t *testing.T) {
	payload := make([]byte, 40_000)
	rand.New(rand.NewSource(41)).Read(payload)
	key := make([]byte, crypto.KeyLen)
	rand.New(rand.NewSource(43)).Read(key)

	path := build(t, payload, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.KeyfileSecret(key)}}})
	smuggle := func(t *testing.T, at int64) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteAt(bytes.Repeat([]byte("SMUGGLED"), 8), at); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// 300 is in the reserved tail; 244 is the gap between the last named field
	// and where the reserved region was documented to start, which was covered
	// by nothing at all.
	smuggle(t, 300)
	smuggle(t, 244)

	r, err := Open(path)
	if err != nil {
		t.Fatalf("the container did not open from its mirror: %v", err)
	}
	if err := r.Unlock(crypto.KeyfileSecret(key)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !strings.Contains(r.HeaderSource(), "mirror") {
		t.Errorf("header came from %q; the edited copy should have been refused", r.HeaderSource())
	}
	if len(r.Notices()) == 0 {
		t.Error("the container opened on its mirror without saying so")
	}
	if got := readAll(t, r); !bytes.Equal(got, payload) {
		t.Error("the payload did not come back")
	}

	// A repair puts the redundancy back, which means writing the authentic
	// header over the edited one – padding and all.
	report, err := r.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(t.TempDir(), "fixed.bond")
	if _, err := Repair(r, fixed, report, nil); err != nil {
		t.Fatalf("Repair refused a container that opened on its spare copy: %v", err)
	}
	r.Close()

	repaired, err := os.ReadFile(fixed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(repaired[:format.SuperblockSize], []byte("SMUGGLED")) {
		t.Error("the repaired container still carries the smuggled bytes in its header")
	}

	// With both copies edited there is nothing authentic left to fall back on,
	// and the right answer is to refuse rather than to serve the payload from a
	// header nobody signed.
	smuggle(t, info.Size()-format.SuperblockSize+300)
	again, err := Open(path)
	if err == nil {
		err = again.Unlock(crypto.KeyfileSecret(key))
		again.Close()
	}
	if err == nil {
		t.Error("a container whose every header copy was edited still opened")
	}
}

// A copy that fails to parse is as damaged as one that fails its MAC, but it
// used to leave no trace: the surviving copy became the only one, the reader
// never reported a fallback, and repair then refused to put the redundancy back
// because nothing had told it any was missing. The container went on looking
// healthy while being one flip from unopenable.
func TestADamagedHeaderCopyIsAlwaysReported(t *testing.T) {
	payload := make([]byte, 40_000)
	rand.New(rand.NewSource(47)).Read(payload)
	key := make([]byte, crypto.KeyLen)
	rand.New(rand.NewSource(53)).Read(key)

	for _, tc := range []struct {
		name string
		at   func(size int64) int64
	}{
		{"the leading header", func(int64) int64 { return 0 }},
		{"the mirror", func(size int64) int64 { return size - format.SuperblockSize }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := build(t, payload, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.KeyfileSecret(key)}}})
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			corrupt(t, path, tc.at(info.Size()), 8) // the magic, so it cannot parse

			r, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer r.Close()
			if err := r.Unlock(crypto.KeyfileSecret(key)); err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			if len(r.Notices()) == 0 {
				t.Fatalf("%s is unreadable and nothing said so", tc.name)
			}
			if got := readAll(t, r); !bytes.Equal(got, payload) {
				t.Error("the payload did not come back")
			}

			report, err := r.Verify(nil)
			if err != nil {
				t.Fatal(err)
			}
			fixed := filepath.Join(t.TempDir(), "fixed.bond")
			if _, err := Repair(r, fixed, report, nil); err != nil {
				t.Fatalf("Repair left the container on its last copy: %v", err)
			}

			again, err := Open(fixed)
			if err != nil {
				t.Fatal(err)
			}
			defer again.Close()
			if err := again.Unlock(crypto.KeyfileSecret(key)); err != nil {
				t.Fatal(err)
			}
			if n := again.Notices(); len(n) != 0 {
				t.Errorf("the repaired container is still short a copy: %v", n)
			}
		})
	}
}

// Repair copies a container byte for byte, so damage the reader merely worked
// around would be reproduced faithfully in the "repaired" file. The point of a
// repair is to put the spare copy back, not to inherit a container that is one
// flip away from being lost.
func TestRepairRestoresTheSpareCopies(t *testing.T) {
	payload := make([]byte, 40_000)
	rand.New(rand.NewSource(29)).Read(payload)
	key := make([]byte, crypto.KeyLen)
	rand.New(rand.NewSource(31)).Read(key)

	path := build(t, payload, Options{ShardSize: 8192, Keys: []KeySpec{{Secret: crypto.KeyfileSecret(key)}}})

	// Break the leading header and the current key-slot table, leaving the
	// mirror and the spare table intact.
	corrupt(t, path, 88, 4)                        // the nonce prefix
	corrupt(t, path, format.SlotTableAOffset+8, 1) // the generation counter

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Unlock(crypto.KeyfileSecret(key)); err != nil {
		t.Fatalf("the container did not open from its spare copies: %v", err)
	}
	if len(r.Notices()) != 2 {
		t.Fatalf("notices = %v, want one for the header and one for the key slots", r.Notices())
	}

	report, err := r.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Damaged() {
		t.Fatal("the payload should be untouched; only the metadata was damaged")
	}

	fixed := filepath.Join(t.TempDir(), "fixed.bond")
	result, err := Repair(r, fixed, report, nil)
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if len(result.Metadata) == 0 {
		t.Error("Repair reported rewriting nothing")
	}

	// The repaired copy must open with no notices at all – every first choice
	// intact – and give back the same bytes.
	again, err := Open(fixed)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.Unlock(crypto.KeyfileSecret(key)); err != nil {
		t.Fatalf("the repaired container does not open: %v", err)
	}
	if n := again.Notices(); len(n) != 0 {
		t.Errorf("the repaired container still falls back on spare copies: %v", n)
	}
	if got := readAll(t, again); !bytes.Equal(got, payload) {
		t.Error("the repaired container gives back different bytes")
	}
}

// Moving a shard is the attack a per-shard tag exists to stop: the bytes are
// authentic, they are simply not the ones that belong there.
func TestShardsCannotBeReordered(t *testing.T) {
	const shard = 8192
	payload := make([]byte, 40_000)
	rand.New(rand.NewSource(19)).Read(payload)
	key := make([]byte, crypto.KeyLen)
	rand.New(rand.NewSource(23)).Read(key)

	path := build(t, payload, Options{ShardSize: shard, Keys: []KeySpec{{Secret: crypto.KeyfileSecret(key)}}})
	pristine, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	swapped := append([]byte(nil), pristine...)
	a := format.PayloadOffset
	b := format.PayloadOffset + shard
	tmp := append([]byte(nil), swapped[a:a+shard]...)
	copy(swapped[a:a+shard], swapped[b:b+shard])
	copy(swapped[b:b+shard], tmp)

	path2 := filepath.Join(t.TempDir(), "swapped.bond")
	if err := os.WriteFile(path2, swapped, 0o644); err != nil {
		t.Fatal(err)
	}
	if result, detail := attempt(path2, key, payload); result != refused {
		t.Errorf("two swapped shards were accepted (%v): %s", result, detail)
	}
}
