package backup

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/parity"
)

// The whole point of streaming the pipeline is that a backup of a terabyte
// needs a terabyte of destination and nothing else. That is easy to claim and
// easy to lose: one io.ReadAll, one slice that grows per file, and the tool
// quietly starts needing memory in proportion to the data.
//
// So the claim is measured rather than asserted. What is bounded is the Go
// heap; 7-Zip runs in its own process and its memory is a function of the
// compression level, not of how much is fed through it.

// peakHeap samples the heap while fn runs and returns the highest reading.
func peakHeap(fn func()) uint64 {
	runtime.GC()
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&m)
			for {
				old := peak.Load()
				if m.HeapAlloc <= old || peak.CompareAndSwap(old, m.HeapAlloc) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	fn()
	close(stop)
	<-done
	return peak.Load()
}

// bigTree writes a few large files, keeping the file index small so this
// measures the streaming path rather than the manifest.
func bigTree(t *testing.T, total int64) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "big")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	const files = 4
	// Compressible, but not so much that the payload stops resembling the
	// input: runs of random bytes repeated a few times.
	block := make([]byte, 64<<10)
	rand.New(rand.NewSource(3)).Read(block)

	each := total / files
	for i := range files {
		f, err := os.Create(filepath.Join(root, "file"+string(rune('a'+i))+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		for written := int64(0); written < each; written += int64(len(block)) {
			if _, err := f.Write(block); err != nil {
				f.Close()
				t.Fatal(err)
			}
		}
		f.Close()
	}
	return root
}

func TestMemoryDoesNotGrowWithThePayload(t *testing.T) {
	if testing.Short() {
		t.Skip("writes and reads a few hundred megabytes")
	}

	const shard = 256 << 10
	s := config.Defaults()
	s.CompressionLevel = 0 // 7-Zip's memory is its own; this measures BOND's
	s.RecoveryPercent = 10
	s.ShardBytes = shard
	s.HashAlgorithm = config.HashNone

	plan, err := parity.For(s.RecoveryPercent)
	if err != nil {
		t.Fatal(err)
	}
	stripe := int64(plan.Data+plan.Parity) * shard

	measure := func(total int64) (uint64, *CreateResult) {
		root := bigTree(t, total)
		var result *CreateResult
		peak := peakHeap(func() {
			result = createContainer(t, root, s, []container.KeySpec{{Secret: crypto.KeyfileSecret(testKey())}})
		})
		return peak, result
	}

	const small = 16 << 20
	const large = 64 << 20

	peakSmall, resSmall := measure(small)
	peakLarge, resLarge := measure(large)

	// The geometry has to be the same in both runs, or the comparison says
	// nothing. shardSizeFor shrinks shards for small payloads; both of these are
	// well past the point where the configured size stands.
	if resSmall.ShardSize != resLarge.ShardSize {
		t.Fatalf("shard size differed between the runs (%d and %d); the comparison is not meaningful",
			resSmall.ShardSize, resLarge.ShardSize)
	}

	t.Logf("stripe is %d KiB (%d+%d shards of %d KiB)", stripe>>10, plan.Data, plan.Parity, shard>>10)
	t.Logf("%3d MiB in: peak heap %d KiB", small>>20, peakSmall>>10)
	t.Logf("%3d MiB in: peak heap %d KiB", large>>20, peakLarge>>10)

	// Four times the data must not mean anything like four times the memory.
	// A generous factor, because heap readings are noisy and the garbage
	// collector is free to keep more than the live set – but nowhere near the
	// factor of four that a buffering implementation would show.
	if float64(peakLarge) > 1.6*float64(peakSmall) {
		t.Errorf("four times the payload took %.1f times the heap (%d KiB against %d KiB); memory is scaling with the data",
			float64(peakLarge)/float64(peakSmall), peakLarge>>10, peakSmall>>10)
	}

	// And in absolute terms it stays within a handful of stripes, which is the
	// figure the documentation quotes.
	if ceiling := uint64(6 * stripe); peakLarge > ceiling {
		t.Errorf("peak heap %d KiB is more than %d KiB, which is six stripes", peakLarge>>10, ceiling>>10)
	}
}

func TestRestoreMemoryDoesNotGrowWithThePayload(t *testing.T) {
	if testing.Short() {
		t.Skip("writes and reads a few hundred megabytes")
	}

	const shard = 256 << 10
	s := config.Defaults()
	s.CompressionLevel = 0
	s.RecoveryPercent = 10
	s.ShardBytes = shard
	s.HashAlgorithm = config.HashNone

	key := testKey()
	measure := func(total int64) uint64 {
		created := createContainer(t, bigTree(t, total), s, []container.KeySpec{{Secret: crypto.KeyfileSecret(key)}})
		dest := t.TempDir()
		return peakHeap(func() {
			r, err := container.Open(created.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err := r.Unlock(crypto.KeyfileSecret(key)); err != nil {
				t.Fatal(err)
			}
			if _, err := Restore(context.Background(), r, RestoreOptions{Dest: dest}); err != nil {
				t.Fatal(err)
			}
		})
	}

	peakSmall := measure(16 << 20)
	peakLarge := measure(64 << 20)
	t.Logf("restore: 16 MiB peak heap %d KiB, 64 MiB peak heap %d KiB", peakSmall>>10, peakLarge>>10)

	if float64(peakLarge) > 1.6*float64(peakSmall) {
		t.Errorf("restoring four times the payload took %.1f times the heap; memory is scaling with the data",
			float64(peakLarge)/float64(peakSmall))
	}
}

// The file index is the one part of a container that does grow with the
// backup – one record per file – so what it costs is worth knowing rather than
// discovering on a tree of a million files.
func TestFileIndexCostPerFile(t *testing.T) {
	if testing.Short() {
		t.Skip("writes tens of thousands of files")
	}

	build := func(count int) *CreateResult {
		root := filepath.Join(t.TempDir(), "many")
		for i := range count {
			dir := filepath.Join(root, "d"+string(rune('a'+i%26)))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "file-with-an-average-sort-of-name-"+itoa(i)+".txt")
			if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		s := config.Defaults()
		s.CompressionLevel = 1
		s.RecoveryPercent = 0
		s.HashAlgorithm = config.HashNone
		return createContainer(t, root, s, []container.KeySpec{{Secret: crypto.KeyfileSecret(testKey())}})
	}

	few := build(1_000)
	many := build(20_000)

	perFile := float64(many.Size-few.Size) / float64(many.Stats.Files-few.Stats.Files)
	t.Logf("%d files: %d bytes; %d files: %d bytes – %.1f bytes per file in the container",
		few.Stats.Files, few.Size, many.Stats.Files, many.Size, perFile)

	// The index is gzipped JSON of highly repetitive records. Well under a
	// hundred bytes per file is what that should come to; if it ever is not,
	// storeFileIndex has become an expensive default.
	if perFile > 100 {
		t.Errorf("the file index costs %.1f bytes per file; storeFileIndex is no longer a cheap default", perFile)
	}
}

func testKey() []byte {
	key := make([]byte, crypto.KeyLen)
	rand.New(rand.NewSource(41)).Read(key)
	return key
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
