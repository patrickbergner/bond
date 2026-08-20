package parity

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPlanFor(t *testing.T) {
	cases := []struct {
		percent  int
		wantData int
		wantPar  int
	}{
		{0, 0, 0},
		{5, 40, 2},
		{10, 20, 2},
		{20, 10, 2},
		{25, 8, 2},
		{30, 10, 3},
		{50, 8, 4},
		{100, 8, 8},
	}
	for _, tc := range cases {
		got, err := For(tc.percent)
		if err != nil {
			t.Errorf("For(%d): %v", tc.percent, err)
			continue
		}
		if got.Data != tc.wantData || got.Parity != tc.wantPar {
			t.Errorf("For(%d) = %d+%d, want %d+%d", tc.percent, got.Data, got.Parity, tc.wantData, tc.wantPar)
		}
		if tc.percent > 0 && got.Percent() < float64(tc.percent)*0.95 {
			t.Errorf("For(%d) gives %.1f%%, which is less than was asked for", tc.percent, got.Percent())
		}
		if got.Data+got.Parity > MaxShards {
			t.Errorf("For(%d) = %d+%d exceeds the shard limit", tc.percent, got.Data, got.Parity)
		}
	}

	// A percentage too small for the geometry gives more protection, never
	// less, and still fits in a stripe.
	tiny, err := For(1)
	if err != nil {
		t.Fatal(err)
	}
	if tiny.Data+tiny.Parity > MaxShards {
		t.Errorf("For(1) = %v exceeds the shard limit", tiny)
	}
	if tiny.Percent() < 1 {
		t.Errorf("For(1) gives %.2f%%, less than asked", tiny.Percent())
	}

	for _, bad := range []int{-1, 101} {
		if _, err := For(bad); err == nil {
			t.Errorf("For(%d) was accepted", bad)
		}
	}
}

func layout(n uint64, shard, last uint32, p Plan) Layout {
	return Layout{ShardSize: shard, LastShardBytes: last, DataShards: n, Plan: p}
}

func TestLayoutWithoutParity(t *testing.T) {
	// With no parity the layout must be exactly what it was before parity
	// existed: shards back to back, the last one short.
	l := layout(4, 1000, 600, Plan{})
	for i := uint64(0); i < 4; i++ {
		if got, want := l.DataOffset(i), i*1000; got != want {
			t.Errorf("DataOffset(%d) = %d, want %d", i, got, want)
		}
	}
	if got, want := l.DataLen(3), uint32(600); got != want {
		t.Errorf("DataLen(3) = %d, want %d", got, want)
	}
	if got, want := l.TotalBytes(), uint64(3*1000+600); got != want {
		t.Errorf("TotalBytes = %d, want %d", got, want)
	}
	if l.ParityShardCount() != 0 {
		t.Errorf("ParityShardCount = %d, want 0", l.ParityShardCount())
	}
}

func TestLayoutStripesDoNotOverlap(t *testing.T) {
	// Every shard, data and parity, must occupy its own range. An overlap
	// would be silent corruption that only shows up in a repair.
	plans := []Plan{{Data: 8, Parity: 2}, {Data: 20, Parity: 2}, {Data: 10, Parity: 3}}
	counts := []uint64{1, 2, 7, 8, 9, 20, 21, 41, 100}
	lasts := []uint32{1024, 4096}

	for _, p := range plans {
		for _, n := range counts {
			for _, last := range lasts {
				l := layout(n, 4096, last, p)
				type span struct {
					start, end uint64
					what       string
				}
				var spans []span
				for i := uint64(0); i < n; i++ {
					start := l.DataOffset(i)
					spans = append(spans, span{start, start + uint64(l.DataLen(i)), "data"})
				}
				for s := range l.Stripes() {
					for q := range l.ParityInStripe(s) {
						start := l.ParityOffset(s, q)
						spans = append(spans, span{start, start + l.ParitySlot(s), "parity"})
					}
				}
				for a := range spans {
					for b := range spans {
						if a >= b {
							continue
						}
						if spans[a].start < spans[b].end && spans[b].start < spans[a].end {
							t.Fatalf("plan %v, %d shards, last %d: %s [%d,%d) overlaps %s [%d,%d)",
								p, n, last, spans[a].what, spans[a].start, spans[a].end,
								spans[b].what, spans[b].start, spans[b].end)
						}
					}
				}
				// And nothing may stick out past the region's own size.
				for _, sp := range spans {
					if sp.end > l.TotalBytes() {
						t.Fatalf("plan %v, %d shards: %s ends at %d, past TotalBytes %d",
							p, n, sp.what, sp.end, l.TotalBytes())
					}
				}
			}
		}
	}
}

func TestLayoutShortFinalStripe(t *testing.T) {
	p := Plan{Data: 20, Parity: 2}

	// A container of exactly one short shard must not carry two full-size
	// parity shards; that would be a file mostly made of recovery data.
	l := layout(1, 4<<20, 5000, p)
	if got := l.ParityInStripe(0); got != 1 {
		t.Errorf("a one-shard container has %d parity shards, want 1", got)
	}
	if got := l.ShardLen(0); got != 5000 {
		t.Errorf("stripe shard length = %d, want the short shard's 5000", got)
	}
	if total := l.TotalBytes(); total > 2*5000+TagLen {
		t.Errorf("a 5000-byte payload occupies %d bytes", total)
	}

	// Two shards, the second short: coding runs at full width, so parity is
	// full width too.
	l2 := layout(2, 4096, 100, p)
	if got := l2.ShardLen(0); got != 4096 {
		t.Errorf("stripe shard length = %d, want 4096", got)
	}
	if got := l2.ParityInStripe(0); got != 2 {
		t.Errorf("parity shards = %d, want 2", got)
	}
}

func TestParityNonceIndicesAreDisjointFromData(t *testing.T) {
	seen := map[uint64]bool{}
	for s := range 50 {
		for q := range 4 {
			n := ParityNonceIndex(s, q)
			if n < 1<<63 {
				t.Fatalf("parity nonce index %d could collide with a data shard", n)
			}
			if seen[n] {
				t.Fatalf("parity nonce index %d is used twice", n)
			}
			seen[n] = true
		}
	}
}

func TestCoderRoundTrip(t *testing.T) {
	p := Plan{Data: 8, Parity: 3}
	c, err := NewCoder(p)
	if err != nil {
		t.Fatal(err)
	}

	const shardLen = 4096
	original := make([][]byte, p.Data)
	for i := range original {
		original[i] = make([]byte, shardLen)
		rand.Read(original[i])
	}

	parityShards, err := c.Encode(original, shardLen, p.Parity)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(parityShards) != p.Parity {
		t.Fatalf("got %d parity shards, want %d", len(parityShards), p.Parity)
	}

	// Lose as many shards as the parity allows, and get them all back.
	for _, lost := range [][]int{{0}, {3, 7}, {0, 1, 2}, {2, 5, 7}} {
		data := make([][]byte, p.Data)
		copy(data, original)
		lengths := make([]uint32, p.Data)
		for i := range lengths {
			lengths[i] = shardLen
		}
		for _, i := range lost {
			data[i] = nil
		}
		par := make([][]byte, p.Parity)
		copy(par, parityShards)

		if err := c.Reconstruct(data, par, lengths, shardLen); err != nil {
			t.Fatalf("losing %v: %v", lost, err)
		}
		for _, i := range lost {
			if !bytes.Equal(data[i], original[i]) {
				t.Errorf("losing %v: shard %d did not come back", lost, i)
			}
		}
	}
}

func TestCoderRefusesTooMuchLoss(t *testing.T) {
	p := Plan{Data: 8, Parity: 2}
	c, _ := NewCoder(p)
	const shardLen = 1024

	data := make([][]byte, p.Data)
	lengths := make([]uint32, p.Data)
	for i := range data {
		data[i] = make([]byte, shardLen)
		rand.Read(data[i])
		lengths[i] = shardLen
	}
	par, err := c.Encode(data, shardLen, p.Parity)
	if err != nil {
		t.Fatal(err)
	}

	if c.CanReconstruct(3, 0) {
		t.Error("CanReconstruct said three losses are recoverable with two parity shards")
	}

	data[0], data[1], data[2] = nil, nil, nil
	if err := c.Reconstruct(data, par, lengths, shardLen); err == nil {
		t.Error("Reconstruct claimed to rebuild three shards from two parity shards")
	}
}

// The final stripe is the awkward one: fewer shards than a full stripe and a
// short last shard. It has to reconstruct back to the exact original lengths.
func TestCoderShortFinalStripe(t *testing.T) {
	p := Plan{Data: 8, Parity: 2}
	c, _ := NewCoder(p)
	const shardLen = 1024

	// Three data shards, the last one 300 bytes.
	original := [][]byte{make([]byte, shardLen), make([]byte, shardLen), make([]byte, 300)}
	for _, s := range original {
		rand.Read(s)
	}
	lengths := []uint32{shardLen, shardLen, 300}

	par, err := c.Encode(original, shardLen, 2)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	for _, lost := range [][]int{{0}, {2}, {1, 2}} {
		data := make([][]byte, len(original))
		copy(data, original)
		for _, i := range lost {
			data[i] = nil
		}
		parCopy := make([][]byte, len(par))
		copy(parCopy, par)

		if err := c.Reconstruct(data, parCopy, lengths, shardLen); err != nil {
			t.Fatalf("losing %v: %v", lost, err)
		}
		for _, i := range lost {
			if !bytes.Equal(data[i], original[i]) {
				t.Errorf("losing %v: shard %d came back as %d bytes, want %d",
					lost, i, len(data[i]), len(original[i]))
			}
		}
	}
}

// Parity can be the thing that is damaged. Losing a parity shard must not
// prevent recovery of the data, and the parity itself must be rebuildable.
func TestCoderRebuildsLostParity(t *testing.T) {
	p := Plan{Data: 8, Parity: 2}
	c, _ := NewCoder(p)
	const shardLen = 512

	data := make([][]byte, p.Data)
	lengths := make([]uint32, p.Data)
	for i := range data {
		data[i] = make([]byte, shardLen)
		rand.Read(data[i])
		lengths[i] = shardLen
	}
	par, _ := c.Encode(data, shardLen, p.Parity)
	want := append([][]byte(nil), par[0])

	lost := [][]byte{nil, par[1]}
	if err := c.Reconstruct(data, lost, lengths, shardLen); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !bytes.Equal(lost[0], want[0]) {
		t.Error("the lost parity shard was not rebuilt")
	}
}
