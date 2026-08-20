package parity

import "math/bits"

// Layout says where every shard lives inside the payload region.
//
// Stripes are interleaved: each one's parity follows its own data, rather than
// all parity being collected at the end. That is what lets a container be
// written in a single streaming pass – parity is emitted the moment its stripe
// is complete, so nothing has to be buffered to disk – and it puts the
// recovery data next to the bytes it recovers.
//
// All offsets are relative to the start of the payload region.
type Layout struct {
	ShardSize uint32 // the nominal size of a shard on disk

	// LastShardBytes is the on-disk size of the final data shard, which is the
	// only one allowed to be short.
	LastShardBytes uint32

	DataShards uint64 // N
	Plan       Plan
}

// Stripes is how many stripes the data shards form.
func (l Layout) Stripes() int { return int(l.stripes64()) }

// stripes64 is Stripes without the narrowing to int, which is what the overflow
// check has to reason about.
func (l Layout) stripes64() uint64 {
	if l.DataShards == 0 {
		return 0
	}
	if !l.Plan.Enabled() {
		return 1
	}
	k := uint64(l.Plan.Data)
	return (l.DataShards + k - 1) / k
}

// MaxPayloadBytes caps the on-disk payload region. Nothing near it is storable;
// the point is that every offset a Layout computes then stays far inside a
// uint64, so stripeStart, DataOffset and TotalBytes can multiply without
// guarding each time.
//
// It matters because these run on numbers nobody has authenticated yet: a
// header carries its own shard count and shard size, and "bond inspect" prints
// PayloadBytes before anything is unlocked.
const MaxPayloadBytes = 1 << 62

// OffsetsFit reports whether this layout's arithmetic stays inside a uint64.
func (l Layout) OffsetsFit() bool {
	if l.DataShards == 0 {
		return true
	}
	if !l.Plan.Enabled() {
		hi, lo := bits.Mul64(l.DataShards, uint64(l.ShardSize))
		return hi == 0 && lo <= MaxPayloadBytes
	}
	hi, lo := bits.Mul64(l.stripes64(), l.fullStripeBytes())
	return hi == 0 && lo <= MaxPayloadBytes
}

// dataInStripe is how many data shards a stripe holds.
func (l Layout) dataInStripe(s int) int {
	if !l.Plan.Enabled() {
		return int(l.DataShards)
	}
	k := uint64(l.Plan.Data)
	first := uint64(s) * k
	if first+k <= l.DataShards {
		return l.Plan.Data
	}
	return int(l.DataShards - first)
}

// DataInStripe is how many data shards a stripe holds.
func (l Layout) DataInStripe(s int) int { return l.dataInStripe(s) }

// ParityInStripe is how many parity shards a stripe carries.
//
// A short final stripe never gets more parity shards than it has data shards:
// storing three copies of one shard is not redundancy worth paying for, and it
// is what keeps a container far smaller than one stripe from being mostly
// parity.
func (l Layout) ParityInStripe(s int) int {
	if !l.Plan.Enabled() {
		return 0
	}
	return min(l.Plan.Parity, l.dataInStripe(s))
}

// ShardLen is the length of one stripe's shards for coding purposes. Every
// data shard is padded to this in memory before the arithmetic runs.
//
// It is the full shard size unless the stripe holds nothing but the short
// final shard, in which case there is no reason to inflate it.
func (l Layout) ShardLen(s int) uint32 {
	if l.dataInStripe(s) > 1 {
		return l.ShardSize
	}
	if s == l.Stripes()-1 {
		return l.LastShardBytes
	}
	return l.ShardSize
}

// DataLen is the on-disk length of one data shard.
func (l Layout) DataLen(index uint64) uint32 {
	if index == l.DataShards-1 {
		return l.LastShardBytes
	}
	return l.ShardSize
}

// StripeOf says which stripe a data shard belongs to, and its position in it.
func (l Layout) StripeOf(index uint64) (stripe, position int) {
	if !l.Plan.Enabled() {
		return 0, int(index)
	}
	k := uint64(l.Plan.Data)
	return int(index / k), int(index % k)
}

// fullStripeBytes is the on-disk size of a stripe that is not the last: k data
// shards, then p parity shards, each of which carries an authentication tag of
// its own and is therefore that much larger.
func (l Layout) fullStripeBytes() uint64 {
	return uint64(l.Plan.Data)*uint64(l.ShardSize) +
		uint64(l.Plan.Parity)*(uint64(l.ShardSize)+TagLen)
}

// stripeStart is where a stripe begins. Every stripe but the last has the same
// size, so this needs no accumulation.
func (l Layout) stripeStart(s int) uint64 {
	if !l.Plan.Enabled() {
		return 0
	}
	return uint64(s) * l.fullStripeBytes()
}

// DataOffset is where a data shard begins.
func (l Layout) DataOffset(index uint64) uint64 {
	s, j := l.StripeOf(index)
	return l.stripeStart(s) + uint64(j)*uint64(l.ShardSize)
}

// ParityOffset is where a stripe's q-th parity shard begins.
func (l Layout) ParityOffset(s, q int) uint64 {
	start := l.stripeStart(s)
	dataBytes := uint64(l.dataInStripe(s)) * uint64(l.ShardSize)
	if s == l.Stripes()-1 {
		// The final data shard may be short, which pulls the parity in.
		dataBytes = uint64(l.dataInStripe(s)-1)*uint64(l.ShardSize) + uint64(l.LastShardBytes)
	}
	return start + dataBytes + uint64(q)*l.paritySlot(s)
}

// paritySlot is the on-disk size of one parity shard, tag included.
func (l Layout) paritySlot(s int) uint64 { return uint64(l.ShardLen(s)) + TagLen }

// ParityLen is the coded length of a stripe's parity shard, before sealing.
func (l Layout) ParityLen(s int) uint32 { return l.ShardLen(s) }

// ParitySlot is the on-disk size of one parity shard.
func (l Layout) ParitySlot(s int) uint64 { return l.paritySlot(s) }

// TagLen is the authentication overhead on a sealed parity shard. It matches
// crypto.TagLen; it is restated here so this package stays free of the crypto
// dependency and can be reasoned about on its own.
const TagLen = 16

// TotalBytes is the on-disk size of the whole payload region.
func (l Layout) TotalBytes() uint64 {
	if l.DataShards == 0 {
		return 0
	}
	last := l.Stripes() - 1
	if p := l.ParityInStripe(last); p > 0 {
		return l.ParityOffset(last, p-1) + l.paritySlot(last)
	}
	return l.ParityOffset(last, 0)
}

// ParityShardCount is how many parity shards the container holds.
func (l Layout) ParityShardCount() int {
	total := 0
	for s := range l.Stripes() {
		total += l.ParityInStripe(s)
	}
	return total
}

// ParityNonceIndex numbers a parity shard for its nonce and associated data.
//
// The high bit keeps parity numbering disjoint from data shard numbering, so
// no nonce can ever be used for both under the same key. Data shard counts are
// bounded far below this by the header checks.
func ParityNonceIndex(stripe, q int) uint64 {
	return 1<<63 | uint64(stripe)<<8 | uint64(q)
}
