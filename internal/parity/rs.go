package parity

import (
	"fmt"

	"github.com/klauspost/reedsolomon"
)

// Coder computes and rebuilds one stripe's parity.
//
// Reed-Solomon needs every shard in a stripe to be the same length, but the
// final data shard of a container is short and the final stripe may hold fewer
// shards than a full one. Both are handled here by padding in memory: the
// padding is never stored, and the reconstruction truncates back to the real
// lengths.
type Coder struct {
	plan Plan
	enc  reedsolomon.Encoder
}

// NewCoder builds a coder for a stripe geometry.
func NewCoder(p Plan) (*Coder, error) {
	if !p.Enabled() {
		return nil, fmt.Errorf("no parity in this plan")
	}
	enc, err := reedsolomon.New(p.Data, p.Parity)
	if err != nil {
		return nil, fmt.Errorf("preparing Reed-Solomon %d+%d: %w", p.Data, p.Parity, err)
	}
	return &Coder{plan: p, enc: enc}, nil
}

// Encode computes parity for one stripe.
//
// data holds the stripe's shards in order; a short final shard is allowed and
// padded here. The result holds parityCount shards of shardLen bytes.
func (c *Coder) Encode(data [][]byte, shardLen uint32, parityCount int) ([][]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("a stripe with no data shards")
	}
	if len(data) > c.plan.Data {
		return nil, fmt.Errorf("stripe holds %d data shards, the plan allows %d", len(data), c.plan.Data)
	}
	if parityCount > c.plan.Parity {
		return nil, fmt.Errorf("stripe wants %d parity shards, the plan allows %d", parityCount, c.plan.Parity)
	}

	shards := c.frame(data, shardLen)
	if err := c.enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("computing parity: %w", err)
	}

	out := make([][]byte, parityCount)
	for q := range parityCount {
		out[q] = shards[c.plan.Data+q]
	}
	return out, nil
}

// frame lays a stripe out as the encoder wants it: k data shards followed by
// p parity shards, all shardLen bytes.
//
// A stripe with fewer than k data shards is completed with zero shards. They
// are never written and never read back, but both sides of the arithmetic
// agree on them, which is what makes a short final stripe work at all.
func (c *Coder) frame(data [][]byte, shardLen uint32) [][]byte {
	shards := make([][]byte, c.plan.Data+c.plan.Parity)
	for i := range shards {
		if i < len(data) && data[i] != nil {
			if uint32(len(data[i])) == shardLen {
				shards[i] = data[i]
				continue
			}
			padded := make([]byte, shardLen)
			copy(padded, data[i])
			shards[i] = padded
			continue
		}
		shards[i] = make([]byte, shardLen)
	}
	return shards
}

// Reconstruct rebuilds the missing shards of one stripe.
//
// data and parity hold what survives, with nil for anything damaged or
// missing. dataLen gives each data shard's real length, so the padding used
// for coding can be stripped again afterwards.
func (c *Coder) Reconstruct(data, parity [][]byte, dataLen []uint32, shardLen uint32) error {
	if len(data) != len(dataLen) {
		return fmt.Errorf("%d shards but %d lengths", len(data), len(dataLen))
	}

	shards := make([][]byte, c.plan.Data+c.plan.Parity)

	// Present data shards, padded for coding.
	for i := range c.plan.Data {
		switch {
		case i >= len(data):
			// Beyond this stripe: an implied zero shard, always available.
			shards[i] = make([]byte, shardLen)
		case data[i] == nil:
			shards[i] = nil
		default:
			shards[i] = pad(data[i], shardLen)
		}
	}
	for q := range c.plan.Parity {
		if q < len(parity) && parity[q] != nil {
			shards[c.plan.Data+q] = pad(parity[q], shardLen)
		}
	}

	if err := c.enc.Reconstruct(shards); err != nil {
		return fmt.Errorf("rebuilding the stripe: %w", err)
	}

	for i := range data {
		if data[i] != nil {
			continue
		}
		// Back to the real length: the padding was only ever a device for the
		// arithmetic and must not reach the file.
		data[i] = shards[i][:dataLen[i]]
	}
	for q := range parity {
		if parity[q] == nil && shards[c.plan.Data+q] != nil {
			parity[q] = shards[c.plan.Data+q]
		}
	}
	return nil
}

// CanReconstruct reports whether a stripe with this many losses is repairable.
func (c *Coder) CanReconstruct(lostData, lostParity int) bool {
	return lostData+lostParity <= c.plan.Parity
}

func pad(b []byte, n uint32) []byte {
	if uint32(len(b)) == n {
		return b
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}
