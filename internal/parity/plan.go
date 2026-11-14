// Package parity is BOND's recovery data: the stripe geometry, where every
// shard sits in the file, and the Reed-Solomon coding itself.
//
// Parity is computed over the *ciphertext* shards, not the plaintext. That
// ordering is the whole point: it repairs exactly the bytes a storage
// provider lost, and the shard's own authentication tag then proves the
// repair produced the original. Reed-Solomon reconstructs; AEAD decides
// whether the reconstruction is right. Never the other way around.
package parity

import (
	"fmt"
	"math"
)

// MaxShards is the Reed-Solomon limit BOND works within. The coding itself
// allows 256 shards per stripe; staying below that leaves room and keeps a
// stripe's working set to something a small machine can hold.
const MaxShards = 128

// Plan is a stripe geometry: k data shards protected by p parity shards.
type Plan struct {
	Data   int // k
	Parity int // p
}

// Enabled reports whether this plan stores any recovery data.
func (p Plan) Enabled() bool { return p.Parity > 0 && p.Data > 0 }

// Percent is the real storage overhead, which may exceed what was asked for.
func (p Plan) Percent() float64 {
	if p.Data == 0 {
		return 0
	}
	return 100 * float64(p.Parity) / float64(p.Data)
}

func (p Plan) String() string {
	if !p.Enabled() {
		return "none"
	}
	return fmt.Sprintf("%d+%d (%.1f%%)", p.Data, p.Parity, p.Percent())
}

// For chooses a geometry for a recovery percentage.
//
// The mapping is part of format 1.0 (NERDME §6): the manifest records the
// percentage, the header records k and p, and a reader refuses a container in
// which For of the one is not the other. Changing what this returns for any
// input makes every existing container with that percentage unreadable, so it
// is a new format version and not a tuning change.
//
// Two parity shards is the floor for anything meaningful – one gives no margin
// once a shard is already lost – so the percentage is met by choosing how many
// data shards they cover. A stripe of fewer than eight data shards is a poor
// trade (the working set shrinks but each loss costs proportionally more), so
// past that point the parity count rises instead.
func For(percent int) (Plan, error) {
	switch {
	case percent < 0:
		return Plan{}, fmt.Errorf("recovery percentage %d is negative", percent)
	case percent == 0:
		return Plan{}, nil
	case percent > 100:
		return Plan{}, fmt.Errorf("recovery percentage %d is above 100", percent)
	}

	const minData = 8
	for parity := 2; parity <= MaxShards/2; parity++ {
		data := int(math.Round(float64(parity) * 100 / float64(percent)))
		if data < minData {
			continue
		}
		if data+parity > MaxShards {
			// Asking for very little recovery runs out of room before it runs
			// out of arithmetic: cover as much as a stripe can hold and give
			// slightly more protection than was asked for.
			return Plan{Data: MaxShards - parity, Parity: parity}, nil
		}
		return Plan{Data: data, Parity: parity}, nil
	}
	// Very high percentages: parity equal to data is 100%.
	return Plan{Data: minData, Parity: minData}, nil
}
