// Package container reads and writes BOND container files.
//
// A container is written in one streaming pass. Its fixed-size head – the
// superblock and the two key-slot tables – is laid down as a placeholder
// before anything else, the payload is sealed shard by shard as the compressed
// stream arrives, and the head is patched with the final counts and hashes at
// the end. Nothing about the payload has to be known in advance, which is what
// lets the whole pipeline run without a temporary copy of the archive.
package container

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"time"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
)

// KeySpec is one way into the container being written. Exactly one of Secret
// and Recipient is set: a recipient needs no secret here, which is the whole
// reason it exists.
type KeySpec struct {
	Secret    crypto.Unlocker
	Recipient *crypto.RecipientPublic
	KDF       crypto.KDFParams
	Label     string
}

// Options configure a new container.
type Options struct {
	ShardSize int64
	Keys      []KeySpec

	// Unencrypted records that the master key is stored in the container. The
	// caller still has to pass the matching plaintext key spec; this only sets
	// the advisory header flag.
	Unencrypted bool

	// RecoveryPercent chooses the Reed-Solomon stripe geometry. Zero writes no
	// recovery data at all.
	RecoveryPercent int

	// MaxVolumeBytes splits the container into numbered files of roughly this
	// size. Zero writes a single file.
	MaxVolumeBytes int64
}

// Writer seals a compressed stream into a container. Write is called with the
// compressed bytes; everything else is bookkeeping.
type Writer struct {
	path string
	vols *volumeWriter

	shardSize   int64
	plainPerSh  int64
	buf         []byte
	bufUsed     int
	shardIndex  uint64
	streamLen   int64
	streamHash  hash.Hash
	sealed      int64
	keys        *crypto.Keys
	sb          *format.Superblock
	slots       []*crypto.Slot
	closed      bool
	unencrypted bool
	recovery    int

	plan        parity.Plan
	coder       *parity.Coder
	stripe      [][]byte // sealed shards of the stripe being built
	stripeIndex int
}

// Create starts a container at path. The file is written where it is told –
// callers put it in a working directory and Publish it afterwards, so a
// half-written container never appears at the destination.
func Create(path string, opts Options) (*Writer, error) {
	if len(opts.Keys) == 0 {
		return nil, fmt.Errorf("a container needs at least one key slot")
	}
	shardSize := opts.ShardSize
	if shardSize == 0 {
		shardSize = 4 << 20
	}
	if shardSize <= crypto.TagLen || shardSize%4096 != 0 {
		return nil, fmt.Errorf("shard size %d must be a positive multiple of 4096", shardSize)
	}

	uuid, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	noncePrefix, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	fmk, err := crypto.NewFMK()
	if err != nil {
		return nil, err
	}
	keys, err := crypto.Derive(fmk, uuid)
	if err != nil {
		return nil, err
	}

	slots := make([]*crypto.Slot, 0, len(opts.Keys))
	for i, spec := range opts.Keys {
		var (
			slot *crypto.Slot
			err  error
		)
		switch {
		case spec.Recipient != nil:
			slot, err = crypto.NewRecipientSlot(crypto.CipherXChaCha20Poly1305, uuid, fmk, spec.Recipient, spec.Label)
		case spec.Secret != nil:
			slot, err = crypto.NewSlot(crypto.CipherXChaCha20Poly1305, uuid, fmk, spec.Secret, spec.KDF, spec.Label)
		default:
			err = fmt.Errorf("neither a secret nor a recipient was given")
		}
		if err != nil {
			return nil, fmt.Errorf("key slot %d (%s): %w", i, spec.Label, err)
		}
		slots = append(slots, slot)
	}

	vols, err := newVolumeWriter(path, opts.MaxVolumeBytes)
	if err != nil {
		return nil, err
	}

	w := &Writer{
		path:        path,
		vols:        vols,
		shardSize:   shardSize,
		plainPerSh:  shardSize - crypto.TagLen,
		buf:         make([]byte, shardSize-crypto.TagLen),
		streamHash:  sha256.New(),
		keys:        keys,
		slots:       slots,
		unencrypted: opts.Unencrypted,
		recovery:    opts.RecoveryPercent,
		sb: &format.Superblock{
			VersionMajor:  format.VersionMajor,
			VersionMinor:  format.VersionMinor,
			Cipher:        crypto.CipherXChaCha20Poly1305,
			KDF:           format.KDFArgon2id,
			Parity:        format.ParityNone,
			ShardSize:     uint32(shardSize),
			Created:       time.Now(),
			ContainerUUID: uuid,
			NoncePrefix:   noncePrefix,
			VolumeCount:   1,
		},
	}
	if opts.Unencrypted {
		w.sb.Flags |= format.FlagUnencrypted
	}

	plan, err := parity.For(opts.RecoveryPercent)
	if err != nil {
		vols.Remove()
		return nil, err
	}
	if plan.Enabled() {
		coder, err := parity.NewCoder(plan)
		if err != nil {
			vols.Remove()
			return nil, err
		}
		w.plan, w.coder = plan, coder
		w.stripe = make([][]byte, 0, plan.Data)
		w.sb.Parity = format.ParityRS
		w.sb.DataShards = uint32(plan.Data)
		w.sb.ParityShards = uint32(plan.Parity)
	}
	return w, nil
}

// ContainerUUID identifies the container being written.
func (w *Writer) ContainerUUID() []byte { return w.sb.ContainerUUID }

// Keys exposes the derived subkeys, for sealing the manifest.
func (w *Writer) Keys() *crypto.Keys { return w.keys }

// Write accepts the compressed stream and seals it into shards.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("container is already finished")
	}
	written := 0
	for len(p) > 0 {
		n := copy(w.buf[w.bufUsed:], p)
		w.streamHash.Write(p[:n])
		w.bufUsed += n
		w.streamLen += int64(n)
		written += n
		p = p[n:]
		if int64(w.bufUsed) == w.plainPerSh {
			if err := w.flushShard(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// flushShard seals whatever is buffered.
//
// Every shard but the last is exactly shardSize on disk, which is what lets
// parity treat the payload as a fixed grid. The last one is sealed at whatever
// length it reached: padding it would waste up to a full shard on every
// container, and the grid does not need it, because parity pads in memory when
// it computes the final stripe.
func (w *Writer) flushShard() error {
	if w.bufUsed == 0 {
		return nil
	}
	plain := w.buf[:w.bufUsed]

	aead, err := crypto.AEAD(w.sb.Cipher, w.keys.Data)
	if err != nil {
		return err
	}
	nonce := crypto.ShardNonce(w.sb.NoncePrefix, w.shardIndex)
	aad := crypto.ShardAAD(w.sb.ContainerUUID, w.shardIndex, w.sb.ShardSize)
	sealed := aead.Seal(nil, nonce, plain, aad)
	if err := w.vols.WriteShard(sealed); err != nil {
		return err
	}

	w.shardIndex++
	w.sb.LastShardBytes = uint32(len(sealed))
	w.bufUsed = 0

	// Parity is computed over the sealed bytes, so the stripe keeps a copy of
	// what was just written until it is complete.
	if w.coder != nil {
		w.stripe = append(w.stripe, sealed)
		if len(w.stripe) == w.plan.Data {
			if err := w.flushStripe(); err != nil {
				return err
			}
		}
	}
	return nil
}

// flushStripe computes and writes the parity for the shards gathered so far.
//
// It runs the moment a stripe is complete, which is what keeps the whole
// pipeline streaming: parity never has to be buffered to disk or held until
// the end of a terabyte.
func (w *Writer) flushStripe() error {
	if w.coder == nil || len(w.stripe) == 0 {
		return nil
	}

	// A stripe holding nothing but the short final shard codes at that shard's
	// length; anything wider codes at the full shard size.
	shardLen := uint32(w.shardSize)
	if len(w.stripe) == 1 && len(w.stripe[0]) < int(w.shardSize) {
		shardLen = uint32(len(w.stripe[0]))
	}
	count := min(w.plan.Parity, len(w.stripe))

	shards, err := w.coder.Encode(w.stripe, shardLen, count)
	if err != nil {
		return err
	}

	aead, err := crypto.AEAD(w.sb.Cipher, w.keys.Data)
	if err != nil {
		return err
	}
	for q, shard := range shards {
		index := parity.ParityNonceIndex(w.stripeIndex, q)
		nonce := crypto.ShardNonce(w.sb.NoncePrefix, index)
		aad := crypto.ShardAAD(w.sb.ContainerUUID, index, w.sb.ShardSize)
		sealed := aead.Seal(nil, nonce, shard, aad)
		if err := w.vols.WriteShard(sealed); err != nil {
			return err
		}
	}

	w.stripeIndex++
	w.stripe = w.stripe[:0]
	return nil
}

// Finish seals the last shard, writes the manifest and completes the header.
func (w *Writer) Finish(m *format.Manifest) error {
	if w.closed {
		return fmt.Errorf("container is already finished")
	}
	if err := w.flushShard(); err != nil {
		return err
	}
	// A final stripe that never filled up still needs its parity.
	if err := w.flushStripe(); err != nil {
		return err
	}

	w.sb.DataShardCount = w.shardIndex
	w.sb.StreamLength = uint64(w.streamLen)

	m.FormatVersion = format.VersionMajor
	m.Created = w.sb.Created
	m.StreamLength = w.streamLen
	m.StreamSHA256 = hex.EncodeToString(w.streamHash.Sum(nil))
	m.ShardSize = w.shardSize
	m.DataShardCount = int64(w.shardIndex)
	m.RecoveryPercent = w.recovery

	tail, err := format.SealManifest(m, w.sb.Cipher, w.keys.Manifest, w.sb.ContainerUUID)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(tail)

	// The tail goes at the end of the last volume, so its offset is a position
	// in that file rather than in the payload as a whole.
	w.sb.TailOffset = uint64(w.vols.TailOffset())
	w.sb.TailLength = uint64(len(tail))
	w.sb.TailSHA256 = sum[:]
	w.sb.KeyCommitment = w.keys.Commitment(w.sb.ContainerUUID)

	// Two copies back to back, then the mirrored header.
	if err := w.vols.WriteTail(tail); err != nil {
		return err
	}
	if err := w.vols.WriteTail(tail); err != nil {
		return err
	}
	// Each volume's header differs only in which slice of the payload it
	// describes, so each is signed for itself – and each volume gets both
	// copies of it, the leading one and the mirror that closes the file.
	if err := w.vols.WriteMirrors(w.sb, func(sb *format.Superblock) { sb.Sign(w.keys.Header) }); err != nil {
		return err
	}
	if err := w.vols.PatchHeaders(w.sb, func(sb *format.Superblock) { sb.Sign(w.keys.Header) }); err != nil {
		return err
	}
	if err := w.writeHead(); err != nil {
		return err
	}

	if err := w.vols.Sync(); err != nil {
		return err
	}
	w.closed = true
	return w.vols.Close()
}

// writeHead lays down the key-slot tables, which live only in the first volume.
func (w *Writer) writeHead() error {
	// Both tables get the same slots at the same generation, so the spare is a
	// real spare from the first byte written. Leaving B empty until the first
	// key change would reserve 64 KiB for redundancy and then not provide any:
	// a single flipped bit in table A would cost the whole container, with the
	// space that should have saved it sitting right behind it, blank.
	//
	// Identical generations are not a problem for the alternating write. A key
	// change picks the newest table that parses, which is A, and writes B at
	// generation 2 – exactly as it would have done.
	table := &format.SlotTable{Generation: 1, Slots: w.slots}
	a, err := table.Marshal(w.keys.Header)
	if err != nil {
		return err
	}
	return w.vols.WriteHead(a, a)
}

// Abort closes and removes a half-written container.
func (w *Writer) Abort() {
	if w.closed {
		return
	}
	w.closed = true
	w.vols.Remove()
	w.keys.Wipe()
}

// Volumes is how many files the container was written to.
func (w *Writer) Volumes() int { return w.vols.Count() }

// Publish moves a finished container to its destination, replacing whatever is
// there only once every volume is complete on disk.
func (w *Writer) Publish(dst string) ([]string, error) {
	if !w.closed {
		return nil, fmt.Errorf("the container is not finished")
	}
	return w.vols.Publish(dst)
}
