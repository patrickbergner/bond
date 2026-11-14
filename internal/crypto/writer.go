package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// A writer key signs the containers a machine writes, so that whoever restores
// one can tell it was written by that machine and not merely by someone who
// knew the recovery card's public key.
//
// It exists because a recipient slot authenticates nothing about its author. A
// slot is made from the public key alone, so anyone holding that key – and in
// a fleet that is everyone who can read a control file – can build a complete
// container the recovery card opens. The signature closes that: the private
// half stays on the writing machine, the public half goes beside the card, and
// a restore that is told which writer to expect refuses anything else.
//
// The writer key opens nothing. A machine holding one can vouch for the
// backups it writes and still cannot read them, which is the property the
// recipient slot was there for in the first place.
//
// Like the key exchange, the signature is hybrid: Ed25519 holds against
// everything known today, ML-DSA against a quantum computer, and a forgery has
// to break both. ML-DSA-65 rather than -87 because its signature fits the
// header's reserved area; its security category is 3, against the category 5
// of the ML-KEM-1024 exchange. That difference is less than it looks: a
// harvested ciphertext can be broken decades later, while a forged signature
// has to exist before the restore that would accept it.

// Sizes of the pieces of a writer key.
const (
	WriterSeedLen      = 32
	writerEdPubLen     = ed25519.PublicKeySize
	writerMLPubLen     = mldsa.MLDSA65PublicKeySize
	WriterPublicLen    = writerEdPubLen + writerMLPubLen
	WriterSignatureLen = ed25519.SignatureSize + mldsa.MLDSA65SignatureSize
	WriterIDLen        = sha256.Size
)

const (
	infoWriterEd25519 = "bond/v2/writer-ed25519"
	infoWriterMLDSA   = "bond/v2/writer-mldsa65"

	// writerContext separates these ML-DSA signatures from any other use of
	// the same key. Ed25519 has no context; the signed message carries the
	// same label instead.
	writerContext = "BOND-WRITER-V2"
)

// WriterPrivate signs containers.
type WriterPrivate struct {
	ed   ed25519.PrivateKey
	ml   *mldsa.PrivateKey
	seed []byte
	pub  *WriterPublic
}

// WriterPublic checks a container's signature.
type WriterPublic struct {
	ed ed25519.PublicKey
	ml *mldsa.PublicKey
}

// NewWriterSeed draws a fresh writer secret.
func NewWriterSeed() ([]byte, error) { return RandomBytes(WriterSeedLen) }

// WriterFromSeed derives both signing keys from one 32-byte secret.
func WriterFromSeed(seed []byte) (*WriterPrivate, error) {
	if len(seed) != WriterSeedLen {
		return nil, fmt.Errorf("a writer seed is %d bytes, this one is %d", WriterSeedLen, len(seed))
	}
	edSeed, err := deriveHKDF(seed, nil, infoWriterEd25519)
	if err != nil {
		return nil, err
	}
	defer Wipe(edSeed)
	mlSeed, err := deriveHKDF(seed, nil, infoWriterMLDSA)
	if err != nil {
		return nil, err
	}
	defer Wipe(mlSeed)
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mlSeed)
	if err != nil {
		return nil, fmt.Errorf("deriving the ML-DSA key: %w", err)
	}
	ed := ed25519.NewKeyFromSeed(edSeed)
	return &WriterPrivate{
		ed:   ed,
		ml:   ml,
		seed: append([]byte(nil), seed...),
		pub:  &WriterPublic{ed: ed.Public().(ed25519.PublicKey), ml: ml.PublicKey()},
	}, nil
}

// Public is the half that goes beside the recovery card.
func (w *WriterPrivate) Public() *WriterPublic { return w.pub }

// Seed is the secret this key was derived from.
func (w *WriterPrivate) Seed() []byte { return w.seed }

// Fingerprint names the key; it is what a signed header records.
func (w *WriterPrivate) Fingerprint() []byte { return w.pub.Fingerprint() }

// Sign signs a message with both keys. ML-DSA signing is hedged: it mixes fresh
// randomness into the deterministic procedure, as FIPS 204 recommends.
func (w *WriterPrivate) Sign(msg []byte) ([]byte, error) {
	ml, err := w.ml.Sign(nil, msg, &mldsa.Options{Context: writerContext})
	if err != nil {
		return nil, err
	}
	return append(ed25519.Sign(w.ed, msg), ml...), nil
}

// Deterministic is the same key with deterministic ML-DSA signing, for
// known-answer vectors only.
func (w *WriterPrivate) Deterministic() Signer { return deterministicWriter{w} }

// Wipe clears the seed and drops the expanded keys.
func (w *WriterPrivate) Wipe() {
	if w == nil {
		return
	}
	Wipe(w.seed)
	Wipe(w.ed)
	w.seed, w.ed, w.ml = nil, nil, nil
}

// Signer is what signs a header.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Fingerprint() []byte
}

type deterministicWriter struct{ w *WriterPrivate }

func (d deterministicWriter) Fingerprint() []byte { return d.w.Fingerprint() }
func (d deterministicWriter) Sign(msg []byte) ([]byte, error) {
	ml, err := d.w.ml.SignDeterministic(msg, &mldsa.Options{Context: writerContext})
	if err != nil {
		return nil, err
	}
	return append(ed25519.Sign(d.w.ed, msg), ml...), nil
}

// Bytes renders the public key as Ed25519 ‖ ML-DSA-65.
func (p *WriterPublic) Bytes() []byte {
	return append(append([]byte(nil), p.ed...), p.ml.Bytes()...)
}

// Fingerprint is SHA-256 of the public key's bytes.
func (p *WriterPublic) Fingerprint() []byte {
	sum := sha256.Sum256(p.Bytes())
	return sum[:]
}

// ParseWriterPublic reads a public key back.
func ParseWriterPublic(b []byte) (*WriterPublic, error) {
	if len(b) != WriterPublicLen {
		return nil, fmt.Errorf("a writer public key is %d bytes, this one is %d", WriterPublicLen, len(b))
	}
	ml, err := mldsa.NewPublicKey(mldsa.MLDSA65(), b[writerEdPubLen:])
	if err != nil {
		return nil, fmt.Errorf("the ML-DSA half is not a valid key: %w", err)
	}
	return &WriterPublic{ed: ed25519.PublicKey(append([]byte(nil), b[:writerEdPubLen]...)), ml: ml}, nil
}

// ErrBadSignature means a signature does not verify under the expected key.
var ErrBadSignature = errors.New("the signature does not verify under the expected writer key")

// Verify checks both halves of a signature. Both have to hold.
func (p *WriterPublic) Verify(msg, sig []byte) error {
	if len(sig) != WriterSignatureLen {
		return ErrBadSignature
	}
	if !ed25519.Verify(p.ed, msg, sig[:ed25519.SignatureSize]) {
		return ErrBadSignature
	}
	if err := mldsa.Verify(p.ml, msg, sig[ed25519.SignatureSize:], &mldsa.Options{Context: writerContext}); err != nil {
		return ErrBadSignature
	}
	return nil
}

// Equal reports whether two public keys are the same key.
func (p *WriterPublic) Equal(q *WriterPublic) bool {
	return q != nil && bytes.Equal(p.Bytes(), q.Bytes())
}
