package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
)

// A recipient slot is the one way into a container that needs no secret at
// backup time. Only the public key sits on the machine making the backup, so a
// job can run unattended and the machine still cannot read what it wrote – and
// a machine that is later compromised gives up nothing about the backups
// already in the cloud.
//
// The key exchange is hybrid on purpose. X25519 is what protects the container
// against everything known today; ML-KEM-1024 is what protects it against a
// quantum computer that does not exist yet but that a backup written now may
// well outlive. Combining both means the result is no weaker than the stronger
// of the two, whichever that turns out to be – if ML-KEM is broken by
// cryptanalysis, X25519 still holds, and vice versa.

// Sizes of the pieces of a hybrid recipient.
const (
	SeedLen        = 32   // the printable secret everything is derived from
	x25519KeyLen   = 32   //
	mlkemSeedLen   = 64   // ML-KEM's own seed format
	mlkemPubLen    = 1568 // ML-KEM-1024 encapsulation key
	mlkemCipherLen = 1568 // ML-KEM-1024 ciphertext

	// RecipientPublicLen is an X25519 public key followed by an ML-KEM
	// encapsulation key.
	RecipientPublicLen = x25519KeyLen + mlkemPubLen

	// encapsulationLen is the ephemeral X25519 public key followed by the
	// ML-KEM ciphertext, stored in the key slot.
	encapsulationLen = x25519KeyLen + mlkemCipherLen
)

const (
	infoRecipientX25519 = "bond/v1/recipient-x25519"
	infoRecipientMLKEM  = "bond/v1/recipient-mlkem"
	infoRecipientKEK    = "bond/v1/recipient-kek"
)

// SlotRecipient is a hybrid public-key slot.
const SlotRecipient SlotType = 4

// RecipientPublic is what goes in the control file: safe to store anywhere,
// useless for reading a backup.
type RecipientPublic struct {
	X25519 *ecdh.PublicKey
	MLKEM  *mlkem.EncapsulationKey1024
}

// RecipientPrivate is what opens the container. It exists only where the seed
// is, which should be a safe and not a computer.
type RecipientPrivate struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey1024
	seed   []byte
}

// NewRecipientSeed draws a fresh recipient secret.
func NewRecipientSeed() ([]byte, error) { return RandomBytes(SeedLen) }

// RecipientFromSeed derives both key pairs from one 32-byte secret.
//
// Deriving rather than storing is what makes the printed card possible at all:
// an ML-KEM-1024 private key is over 3 KB and its own seed is 64 bytes, but
// both halves of a hybrid recipient can be regrown from 32 bytes – which is
// about sixty characters on paper instead of five thousand.
func RecipientFromSeed(seed []byte) (*RecipientPrivate, error) {
	if len(seed) != SeedLen {
		return nil, fmt.Errorf("a recipient seed is %d bytes, this one is %d", SeedLen, len(seed))
	}

	xSeed, err := deriveHKDF(seed, nil, infoRecipientX25519)
	if err != nil {
		return nil, err
	}
	defer Wipe(xSeed)
	xPriv, err := ecdh.X25519().NewPrivateKey(xSeed)
	if err != nil {
		return nil, fmt.Errorf("deriving the X25519 key: %w", err)
	}

	mSeed, err := hkdfLong(seed, nil, infoRecipientMLKEM, mlkemSeedLen)
	if err != nil {
		return nil, err
	}
	defer Wipe(mSeed)
	mPriv, err := mlkem.NewDecapsulationKey1024(mSeed)
	if err != nil {
		return nil, fmt.Errorf("deriving the ML-KEM key: %w", err)
	}

	return &RecipientPrivate{
		X25519: xPriv,
		MLKEM:  mPriv,
		seed:   append([]byte(nil), seed...),
	}, nil
}

// Public is the half that may be published.
func (p *RecipientPrivate) Public() *RecipientPublic {
	return &RecipientPublic{X25519: p.X25519.PublicKey(), MLKEM: p.MLKEM.EncapsulationKey()}
}

// Seed is the secret this recipient was derived from.
func (p *RecipientPrivate) Seed() []byte { return p.seed }

// Wipe clears the seed.
func (p *RecipientPrivate) Wipe() { Wipe(p.seed) }

// Bytes renders a public key as X25519 ‖ ML-KEM.
func (p *RecipientPublic) Bytes() []byte {
	out := make([]byte, 0, RecipientPublicLen)
	out = append(out, p.X25519.Bytes()...)
	out = append(out, p.MLKEM.Bytes()...)
	return out
}

// ParseRecipientPublic reads a public key back.
func ParseRecipientPublic(b []byte) (*RecipientPublic, error) {
	if len(b) != RecipientPublicLen {
		return nil, fmt.Errorf("a recipient public key is %d bytes, this one is %d", RecipientPublicLen, len(b))
	}
	x, err := ecdh.X25519().NewPublicKey(b[:x25519KeyLen])
	if err != nil {
		return nil, fmt.Errorf("the X25519 half is not a valid key: %w", err)
	}
	m, err := mlkem.NewEncapsulationKey1024(b[x25519KeyLen:])
	if err != nil {
		return nil, fmt.Errorf("the ML-KEM half is not a valid key: %w", err)
	}
	return &RecipientPublic{X25519: x, MLKEM: m}, nil
}

// RecipientSecret unlocks a recipient slot. It is the private half, held only
// where the seed is.
type RecipientSecret struct{ Private *RecipientPrivate }

func (RecipientSecret) slotType() SlotType { return SlotRecipient }
func (RecipientSecret) describe() string   { return "recovery key" }

// kek is not used for recipient slots: the shared secret comes from the
// encapsulation stored in the slot, which the generic path does not carry.
func (RecipientSecret) kek(*Slot) ([]byte, error) {
	return nil, errors.New("a recipient slot is opened through its encapsulation")
}

// NewRecipientSlot wraps the master key so only the recipient's private half
// can recover it.
func NewRecipientSlot(c Cipher, containerUUID []byte, fmk FMK, pub *RecipientPublic, label string) (*Slot, error) {
	uuid, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}
	salt, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}
	nonce, err := RandomBytes(NonceLen)
	if err != nil {
		return nil, err
	}

	// X25519: a fresh ephemeral key for every slot, so the same recipient used
	// twice shares nothing between containers.
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	classical, err := ephemeral.ECDH(pub.X25519)
	if err != nil {
		return nil, fmt.Errorf("the X25519 exchange failed: %w", err)
	}
	defer Wipe(classical)

	quantum, ciphertext := pub.MLKEM.Encapsulate()
	defer Wipe(quantum)

	encapsulation := make([]byte, 0, encapsulationLen)
	encapsulation = append(encapsulation, ephemeral.PublicKey().Bytes()...)
	encapsulation = append(encapsulation, ciphertext...)

	kek, err := recipientKEK(classical, quantum, encapsulation, pub.Bytes(), salt)
	if err != nil {
		return nil, err
	}
	defer Wipe(kek)

	s := &Slot{
		Type:          SlotRecipient,
		UUID:          uuid,
		Label:         label,
		Nonce:         nonce,
		Salt:          salt,
		Encapsulation: encapsulation,
	}

	aead, err := AEAD(c, kek)
	if err != nil {
		return nil, err
	}
	s.Wrapped = aead.Seal(nil, s.Nonce, fmk, s.aad(containerUUID))
	return s, nil
}

// unwrapRecipient recovers the master key from a recipient slot.
func (s *Slot) unwrapRecipient(c Cipher, containerUUID []byte, priv *RecipientPrivate) (FMK, error) {
	if len(s.Encapsulation) != encapsulationLen {
		return nil, fmt.Errorf("this recipient slot carries %d bytes of key exchange data, want %d",
			len(s.Encapsulation), encapsulationLen)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(s.Encapsulation[:x25519KeyLen])
	if err != nil {
		return nil, ErrWrongKey
	}
	classical, err := priv.X25519.ECDH(ephPub)
	if err != nil {
		return nil, ErrWrongKey
	}
	defer Wipe(classical)

	quantum, err := priv.MLKEM.Decapsulate(s.Encapsulation[x25519KeyLen:])
	if err != nil {
		return nil, ErrWrongKey
	}
	defer Wipe(quantum)

	kek, err := recipientKEK(classical, quantum, s.Encapsulation, priv.Public().Bytes(), s.Salt)
	if err != nil {
		return nil, err
	}
	defer Wipe(kek)

	aead, err := AEAD(c, kek)
	if err != nil {
		return nil, err
	}
	fmk, err := aead.Open(nil, s.Nonce, s.Wrapped, s.aad(containerUUID))
	if err != nil {
		return nil, ErrWrongKey
	}
	return fmk, nil
}

// recipientKEK combines the two shared secrets.
//
// Both go into one derivation along with everything that identifies this
// exchange – the ephemeral key, the ciphertext and the recipient's own public
// key. Feeding the transcript in is what stops an attacker who can rewrite the
// slot from steering the result: change any of it and the key that comes out
// is a different one, and the wrapped master key no longer opens.
func recipientKEK(classical, quantum, encapsulation, recipientPub, salt []byte) ([]byte, error) {
	secret := make([]byte, 0, len(classical)+len(quantum)+len(encapsulation)+len(recipientPub))
	secret = append(secret, classical...)
	secret = append(secret, quantum...)
	secret = append(secret, encapsulation...)
	secret = append(secret, recipientPub...)
	defer Wipe(secret)
	return deriveHKDF(secret, salt, infoRecipientKEK)
}
