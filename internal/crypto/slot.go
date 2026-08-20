package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// SlotType is how one key slot is unlocked.
type SlotType uint8

const (
	SlotPassphrase SlotType = 1
	SlotKeyfile    SlotType = 2

	// SlotPlaintext wraps the master key under an all-zero key-encryption key.
	// It is what "encryptionMethod: NONE" produces: the container is still
	// authenticated end to end, but anyone holding it can open it. Reusing the
	// wrapping path rather than special-casing an unencrypted container means
	// there is exactly one way in, and one way to get it wrong.
	SlotPlaintext SlotType = 3
)

func (s SlotType) String() string {
	switch s {
	case SlotPassphrase:
		return "passphrase"
	case SlotKeyfile:
		return "keyfile"
	case SlotPlaintext:
		return "plaintext"
	case SlotRecipient:
		return "recipient"
	default:
		return fmt.Sprintf("unknown slot type %d", uint8(s))
	}
}

// ErrWrongKey means a slot exists but the secret offered does not open it.
var ErrWrongKey = errors.New("wrong passphrase or key")

// KDFParams are Argon2id's cost settings, stored per slot so they can be
// raised for new containers without invalidating old ones.
type KDFParams struct {
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint32 `json:"parallelism"`
}

// DefaultKDF is the starting point: roughly a second on a current desktop, and
// 512 MiB of memory that an attacker has to find for every single guess.
// "bond bench-kdf" measures the machine and suggests something better.
var DefaultKDF = KDFParams{MemoryKiB: 512 * 1024, Iterations: 3, Parallelism: 4}

// LowMemoryKDF is RFC 9106's second recommended profile, for machines that
// cannot spare half a gigabyte. It is weaker, and BOND only uses it when asked.
var LowMemoryKDF = KDFParams{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4}

// Validate rejects parameters that would not harden anything.
func (p KDFParams) Validate() error {
	switch {
	case p.MemoryKiB < 8*1024:
		return fmt.Errorf("argon2 memory %d KiB is too low to be worth doing; use at least 8192", p.MemoryKiB)
	case p.Iterations < 1:
		return errors.New("argon2 needs at least one iteration")
	case p.Parallelism < 1:
		return errors.New("argon2 needs at least one lane")
	case p.Parallelism > maxLanes:
		// Argon2 takes the lane count as a single byte, and the slot stores a
		// uint32 that is bound into its associated data. Quietly clamping a
		// larger number would make BOND derive a different key from the
		// parameters the slot actually records – it would still open the
		// container, and the recovery procedure in NERDME §11, which says to use
		// the stored values, would not.
		return fmt.Errorf("argon2 takes at most %d lanes, this slot asks for %d", maxLanes, p.Parallelism)
	}
	return nil
}

// maxLanes is what Argon2's lane count fits in.
const maxLanes = 255

func (p KDFParams) encode() []byte {
	b := make([]byte, 0, 12)
	b = binary.LittleEndian.AppendUint32(b, p.MemoryKiB)
	b = binary.LittleEndian.AppendUint32(b, p.Iterations)
	b = binary.LittleEndian.AppendUint32(b, p.Parallelism)
	return b
}

// Slot is one way into a container. Every slot wraps the same master key, so
// they are alternatives rather than parts of a whole.
type Slot struct {
	Type  SlotType
	UUID  []byte // 16 bytes
	Label string

	Nonce   []byte // 24 bytes
	Wrapped []byte // the sealed master key, 48 bytes

	Salt []byte    // 16 bytes; passphrase and keyfile slots
	KDF  KDFParams // passphrase slots only

	// Encapsulation carries a recipient slot's ephemeral public key and
	// ML-KEM ciphertext. Empty for every other slot type.
	Encapsulation []byte
}

// Unlocker is a secret offered to a slot.
type Unlocker interface {
	// kek turns the secret into a key-encryption key for one slot.
	kek(s *Slot) ([]byte, error)
	// slotType is the slot kind this secret can open.
	slotType() SlotType
	// describe names the secret for messages, without revealing it.
	describe() string
}

// Passphrase unlocks passphrase slots.
type Passphrase []byte

func (p Passphrase) slotType() SlotType { return SlotPassphrase }
func (p Passphrase) describe() string   { return "passphrase" }

// Derive exposes the key-encryption key derivation so bench-kdf can time it.
func (p Passphrase) Derive(s *Slot) ([]byte, error) { return p.kek(s) }

func (p Passphrase) kek(s *Slot) ([]byte, error) {
	if err := s.KDF.Validate(); err != nil {
		return nil, fmt.Errorf("this container's key slot is unusable: %w", err)
	}
	// Validate has already refused a lane count that does not fit in the byte
	// Argon2 takes, so this narrowing cannot lose anything.
	return argon2.IDKey(p, s.Salt, s.KDF.Iterations, s.KDF.MemoryKiB, uint8(s.KDF.Parallelism), KeyLen), nil
}

// KeyfileSecret unlocks key-file slots. The key file is 32 random bytes; the
// per-slot salt means the same file used for two containers still produces two
// unrelated wrapping keys.
type KeyfileSecret []byte

func (k KeyfileSecret) slotType() SlotType { return SlotKeyfile }
func (k KeyfileSecret) describe() string   { return "key file" }

func (k KeyfileSecret) kek(s *Slot) ([]byte, error) {
	if len(k) != KeyLen {
		return nil, fmt.Errorf("a key file must be exactly %d bytes, this one is %d", KeyLen, len(k))
	}
	return hkdfKey(k, s.Salt, infoKeyfile)
}

// PlaintextSecret opens the slot written when encryption is switched off.
type PlaintextSecret struct{}

func (PlaintextSecret) slotType() SlotType { return SlotPlaintext }
func (PlaintextSecret) describe() string   { return "unencrypted container" }

func (PlaintextSecret) kek(*Slot) ([]byte, error) { return make([]byte, KeyLen), nil }

// NewSlot wraps fmk so that secret can recover it.
func NewSlot(c Cipher, containerUUID []byte, fmk FMK, secret Unlocker, kdf KDFParams, label string) (*Slot, error) {
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

	s := &Slot{
		Type:  secret.slotType(),
		UUID:  uuid,
		Label: label,
		Nonce: nonce,
		Salt:  salt,
		KDF:   kdf,
	}
	if s.Type == SlotPassphrase {
		if err := kdf.Validate(); err != nil {
			return nil, err
		}
	}

	kek, err := secret.kek(s)
	if err != nil {
		return nil, err
	}
	defer Wipe(kek)

	aead, err := AEAD(c, kek)
	if err != nil {
		return nil, err
	}
	s.Wrapped = aead.Seal(nil, s.Nonce, fmk, s.aad(containerUUID))
	return s, nil
}

// Unwrap recovers the master key from this slot, or reports ErrWrongKey.
func (s *Slot) Unwrap(c Cipher, containerUUID []byte, secret Unlocker) (FMK, error) {
	if secret.slotType() != s.Type {
		return nil, ErrWrongKey
	}
	// A recipient slot does not derive its wrapping key from the secret alone;
	// it comes out of the key exchange stored in the slot itself.
	if r, ok := secret.(RecipientSecret); ok {
		return s.unwrapRecipient(c, containerUUID, r.Private)
	}
	kek, err := secret.kek(s)
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
	if len(fmk) != KeyLen {
		return nil, fmt.Errorf("this slot holds a %d-byte key, want %d", len(fmk), KeyLen)
	}
	return fmk, nil
}

// aad binds the wrapped key to its container, its slot and its parameters, so
// a slot cannot be copied between containers and the cost parameters cannot be
// lowered by an attacker hoping to make guessing cheaper.
func (s *Slot) aad(containerUUID []byte) []byte {
	params := s.Salt
	switch s.Type {
	case SlotPassphrase:
		params = append(append([]byte{}, s.Salt...), s.KDF.encode()...)
	case SlotRecipient:
		// The key exchange is part of what this slot is, so it is bound in too.
		params = append(append([]byte{}, s.Salt...), s.Encapsulation...)
	}
	return SlotAAD(containerUUID, s.UUID, uint8(s.Type), params)
}

func hkdfKey(secret, salt []byte, info string) ([]byte, error) {
	return deriveHKDF(secret, salt, info)
}
