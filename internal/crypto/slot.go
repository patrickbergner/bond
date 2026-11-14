package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// SlotType is how one key slot is unlocked.
type SlotType uint8

const (
	SlotPassphrase SlotType = 1
	SlotKeyfile    SlotType = 2

	// SlotPlaintext wraps the master key under an all-zero key-encryption key.
	// It is what "encryptionMethod: NONE" produces: tags still detect accidental
	// corruption, but anyone holding the container can open it and can therefore
	// create replacement data with valid tags. Reusing the
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

// ErrSlotDamaged means the secret is the right one for a slot – its key
// commitment matches – and the wrapped master key inside still does not open.
// That is damage or tampering, not a mistyped passphrase, and it is worth
// telling apart: the answer to one is "try again" and to the other "use the
// spare table, or another key".
var ErrSlotDamaged = errors.New("the key matches this slot, but the master key stored in it is damaged")

// CommitmentLen is the size of a slot's key commitment.
const CommitmentLen = 32

// KDFParams are Argon2id's cost settings, stored per slot so they can be
// raised for new containers without invalidating old ones.
type KDFParams struct {
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint32 `json:"parallelism"`
}

// DefaultKDF is what every passphrase slot is written with: well under a second
// on a current desktop, and 512 MiB of memory that an attacker has to find for
// every single guess. "bond bench-kdf" measures what it costs on a machine;
// there is no setting that selects another profile.
var DefaultKDF = KDFParams{MemoryKiB: 512 * 1024, Iterations: 3, Parallelism: 4}

// LowMemoryKDF is RFC 9106's second recommended profile, for machines that
// cannot spare half a gigabyte. It is weaker. Nothing writes a slot with it;
// bench-kdf times it for comparison.
var LowMemoryKDF = KDFParams{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 4}

// ErrKDFPolicy means a valid Argon2 profile exceeds the amount of
// unauthenticated work this process is willing to perform. Slot parameters are
// not authenticated until after a key has been recovered, so format validity
// alone is not a safe admission policy for them.
var ErrKDFPolicy = errors.New("argon2 parameters exceed the local safety policy")

// KDFPolicy bounds one Argon2 derivation and the number of derivations an
// unlock may start. Work is measured as KiB-passes: memoryKiB * iterations.
//
// The two halves do different jobs. The cost limits bound what a single edited
// slot record can demand – the memory ceiling is the one that matters, because
// a four-byte lie about MemoryKiB is otherwise a request for petabytes.
// MaxDerivations bounds how many times that cost can be paid, because a table
// may declare up to maxSlots slots and each is tried against every secret
// offered.
//
// There is deliberately no cumulative *work* ceiling. Any such number is either
// above slots × MaxWorkKiBPasses, in which case the per-derivation cap already
// enforces it, or below it – in which case it refuses containers BOND itself
// wrote. An earlier version used six GiB-passes, which is four derivations at
// the default profile: a perfectly ordinary container with five passphrase
// slots then failed to open, reporting that its own default parameters exceeded
// the safety policy and suggesting --allow-expensive-kdf. Bounding the count
// says the same thing about hostile input without lying about legitimate input.
type KDFPolicy struct {
	MaxMemoryKiB     uint32
	MaxIterations    uint32
	MaxParallelism   uint32
	MaxWorkKiBPasses uint64
	MaxDerivations   uint32
	AllowExpensive   bool
}

// DefaultKDFPolicy accepts the normal profile and modestly stronger archival
// profiles without allowing a damaged slot to consume unbounded resources.
//
// MaxDerivations is twice the largest slot table the format allows, so every
// slot of a full container gets a turn against two offered secrets before the
// limit is anywhere near. Memory stays bounded at MaxMemoryKiB throughout,
// because the derivations run one after another.
var DefaultKDFPolicy = KDFPolicy{
	MaxMemoryKiB:     1024 * 1024,
	MaxIterations:    6,
	MaxParallelism:   64,
	MaxWorkKiBPasses: 3 * 1024 * 1024,
	MaxDerivations:   64,
}

// Work is the memory-pass product used by the reader's cumulative budget.
func (p KDFParams) Work() uint64 { return uint64(p.MemoryKiB) * uint64(p.Iterations) }

// Check applies local resource limits after checking permanent format rules.
func (p KDFParams) Check(policy KDFPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if policy.AllowExpensive {
		return nil
	}
	switch {
	case p.MemoryKiB > policy.MaxMemoryKiB:
		return fmt.Errorf("%w: memory is %d KiB, limit is %d KiB", ErrKDFPolicy, p.MemoryKiB, policy.MaxMemoryKiB)
	case p.Iterations > policy.MaxIterations:
		return fmt.Errorf("%w: passes are %d, limit is %d", ErrKDFPolicy, p.Iterations, policy.MaxIterations)
	case p.Parallelism > policy.MaxParallelism:
		return fmt.Errorf("%w: lanes are %d, limit is %d", ErrKDFPolicy, p.Parallelism, policy.MaxParallelism)
	case p.Work() > policy.MaxWorkKiBPasses:
		return fmt.Errorf("%w: work is %d KiB-passes, limit is %d", ErrKDFPolicy, p.Work(), policy.MaxWorkKiBPasses)
	}
	return nil
}

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

	// Commitment binds the slot to the one key-encryption key that made it.
	//
	// An AEAD tag does not do that: XChaCha20-Poly1305 does not commit to its
	// key, so a wrapped key can be built that opens under several
	// key-encryption keys at once. With that, whoever stores a container can
	// swap in a slot that opens under a whole set of candidate passphrases
	// and learn from how the reader fails which set the real one is in – many
	// guesses for the price of one unlock. The commitment is checked before
	// anything is decrypted, and a secret that does not match it is a wrong
	// key and nothing more.
	Commitment []byte // 32 bytes

	Salt []byte    // 16 bytes; passphrase and keyfile slots
	KDF  KDFParams // passphrase slots only

	// Encapsulation carries a recipient slot's ephemeral public key and
	// ML-KEM ciphertext. Empty for every other slot type.
	Encapsulation []byte
}

// DisplayLabel is the label made safe to print.
//
// A label is read from the slot table before anything has authenticated it, and
// it is free text: whoever stores the container can put terminal control
// sequences into it, and "bond keys list" would send them to the operator's
// terminal. Everything that prints a label prints this.
func (s *Slot) DisplayLabel() string { return Printable(s.Label) }

// Printable replaces what a terminal would act on rather than show: control
// characters, the C1 range, bidirectional overrides, and bytes that are not
// valid UTF-8.
func Printable(text string) string {
	clean := true
	for _, r := range text {
		if unprintable(r) {
			clean = false
			break
		}
	}
	if clean {
		return text
	}
	out := make([]rune, 0, len(text))
	for _, r := range text {
		if unprintable(r) {
			r = '?'
		}
		out = append(out, r)
	}
	return string(out)
}

func unprintable(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0xFFFD: // also what a byte that is not UTF-8 decodes to
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
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
	// The passphrase is hashed in Unicode normalization form C. The same
	// characters reach a program as different bytes depending on the keyboard
	// and the operating system – an umlaut typed on macOS may arrive as a
	// letter followed by a combining mark, on Windows as one code point – and a
	// backup written on one and restored on the other would otherwise be
	// refused its own passphrase. Bytes that are not text pass through as they
	// are.
	// Append into a buffer of its own: Bytes hands back its argument when
	// nothing needed changing, and wiping that would wipe the caller's
	// passphrase.
	normalized := norm.NFC.Append(make([]byte, 0, len(p)), p...)
	defer Wipe(normalized)
	// Validate has already refused a lane count that does not fit in the byte
	// Argon2 takes, so this narrowing cannot lose anything.
	return argon2.IDKey(normalized, s.Salt, s.KDF.Iterations, s.KDF.MemoryKiB, uint8(s.KDF.Parallelism), KeyLen), nil
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

	if err := s.seal(c, containerUUID, kek, fmk); err != nil {
		return nil, err
	}
	return s, nil
}

// Reseal wraps fmk again in a slot whose identifiers, salt and nonce are
// already set, instead of drawing fresh ones.
//
// It exists for known-answer vectors, which need a slot whose every random
// input is fixed so that the wrapped key and its commitment can be compared
// byte for byte. Nothing that writes a container uses it: a nonce chosen by
// the caller is a nonce that can be chosen twice.
func (s *Slot) Reseal(c Cipher, containerUUID []byte, fmk FMK, secret Unlocker) error {
	if secret.slotType() != s.Type || s.Type == SlotRecipient {
		return fmt.Errorf("a %s slot cannot be resealed with this secret", s.Type)
	}
	kek, err := secret.kek(s)
	if err != nil {
		return err
	}
	defer Wipe(kek)
	return s.seal(c, containerUUID, kek, fmk)
}

// slotKeys splits a key-encryption key into the key that wraps the master key
// and the key that commits to it, so neither job borrows the other's key.
func slotKeys(kek []byte) (enc, com []byte, err error) {
	if enc, err = deriveHKDF(kek, nil, infoSlotEnc); err != nil {
		return nil, nil, err
	}
	if com, err = deriveHKDF(kek, nil, infoSlotCom); err != nil {
		Wipe(enc)
		return nil, nil, err
	}
	return enc, com, nil
}

// seal wraps the master key under kek and records the commitment to kek.
func (s *Slot) seal(c Cipher, containerUUID, kek []byte, fmk FMK) error {
	enc, com, err := slotKeys(kek)
	if err != nil {
		return err
	}
	defer Wipe(enc)
	defer Wipe(com)

	aead, err := AEAD(c, enc)
	if err != nil {
		return err
	}
	aad := s.aad(containerUUID)
	s.Commitment = MAC(com, Tuple(s.Nonce, aad))
	s.Wrapped = aead.Seal(nil, s.Nonce, fmk, aad)
	return nil
}

// open is the reverse of seal. The commitment is checked first and in constant
// time: a key that does not match it is ErrWrongKey before any decryption.
func (s *Slot) open(c Cipher, containerUUID, kek []byte) (FMK, error) {
	enc, com, err := slotKeys(kek)
	if err != nil {
		return nil, err
	}
	defer Wipe(enc)
	defer Wipe(com)

	aad := s.aad(containerUUID)
	if !CheckMAC(com, Tuple(s.Nonce, aad), s.Commitment) {
		return nil, ErrWrongKey
	}
	aead, err := AEAD(c, enc)
	if err != nil {
		return nil, err
	}
	fmk, err := aead.Open(nil, s.Nonce, s.Wrapped, aad)
	if err != nil {
		return nil, ErrSlotDamaged
	}
	if len(fmk) != KeyLen {
		Wipe(fmk)
		return nil, fmt.Errorf("this slot holds a %d-byte key, want %d", len(fmk), KeyLen)
	}
	return fmk, nil
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
	return s.open(c, containerUUID, kek)
}

// aad binds the wrapped key to its container, its slot and its parameters, so
// a slot cannot be copied between containers and the cost parameters cannot be
// lowered by an attacker hoping to make guessing cheaper.
func (s *Slot) aad(containerUUID []byte) []byte {
	var params []byte
	switch s.Type {
	case SlotPassphrase:
		params = s.KDF.encode()
	case SlotRecipient:
		// The key exchange is part of what this slot is, so it is bound in too.
		params = s.Encapsulation
	}
	return SlotAAD(containerUUID, s.UUID, uint8(s.Type), s.Salt, params)
}

func hkdfKey(secret, salt []byte, info string) ([]byte, error) {
	return deriveHKDF(secret, salt, info)
}
