package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// fastKDF keeps the passphrase tests quick. Production parameters are
// deliberately slow, which is the point of them.
var fastKDF = KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1}

func newContainer(t *testing.T) ([]byte, FMK) {
	t.Helper()
	uuid, err := RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	fmk, err := NewFMK()
	if err != nil {
		t.Fatal(err)
	}
	return uuid, fmk
}

func TestDeriveSeparatesSubkeys(t *testing.T) {
	uuid, fmk := newContainer(t)
	k, err := Derive(fmk, uuid)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	subkeys := map[string][]byte{"data": k.Data, "header": k.Header, "manifest": k.Manifest, "commit": k.Commit}
	for nameA, a := range subkeys {
		if len(a) != KeyLen {
			t.Errorf("%s key is %d bytes, want %d", nameA, len(a), KeyLen)
		}
		if bytes.Equal(a, fmk) {
			t.Errorf("%s key equals the master key; the derivation did nothing", nameA)
		}
		for nameB, b := range subkeys {
			if nameA < nameB && bytes.Equal(a, b) {
				t.Errorf("%s and %s keys are identical", nameA, nameB)
			}
		}
	}
}

func TestDeriveIsDeterministicPerContainer(t *testing.T) {
	uuid, fmk := newContainer(t)
	a, _ := Derive(fmk, uuid)
	b, _ := Derive(fmk, uuid)
	if !bytes.Equal(a.Data, b.Data) {
		t.Error("the same master key and container gave different data keys")
	}

	// A different container must not reuse a subkey even with the same master
	// key, which is why the UUID is the HKDF salt.
	other, _ := RandomBytes(16)
	c, _ := Derive(fmk, other)
	if bytes.Equal(a.Data, c.Data) {
		t.Error("two containers derived the same data key from one master key")
	}
}

func TestCommitmentBindsToTheKey(t *testing.T) {
	uuid, fmk := newContainer(t)
	k, _ := Derive(fmk, uuid)

	if !k.CheckCommitment(uuid, k.Commitment(uuid)) {
		t.Error("a key does not match its own commitment")
	}

	_, otherFMK := newContainer(t)
	other, _ := Derive(otherFMK, uuid)
	if other.CheckCommitment(uuid, k.Commitment(uuid)) {
		t.Error("a different master key satisfied the commitment")
	}

	wrong := k.Commitment(uuid)
	wrong[0] ^= 1
	if k.CheckCommitment(uuid, wrong) {
		t.Error("a modified commitment was accepted")
	}
}

func TestPassphraseSlotRoundTrip(t *testing.T) {
	uuid, fmk := newContainer(t)

	slot, err := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, Passphrase("correct horse battery staple"), fastKDF, "primary")
	if err != nil {
		t.Fatalf("NewSlot: %v", err)
	}
	if bytes.Contains(slot.Wrapped, fmk) {
		t.Fatal("the master key appears in the slot in the clear")
	}

	got, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, Passphrase("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, fmk) {
		t.Error("the recovered key is not the one that was wrapped")
	}

	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, Passphrase("wrong")); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a wrong passphrase gave %v, want ErrWrongKey", err)
	}
}

func TestKeyfileSlotRoundTrip(t *testing.T) {
	uuid, fmk := newContainer(t)
	keyfile, _ := RandomBytes(KeyLen)

	slot, err := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, KeyfileSecret(keyfile), KDFParams{}, "usb stick")
	if err != nil {
		t.Fatalf("NewSlot: %v", err)
	}
	got, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, KeyfileSecret(keyfile))
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, fmk) {
		t.Error("the recovered key is not the one that was wrapped")
	}

	other, _ := RandomBytes(KeyLen)
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, KeyfileSecret(other)); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a wrong key file gave %v, want ErrWrongKey", err)
	}
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, KeyfileSecret([]byte("too short"))); err == nil {
		t.Error("a key file of the wrong length was accepted")
	}
}

func TestPlaintextSlotIsOpenToAnyone(t *testing.T) {
	uuid, fmk := newContainer(t)
	slot, err := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, PlaintextSecret{}, KDFParams{}, "")
	if err != nil {
		t.Fatalf("NewSlot: %v", err)
	}
	got, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, PlaintextSecret{})
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, fmk) {
		t.Error("the unencrypted slot did not give the key back")
	}
}

func TestSlotRejectsWrongSecretKind(t *testing.T) {
	uuid, fmk := newContainer(t)
	slot, _ := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, Passphrase("x"), fastKDF, "")
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, KeyfileSecret(make([]byte, KeyLen))); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a key file opened a passphrase slot: %v", err)
	}
}

// A slot lifted out of one container must not open another, even when the
// attacker also controls the passphrase.
func TestSlotIsBoundToItsContainer(t *testing.T) {
	uuidA, fmk := newContainer(t)
	slot, _ := NewSlot(CipherXChaCha20Poly1305, uuidA, fmk, Passphrase("shared"), fastKDF, "")

	uuidB, _ := RandomBytes(16)
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuidB, Passphrase("shared")); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a slot opened under a different container UUID: %v", err)
	}
}

// Lowering the recorded cost would make guessing cheaper, so the parameters
// are part of what the tag covers.
func TestSlotParametersAreAuthenticated(t *testing.T) {
	uuid, fmk := newContainer(t)
	slot, _ := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, Passphrase("secret"), fastKDF, "")

	weakened := *slot
	weakened.KDF.MemoryKiB = 8 * 1024
	weakened.KDF.Iterations = 1
	if weakened.KDF == slot.KDF {
		t.Skip("the test parameters are already minimal")
	}
	if _, err := weakened.Unwrap(CipherXChaCha20Poly1305, uuid, Passphrase("secret")); err == nil {
		t.Error("a slot with weakened cost parameters still unwrapped")
	}

	moved := *slot
	moved.UUID = bytes.Repeat([]byte{9}, 16)
	if _, err := moved.Unwrap(CipherXChaCha20Poly1305, uuid, Passphrase("secret")); !errors.Is(err, ErrWrongKey) {
		t.Error("a slot with a changed identity still unwrapped")
	}
}

func TestSeveralSlotsOpenTheSameContainer(t *testing.T) {
	uuid, fmk := newContainer(t)
	keyfile, _ := RandomBytes(KeyLen)

	pass, _ := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, Passphrase("one"), fastKDF, "passphrase")
	file, _ := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, KeyfileSecret(keyfile), KDFParams{}, "key file")

	fromPass, err := pass.Unwrap(CipherXChaCha20Poly1305, uuid, Passphrase("one"))
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := file.Unwrap(CipherXChaCha20Poly1305, uuid, KeyfileSecret(keyfile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromPass, fromFile) {
		t.Error("two slots of the same container gave different master keys")
	}
}

func TestShardNonceIsUniquePerIndex(t *testing.T) {
	prefix, _ := RandomBytes(16)
	seen := make(map[string]uint64)
	for _, i := range []uint64{0, 1, 2, 255, 256, 1 << 20, 1<<64 - 1} {
		nonce := ShardNonce(prefix, i)
		if len(nonce) != NonceLen {
			t.Fatalf("nonce for shard %d is %d bytes, want %d", i, len(nonce), NonceLen)
		}
		if !bytes.HasPrefix(nonce, prefix) {
			t.Errorf("shard %d: the container prefix is not intact", i)
		}
		if prev, dup := seen[string(nonce)]; dup {
			t.Errorf("shards %d and %d share a nonce", prev, i)
		}
		seen[string(nonce)] = i
	}
}

func TestShardSealing(t *testing.T) {
	uuid, fmk := newContainer(t)
	k, _ := Derive(fmk, uuid)
	aead, err := AEAD(CipherXChaCha20Poly1305, k.Data)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _ := RandomBytes(16)

	plain := bytes.Repeat([]byte("shard contents "), 100)
	const size = 4096
	sealed := aead.Seal(nil, ShardNonce(prefix, 7), plain, ShardAAD(uuid, 7, size))

	got, err := aead.Open(nil, ShardNonce(prefix, 7), sealed, ShardAAD(uuid, 7, size))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("the shard did not survive the round trip")
	}

	// Moving a shard to another index, or into another container, must fail
	// even though the bytes themselves are untouched.
	if _, err := aead.Open(nil, ShardNonce(prefix, 8), sealed, ShardAAD(uuid, 8, size)); err == nil {
		t.Error("a shard authenticated at the wrong index")
	}
	otherUUID, _ := RandomBytes(16)
	if _, err := aead.Open(nil, ShardNonce(prefix, 7), sealed, ShardAAD(otherUUID, 7, size)); err == nil {
		t.Error("a shard authenticated under another container's UUID")
	}

	damaged := append([]byte(nil), sealed...)
	damaged[len(damaged)/2] ^= 1
	if _, err := aead.Open(nil, ShardNonce(prefix, 7), damaged, ShardAAD(uuid, 7, size)); err == nil {
		t.Error("a flipped bit was not detected")
	}
}

func TestMAC(t *testing.T) {
	key, _ := RandomBytes(KeyLen)
	data := []byte("header bytes")
	mac := MAC(key, data)
	if !CheckMAC(key, data, mac) {
		t.Error("a MAC did not verify against its own input")
	}
	if CheckMAC(key, append(data, '!'), mac) {
		t.Error("a MAC verified against different data")
	}
	other, _ := RandomBytes(KeyLen)
	if CheckMAC(other, data, mac) {
		t.Error("a MAC verified under a different key")
	}
}

func TestKDFValidate(t *testing.T) {
	if err := DefaultKDF.Validate(); err != nil {
		t.Errorf("the default profile is invalid: %v", err)
	}
	if err := LowMemoryKDF.Validate(); err != nil {
		t.Errorf("the low-memory profile is invalid: %v", err)
	}
	for _, bad := range []KDFParams{
		{MemoryKiB: 64, Iterations: 3, Parallelism: 4},
		{MemoryKiB: 512 * 1024, Iterations: 0, Parallelism: 4},
		{MemoryKiB: 512 * 1024, Iterations: 3, Parallelism: 0},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestWipe(t *testing.T) {
	uuid, fmk := newContainer(t)
	k, _ := Derive(fmk, uuid)
	k.Wipe()
	for name, b := range map[string][]byte{"data": k.Data, "header": k.Header, "manifest": k.Manifest, "commit": k.Commit, "fmk": fmk} {
		for _, v := range b {
			if v != 0 {
				t.Errorf("%s key still holds data after Wipe", name)
				break
			}
		}
	}
	var nilKeys *Keys
	nilKeys.Wipe()
}

// Argon2 takes its lane count as a single byte, and the slot stores a uint32
// that is bound into the associated data. Quietly narrowing a larger number
// would make BOND derive a key from parameters the slot does not record: it
// would still open the container, and the by-hand recovery procedure, which
// says to use the stored values, would not.
func TestTooManyLanesIsRefusedRatherThanClamped(t *testing.T) {
	params := KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 256}
	if err := params.Validate(); err == nil {
		t.Fatal("a lane count that does not fit in a byte was accepted")
	}

	uuid := make([]byte, 16)
	fmk, err := NewFMK()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSlot(CipherXChaCha20Poly1305, uuid, fmk, Passphrase("x"), params, "too many lanes"); err == nil {
		t.Error("a slot was written with a lane count it cannot record")
	}

	// The largest value that does fit still works.
	params.Parallelism = 255
	if err := params.Validate(); err != nil {
		t.Errorf("255 lanes should be allowed: %v", err)
	}
}

func TestKDFPolicyBoundsUnauthenticatedWork(t *testing.T) {
	accepted := []KDFParams{
		DefaultKDF,
		{MemoryKiB: 1024 * 1024, Iterations: 3, Parallelism: 8},
		{MemoryKiB: 512 * 1024, Iterations: 6, Parallelism: 64},
	}
	for _, params := range accepted {
		if err := params.Check(DefaultKDFPolicy); err != nil {
			t.Errorf("default policy rejected %+v: %v", params, err)
		}
	}
	rejected := []KDFParams{
		{MemoryKiB: 1024*1024 + 1, Iterations: 1, Parallelism: 1},
		{MemoryKiB: 8 * 1024, Iterations: 7, Parallelism: 1},
		{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 65},
		{MemoryKiB: 1024 * 1024, Iterations: 4, Parallelism: 1},
	}
	for _, params := range rejected {
		if err := params.Check(DefaultKDFPolicy); !errors.Is(err, ErrKDFPolicy) {
			t.Errorf("default policy accepted %+v: %v", params, err)
		}
		unlimited := DefaultKDFPolicy
		unlimited.AllowExpensive = true
		if err := params.Check(unlimited); err != nil {
			t.Errorf("explicit override rejected format-valid %+v: %v", params, err)
		}
	}
}
