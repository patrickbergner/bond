package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRecipientRoundTrip(t *testing.T) {
	uuid, fmk := newContainer(t)

	seed, err := NewRecipientSeed()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := RecipientFromSeed(seed)
	if err != nil {
		t.Fatalf("RecipientFromSeed: %v", err)
	}

	// Only the public half is needed to write the container.
	slot, err := NewRecipientSlot(CipherXChaCha20Poly1305, uuid, fmk, priv.Public(), "safe")
	if err != nil {
		t.Fatalf("NewRecipientSlot: %v", err)
	}
	if bytes.Contains(slot.Wrapped, fmk) || bytes.Contains(slot.Encapsulation, fmk) {
		t.Fatal("the master key appears in the slot in the clear")
	}

	got, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, RecipientSecret{Private: priv})
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, fmk) {
		t.Error("the recovered key is not the one that was wrapped")
	}

	// A different recipient must not open it.
	otherSeed, _ := NewRecipientSeed()
	other, _ := RecipientFromSeed(otherSeed)
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, RecipientSecret{Private: other}); !errors.Is(err, ErrWrongKey) {
		t.Errorf("another recipient opened the slot: %v", err)
	}
}

func TestRecipientIsDerivedDeterministically(t *testing.T) {
	seed, _ := NewRecipientSeed()
	a, err := RecipientFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RecipientFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Public().Bytes(), b.Public().Bytes()) {
		t.Error("the same seed produced two different public keys")
	}

	// This is what the printed card depends on: 32 bytes on paper regrow both
	// halves, including an ML-KEM key of several kilobytes.
	if len(a.Public().Bytes()) != RecipientPublicLen {
		t.Errorf("public key is %d bytes, want %d", len(a.Public().Bytes()), RecipientPublicLen)
	}
	if len(seed) != 32 {
		t.Errorf("the seed is %d bytes; the card format assumes 32", len(seed))
	}
}

func TestRecipientPublicEncoding(t *testing.T) {
	seed, _ := NewRecipientSeed()
	priv, _ := RecipientFromSeed(seed)

	encoded := priv.Public().Bytes()
	back, err := ParseRecipientPublic(encoded)
	if err != nil {
		t.Fatalf("ParseRecipientPublic: %v", err)
	}
	if !bytes.Equal(back.Bytes(), encoded) {
		t.Error("the public key did not survive a round trip")
	}

	if _, err := ParseRecipientPublic(encoded[:100]); err == nil {
		t.Error("a truncated public key was accepted")
	}
	damaged := append([]byte(nil), encoded...)
	damaged[40] ^= 0xff
	if _, err := ParseRecipientPublic(damaged); err == nil {
		t.Log("a damaged ML-KEM key was accepted; the encoding has no checksum of its own")
	}
}

// Both halves of the hybrid have to matter. If the wrapping key depended on
// only one of them, breaking that one would be enough.
func TestRecipientNeedsBothHalves(t *testing.T) {
	uuid, fmk := newContainer(t)
	seed, _ := NewRecipientSeed()
	priv, _ := RecipientFromSeed(seed)
	slot, _ := NewRecipientSlot(CipherXChaCha20Poly1305, uuid, fmk, priv.Public(), "")

	// Swap in another recipient's X25519 key, keeping the ML-KEM half.
	otherSeed, _ := NewRecipientSeed()
	other, _ := RecipientFromSeed(otherSeed)

	mixed := &RecipientPrivate{X25519: other.X25519, MLKEM: priv.MLKEM}
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, RecipientSecret{Private: mixed}); err == nil {
		t.Error("the slot opened with only the ML-KEM half correct")
	}

	mixed2 := &RecipientPrivate{X25519: priv.X25519, MLKEM: other.MLKEM}
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, RecipientSecret{Private: mixed2}); err == nil {
		t.Error("the slot opened with only the X25519 half correct")
	}
}

func TestRecipientEncapsulationIsAuthenticated(t *testing.T) {
	uuid, fmk := newContainer(t)
	seed, _ := NewRecipientSeed()
	priv, _ := RecipientFromSeed(seed)
	slot, _ := NewRecipientSlot(CipherXChaCha20Poly1305, uuid, fmk, priv.Public(), "")

	tampered := *slot
	tampered.Encapsulation = append([]byte(nil), slot.Encapsulation...)
	tampered.Encapsulation[10] ^= 1
	if _, err := tampered.Unwrap(CipherXChaCha20Poly1305, uuid, RecipientSecret{Private: priv}); err == nil {
		t.Error("a slot with an altered key exchange still opened")
	}
}

func TestRecipientSlotIsBoundToItsContainer(t *testing.T) {
	uuidA, fmk := newContainer(t)
	seed, _ := NewRecipientSeed()
	priv, _ := RecipientFromSeed(seed)
	slot, _ := NewRecipientSlot(CipherXChaCha20Poly1305, uuidA, fmk, priv.Public(), "")

	uuidB, _ := RandomBytes(16)
	if _, err := slot.Unwrap(CipherXChaCha20Poly1305, uuidB, RecipientSecret{Private: priv}); !errors.Is(err, ErrWrongKey) {
		t.Error("a recipient slot opened under a different container UUID")
	}
}

func TestRecipientFromBadSeed(t *testing.T) {
	if _, err := RecipientFromSeed(make([]byte, 16)); err == nil {
		t.Error("a short seed was accepted")
	}
}

func TestRecoveryKeyRoundTrip(t *testing.T) {
	seed, _ := NewRecipientSeed()
	card, err := EncodeRecoveryKey(seed)
	if err != nil {
		t.Fatalf("EncodeRecoveryKey: %v", err)
	}

	if !strings.HasPrefix(card, CardPrefix) {
		t.Errorf("the key does not start with %s: %q", CardPrefix, card)
	}
	// Short enough to write on a card and type back without despair.
	if len(card) > 80 {
		t.Errorf("the recovery key is %d characters long: %q", len(card), card)
	}
	t.Logf("recovery key: %s (%d characters)", card, len(card))

	back, err := DecodeRecoveryKey(card)
	if err != nil {
		t.Fatalf("DecodeRecoveryKey: %v", err)
	}
	if !bytes.Equal(back, seed) {
		t.Error("the seed did not survive the round trip")
	}
}

// Whoever types this back may be doing it years later, from paper, in a hurry.
func TestRecoveryKeyToleratesHumanInput(t *testing.T) {
	seed := bytes.Repeat([]byte{0xa5}, SeedLen)
	card, err := EncodeRecoveryKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	variants := map[string]string{
		"as printed":       card,
		"lower case":       strings.ToLower(card),
		"no hyphens":       strings.ReplaceAll(card, "-", ""),
		"spaces instead":   strings.ReplaceAll(card, "-", " "),
		"trailing newline": card + "\n",
		"wrapped":          strings.ReplaceAll(card, "-", "-\n"),
		"without prefix":   strings.TrimPrefix(card, CardPrefix+"-"),
	}
	for name, v := range variants {
		got, err := DecodeRecoveryKey(v)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, seed) {
			t.Errorf("%s: decoded to the wrong seed", name)
		}
	}
}

// The alphabet leaves out the characters that get misread; the decoder accepts
// the misreadings and maps them back.
func TestRecoveryKeyAcceptsConfusableCharacters(t *testing.T) {
	seed := make([]byte, SeedLen)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	card, _ := EncodeRecoveryKey(seed)

	if strings.ContainsAny(card[len(CardPrefix):], "ILOU") {
		t.Errorf("the encoding used a character the alphabet excludes: %q", card)
	}

	// Someone reads 1 as I, and 0 as O. Only in the body: the "1" in the
	// BOND-R1 prefix is a version number, not part of the encoding.
	body := strings.TrimPrefix(card, CardPrefix)
	confused := CardPrefix + strings.NewReplacer("1", "I", "0", "O").Replace(body)
	got, err := DecodeRecoveryKey(confused)
	if err != nil {
		t.Fatalf("a key with I for 1 and O for 0 was refused: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Error("the confusable characters decoded to the wrong seed")
	}
}

// A key typed wrong must say so, not hand back a seed that opens nothing.
func TestRecoveryKeyChecksum(t *testing.T) {
	seed, _ := NewRecipientSeed()
	card, _ := EncodeRecoveryKey(seed)

	body := []byte(strings.ReplaceAll(card, "-", ""))
	for _, at := range []int{len(CardPrefix) + 1, len(body) / 2, len(body) - 4} {
		wrong := append([]byte(nil), body...)
		// Move one character to a different one in the alphabet.
		for _, c := range []byte(cardAlphabet) {
			if c != wrong[at] {
				wrong[at] = c
				break
			}
		}
		if _, err := DecodeRecoveryKey(string(wrong)); err == nil {
			t.Errorf("a key with a wrong character at %d was accepted", at)
		}
	}

	if _, err := DecodeRecoveryKey("BOND-R1-TOOSHORT"); err == nil {
		t.Error("a short key was accepted")
	}
	if _, err := DecodeRecoveryKey("BOND-R9-ABCDE-ABCDE"); err == nil {
		t.Error("a key from another format version was accepted")
	}
}

func TestRecoveryKeyOpensAContainerSlot(t *testing.T) {
	uuid, fmk := newContainer(t)

	seed, _ := NewRecipientSeed()
	priv, _ := RecipientFromSeed(seed)
	slot, _ := NewRecipientSlot(CipherXChaCha20Poly1305, uuid, fmk, priv.Public(), "printed card")

	// Print it, forget everything else, type it back.
	card, err := EncodeRecoveryKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	typedBack, err := DecodeRecoveryKey(strings.ToLower(card))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := RecipientFromSeed(typedBack)
	if err != nil {
		t.Fatal(err)
	}

	got, err := slot.Unwrap(CipherXChaCha20Poly1305, uuid, RecipientSecret{Private: recovered})
	if err != nil {
		t.Fatalf("the printed recovery key did not open the container: %v", err)
	}
	if !bytes.Equal(got, fmk) {
		t.Error("the recovery key gave the wrong master key")
	}
}
