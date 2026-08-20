package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// The recovery key is the one piece of BOND a human retypes, years later, from
// a card in a safe, possibly having lost the tool that wrote it. Everything
// about the decoder is therefore about being generous with the input without
// ever being generous with the answer: it accepts any case, any hyphenation and
// the characters people misread, and it either returns the exact seed or an
// error.

func FuzzDecodeRecoveryKey(f *testing.F) {
	seed := make([]byte, SeedLen)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	if card, err := EncodeRecoveryKey(seed); err == nil {
		f.Add(card)
		f.Add(strings.ToLower(card))
		f.Add(strings.ReplaceAll(card, "-", ""))
	}
	f.Add("")
	f.Add("BOND-R1-")
	f.Add("BOND-R9-AAAA")
	f.Add(strings.Repeat("A", 200))

	f.Fuzz(func(t *testing.T, s string) {
		got, err := DecodeRecoveryKey(s)
		if err != nil {
			return
		}
		// Accepted, so it must be a key of the right size – a short or long
		// answer would be handed straight to the key derivation.
		if len(got) != SeedLen {
			t.Fatalf("DecodeRecoveryKey(%q) returned %d bytes, want %d", s, len(got), SeedLen)
		}
	})
}

// Whatever a card is put through on its way back – lower case, no hyphens,
// spaces, the letters Crockford's alphabet exists to disambiguate – it has to
// come back as the same seed.
func FuzzRecoveryKeySurvivesRetyping(f *testing.F) {
	f.Add(make([]byte, SeedLen), uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, SeedLen), uint8(3))

	f.Fuzz(func(t *testing.T, seed []byte, mangle uint8) {
		if len(seed) != SeedLen {
			return
		}
		card, err := EncodeRecoveryKey(seed)
		if err != nil {
			t.Fatalf("EncodeRecoveryKey: %v", err)
		}

		typed := card
		switch mangle % 5 {
		case 0:
			typed = strings.ToLower(card)
		case 1:
			typed = strings.ReplaceAll(card, "-", "")
		case 2:
			typed = strings.ReplaceAll(card, "-", " ")
		case 3:
			// The characters the alphabet leaves out, as someone reading a
			// printed card would produce them. Only the body is touched: the
			// version prefix is not base32 and is not the operator's to guess.
			body := strings.TrimPrefix(card, CardPrefix)
			body = strings.NewReplacer("1", "I", "0", "O").Replace(body)
			typed = CardPrefix + body
		case 4:
			typed = "  " + card + "\r\n"
		}

		got, err := DecodeRecoveryKey(typed)
		if err != nil {
			t.Fatalf("a card retyped as %q did not decode: %v", typed, err)
		}
		if !bytes.Equal(got, seed) {
			t.Fatalf("a card retyped as %q decoded to a different seed", typed)
		}
	})
}
