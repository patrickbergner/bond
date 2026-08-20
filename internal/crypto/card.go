package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
)

// A recovery key is a recipient seed written down.
//
// It is meant to be printed, put in a safe, and one day typed back in by
// someone under stress – possibly not the person who wrote it. Everything
// about the encoding serves that: Crockford's base32 alphabet leaves out the
// letters that get confused for digits, the decoder accepts the confusions
// anyway and folds case, hyphens are ignored wherever they fall, and a
// checksum catches what is left before a wrong key becomes a wrong answer.

// cardAlphabet is Crockford base32: no I, L, O or U. I and L look like 1, O
// looks like 0, and U is left out so the encoding cannot spell anything
// unfortunate.
const cardAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CardPrefix opens every recovery key, so a stray line of text is recognisable
// as one, and the version is there for the day the format changes.
const CardPrefix = "BOND-R1"

const (
	cardChecksumLen = 2
	cardGroup       = 5
)

var cardDecodeTable = buildCardDecodeTable()

func buildCardDecodeTable() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i, c := range cardAlphabet {
		t[c] = int8(i)
		if c >= 'A' && c <= 'Z' {
			t[c+32] = int8(i) // lower case
		}
	}
	// The confusions Crockford's alphabet avoids, accepted on the way in.
	for _, p := range []struct {
		from byte
		to   byte
	}{
		{'I', '1'}, {'i', '1'}, {'L', '1'}, {'l', '1'},
		{'O', '0'}, {'o', '0'},
	} {
		t[p.from] = t[p.to]
	}
	return t
}

// EncodeRecoveryKey renders a seed as a printable recovery key.
func EncodeRecoveryKey(seed []byte) (string, error) {
	if len(seed) != SeedLen {
		return "", fmt.Errorf("a recovery key holds %d bytes, this is %d", SeedLen, len(seed))
	}

	body := append(append([]byte(nil), seed...), cardChecksum(seed)...)
	encoded := base32Encode(body)

	var b strings.Builder
	b.WriteString(CardPrefix)
	for i := 0; i < len(encoded); i += cardGroup {
		b.WriteByte('-')
		b.WriteString(encoded[i:min(i+cardGroup, len(encoded))])
	}
	return b.String(), nil
}

// DecodeRecoveryKey reads a recovery key back, whatever the operator's
// keyboard, case or hyphenation did to it.
func DecodeRecoveryKey(s string) ([]byte, error) {
	cleaned := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
			continue
		default:
			cleaned = append(cleaned, c)
		}
	}

	// The prefix is matched with its hyphen already removed, like everything
	// else here. It is optional on the way in: someone who copied only the
	// body of the key has not made a mistake worth refusing.
	upper := strings.ToUpper(string(cleaned))
	bare := strings.ReplaceAll(CardPrefix, "-", "")
	trimmed := strings.TrimPrefix(upper, bare)
	if trimmed == upper && strings.HasPrefix(upper, "BOND") {
		return nil, fmt.Errorf("this looks like a recovery key from another version of BOND; this build reads %s", CardPrefix)
	}

	decoded, err := base32Decode(trimmed)
	if err != nil {
		return nil, err
	}
	if len(decoded) < SeedLen+cardChecksumLen {
		return nil, fmt.Errorf("this recovery key is too short: %d characters where %d are expected",
			len(trimmed), base32Len(SeedLen+cardChecksumLen))
	}
	seed, sum := decoded[:SeedLen], decoded[SeedLen:SeedLen+cardChecksumLen]

	if subtle.ConstantTimeCompare(sum, cardChecksum(seed)) != 1 {
		return nil, fmt.Errorf("this recovery key does not check out; a character was probably misread")
	}
	return seed, nil
}

// cardChecksum is what catches a transcription slip. Two bytes is not
// integrity – nothing here is secret or adversarial – it is enough to make a
// mistyped key say so instead of quietly failing to open the backup.
func cardChecksum(seed []byte) []byte {
	sum := sha256.Sum256(append([]byte("BOND-RECOVERY-V1"), seed...))
	return sum[:cardChecksumLen]
}

func base32Len(n int) int { return (n*8 + 4) / 5 }

func base32Encode(b []byte) string {
	var out strings.Builder
	out.Grow(base32Len(len(b)))

	var buf, bits uint32
	for _, c := range b {
		buf = buf<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(cardAlphabet[(buf>>bits)&31])
		}
	}
	if bits > 0 {
		out.WriteByte(cardAlphabet[(buf<<(5-bits))&31])
	}
	return out.String()
}

func base32Decode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)*5/8)

	var buf, bits uint32
	for i := 0; i < len(s); i++ {
		v := cardDecodeTable[s[i]]
		if v < 0 {
			return nil, fmt.Errorf("%q is not a character a recovery key can contain", string(s[i]))
		}
		buf = buf<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}
