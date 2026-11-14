// Package crypto holds BOND's key model: one random key per container, several
// independent ways to unlock it, and the authenticated encryption that
// protects the payload.
//
// The shape of it is deliberate. The File Master Key is random and is never
// derived from a passphrase, so changing a passphrase, adding a key file or
// printing a recovery card rewrites 128 KiB of key slots and leaves a
// terabyte of payload untouched. Everything the container needs is derived
// from that one key by HKDF, so no two purposes ever share a key.
package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// KeyLen is the size of every key in the design: the file master key, every
// key-encryption key, and every derived subkey.
const KeyLen = 32

// Domain separation strings. Changing one of these changes the format.
const (
	infoData     = "bond/v2/data"
	infoHeader   = "bond/v2/header"
	infoManifest = "bond/v2/manifest"
	infoCommit   = "bond/v2/commit"
	infoKeyfile  = "bond/v2/keyfile-kek"
	infoSlotEnc  = "bond/v2/slot-enc"
	infoSlotCom  = "bond/v2/slot-com"
)

// FMK is a container's File Master Key. It is generated once, wrapped by every
// key slot, and never leaves memory in the clear.
type FMK []byte

// NewFMK draws a fresh file master key.
func NewFMK() (FMK, error) {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("drawing a file master key: %w", err)
	}
	return k, nil
}

// Keys are the subkeys a container works with. They are always derived
// together, so a caller cannot accidentally use one key for two jobs.
type Keys struct {
	Data     []byte // seals payload shards
	Header   []byte // authenticates the superblock and the key-slot tables
	Manifest []byte // seals the manifest
	Commit   []byte // proves an unlock found the right key

	fmk FMK
}

// Derive expands the file master key into the container's subkeys. The
// container UUID is the HKDF salt, so two containers never share a subkey even
// if they somehow shared a master key.
func Derive(fmk FMK, containerUUID []byte) (*Keys, error) {
	if len(fmk) != KeyLen {
		return nil, fmt.Errorf("file master key is %d bytes, want %d", len(fmk), KeyLen)
	}
	k := &Keys{fmk: fmk}
	for _, sub := range []struct {
		info string
		dst  *[]byte
	}{
		{infoData, &k.Data},
		{infoHeader, &k.Header},
		{infoManifest, &k.Manifest},
		{infoCommit, &k.Commit},
	} {
		key, err := hkdf.Key(sha512.New, fmk, containerUUID, sub.info, KeyLen)
		if err != nil {
			return nil, fmt.Errorf("deriving %s: %w", sub.info, err)
		}
		*sub.dst = key
	}
	return k, nil
}

// FMK returns the master key these subkeys came from, for re-wrapping slots.
func (k *Keys) FMK() FMK { return k.fmk }

// Commitment binds an unlock to one exact master key.
//
// AEAD tags prove that a ciphertext was made with the key that opens it, but
// they do not prove which key that was: without this, a container could in
// principle be crafted to open differently under two different secrets. The
// commitment is checked before anything else is trusted, so an unlock either
// finds the key the container was built with or fails outright.
func (k *Keys) Commitment(containerUUID []byte) []byte {
	mac := hmac.New(sha256.New, k.Commit)
	mac.Write(Tuple([]byte(adCommit), containerUUID))
	return mac.Sum(nil)
}

// CheckCommitment reports whether want matches this key's commitment.
func (k *Keys) CheckCommitment(containerUUID, want []byte) bool {
	return hmac.Equal(k.Commitment(containerUUID), want)
}

// MAC computes the authentication value for header and key-slot bytes.
func MAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// CheckMAC compares a MAC in constant time.
func CheckMAC(key, data, want []byte) bool {
	return hmac.Equal(MAC(key, data), want)
}

// Wipe overwrites key material. Go can copy a slice's contents elsewhere
// before this runs, so it reduces exposure rather than removing it – worth
// doing, not worth relying on.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Wipe clears every derived subkey and the master key.
func (k *Keys) Wipe() {
	if k == nil {
		return
	}
	for _, b := range [][]byte{k.Data, k.Header, k.Manifest, k.Commit, k.fmk} {
		Wipe(b)
	}
}

// deriveHKDF is the one place HKDF is called with a caller-chosen info string.
func deriveHKDF(secret, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha512.New, secret, salt, info, KeyLen)
}

// RandomBytes draws n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// hkdfLong derives a key of arbitrary length, for the few consumers that need
// something other than 32 bytes.
func hkdfLong(secret, salt []byte, info string, n int) ([]byte, error) {
	return hkdf.Key(sha512.New, secret, salt, info, n)
}
