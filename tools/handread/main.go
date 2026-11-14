// Command handread decrypts a BOND format 2.0 container without BOND.
//
// It is the procedure of NERDME.md §11 written out, and it deliberately shares
// no code with the rest of this repository: nothing under internal/ is
// imported, every offset and label below is typed in from the document, and the
// only dependencies are the primitives the document names. That is what makes
// it worth having. The format's own tests are written against the format's own
// constants, so a constant that moved would move in both and every test would
// still pass; this reader would stop working.
//
// It handles what §11 handles – a passphrase or key-file slot, one file or a
// split set, with or without recovery data, and a writer signature when it is
// told which writer to expect – and nothing else. It does not
// repair, does not use parity, and stops at the first thing that does not
// authenticate. The result is the compressed stream: an xz stream, or a tar if
// the manifest says "compression": "none".
//
//	go run ./tools/handread -passphrase-file pass.txt -o stream.xz backup.bond
//	go run ./tools/handread -keyfile usb.key backup.bond.001 backup.bond.002 | xz -d | tar -xf -
//	go run ./tools/handread -expect-writer writer.key.pub -passphrase-file pass.txt backup.bond >/dev/null
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"
)

func main() {
	var passphraseFile, keyfile, out, expectWriter string
	flag.StringVar(&passphraseFile, "passphrase-file", "", "file whose first line is the passphrase")
	flag.StringVar(&expectWriter, "expect-writer", "", "a .pub file from \"bond keygen --signing-key\"; refuse anything it did not sign")
	flag.StringVar(&keyfile, "keyfile", "", "32-byte key file")
	flag.StringVar(&out, "o", "", "where to write the stream (default: standard output)")
	flag.Parse()

	var s secret
	switch {
	case passphraseFile != "" && keyfile == "":
		data, err := os.ReadFile(passphraseFile)
		fail(err)
		line, _, _ := strings.Cut(string(data), "\n")
		s.passphrase = []byte(strings.TrimRight(line, "\r"))
	case keyfile != "" && passphraseFile == "":
		data, err := os.ReadFile(keyfile)
		fail(err)
		s.keyfile = data
	default:
		fail(errors.New("give exactly one of -passphrase-file and -keyfile, then the container's files in order"))
	}

	if expectWriter != "" {
		data, err := os.ReadFile(expectWriter)
		fail(err)
		s.writer, err = parseWriterPublic(string(data))
		fail(err)
	}

	stream, _, err := read(flag.Args(), s)
	fail(err)
	if out == "" {
		_, err = os.Stdout.Write(stream)
	} else {
		err = os.WriteFile(out, stream, 0o600)
	}
	fail(err)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "handread:", err)
		os.Exit(1)
	}
}

// secret is a passphrase or the bytes of a key file.
type secret struct {
	passphrase []byte
	keyfile    []byte
	writer     []byte // a writer's public key, Ed25519 ‖ ML-DSA-65; nil when none is expected
}

// parseWriterPublic reads the bondwp1… line of a writer's .pub file.
func parseWriterPublic(text string) ([]byte, error) {
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if body, ok := strings.CutPrefix(line, "bondwp1"); ok {
			key, err := base64.RawURLEncoding.DecodeString(body)
			if err != nil || len(key) != 32+mldsa.MLDSA65PublicKeySize {
				return nil, errors.New("the writer public key is damaged")
			}
			return key, nil
		}
	}
	return nil, errors.New("no line starting with bondwp1 was found")
}

// checkWriter verifies a volume's writer signature and its payload digest,
// NERDME §11 step 8. Neither needs a decryption key.
func checkWriter(file []byte, h *header, pub []byte, first bool) error {
	if binary.LittleEndian.Uint32(h.raw[276:]) != 1 {
		return errors.New("the volume is not signed")
	}
	fingerprint := sha256.Sum256(pub)
	if !bytes.Equal(h.raw[280:312], fingerprint[:]) {
		return errors.New("the volume is signed by another writer")
	}
	const sigEnd = 312 + ed25519.SignatureSize + mldsa.MLDSA65SignatureSize
	signed := append([]byte(nil), h.raw...)
	clear(signed[208:240])
	clear(signed[312:sigEnd])
	msg := tuple([]byte("BOND-WRITER-V2"), signed)
	sig := h.raw[312:sigEnd]
	if !ed25519.Verify(ed25519.PublicKey(pub[:32]), msg, sig[:ed25519.SignatureSize]) {
		return errors.New("the Ed25519 signature does not verify")
	}
	mlPub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub[32:])
	if err != nil {
		return err
	}
	if err := mldsa.Verify(mlPub, msg, sig[ed25519.SignatureSize:], &mldsa.Options{Context: "BOND-WRITER-V2"}); err != nil {
		return errors.New("the ML-DSA signature does not verify")
	}
	start := uint64(headerSize)
	if first {
		start = payloadOffset
	}
	if start+h.logicalLen > uint64(len(file)) {
		return errors.New("the volume is shorter than its payload")
	}
	if sum := sha256.Sum256(file[start : start+h.logicalLen]); !bytes.Equal(sum[:], h.raw[244:276]) {
		return errors.New("the payload is not what the writer signed")
	}
	return nil
}

// Fixed sizes and offsets, NERDME §2 and §3.
const (
	headerSize    = 4096
	slotTableA    = 4096
	slotTableSize = 65536
	payloadOffset = 135168
	tagLen        = 16
)

// header is the part of a superblock this reader needs, NERDME §3.
type header struct {
	raw            []byte
	parityID       uint32
	shardSize      uint32
	k, p           uint32
	dataShardCount uint64
	paddedLength   uint64
	uuid           []byte
	noncePrefix    []byte
	tailOffset     uint64
	tailLength     uint64
	volumeIndex    uint32
	volumeCount    uint32
	logicalStart   uint64
	logicalLen     uint64
	commitment     []byte
	mac            []byte
	lastShardBytes uint32
}

func parseHeader(b []byte) (*header, error) {
	if len(b) < headerSize || !bytes.Equal(b[0:8], []byte{'B', 'O', 'N', 'D', 0x00, '\r', 0x1a, '\n'}) {
		return nil, errors.New("not a BOND container")
	}
	le := binary.LittleEndian
	if major, minor := le.Uint16(b[8:]), le.Uint16(b[10:]); major != 2 || minor != 0 {
		return nil, fmt.Errorf("format %d.%d; this reader knows 2.0", major, minor)
	}
	if cipher := le.Uint32(b[24:]); cipher != 1 {
		return nil, fmt.Errorf("cipher id %d; this reader knows 1, XChaCha20-Poly1305", cipher)
	}
	return &header{
		raw:            append([]byte(nil), b[:headerSize]...),
		parityID:       le.Uint32(b[32:]),
		shardSize:      le.Uint32(b[36:]),
		k:              le.Uint32(b[40:]),
		p:              le.Uint32(b[44:]),
		dataShardCount: le.Uint64(b[48:]),
		paddedLength:   le.Uint64(b[56:]),
		uuid:           b[72:88],
		noncePrefix:    b[88:104],
		tailOffset:     le.Uint64(b[104:]),
		tailLength:     le.Uint64(b[112:]),
		volumeIndex:    le.Uint32(b[152:]),
		volumeCount:    le.Uint32(b[156:]),
		logicalStart:   le.Uint64(b[160:]),
		logicalLen:     le.Uint64(b[168:]),
		commitment:     b[176:208],
		mac:            b[208:240],
		lastShardBytes: le.Uint32(b[240:]),
	}, nil
}

// tuple is T(x₁, …, xₙ) of NERDME §4: each value preceded by its length as a
// little-endian uint32.
func tuple(fields ...[]byte) []byte {
	var out []byte
	for _, f := range fields {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

func hkdf512(secret, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha512.New, secret, salt, info, 32)
}

func hmac256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// masterKey walks one key-slot table and returns the master key from the first
// slot the secret opens. NERDME §11 steps 2 and 3.
func masterKey(table []byte, h *header, s secret) ([]byte, error) {
	le := binary.LittleEndian
	if len(table) < slotTableSize || string(table[0:4]) != "BSLT" {
		return nil, errors.New("no key-slot table at this position")
	}
	if v := le.Uint16(table[4:]); v != 2 {
		return nil, fmt.Errorf("key-slot table version %d; this reader knows 2", v)
	}
	count := int(le.Uint16(table[6:]))
	used := int(le.Uint32(table[16:]))
	if used > slotTableSize-64 {
		return nil, errors.New("key-slot table claims more records than it can hold")
	}
	records := table[64 : 64+used]

	for i := 0; i < count; i++ {
		if len(records) < 112 {
			return nil, errors.New("key-slot record is truncated")
		}
		size := int(le.Uint32(records[0:]))
		if size < 112 || size > len(records) {
			return nil, errors.New("key-slot record has an impossible size")
		}
		rec := records[:size]
		records = records[size:]

		slotType := rec[6]
		slotUUID, nonce, salt := rec[8:24], rec[24:48], rec[48:64]
		kdfParams := rec[64:76] // memory KiB, passes, lanes
		wrapLen := int(le.Uint32(rec[76:]))
		commitment := rec[80:112]
		if 112+wrapLen > size {
			return nil, errors.New("key-slot record has an impossible wrapped length")
		}
		wrapped := rec[112 : 112+wrapLen]

		var kek, params []byte
		var err error
		switch {
		case slotType == 1 && s.passphrase != nil:
			kek = argon2.IDKey(norm.NFC.Bytes(s.passphrase), salt,
				le.Uint32(kdfParams[4:]), le.Uint32(kdfParams[0:]), uint8(le.Uint32(kdfParams[8:])), 32)
			params = kdfParams
		case slotType == 2 && s.keyfile != nil:
			kek, err = hkdf512(s.keyfile, salt, "bond/v2/keyfile-kek")
			if err != nil {
				return nil, err
			}
		default:
			continue // not a slot this secret is for
		}

		enc, err := hkdf512(kek, nil, "bond/v2/slot-enc")
		if err != nil {
			return nil, err
		}
		com, err := hkdf512(kek, nil, "bond/v2/slot-com")
		if err != nil {
			return nil, err
		}
		aad := tuple([]byte("BOND-SLOT-V2"), h.uuid, slotUUID, []byte{slotType}, salt, params)
		if !hmac.Equal(hmac256(com, tuple(nonce, aad)), commitment) {
			continue // the wrong secret for this slot
		}
		aead, err := chacha20poly1305.NewX(enc)
		if err != nil {
			return nil, err
		}
		fmk, err := aead.Open(nil, nonce, wrapped, aad)
		if err != nil {
			return nil, errors.New("the secret matches a slot whose wrapped key is damaged")
		}
		return fmk, nil
	}
	return nil, errors.New("the secret opens no slot of this table")
}

// read decrypts the container stored in paths, which are its files in order.
// It returns the compressed stream and the manifest as JSON.
func read(paths []string, s secret) (stream, manifest []byte, err error) {
	if len(paths) == 0 {
		return nil, nil, errors.New("no container file was named")
	}
	files := make([][]byte, len(paths))
	headers := make([]*header, len(paths))
	for i, path := range paths {
		if files[i], err = os.ReadFile(path); err != nil {
			return nil, nil, err
		}
		// Step 1: the header at the front; the mirror in the last 4096 bytes if
		// the front one is not a header.
		if headers[i], err = parseHeader(files[i]); err != nil && len(files[i]) >= headerSize {
			headers[i], err = parseHeader(files[i][len(files[i])-headerSize:])
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	h := headers[0]
	if int(h.volumeCount) != len(paths) {
		return nil, nil, fmt.Errorf("this container is in %d files, %d were given", h.volumeCount, len(paths))
	}

	// Steps 2 and 3: table A, then table B.
	var fmk []byte
	for _, at := range []int{slotTableA, slotTableA + slotTableSize} {
		if len(files[0]) < at+slotTableSize {
			break
		}
		if fmk, err = masterKey(files[0][at:at+slotTableSize], h, s); err == nil {
			break
		}
	}
	if fmk == nil {
		return nil, nil, err
	}

	// Step 4: the subkeys.
	dataKey, err := hkdf512(fmk, h.uuid, "bond/v2/data")
	if err != nil {
		return nil, nil, err
	}
	manifestKey, _ := hkdf512(fmk, h.uuid, "bond/v2/manifest")
	headerKey, _ := hkdf512(fmk, h.uuid, "bond/v2/header")
	commitKey, _ := hkdf512(fmk, h.uuid, "bond/v2/commit")

	// The header of every file is authenticated before any offset in it is used.
	for i, vh := range headers {
		signable := append([]byte(nil), vh.raw...)
		clear(signable[208:240])
		if !hmac.Equal(hmac256(headerKey, signable), vh.mac) {
			return nil, nil, fmt.Errorf("%s: the header fails authentication", paths[i])
		}
		if !bytes.Equal(vh.uuid, h.uuid) || int(vh.volumeIndex) != i {
			return nil, nil, fmt.Errorf("%s is not file %d of this container", paths[i], i+1)
		}
	}
	if !hmac.Equal(hmac256(commitKey, tuple([]byte("BOND-COMMIT-V2"), h.uuid)), h.commitment) {
		return nil, nil, errors.New("the key commitment does not match")
	}
	if s.writer != nil {
		for i, vh := range headers {
			if err := checkWriter(files[i], vh, s.writer, i == 0); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", paths[i], err)
			}
		}
	}

	// Step 7, done first because the exact stream length is in the manifest: the
	// header only knows the padded one.
	last := files[len(files)-1]
	manifest, err = openManifest(last, h, manifestKey)
	if err != nil {
		return nil, nil, err
	}
	var m struct {
		StreamLength uint64 `json:"streamLength"`
		PaddedLength uint64 `json:"paddedLength"`
		StreamSHA256 string `json:"streamSha256"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, nil, err
	}
	if m.PaddedLength != h.paddedLength || m.StreamLength > m.PaddedLength {
		return nil, nil, errors.New("the manifest and the header disagree about the stream's length")
	}

	// Step 5: the shards.
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, nil, err
	}
	stripeBytes := uint64(h.k)*uint64(h.shardSize) + uint64(h.p)*(uint64(h.shardSize)+tagLen)
	for i := uint64(0); i < h.dataShardCount; i++ {
		offset := i * uint64(h.shardSize)
		if h.parityID != 0 {
			offset = (i/uint64(h.k))*stripeBytes + (i%uint64(h.k))*uint64(h.shardSize)
		}
		length := uint64(h.shardSize)
		if i == h.dataShardCount-1 {
			length = uint64(h.lastShardBytes)
		}
		sealed, err := payload(files, headers, offset, length)
		if err != nil {
			return nil, nil, fmt.Errorf("shard %d: %w", i, err)
		}
		nonce := append(append([]byte(nil), h.noncePrefix...), le64(i)...)
		aad := tuple([]byte("BOND-DATA-V2"), h.uuid, le64(i), le32(h.shardSize))
		plain, err := aead.Open(nil, nonce, sealed, aad)
		if err != nil {
			return nil, nil, fmt.Errorf("shard %d fails authentication", i)
		}
		stream = append(stream, plain...)
	}
	if uint64(len(stream)) != m.PaddedLength {
		return nil, nil, fmt.Errorf("the shards hold %d bytes, the header says %d", len(stream), m.PaddedLength)
	}
	stream = stream[:m.StreamLength]
	if sum := sha256.Sum256(stream); fmt.Sprintf("%x", sum) != m.StreamSHA256 {
		return nil, nil, errors.New("the stream does not match the digest in the manifest")
	}
	return stream, manifest, nil
}

// payload reads length bytes at a payload offset. Each file holds the slice of
// the payload its header names, after a 132 KiB head in the first file and a
// 4 KiB header in the others (NERDME §6a). A shard is never split across files.
func payload(files [][]byte, headers []*header, offset, length uint64) ([]byte, error) {
	for i, vh := range headers {
		if offset < vh.logicalStart || offset >= vh.logicalStart+vh.logicalLen {
			continue
		}
		start := uint64(headerSize)
		if i == 0 {
			start = payloadOffset
		}
		at := start + offset - vh.logicalStart
		if at+length > uint64(len(files[i])) || offset+length > vh.logicalStart+vh.logicalLen {
			return nil, errors.New("runs past the end of its file")
		}
		return files[i][at : at+length], nil
	}
	return nil, errors.New("is in none of the files")
}

// openManifest reads the first manifest copy and falls back to the second.
// NERDME §8: [LE64 length][24-byte nonce][ciphertext]; the plaintext is a LE64
// length, that many bytes of gzip, and zero padding.
func openManifest(last []byte, h *header, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	var problem error
	for copyIndex := uint64(0); copyIndex < 2; copyIndex++ {
		at := h.tailOffset + copyIndex*h.tailLength
		if h.tailLength < 32 || at+h.tailLength > uint64(len(last)) {
			problem = errors.New("the manifest lies outside the last file")
			continue
		}
		frame := last[at : at+h.tailLength]
		if binary.LittleEndian.Uint64(frame) != h.tailLength-32 {
			problem = errors.New("the manifest's length field is wrong")
			continue
		}
		inner, err := aead.Open(nil, frame[8:32], frame[32:], tuple([]byte("BOND-MANIFEST-V2"), h.uuid))
		if err != nil || len(inner) < 8 {
			problem = errors.New("the manifest fails authentication")
			continue
		}
		packedLen := binary.LittleEndian.Uint64(inner)
		if packedLen > uint64(len(inner)-8) {
			problem = errors.New("the manifest's inner length is wrong")
			continue
		}
		zr, err := gzip.NewReader(bytes.NewReader(inner[8 : 8+packedLen]))
		if err != nil {
			problem = err
			continue
		}
		plain, err := io.ReadAll(zr)
		if err != nil {
			problem = err
			continue
		}
		return plain, nil
	}
	return nil, problem
}
