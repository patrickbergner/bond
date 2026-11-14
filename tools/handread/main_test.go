package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

// The reader shares no code with BOND, so these tests are the two
// implementations checking each other. The writer under test is the real one;
// what reads its output here was typed in from NERDME §11.

const golden = "../../internal/container/testdata/v2-golden.bond"

func fixtureKeyfile() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x30 + byte(i)
	}
	return k
}

func TestGoldenContainerByHand(t *testing.T) {
	for name, s := range map[string]secret{
		"passphrase": {passphrase: []byte("bond-v2-fixture-passphrase")},
		"key file":   {keyfile: fixtureKeyfile()},
	} {
		t.Run(name, func(t *testing.T) {
			stream, manifest, err := read([]string{golden}, s)
			if err != nil {
				t.Fatal(err)
			}

			var m struct {
				Compression struct{ Format string } `json:"compression"`
				Files       int                     `json:"files"`
			}
			if err := json.Unmarshal(manifest, &m); err != nil {
				t.Fatal(err)
			}
			if m.Compression.Format != "none" || m.Files != 2 {
				t.Fatalf("unexpected manifest: %s", manifest)
			}

			// Step 6 of the procedure: what is left is an ordinary tar.
			tr := tar.NewReader(bytes.NewReader(stream))
			got := map[string][]byte{}
			for {
				hdr, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				content, err := io.ReadAll(tr)
				if err != nil {
					t.Fatal(err)
				}
				got[hdr.Name] = content
			}
			if string(got["fixture/hello.txt"]) != "BOND format 2.0 compatibility fixture\n" {
				t.Errorf("hello.txt = %q", got["fixture/hello.txt"])
			}
			pattern := got["fixture/pattern.bin"]
			if len(pattern) != 40000 {
				t.Fatalf("pattern.bin is %d bytes, want 40000", len(pattern))
			}
			for i, b := range pattern {
				if want := byte(i) ^ byte(i>>8) ^ byte(i>>16); b != want {
					t.Fatalf("pattern.bin byte %d = %#x, want %#x", i, b, want)
				}
			}
		})
	}
}

// The golden fixture is signed by the writer whose seed is the 32 bytes
// 60 61 … 7f. The reader takes the public key the way an operator would hand it
// over: as the .pub file "bond keygen --signing-key" writes.
func TestGoldenContainerIsSignedByItsWriter(t *testing.T) {
	seed := make([]byte, crypto.WriterSeedLen)
	for i := range seed {
		seed[i] = 0x60 + byte(i)
	}
	writer, err := crypto.WriterFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Wipe()
	pub, err := parseWriterPublic("# a comment\nbondwp1" + base64.RawURLEncoding.EncodeToString(writer.Public().Bytes()) + "\n")
	if err != nil {
		t.Fatal(err)
	}

	s := secret{passphrase: []byte("bond-v2-fixture-passphrase"), writer: pub}
	if _, _, err := read([]string{golden}, s); err != nil {
		t.Fatalf("the golden container does not verify as signed by its writer: %v", err)
	}

	other := append([]byte(nil), pub...)
	other[0] ^= 1
	s.writer = other
	if _, _, err := read([]string{golden}, s); err == nil {
		t.Error("the golden container verified under another writer's key")
	}
}

func TestWrongSecretsOpenNothing(t *testing.T) {
	for name, s := range map[string]secret{
		"passphrase": {passphrase: []byte("not the fixture passphrase")},
		"key file":   {keyfile: bytes.Repeat([]byte{7}, 32)},
	} {
		if _, _, err := read([]string{golden}, s); err == nil {
			t.Errorf("a wrong %s opened the container", name)
		}
	}
}

// Containers the real writer produces now, in the shapes §11 has to cover: with
// and without recovery data, in one file and split, and a passphrase typed in a
// different Unicode form from the one it was set in.
func TestFreshContainersByHand(t *testing.T) {
	cases := []struct {
		name    string
		percent int
		volume  int64
		size    int
	}{
		{"one file, no recovery data", 0, 0, 100_000},
		{"one file, recovery data", 20, 0, 300_000},
		{"split, recovery data", 10, 300_000, 1_500_000},
		{"split, no recovery data", 0, 300_000, 900_000},
		{"shorter than a shard", 10, 0, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			rand.Read(payload)

			base := filepath.Join(t.TempDir(), "fresh.bond")
			w, err := container.Create(base, container.Options{
				ShardSize:       64 << 10,
				RecoveryPercent: tc.percent,
				MaxVolumeBytes:  tc.volume,
				Keys: []container.KeySpec{{
					Secret: crypto.Passphrase("Grüße aus dem Tresor"), // precomposed ü
					KDF:    crypto.KDFParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Destroy()
			if _, err := w.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := w.Finish(&format.Manifest{}); err != nil {
				t.Fatal(err)
			}

			paths := []string{base}
			if tc.volume > 0 {
				paths = nil
				for i := range w.Volumes() {
					paths = append(paths, base+container.VolumeSuffix(i))
				}
				if len(paths) < 2 {
					t.Fatalf("expected a split set, got %d file", len(paths))
				}
			}

			stream, _, err := read(paths, secret{passphrase: []byte("Grüße aus dem Tresor")}) // u + combining diaeresis
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stream, payload) {
				t.Fatalf("read back %d bytes that are not the %d written", len(stream), len(payload))
			}
		})
	}
}
