package container

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/patrickbergner/bond/internal/crypto"
)

func TestImmutableFormatV2GoldenContainer(t *testing.T) {
	const (
		path       = "testdata/v2-golden.bond"
		wantHash   = "2d16b133d11e02f0172708801059d7529535ec858a05761bf553043616bd2305"
		passphrase = "bond-v2-fixture-passphrase"
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != wantHash {
		t.Fatalf("immutable fixture SHA-256 = %s, want %s; do not regenerate it without reviewing a format change", got, wantHash)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	secret := crypto.Passphrase([]byte(passphrase))
	defer crypto.Wipe(secret)
	if err := r.Unlock(secret); err != nil {
		t.Fatalf("fixture no longer unlocks: %v", err)
	}
	if m := r.Manifest(); m.FormatVersion != 2 || !m.IndexStored || m.Files != 2 || m.Dirs != 1 || m.Bytes != 40038 {
		t.Fatalf("unexpected fixture manifest: %+v", m)
	}
	if n := r.Notices(); len(n) != 0 {
		t.Fatalf("the fixture reports damage: %v", n)
	}

	stream, err := r.Stream()
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(stream)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "fixture/" || hdr.Typeflag != tar.TypeDir {
		t.Fatalf("first archive entry = %+v, %v", hdr, err)
	}
	hdr, err = tr.Next()
	if err != nil || hdr.Name != "fixture/hello.txt" || hdr.Typeflag != tar.TypeReg {
		t.Fatalf("second archive entry = %+v, %v", hdr, err)
	}
	content, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(content), "BOND format 2.0 compatibility fixture\n"; got != want {
		t.Fatalf("fixture content = %q, want %q", got, want)
	}
	hdr, err = tr.Next()
	if err != nil || hdr.Name != "fixture/pattern.bin" || hdr.Size != 40000 {
		t.Fatalf("third archive entry = %+v, %v", hdr, err)
	}
	pattern, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range pattern {
		if want := byte(i) ^ byte(i>>8) ^ byte(i>>16); b != want {
			t.Fatalf("pattern.bin byte %d = %#x, want %#x", i, b, want)
		}
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatalf("archive has trailing entry/data: %v", err)
	}

	// The key file opens it as well, and the whole container verifies.
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	keyfile := make([]byte, crypto.KeyLen)
	for i := range keyfile {
		keyfile[i] = 0x30 + byte(i)
	}
	if err := again.Unlock(crypto.KeyfileSecret(keyfile)); err != nil {
		t.Fatalf("fixture no longer unlocks with its key file: %v", err)
	}
	report, err := again.Verify(nil)
	if err != nil || !report.Healthy() {
		t.Fatalf("fixture does not verify: %+v, %v", report, err)
	}
}
