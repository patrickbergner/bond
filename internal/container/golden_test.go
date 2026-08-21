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

func TestImmutableFormatV1GoldenContainer(t *testing.T) {
	const (
		path       = "testdata/v1-golden.bond"
		wantHash   = "8b8adec670fcbc01207515d51dec7354a420ac0fe6908c4efc001961731c1d07"
		passphrase = "bond-v1-fixture-passphrase"
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
	if m := r.Manifest(); m.FormatVersion != 1 || !m.IndexStored || m.Files != 1 || m.Dirs != 1 || m.Bytes != 38 {
		t.Fatalf("unexpected fixture manifest: %+v", m)
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
	if got, want := string(content), "BOND format 1.0 compatibility fixture\n"; got != want {
		t.Fatalf("fixture content = %q, want %q", got, want)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatalf("archive has trailing entry/data: %v", err)
	}
}
