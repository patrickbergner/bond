package archive

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A name that is not text has to come out of the index as the bytes that went
// in, and equal to what the tar stream beside it says – that equality is what a
// restore checks.
func TestIndexKeepsNamesThatAreNotUTF8(t *testing.T) {
	const latin1 = "dir/caf\xe9.txt"
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	encoded, err := json.Marshal([]FileInfo{
		{Path: latin1, Kind: KindFile, Mode: 0o644, ModTime: stamp},
		{Path: "dir/café.txt", Kind: KindFile, Mode: 0o644, ModTime: stamp},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(encoded), "pathBytes"); n != 1 {
		t.Errorf("pathBytes appears %d times, want it only on the name that is not UTF-8: %s", n, encoded)
	}
	var back []FileInfo
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back[0].Path != latin1 || back[1].Path != "dir/café.txt" {
		t.Fatalf("names came back as %q and %q", back[0].Path, back[1].Path)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: latin1, Mode: 0o644, ModTime: stamp, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	hdr, err := tar.NewReader(&buf).Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != back[0].Path {
		t.Errorf("the archive says %q and the index says %q", hdr.Name, back[0].Path)
	}

	for name, doc := range map[string]string{
		"pathBytes on a UTF-8 name": `{"path":"a","pathBytes":"YQ==","kind":0,"mode":420,"modTime":"2026-01-02T03:04:05Z"}`,
		"an unknown field":          `{"path":"a","kind":0,"mode":420,"modTime":"2026-01-02T03:04:05Z","extra":1}`,
	} {
		var fi FileInfo
		if err := json.Unmarshal([]byte(doc), &fi); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestRestoreRefusesANameThisSystemCannotStore(t *testing.T) {
	_, err := SafeJoin(t.TempDir(), "dir/caf\xe9.txt")
	if namesAreBytes && err != nil {
		t.Errorf("refused where names are bytes: %v", err)
	}
	if !namesAreBytes && err == nil {
		t.Error("a name that is not UTF-8 was accepted on a system that cannot store it")
	}
}
