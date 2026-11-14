package container

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

func writerKey(t *testing.T, fill byte) *crypto.WriterPrivate {
	t.Helper()
	w, err := crypto.WriterFromSeed(bytes.Repeat([]byte{fill}, crypto.WriterSeedLen))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Wipe)
	return w
}

func recipientKey(t *testing.T, fill byte) *crypto.RecipientPrivate {
	t.Helper()
	priv, err := crypto.RecipientFromSeed(bytes.Repeat([]byte{fill}, crypto.SeedLen))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(priv.Wipe)
	return priv
}

func unlockExpecting(path string, expect *crypto.WriterPublic, secret crypto.Unlocker) (*Reader, error) {
	r, err := Open(path)
	if err != nil {
		return nil, err
	}
	err = r.UnlockWithOptions(UnlockOptions{ExpectWriter: expect}, secret)
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// The attack a writer signature exists for: someone who has only the
// recipient's public key builds a container of their own, and it opens with the
// recovery card exactly like the real one. Without a signature to check nothing
// tells them apart; with one, the forgery is refused and the real one is not.
func TestExpectedWriterTellsAForgeryFromTheRealThing(t *testing.T) {
	card := recipientKey(t, 0x11)
	writer := writerKey(t, 0x22)
	keys := []KeySpec{{Recipient: card.Public(), Label: "the safe"}}

	genuine := build(t, []byte("what the writer really backed up"), Options{ShardSize: 8192, Keys: keys, Signer: writer})
	forged := build(t, []byte("what someone else would like restored"), Options{ShardSize: 8192, Keys: keys})
	otherWriter := build(t, []byte("signed, by somebody else"), Options{ShardSize: 8192, Keys: keys, Signer: writerKey(t, 0x33)})

	secret := crypto.RecipientSecret{Private: card}

	// Without an expected writer, all three open: that is the gap.
	for _, path := range []string{genuine, forged, otherWriter} {
		r, err := unlockExpecting(path, nil, secret)
		if err != nil {
			t.Fatalf("without an expected writer: %v", err)
		}
		if r.OpenedWith() != crypto.SlotRecipient || r.WriterChecked() {
			t.Errorf("opened with %v, writer checked %v", r.OpenedWith(), r.WriterChecked())
		}
		r.Close()
	}

	r, err := unlockExpecting(genuine, writer.Public(), secret)
	if err != nil {
		t.Fatalf("the genuine container was refused: %v", err)
	}
	if !r.WriterChecked() || !bytes.Equal(r.Signer(), writer.Fingerprint()) {
		t.Error("the genuine container opened without its writer being reported as checked")
	}
	r.Close()

	if _, err := unlockExpecting(forged, writer.Public(), secret); !errors.Is(err, format.ErrNotSigned) {
		t.Errorf("the unsigned forgery: got %v, want ErrNotSigned", err)
	}
	if _, err := unlockExpecting(otherWriter, writer.Public(), secret); err == nil || !strings.Contains(err.Error(), "not by the expected") {
		t.Errorf("a container signed by another writer: got %v", err)
	}
}

// A signed container's signature lives in its headers, which key changes and
// repairs leave as they are.
func TestSignatureSurvivesKeyChangesAndRepair(t *testing.T) {
	writer := writerKey(t, 0x44)
	payload := make([]byte, 200_000)
	rand.Read(payload)
	path := build(t, payload, Options{ShardSize: 8192, RecoveryPercent: 20, Signer: writer})

	r := openUnlocked(t, path)
	extra, err := crypto.NewSlot(r.Superblock().Cipher, r.Superblock().ContainerUUID, r.Keys().FMK(),
		crypto.KeyfileSecret(bytes.Repeat([]byte{9}, crypto.KeyLen)), crypto.KDFParams{}, "added")
	if err != nil {
		t.Fatal(err)
	}
	if err := UpdateSlots(path, r.Keys(), append(r.Slots(), extra)); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := VerifySigned(path, writer.Public()); err != nil {
		t.Fatalf("after a key change: %v", err)
	}

	// Damage a data shard and the mirrored header, repair, and check again.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := f.Stat()
	f.WriteAt([]byte{0xff, 0xee}, format.PayloadOffset+100)
	f.WriteAt([]byte{0xff, 0xee}, info.Size()-200)
	f.Close()
	if _, err := VerifySigned(path, writer.Public()); err == nil {
		t.Fatal("a damaged payload passed the signed check")
	}

	damaged := openUnlocked(t, path)
	defer damaged.Close()
	report, err := damaged.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(t.TempDir(), "fixed.bond")
	if _, err := Repair(context.Background(), damaged, fixed, report, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifySigned(fixed, writer.Public())
	if err != nil {
		t.Fatalf("the repaired container no longer matches its signature: %v", err)
	}
	if len(rep.Notices) != 0 {
		t.Errorf("the repaired container still reports damage: %v", rep.Notices)
	}
}

// The keyless check covers everything a substitution would have to change.
func TestVerifySignedNeedsNoKeyAndMissesNothing(t *testing.T) {
	writer := writerKey(t, 0x55)
	payload := make([]byte, 400_000)
	rand.Read(payload)
	base := filepath.Join(t.TempDir(), "split.bond")
	w, err := Create(base, Options{
		ShardSize: 8192, RecoveryPercent: 10, MaxVolumeBytes: 205_000, Signer: writer,
		Keys: []KeySpec{{Secret: crypto.Passphrase(testPass), KDF: fastKDF}},
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
	if err := w.Validate(base + VolumeSuffix(0)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	volumes := w.Volumes()
	if volumes < 2 {
		t.Fatalf("want a split set, got %d volume", volumes)
	}

	rep, err := VerifySigned(base+VolumeSuffix(1), writer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Paths) != volumes || len(rep.Notices) != 0 {
		t.Fatalf("report %+v for %d volumes", rep, volumes)
	}
	if _, err := VerifySigned(base+VolumeSuffix(0), writerKey(t, 0x56).Public()); err == nil {
		t.Error("the wrong writer key passed")
	}

	mutate := func(t *testing.T, name string, at func(size int64) int64) {
		t.Helper()
		dir := t.TempDir()
		for i := range volumes {
			data, err := os.ReadFile(base + VolumeSuffix(i))
			if err != nil {
				t.Fatal(err)
			}
			if i == volumes-1 {
				data[at(int64(len(data)))] ^= 0x01
			}
			os.WriteFile(filepath.Join(dir, "split.bond"+VolumeSuffix(i)), data, 0o600)
		}
		rep, err := VerifySigned(filepath.Join(dir, "split.bond"+VolumeSuffix(0)), writer.Public())
		switch name {
		case "mirror", "manifest copy":
			if err != nil || len(rep.Notices) != 1 {
				t.Errorf("%s: %v %+v; want it reported and survived", name, err, rep)
			}
		default:
			if err == nil {
				t.Errorf("a flipped bit in the %s passed the signed check", name)
			}
		}
	}
	mutate(t, "payload", func(size int64) int64 { return format.SuperblockSize + 10 })
	mutate(t, "mirror", func(size int64) int64 { return size - 100 })
	mutate(t, "manifest copy", func(size int64) int64 { return size - format.SuperblockSize - 40 })
}
