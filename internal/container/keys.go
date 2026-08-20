package container

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

// UpdateSlots replaces a container's key slots.
//
// This is the operation the whole format was shaped around. The two key-slot
// tables sit at fixed offsets and alternate: the new set is written into
// whichever one is not current, with the next generation number, and that is
// the entire write. 64 KiB, wherever the container is a terabyte or a
// megabyte, and the payload is not read, moved or rewritten.
//
// It is also atomic without a journal. Until the new table lands, the old one
// is still the highest valid generation; if the write is interrupted, the
// container opens exactly as it did before.
func UpdateSlots(path string, keys *crypto.Keys, slots []*crypto.Slot) error {
	if len(slots) == 0 {
		return fmt.Errorf("a container must keep at least one key slot, or nothing can ever open it again")
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// The slot tables live in the first volume only. Handed a later one, the
	// offsets below land in the middle of the payload, where the read succeeds
	// and the parse fails with a message about a missing magic number – true,
	// and no help at all in working out what went wrong.
	head := make([]byte, format.SuperblockSize)
	if _, err := f.ReadAt(head, 0); err != nil {
		return err
	}
	if sb, err := format.Unmarshal(head); err == nil && sb.VolumeIndex != 0 {
		return fmt.Errorf("%s is volume %d of %d, and the key slots live in the first one; run this against %s",
			filepath.Base(path), sb.VolumeIndex+1, sb.VolumeCount,
			filepath.Base(VolumeBase(path)+VolumeSuffix(0)))
	}

	a := make([]byte, format.SlotTableSize)
	b := make([]byte, format.SlotTableSize)
	if _, err := f.ReadAt(a, format.SlotTableAOffset); err != nil {
		return err
	}
	if _, err := f.ReadAt(b, format.SlotTableBOffset); err != nil {
		return err
	}

	current, index, err := format.PickTable(a, b)
	if err != nil {
		return err
	}

	// Write into the other one.
	target := int64(format.SlotTableAOffset)
	if index == 0 {
		target = format.SlotTableBOffset
	}

	next := &format.SlotTable{Generation: current.Generation + 1, Slots: slots}
	encoded, err := next.Marshal(keys.Header)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(encoded, target); err != nil {
		return err
	}
	return f.Sync()
}

// PayloadDigest hashes everything after the key-slot tables, across every
// volume of a set. It exists so that changing a key can prove it left the
// payload alone, which is a claim worth checking rather than asserting.
//
// Only the first volume has slot tables to skip past; the rest begin their
// payload directly after their own header.
func PayloadDigest(paths []string) ([]byte, error) {
	h := sha256.New()
	for i, path := range paths {
		start := int64(format.SuperblockSize)
		if i == 0 {
			start = format.PayloadOffset
		}
		if err := hashFrom(h, path, start); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func hashFrom(h io.Writer, path string, start int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	_, err = io.Copy(h, f)
	return err
}
