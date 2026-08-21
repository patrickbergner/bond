package container

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
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

	// Authenticate the header on this writable handle. The path may have been
	// replaced since the Reader that supplied keys was opened, and a damaged
	// leading copy may require the mirror at EOF.
	sb, err := authenticatedHead(f, keys)
	if err != nil {
		return err
	}
	if sb.VolumeIndex != 0 {
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

	type authenticTable struct {
		table *format.SlotTable
		index int
		raw   []byte
	}
	var authentic []authenticTable
	for index, raw := range [][]byte{a, b} {
		table, parseErr := format.ParseSlotTable(raw)
		if parseErr != nil || table.Verify(keys.Header) != nil {
			continue
		}
		authentic = append(authentic, authenticTable{table: table, index: index, raw: raw})
	}
	if len(authentic) == 0 {
		return fmt.Errorf("neither key-slot table authenticates with this container's key")
	}
	current := authentic[0]
	for _, candidate := range authentic[1:] {
		switch {
		case candidate.table.Generation > current.table.Generation:
			current = candidate
		case candidate.table.Generation == current.table.Generation && !bytes.Equal(candidate.raw, current.raw):
			return fmt.Errorf("the two authentic key-slot tables have generation %d but different contents", current.table.Generation)
		}
	}
	if current.table.Generation == math.MaxUint64 {
		return fmt.Errorf("key-slot generation has reached its maximum value")
	}

	// Write into the other one.
	target := int64(format.SlotTableAOffset)
	if current.index == 0 {
		target = format.SlotTableBOffset
	}

	next := &format.SlotTable{Generation: current.table.Generation + 1, Slots: slots}
	encoded, err := next.Marshal(keys.Header)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(encoded, target); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	written := make([]byte, format.SlotTableSize)
	if _, err := f.ReadAt(written, target); err != nil {
		return fmt.Errorf("reading back the updated key slots: %w", err)
	}
	checked, err := format.ParseSlotTable(written)
	if err != nil {
		return fmt.Errorf("the updated key slots cannot be parsed: %w", err)
	}
	if checked.Generation != next.Generation {
		return fmt.Errorf("the updated key-slot generation is %d, want %d", checked.Generation, next.Generation)
	}
	if err := checked.Verify(keys.Header); err != nil {
		return fmt.Errorf("the updated key slots fail authentication: %w", err)
	}
	return nil
}

func authenticatedHead(f *os.File, keys *crypto.Keys) (*format.Superblock, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	positions := []int64{0}
	if info.Size() >= format.SuperblockSize {
		positions = append(positions, info.Size()-format.SuperblockSize)
	}
	var found *format.Superblock
	for _, at := range positions {
		raw := make([]byte, format.SuperblockSize)
		if _, err := f.ReadAt(raw, at); err != nil {
			continue
		}
		sb, err := format.Unmarshal(raw)
		if err != nil || sb.Verify(keys) != nil {
			continue
		}
		if found != nil && !found.IdenticalTo(sb) {
			return nil, fmt.Errorf("the two authentic header copies differ")
		}
		found = sb
	}
	if found == nil {
		return nil, fmt.Errorf("neither header copy authenticates with this container's key")
	}
	return found, nil
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
