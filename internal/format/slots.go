package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/patrickbergner/bond/internal/crypto"
)

// The key-slot table is written twice, at two fixed offsets, and only one of
// the two is current. Changing a key writes the *other* one and bumps its
// generation, so the operation is atomic without any journal: a crash halfway
// through leaves the previous table untouched and still the highest valid
// generation. Readers take the newest table that verifies.
//
// This is also why the superblock does not authenticate these tables. If it
// did, adding a key would mean rewriting the superblock in every volume of a
// terabyte container. Instead each table carries its own MAC, and changing a
// key touches exactly 64 KiB in the first volume.

const (
	slotTableHeaderSize = 64
	maxSlots            = 32
	maxLabelLen         = 64

	offSlotMagic      = 0
	offSlotVersion    = 4
	offSlotCount      = 6
	offSlotGeneration = 8
	offSlotUsedBytes  = 16
	offSlotMAC        = 32
	offSlotRecords    = slotTableHeaderSize
)

var slotMagic = [4]byte{'B', 'S', 'L', 'T'}

// ErrNoSlotTable means neither table could be read.
var ErrNoSlotTable = errors.New("this container has no readable key slots")

// SlotTable is one of a container's two key-slot tables.
type SlotTable struct {
	Generation uint64
	Slots      []*crypto.Slot
	MAC        []byte
	raw        []byte
}

// Marshal renders the table into exactly SlotTableSize bytes. The MAC is left
// zero unless headerKey is given.
func (t *SlotTable) Marshal(headerKey []byte) ([]byte, error) {
	if len(t.Slots) > maxSlots {
		return nil, fmt.Errorf("%d key slots; a container holds at most %d", len(t.Slots), maxSlots)
	}

	var records bytes.Buffer
	for _, s := range t.Slots {
		rec, err := marshalSlot(s)
		if err != nil {
			return nil, err
		}
		records.Write(rec)
	}
	if records.Len() > SlotTableSize-slotTableHeaderSize {
		return nil, fmt.Errorf("the key slots need %d bytes, the table holds %d",
			records.Len(), SlotTableSize-slotTableHeaderSize)
	}

	b := make([]byte, SlotTableSize)
	copy(b[offSlotMagic:], slotMagic[:])
	binary.LittleEndian.PutUint16(b[offSlotVersion:], 1)
	binary.LittleEndian.PutUint16(b[offSlotCount:], uint16(len(t.Slots)))
	binary.LittleEndian.PutUint64(b[offSlotGeneration:], t.Generation)
	binary.LittleEndian.PutUint32(b[offSlotUsedBytes:], uint32(records.Len()))
	copy(b[offSlotRecords:], records.Bytes())

	if headerKey != nil {
		t.MAC = crypto.MAC(headerKey, b) // computed with the MAC field still zero
		copy(b[offSlotMAC:], t.MAC)
	}
	return b, nil
}

// ParseSlotTable reads a table without authenticating it. The wrapped keys
// inside carry their own tags, so a tampered record simply fails to unwrap;
// the table MAC is checked afterwards, once a key is available.
func ParseSlotTable(b []byte) (*SlotTable, error) {
	if len(b) < SlotTableSize {
		return nil, errors.New("key-slot table is truncated")
	}
	if !bytes.Equal(b[offSlotMagic:offSlotMagic+4], slotMagic[:]) {
		return nil, errors.New("key-slot table is missing its magic")
	}
	if v := binary.LittleEndian.Uint16(b[offSlotVersion:]); v != 1 {
		return nil, fmt.Errorf("key-slot table version %d is not supported", v)
	}

	count := int(binary.LittleEndian.Uint16(b[offSlotCount:]))
	used := int(binary.LittleEndian.Uint32(b[offSlotUsedBytes:]))
	if count > maxSlots {
		return nil, fmt.Errorf("key-slot table claims %d slots, the format allows %d", count, maxSlots)
	}
	if used < 0 || used > SlotTableSize-slotTableHeaderSize {
		return nil, fmt.Errorf("key-slot table claims %d bytes of records", used)
	}

	t := &SlotTable{
		Generation: binary.LittleEndian.Uint64(b[offSlotGeneration:]),
		MAC:        append([]byte(nil), b[offSlotMAC:offSlotMAC+32]...),
		raw:        append([]byte(nil), b[:SlotTableSize]...),
	}

	rest := b[offSlotRecords : offSlotRecords+used]
	for i := 0; i < count; i++ {
		slot, n, err := parseSlot(rest)
		if err != nil {
			return nil, fmt.Errorf("key slot %d: %w", i, err)
		}
		t.Slots = append(t.Slots, slot)
		rest = rest[n:]
	}
	return t, nil
}

// Verify checks the table's MAC, which is possible only once a key has been
// recovered from one of its slots.
func (t *SlotTable) Verify(headerKey []byte) error {
	var b []byte
	if len(t.raw) == SlotTableSize {
		b = append([]byte(nil), t.raw...)
		clear(b[offSlotMAC : offSlotMAC+32])
	} else {
		unsigned := &SlotTable{Generation: t.Generation, Slots: t.Slots}
		var err error
		b, err = unsigned.Marshal(nil)
		if err != nil {
			return err
		}
	}
	if !crypto.CheckMAC(headerKey, b, t.MAC) {
		return errors.New("the key-slot table fails authentication; it has been damaged or altered")
	}
	return nil
}

// Slot record layout.
const (
	offRecSize     = 0
	offRecVersion  = 4
	offRecType     = 6
	offRecUUID     = 8
	offRecNonce    = 24
	offRecSalt     = 48
	offRecKDFMem   = 64
	offRecKDFIter  = 68
	offRecKDFLanes = 72
	offRecWrapLen  = 76
	offRecWrapped  = 80
)

func marshalSlot(s *crypto.Slot) ([]byte, error) {
	switch {
	case len(s.UUID) != 16:
		return nil, fmt.Errorf("slot uuid is %d bytes, want 16", len(s.UUID))
	case len(s.Nonce) != crypto.NonceLen:
		return nil, fmt.Errorf("slot nonce is %d bytes, want %d", len(s.Nonce), crypto.NonceLen)
	case len(s.Salt) != 16:
		return nil, fmt.Errorf("slot salt is %d bytes, want 16", len(s.Salt))
	case len(s.Label) > maxLabelLen:
		return nil, fmt.Errorf("slot label is %d bytes, the format allows %d", len(s.Label), maxLabelLen)
	}

	size := offRecWrapped + len(s.Wrapped) + 2 + len(s.Label) + 4 + len(s.Encapsulation)
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b[offRecSize:], uint32(size))
	binary.LittleEndian.PutUint16(b[offRecVersion:], 1)
	b[offRecType] = uint8(s.Type)
	copy(b[offRecUUID:], s.UUID)
	copy(b[offRecNonce:], s.Nonce)
	copy(b[offRecSalt:], s.Salt)
	binary.LittleEndian.PutUint32(b[offRecKDFMem:], s.KDF.MemoryKiB)
	binary.LittleEndian.PutUint32(b[offRecKDFIter:], s.KDF.Iterations)
	binary.LittleEndian.PutUint32(b[offRecKDFLanes:], s.KDF.Parallelism)
	binary.LittleEndian.PutUint32(b[offRecWrapLen:], uint32(len(s.Wrapped)))
	copy(b[offRecWrapped:], s.Wrapped)
	binary.LittleEndian.PutUint16(b[offRecWrapped+len(s.Wrapped):], uint16(len(s.Label)))
	copy(b[offRecWrapped+len(s.Wrapped)+2:], s.Label)

	// A recipient slot carries its key exchange – an ephemeral public key and
	// an ML-KEM ciphertext, about 1.6 KiB. Everything else stores nothing here.
	encapAt := offRecWrapped + len(s.Wrapped) + 2 + len(s.Label)
	binary.LittleEndian.PutUint32(b[encapAt:], uint32(len(s.Encapsulation)))
	copy(b[encapAt+4:], s.Encapsulation)
	return b, nil
}

func parseSlot(b []byte) (*crypto.Slot, int, error) {
	if len(b) < offRecWrapped {
		return nil, 0, errors.New("record is truncated")
	}
	size := int(binary.LittleEndian.Uint32(b[offRecSize:]))
	if size < offRecWrapped || size > len(b) {
		return nil, 0, fmt.Errorf("record claims %d bytes, %d are available", size, len(b))
	}
	if v := binary.LittleEndian.Uint16(b[offRecVersion:]); v != 1 {
		return nil, 0, fmt.Errorf("record version %d is not supported", v)
	}

	wrapLen := int(binary.LittleEndian.Uint32(b[offRecWrapLen:]))
	if wrapLen < 0 || offRecWrapped+wrapLen+2 > size {
		return nil, 0, fmt.Errorf("record claims a %d-byte wrapped key", wrapLen)
	}
	labelLen := int(binary.LittleEndian.Uint16(b[offRecWrapped+wrapLen:]))
	if offRecWrapped+wrapLen+2+labelLen+4 > size {
		return nil, 0, fmt.Errorf("record claims a %d-byte label", labelLen)
	}

	encapAt := offRecWrapped + wrapLen + 2 + labelLen
	encapLen := int(binary.LittleEndian.Uint32(b[encapAt:]))
	if encapLen < 0 || encapAt+4+encapLen > size {
		return nil, 0, fmt.Errorf("record claims %d bytes of key exchange data", encapLen)
	}

	s := &crypto.Slot{
		Type:    crypto.SlotType(b[offRecType]),
		UUID:    append([]byte(nil), b[offRecUUID:offRecUUID+16]...),
		Nonce:   append([]byte(nil), b[offRecNonce:offRecNonce+crypto.NonceLen]...),
		Salt:    append([]byte(nil), b[offRecSalt:offRecSalt+16]...),
		Wrapped: append([]byte(nil), b[offRecWrapped:offRecWrapped+wrapLen]...),
		KDF: crypto.KDFParams{
			MemoryKiB:   binary.LittleEndian.Uint32(b[offRecKDFMem:]),
			Iterations:  binary.LittleEndian.Uint32(b[offRecKDFIter:]),
			Parallelism: binary.LittleEndian.Uint32(b[offRecKDFLanes:]),
		},
		Label: string(b[offRecWrapped+wrapLen+2 : offRecWrapped+wrapLen+2+labelLen]),
	}
	if encapLen > 0 {
		s.Encapsulation = append([]byte(nil), b[encapAt+4:encapAt+4+encapLen]...)
	}
	return s, size, nil
}

// PickTable chooses between the two on-disk tables: the highest generation
// that parses wins. A table that fails to parse is simply not a candidate,
// which is what makes the alternating write safe.
func PickTable(a, b []byte) (*SlotTable, int, error) {
	tables := [2][]byte{a, b}
	var best *SlotTable
	bestIndex := -1
	var problems []string

	for i, raw := range tables {
		t, err := ParseSlotTable(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("table %c: %v", 'A'+i, err))
			continue
		}
		if best == nil || t.Generation > best.Generation {
			best, bestIndex = t, i
		}
	}
	if best == nil {
		return nil, -1, fmt.Errorf("%w (%s)", ErrNoSlotTable, joinProblems(problems))
	}
	return best, bestIndex, nil
}

// TableCopy is one of the two on-disk key-slot tables, and which of the two it
// is.
type TableCopy struct {
	Table *SlotTable
	Index int // 0 for table A, 1 for table B
}

// PickTables returns every table that parses, newest generation first.
//
// Both are returned rather than only the newest, because "parses" and
// "authentic" are different questions and only the second one matters – it
// needs a key, so it cannot be answered here. A single flipped bit can leave
// the newer table structurally perfect and merely unauthentic, and refusing the
// container then, with a good table sitting 64 KiB away, would lose a backup
// over one byte.
func PickTables(a, b []byte) ([]TableCopy, error) {
	var (
		found    []TableCopy
		problems []string
	)
	for i, raw := range [2][]byte{a, b} {
		t, err := ParseSlotTable(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("table %c: %v", 'A'+i, err))
			continue
		}
		found = append(found, TableCopy{Table: t, Index: i})
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%w (%s)", ErrNoSlotTable, joinProblems(problems))
	}
	if len(found) == 2 && found[1].Table.Generation > found[0].Table.Generation {
		found[0], found[1] = found[1], found[0]
	}
	return found, nil
}

func joinProblems(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
