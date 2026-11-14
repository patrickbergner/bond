package container

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
)

// SignedReport is what a check against a writer key found.
type SignedReport struct {
	Paths []string

	// Notices names what was worked around: a header copy that did not
	// verify, a damaged manifest copy. As with Reader.Notices, an empty list
	// means every copy was intact.
	Notices []string
}

// VerifySigned checks a container against the key of the writer that is
// supposed to have written it, without any decryption key.
//
// Every volume's header has to carry that writer's signature; every volume's
// payload has to hash to the digest its signed header records; and the last
// volume's manifest has to match the digest the header records for it. That
// is the whole container except the key-slot tables, which change with every
// key change and which nothing signs – harmless, because a slot only yields
// the master key the signed header commits to.
//
// This is what lets a job holding nothing but the writer's public key prove
// that stored containers are the ones that were written. A checksum file
// cannot: it is as easy to replace as the container beside it.
func VerifySigned(path string, pub *crypto.WriterPublic) (*SignedReport, error) {
	vols, _, _, err := openVolumes(path)
	if err != nil {
		return nil, err
	}
	defer vols.Close()

	rep := &SignedReport{Paths: vols.Paths()}
	first := vols.First()
	for i, v := range vols.vols {
		chosen := -1
		var refusal error
		for j, c := range v.scan.copies {
			err := c.sb.VerifyWriter(pub)
			if err == nil {
				chosen = j
				break
			}
			if refusal == nil {
				refusal = err
			}
		}
		if chosen < 0 {
			return nil, fmt.Errorf("%s: %w", filepath.Base(v.path), refusal)
		}
		v.use(chosen)
		sb := v.sb
		if int(sb.VolumeIndex) != i || int(sb.VolumeCount) != vols.Count() {
			return nil, fmt.Errorf("%s is signed as volume %d of %d, and was found as %d of %d",
				filepath.Base(v.path), sb.VolumeIndex+1, sb.VolumeCount, i+1, vols.Count())
		}
		if msg := v.headerNotice(vols.Count()); msg != "" {
			rep.Notices = append(rep.Notices, msg)
		}
	}
	for _, v := range vols.vols[1:] {
		if !bytes.Equal(v.sb.ContainerUUID, first.sb.ContainerUUID) {
			return nil, fmt.Errorf("%s belongs to a different container", filepath.Base(v.path))
		}
	}
	if err := vols.checkContiguous(); err != nil {
		return nil, err
	}

	for _, v := range vols.vols {
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(v, v.payloadStart, v.logicalLen)); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(v.path), err)
		}
		if subtle.ConstantTimeCompare(h.Sum(nil), v.sb.PayloadSHA256) != 1 {
			return nil, fmt.Errorf("the payload of %s is not what its writer signed: the volume has been damaged or altered",
				filepath.Base(v.path))
		}
	}

	last := vols.Last()
	sb := last.sb
	end := sb.TailOffset + 2*sb.TailLength + format.SuperblockSize
	if end < sb.TailOffset || end != uint64(last.size) {
		return nil, fmt.Errorf("%s is not the length its signed header describes", filepath.Base(last.path))
	}
	intact := 0
	for copyIndex := range 2 {
		buf := make([]byte, sb.TailLength)
		if _, err := last.ReadAt(buf, int64(sb.TailOffset+uint64(copyIndex)*sb.TailLength)); err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(buf); subtle.ConstantTimeCompare(sum[:], sb.TailSHA256) == 1 {
			intact++
			continue
		}
		which := "first"
		if copyIndex == 1 {
			which = "second"
		}
		rep.Notices = append(rep.Notices, "the "+which+" copy of the manifest is damaged; only one copy of the file index and settings is left")
	}
	if intact == 0 {
		return nil, errors.New("both copies of the manifest are damaged")
	}
	return rep, nil
}
