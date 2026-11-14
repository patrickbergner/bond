// Package archive builds and reads the tar stream that sits inside a BOND
// container.
//
// BOND writes the tar itself rather than letting 7-Zip archive anything, for
// three reasons. Entry names are then exactly what the source layout decided,
// rather than whatever an archiver's path switches produce. Extraction is
// ordinary Go code, so the rules about what a restore is allowed to write are
// ours and are tested here. And the per-file digests the manifest needs come
// out of the same pass that writes the data.
package archive

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"time"
	"unicode/utf8"
)

// Kind is what an entry is.
type Kind uint8

const (
	KindFile Kind = iota
	KindDir
)

func (k Kind) String() string {
	switch k {
	case KindDir:
		return "directory"
	default:
		return "file"
	}
}

// Entry is one thing to store. Path is the name inside the archive, '/'
// separated and relative; Disk is where to read the content from.
type Entry struct {
	Path     string
	Disk     string
	Kind     Kind
	Size     int64
	Mode     fs.FileMode
	ModTime  time.Time
	Expected fs.FileInfo
}

// FileInfo is what the manifest records about one stored entry. The digest is
// of the bytes actually written, which is what makes a later verification
// meaningful even for a file that changed while it was being read.
type FileInfo struct {
	Path    string      `json:"path"`
	Kind    Kind        `json:"kind"`
	Size    int64       `json:"size,omitempty"`
	Mode    fs.FileMode `json:"mode"`
	ModTime time.Time   `json:"modTime"`
	SHA256  string      `json:"sha256,omitempty"`
}

// fileInfoJSON is FileInfo as the manifest stores it.
//
// A file name on Linux is a string of bytes and need not be text: a tree that
// has been around since before UTF-8 carries names in Latin-1, and they are as
// much part of the backup as any other. JSON cannot hold them – it writes
// U+FFFD where a byte is not valid UTF-8 – so the index would name an entry
// differently from the archive beside it, and a restore that checks one
// against the other would stop there. Such a name is therefore stored a second
// time as its bytes, in pathBytes (base64), and that is what a reader goes by.
// A name that is valid UTF-8 has no pathBytes, so an ordinary index reads
// exactly as it always has.
type fileInfoJSON struct {
	Path      string      `json:"path"`
	PathBytes []byte      `json:"pathBytes,omitempty"`
	Kind      Kind        `json:"kind"`
	Size      int64       `json:"size,omitempty"`
	Mode      fs.FileMode `json:"mode"`
	ModTime   time.Time   `json:"modTime"`
	SHA256    string      `json:"sha256,omitempty"`
}

func (f FileInfo) MarshalJSON() ([]byte, error) {
	out := fileInfoJSON{Path: f.Path, Kind: f.Kind, Size: f.Size, Mode: f.Mode, ModTime: f.ModTime, SHA256: f.SHA256}
	if !utf8.ValidString(f.Path) {
		out.PathBytes = []byte(f.Path)
	}
	return json.Marshal(out)
}

func (f *FileInfo) UnmarshalJSON(data []byte) error {
	var in fileInfoJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return err
	}
	*f = FileInfo{Path: in.Path, Kind: in.Kind, Size: in.Size, Mode: in.Mode, ModTime: in.ModTime, SHA256: in.SHA256}
	if in.PathBytes != nil {
		// Only ever written for a name that is not text; anything else is a
		// second spelling of a name that already has one.
		if utf8.Valid(in.PathBytes) {
			return errors.New("pathBytes is present for a name that is valid UTF-8")
		}
		f.Path = string(in.PathBytes)
	}
	return nil
}
