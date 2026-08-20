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
	"io/fs"
	"time"
)

// Kind is what an entry is.
type Kind uint8

const (
	KindFile Kind = iota
	KindDir
	KindSymlink
)

func (k Kind) String() string {
	switch k {
	case KindDir:
		return "directory"
	case KindSymlink:
		return "symlink"
	default:
		return "file"
	}
}

// Entry is one thing to store. Path is the name inside the archive, '/'
// separated and relative; Disk is where to read the content from.
type Entry struct {
	Path    string
	Disk    string
	Kind    Kind
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
	Link    string
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
	Link    string      `json:"link,omitempty"`
	SHA256  string      `json:"sha256,omitempty"`
}
