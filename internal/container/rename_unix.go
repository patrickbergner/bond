//go:build linux || darwin

package container

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace moves a file only if nothing is at the destination. Publish
// depends on that: a plain rename replaces silently on POSIX, which would let a
// name collision destroy the previous backup one volume at a time.
//
// The kernel call is the good path, and it is not always there. RENAME_NOREPLACE
// arrived in Linux 3.15 and is implemented per filesystem: NFS, several FUSE
// backends and some overlay configurations return EINVAL, ENOSYS or EOPNOTSUPP
// for it. Those are exactly the destinations an archival tool is pointed at, and
// failing publication on them with a bare errno would be refusing to write a
// backup because of a flag rather than because of anything wrong.
//
// link+unlink is the portable equivalent and predates the flag by decades:
// link() fails with EEXIST if the destination exists, which is the atomic
// no-replace guarantee, and the unlink that follows only drops the staging name
// for content that is already durable under the new one. It cannot cross a
// filesystem, but ValidatePublication has already proved staging and destination
// share one. It needs the source not to be a directory, which volumes are not.
func renameNoReplace(oldPath, newPath string) error {
	err := renameNoReplaceSyscall(oldPath, newPath)
	if !unsupportedRename(err) {
		return err
	}
	if linkErr := os.Link(oldPath, newPath); linkErr != nil {
		// Report the original refusal too: on a filesystem with neither
		// mechanism, "hard links are not supported" alone sends the reader
		// looking in the wrong place.
		return fmt.Errorf("this filesystem supports neither an atomic no-replace rename (%v) nor hard links: %w", err, linkErr)
	}
	if err := os.Remove(oldPath); err != nil {
		return fmt.Errorf("published %s but could not remove its staging copy %s: %w", newPath, oldPath, err)
	}
	return nil
}

func unsupportedRename(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP)
}
