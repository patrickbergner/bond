//go:build darwin

package container

import "golang.org/x/sys/unix"

func renameNoReplaceSyscall(oldPath, newPath string) error {
	return unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
}
