//go:build windows

package container

import "golang.org/x/sys/windows"

func renameNoReplace(oldPath, newPath string) error {
	oldPtr, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldPtr, newPtr, windows.MOVEFILE_WRITE_THROUGH)
}
