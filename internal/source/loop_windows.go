//go:build windows

package source

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isSymlinkLoop(err error) bool { return errors.Is(err, windows.ERROR_CANT_RESOLVE_FILENAME) }
