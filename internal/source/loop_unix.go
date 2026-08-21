//go:build linux || darwin

package source

import (
	"errors"
	"syscall"
)

func isSymlinkLoop(err error) bool { return errors.Is(err, syscall.ELOOP) }
