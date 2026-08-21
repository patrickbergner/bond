//go:build linux || darwin

package container

import (
	"fmt"
	"os"
	"syscall"
)

func validateSameFilesystem(first, second string) error {
	a, err := os.Stat(first)
	if err != nil {
		return err
	}
	b, err := os.Stat(second)
	if err != nil {
		return err
	}
	aStat, aOK := a.Sys().(*syscall.Stat_t)
	bStat, bOK := b.Sys().(*syscall.Stat_t)
	if !aOK || !bOK {
		return fmt.Errorf("filesystem identity is unavailable")
	}
	if aStat.Dev != bStat.Dev {
		return fmt.Errorf("staging and destination are on different filesystems")
	}
	return nil
}
