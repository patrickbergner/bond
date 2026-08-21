//go:build windows

package container

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func validateSameFilesystem(first, second string) error {
	a, err := volumeSerial(first)
	if err != nil {
		return err
	}
	b, err := volumeSerial(second)
	if err != nil {
		return err
	}
	if a != b {
		return fmt.Errorf("staging and destination are on different volumes")
	}
	return nil
}

func volumeSerial(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return 0, err
	}
	return info.VolumeSerialNumber, nil
}
