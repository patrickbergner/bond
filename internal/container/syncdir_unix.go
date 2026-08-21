//go:build linux || darwin

package container

import "os"

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}
