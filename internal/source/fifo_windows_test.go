//go:build windows

package source

import "errors"

func makeFIFO(string) error { return errors.New("no FIFOs on this platform") }
