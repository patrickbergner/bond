//go:build windows

package container

// Publication uses MOVEFILE_WRITE_THROUGH for each Windows commit rename.
func syncDir(string) error { return nil }
