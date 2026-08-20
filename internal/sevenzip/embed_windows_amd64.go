//go:build windows && amd64

package sevenzip

import _ "embed"

// The helper for this platform. tools/fetch puts it in place; without it
// the build fails here, which is the intended way to notice.
//
//go:embed bin/7za-windows-amd64.exe
var binary []byte

const binaryName = "7za.exe"
