#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION="${BOND_VERSION:-$(cat VERSION)}"
if [ -z "$VERSION" ]; then
    echo "error: VERSION is missing or empty; it is the only place the release is named" >&2
    exit 1
fi
LDFLAGS="-s -w -X main.Version=${VERSION}"

go run ./tools/fetch
go vet ./...
go test ./...

build() {
    local goos="$1" goarch="$2" out="$3"
    echo "Building ${goos}/${goarch}..."
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "./$out" ./cmd/bond
}

build windows amd64 bond-windows-amd64.exe
build windows arm64 bond-windows-arm64.exe
build linux   amd64 bond-linux-amd64
build linux   arm64 bond-linux-arm64
build darwin  arm64 bond-macos-arm64

echo "Done: bond ${VERSION}"
