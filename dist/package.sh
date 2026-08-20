#!/usr/bin/env bash
#
# Builds the release packages from what build.sh left in the repository root.
# Run build.sh first; this script compiles nothing.
set -euo pipefail

# Every path below is written from the repository root.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${BOND_VERSION:-$(cat VERSION)}"
if [ -z "$VERSION" ]; then
    echo "error: VERSION is missing or empty; it is the only place the release is named" >&2
    exit 1
fi

DIST="dist"
STAGE="$DIST/stage"
ROOT="bond-${VERSION}"

# Reproducible archives: every file is given the commit timestamp
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || date +%s)"
fi
export SOURCE_DATE_EPOCH TZ=UTC

# tag           the word in the archive name
# binary        what build.sh produced
# exe           what it is called inside the archive
# license       the 7-Zip terms for that exact binary, from tools/licenses
# format        zip carries no executable bit, so only Windows gets it
TARGETS=(
    "windows-amd64 bond-windows-amd64.exe bond.exe 7za-windows-amd64.exe.txt zip"
    "windows-arm64 bond-windows-arm64.exe bond.exe 7za-windows-arm64.exe.txt zip"
    "linux-amd64   bond-linux-amd64       bond     7zz-linux-amd64.txt       tar"
    "linux-arm64   bond-linux-arm64       bond     7zz-linux-arm64.txt       tar"
    "macos-arm64   bond-macos-arm64      bond     7zz-darwin-arm64.txt      tar"
)

CONTENTS=(config.sample.json readme.txt LICENSE LICENSE-7-Zip.txt)

rm -rf "$STAGE"
rm -f "$DIST"/bond-*.zip "$DIST"/bond-*.tar.gz "$DIST"/SHA256SUMS.txt
mkdir -p "$STAGE"

for spec in "${TARGETS[@]}"; do
    read -r tag binary exe license format <<<"$spec"

    if [ ! -f "$binary" ]; then
        echo "error: $binary is not here; run ./build.sh first" >&2
        exit 1
    fi

    if [ ! -s "tools/licenses/$license" ]; then
        echo "error: tools/licenses/$license is missing or empty; run 'go run ./tools/fetch'" >&2
        exit 1
    fi

    dir="$STAGE/$tag/$ROOT"
    mkdir -p "$dir"

    install -m 0755 "$binary" "$dir/$exe"
    install -m 0644 config.sample.json "$dir/config.sample.json"
    install -m 0644 LICENSE "$dir/LICENSE"
    install -m 0644 "tools/licenses/$license" "$dir/LICENSE-7-Zip.txt"

    # Windows packages get CRLF readme.txt
    if [ "$format" = zip ]; then
        sed 's/$/\r/' "$DIST/readme.txt" >"$dir/readme.txt"
    else
        cp "$DIST/readme.txt" "$dir/readme.txt"
    fi
    chmod 0644 "$dir/readme.txt"

    find "$STAGE/$tag" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

    case "$format" in
        zip)
            archive="$DIST/bond-$VERSION-$tag.zip"
            (cd "$STAGE/$tag" && zip -q -X "$OLDPWD/$archive" \
                "$ROOT/" "$ROOT/$exe" "${CONTENTS[@]/#/$ROOT/}")
            ;;
        tar)
            archive="$DIST/bond-$VERSION-$tag.tar.gz"
            tar --format=gnu --sort=name --owner=0 --group=0 --numeric-owner \
                --mtime="@$SOURCE_DATE_EPOCH" \
                -C "$STAGE/$tag" -cf - "$ROOT" | gzip -9n >"$archive"
            ;;
    esac

    # Read the archive back and check what is actually in it
    case "$format" in
        zip)
            actual="$(unzip -Z1 "$archive")"
            expected="$(printf '%s\n' "$ROOT/$exe" "${CONTENTS[@]/#/$ROOT/}")"
            ;;
        tar)
            actual="$(tar -tvzf "$archive" | awk '{ print $1, $NF }')"
            expected="$(
                echo "-rwxr-xr-x $ROOT/$exe"
                printf -- '-rw-r--r-- %s\n' "${CONTENTS[@]/#/$ROOT/}"
            )"
            ;;
    esac
    actual="$(printf '%s\n' "$actual" | grep -v '/$' | LC_ALL=C sort)"
    expected="$(printf '%s\n' "$expected" | LC_ALL=C sort)"

    if [ "$actual" != "$expected" ]; then
        echo "error: unexpected layout in $archive" >&2
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
        exit 1
    fi

    echo "Packaged $archive"
done

rm -rf "$STAGE"

(cd "$DIST" && sha256sum bond-"$VERSION"-* >SHA256SUMS.txt)

echo "Done: bond ${VERSION}, ${#TARGETS[@]} packages in ${DIST}/"
