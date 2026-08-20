#!/usr/bin/env bash
#
# End-to-end tests: the bond binary, a real control file, real containers on a
# real filesystem.
#
# The Go tests cover the packages thoroughly and the format exhaustively. What
# they do not cover is the binary – argument parsing, exit codes, config
# discovery, the way a secret reaches the tool without a terminal, and a
# container as the file an operator copies, renames, loses a volume of and
# tries to open anyway. That is what runs here.
#
# Run it after ./build.sh, which produces the binaries it drives.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

SUITE_DIR="$PWD"
REPO_DIR="$(dirname "$SUITE_DIR")"

# Paths are handed to a Go binary, so on Windows they have to be the paths
# Windows knows. Mixed mode (C:/like/this) is understood by both this shell and
# the binary, and needs no escaping in a JSON control file.
if command -v cygpath >/dev/null 2>&1; then
    SUITE_DIR="$(cygpath -m "$SUITE_DIR")"
    REPO_DIR="$(cygpath -m "$REPO_DIR")"

    # MSYS has a mode where "ln -s" writes a Windows shortcut. This shell then
    # reports it as a symbolic link and a Go binary reads it as an ordinary
    # file, which would turn the symlink case into a test of the shortcut
    # format. Either the machine makes real links or the case skips; a
    # shortcut is neither, so the mode that produces one is turned off here.
    export MSYS="${MSYS:+$MSYS }winsymlinks:nativestrict"
fi

KEEP=""
SUITE_VERBOSE=""
LIST_ONLY=""
PATTERNS=()

usage() {
    cat <<'EOF'
usage: testsuite/run.sh [options] [pattern ...]

Runs each testsuite/NN-name/case.sh against a bond binary from the repository
root. A pattern selects cases whose directory name contains it.

options:
      --keep      leave every case's working directory behind, not just the
                  ones that failed
  -v, --verbose   print each step as it is proved, and each case's output
      --list      name the cases that would run, and run none of them
  -h, --help      this

environment:
      BOND_BIN         a binary to test instead of the one for this platform
      BOND_TEST_SEED   reshapes every generated tree (default 13333337)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --keep) KEEP=1 ;;
        -v|--verbose) SUITE_VERBOSE=1 ;;
        --list) LIST_ONLY=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "error: unknown option $1" >&2; usage >&2; exit 2 ;;
        *) PATTERNS+=("$1") ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# The binary under test

# platform_binary names the build.sh output for this machine.
platform_binary() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        MINGW*|MSYS*|CYGWIN*)
            case "$arch" in
                x86_64) echo "bond-windows-amd64.exe" ;;
                aarch64|arm64) echo "bond-windows-arm64.exe" ;;
                *) return 1 ;;
            esac ;;
        Linux)
            case "$arch" in
                x86_64) echo "bond-linux-amd64" ;;
                aarch64|arm64) echo "bond-linux-arm64" ;;
                *) return 1 ;;
            esac ;;
        Darwin)
            case "$arch" in
                arm64) echo "bond-macos-arm64" ;;
                *) return 1 ;;
            esac ;;
        *) return 1 ;;
    esac
}

if [ -n "${BOND_BIN:-}" ]; then
    BOND="$BOND_BIN"
    if [ ! -x "$BOND" ]; then
        echo "error: BOND_BIN is set to $BOND, which is not an executable file" >&2
        exit 1
    fi
else
    name="$(platform_binary)" || {
        echo "error: there is no build.sh output for $(uname -s)/$(uname -m); name one with BOND_BIN" >&2
        exit 1
    }
    BOND="$REPO_DIR/$name"
    if [ ! -x "$BOND" ]; then
        echo "error: $name is not in the repository root; run ./build.sh first" >&2
        exit 1
    fi
fi

export BOND

# ---------------------------------------------------------------------------
# Colour, only for a person watching

if [ -t 1 ]; then
    C_PASS=$'\033[0;92m'; C_FAIL=$'\033[0;91m'; C_SKIP=$'\033[0;93m'; C_DIM=$'\033[0;90m'; C_OFF=$'\033[0m'
else
    C_PASS=""; C_FAIL=""; C_SKIP=""; C_DIM=""; C_OFF=""
fi

# ---------------------------------------------------------------------------
# Discovery

mapfile -t ALL_CASES < <(find . -mindepth 2 -maxdepth 2 -name case.sh |
    sed -e 's|^\./||' -e 's|/case\.sh$||' | LC_ALL=C sort)

if [ ${#ALL_CASES[@]} -eq 0 ]; then
    echo "error: no NN-name/case.sh found beside this script" >&2
    exit 1
fi

CASES=()
for c in "${ALL_CASES[@]}"; do
    if [ ${#PATTERNS[@]} -eq 0 ]; then
        CASES+=("$c")
        continue
    fi
    for p in "${PATTERNS[@]}"; do
        case "$c" in
            *"$p"*) CASES+=("$c"); break ;;
        esac
    done
done

if [ ${#CASES[@]} -eq 0 ]; then
    echo "error: no cases matched" >&2
    exit 1
fi

if [ -n "$LIST_ONLY" ]; then
    printf '%s\n' "${CASES[@]}"
    exit 0
fi

# ---------------------------------------------------------------------------
# Running

RUN_ID="$$"
RUN_DIR="$SUITE_DIR/tmp/$RUN_ID"
mkdir -p "$RUN_DIR"

BOND_TEST_SEED="${BOND_TEST_SEED:-13333337}"
export BOND_TEST_SEED

# Every case unlocks with this, by --passphrase-env. A constant is right here:
# the secret is not what is being tested, and a container written by a run that
# failed is more useful to look at than one nobody can open.
BOND_TEST_PASS="the pen is mightier than the sword, but not than a shard"
export BOND_TEST_PASS

echo "bond      $("$BOND" version | head -n 1) – $BOND"
echo "seed      $BOND_TEST_SEED"
echo "workspace $RUN_DIR"
echo

passed=0
failed=0
skipped=0
FAILED_CASES=()
started_all=$SECONDS

for name in "${CASES[@]}"; do
    case_tmp="$RUN_DIR/$name"
    case_log="$RUN_DIR/$name.log"
    case_skip="$RUN_DIR/$name.skip"
    mkdir -p "$case_tmp"

    printf '%s... ' "$name"
    started=$SECONDS

    status=0
    (
        set -euo pipefail
        export CASE_DIR="$SUITE_DIR/$name"
        export CASE_TMP="$case_tmp"
        export CASE_SKIP="$case_skip"
        export SUITE_VERBOSE
        # shellcheck source=lib/harness.sh
        . "$SUITE_DIR/lib/harness.sh"
        . "$SUITE_DIR/lib/gendata.sh"
        . "$SUITE_DIR/lib/config.sh"
        . "$SUITE_DIR/lib/damage.sh"
        seed_rng "$BOND_TEST_SEED"
        cd "$CASE_TMP"
        . "$SUITE_DIR/$name/case.sh"
    ) >"$case_log" 2>&1 || status=$?

    took=$(( SECONDS - started ))

    if [ "$status" -eq 0 ] && [ -f "$case_skip" ]; then
        skipped=$(( skipped + 1 ))
        printf '%sSKIP%s  %s\n' "$C_SKIP" "$C_OFF" "$(cat "$case_skip")"
        [ -n "$KEEP" ] || rm -rf "$case_tmp"
    elif [ "$status" -eq 0 ]; then
        passed=$(( passed + 1 ))
        printf '%sPASS%s %s(%ss)%s\n' "$C_PASS" "$C_OFF" "$C_DIM" "$took" "$C_OFF"
        if [ -n "$SUITE_VERBOSE" ]; then
            sed 's/^/    /' "$case_log"
        fi
        [ -n "$KEEP" ] || rm -rf "$case_tmp"
    else
        failed=$(( failed + 1 ))
        FAILED_CASES+=("$name")
        printf '%sFAIL%s %s(%ss)%s\n' "$C_FAIL" "$C_OFF" "$C_DIM" "$took" "$C_OFF"
        sed 's/^/    /' "$case_log"
        printf '    %skept: %s%s\n' "$C_DIM" "$case_tmp" "$C_OFF"
    fi
done

echo
printf '%d passed, %d failed, %d skipped in %ss\n' "$passed" "$failed" "$skipped" "$(( SECONDS - started_all ))"

if [ "$failed" -gt 0 ]; then
    printf 'failed: %s\n' "${FAILED_CASES[*]}"
    echo "the working directories above were kept; run again with -v for each step as it is proved"
    exit 1
fi

# Nothing failed, so there is nothing to look at. Anything the run left behind
# on purpose stays; the run's own directory does not.
[ -n "$KEEP" ] || rm -rf "$RUN_DIR"
rmdir "$SUITE_DIR/tmp" 2>/dev/null || true
exit 0
