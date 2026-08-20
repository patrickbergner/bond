# Assertions and the bond wrapper that every case is written against.
#
# Sourced by run.sh into each case's subshell, so a case can open with `step`
# and read like the drill it describes rather than like a script.
#
# The rule from CLAUDE.md about error messages applies to this suite's own
# output: when a case fails, the person reading is trying to find out what BOND
# got wrong, not what line of bash gave up. Every failure names the property
# that broke and shows what the binary actually printed.

# ---------------------------------------------------------------------------
# Running the binary

# step names the property the next few assertions prove. It is printed with
# every failure, so an assertion never has to repeat the context it is in.
step() {
    CURRENT_STEP="$1"
    if [ -n "${SUITE_VERBOSE:-}" ]; then
        printf '  · %s\n' "$1"
    fi
}

# bond runs the binary and captures everything, without failing the case. The
# assertion that follows decides whether the outcome was the right one, which
# is why this never exits on a non-zero status of its own.
#
# stdin is /dev/null unless bond_with_stdin supplied something. That is not a
# detail: BOND's prompts check whether stdin is a terminal, and giving it a
# terminal here would hang the suite waiting for a passphrase nobody types.
bond() {
    BOND_ARGS="$*"
    BOND_STATUS=0
    "$BOND" "$@" <"${BOND_STDIN:-/dev/null}" >"$CASE_TMP/.stdout" 2>"$CASE_TMP/.stderr" || BOND_STATUS=$?
    BOND_OUT=$(cat "$CASE_TMP/.stdout")
    BOND_ERR=$(cat "$CASE_TMP/.stderr")
    return 0
}

# bond_with_stdin feeds one line on stdin.
#
# Three operations read a *new* passphrase through ui.ReadPassphrase directly
# rather than through the --passphrase-* flags, because there is no flag for a
# secret that does not exist yet: `keys add --new-passphrase`,
# `keys rotate-passphrase` and `rekey`. For those, and only those, the new
# secret arrives this way while the existing one still comes from
# --passphrase-env.
bond_with_stdin() {
    local text="$1"
    shift
    printf '%s\n' "$text" >"$CASE_TMP/.stdin"
    BOND_STDIN="$CASE_TMP/.stdin" bond "$@"
}

# bond_ok, bond_fail and bond_usage assert the documented exit codes. They are
# separate names rather than one function with a number because a case reading
# `bond_usage restore "$c"` says what it means: this is a mistake in how bond
# was invoked, not a failure while doing the work. See cmd/bond/main.go.
bond_ok() {
    bond "$@"
    [ "$BOND_STATUS" -eq 0 ] || fail "expected this to succeed, but it exited $BOND_STATUS"
}

bond_fail() {
    bond "$@"
    [ "$BOND_STATUS" -eq 1 ] || fail "expected this to be refused with exit 1, but it exited $BOND_STATUS"
}

bond_usage() {
    bond "$@"
    [ "$BOND_STATUS" -eq 2 ] || fail "expected this to be rejected as a usage error (exit 2), but it exited $BOND_STATUS"
}

# ---------------------------------------------------------------------------
# Looking at what it printed
#
# The stream matters and is asserted on deliberately. Normal reporting goes to
# stdout; errors, prompts and every subcommand's --help go to stderr. A test
# that accepted either would not notice the day a message moved into the
# middle of a pipe.

expect_out() {
    case "$BOND_OUT" in
        *"$1"*) : ;;
        *) fail "expected stdout to contain: $1" ;;
    esac
}

expect_err() {
    case "$BOND_ERR" in
        *"$1"*) : ;;
        *) fail "expected stderr to contain: $1" ;;
    esac
}

# expect_out_path matches a path on stdout whichever separator the platform
# printed it with. Enumeration reports paths as the operating system spells
# them – backslashes on Windows – while everything inside a container uses
# forward slashes, and a case should not have to care which one it is reading.
expect_out_path() {
    case "$(printf '%s' "$BOND_OUT" | tr '\\' '/')" in
        *"$1"*) : ;;
        *) fail "expected stdout to name the path: $1" ;;
    esac
}

expect_no_out() {
    case "$BOND_OUT" in
        *"$1"*) fail "did not expect stdout to contain: $1" ;;
        *) : ;;
    esac
}

expect_empty_out() {
    [ -z "$BOND_OUT" ] || fail "expected nothing on stdout, got $(printf '%s' "$BOND_OUT" | wc -l) lines"
}

# out_lines counts the lines the last command wrote to stdout.
out_lines() {
    if [ -z "$BOND_OUT" ]; then
        printf '0\n'
    else
        printf '%s\n' "$BOND_OUT" | wc -l | tr -d ' '
    fi
}

# ---------------------------------------------------------------------------
# Comparing trees
#
# The question a restore has to answer is "are these the same files", so that
# is what is compared: the set of paths, what kind of thing each one is, and
# the bytes. Ownership and permissions are left out because they do not
# survive the Windows leg of a cross-platform format and BOND does not claim
# they do.

# tree_manifest prints one sorted line per entry: kind, relative path, and for
# files the digest of the contents.
#
# The digest is taken from a redirect rather than from an argument so that a
# name with a space or an umlaut in it cannot end up inside the digest line.
tree_manifest() {
    local root="$1"
    (
        cd "$root" || exit 1
        find . -mindepth 1 | LC_ALL=C sort | while IFS= read -r p; do
            local rel="${p#./}"
            if [ -L "$p" ]; then
                printf 'link  %s -> %s\n' "$rel" "$(readlink "$p")"
            elif [ -d "$p" ]; then
                printf 'dir   %s\n' "$rel"
            else
                printf 'file  %s  %s\n' "$rel" "$(sha256sum <"$p" | cut -d' ' -f1)"
            fi
        done
    )
}

assert_trees_equal() {
    local a="$1" b="$2"
    tree_manifest "$a" >"$CASE_TMP/.tree-a"
    tree_manifest "$b" >"$CASE_TMP/.tree-b"
    if ! diff -u "$CASE_TMP/.tree-a" "$CASE_TMP/.tree-b" >"$CASE_TMP/.tree-diff" 2>&1; then
        printf '  the two trees differ (- is %s, + is %s):\n' "$a" "$b" >&2
        head -n 40 "$CASE_TMP/.tree-diff" | sed 's/^/  /' >&2
        fail "the restored tree is not the tree that was backed up"
    fi
}

# assert_paths lists the relative paths under a tree and compares them with
# what the case expects, one per line. Used by the filter cases, where the
# contents are beside the point and the selection is the whole question.
assert_paths() {
    local root="$1" expected="$2"
    ( cd "$root" && find . -mindepth 1 -type f | sed 's|^\./||' ) | LC_ALL=C sort >"$CASE_TMP/.paths-got"
    printf '%s\n' "$expected" | grep -v '^$' | LC_ALL=C sort >"$CASE_TMP/.paths-want"
    if ! diff -u "$CASE_TMP/.paths-want" "$CASE_TMP/.paths-got" >"$CASE_TMP/.paths-diff" 2>&1; then
        printf '  (- expected, + actually restored):\n' >&2
        sed 's/^/  /' "$CASE_TMP/.paths-diff" >&2
        fail "the wrong set of files came back"
    fi
}

mtime_of() {
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"
}

# assert_mtimes_equal proves the format's claim that modification times
# survive. Only files are compared: directory times are rewritten as their
# contents are unpacked, on every extractor there is.
#
# The loop reads from a process substitution rather than from a pipe, because a
# pipe would run it in a subshell where `fail` ends the loop and not the case –
# an assertion that cannot fail the thing it is asserting about is worse than
# no assertion at all.
assert_mtimes_equal() {
    local a="$1" b="$2" rel ta tb
    while IFS= read -r rel; do
        ta=$(mtime_of "$a/$rel")
        tb=$(mtime_of "$b/$rel")
        if [ "$ta" != "$tb" ]; then
            printf '  %s: was %s, came back %s\n' "${rel#./}" "$ta" "$tb" >&2
            fail "modification times did not survive the round trip"
        fi
    done < <( cd "$a" && find . -mindepth 1 -type f | LC_ALL=C sort )
}

assert_files_identical() {
    cmp -s "$1" "$2" || fail "$1 and $2 differ, and this case requires them to be byte-for-byte the same"
}

assert_files_differ() {
    cmp -s "$1" "$2" && fail "$1 and $2 are identical, and this case requires them to differ"
    return 0
}

assert_exists() {
    [ -e "$1" ] || fail "expected $1 to exist"
}

assert_missing() {
    [ ! -e "$1" ] || fail "expected $1 not to exist"
}

file_bytes() {
    wc -c <"$1" | tr -d ' '
}

# ---------------------------------------------------------------------------
# Finding what a backup wrote
#
# Container names carry {{TIMESTAMP}}, so no case may hardcode one. These are
# the only sanctioned way to name a container a backup just produced.

container_in() {
    local dir="$1" found n
    found=$(find "$dir" -maxdepth 1 -name '*.bond' | LC_ALL=C sort)
    n=$(printf '%s' "$found" | grep -c . || true)
    [ "$n" -eq 1 ] || fail "expected exactly one container in $dir, found $n"
    printf '%s\n' "$found"
}

# container_for names the container a particular target produced, for the runs
# that back up several at once.
container_for() {
    local dir="$1" id="$2" found n
    found=$(find "$dir" -maxdepth 1 -name "$id-*.bond" | LC_ALL=C sort)
    n=$(printf '%s' "$found" | grep -c . || true)
    [ "$n" -eq 1 ] || fail "expected exactly one container for target $id in $dir, found $n"
    printf '%s\n' "$found"
}

# volume_base_in names a split set by the stem its volumes share, which is the
# name an operator uses and the name every command accepts.
volume_base_in() {
    local dir="$1" found n
    found=$(find "$dir" -maxdepth 1 -name '*.bond.001' | LC_ALL=C sort)
    n=$(printf '%s' "$found" | grep -c . || true)
    [ "$n" -eq 1 ] || fail "expected exactly one split set in $dir, found $n first volumes"
    printf '%s\n' "${found%.001}"
}

volumes_of() {
    find "$(dirname "$1")" -maxdepth 1 -name "$(basename "$1").[0-9][0-9][0-9]" | LC_ALL=C sort
}

count_volumes() {
    volumes_of "$1" | grep -c . || true
}

# ---------------------------------------------------------------------------
# Ending a case

# skip_case ends the case as SKIP. The reason is shown in the summary, so it
# has to say what is missing here rather than what was skipped.
skip_case() {
    printf '%s\n' "$1" >"$CASE_SKIP"
    exit 0
}

fail() {
    {
        printf '\n'
        printf '  the property that broke:  %s\n' "${CURRENT_STEP:-(no step was named)}"
        printf '  what went wrong:          %s\n' "$1"
        if [ -n "${BOND_ARGS:-}" ]; then
            printf '  last command:             bond %s\n' "$BOND_ARGS"
            printf '  it exited:                %s\n' "${BOND_STATUS:-?}"
            if [ -n "${BOND_OUT:-}" ]; then
                printf '  --- its stdout ---\n'
                printf '%s\n' "$BOND_OUT" | sed 's/^/  | /'
            fi
            if [ -n "${BOND_ERR:-}" ]; then
                printf '  --- its stderr ---\n'
                printf '%s\n' "$BOND_ERR" | sed 's/^/  | /'
            fi
        fi
    } >&2
    exit 1
}

CURRENT_STEP=""
