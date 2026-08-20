# Input that is wrong, and has to be refused rather than worked around.
#
# The premise of this tool is that the storage cannot be trusted, and the
# reader's job when something does not add up is to say so. Every step here
# checks a refusal: that it happens, that it is loud, and that the message
# gives the person on the other end of it somewhere to go.

src="$CASE_TMP/data"
out="$CASE_TMP/output"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

gen_tree "$src" 512

config_new "$out" "$work"
config_setting '"encryptionMethod": "PROMPT_KEYPHRASE"'
config_target vault "$src"
config_write "$cfg"
bond_ok backup --config "$cfg" --passphrase-env BOND_TEST_PASS
container="$(container_in "$out")"

# ---------------------------------------------------------------------------
# Secrets that are not the secret

step "a wrong passphrase is refused, and the refusal names what the container takes"
export BOND_WRONG="not the passphrase, and never was"
bond_fail list "$container" --passphrase-env BOND_WRONG
expect_err "wrong passphrase or key"
expect_err "passphrase"

step "a wrong passphrase is refused before a byte of payload is read"
# A restore that got as far as writing files before noticing would be worse
# than one that never started: half a tree is harder to reason about than none.
bond_fail restore "$container" --to "$CASE_TMP/restored-wrong" --passphrase-env BOND_WRONG
[ -z "$(find "$CASE_TMP/restored-wrong" -type f 2>/dev/null)" ] ||
    fail "a restore under the wrong passphrase wrote files before it gave up"

step "an environment variable that is not set is different from one that is empty"
unset BOND_UNSET 2>/dev/null || true
bond_fail list "$container" --passphrase-env BOND_UNSET
expect_err "is not set"
export BOND_EMPTY=""
bond_fail list "$container" --passphrase-env BOND_EMPTY
expect_err "is empty"

step "an empty passphrase file is refused rather than treated as a passphrase"
: >"$CASE_TMP/empty-pass.txt"
bond_fail list "$container" --passphrase-file "$CASE_TMP/empty-pass.txt"
expect_err "is empty"

step "a passphrase file that does not exist says which one"
bond_fail list "$container" --passphrase-file "$CASE_TMP/no-such-file.txt"
expect_err "reading the passphrase file"

step "a passphrase file is read as its first line, so a trailing newline is not part of the secret"
printf '%s\n' "$BOND_TEST_PASS" >"$CASE_TMP/pass.txt"
bond_ok list "$container" --passphrase-file "$CASE_TMP/pass.txt"

step "a passphrase on the command line works, and warns that it should not have been"
bond_ok list "$container" --passphrase "$BOND_TEST_PASS"
expect_err "visible to other processes"

# ---------------------------------------------------------------------------
# Files that are not containers

step "a file of random bytes is not a container, and is not treated as one"
head -c 200000 /dev/urandom >"$CASE_TMP/noise.bond"
bond_fail inspect "$CASE_TMP/noise.bond"
bond_fail verify "$CASE_TMP/noise.bond" --passphrase-env BOND_TEST_PASS
bond_fail restore "$CASE_TMP/noise.bond" --to "$CASE_TMP/restored-noise" --passphrase-env BOND_TEST_PASS

step "an empty file is not a container either"
: >"$CASE_TMP/empty.bond"
bond_fail inspect "$CASE_TMP/empty.bond"

step "a container that does not exist says so, rather than saying nothing"
bond_fail inspect "$CASE_TMP/never-existed.bond"
bond_fail verify "$CASE_TMP/never-existed.bond" --quick
expect_err "does not exist"

step "a truncated container is refused by every command that reads it"
cp "$container" "$CASE_TMP/short.bond"
truncate_by "$CASE_TMP/short.bond" 60000
bond_fail verify "$CASE_TMP/short.bond" --passphrase-env BOND_TEST_PASS
bond_fail restore "$CASE_TMP/short.bond" --to "$CASE_TMP/restored-truncated" --passphrase-env BOND_TEST_PASS

step "one destroyed header copy is survived, because the mirror at the end is the other one"
cp "$container" "$CASE_TMP/one-header.bond"
poke "$CASE_TMP/one-header.bond" 0 512
bond_ok inspect "$CASE_TMP/one-header.bond" --passphrase-env BOND_TEST_PASS
expect_out "the header at the front is damaged; the mirror at the end was used"

step "both header copies destroyed is refused loudly, with nothing salvaged in silence"
cp "$CASE_TMP/one-header.bond" "$CASE_TMP/headless.bond"
poke "$CASE_TMP/headless.bond" $(( $(file_bytes "$CASE_TMP/headless.bond") - 4096 )) 512
bond_fail inspect "$CASE_TMP/headless.bond"
bond_fail restore "$CASE_TMP/headless.bond" --to "$CASE_TMP/restored-headless" --passphrase-env BOND_TEST_PASS

# ---------------------------------------------------------------------------
# Control files that are wrong

step "an unknown key in the control file is an error, not something ignored"
config_new "$out" "$work"
config_setting '"compressionLevel": 3'
config_setting '"compresionLevel": 3'
config_target vault "$src"
config_write "$cfg"
bond_fail backup --config "$cfg" --passphrase-env BOND_TEST_PASS
expect_err "compresionLevel"

step "a control file that is not JSON at all says where it went wrong"
echo 'targets: everything' >"$cfg"
bond_fail backup --config "$cfg"

step "a control file named but not there stops the run and names the file"
# Recorded as it behaves: this is exit 1 rather than the 2 that a control file
# found in none of the default places produces. The two are different questions
# – one is a mistake in the command, the other is a file that is missing – so
# the difference is defensible; the test is here to notice if it changes.
bond_fail backup --config "$CASE_TMP/no-such-config.json"
expect_err "no-such-config.json"

step "with no control file anywhere, bond says where it looked"
mkdir -p "$CASE_TMP/nowhere"
( cd "$CASE_TMP/nowhere" && "$BOND" backup ) >"$CASE_TMP/.nowhere-out" 2>"$CASE_TMP/.nowhere-err" && \
    fail "a backup with no control file anywhere should not have succeeded"
grep -q 'no control file found' "$CASE_TMP/.nowhere-err" ||
    fail "the message did not say that no control file was found: $(cat "$CASE_TMP/.nowhere-err")"

step "a source path that does not exist stops the run and names the path"
config_new "$out" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target ghost "$CASE_TMP/there-is-no-such-directory"
config_write "$cfg"
bond_fail backup --config "$cfg"
expect_out_path "there-is-no-such-directory"

step "a target id the format does not allow is refused when the control file is read"
config_new "$out" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target 'not a valid id' "$src"
config_write "$cfg"
bond_fail backup --config "$cfg"

# ---------------------------------------------------------------------------
# Sources that cannot be read

step "an unreadable path fails the run, and --ignore-errors backs up the rest while still failing"
# On Windows a directory whose name ends in a space is the easy way to make a
# path the system will not open: MSYS creates it, and the Win32 API then cannot
# find it. Where that trick does not work, the step has nothing to test and
# says so rather than passing vacuously.
awkward_src="$CASE_TMP/partly-readable"
mkdir -p "$awkward_src/fine"
echo 'readable' >"$awkward_src/fine/ok.txt"

# Two candidates, because no single trick works on both platforms: a directory
# with its permissions taken away, which POSIX honours, and one whose name ends
# in a space, which the Win32 API cannot open at all. Whether either of them
# really is unreadable is decided by asking BOND rather than by asking the
# shell – on Windows, MSYS can happily stat a path the Win32 API cannot open,
# so a shell-side test says yes exactly where the tool says no.
mkdir -p "$awkward_src/no-permission" 2>/dev/null || true
echo 'hidden' >"$awkward_src/no-permission/secret.txt" 2>/dev/null || true
chmod 000 "$awkward_src/no-permission" 2>/dev/null || true
mkdir "$awkward_src/trailing space " 2>/dev/null || true

config_new "$CASE_TMP/output-partial" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target partial "$awkward_src"
config_write "$cfg"
bond backup --config "$cfg"

if [ "$BOND_STATUS" -ne 0 ] && printf '%s' "$BOND_OUT" | grep -q 'could not be read'; then
    expect_out "use --ignore-errors to back up what is readable anyway"
    [ "$(find "$CASE_TMP/output-partial" -name '*.bond' 2>/dev/null | grep -c . || true)" -eq 0 ] ||
        fail "a backup that failed on an unreadable path left a container behind"

    step "--ignore-errors stores what can be read, and the run still fails so nobody calls it complete"
    bond_fail backup --config "$cfg" --ignore-errors
    partial="$(container_in "$CASE_TMP/output-partial")"
    bond_ok verify "$partial"
    expect_out "OK"

    step "and what it did store comes back"
    # The restore itself may be refused: a directory named with a trailing
    # space can be enumerated on Windows even though it cannot be opened, so
    # the entry reaches the container and the extraction policy then declines
    # to write a path the filesystem would silently rename. Either answer is
    # right. Writing the readable file to the wrong name would not be.
    bond restore "$partial" --to "$CASE_TMP/restored-partial"
    if [ "$BOND_STATUS" -ne 0 ]; then
        expect_err "ends in a space or dot, which Windows silently strips"
    fi
    assert_exists "$CASE_TMP/restored-partial/partly-readable/fine/ok.txt"
    cmp -s "$CASE_TMP/restored-partial/partly-readable/fine/ok.txt" "$awkward_src/fine/ok.txt" ||
        fail "the one file that was readable did not come back intact"
else
    printf '    (nothing on this machine could be made unreadable, so --ignore-errors was not exercised)\n'
fi
chmod 755 "$awkward_src/no-permission" 2>/dev/null || true

# ---------------------------------------------------------------------------

step "restoring over existing files is refused, and --overwrite is the way to mean it"
bond_ok restore "$container" --to "$CASE_TMP/restored-twice" --passphrase-env BOND_TEST_PASS
bond_fail restore "$container" --to "$CASE_TMP/restored-twice" --passphrase-env BOND_TEST_PASS
bond_ok restore "$container" --to "$CASE_TMP/restored-twice" --overwrite --passphrase-env BOND_TEST_PASS
assert_trees_equal "$src" "$CASE_TMP/restored-twice/data"

step "a destination whose parent does not exist is created rather than refused"
bond_ok restore "$container" --to "$CASE_TMP/a/b/c/restored" --passphrase-env BOND_TEST_PASS
assert_trees_equal "$src" "$CASE_TMP/a/b/c/restored/data"

step "a name the filesystem would silently rename is never written under the renamed name"
# The extraction policy's job is that a path in a container either comes out as
# itself or does not come out at all. The stripped form appearing on disk would
# be the worst kind of success: a restore that reported no problem and put the
# file somewhere else.
if [ -d "$CASE_TMP/restored-partial" ]; then
    assert_missing "$CASE_TMP/restored-partial/partly-readable/trailing space"
fi
