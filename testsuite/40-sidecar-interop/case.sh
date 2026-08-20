# The checksum file, read by something other than bond.
#
# A backup is only as good as the copy that arrived, and the first thing an
# operator does after an upload is check it. BOND writes the sidecar in the
# format the standard sha*sum tools read, precisely so that check does not
# depend on having bond to hand – a machine that has lost the tool has not lost
# the ability to tell whether the file is intact. Nothing but a shell can prove
# that, so nothing but this case does.

src="$CASE_TMP/data"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

gen_tree "$src" 512

backup_with() {
    local id="$1" hash_setting="$2" out="$CASE_TMP/output-$1"
    config_new "$out" "$work"
    config_setting '"encryptionMethod": "NONE"'
    config_setting "$hash_setting"
    config_target "$id" "$src"
    config_write "$cfg"
    bond_ok backup --config "$cfg"
    CONTAINER="$(container_in "$out")"
}

step "the default is SHA-384, and coreutils reads the file bond wrote"
backup_with default '"hashAlgorithm": "SHA384"'
assert_exists "$CONTAINER.sha384"
( cd "$(dirname "$CONTAINER")" && sha384sum -c "$(basename "$CONTAINER").sha384" ) >"$CASE_TMP/.sha" 2>&1 ||
    fail "sha384sum could not verify the file bond wrote: $(cat "$CASE_TMP/.sha")"

step "the sidecar names the container by its bare name, so the pair can be moved together"
elsewhere="$CASE_TMP/elsewhere"
mkdir -p "$elsewhere"
cp "$CONTAINER" "$CONTAINER.sha384" "$elsewhere/"
( cd "$elsewhere" && sha384sum -c "$(basename "$CONTAINER").sha384" ) >/dev/null 2>&1 ||
    fail "the checksum file stopped working once the pair was moved to another directory"

step "one changed byte is caught by coreutils and by bond alike"
poke_payload "$elsewhere/$(basename "$CONTAINER")" 4096 64
( cd "$elsewhere" && sha384sum -c "$(basename "$CONTAINER").sha384" ) >/dev/null 2>&1 &&
    fail "sha384sum accepted a container that had been altered"
bond_fail verify "$elsewhere/$(basename "$CONTAINER")" --quick
expect_err "does not match"

step "SHA-256 and SHA-512 are written under their own names and read the same way"
backup_with two-fifty-six '"hashAlgorithm": "SHA256"'
assert_exists "$CONTAINER.sha256"
assert_missing "$CONTAINER.sha384"
( cd "$(dirname "$CONTAINER")" && sha256sum -c "$(basename "$CONTAINER").sha256" ) >/dev/null 2>&1 ||
    fail "sha256sum could not verify the file bond wrote"

backup_with five-twelve '"hashAlgorithm": "SHA512"'
assert_exists "$CONTAINER.sha512"
( cd "$(dirname "$CONTAINER")" && sha512sum -c "$(basename "$CONTAINER").sha512" ) >/dev/null 2>&1 ||
    fail "sha512sum could not verify the file bond wrote"

step "asking for no checksum file writes none, and the quick check says so rather than passing"
backup_with none '"hashAlgorithm": "NONE"'
assert_missing "$CONTAINER.sha256"
assert_missing "$CONTAINER.sha384"
assert_missing "$CONTAINER.sha512"
bond_fail verify "$CONTAINER" --quick
expect_err "no checksum file next to"

step "a container with no sidecar still verifies in full: the sidecar is a convenience, not the proof"
bond_ok verify "$CONTAINER"
expect_out "OK"
