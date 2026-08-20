# The files that break archivers.
#
# Empty files, names with umlauts and spaces in them, a directory with nothing
# in it, a path long enough to worry about, something incompressible and
# something that compresses to almost nothing. None of it is exotic – it is
# what a real home directory holds – and all of it is where a backup tool
# quietly loses an entry and reports success.

src="$CASE_TMP/awkward"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

gen_tree "$src" 512 awkward

step "an empty file, an empty directory and a one-byte file are all really there to begin with"
assert_exists "$src/empty.txt"
[ "$(file_bytes "$src/empty.txt")" -eq 0 ] || fail "empty.txt is not empty"
[ "$(file_bytes "$src/one-byte.txt")" -eq 1 ] || fail "one-byte.txt is not one byte"
[ -d "$src/an empty directory" ] || fail "the empty directory was not created"

round_trip() {
    local id="$1" level="$2" out="$CASE_TMP/output-$1"
    config_new "$out" "$work"
    config_setting '"encryptionMethod": "NONE"'
    config_setting "\"compressionLevel\": $level"
    config_target "$id" "$src"
    config_write "$cfg"
    bond_ok backup --config "$cfg"
    CONTAINER="$(container_in "$out")"
    bond_ok verify "$CONTAINER"
    bond_ok restore "$CONTAINER" --to "$CASE_TMP/restored-$1"
    RESTORED="$CASE_TMP/restored-$1/awkward"
}

step "stored without compression, every awkward entry comes back exactly as it went in"
round_trip stored 0
assert_trees_equal "$src" "$RESTORED"
bond_ok inspect "$CONTAINER"
expect_out "compression       none"

step "compressed hard, the same tree comes back the same way"
round_trip squeezed 9
assert_trees_equal "$src" "$RESTORED"
bond_ok inspect "$CONTAINER"
expect_out "compression       xz, level 9"

step "compression is not just a flag: the compressed container is the smaller of the two"
stored_bytes=$(file_bytes "$(container_in "$CASE_TMP/output-stored")")
squeezed_bytes=$(file_bytes "$(container_in "$CASE_TMP/output-squeezed")")
[ "$squeezed_bytes" -lt "$stored_bytes" ] ||
    fail "compressing produced $squeezed_bytes bytes and storing produced $stored_bytes; compression achieved nothing"

step "the empty directory survived, which is the entry most often dropped"
[ -d "$RESTORED/an empty directory" ] ||
    fail "the empty directory was not restored; an archiver that stores only files loses it"
[ -z "$(find "$RESTORED/an empty directory" -mindepth 1)" ] ||
    fail "something was restored into the empty directory"

step "names with umlauts and spaces are listed as they are spelled"
bond_ok list "$CONTAINER"
expect_out "awkward/Grüße/Kapitel 1.txt"
expect_out "awkward/ünïcödé and spaces.json"

step "a subtree can be restored on its own, and nothing outside it comes with it"
bond_ok restore "$CONTAINER" --to "$CASE_TMP/restored-part" --include "awkward/notes"
assert_exists "$CASE_TMP/restored-part/awkward/notes"
assert_missing "$CASE_TMP/restored-part/awkward/photos"
assert_missing "$CASE_TMP/restored-part/awkward/empty.txt"

step "a prefix that matches nothing restores nothing, rather than everything"
bond_ok restore "$CONTAINER" --to "$CASE_TMP/restored-none" --include "awkward/nothing-by-that-name"
[ -z "$(find "$CASE_TMP/restored-none" -type f 2>/dev/null)" ] ||
    fail "an --include prefix that matches nothing restored files anyway"

