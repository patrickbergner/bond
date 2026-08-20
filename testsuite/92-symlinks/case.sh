# Symbolic links, which are three different things depending on what was asked
# for.
#
# A link can be stored as a link, stored as the file it points at, or left out
# of a restore entirely – and the default is the cautious one, because a
# restore that recreates links recreates whatever they point at too, possibly
# somewhere the operator did not mean to write.
#
# This is its own case rather than part of 91 because a machine that will not
# make a symbolic link cannot answer any of it, and one platform limitation
# should not hide eight results that have nothing to do with it.

src="$CASE_TMP/links"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

mkdir -p "$src/real"
echo 'the thing itself' >"$src/real/target.txt"
gen_blob "$src/real/bulk.bin" 40000 mixed

if ! gen_symlink "$src/pointer.txt" "real/target.txt"; then
    skip_case "this machine will not create symbolic links (on Windows that needs developer mode)"
fi
gen_symlink "$src/pointer-to-nowhere" "real/does-not-exist" ||
    fail "one symbolic link could be created and another could not"

step "a link is stored as a link, and the listing says where it points"
config_new "$CASE_TMP/output-links" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"followSymlinks": false'
config_target links "$src"
config_write "$cfg"
bond_ok backup --config "$cfg"
container="$(container_in "$CASE_TMP/output-links")"
bond_ok list "$container" -l
expect_out "pointer.txt -> real/target.txt"

step "a link that points at nothing is stored as what it is, not chased and not dropped"
expect_out "pointer-to-nowhere -> real/does-not-exist"
bond_ok verify "$container"
expect_out "OK"

step "a restore leaves links out unless it is asked for them"
bond_ok restore "$container" --to "$CASE_TMP/restored-nolinks"
assert_exists "$CASE_TMP/restored-nolinks/links/real/target.txt"
assert_missing "$CASE_TMP/restored-nolinks/links/pointer.txt"
expect_out "skipped"

step "--symlinks restores it, still a link and still pointing where it pointed"
bond_ok restore "$container" --to "$CASE_TMP/restored-links" --symlinks
[ -L "$CASE_TMP/restored-links/links/pointer.txt" ] ||
    fail "pointer.txt came back, but not as a symbolic link"
[ "$(readlink "$CASE_TMP/restored-links/links/pointer.txt")" = "real/target.txt" ] ||
    fail "the restored link points at $(readlink "$CASE_TMP/restored-links/links/pointer.txt") instead"
cmp -s "$CASE_TMP/restored-links/links/real/target.txt" "$src/real/target.txt" ||
    fail "the file the restored link points at is not the file it pointed at"

step "followSymlinks stores what the link points at, as an ordinary file"
# The dangling link is left out of this target on purpose: a link to nothing is
# a legitimate thing to store, and a legitimate thing to fail on when told to
# store what it points at. Which of those happens is a separate question from
# this one, and mixing them would make a failure here ambiguous.
config_new "$CASE_TMP/output-followed" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"followSymlinks": true'
config_target followed "$src" '"excludedFileNames": ["pointer-to-nowhere"]'
config_write "$cfg"
bond_ok backup --config "$cfg"
bond_ok restore "$(container_in "$CASE_TMP/output-followed")" --to "$CASE_TMP/restored-followed"
[ -f "$CASE_TMP/restored-followed/links/pointer.txt" ] ||
    fail "with followSymlinks set, the link should have been stored as a file"
[ ! -L "$CASE_TMP/restored-followed/links/pointer.txt" ] ||
    fail "with followSymlinks set, the link was stored as a link anyway"
cmp -s "$CASE_TMP/restored-followed/links/pointer.txt" "$src/real/target.txt" ||
    fail "the followed link does not hold what it pointed at"

step "a followed link needs no --symlinks to come back, because it is not a link any more"
expect_no_out "skipped"
