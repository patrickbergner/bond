# Source links are an archive-time choice. They are either materialized as
# ordinary files/directories (the default), or counted, warned about and
# omitted. A BOND container never contains a link entry.

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
gen_symlink "$src/alias" "real" || fail "could not create a directory alias"
gen_symlink "$src/real/loop" ".." || fail "could not create a directory loop"

step "followSymlinks false omits included links and reports the count"
config_new "$CASE_TMP/output-skipped" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"followSymlinks": false'
config_target links "$src"
config_write "$cfg"
bond_ok backup --config "$cfg"
expect_out "links skipped"
bond_ok restore --allow-unencrypted "$(container_in "$CASE_TMP/output-skipped")" --to "$CASE_TMP/restored-skipped"
assert_exists "$CASE_TMP/restored-skipped/links/real/target.txt"
assert_missing "$CASE_TMP/restored-skipped/links/pointer.txt"
assert_missing "$CASE_TMP/restored-skipped/links/pointer-to-nowhere"
assert_missing "$CASE_TMP/restored-skipped/links/alias"
assert_missing "$CASE_TMP/restored-skipped/links/real/loop"

step "following is the default: links are materialized and loops are cut"
config_new "$CASE_TMP/output-followed" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target followed "$src" '"excludedFileNames": ["pointer-to-nowhere"]'
config_write "$cfg"
bond_ok backup --config "$cfg"
expect_out "loop"
bond_ok restore --allow-unencrypted "$(container_in "$CASE_TMP/output-followed")" --to "$CASE_TMP/restored-followed"
[ -f "$CASE_TMP/restored-followed/links/pointer.txt" ] ||
    fail "with followSymlinks set, the link should have been stored as a file"
[ ! -L "$CASE_TMP/restored-followed/links/pointer.txt" ] ||
    fail "with followSymlinks set, the link was stored as a link anyway"
cmp -s "$CASE_TMP/restored-followed/links/pointer.txt" "$src/real/target.txt" ||
    fail "the followed link does not hold what it pointed at"
[ -d "$CASE_TMP/restored-followed/links/alias" ] || fail "directory link was not materialized"
[ ! -L "$CASE_TMP/restored-followed/links/alias" ] || fail "directory alias was stored as a link"
cmp -s "$CASE_TMP/restored-followed/links/alias/bulk.bin" "$src/real/bulk.bin" ||
    fail "materialized alias tree differs"
assert_missing "$CASE_TMP/restored-followed/links/real/loop"
assert_missing "$CASE_TMP/restored-followed/links/alias/loop"
