# Backing up part of a directory, which is what anyone with a home directory
# actually does.
#
# The tree here is written by hand rather than generated: the whole question is
# which files were chosen, so the answer has to be something a reader of this
# case can check by eye.

src="$CASE_TMP/project"
out="$CASE_TMP/output"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

mkdir -p "$src"/{src/generated,docs/img,node_modules/pkg,build}
echo 'package main'   >"$src/src/main.go"
echo 'package main'   >"$src/src/helper.go"
echo 'generated'      >"$src/src/generated/gen.go"
echo '# readme'       >"$src/docs/readme.md"
printf 'PNG'          >"$src/docs/img/logo.png"
echo 'module.exports' >"$src/node_modules/pkg/index.js"
printf 'ELF'          >"$src/build/out.bin"
printf 'thumbs'       >"$src/Thumbs.db"
echo 'loose'          >"$src/notes.txt"

config_new "$out" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"compressionLevel": 0'
config_target prefixes "$src" '"includedPathPrefixes": ["src", "docs"], "excludedPathPrefixes": ["src/generated"]'
config_target names    "$src" '"excludedDirectoryNames": ["node_modules", "build"], "excludedFileNames": ["Thumbs.db"]'
config_target patterns "$src" '"includedPathPatterns": ["\\.go$"]'
config_target literals "$src" '"includedPaths": ["notes.txt", "docs"]'
config_target hibernating "$src" "" '"skip": true'
config_write "$cfg"

# restore_of unpacks one target's container and leaves the destination in
# $RESTORED. It sets a variable rather than printing one because an assertion
# inside a $( ) runs in a subshell, where failing would end the subshell and
# not the case.
restore_of() {
    RESTORED="$CASE_TMP/restored-$1"
    bond_ok restore --allow-unencrypted "$(container_for "$out" "$1")" --to "$RESTORED"
}

step "a dry run reports what would be stored and writes nothing at all"
mkdir -p "$out"
before=$(find "$out" "$work" -type f 2>/dev/null | LC_ALL=C sort)
bond_ok backup --config "$cfg" --dry-run --verbose
expect_out_path "project/src/main.go"
expect_out "nothing was written; this was a dry run"
after=$(find "$out" "$work" -type f 2>/dev/null | LC_ALL=C sort)
[ "$before" = "$after" ] || fail "a dry run left files behind"

step "a dry run explains its filter decisions when asked"
expect_out "node_modules"

step "included prefixes select a subtree, and an excluded prefix carves out of it"
bond_ok backup --config "$cfg" --target prefixes
restore_of prefixes
assert_paths "$RESTORED" 'project/src/main.go
project/src/helper.go
project/docs/readme.md
project/docs/img/logo.png'

step "excluded directory and file names apply anywhere in the tree"
bond_ok backup --config "$cfg" -t names
restore_of names
assert_paths "$RESTORED" 'project/src/main.go
project/src/helper.go
project/src/generated/gen.go
project/docs/readme.md
project/docs/img/logo.png
project/notes.txt'

step "an included pattern is a regular expression over the source-relative path"
bond_ok backup --config "$cfg" --target patterns
restore_of patterns
assert_paths "$RESTORED" 'project/src/main.go
project/src/helper.go
project/src/generated/gen.go'

step "a literal included path may name a file or a whole directory"
bond_ok backup --config "$cfg" --target literals
restore_of literals
assert_paths "$RESTORED" 'project/notes.txt
project/docs/readme.md
project/docs/img/logo.png'

step "a target marked skip stays out of a plain run, and is still there when named"
plain="$CASE_TMP/output-plain"
config_new "$plain" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"compressionLevel": 0'
config_target awake "$src" '"includedPaths": ["notes.txt"]'
config_target hibernating "$src" '"includedPaths": ["notes.txt"]' '"skip": true'
config_write "$cfg"
bond_ok backup --config "$cfg"
[ "$(find "$plain" -maxdepth 1 -name 'hibernating-*.bond' | grep -c . || true)" -eq 0 ] ||
    fail "a target marked skip was backed up by a plain run"
bond_ok backup --config "$cfg" --target hibernating
container_for "$plain" hibernating >/dev/null

step "naming a target that does not exist stops the run and says which one"
# Recorded as it behaves: this exits 1, not the 2 that other mistakes in how
# bond was invoked produce, because the name is only found to be wrong after
# the control file has been read. The message names the target either way,
# which is the part an operator needs.
bond_fail backup --config "$cfg" --target awake --target nonesuch
expect_err "no such target: nonesuch"

step "several sources are stored under their own names, relative to what they share"
two="$CASE_TMP/output-two"
mkdir -p "$CASE_TMP/trees/alpha" "$CASE_TMP/trees/beta"
echo a >"$CASE_TMP/trees/alpha/a.txt"
echo b >"$CASE_TMP/trees/beta/b.txt"
config_new "$two" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"compressionLevel": 0'
config_target_multi pair "            { \"path\": $(json_string "$CASE_TMP/trees/alpha") },
            { \"path\": $(json_string "$CASE_TMP/trees/beta") }"
config_write "$cfg"
bond_ok backup --config "$cfg" --target pair
bond_ok restore --allow-unencrypted "$(container_for "$two" pair)" --to "$CASE_TMP/restored-pair"
assert_paths "$CASE_TMP/restored-pair" 'alpha/a.txt
beta/b.txt'

step "a single file is a legitimate source"
one="$CASE_TMP/output-one"
config_new "$one" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"compressionLevel": 0'
config_target lonely "$src/notes.txt"
config_write "$cfg"
bond_ok backup --config "$cfg" --target lonely
bond_ok restore --allow-unencrypted "$(container_for "$one" lonely)" --to "$CASE_TMP/restored-one"
assert_paths "$CASE_TMP/restored-one" 'notes.txt'
