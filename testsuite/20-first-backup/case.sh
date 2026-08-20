# The five lines from the README, in the order a person types them.
#
# This is the case that has to pass for the tool to be worth anything: a
# directory goes in, a container comes out, and the same directory comes back.

src="$CASE_TMP/documents"
out="$CASE_TMP/output"
work="$CASE_TMP/work"
dest="$CASE_TMP/restored"
cfg="$CASE_TMP/config.json"

gen_tree "$src" 2048

config_new "$out" "$work"
config_setting '"encryptionMethod": "PROMPT_KEYPHRASE"'
config_target documents "$src"
config_write "$cfg"

step "a backup writes one container, named for its target and the moment it ran"
bond_ok backup --config "$cfg" --passphrase-env BOND_TEST_PASS
container="$(container_in "$out")"
case "$(basename "$container")" in
    documents-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].bond) : ;;
    *) fail "the container is called $(basename "$container"), which is not <target>-<timestamp>.bond" ;;
esac

step "the work directory is left empty: a finished container is not half in two places"
[ -z "$(find "$work" -type f 2>/dev/null)" ] || fail "$work still holds files after a successful backup"

step "the quick check needs no key, which is the point of it"
bond_ok verify "$container" --quick
expect_out "matches its"

step "a full verify authenticates every shard"
bond_ok verify "$container" --passphrase-env BOND_TEST_PASS
expect_out "OK"
expect_out "every shard authenticates and the stream matches its digest"

step "the container holds what it says it holds, without decompressing anything"
bond_ok list "$container" --passphrase-env BOND_TEST_PASS
files_in_source=$(cd "$src" && find . -type f | grep -c .)
files_listed=$(printf '%s\n' "$BOND_OUT" | grep -c . )
[ "$files_listed" -ge "$files_in_source" ] ||
    fail "the source has $files_in_source files but list showed only $files_listed entries"

step "the long listing carries a size and a time for every file"
bond_ok list "$container" -l --passphrase-env BOND_TEST_PASS
expect_out "notes/note-01.md"
printf '%s\n' "$BOND_OUT" | grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' ||
    fail "no modification time in the long listing"

step "inspect describes the container before a key is offered, and more once it is"
bond_ok inspect "$container" --passphrase-env BOND_TEST_PASS
expect_out "without a key"
expect_out "with the key"
expect_out "format            BOND 1.0"
expect_out "target            documents"

step "inspect without a key says what it cannot show, rather than failing"
bond_ok inspect "$container"
expect_out "not shown"

step "a source keeps its own name inside the container, so a restore says where things came from"
bond_ok restore "$container" --to "$dest" --passphrase-env BOND_TEST_PASS
expect_out "restored"
assert_exists "$dest/documents"
[ "$(find "$dest" -mindepth 1 -maxdepth 1 | grep -c .)" -eq 1 ] ||
    fail "one source should restore under one directory, not scattered into $dest"

step "the tree comes back, byte for byte"
assert_trees_equal "$src" "$dest/documents"

step "restore checks each file against the digest recorded at backup time"
expect_out "match the digests recorded at backup time"

step "modification times survive the round trip"
assert_mtimes_equal "$src" "$dest/documents"

step "restoring again into the same directory is refused rather than done quietly"
bond_fail restore "$container" --to "$dest" --passphrase-env BOND_TEST_PASS

step "--overwrite is how you say you meant it"
bond_ok restore "$container" --to "$dest" --overwrite --passphrase-env BOND_TEST_PASS
assert_trees_equal "$src" "$dest/documents"
