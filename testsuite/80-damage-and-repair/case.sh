# Damage, which is the whole reason this tool exists.
#
# Untrusted storage is storage that loses bytes, and the promises are specific:
# damage is located rather than guessed at, damage within the recovery data's
# reach is rebuilt, damage beyond it is refused out loud, and the damaged file
# is never modified in the process. Every one of those is checked here through
# the binary, on a real file, with the bytes changed underneath it.

src="$CASE_TMP/data"
out="$CASE_TMP/output"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

gen_tree "$src" 4096

config_new "$out" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"compressionLevel": 0'
config_setting '"recoveryPercent": 20'
config_setting '"shardBytes": 262144'
config_target vault "$src"
config_write "$cfg"

# Each part of this case starts from an identical, undamaged copy, so a failure
# in one does not leave the next looking at rubble it did not create.
bond_ok backup --config "$cfg"
pristine="$CASE_TMP/pristine.bond"
pristine_sidecar="$CASE_TMP/pristine.bond.sha384"
cp "$(container_in "$out")" "$pristine"
cp "$(container_in "$out").sha384" "$pristine_sidecar"

fresh_copy() {
    SUBJECT="$CASE_TMP/subject-$1.bond"
    cp "$pristine" "$SUBJECT"
    cp "$pristine_sidecar" "$SUBJECT.sha384"
}

step "an undamaged container has nothing to repair, and says so without writing a file"
fresh_copy healthy
bond_ok repair "$SUBJECT"
expect_out "nothing to do – this container is not damaged"
assert_missing "$CASE_TMP/subject-healthy.repaired.bond"

# ---------------------------------------------------------------------------

step "damage inside the payload is found, located, and reported as repairable"
fresh_copy small
poke_payload "$SUBJECT" 300000 512
bond_fail verify "$SUBJECT"
expect_out "damaged"
expect_out "repairable  yes – run: bond repair"
expect_err "the container is damaged but can be rebuilt from its recovery data"

step "the quick check catches it too, without needing a key"
bond_fail verify "$SUBJECT" --quick
expect_err "does not match"

step "repair writes a new file and does not touch the damaged one"
cp "$SUBJECT" "$CASE_TMP/subject-small-as-found.bond"
bond_ok repair "$SUBJECT"
repaired="$CASE_TMP/subject-small.repaired.bond"
assert_exists "$repaired"
expect_out "rebuilt"
expect_out "verified      every shard authenticates and the stream matches its digest"
assert_files_identical "$SUBJECT" "$CASE_TMP/subject-small-as-found.bond"

step "the repaired copy carries its own checksum file, so the next quick check means something"
assert_exists "$repaired.sha384"
( cd "$CASE_TMP" && sha384sum -c "$(basename "$repaired").sha384" ) >/dev/null 2>&1 ||
    fail "the checksum file written beside the repaired container does not match it"
bond_ok verify "$repaired" --quick

step "the repaired copy verifies in full and gives back the original tree"
bond_ok verify "$repaired"
expect_out "OK"
bond_ok restore "$repaired" --to "$CASE_TMP/restored-repaired"
assert_trees_equal "$src" "$CASE_TMP/restored-repaired/data"

step "repair will not write over something that is already there"
bond_fail repair "$SUBJECT"
expect_err "already exists; name a different destination with --out"

step "--out puts it where you say"
bond_ok repair "$SUBJECT" --out "$CASE_TMP/elsewhere.bond"
assert_exists "$CASE_TMP/elsewhere.bond"
bond_ok verify "$CASE_TMP/elsewhere.bond"

# ---------------------------------------------------------------------------

step "damage beyond what the recovery data covers is refused rather than guessed at"
fresh_copy huge
wreck_span "$SUBJECT" 20 70
bond_fail verify "$SUBJECT"
expect_out "repairable  no"
expect_err "the damage is beyond what this container's recovery data covers"

step "repair refuses it too, and writes nothing"
bond_fail repair "$SUBJECT"
expect_err "cannot be repaired from the recovery data in the container"
assert_missing "$CASE_TMP/subject-huge.repaired.bond"

step "a restore from it is refused, and nothing it did write is quietly wrong"
bond_fail restore "$SUBJECT" --to "$CASE_TMP/restored-huge"
expect_no_out "match the digests recorded at backup time"
# A restore is a stream, so a refusal partway through can leave files on disk.
# What must never happen is a file that looks finished and holds the wrong
# bytes: anything of the right length has to be the right length's worth of the
# right content.
if [ -d "$CASE_TMP/restored-huge" ]; then
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        original="$src/${rel#*/}"
        [ -f "$original" ] ||
            fail "a refused restore left $rel behind, and it is not a file that was backed up"
        if [ "$(file_bytes "$CASE_TMP/restored-huge/$rel")" -eq "$(file_bytes "$original")" ]; then
            cmp -s "$CASE_TMP/restored-huge/$rel" "$original" ||
                fail "a refused restore wrote $rel at its full length with the wrong bytes in it"
        fi
    done < <( cd "$CASE_TMP/restored-huge" && find . -type f | sed 's|^\./||' | LC_ALL=C sort )
fi

# ---------------------------------------------------------------------------

step "a damaged header at the front is survived: the mirror at the end carries it"
fresh_copy header
damage_header "$SUBJECT"
bond_ok verify "$SUBJECT"
expect_out "the header at the front is damaged; the mirror at the end was used"
expect_out "OK"

step "repair puts the header back, and says which region it rewrote"
bond_ok repair "$SUBJECT"
expect_out "rewritten"
bond_ok verify "$CASE_TMP/subject-header.repaired.bond"
expect_out "OK"
expect_no_out "the header at the front is damaged"

step "a container whose header was healed still gives back the same files"
bond_ok restore "$CASE_TMP/subject-header.repaired.bond" --to "$CASE_TMP/restored-header"
assert_trees_equal "$src" "$CASE_TMP/restored-header/data"

# ---------------------------------------------------------------------------

step "bytes written into the header's reserved padding are not smuggled past the MAC"
# NERDME §3 says nothing can be hidden in the padding. The header holding the
# smuggled bytes must therefore stop authenticating, leaving the mirror to open
# the container – which is a notice, not a silent success.
fresh_copy reserved
damage_reserved "$SUBJECT"
bond_ok verify "$SUBJECT"
expect_out "the header at the front is damaged; the mirror at the end was used"

step "repair scrubs the padding rather than leaving the passenger on board"
bond_ok repair "$SUBJECT"
scrubbed="$CASE_TMP/subject-reserved.repaired.bond"
bond_ok verify "$scrubbed"
expect_no_out "is damaged"
head -c 4096 "$scrubbed" | tail -c +249 | tr -d '\000' >"$CASE_TMP/.padding"
[ ! -s "$CASE_TMP/.padding" ] ||
    fail "the repaired header still carries $(file_bytes "$CASE_TMP/.padding") non-zero bytes in its reserved region"

# ---------------------------------------------------------------------------

step "a damaged key-slot table is survived by its spare, and repair puts it back"
fresh_copy slots
damage_slot_table "$SUBJECT"
bond_ok verify "$SUBJECT"
expect_out "key-slot table"
bond_ok repair "$SUBJECT"
bond_ok verify "$CASE_TMP/subject-slots.repaired.bond"
expect_no_out "key-slot table"
expect_out "OK"

step "a truncated container is refused: a short file is never a complete backup"
fresh_copy short
truncate_by "$SUBJECT" 200000
bond_fail verify "$SUBJECT"
bond_fail restore "$SUBJECT" --to "$CASE_TMP/restored-short"
