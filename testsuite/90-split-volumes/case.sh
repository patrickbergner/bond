# A container split across several files.
#
# This is the ground the package tests reached last and the assessment called
# out by name: until now every corruption test ran on a single-volume container,
# and repair's split-container path with checksum files present had never been
# driven end to end. A split set is also the shape a backup actually travels in
# – a dozen files uploaded one at a time, of which one arrives short, one gets
# lost, and one turns out to belong to a different backup altogether.

src="$CASE_TMP/data"
out="$CASE_TMP/output"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

VOLUME_BYTES=1048576

gen_tree "$src" 6144

write_set() {
    local id="$1" dir="$2" extra="${3:-}"
    config_new "$dir" "$work"
    config_setting '"encryptionMethod": "NONE"'
    config_setting '"compressionLevel": 0'
    config_setting '"recoveryPercent": 20'
    config_setting '"shardBytes": 131072'
    config_setting "\"maxVolumeBytes\": $VOLUME_BYTES"
    if [ -n "$extra" ]; then
        config_setting "$extra"
    fi
    config_target "$id" "$src"
    config_write "$cfg"
    bond_ok backup --config "$cfg"
    BASE="$(volume_base_in "$dir")"
}

step "a size limit turns one container into a numbered set of files"
write_set vault "$out"
volumes=$(count_volumes "$BASE")
[ "$volumes" -ge 5 ] || fail "expected at least five volumes, got $volumes"
assert_missing "$BASE"
while IFS= read -r v; do
    [ "$(file_bytes "$v")" -le "$VOLUME_BYTES" ] ||
        fail "$(basename "$v") is $(file_bytes "$v") bytes, past the $VOLUME_BYTES it was limited to"
done < <(volumes_of "$BASE")

step "every volume gets its own checksum file, because they are uploaded one at a time"
while IFS= read -r v; do
    assert_exists "$v.sha384"
done < <(volumes_of "$BASE")

step "the quick check covers the whole set, named by the stem the volumes share"
bond_ok verify "$BASE" --quick
[ "$(out_lines)" -ge "$volumes" ] || fail "the quick check did not report on every volume"

step "the set verifies and restores in full"
bond_ok verify --allow-unencrypted "$BASE"
expect_out "OK"
bond_ok restore --allow-unencrypted "$BASE" --to "$CASE_TMP/restored-base"
assert_trees_equal "$src" "$CASE_TMP/restored-base/data"

step "the set opens when named by any of its volumes, not only the first"
bond_ok restore --allow-unencrypted "$BASE.003" --to "$CASE_TMP/restored-third"
assert_trees_equal "$src" "$CASE_TMP/restored-third/data"
bond_ok list --allow-unencrypted "$BASE.002"
bond_ok inspect --allow-unencrypted "$BASE.004"
expect_out "volumes"

step "the whole set can be moved and renamed, because a container is a file and not a registration"
moved="$CASE_TMP/moved"
mkdir -p "$moved"
i=1
while IFS= read -r v; do
    cp "$v" "$moved/$(printf 'archive-2026.bond.%03d' "$i")"
    cp "$v.sha384" "$moved/$(printf 'archive-2026.bond.%03d.sha384' "$i")"
    i=$(( i + 1 ))
done < <(volumes_of "$BASE")
bond_ok restore --allow-unencrypted "$moved/archive-2026.bond" --to "$CASE_TMP/restored-moved"
assert_trees_equal "$src" "$CASE_TMP/restored-moved/data"

# ---------------------------------------------------------------------------
# The ways a set arrives wrong.

step "a missing volume is refused, and the message names the one that is missing"
gone="$CASE_TMP/gone"
cp -r "$moved" "$gone"
rm -f "$gone/archive-2026.bond.003" "$gone/archive-2026.bond.003.sha384"
bond_fail restore --allow-unencrypted "$gone/archive-2026.bond" --to "$CASE_TMP/restored-gone"
expect_err "003"

step "a truncated volume is refused: a short file is never a complete volume"
short="$CASE_TMP/short"
cp -r "$moved" "$short"
truncate_by "$short/archive-2026.bond.002" 100000
bond_fail restore --allow-unencrypted "$short/archive-2026.bond" --to "$CASE_TMP/restored-short"

step "a volume from a different container is refused, on the identity in its header"
write_set other "$CASE_TMP/output-other"
mixed="$CASE_TMP/mixed"
cp -r "$moved" "$mixed"
cp "$(volumes_of "$BASE" | sed -n 2p)" "$mixed/archive-2026.bond.002"
bond_fail restore --allow-unencrypted "$mixed/archive-2026.bond" --to "$CASE_TMP/restored-mixed"

# ---------------------------------------------------------------------------
# Damage inside the set, with the checksum files still beside it – the path
# that had never been driven from the command line.

step "damage in a middle volume is located and reported as repairable"
damaged="$CASE_TMP/damaged"
cp -r "$moved" "$damaged"
middle="$damaged/archive-2026.bond.003"
poke_payload "$middle" 200000 1024
bond_fail verify --allow-unencrypted "$damaged/archive-2026.bond"
expect_out "repairable  yes – run: bond repair"

step "the quick check names which volume of the set is the bad one"
bond_fail verify "$damaged/archive-2026.bond" --quick
expect_err "archive-2026.bond.003"

step "repair rebuilds the set into a new one, leaving every original volume alone"
cp -r "$damaged" "$CASE_TMP/damaged-as-found"
bond_ok repair --allow-unencrypted "$damaged/archive-2026.bond"
expect_out "rebuilt"
expect_out "verified      every shard authenticates"
while IFS= read -r v; do
    assert_files_identical "$v" "$CASE_TMP/damaged-as-found/$(basename "$v")"
done < <(volumes_of "$damaged/archive-2026.bond")

step "the repaired set is a set in its own right, numbered from one and not from the name it was made from"
repaired="$damaged/archive-2026.repaired.bond"
[ "$(count_volumes "$repaired")" -eq "$volumes" ] ||
    fail "the repaired set has $(count_volumes "$repaired") volumes and the original had $volumes"
assert_missing "$repaired.001.001"

step "every repaired volume carries a fresh checksum file, so the next quick check is not a false alarm"
while IFS= read -r v; do
    assert_exists "$v.sha384"
    ( cd "$(dirname "$v")" && sha384sum -c "$(basename "$v").sha384" ) >/dev/null 2>&1 ||
        fail "$(basename "$v").sha384 does not match the volume it was written for"
done < <(volumes_of "$repaired")
bond_ok verify "$repaired" --quick

step "the repaired set verifies and gives back the original tree"
bond_ok verify --allow-unencrypted "$repaired"
expect_out "OK"
bond_ok restore --allow-unencrypted "$repaired" --to "$CASE_TMP/restored-repaired"
assert_trees_equal "$src" "$CASE_TMP/restored-repaired/data"

step "a damaged header in one volume is survived by that volume's own mirror"
hdr="$CASE_TMP/header"
cp -r "$moved" "$hdr"
damage_header "$hdr/archive-2026.bond.004"
bond_ok list --allow-unencrypted "$hdr/archive-2026.bond"
bond_fail verify --allow-unencrypted "$hdr/archive-2026.bond"
expect_out "archive-2026.bond.004"
expect_out "repairable  yes – run: bond repair"
bond_ok repair --allow-unencrypted "$hdr/archive-2026.bond"
bond_ok verify --allow-unencrypted "$hdr/archive-2026.repaired.bond"
expect_no_out "is damaged"

# ---------------------------------------------------------------------------

step "a set whose last volume is a sliver still opens, verifies and restores"
# The volume boundary falling a few kilobytes before the end of the stream is
# the arithmetic most likely to be got wrong, and the least likely to be met by
# accident. The filler below is sized from a first run so the last volume lands
# well under 128 KiB rather than by luck.
sliver_src="$CASE_TMP/sliver-data"
sliver_out="$CASE_TMP/output-sliver"
gen_tree "$sliver_src" 2048

# maxVolumeBytes will not go below 1 MiB, and a volume holds a whole number of
# shards, so the only way to a sliver is to size the content. Small shards make
# a small tail representable at all: the last shard is a partial one, and with
# 64 KiB shards the final volume can be a header and a fraction.
#
# The size is searched for rather than calculated. Volumes come out well under
# the limit they were given, parity inflates whatever is added, and a formula
# that got either wrong would fail in a way that looked like a bug in BOND.
# Measuring what the tool actually produced and adjusting cannot.
sliver_backup() {
    rm -rf "$sliver_out"
    config_new "$sliver_out" "$work"
    config_setting '"encryptionMethod": "NONE"'
    config_setting '"compressionLevel": 0'
    config_setting '"recoveryPercent": 20'
    config_setting '"shardBytes": 65536'
    config_setting "\"maxVolumeBytes\": $VOLUME_BYTES"
    config_target sliver "$sliver_src"
    config_write "$cfg"
    bond_ok backup --config "$cfg"
    sliver_base="$(volume_base_in "$sliver_out")"
    SLIVER_TAIL=$(file_bytes "$(volumes_of "$sliver_base" | tail -n 1)")
    SLIVER_FULL=$(file_bytes "$(volumes_of "$sliver_base" | sed -n 2p)")
}

# One shard at a time, rather than a formula. The last volume also carries the
# manifest and is allowed to run past the limit the others keep to, so its size
# is not a function of the others that can be inverted – but adding one shard's
# worth of content moves the set on by exactly one shard, and after at most a
# volume's worth of those the tail has rolled over and holds a single shard.
filler=0
attempt=0
while :; do
    attempt=$(( attempt + 1 ))
    sliver_backup
    printf '    attempt %d: %d volumes, last is %d bytes (a full one is %d)\n' \
        "$attempt" "$(count_volumes "$sliver_base")" "$SLIVER_TAIL" "$SLIVER_FULL"
    [ "$SLIVER_TAIL" -lt 131072 ] && break
    [ "$attempt" -lt 24 ] ||
        fail "after $attempt tries the final volume is still $SLIVER_TAIL bytes, never under 128 KiB"

    # 5/6 undoes the 20% the recovery data adds to whatever goes in.
    filler=$(( filler + 65536 * 5 / 6 ))
    gen_blob "$sliver_src/filler.bin" "$filler" random
done

[ "$(count_volumes "$sliver_base")" -ge 3 ] ||
    fail "the sliver set has only $(count_volumes "$sliver_base") volumes"
bond_ok verify "$sliver_base" --quick
bond_ok verify --allow-unencrypted "$sliver_base"
expect_out "OK"
bond_ok restore --allow-unencrypted "$sliver_base" --to "$CASE_TMP/restored-sliver"
assert_trees_equal "$sliver_src" "$CASE_TMP/restored-sliver/sliver-data"

step "and a sliver-tailed set repairs like any other"
poke_payload "$(volumes_of "$sliver_base" | sed -n 2p)" 150000 512
bond_fail verify --allow-unencrypted "$sliver_base"
expect_out "repairable  yes"
bond_ok repair --allow-unencrypted "$sliver_base"
sliver_repaired="$(dirname "$sliver_base")/$(basename "${sliver_base%.bond}").repaired.bond"
bond_ok verify --allow-unencrypted "$sliver_repaired"
expect_out "OK"
bond_ok restore --allow-unencrypted "$sliver_repaired" --to "$CASE_TMP/restored-sliver-repaired"
assert_trees_equal "$sliver_src" "$CASE_TMP/restored-sliver-repaired/sliver-data"
