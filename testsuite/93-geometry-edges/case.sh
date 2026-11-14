# The settings at the ends of their ranges.
#
# shardBytes is both the encryption block and the parity unit, and
# recoveryPercent decides how much of a stripe can be lost. The interesting
# values are not the defaults: one shard, less than one shard, no recovery data
# at all, and as much recovery data as the format allows.

work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

# build makes a container from a tree of a given size with given settings, and
# leaves it in $CONTAINER.
build() {
    local id="$1" size_kb="$2" settings="$3" src="$CASE_TMP/src-$1" out="$CASE_TMP/out-$1"
    rm -rf "$src"
    if [ "$size_kb" -gt 0 ]; then
        gen_tree "$src" "$size_kb"
    else
        mkdir -p "$src"
    fi
    config_new "$out" "$work"
    config_setting '"encryptionMethod": "NONE"'
    config_setting '"compressionLevel": 0'
    eval "$settings"
    config_target "$id" "$src"
    config_write "$cfg"
    bond_ok backup --config "$cfg"
    CONTAINER="$(container_in "$out")"
    SOURCE="$src"
}

round_trips() {
    local id="$1"
    bond_ok verify --allow-unencrypted "$CONTAINER"
    expect_out "OK"
    bond_ok restore --allow-unencrypted "$CONTAINER" --to "$CASE_TMP/restored-$id"
    assert_trees_equal "$SOURCE" "$CASE_TMP/restored-$id/src-$id"
}

step "the smallest shard the format allows still round-trips"
build tiny-shards 1024 'config_setting "\"shardBytes\": 65536"'
bond_ok inspect --allow-unencrypted "$CONTAINER"
expect_out "shard size        64.0 KiB"
round_trips tiny-shards

step "a payload smaller than a single shard is a container like any other"
SOURCE="$CASE_TMP/src-one-shard"
mkdir -p "$SOURCE"
echo 'the only file there is' >"$SOURCE/only.txt"
config_new "$CASE_TMP/out-one-shard" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"compressionLevel": 0'
config_setting '"shardBytes": 65536'
config_target one-shard "$SOURCE"
config_write "$cfg"
bond_ok backup --config "$cfg"
CONTAINER="$(container_in "$CASE_TMP/out-one-shard")"
bond_ok inspect --allow-unencrypted "$CONTAINER"
expect_out "shards            1"
round_trips one-shard

step "an empty tree is backed up and restored as the empty tree it is"
build nothing 0 ''
bond_ok verify --allow-unencrypted "$CONTAINER"
expect_out "OK"
bond_ok restore --allow-unencrypted "$CONTAINER" --to "$CASE_TMP/restored-nothing"
[ -z "$(find "$CASE_TMP/restored-nothing" -type f 2>/dev/null)" ] ||
    fail "restoring an empty backup produced files"

step "shardBytes is a ceiling, not a fixed size: a small backup gets smaller shards"
# Asking for 4 MiB shards on a payload of about 2 MiB would otherwise mean one
# data shard and one parity shard – 100% overhead for a setting that said 10%.
# The container is expected to pick a smaller shard instead, so the number an
# operator wrote down is the number they get.
build big-shards 2048 'config_setting "\"shardBytes\": 4194304"; config_setting "\"recoveryPercent\": 10"'
bond_ok inspect --allow-unencrypted "$CONTAINER"
shard_line=$(printf '%s\n' "$BOND_OUT" | sed -n 's/^  shard size  *//p')
case "$shard_line" in
    *MiB) fail "a 2 MiB backup was given $shard_line shards, so recoveryPercent could not have been honoured" ;;
esac
expect_out "recovery data     20+2 (10.0%)"

step "and the overhead on disk is the overhead that was asked for"
payload_bytes=$(( $(file_bytes "$CONTAINER") - DAMAGE_PAYLOAD_OFFSET ))
source_bytes=$(cd "$SOURCE" && find . -type f -exec cat {} + | wc -c)
overhead_pct=$(( (payload_bytes - source_bytes) * 100 / source_bytes ))
[ "$overhead_pct" -lt 25 ] ||
    fail "10% recovery data cost $overhead_pct% of the payload; shardBytes was not adapted to the size"
round_trips big-shards

# ---------------------------------------------------------------------------

step "recoveryPercent 0 writes no recovery data, and says so rather than implying otherwise"
build no-recovery 1024 'config_setting "\"recoveryPercent\": 0"; config_setting "\"shardBytes\": 65536"'
bond_ok inspect --allow-unencrypted "$CONTAINER"
expect_out "recovery data     none"
round_trips no-recovery

step "damage to a container with no recovery data is still found, and honestly called unrepairable"
poke_payload "$CONTAINER" 100000 256
bond_fail verify --allow-unencrypted "$CONTAINER"
expect_err "this container carries no recovery data, so the damage cannot be repaired"
expect_err "restore from another copy"

step "repair does not pretend it can help"
bond_fail repair --allow-unencrypted "$CONTAINER"
assert_missing "$CASE_TMP/out-no-recovery/$(basename "${CONTAINER%.bond}").repaired.bond"

step "the most recovery data the format allows survives correspondingly more damage"
build most-recovery 1024 'config_setting "\"recoveryPercent\": 50"; config_setting "\"shardBytes\": 65536"'
bond_ok inspect --allow-unencrypted "$CONTAINER"
expect_out "recovery data     "
expect_no_out "recovery data     none"
half_size=$(file_bytes "$CONTAINER")
build least-recovery 1024 'config_setting "\"recoveryPercent\": 1"; config_setting "\"shardBytes\": 65536"'
[ "$half_size" -gt "$(file_bytes "$CONTAINER")" ] ||
    fail "asking for 50% recovery data produced a container no larger than asking for 1%"

step "shards knocked out one at a time are rebuilt while the parity still covers them"
build repairable 2048 'config_setting "\"recoveryPercent\": 40"; config_setting "\"shardBytes\": 65536"'
poke_payload "$CONTAINER" 70000 512
bond_fail verify --allow-unencrypted "$CONTAINER"
expect_out "repairable  yes"
bond_ok repair --allow-unencrypted "$CONTAINER"
bond_ok restore --allow-unencrypted "$CASE_TMP/out-repairable/$(basename "${CONTAINER%.bond}").repaired.bond" \
    --to "$CASE_TMP/restored-repairable"
assert_trees_equal "$SOURCE" "$CASE_TMP/restored-repairable/src-repairable"

# ---------------------------------------------------------------------------

step "without a stored file index, list says so and says what to do instead of guessing"
build no-index 512 'config_setting "\"storeFileIndex\": false"'
bond_ok inspect --allow-unencrypted "$CONTAINER"
expect_out "file index        not stored"
bond_fail list --allow-unencrypted "$CONTAINER"
expect_err "written without a file index"
expect_err "restore it to see what is inside"

step "and the container itself is unaffected: the files are all still in it"
round_trips no-index

step "with the index stored, the listing needs nothing decompressed"
build with-index 512 'config_setting "\"storeFileIndex\": true"'
bond_ok inspect --allow-unencrypted "$CONTAINER"
expect_out "entries recorded"

# ---------------------------------------------------------------------------

step "a shard size the format cannot use is refused when the control file is read"
config_new "$CASE_TMP/out-bad" "$work"
config_setting '"shardBytes": 70000'
config_target bad "$CASE_TMP/src-with-index"
config_write "$cfg"
bond_fail backup --config "$cfg"
expect_err "shardBytes"

step "a recovery percentage outside the range is refused the same way"
config_new "$CASE_TMP/out-bad" "$work"
config_setting '"recoveryPercent": 90'
config_target bad "$CASE_TMP/src-with-index"
config_write "$cfg"
bond_fail backup --config "$cfg"
expect_err "recoveryPercent"
