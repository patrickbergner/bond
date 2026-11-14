# Byte-level damage, the way a bad disk or a bad transfer inflicts it.
#
# The fixed offsets below are the ones NERDME §11 documents for recovering a
# container by hand, and they are quoted here rather than derived because that
# section is a promise to an operator with a hex editor: if these numbers move,
# a case here should fail and NERDME should be the thing that gets updated.
#
# Everything else – how many shards there are, where a stripe ends – is left to
# the container. A suite that recomputed the parity geometry in bash would be
# testing its own arithmetic, and would agree with a bug in the real geometry
# as readily as with the truth.

DAMAGE_SUPERBLOCK_OFFSET=0        # the header, 4096 bytes
DAMAGE_RESERVED_OFFSET=3700       # first reserved byte inside the header (NERDME §3)
DAMAGE_SLOT_TABLE_A=4096          # 64 KiB
DAMAGE_SLOT_TABLE_B=69632         # 64 KiB, the spare
DAMAGE_PAYLOAD_OFFSET=135168      # the first shard begins here, in every container

# overwrite_at splices a file's worth of bytes into another file in place,
# without changing its length.
#
# head and tail rather than dd: dd's byte-granular seek is slow enough to
# notice on a multi-megabyte span, and its portable spelling differs between
# implementations in exactly the way a testsuite should not have to care about.
overwrite_at() {
    local path="$1" offset="$2" src="$3" length size
    length=$(file_bytes "$src")
    size=$(file_bytes "$path")
    [ $(( offset + length )) -le "$size" ] ||
        fail "overwrite_at would run $(( offset + length - size )) bytes past the end of $path"
    {
        head -c "$offset" "$path"
        cat "$src"
        tail -c "+$(( offset + length + 1 ))" "$path"
    } >"$CASE_TMP/.spliced"
    mv "$CASE_TMP/.spliced" "$path"
    [ "$(file_bytes "$path")" -eq "$size" ] || fail "overwrite_at changed the length of $path"
}

# poke overwrites COUNT bytes at OFFSET.
#
# It checks that the file actually changed, and tries a different pattern if it
# did not. Damage that silently damaged nothing – because the pattern happened
# to be what was already there – would leave a case passing while proving the
# opposite of what it claims, and that is exactly the sort of green test this
# tool cannot afford.
poke() {
    local path="$1" offset="$2" count="${3:-64}" attempt

    cp "$path" "$CASE_TMP/.poke-before"
    for attempt in 1 2 3; do
        case "$attempt" in
            1) yes 'DEADBEEF' | head -c "$count" >"$CASE_TMP/.poke-src" ;;
            2) head -c "$count" /dev/zero >"$CASE_TMP/.poke-src" ;;
            3) head -c "$count" /dev/urandom >"$CASE_TMP/.poke-src" ;;
        esac
        overwrite_at "$path" "$offset" "$CASE_TMP/.poke-src"
        if ! cmp -s "$CASE_TMP/.poke-before" "$path"; then
            rm -f "$CASE_TMP/.poke-before" "$CASE_TMP/.poke-src"
            return 0
        fi
    done
    fail "poking $count bytes at offset $offset did not change $path"
}

# poke_payload damages bytes at an offset measured from the first shard, which
# is how a case says "well inside the data, nowhere near the header".
poke_payload() {
    local path="$1" offset="$2" count="${3:-64}"
    poke "$path" $(( DAMAGE_PAYLOAD_OFFSET + offset )) "$count"
}

# wreck_span overwrites a contiguous run, given as a percentage range of the
# payload.
#
# Contiguous is the point. Scattered damage of the same total size may still be
# repairable – each stripe might lose no more than the parity covers – so a
# case that wants damage the recovery data provably cannot cover has to take
# out whole neighbouring shards, which is what a run does.
wreck_span() {
    local path="$1" from_pct="$2" to_pct="$3" size payload start length
    size=$(file_bytes "$path")
    payload=$(( size - DAMAGE_PAYLOAD_OFFSET ))
    start=$(( DAMAGE_PAYLOAD_OFFSET + payload * from_pct / 100 ))
    length=$(( payload * (to_pct - from_pct) / 100 ))
    [ "$length" -gt 0 ] || fail "wreck_span: ${from_pct}%–${to_pct}% of $path is no bytes at all"

    cp "$path" "$CASE_TMP/.poke-before"
    head -c "$length" /dev/urandom >"$CASE_TMP/.poke-src"
    overwrite_at "$path" "$start" "$CASE_TMP/.poke-src"
    cmp -s "$CASE_TMP/.poke-before" "$path" && fail "wrecking ${from_pct}%–${to_pct}% of $path changed nothing"
    rm -f "$CASE_TMP/.poke-before" "$CASE_TMP/.poke-src"
    return 0
}

# damage_header damages the header copy at the front of the file, leaving the
# magic alone so that the damage is a failed MAC rather than an unrecognised
# file. Those are different scenarios and the format answers them differently.
damage_header() {
    poke "$1" $(( DAMAGE_SUPERBLOCK_OFFSET + 200 )) 32
}

# damage_reserved writes into the header's reserved padding – the region the
# format promises nothing can be smuggled into. See NERDME §3.
damage_reserved() {
    poke "$1" "$DAMAGE_RESERVED_OFFSET" 64
}

# damage_slot_table damages the primary key-slot table, so the container has to
# come up on its spare.
damage_slot_table() {
    poke "$1" $(( DAMAGE_SLOT_TABLE_A + 128 )) 64
}

# truncate_by shortens a file: the classic incomplete download.
truncate_by() {
    local path="$1" bytes="$2" size
    size=$(file_bytes "$path")
    [ "$size" -gt "$bytes" ] || fail "cannot cut $bytes bytes off a $size-byte file"
    head -c $(( size - bytes )) "$path" >"$CASE_TMP/.truncated"
    mv "$CASE_TMP/.truncated" "$path"
}
