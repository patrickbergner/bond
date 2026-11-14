# Changing who can open a backup, without touching the backup.
#
# The claim being tested is the one in NERDME §5: adding, removing and rotating
# a key rewrites a fixed 128 KiB and never a byte of payload – the same work on
# a terabyte as on a megabyte. That is checkable from outside the process, and
# outside the process is the only place it counts, so this case takes a copy of
# the payload region before each operation and compares it afterwards.

src="$CASE_TMP/data"
out="$CASE_TMP/output"
work="$CASE_TMP/work"
keys="$CASE_TMP/keys"
cfg="$CASE_TMP/config.json"

NEW_PASS="a second secret, chosen in a calmer month"

mkdir -p "$keys"
gen_tree "$src" 1024

config_new "$out" "$work"
config_setting '"encryptionMethod": "PROMPT_KEYPHRASE"'
config_target vault "$src"
config_write "$cfg"
bond_ok backup --config "$cfg" --passphrase-env BOND_TEST_PASS
container="$(container_in "$out")"

# The payload begins after the header and both slot tables. Everything a key
# operation is allowed to touch lies before this point.
payload_snapshot() {
    tail -c "+$(( DAMAGE_PAYLOAD_OFFSET + 1 ))" "$container" | sha256sum | cut -d' ' -f1
}
payload_before=$(payload_snapshot)
size_before=$(file_bytes "$container")

# assert_payload_untouched is called after every key operation below. It is a
# function rather than three repeated lines because the property is the same
# one each time, and a reader should see that it is.
assert_payload_untouched() {
    [ "$(payload_snapshot)" = "$payload_before" ] ||
        fail "the payload changed during a key operation, which the format promises it never does"
    [ "$(file_bytes "$container")" -eq "$size_before" ] ||
        fail "the container changed size during a key operation"
}

step "the slots can be listed without any key at all"
bond_ok keys list "$container"
expect_out "1 key slot"
expect_out "passphrase"

step "a second passphrase can be added, and the payload is not read or rewritten"
bond_with_stdin "$NEW_PASS" keys add "$container" --new-passphrase --label "the calm one" \
    --passphrase-env BOND_TEST_PASS
[ "$BOND_STATUS" -eq 0 ] || fail "adding a passphrase slot exited $BOND_STATUS"
expect_out "payload       untouched"
assert_payload_untouched

step "both passphrases now open it"
bond_ok list "$container" --passphrase-env BOND_TEST_PASS
BOND_NEW_PASS="$NEW_PASS" bond_ok list "$container" --passphrase-env BOND_NEW_PASS

step "a key file can be added to a passphrase-locked container, and opens it on its own"
bond_ok keygen --keyfile "$keys/usb.key"
bond_ok keys add "$container" --new-keyfile "$keys/usb.key" --label "the usb stick" \
    --passphrase-env BOND_TEST_PASS
assert_payload_untouched
bond_ok restore "$container" --to "$CASE_TMP/restored-usb" --keyfile "$keys/usb.key"
assert_trees_equal "$src" "$CASE_TMP/restored-usb/data"

step "a recipient can be added, so a card in a safe opens a backup made before the card existed"
bond_ok keygen --recovery-card "$keys/card.txt"
recovery_key=$(grep -o 'BOND-R1-[A-Z0-9-]*' "$keys/card.txt" | head -n 1)
public_key=$(sed -n 's/.*"publicKey": "\([^"]*\)".*/\1/p' "$keys/card.txt.pub")
bond_ok keys add "$container" --new-recipient "$public_key" --label "the safe" \
    --passphrase-env BOND_TEST_PASS
assert_payload_untouched
bond_ok restore "$container" --to "$CASE_TMP/restored-safe" --recovery-key "$recovery_key"
assert_trees_equal "$src" "$CASE_TMP/restored-safe/data"

step "keys list now shows all four, with the labels they were given"
bond_ok keys list "$container"
expect_out "4 key slots"
expect_out "the calm one"
expect_out "the usb stick"
expect_out "the safe"

step "removing a slot is not done on a guess: without --yes it is refused"
bond_fail keys remove "$container" --slot "the usb stick" --passphrase-env BOND_TEST_PASS
expect_err "pass --yes to remove a key slot without being asked"
bond_ok keys list "$container"
expect_out "4 key slots"

step "with --yes the slot goes, and the key it held stops working"
bond_ok keys remove "$container" --slot "the usb stick" --yes --passphrase-env BOND_TEST_PASS
assert_payload_untouched
bond_ok keys list "$container"
expect_out "3 key slots"
expect_no_out "the usb stick"
bond_fail restore "$container" --to "$CASE_TMP/restored-gone" --keyfile "$keys/usb.key"

step "a slot may also be named by its index"
bond_ok keys remove "$container" --slot 2 --yes --passphrase-env BOND_TEST_PASS
assert_payload_untouched
bond_ok keys list "$container"
expect_out "2 key slots"

step "a name that matches no slot says so and names the command that would show them"
bond_fail keys remove "$container" --slot "the one I forgot" --yes --passphrase-env BOND_TEST_PASS
expect_err "run: bond keys list"

step "rotating the passphrase leaves the payload alone and installs the new secret"
bond_with_stdin "$NEW_PASS-rotated" keys rotate-passphrase "$container" --passphrase-env BOND_TEST_PASS
[ "$BOND_STATUS" -eq 0 ] || fail "rotate-passphrase exited $BOND_STATUS"
expect_out "payload       untouched"
assert_payload_untouched
BOND_ROTATED="$NEW_PASS-rotated" bond_ok list "$container" --passphrase-env BOND_ROTATED

# Rotation is revocation for anyone who has only the container, and this step is
# what holds it to that.
#
# A key change writes the new slot table into the copy that is not current,
# reads it back, and then writes it over the one that was. The second write is
# the point: with the previous table left in the file, a reader falls back to it
# and the passphrase that was just rotated away goes on opening the container
# until some later key change happens to overwrite that copy. NERDME §5.
#
# What rotation cannot do is reach a copy of the file somebody kept from before;
# that takes `bond rekey`, further down.
step "the checksum file follows a key change, so the quick check still passes"
bond_ok verify "$container" --quick

step "the rotated-away passphrase is refused at once"
bond_fail list "$container" --passphrase-env BOND_TEST_PASS
expect_err "wrong passphrase or key"

step "another key can still be added, and the old passphrase stays refused"
BOND_ROTATED="$NEW_PASS-rotated" bond_with_stdin "a third secret" keys add "$container" --new-passphrase --label "the third" --passphrase-env BOND_ROTATED
[ "$BOND_STATUS" -eq 0 ] || fail "adding a third passphrase exited $BOND_STATUS"
assert_payload_untouched
bond_fail list "$container" --passphrase-env BOND_TEST_PASS
expect_err "wrong passphrase or key"

step "removing that third slot again leaves a container two keys still open"
BOND_ROTATED="$NEW_PASS-rotated" bond_ok keys remove "$container" --slot "the third" --yes --passphrase-env BOND_ROTATED
assert_payload_untouched
BOND_ROTATED="$NEW_PASS-rotated" bond_ok list "$container" --passphrase-env BOND_ROTATED

step "the last slot cannot be removed: an unopenable container is not a backup"
bond_ok keys list "$container"
while [ "$(printf '%s\n' "$BOND_OUT" | grep -c '^  \[')" -gt 1 ]; do
    BOND_ROTATED="$NEW_PASS-rotated" bond_ok keys remove "$container" --slot 1 --yes --passphrase-env BOND_ROTATED
    BOND_ROTATED="$NEW_PASS-rotated" bond_ok keys list "$container" --passphrase-env BOND_ROTATED
done
BOND_ROTATED="$NEW_PASS-rotated" bond_fail keys remove "$container" --slot 0 --yes --passphrase-env BOND_ROTATED
expect_err "this is the only key slot"

step "the container still restores after all of that"
BOND_ROTATED="$NEW_PASS-rotated" bond_ok restore "$container" --to "$CASE_TMP/restored-after" --passphrase-env BOND_ROTATED
assert_trees_equal "$src" "$CASE_TMP/restored-after/data"
assert_payload_untouched

# ---------------------------------------------------------------------------

step "rekey is the one command that re-encrypts, and it writes a new file rather than editing one"
cp "$container" "$CASE_TMP/original-copy.bond"
BOND_ROTATED="$NEW_PASS-rotated" bond_with_stdin "a master key nobody has ever seen" \
    rekey "$container" --out "$CASE_TMP/rekeyed.bond" --passphrase-env BOND_ROTATED
[ "$BOND_STATUS" -eq 0 ] || fail "rekey exited $BOND_STATUS"
assert_exists "$CASE_TMP/rekeyed.bond"
assert_files_identical "$container" "$CASE_TMP/original-copy.bond"

step "the re-encrypted copy holds the same files under a new key, and the old key does not open it"
BOND_REKEYED="a master key nobody has ever seen" bond_ok restore "$CASE_TMP/rekeyed.bond" \
    --to "$CASE_TMP/restored-rekeyed" --passphrase-env BOND_REKEYED
assert_trees_equal "$src" "$CASE_TMP/restored-rekeyed/data"
BOND_ROTATED="$NEW_PASS-rotated" bond_fail list "$CASE_TMP/rekeyed.bond" --passphrase-env BOND_ROTATED

step "the payload really was re-encrypted: the same files, different bytes"
new_payload=$(tail -c "+$(( DAMAGE_PAYLOAD_OFFSET + 1 ))" "$CASE_TMP/rekeyed.bond" | sha256sum | cut -d' ' -f1)
[ "$new_payload" != "$payload_before" ] ||
    fail "rekey produced a container whose payload bytes are unchanged, so nothing was re-encrypted"

step "rekey refuses to write over something that is already there"
BOND_REKEYED="a master key nobody has ever seen" bond_fail rekey "$container" --out "$CASE_TMP/rekeyed.bond" \
    --passphrase-env BOND_REKEYED
expect_err "already exists"

step "the re-encrypted copy has a checksum file of its own, as the original did"
bond_ok verify "$CASE_TMP/rekeyed.bond" --quick
