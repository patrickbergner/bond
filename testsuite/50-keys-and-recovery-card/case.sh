# The day the passphrase is gone.
#
# A backup that can only be opened by something in the operator's head is one
# bad week away from being no backup at all. These are the other ways in: a key
# file on a device, and a printed card in a safe – including the case that
# matters most, where the machine that made the backup held nothing that could
# open it.

src="$CASE_TMP/data"
work="$CASE_TMP/work"
keys="$CASE_TMP/keys"
cfg="$CASE_TMP/config.json"

mkdir -p "$keys"
gen_tree "$src" 512

step "a key file is exactly 32 bytes, and keygen says what to do with it"
bond_ok keygen --keyfile "$keys/usb.key"
assert_exists "$keys/usb.key"
[ "$(file_bytes "$keys/usb.key")" -eq 32 ] ||
    fail "a key file should be 32 bytes, this one is $(file_bytes "$keys/usb.key")"
expect_out '"type": "keyfile"'

step "key material is never overwritten, however it was asked for"
bond_fail keygen --keyfile "$keys/usb.key"
expect_err "refusing to overwrite key material"
[ "$(file_bytes "$keys/usb.key")" -eq 32 ] || fail "the refused keygen damaged the existing key file"

step "a recovery card carries a printable key and the public key that locks the backup"
bond_ok keygen --recovery-card "$keys/card.txt" --label "the safe at home"
assert_exists "$keys/card.txt"
assert_exists "$keys/card.txt.pub"
expect_out "BOND RECOVERY KEY"
expect_out "the safe at home"
grep -q '^  BOND-R1-' "$keys/card.txt" || fail "the card has no recovery key line on it"
grep -q '"type": "recipient"' "$keys/card.txt.pub" || fail "the .pub file is not a control-file snippet"

# The card is written for a person: instructions, a date, and the key repeated
# inside a ready-made restore command. The bare line is the key itself.
recovery_key=$(grep -o 'BOND-R1-[A-Z0-9-]*' "$keys/card.txt" | head -n 1)
[ -n "$recovery_key" ] || fail "could not read the recovery key off the card"

step "--recipient writes the same key pair for a script rather than for a person"
bond_ok keygen --recipient "$keys/machine.key"
assert_exists "$keys/machine.key.pub"
expect_no_out "BOND RECOVERY KEY"

# The public key is what goes in the control file. Reading it back out of the
# snippet keygen wrote is what an operator does by copy and paste.
public_key=$(sed -n 's/.*"publicKey": "\([^"]*\)".*/\1/p' "$keys/card.txt.pub")
[ -n "$public_key" ] || fail "could not read the public key out of $keys/card.txt.pub"

# ---------------------------------------------------------------------------

step "a container locked with a key file opens with that key file"
out_keyfile="$CASE_TMP/output-keyfile"
config_new "$out_keyfile" "$work"
config_setting '"encryptionMethod": "KEYFILE"'
config_target byfile "$src"
config_write "$cfg"
bond_ok backup --config "$cfg" --keyfile "$keys/usb.key"
container="$(container_in "$out_keyfile")"
bond_ok restore "$container" --to "$CASE_TMP/restored-keyfile" --keyfile "$keys/usb.key"
assert_trees_equal "$src" "$CASE_TMP/restored-keyfile/data"

step "a different key file of the right length is refused, not guessed at"
head -c 32 /dev/urandom >"$keys/wrong.key"
bond_fail restore "$container" --to "$CASE_TMP/restored-wrong" --keyfile "$keys/wrong.key"
assert_missing "$CASE_TMP/restored-wrong/data"

step "a key file of the wrong length is refused with its length named"
head -c 31 /dev/urandom >"$keys/short.key"
bond_fail restore "$container" --to "$CASE_TMP/restored-short" --keyfile "$keys/short.key"
expect_err "31 bytes"

step "offering a passphrase to a container that has no passphrase slot says what it does take"
bond_fail restore "$container" --to "$CASE_TMP/restored-pass" --passphrase-env BOND_TEST_PASS
expect_err "this container has no slot of that kind"
expect_err "it opens with keyfile"

# ---------------------------------------------------------------------------

step "a backup can be locked by a public key, with nothing on the machine that could open it"
out_card="$CASE_TMP/output-card"
config_new "$out_card" "$work"
config_setting '"encryptionMethod": "RECIPIENT"'
config_setting "\"keySlots\": [ { \"type\": \"recipient\", \"publicKey\": $(json_string "$public_key"), \"label\": \"the safe at home\" } ]"
config_target bycard "$src"
config_write "$cfg"
bond_ok backup --config "$cfg"
container="$(container_in "$out_card")"
expect_no_out "BOND-R1-"

step "the card in the safe opens it, typed in as it is written"
bond_ok restore "$container" --to "$CASE_TMP/restored-card" --recovery-key "$recovery_key"
assert_trees_equal "$src" "$CASE_TMP/restored-card/data"

step "case and hyphens do not matter when typing the key back"
lowered=$(printf '%s' "$recovery_key" | tr 'A-Z' 'a-z')
bond_ok restore "$container" --to "$CASE_TMP/restored-lower" --recovery-key "$lowered"
assert_trees_equal "$src" "$CASE_TMP/restored-lower/data"

step "the whole card can be handed over as a file: the key is found inside it"
bond_ok restore "$container" --to "$CASE_TMP/restored-cardfile" --recovery-key-file "$keys/card.txt"
assert_trees_equal "$src" "$CASE_TMP/restored-cardfile/data"

step "a card for a different backup is refused"
bond_ok keygen --recovery-card "$keys/other-card.txt"
other_key=$(grep -o 'BOND-R1-[A-Z0-9-]*' "$keys/other-card.txt" | head -n 1)
bond_fail restore "$container" --to "$CASE_TMP/restored-other" --recovery-key "$other_key"

step "a file with no recovery key in it says that, rather than failing obscurely"
echo 'this is my shopping list' >"$keys/not-a-card.txt"
bond_fail restore "$container" --to "$CASE_TMP/restored-nocard" --recovery-key-file "$keys/not-a-card.txt"
expect_err "no line starting with BOND-R1 was found"

step "the slots are listed without any key at all, so an operator can see what to go and find"
bond_ok keys list "$container"
expect_out "recipient"
expect_out "the safe at home"
