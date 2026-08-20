# A year of backups.
#
# BOND has no incremental mode and no retention policy: every run writes a
# complete, independent container. That is a design decision with a consequence
# worth proving rather than assuming – a container from January owes nothing to
# the eleven that came after it, and still opens when the source directory, the
# machine's passphrase and the rest of the set are all gone.

src="$CASE_TMP/documents"
snapshots="$CASE_TMP/snapshots"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"
base="$CASE_TMP/archive"

OLD_PASS="$BOND_TEST_PASS"
NEW_PASS="the passphrase from the July that everything changed"
export BOND_YEAR_OLD="$OLD_PASS"
export BOND_YEAR_NEW="$NEW_PASS"

gen_tree "$src" 256
mkdir -p "$snapshots"

step "the dated and per-target placeholders put a run where an operator can find it"
config_new "$base/{{TARGET_ID}}/{{DATE}}" "$work"
config_setting '"encryptionMethod": "PROMPT_KEYPHRASE"'
config_setting '"compressionLevel": 1'
config_target documents "$src"
config_write "$cfg"
bond_ok backup --config "$cfg" --passphrase-env BOND_YEAR_OLD
today=$(date +%Y-%m-%d)
assert_exists "$base/documents/$today"
container_in "$base/documents/$today" >/dev/null

step "an unknown placeholder is caught when the control file is read, not halfway through a run"
config_new "$base/{{TOOLDIR}}" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target documents "$src"
config_write "$cfg"
bond_fail backup --config "$cfg"
expect_err "unknown placeholder"

# ---------------------------------------------------------------------------
# Twelve monthly runs. Each goes to its own directory: {{DATE}} is proved
# above, and it would give all twelve the same name here because they happen
# inside the same minute rather than across a year.

step "twelve monthly runs each write a complete container of the tree as it then stood"
for month in $(seq 1 12); do
    mm=$(printf '%02d' "$month")

    # From July, the machine's passphrase is a different one – the ordinary
    # reason being that the old one was typed somewhere it should not have been.
    if [ "$month" -ge 7 ]; then
        pass_var=BOND_YEAR_NEW
    else
        pass_var=BOND_YEAR_OLD
    fi

    config_new "$base/month-$mm" "$work"
    config_setting '"encryptionMethod": "PROMPT_KEYPHRASE"'
    config_setting '"compressionLevel": 1'
    config_target documents "$src"
    config_write "$cfg"

    bond_ok backup --config "$cfg" --passphrase-env "$pass_var"
    cp -r "$src" "$snapshots/month-$mm"
    mutate_tree "$src"
done

step "there are twelve containers, and no run overwrote another"
[ "$(find "$base" -name 'documents-*.bond' | grep -c .)" -eq 13 ] ||
    fail "expected thirteen containers (twelve monthly plus the dated one), found $(find "$base" -name 'documents-*.bond' | grep -c .)"

step "every month verifies, and restores exactly the tree as it stood that month"
for month in $(seq 1 12); do
    mm=$(printf '%02d' "$month")
    if [ "$month" -ge 7 ]; then
        pass_var=BOND_YEAR_NEW
    else
        pass_var=BOND_YEAR_OLD
    fi
    c="$(container_in "$base/month-$mm")"
    bond_ok verify "$c" --quick
    bond_ok verify "$c" --passphrase-env "$pass_var"
    bond_ok restore "$c" --to "$CASE_TMP/restored-$mm" --passphrase-env "$pass_var"
    assert_trees_equal "$snapshots/month-$mm" "$CASE_TMP/restored-$mm/documents"
    rm -rf "$CASE_TMP/restored-$mm"
done

step "a month made under the old passphrase does not open with the new one, or the other way round"
bond_fail list "$(container_in "$base/month-01")" --passphrase-env BOND_YEAR_NEW
bond_fail list "$(container_in "$base/month-12")" --passphrase-env BOND_YEAR_OLD

step "January still restores after the source directory and every other month are gone"
january="$CASE_TMP/january.bond"
cp "$(container_in "$base/month-01")" "$january"
rm -rf "$src" "$base" "$work"
bond_ok restore "$january" --to "$CASE_TMP/restored-january" --passphrase-env BOND_YEAR_OLD
assert_trees_equal "$snapshots/month-01" "$CASE_TMP/restored-january/documents"

step "the restore drill from the README, on a container with nothing left around it"
bond_fail verify "$january" --quick          # the sidecar was left behind with the rest
expect_err "no checksum file next to"
bond_ok verify "$january" --passphrase-env BOND_YEAR_OLD
expect_out "OK"
bond_ok list "$january" --passphrase-env BOND_YEAR_OLD
expect_out "documents/notes"
bond_ok restore "$january" --to "$CASE_TMP/drill" --passphrase-env BOND_YEAR_OLD
assert_trees_equal "$snapshots/month-01" "$CASE_TMP/drill/documents"
