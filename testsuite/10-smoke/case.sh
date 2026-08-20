# Does this machine have a working bond at all?
#
# Everything below this case assumes the embedded 7-Zip unpacks and runs here.
# When it does not, twelve cases fail for one reason, and the one reason is
# what a person needs to see – so this case runs first and says it plainly.

step "the embedded 7-Zip unpacks and round-trips on this machine"
bond_ok selftest
expect_out "OK"

step "bond reports the version build.sh stamped into it"
bond_ok version
expect_out "bond "
[ -n "$BOND_OUT" ] || fail "bond version printed nothing"

step "asking for help is not an error, and the help goes to stdout"
bond_ok help
expect_out "usage: bond <command>"
expect_out "backup"
expect_out "restore"
[ -z "$BOND_ERR" ] || fail "bond help wrote to stderr as well as stdout"

step "-h and --help are the same as help"
for flag in -h --help; do
    bond_ok "$flag"
    expect_out "usage: bond <command>"
done

step "bond with no arguments is a usage error, and says so on stderr"
bond_usage
expect_err "usage: bond <command>"
expect_empty_out

step "every command bond advertises is a command it accepts"
bond_ok help
printf '%s\n' "$BOND_OUT" |
    sed -n 's/^  \([a-z-]*\) .*/\1/p' >"$CASE_TMP/.commands"
[ -s "$CASE_TMP/.commands" ] || fail "could not read the command list out of the help text"
while IFS= read -r cmd; do
    bond "$cmd" --help
    [ "$BOND_STATUS" -eq 0 ] || fail "bond $cmd --help exited $BOND_STATUS; a command that is advertised should at least explain itself"
done <"$CASE_TMP/.commands"
