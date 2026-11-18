# The contract anything scripted around bond relies on.
#
# cmd/bond/main.go says so in as many words: "Exit codes. Anything scripted
# around bond can rely on these." A backup tool ends up inside cron jobs and CI
# pipelines, where the only thing read is the number it exited with and the
# only thing logged is whichever stream was captured – so both are checked here
# rather than assumed.

src="$CASE_TMP/data"
out="$CASE_TMP/output"
work="$CASE_TMP/work"
cfg="$CASE_TMP/config.json"

mkdir -p "$src"
echo 'something to back up' >"$src/file.txt"

config_new "$out" "$work"
config_setting '"encryptionMethod": "NONE"'
config_setting '"compressionLevel": 0'
config_target vault "$src"
config_write "$cfg"
bond_ok backup --config "$cfg"
container="$(container_in "$out")"

# ---------------------------------------------------------------------------
# Exit codes

step "0 means it worked"
bond_ok version
bond_ok help
bond_ok list --allow-unencrypted "$container"
expect_err "opened with the key stored in the container"

step "an unencrypted container is refused until the operator says it is expected"
bond_fail list "$container"
expect_err "--allow-unencrypted"

step "2 means the command was wrong: no command at all, or one that does not exist"
bond_usage
bond_usage nonesuch
expect_err "unknown command"

step "2 also covers a missing positional argument"
for command in restore list verify repair inspect rekey; do
    bond_usage "$command"
    expect_err "needs exactly one container"
done

step "2 also covers too many positional arguments"
bond_usage list "$container" "$container"
bond_usage backup --config "$cfg" something-positional
expect_err "backup takes no positional arguments"

step "2 also covers a required option that was not given"
bond_usage restore "$container"
expect_err "name a destination with --to"
bond_usage rekey "$container"
expect_err "name the destination with --out"
bond_usage keys remove "$container"
expect_err "name the slot to remove with --slot"
bond_usage keygen
expect_err "name what to create"
bond_usage keys
expect_err "keys needs a subcommand"
bond_usage keys nonesuch "$container"

step "1 means the work failed, and an option bond does not have is one of those"
# Recorded because it is easy to expect otherwise: an unknown flag comes from
# the flag package rather than from bond's own usage checks, so it is a failure
# and not a usage error. Anything switching on the exit code needs to know.
bond_fail verify --bogus "$container"
expect_err "flag provided but not defined"

step "1 also means a container that could not be opened"
bond_fail verify "$CASE_TMP/no-such-container.bond"

# ---------------------------------------------------------------------------
# Streams

step "the top-level help goes to stdout when it was asked for, and to stderr when it is a complaint"
bond_ok help
[ -n "$BOND_OUT" ] || fail "bond help wrote nothing to stdout"
[ -z "$BOND_ERR" ] || fail "bond help wrote to stderr as well"
bond_usage
[ -z "$BOND_OUT" ] || fail "the usage shown because of a mistake went to stdout"
[ -n "$BOND_ERR" ] || fail "the usage shown because of a mistake did not go to stderr"

step "a subcommand's help goes to stderr, so piping a command's output never mixes help into it"
for command in backup restore list verify repair inspect keygen keys rekey; do
    bond "$command" --help
    [ "$BOND_STATUS" -eq 0 ] || fail "bond $command --help exited $BOND_STATUS"
    expect_empty_out
    [ -n "$BOND_ERR" ] || fail "bond $command --help printed nothing at all"
done

step "reporting goes to stdout, so a container's contents can be piped into something else"
bond_ok list --allow-unencrypted "$container"
[ "$BOND_OUT" = "$(printf 'data\ndata/file.txt')" ] ||
    fail "the listing was not the two lines expected, but: $BOND_OUT"

step "errors go to stderr, so a script that captures only stdout does not miss them"
bond_fail verify "$CASE_TMP/no-such-container.bond"
[ -n "$BOND_ERR" ] || fail "an error was reported without anything on stderr"

# ---------------------------------------------------------------------------
# Argument order

step "options may come after the positional argument, because that is how people type it"
bond_ok restore --allow-unencrypted "$container" --to "$CASE_TMP/restored-after"
assert_exists "$CASE_TMP/restored-after/data/file.txt"

step "and before it, because that is how the usage line reads"
bond_ok restore --allow-unencrypted --to "$CASE_TMP/restored-before" "$container"
assert_exists "$CASE_TMP/restored-before/data/file.txt"

step "and interleaved, because parsing should not be a puzzle"
bond_ok restore --allow-unencrypted --to "$CASE_TMP/restored-between" "$container" --verbose
expect_out "data/file.txt"

step "-- ends the options, so a container whose name begins with a dash is still openable"
dashed="$CASE_TMP/-dashed.bond"
cp "$container" "$dashed"
bond_ok list --allow-unencrypted -- "$dashed"
expect_out "data/file.txt"

step "the short forms mean what the long forms mean"
bond_ok backup -c "$cfg" -n
expect_out "nothing was written; this was a dry run"
bond_ok backup --config "$cfg" --dry-run
expect_out "nothing was written; this was a dry run"
bond_ok backup -c "$cfg" -t vault -n
bond_ok list --allow-unencrypted "$container" -l
expect_out "data/file.txt"
bond_ok list --allow-unencrypted "$container" --long
expect_out "data/file.txt"

step "-v and --version are the version, wherever else -v means verbose"
bond_ok -v
expect_out "bond "
bond_ok --version
expect_out "bond "

# ---------------------------------------------------------------------------
# Finding the control file

step "with no --config, bond uses bond.config.json in the working directory"
here="$CASE_TMP/working-directory"
mkdir -p "$here"
config_new "$here/output" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target found "$src"
config_write "$here/bond.config.json"
( cd "$here" && "$BOND" backup ) >"$CASE_TMP/.found-out" 2>"$CASE_TMP/.found-err" ||
    fail "a backup with bond.config.json in the working directory did not run: $(cat "$CASE_TMP/.found-err")"
container_for "$here/output" found >/dev/null

step "a BOND control file named config.json in the working directory is refused"
stray="$CASE_TMP/stray-directory"
mkdir -p "$stray"
config_new "$stray/output" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target stray "$src"
config_write "$stray/config.json"
cd "$stray"
bond_usage backup
cd - >/dev/null
expect_err "bond.config.json"
[ ! -e "$stray/output" ] || fail "the refused backup still wrote into $stray/output"

# An installed binary has no directory of its own to keep a control file in, so
# the user's config directory is searched last. os.UserConfigDir reads a
# different variable on each platform; only the bond process sees the change.
step "with no --config, bond uses config.json in the user's config directory"
user_root="$CASE_TMP/user-config"
case "$(uname -s)" in
    Darwin) user_var=HOME user_dir="$user_root/Library/Application Support/bond" ;;
    MINGW* | MSYS* | CYGWIN*) user_var=APPDATA user_dir="$user_root/bond" ;;
    *) user_var=XDG_CONFIG_HOME user_dir="$user_root/bond" ;;
esac
nowhere="$CASE_TMP/no-control-file-here"
mkdir -p "$nowhere"
config_new "$user_dir/output" "$work"
config_setting '"encryptionMethod": "NONE"'
config_target user "$src"
config_write "$user_dir/config.json"
( cd "$nowhere" && env "$user_var=$user_root" "$BOND" backup ) >"$CASE_TMP/.user-out" 2>"$CASE_TMP/.user-err" ||
    fail "a backup with config.json in the user's config directory did not run: $(cat "$CASE_TMP/.user-err")"
container_for "$user_dir/output" user >/dev/null

step "{{CONFIG_DIR}} is the directory holding the control file"
placed="$CASE_TMP/placed"
config_new '{{CONFIG_DIR}}/output' '{{CONFIG_DIR}}/work'
config_setting '"encryptionMethod": "NONE"'
config_target placed "$src"
config_write "$placed/anywhere.json"
bond_ok backup --config "$placed/anywhere.json"
container_for "$placed/output" placed >/dev/null

# The defaults for outputPath and workPath sit beside the binary – usually the
# repository root. With the control file elsewhere they are refused, before a
# single file is written.
step "a control file away from the binary that leaves outputPath and workPath out is refused"
defaults="$CASE_TMP/defaults/bond.config.json"
mkdir -p "$(dirname "$defaults")"
printf '{ "settings": { "encryptionMethod": "NONE" }, "targets": [ { "id": "defaulted", "sources": [ { "path": %s } ] } ] }\n' \
    "$(json_string "$src")" >"$defaults"
bond_fail backup --config "$defaults"
expect_err "outputPath"
expect_err '{{CONFIG_DIR}}/output'
tool_dir="$(dirname "$BOND")"
[ -z "$(find "$tool_dir/output" "$tool_dir/work" -name 'defaulted-*' 2>/dev/null)" ] ||
    fail "the refused backup still wrote beside the binary"
