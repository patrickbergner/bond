# The end-to-end testsuite

`go test ./...` covers the packages, and covers them well. This covers the
*binary*: the arguments people type, the exit codes scripts switch on, a real
`config.json` on disk, the way a secret reaches the tool when there is no
terminal to type it into, and a container as the file an operator copies,
renames, loses a volume of and tries to open anyway.

None of that is reachable from a Go test that calls a package. All of it is
reachable from a shell.

```
./build.sh                       # the suite drives what this produces
./testsuite/run.sh               # every case
./testsuite/run.sh 80 90         # only the cases whose names contain these
./testsuite/run.sh --list        # what would run
./testsuite/run.sh -v --keep 90  # each step as it is proved, working files left behind
```

Exit status is 0 when nothing failed. A failing case prints its whole log and
leaves its working directory under `testsuite/tmp/` for you to look at; a
passing one cleans up after itself.

| Environment | |
|---|---|
| `BOND_BIN` | a binary to test instead of the one for this platform |
| `BOND_TEST_SEED` | reshapes every generated tree; the default is fixed |

By default `run.sh` picks the `build.sh` output for the machine it is on –
`bond-windows-amd64.exe`, `bond-linux-amd64`, and so on – from the repository
root, and refuses to start if it is not there.

## The cases

| | |
|---|---|
| `10-smoke` | the embedded 7-Zip works here; help and version behave |
| `20-first-backup` | the five lines from the README, and the tree comes back |
| `30-filters-and-targets` | which files a filter chooses, and which targets a run does |
| `40-sidecar-interop` | `sha384sum -c` reads the checksum file BOND wrote |
| `50-keys-and-recovery-card` | key files, recovery cards, and the day the passphrase is gone |
| `60-key-management` | add, remove, rotate, rekey – and the payload never moves |
| `70-over-the-year` | twelve monthly runs, a passphrase change in July, January still opens |
| `80-damage-and-repair` | damage found, located, rebuilt, or refused out loud |
| `90-split-volumes` | a set of numbered files: moved, damaged, missing, mismatched, repaired |
| `91-awkward-trees` | empty files, umlauts, spaces, deep paths, both ends of compression |
| `92-symlinks` | materialized by default or counted and omitted |
| `93-geometry-edges` | shard sizes and recovery percentages at their limits |
| `94-bad-input` | wrong keys, wrong files, wrong control files, all refused |
| `95-cli-contract` | exit codes, streams, argument order, config discovery |

`92-symlinks` reports SKIP where the machine will not create a symbolic link,
which on Windows means developer mode is off. Nothing else skips.

## Writing another one

Make a directory named `NN-what-it-proves/` with a `case.sh` in it. `run.sh`
finds it, gives it a clean working directory, and sources the four libraries
first, so a case is a list of properties and not a program:

```bash
step "a container written today opens tomorrow"
bond_ok restore "$container" --to "$dest" --passphrase-env BOND_TEST_PASS
assert_trees_equal "$src" "$dest/data"
```

- `$CASE_TMP` is the case's own directory, and the shell starts there.
- `$BOND` is the binary. Call it through `bond`, `bond_ok`, `bond_fail` or
  `bond_usage` – those capture `$BOND_OUT`, `$BOND_ERR` and `$BOND_STATUS`,
  which the `expect_*` assertions then read.
- `step` names the property under test. It is printed with every failure below
  it, so the message a person sees says what broke and not which line did.
- `skip_case "reason"` ends a case when the machine cannot answer the question.
  Use it for platform limits, never for a result you did not like.

The libraries are `lib/harness.sh` (assertions), `lib/gendata.sh` (trees),
`lib/config.sh` (control files) and `lib/damage.sh` (corruption). Each says at
the top what it is for and why it does it that way.

Two conventions worth keeping:

**Paths are mixed-mode.** `run.sh` resolves its directories through
`cygpath -m` on Windows, so they read `C:/like/this` – understood by this shell
*and* by a Go binary, and needing no escaping inside a JSON control file. A
POSIX `/c/...` path is invisible to the binary under test.

**Every config names `outputPath` and `workPath`.** `config_new` takes them as
arguments so that no case can leave them out. Their default is `{{TOOL_DIR}}`,
which is the directory holding the binary – the repository root.
