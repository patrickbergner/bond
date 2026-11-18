# Backups on Non-Trusted Destinations (BOND)

Back up a configurable, filtered set of files into **quantum-safe, encrypted containers** with 
**high-grade LZMA2 compression** (think of 7-Zip), hand it to **storage you have no reason to trust**
(think of cheap cloud storage), and get every byte back years later. All in a single binary for Windows,
macOS or Linux.

The destination is assumed hostile: it may read your backup without you knowing, it may quietly lose bytes,
and it may still have the file long after you have forgotten it or the machine that wrote it is gone.

## Who it is for

- **One laptop and irreplaceable photos.** A control file naming the handful of directories that actually matter, a
  passphrase, and containers dropped into whatever cloud storage is cheap or comfortable.
- **A freelancer or small office.** Client work under a passphrase the people who need it know, plus a printed
  recovery card in a safe – so the backups survive a forgotten passphrase, a lost laptop and a change of staff, and
  the archive of a finished project can be handed to cold storage.
- **A homelab or self-hosted server.** A nightly unattended run with a public recipient key: nothing on the box can
  decrypt what the box wrote, which is the difference between "the NAS was compromised" and "the last five years
  of backups were compromised too".
- **An IT administrator with a fleet of workstations.** The same control file and the same public key rolled out by
  GPO or MDM, no per-machine secrets, no key escrow to build. Because quick verification needs no key at all, a
  monitoring job can check every stored container against its checksum file while holding nothing that could open
  any. That finds what storage does to a file by accident; a checksum file sits beside the container and proves
  nothing against someone who replaces both, which is what `bond verify` with a key is for.
- **A cloud or edge architecture administrator.** Thousands of nodes writing containers into object storage under
  someone else's control, each with a public key only, so a stolen image or an exfiltrated instance role yields
  ciphertext. Restores happen at one deliberate place from a key that lives offline, and a second recipient slot on a
  printed card is the break-glass path when that key is unavailable. A writer key per node signs what it writes, so a
  restore can refuse a container built by anyone else who knows the public key.
- **Anyone backing up for the long horizon.** Notarial, medical, legal and research material that must outlive the
  hardware, the storage contract and probably the vendor: post-quantum key exchange for the decades of exposure,
  parity for the bit rot, and a documented format for the day nobody can find the binary.

### What it is not

BOND backs up the *contents* of files and directories: names, bytes, permission bits and modification times. It is
not a system backup and not a sync tool, and these limits are worth knowing before relying on it:

- **Every run is a full backup.** There is no incremental or deduplicated mode and no pruning of old containers;
  each run reads everything and writes a new container, and deleting old ones is yours to do.
- **One container is one stream.** Restoring a single file reads the container from the start, so `--include` costs
  the time of a full restore.
- **Not stored, and so not restored:** owners and groups, ACLs, extended attributes, Windows attributes and
  alternate data streams, hard links (each name is stored as its own file), sparse regions (stored in full), and
  anything that is not a file or directory. A symlink is stored as what it points to, or left out.
- **No snapshot is taken.** Files are read as they are while the backup runs. One that changes underneath is stored
  as it was read, with a warning; an open database or mail store may come back inconsistent. Back those up from a
  dump or a snapshot.
- **One file protects against damage, not against loss.** Parity rebuilds a container that storage has corrupted. It
  does nothing about a container that was deleted, or replaced by an older one that was valid when it was written;
  keep two copies in two places. The full list is in [NERDME.md §10](NERDME.md#10-threat-model).

## How it is designed

- **Zero trust in the destination.** The operator gets an opaque file. File names, source paths and per-file sizes
  are sealed along with the data, and the container is padded, so its size gives the size of the backup only
  roughly (at a cost of a few percent). A storage provider can see nothing else about what is inside it. All internal
  container structures are authenticated, so a container that was altered on the way is refused rather than
  restored when the storage provider does not possess an unlocking secret. Two modes are explicitly different.
  `NONE` offers corruption detection but neither confidentiality nor malicious-tamper authenticity, and a container
  only opens that way when `--allow-unencrypted` says it is expected. A container that only a public key was needed
  to write proves nothing about *who* wrote it: see [Keys](#keys).
- **Creating a backup needs no secret.** When using asymmetric keys, BOND only needs the *public key* on the machine
  making the backup: the job runs unattended and cannot read back what it just wrote, and a host compromised next year
  gives up nothing about the backups it already shipped. One public key in one control file scales to thousands of
  cloud and edge servers with no unlockable key material on any of them.
- **A recovery key you can print.** The secret is roughly sixty characters of Crockford Base 32 on a card carrying
  the restore procedure and the fingerprint of its public key. One card opens every container written to that public
  key. It is generated where you choose, never has to touch the machine being backed up, and belongs in a safe rather
  than a password manager.
- **Hardware key files and passphrases, as usual.** Random bytes on a device plugged in for the run, or a passphrase
  behind Argon2id. A new passphrase needs at least twelve characters, and is hashed in Unicode normal form, so one
  set on a Mac opens on Windows. Authentication slots of an encrypted container are independent – any one of them opens it – 
  and because the key-slot tables sit outside everything the superblock authenticates, adding or replacing a key
  rewrites the two 64 KiB tables rather than the whole container, on a 400 GB one as much as on a small one.
- **Post-quantum, from the first byte.** Authentication keys are military grade hybrid X25519 + ML-KEM-1024. A backup
  written this year may still be sitting in someone's object storage in twenty, which is exactly the horizon a
  "harvest now, decrypt later" attack aims at – and combining a classical exchange with a post-quantum lattice one
  means the container is no weaker than whichever of the two turns out to survive.
- **Damage is survivable.** Reed-Solomon parity optionally rides inside the container, so bit rot is located, reported
  and rebuilt from the file itself, with no second file to keep track of and no network round trip. Everything that is
  not your data – the header of every volume, the key slots, the file index – is stored twice, so a flipped bit there
  costs nothing at all. A damaged spare is reported even when it was not the copy needed, because a container quietly
  down to its last copy of something is the one worth hearing about.
- **Five platforms, and a format documented to the byte.** Windows, Windows on ARM, macOS on Apple Silicon and Linux
  AMD64 & ARM64 are supported. Write on one, restore on another. [NERDME.md](NERDME.md) walks you through all the
  technical details, including decrypting a container by hand, because a format only its own tool can read is a
  single point of failure. That procedure also exists as a small stand-alone program,
  [tools/handread](tools/handread/main.go), which shares no code with BOND and is tested against it.
- **None of the above is claimed untested.** Every promise on this page is checked by something that fails when it
  stops being true – a single-bit sweep across a whole container, six fuzz targets, and an
  [end-to-end suite](testsuite/) that damages, splits, loses and repairs real containers through the real command
  line. See [how it is tested](#how-it-is-tested).

## Using it

```
bond selftest                                  # check the embedded 7-Zip works here
bond backup --dry-run                          # what would be stored, writing nothing
bond backup                                    # write the containers
bond verify  backup.bond                       # authenticate every shard
bond verify  backup.bond --quick               # checksum only; needs no key
bond repair  backup.bond                       # rebuild damaged shards from the recovery data
bond list    backup.bond -l                    # what is inside, from the manifest
bond inspect backup.bond                       # format and settings
bond restore backup.bond --to ./restored
bond bench-kdf                                 # what the passphrase hardening costs on this machine

bond keygen --recovery-card card.txt           # a printable key, and a public key for the config
bond keygen --keyfile usb.key                  # 32 bytes for a device you plug in
bond keygen --signing-key writer.key           # signs what this machine writes; writer.key.pub checks it
bond keys list  backup.bond                    # what can open this container, as stored (needs no key)
bond keys add   backup.bond --new-passphrase   # 128 KiB of writing, whatever the container's size
bond keys rotate-passphrase backup.bond
bond rekey backup.bond --out new.bond          # the only command that re-encrypts everything
```

`--dry-run` enumerates every source, applies the filters and reports what would go into each container without
writing anything. `--verbose` adds one line per decision naming the rule responsible, which is how a control file
gets tuned against a real tree.

Interrupting a run with Ctrl-C or SIGTERM ends it cleanly: whatever was being assembled is removed from the working
directory and nothing half-written is published. A second interrupt ends the process at once.

A passphrase is asked for at the terminal. For unattended runs, `--passphrase-file <path>` is the recommended form;
`--passphrase-env <name>` and `--passphrase <text>` also work, the last with a warning, because a command line is
visible to every other process and lands in shell history.

`selftest` is the per-platform check. BOND is cross-compiled for five platforms from one of them, so most of what it
ships can never be run by whoever built it: this command unpacks the embedded 7-Zip, pushes a real archive through
compression and back, restores it and compares every digest. Run it once on each machine that matters.

### Keys

Four ways into a container, and any number of them at once. All wrap the same master key, so adding, removing or
rotating one writes **128 KiB**, both copies of the key-slot table – the same work on a one-terabyte backup as on a
one-megabyte one. Only `bond rekey` re-encrypts anything, and it says so before it starts.

A removed or rotated key stops opening the container as soon as the command returns. It still opens any copy of the
file made before that, because the master key underneath has not changed; when an old copy and an old key may be in
the same hands, `bond rekey` is the answer. A key change also rewrites the first volume's checksum file, so
`bond verify --quick` goes on passing.

`bond rekey` shares no key with the container it reads, so it is told what the new one opens with: `--new-passphrase`,
`--new-keyfile <path>`, `--new-recipient <public key>`, in any combination, and a passphrase is asked for when none
is given. A split set stays split, with no volume larger than the largest it had (`--max-volume-bytes` overrides),
and the copy gets checksum files when the original had them.

| | needs at backup time | needs at restore time |
|---|---|---|
| **passphrase** | typed, or `--passphrase-file` | the same passphrase |
| **key file** | the file | the file |
| **recovery card** | *nothing but a public key* | the printed key |
| **none** | nothing | `--allow-unencrypted` – no confidentiality; corruption detection only |

The recovery card is the interesting one. `bond keygen --recovery-card` writes a printable key and a public key; only
the public key goes in the control file, so a scheduled backup runs unattended and **the machine making the backup
cannot read it**. Print the card, put it in a safe, delete it from the machine. `keygen` shows the card only on a
terminal; redirected into a file or a log, its output names the card file and leaves the key out. Restoring is
`bond restore backup.bond --to ./restored --recovery-key "BOND-R1-…"`; case and hyphens do not matter, and the letters
that get misread – I, L, O – are accepted and corrected. A key that is too short, too long, or fails its checksum is
refused with a message that says which, before anything is tried against the container.

What the public key cannot do is vouch for a backup. Anyone who has it can write a container the card opens, so a
container with only recipient slots is confidential but not attributable: someone who knows the public key could
replace the whole file with one of their own making, and it would restore. A restore through the card says so.

A **writer key** closes that. `bond keygen --signing-key writer.key` makes a pair; the secret half goes in the control
file of the machine that writes backups (`"signingKey": "{{HOME}}/writer.key"`), and every container it writes is
signed – Ed25519 and ML-DSA-65, both of which have to hold. The public half, `writer.key.pub`, goes beside the card:

```
bond restore backup.bond --to ./restored --recovery-key "BOND-R1-…" --expect-writer writer.key.pub
bond verify  backup.bond --quick --expect-writer writer.key.pub     # needs no decryption key at all
```

A container the writer did not sign is refused before anything is restored. The second line is the check for a
monitoring job: it proves every volume is what the writer wrote, with no key that could open any of them – which a
checksum file, sitting beside the container and as easy to replace, cannot. The writer key opens nothing; a machine
holding one can vouch for its backups and still cannot read them.

An unencrypted container (`encryptionMethod: NONE`) stores its key inside itself, and opens only with
`--allow-unencrypted`. BOND never takes that route on its own: which slots a container lists is read before anything
is authenticated, so a file that announced "no key needed" and was believed would restore whatever its author put
in it. The flag cannot be combined with a key.

Before authentication, passphrase slots are limited to 1 GiB memory, 6 passes, 64 lanes and 3 GiB-passes per
derivation, and one unlock runs at most 64 of them. This prevents a damaged or hostile container from requesting
unbounded Argon2 work, and is set so that a container using BOND's own defaults in every slot the format allows still
opens on the last one tried. `--allow-expensive-kdf` on commands that unlock a container bypasses those local
willingness limits, keeps the format validity checks, and prints a resource-risk warning; use it only for a container
whose unusual costs are expected.

### Volumes

`maxVolumeBytes` splits a container into numbered files, for object stores that cap a single upload. Each volume
carries its own header – twice, once at each end of the file – and its own checksum file, so any one of them finds the
rest and none of them is a single flipped bit away from being unreadable: `bond restore backup.bond.003` works as well
as starting from the first, and `bond verify --quick` checks every volume of the set.

A volume never splits a shard, so the shards of a split container are cut to fit: no volume is larger than
`maxVolumeBytes`, whatever `shardBytes` says. The one exception is the last volume of a backup with a very large file
index, which may run over by the size of that index.

### Recovery data

`recoveryPercent` (10 by default) adds Reed-Solomon parity so a container survives the corruption storage quietly
inflicts on it. `bond verify` locates the damage and says whether it can be rebuilt; `bond repair` rebuilds it into a
**new** file, leaving the damaged one untouched. The repaired copy is assembled under a working name, verified in
full, and only then given its name, so a repair that fails or is interrupted leaves nothing that looks like a
container.

`bond restore` uses the recovery data as well: a shard that fails while it is being read is rebuilt in memory, the
restore completes, and its summary says the container is damaged and wants `bond repair`. A recovery does not have to
wait for a second full copy of the backup to be written first.

`bond verify` exits non-zero for anything short of full health. That includes a container whose payload is whole but
which opened on its last copy of a header, a key-slot table or the manifest: nothing is lost yet, the next fault
there loses everything, and `bond repair` puts the copy back without needing any recovery data.

The capacity is **per stripe**, not per container. At 10% a stripe is 20 data shards protected by 2 parity shards, so
any two losses out of twenty are recoverable – and a container of a thousand shards survives a hundred losses if they
fall two per stripe, but not three in one. Set `recoveryPercent` to 20 or 30 for backups that matter more.

Parity repairs corruption, not deletion. Nothing in a single file protects against that file being removed, so keep
two copies.

### What it costs

Compression is the whole story. Everything else BOND does – encryption, parity, the checksums – is a few percent, and
individually too small to measure. From a 135 MB tree, half of it deliberately incompressible, on an ordinary laptop:

| Operation | Time | |
|---|---:|---|
| Backup, `compressionLevel: 0` | 0.7 s | no compression at all |
| Backup, `compressionLevel: 1` | 2.8 s | |
| Backup, `compressionLevel: 5` | 7.2 s | the default |
| `verify` | 0.2 s | every shard authenticated |
| `restore` | 0.4 s | |

So: **set `compressionLevel: 0` for photos, video and music.** They are already compressed, LZMA2 will find nothing,
and it is ten times faster. Keep level 5 for documents, mail and source code, where it earns its time. The maximum
level is 9. Note that restoring is far cheaper than backing up, which is the right way round for something you hope
to do once.

### Restoring

`bond restore backup.bond --to ./somewhere` writes everything into a directory of your choosing. That directory should
be empty: a file that is already there stops the restore unless `--overwrite` is given, because an occupied
destination usually means the wrong one was named.

Every shard is authenticated as it is read, so nothing that failed its tag reaches the decompressor; a shard rebuilt
from the recovery data has to pass the same tag. Every archive
name is checked before a file is created: absolute paths, `..`, drive letters, Windows device names and every link
entry abort the whole restore rather than being skipped. Archive entry names are confined lexically below the selected
destination. Existing symlinks, junctions and other filesystem redirections below it follow normal operating-system
behavior and are the user's responsibility; restore into a new or suitably prepared directory if that is not desired.
Each restored file is then hashed and compared with the digest recorded when it was backed up, and `bond restore`
reports how many matched. `--include` restores a subset but still reads and hashes the whole archive, because a
container is one sealed stream and checking only the part asked for would leave the rest unexamined — so a partial
restore costs the time of a full one, and a digest that does not match anywhere fails it. The count reported as
verified is the files actually written.

### The restore drill

A backup nobody has ever restored is a hypothesis. Twice a year, on the copy that actually lives in the cloud:

```
bond verify  backup.bond --quick            # 1. it arrived intact – no key needed
bond verify  backup.bond                    # 2. every shard authenticates
bond list    backup.bond -l | head          # 3. it holds what you think it holds
bond restore backup.bond --to ./drill       # 4. it comes back
```

Step 4 is the one people skip and the only one that proves anything. Do it from the **printed recovery card**, typed
in by hand, not from the passphrase in your password manager – that is the path you will be on when it matters, and
the only way to find out the card is wrong is to use it. Restore into a scratch directory, compare a few files, delete
it.

If a container comes back damaged, `bond verify` says whether it can be rebuilt and `bond repair` rebuilds it into a
new file, leaving the damaged one alone.

## The control file

A JSON file listing targets and the settings that govern them. Unless `--config` names one, BOND reads the first of:

1. `bond.config.json` in the working directory.
2. `config.json` beside the binary, the layout of the release archives.
3. `config.json` in the user's config directory, for an installed binary such as one from a package manager:
   `$XDG_CONFIG_HOME/bond`, usually `~/.config/bond`, on Linux, `~/Library/Application Support/bond` on macOS and
   `%AppData%\bond` on Windows.

[config.sample.json](config.sample.json) is a worked example, and
[schema/bond-config.schema.json](schema/bond-config.schema.json) is a JSON Schema, so an editor can validate it while
you type. Unknown keys are a load error: a misspelled filter would otherwise silently widen a backup.

`outputPath`, `workPath`, `signingKey` and the `path` of a key slot take the placeholders `{{HOME}}`, `{{TOOL_DIR}}`
(the directory holding the binary), `{{CONFIG_DIR}}` (the directory holding the control file), `{{TARGET_ID}}`,
`{{DATE}}` and `{{TIMESTAMP}}`. The defaults for `outputPath` and `workPath` are `{{TOOL_DIR}}/output` and
`{{TOOL_DIR}}/work`, made for the portable layout, and BOND uses them only when the control file sits beside the
binary. Anywhere else – typically with an installed binary, whose directory is something like `/usr/bin` – a backup
that would fall back on them is refused before the first target, naming the setting to add. The sample sets both to
`{{CONFIG_DIR}}`, which is the same place in the portable layout and a writable one for an installed binary.

Each source is a directory tree plus filters, all matched against the source-relative path with `/` separators
(case-insensitively on Windows and macOS):

| Filter | Meaning |
|---|---|
| `includedPaths` / `excludedPaths` | Literal paths. Naming a directory covers its whole subtree. |
| `includedPathPrefixes` / `excludedPathPrefixes` | String prefix, so `mandrel/conf` also covers `mandrel/config`. |
| `includedPathPatterns` / `excludedPathPatterns` | Go regular expressions. |
| `excludedFileNames` / `excludedDirectoryNames` | A name anywhere in the tree. |

An exclusion always wins. If any include list is non-empty the default flips to deny, which is how "this subtree,
except these bits" is written.

`followSymlinks` defaults to `true`. Links to files and directories are materialized at the link's archive path; a
directory loop is cut at that edge with a warning, while repeated non-cyclic aliases are each archived. Set it to
`false` to omit included links with a counted warning. BOND never stores or restores a link entry. A Windows
junction is a link like any other and follows the same setting.

Only files and directories are archived. Named pipes, sockets and device nodes are left out with a warning and a
count in the summary. A name that is not valid UTF-8 – a Latin-1 name on an old Linux tree – is backed up under
exactly the bytes it has, and restores on Linux; Windows and macOS cannot store such a name and refuse that entry by
name.

Files land in the archive under the longest common ancestor of the sources' parent directories, so
`D:\Apps\Notepad++` and `D:\Apps\7-Zip` become `Notepad++/…` and `7-Zip/…`. When sources span Windows drives or
UNC shares there is no common ancestor and each root becomes synthetic – `c_drive/…`, `d_drive/…`,
`unc_server_share/…`.

On Windows a source path must name its drive. `/data/tools` is rooted but not absolute there – it binds to whichever
drive happens to be current – so BOND refuses it rather than backing up something nobody asked for.

## How it is built

```
./build.sh   # fetch embedded binaries, vet, test, then cross-compile all five platforms
```

Targets: `windows/amd64`, `windows/arm64`, `linux/amd64`, `linux/arm64`, `darwin/arm64`. The version they report
comes from [VERSION](VERSION).

The embedded binaries are **not** committed. `tools/fetch` downloads a release pinned in
[tools/manifest.json](tools/manifest.json). `go:embed` then builds each one into the binary for its platform.

## How it is tested

Two layers, and both run from a checkout.

`go test ./...` covers the packages and the format: a single-bit sweep that flips one bit at each of 632 offsets
across a container – every header field densely, every other region by a fixed count – and requires each flip to be
either refused or absorbed, never silent; six fuzz targets whose corpus runs on every invocation, the parity capacity
arithmetic, a peak-memory ceiling, and full round trips through the real 7-Zip.

[testsuite/](testsuite/) covers the *binary* – the part no package test can reach. Fourteen cases drive the built
executable the way an operator does: a control file on disk, secrets arriving with no terminal to type them into,
and containers copied, renamed, split across volumes, damaged and repaired as files.

```
./testsuite/run.sh   # fourteen cases, about three minutes
```

- **The ordinary run** – back up, `verify --quick`, `verify`, `list`, `restore`, and the tree matches byte for byte,
  modification times included. Filters, targets, dry runs. A checksum file that plain `sha384sum -c` can read.
- **The bad day** – key files and printed recovery cards, restoring from the card as it is written on it, adding and
  rotating and removing keys, `rekey`, and twelve monthly backups with the passphrase changing in July.
- **The damage** – bytes flipped inside a payload, past what the parity covers, in a header, in the reserved padding,
  in a key-slot table, and in the middle volume of a split set with its checksum files still beside it.
- **The edges** – empty files, umlauts, deep paths, symlinks, shard sizes and recovery percentages at their limits,
  wrong keys, truncated containers, malformed control files, and the exit codes a cron job switches on.

Every tree it needs is generated at run time from a seed and deleted when the case passes; nothing large is
committed. `testsuite/run.sh --list` names the cases, `-v` prints each property as it is proved.
