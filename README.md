# Backups on Non-Trusted Destinations (BOND)

Back up a configurable, filtered set of files into **quantum-safe, encrypted containers** with 
**high-grade LZMA2 compression** (think of 7-Zip), hand it to **storage you have no reason to trust**
(think of cheap cloud storage), and get every byte back years later. All in a single binary for Windows,
macOS or Linux.

The destination is assumed hostile: it may read your backup without you knowing, it may quietly lose bytes,
and it may still have the file long after you have forgotten it or the machine that wrote it is gone.

## Getting it

Take the archive for your platform from the [Releases](../../releases) page – `windows-amd64` or `windows-arm64`
as a `.zip`, `linux-amd64`, `linux-arm64` or `macos-arm64` as a `.tar.gz` – and verify it against
`SHA256SUMS.txt`. Each one unpacks to a single `bond-<version>/` directory holding the binary as plain `bond` or
`bond.exe`, [config.sample.json](config.sample.json), a short `readme.txt`, `LICENSE` and the terms of the
embedded 7-Zip. Nothing else is needed; there is no installer and no runtime to have. Run `bond selftest` once on
the machine, and see [how it is built](#how-it-is-built) to make the same archives yourself.

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
  monitoring job can prove every stored container is still intact while holding nothing that could open any.
- **A cloud or edge architecture administrator.** Thousands of nodes writing containers into object storage under
  someone else's control, each with a public key only, so a stolen image or an exfiltrated instance role yields
  ciphertext. Restores happen at one deliberate place from a key that lives offline, and a second recipient slot on a
  printed card is the break-glass path when that key is unavailable.
- **Anyone backing up for the long horizon.** Notarial, medical, legal and research material that must outlive the
  hardware, the storage contract and probably the vendor: post-quantum key exchange for the decades of exposure,
  parity for the bit rot, and a documented format for the day nobody can find the binary.

## How it is designed

- **Zero trust in the destination.** The operator gets an opaque file. File names, source paths and per-file sizes
  are sealed along with the data, so a storage provider can see nothing about what is inside it. All internal
  container structures are authenticated, so a container that was altered on the way is refused rather than
  restored. This is what makes it reasonable to put critical files in a zero trust environment.
- **Creating a backup needs no secret.** When using asymmetric keys, BOND only needs the *public key* on the machine
  making the backup: the job runs unattended and cannot read back what it just wrote, and a host compromised next year
  gives up nothing about the backups it already shipped. One public key in one control file scales to thousands of
  cloud and edge servers with no unlockable key material on any of them.
- **A recovery key you can print.** The secret is roughly sixty characters of Crockford Base 32 on a card carrying
  the container UUID and the restore procedure. It is generated where you choose, never has to touch the machine being
  backed up, and belongs in a safe rather than a password manager.
- **Hardware key files and passphrases, as usual.** Random bytes on a device plugged in for the run, or a passphrase
  behind Argon2id. Authentication slots of an encrypted container are independent – any one of them opens it – 
  and because the key-slot tables sit outside everything the superblock authenticates, adding or replacing a key
  rewrites exactly 64 KiB rather than the whole container, on a 400 GB one as much as on a small one.
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
  single point of failure.
- **None of the above is claimed untested.** Every promise on this page is checked by something that fails when it
  stops being true – a single-bit sweep across a whole container, seven fuzz targets, and an
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
bond bench-kdf                                 # how hard can this machine hash a passphrase

bond keygen --recovery-card card.txt           # a printable key, and a public key for the config
bond keygen --keyfile usb.key                  # 32 bytes for a device you plug in
bond keys list  backup.bond                    # what can open this container
bond keys add   backup.bond --new-passphrase   # 64 KiB of writing, whatever the container's size
bond keys rotate-passphrase backup.bond
bond rekey backup.bond --out new.bond          # the only command that re-encrypts everything
```

`--dry-run` enumerates every source, applies the filters and reports what would go into each container without
writing anything. `--verbose` adds one line per decision naming the rule responsible, which is how a control file
gets tuned against a real tree.

A passphrase is asked for at the terminal. For unattended runs, `--passphrase-file <path>` is the recommended form;
`--passphrase-env <name>` and `--passphrase <text>` also work, the last with a warning, because a command line is
visible to every other process and lands in shell history.

`selftest` is the per-platform check. BOND is cross-compiled for five platforms from one of them, so most of what it
ships can never be run by whoever built it: this command unpacks the embedded 7-Zip, pushes a real archive through
compression and back, restores it and compares every digest. Run it once on each machine that matters.

### Keys

Four ways into a container, and any number of them at once. All wrap the same master key, so adding, removing or
rotating one writes **64 KiB** – the same work on a one-terabyte backup as on a one-megabyte one. Only `bond rekey`
re-encrypts anything, and it says so before it starts.

| | needs at backup time | needs at restore time |
|---|---|---|
| **passphrase** | typed, or `--passphrase-file` | the same passphrase |
| **key file** | the file | the file |
| **recovery card** | *nothing but a public key* | the printed key |
| **none** | nothing | nothing – no confidentiality, integrity only |

The recovery card is the interesting one. `bond keygen --recovery-card` writes a printable key and a public key; only
the public key goes in the control file, so a scheduled backup runs unattended and **the machine making the backup
cannot read it**. Print the card, put it in a safe, delete it from the machine. Restoring is
`bond restore backup.bond --to ./restored --recovery-key "BOND-R1-…"`; case and hyphens do not matter, and the letters
that get misread – I, L, O – are accepted and corrected.

### Volumes

`maxVolumeBytes` splits a container into numbered files, for object stores that cap a single upload. Each volume
carries its own header – twice, once at each end of the file – and its own checksum file, so any one of them finds the
rest and none of them is a single flipped bit away from being unreadable: `bond restore backup.bond.003` works as well
as starting from the first, and `bond verify --quick` checks every volume of the set.

### Recovery data

`recoveryPercent` (10 by default) adds Reed-Solomon parity so a container survives the corruption storage quietly
inflicts on it. `bond verify` locates the damage and says whether it can be rebuilt; `bond repair` rebuilds it into a
**new** file, leaving the damaged one untouched, and re-verifies the result before reporting success.

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

Every shard is authenticated as it is read, so nothing that failed its tag reaches the decompressor. Every archive
name is checked before a file is created: absolute paths, `..`, drive letters, Windows
device names and links pointing outside the destination abort the whole restore rather than being skipped. Each
restored file is then hashed and compared with the digest recorded when it was backed up, and `bond restore` reports
how many matched.

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

A JSON file – `config.json` beside the binary or in the working directory unless `--config` says otherwise – listing
targets and the settings that govern them. [config.sample.json](config.sample.json) is a worked
example, and [schema/bond-config.schema.json](schema/bond-config.schema.json) is a JSON Schema, so an editor can
validate it while you type. Unknown keys are a load error: a misspelled filter would otherwise silently widen a
backup.

Each source is a directory tree plus filters, all matched against the source-relative path with `/` separators
(case-insensitively on Windows):

| Filter | Meaning |
|---|---|
| `includedPaths` / `excludedPaths` | Literal paths. Naming a directory covers its whole subtree. |
| `includedPathPrefixes` / `excludedPathPrefixes` | String prefix, so `mandrel/conf` also covers `mandrel/config`. |
| `includedPathPatterns` / `excludedPathPatterns` | Go regular expressions. |
| `excludedFileNames` / `excludedDirectoryNames` | A name anywhere in the tree. |

An exclusion always wins. If any include list is non-empty the default flips to deny, which is how "this subtree,
except these bits" is written.

Files land in the archive under the longest common ancestor of the sources' parent directories, so
`D:\Apps\Notepad++` and `D:\Apps\7-Zip` become `Notepad++/…` and `7-Zip/…`. When sources span Windows drives or
UNC shares there is no common ancestor and each root becomes synthetic – `c_drive/…`, `d_drive/…`,
`unc_server_share/…`.

On Windows a source path must name its drive. `/data/tools` is rooted but not absolute there – it binds to whichever
drive happens to be current – so BOND refuses it rather than backing up something nobody asked for.

## How it is built

```
./build.sh          # fetch embedded binaries, vet, test, then cross-compile all five platforms
./dist/package.sh   # pack those five into the release archives, under dist/
```

Targets: `windows/amd64`, `windows/arm64`, `linux/amd64`, `linux/arm64`, `darwin/arm64`. The version they report
comes from [VERSION](VERSION).

The embedded binaries are **not** committed. `tools/fetch` downloads a release pinned in
[tools/manifest.json](tools/manifest.json). `go:embed` then builds each one into the binary for its platform.

[dist/package.sh](dist/package.sh) produces exactly what a release publishes, so a package can be inspected before
it is one. It asserts the layout of every archive it writes, and the archives are reproducible: the same commit
packs to the same bytes. It needs a Linux host – GNU tar, `zip` and coreutils – which is where releases are built.

It and [dist/readme.txt](dist/readme.txt), the plain-text readme that ships inside every package, are the two files
in `dist/` that are checked in; everything else there is built and ignored.

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs gofmt, `build.sh`, the end-to-end suite and `package.sh`
on every push and pull request, on Linux. [release.yml](.github/workflows/release.yml) does the same on a `v*` tag
and publishes the archives, refusing before it builds anything if the tag and [VERSION](VERSION) disagree.

## How it is tested

Two layers, and both run from a checkout.

`go test ./...` covers the packages and the format: a single-bit sweep that flips every byte of a container in turn
and requires each one to be caught, seven fuzz targets whose corpus runs on every invocation, the parity capacity
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
