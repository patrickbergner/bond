==============================================================================
 BOND - Backups on Non-Trusted Destinations
==============================================================================

Back up a configurable, filtered set of files into quantum-safe, encrypted
containers with high-grade LZMA2 compression (think of 7-Zip), hand it to
storage you have no reason to trust (think of cheap cloud storage), and get
every byte back years later. All in a single binary for Windows, macOS or
Linux.


CONTENTS OF THIS PACKAGE
------------------------------------------------------------------------------

  bond / bond.exe       the application; a single static binary
  config.sample.json    a worked control file, the template for your own
                        config.json
  readme.txt            this file
  LICENSE               BOND's own licence (MIT)
  LICENSE-7-Zip.txt     the terms of the 7-Zip build embedded in the binary


GETTING STARTED
------------------------------------------------------------------------------

1. Copy this "bond" folder somewhere permanent. Keep the files together: the
   binary looks for config.json next to itself.

2. Check that this machine can run it at all:

       bond selftest

3. Copy config.sample.json to config.json and edit it: name the directories
   worth backing up, and pick how the container is locked.

4. See what would be stored, without writing anything:

       bond backup --dry-run

   Add --verbose for one line per decision, naming the filter rule
   responsible. That is how a control file gets tuned against a real tree.

5. Write the containers:

       bond backup


COMMANDS
------------------------------------------------------------------------------

  bond selftest                       check the embedded 7-Zip works here
  bond backup --dry-run               what would be stored, writing nothing
  bond backup                         write the containers
  bond verify  backup.bond            authenticate every shard
  bond verify  backup.bond --quick    checksum only; needs no key
  bond repair  backup.bond            rebuild damaged shards from the
                                      recovery data
  bond list    backup.bond -l         what is inside, from the manifest
  bond inspect backup.bond            format and settings
  bond restore backup.bond --to ./restored
  bond bench-kdf                      what the passphrase hardening costs
                                      on this machine

  bond keygen --recovery-card card.txt    a printable key, and a public key
                                          for the control file
  bond keygen --keyfile usb.key           32 bytes for a device you plug in
  bond keygen --signing-key writer.key    signs what this machine writes
  bond keys list  backup.bond             what can open this container
  bond keys add   backup.bond --new-passphrase
  bond keys rotate-passphrase backup.bond
  bond rekey backup.bond --out new.bond   the only command that re-encrypts
                                          everything

A passphrase is asked for at the terminal. For unattended runs
--passphrase-file <path> is the recommended form; --passphrase-env <name> and
--passphrase <text> also work, the last with a warning, because a command
line is visible to every other process and lands in shell history.


KEYS
------------------------------------------------------------------------------

Four ways into a container, and any number of them at once:

  passphrase        typed, or --passphrase-file, at both ends
  key file          the file at both ends
  recovery card     nothing but a public key to back up; the printed key to
                    restore
  none              no confidentiality, integrity only; opens with
                    --allow-unencrypted and never without it

All of them wrap the same master key, so adding, removing or rotating one
writes 128 KiB - the same work on a one-terabyte backup as on a one-megabyte
one. Only "bond rekey" re-encrypts anything, and it says so before it starts.
A removed or rotated key stops opening the container at once, but still
opens a copy of the file made earlier; "bond rekey" is what changes that.

A public key can lock a backup and never open one, but it cannot vouch for
one either: anyone who has it can write a container the recovery card opens.
A writer key closes that: put "signingKey" in the control file, keep the .pub
file beside the card, and restore with --expect-writer writer.key.pub. A
container the writer did not sign is then refused. "bond verify --quick
--expect-writer writer.key.pub" checks a stored container with no key that
could open it.

The recovery card is the interesting one. "bond keygen --recovery-card"
writes a printable key and a public key; only the public key goes in the
control file, so a scheduled backup runs unattended and the machine making
the backup cannot read it. Restoring is

    bond restore backup.bond --to ./restored --recovery-key "BOND-R1-..."

Case and hyphens do not matter, and the letters that get misread - I, L, O -
are accepted and corrected.


THE CONTROL FILE
------------------------------------------------------------------------------

A JSON file, config.json beside the binary or in the working directory unless
--config says otherwise, listing targets and the settings that govern them.
config.sample.json in this folder is a worked example. It declares a $schema,
so an editor that honours it gives completion and validation while you type.

Unknown keys are a load error: a misspelled filter would otherwise silently
widen a backup.

Each source is a directory tree plus filters, all matched against the
source-relative path with "/" separators (case-insensitively on Windows):

  includedPaths / excludedPaths
        Literal paths. Naming a directory covers its whole subtree.
  includedPathPrefixes / excludedPathPrefixes
        String prefix, so "mandrel/conf" also covers "mandrel/config".
  includedPathPatterns / excludedPathPatterns
        Go regular expressions.
  excludedFileNames / excludedDirectoryNames
        A name anywhere in the tree.

An exclusion always wins. If any include list is non-empty the default flips
to deny, which is how "this subtree, except these bits" is written.

Two settings are worth deciding deliberately:

  compressionLevel   Set it to 0 for photos, video and music. They are
                     already compressed, LZMA2 will find nothing, and it is
                     ten times faster. Keep the default of 5 for documents,
                     mail and source code, where it earns its time.
                     The maximum level is 9.
  recoveryPercent    See below. 10 by default; 20 or 30 for backups that
                     matter more.


RECOVERY DATA AND VOLUMES
------------------------------------------------------------------------------

recoveryPercent adds Reed-Solomon parity so a container survives the
corruption storage quietly inflicts on it. "bond verify" locates the damage
and says whether it can be rebuilt; "bond repair" rebuilds it into a NEW
file, leaving the damaged one untouched, and verifies the result in full
before giving it its name.

"bond restore" uses the recovery data too: a shard that fails while being
read is rebuilt in memory, and the summary says the container is damaged.
"bond verify" exits non-zero for anything short of full health, including a
container that opened on its last copy of a header, a key-slot table or the
manifest; "bond repair" puts that copy back.

The capacity is per stripe, not per container. At 10% a stripe is 20 data
shards protected by 2 parity shards, so any two losses out of twenty are
recoverable - and a container of a thousand shards survives a hundred losses
if they fall two per stripe, but not three in one.

Parity repairs corruption, not deletion. Nothing inside a single file
protects against that file being removed, so keep two copies.

maxVolumeBytes splits a container into numbered files, for object stores that
cap a single upload. Each volume carries its own header - twice, once at each
end of the file - and its own checksum file, so any one of them finds the
rest: "bond restore backup.bond.003" works as well as starting from the
first, and "bond verify --quick" checks every volume of the set. Shards are
cut to fit, so no volume is larger than maxVolumeBytes.


THE RESTORE DRILL
------------------------------------------------------------------------------

A backup nobody has ever restored is a hypothesis. Twice a year, on the copy
that actually lives in the cloud:

    bond verify  backup.bond --quick     1. it arrived intact - no key needed
    bond verify  backup.bond             2. every shard authenticates
    bond list    backup.bond -l          3. it holds what you think it holds
    bond restore backup.bond --to ./drill    4. it comes back

Step 4 is the one people skip and the only one that proves anything. Do it
from the printed recovery card, typed in by hand, not from the passphrase in
your password manager - that is the path you will be on when it matters, and
the only way to find out the card is wrong is to use it. Restore into a
scratch directory, compare a few files, delete it.

The destination directory should be empty: a file that is already there stops
the restore unless --overwrite is given, because an occupied destination
usually means the wrong one was named.


MORE
------------------------------------------------------------------------------

The full README, the format specification (NERDME.md, which documents the
container to the byte and walks through decrypting one by hand) and the
source:

    https://github.com/patrickbergner/bond


LICENSE
------------------------------------------------------------------------------

BOND is MIT licensed. See the LICENSE file in this folder.

The binary embeds a build of 7-Zip, which is licensed separately; its terms
are in LICENSE-7-Zip.txt in this folder.
