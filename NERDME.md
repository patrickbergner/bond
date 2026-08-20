# NERDME – how BOND actually works

The authoritative description of the BOND container format, version 1.0. [README.md](README.md) is the operator's
guide; this is everything underneath it.

**Status:** v1 is complete. Everything below is implemented, and every number in it was measured rather than
estimated – the corruption figures in [§9](#9-what-survives-what-does-not) come out of the test suite and the timings
in [§12](#12-where-the-time-goes) out of a real run, both reproducible with the commands given.

---

## 1. The pipeline

One pass each way, nothing buffered to disk. A backup of a terabyte needs a terabyte of destination and nothing else.

```
  files on disk
        │  enumerate + filter          internal/source
        ▼
  tar stream                           internal/archive   ── per-file SHA-256 ──┐
        │  (Go, in process)                                                     │
        ▼                                                                       │
  7zz a -txz -si -so                   internal/sevenzip                        │
        │  xz / LZMA2                                                           │
        ▼                                                                       │
  compressed stream                    ── SHA-256 of the whole stream ──┐       │
        │  split into shardSize-16 chunks                               │       │
        ▼                                                               ▼       ▼
  XChaCha20-Poly1305 per shard         internal/crypto            manifest (sealed)
        │                                                                 │
        ▼                                                                 ▼
  ┌───────────────────────────── container file ──────────────────────────────┐
  │ superblock │ slots A │ slots B │ shard 0 … shard N-1 │ tail ×2 │ mirror   │
  └───────────────────────────────────────────────────────────────────────────┘
```

Restore is the same picture backwards, with one rule added: a shard that fails its authentication tag stops the read.
Nothing that failed authentication is ever handed to the decompressor.

### Why tar‖xz and not .7z

A `.7z` file cannot be written to a pipe. Its signature header at offset 0 contains `NextHeaderOffset`,
`NextHeaderSize` and `NextHeaderCRC`, which are only known once the archive is complete – so the writer must seek back
to byte 0. 7-Zip's own `-so` switch reflects this and supports only bzip2, gzip, tar and xz with the `a` command.

Piping a tar through `7zz a -txz -si -so` uses the same LZMA2 codec at the same `-mx` levels, is inherently solid, and
behaves identically on all five platforms. Building the tar in Go rather than letting an archiver do it also means
entry names are exactly what [§7](#7-the-archive-namespace) decides, extraction is ordinary Go code whose rules are
tested here, and the per-file digests fall out of the same pass.

**One trap worth recording.** On an *extract* command with `-si`, a positional archive name is read as a filter
selecting files *inside* the archive. `7zz e bond.xz -txz -si -so` therefore matches nothing, writes zero bytes, and
exits 0 – a restore that reports success and produces an empty tree. The writer requires an archive name; the reader
must not have one. See `internal/sevenzip/xz.go`.

---

## 2. Container layout

Every offset below is exact and constant. `internal/format.PayloadOffset` is 135168 in every container ever written.

| Offset | Size | Region |
|---:|---:|---|
| 0 | 4096 | Superblock |
| 4096 | 65536 | Key-slot table A |
| 69632 | 65536 | Key-slot table B |
| 135168 | see [§6](#6-payload-shards-and-recovery-data) | Payload: data shards, with each stripe's parity following its own data |
| *tailOffset* | *tailLength* | Sealed manifest, copy 1 |
| *tailOffset + tailLength* | *tailLength* | Sealed manifest, copy 2 |
| *end − 4096* | 4096 | Superblock mirror |

That is one file. A split container puts the slot tables and the manifest where the table says – in the first volume
and the last – but **the mirrored superblock closes every volume**, so no single file of a set is one flipped bit from
being unreadable. See [§6a](#6a-volumes).

The fixed 132 KiB head is the price of [§5](#5-changing-a-key-never-touches-the-payload): because the slot tables never
move and never change size, adding a key rewrites 64 KiB of a terabyte file.

The manifest is stored twice because it is the one region with no parity of its own. A payload nobody can interpret is
not a backup, and two copies cost a few hundred kilobytes.

**Everything outside the payload is stored twice, and both copies are populated from the first byte written.** Every
volume's header has its mirror, the manifest has its second copy, and the two slot tables start life identical rather
than the spare being left blank until someone happens to rotate a key. The consequence is measured in
[§9](#9-what-survives-what-does-not): outside the payload, a single flipped bit costs nothing at all.

A copy that is damaged is *reported* even when it was not the one needed. That is not fussiness: a container whose
spare copy is the rotten one opens on its first choice and looks perfectly healthy while being one flip from
unopenable, and `bond repair` decides there is redundancy to restore by asking whether anything was reported. A region
that stays quiet is a region that never gets healed.

---

## 3. Superblock

4096 bytes, little-endian, at offset 0 and mirrored at the end of the file.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Magic `42 4F 4E 44 00 0D 1A 0A` – `BOND\0\r\x1a\n` |
| 8 | 2 | Major version (1) |
| 10 | 2 | Minor version (0) |
| 12 | 4 | Header size (4096) |
| 16 | 8 | Flags – bit 0: the master key is stored in this container |
| 24 | 4 | Cipher id (1 = XChaCha20-Poly1305) |
| 28 | 4 | KDF id (1 = Argon2id) |
| 32 | 4 | Parity scheme (0 = none, 1 = Reed-Solomon) |
| 36 | 4 | Shard size in bytes |
| 40 | 4 | Data shards per stripe (k) |
| 44 | 4 | Parity shards per stripe (p) |
| 48 | 8 | Data shard count |
| 56 | 8 | Compressed stream length, exact |
| 64 | 8 | Creation time, Unix nanoseconds |
| 72 | 16 | Container UUID, random |
| 88 | 16 | Payload nonce prefix, random |
| 104 | 8 | Tail metadata offset |
| 112 | 8 | Tail metadata length, one copy |
| 120 | 32 | SHA-256 of one tail copy |
| 152 | 4 | Volume index |
| 156 | 4 | Volume count |
| 160 | 8 | Where this volume's payload slice starts in the payload as a whole |
| 168 | 8 | How much payload this volume holds |
| 176 | 32 | Key commitment |
| 208 | 32 | Header MAC |
| 240 | 4 | On-disk size of the final shard |
| 244 | 3852 | Reserved, zero |

The **header MAC** is `HMAC-SHA256(headerKey, superblock with bytes 208–239 zeroed)` and covers all 4096 bytes,
reserved area included, so nothing can be smuggled into the padding.

**It is taken over the bytes as they were read**, not over a re-rendering of the fields the reader understood. The
difference is the whole of what that sentence promises. Marshalling a parsed header back out writes zeros across the
reserved region, so a MAC computed that way never looks at what is really stored there – which left 3852 bytes per
header copy that anyone could write to, on a container that would then pass `bond verify` reporting no damage at all.
Reading the MAC over the raw bytes also means a later minor version can put a field in that region and an older build
still authenticates the header; it simply does not know what the field means.

The honest limit: this stops anyone *without* the header key. A key holder can put whatever they like in the padding
and sign it, and no reader can tell.

The magic's `\r\x1a\n` tail is the trick PNG uses: it catches a transfer that translated line endings and stops the
file being dumped to a terminal.

### Reading order, and why it is that order

The MAC needs `headerKey`, which needs the master key, which comes from a key slot. So a reader necessarily parses an
**unauthenticated** header first. Everything in `Unmarshal` therefore treats the bytes as attacker-controlled: it
bounds-checks shard size, shard count, stream length, the final shard's size and the tail offset, and refuses anything
that could steer a later read or a large allocation. Only after `Unlock` succeeds – key, then MAC, then commitment,
then manifest, then a cross-check that the manifest and header agree – is any offset acted on.

**Which copy is used is decided at unlock, not at open.** This is worth spelling out, because the obvious design is
wrong. Choosing the front header when it parses and falling back to the mirror only when it does not looks reasonable,
but "parses" and "is authentic" are different questions: most single-bit edits leave a header perfectly parseable and
merely unauthentic, and a reader that has already committed to it has nowhere to go when the MAC fails. It refuses a
container whose intact mirror is sitting 4 KiB from the end of the same file.

So the whole unlock sequence – slot, master key, header MAC, commitment, manifest, cross-check – is attempted against
each header copy and each slot table in turn. Four attempts at worst, and more than one only when something is damaged.
Two details force this ordering rather than a fallback at the point of failure:

- A flip in the **container UUID** or the **nonce prefix** derails the key derivation itself. The slot unwrap fails
  first, and it fails looking exactly like a wrong passphrase.
- A flip in the **volume count** sends a reader hunting for `backup.bond.002` and `.003` that were never written, so
  it fails at open, before any key exists.

When a spare copy carries the day the reader records it, and `bond verify`, `bond inspect` and `bond repair` print it.
The container opened, but it did so on its last copy of something, and the next flip is the one that loses it –
`bond repair` writes the redundancy back.

---

## 4. Key model

```
        passphrase ──── Argon2id(salt, m, t, p) ──┐
        key file ────── HKDF(salt) ───────────────┤
        recovery key ── X25519 + ML-KEM-1024 ─────┤
        (nothing) ───── all-zero key ─────────────┤   key-encryption key
                                                  │           │
                                                  │  XChaCha20-Poly1305
                                                  │           │
                                                  ▼           ▼
                                            key slot   ⟶  File Master Key (32 random bytes)
                                                                  │
                                       HKDF-SHA512(FMK, salt = container UUID, info)
                                                                  │
                    ┌──────────────┬──────────────┬───────────────┴──────────┐
                    ▼              ▼              ▼                          ▼
              "bond/v1/data"  "bond/v1/header"  "bond/v1/manifest"   "bond/v1/commit"
                dataKey        headerKey         manifestKey           commitKey
```

The **File Master Key** is 32 bytes from `crypto/rand` and is never derived from a passphrase. That is what makes key
changes cheap: every slot wraps the same FMK, so a new passphrase re-wraps 32 bytes rather than re-encrypting a
terabyte.

The **container UUID is the HKDF salt**, so two containers never share a subkey even if they somehow shared a master
key.

The **key commitment** is `HMAC-SHA256(commitKey, "BOND-COMMIT-V1" ‖ containerUUID)`, stored in the header. AEAD tags
prove a ciphertext was made with the key that opens it, but not *which* key that was; without a commitment a container
could in principle be crafted to open differently under two different secrets. The commitment is checked before
anything else is trusted.

**`encryptionMethod: NONE`** is not a separate code path. BOND still generates an FMK, still seals every shard, and
stores the FMK wrapped under an all-zero key-encryption key in a `plaintext` slot. The container is authenticated end
to end; anyone holding it can read it. `bond inspect` says so in those words.

### Key-slot table

Two tables at fixed offsets, 64 KiB each. A fresh container writes the same slots into both at generation 1; after
that they alternate, and the higher generation is the current one.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Magic `BSLT` |
| 4 | 2 | Version (1) |
| 6 | 2 | Slot count (max 32) |
| 8 | 8 | Generation |
| 16 | 4 | Bytes of records in use |
| 32 | 32 | Table MAC – `HMAC-SHA256(headerKey, table with this field zeroed)` |
| 64 | … | Slot records, packed |

Each record:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Record size |
| 4 | 2 | Record version (1) |
| 6 | 1 | Slot type: 1 passphrase, 2 key file, 3 plaintext, 4 recipient |
| 8 | 16 | Slot UUID |
| 24 | 24 | Wrapping nonce |
| 48 | 16 | Salt |
| 64 | 12 | Argon2id memory (KiB), passes, lanes |
| 76 | 4 | Wrapped length (48) |
| 80 | 48 | The sealed master key |
| 128 | 2 + n | Label length and UTF-8 label |
| … | 4 + m | Key-exchange length and bytes – recipient slots only, otherwise 0 |

The slot's associated data is `"BOND-SLOT-V1" ‖ containerUUID ‖ slotUUID ‖ slotType ‖ salt ‖ kdfParams`, with the key
exchange in place of the KDF parameters for a recipient slot. Binding the cost parameters matters: without it, an
attacker could lower the recorded memory and pass count to make guessing cheaper, and the tag would not notice.

### Recipient slots and the printed recovery key

A recipient slot is the one way into a container that needs no secret at backup time. Only the public key sits on the
machine making the backup, so a scheduled job can run unattended and that machine still cannot read what it wrote –
and a machine compromised later gives up nothing about the backups already in the cloud.

The exchange is hybrid, and both halves matter:

```
ephemeral X25519 ─── ECDH ──→ shared secret 1 ─┐
recipient ML-KEM-1024 ─ encapsulate → secret 2 ─┴─ HKDF(… ‖ ephemeral pub ‖ ciphertext ‖ recipient pub) → KEK
```

X25519 protects the container against everything known today; ML-KEM-1024 protects it against a quantum computer that
does not exist yet but that a backup written now may well outlive. Combining both means the result is no weaker than
the stronger of the two, whichever that turns out to be. The whole transcript – ephemeral key, ciphertext and the
recipient's own public key – goes into the derivation, so an attacker who rewrites the slot cannot steer the result.
The stored key exchange is about 1.6 KiB, which is why slot records carry a variable tail.

**The printed recovery key is the private half, and it is 32 bytes.** An ML-KEM-1024 private key is over 3 KiB and its
own seed is 64 bytes, but both halves of a hybrid recipient can be regrown from one 32-byte seed by HKDF – which is
about sixty characters on paper instead of five thousand:

```
BOND-R1-JJMCG-N80K4-YYQ9M-8WCQ6-FYTW8-9MDKS-2T7G5-7YQ4G-KBPDS-PWF57-HXWM0
```

The encoding is built for someone typing it back years later, from paper, possibly not the person who wrote it.
Crockford's base32 alphabet omits I, L, O and U; the decoder accepts those anyway and maps them to 1, 1 and 0; case
and hyphens are ignored wherever they fall; and a two-byte checksum catches what is left, so a mistyped key says so
instead of quietly failing to open the backup.

---

## 5. Changing a key never touches the payload

This is a design requirement, so the format is built for it rather than relying on care.

The superblock **does not authenticate the slot tables**. If it did, adding a key would mean rewriting the superblock –
and in a split container, the superblock in every volume. Instead each table carries its own MAC and its own
generation counter, and the two tables alternate:

1. Unlock the master key with an existing slot.
2. Build the new slot set and write it into the **inactive** table with `generation + 1`.
3. fsync.

A crash between steps leaves the previous table untouched and still the highest valid generation, so the operation is
atomic without a journal. Readers try the newest table that parses and fall back to the other if it fails to
authenticate. Total I/O for a key change on a terabyte container: 64 KiB.

That fallback is availability, not a weakening of `bond keys remove`. Rolling a container back to an older slot set is
already open to anyone who can write to the file – destroy the newer table's magic and the older one is picked, and it
is genuinely authentic, because it was. What the fallback removes is the case where the same one-byte edit denies
access to *everyone* instead. A removed key that must stay removed is removed with `bond rekey`, which changes the
master key itself and leaves nothing for an old slot to unwrap.

Rotating the *master key* is genuinely a full rewrite, and gets its own command – `bond rekey` – that says so before
it starts. The distinction is worth insisting on: a passphrase that may have been seen is answered by
`bond keys rotate-passphrase` in milliseconds, and rekeying is for when the master key itself may be exposed, which in
practice means a restore happened on a machine that is no longer trusted.

`bond keys add|remove|rotate-passphrase` check the claim rather than making it: the payload region is hashed before
and after, and a mismatch is reported as a bug rather than shrugged off.

---

## 6. Payload shards and recovery data

Every data shard but the last is exactly `shardSize` bytes on disk: `shardSize - 16` bytes of compressed stream, plus
a 16-byte Poly1305 tag.

- **Nonce**: `noncePrefix ‖ LE64(shardIndex)` – 16 random bytes per container, then the index. Derived rather than
  stored: an index is unique within a container by construction, so the same nonce cannot occur twice under one key.
- **Associated data**: `"BOND-DATA-V1" ‖ containerUUID ‖ LE64(shardIndex) ‖ LE32(shardSize)`. Without the index a
  shard could be moved or repeated within the container and still authenticate; without the UUID a shard from another
  container under the same key would too. A tag alone notices neither.
- **The last shard is short.** It is sealed at whatever length it reached. Padding it would waste up to a full shard
  on every container – for a 444 KiB backup that was the difference between 4.13 MiB and 432 KiB – and buys nothing,
  because parity pads in memory when it computes the final stripe. Its on-disk size is recorded at offset 240.

### Stripes

Data shards are grouped into stripes of `k`, each followed immediately by its own `p` parity shards:

```
| d0 d1 … d19 | P0 P1 | d20 d21 … d39 | P0 P1 | d40 d41 d42 | P0 P1 |
└──── stripe 0 ──────┘└──── stripe 1 ───────┘└─ stripe 2 (short) ──┘
```

Interleaving rather than collecting all parity at the end is what keeps the container writable in one streaming pass:
parity is emitted the moment its stripe completes, so a 400 GB backup never has to buffer 40 GB of recovery data
anywhere. It also puts the recovery data next to the bytes it recovers.

**Geometry.** `recoveryPercent` chooses `k` and `p`: two parity shards is the floor for anything meaningful, so the
percentage is met by choosing how many data shards they cover. Below eight data shards per stripe the trade stops
being worthwhile, so past that point the parity count rises instead.

| recoveryPercent | k + p | real overhead |
|---:|---|---:|
| 5 | 40 + 2 | 5.0% |
| 10 | 20 + 2 | 10.0% |
| 20 | 10 + 2 | 20.0% |
| 30 | 10 + 3 | 30.0% |
| 50 | 8 + 4 | 50.0% |

A percentage too small for a 128-shard stripe to express is rounded **up**, never down.

**Shard sizing.** `shardBytes` is a maximum, not a fixed choice. A stripe cannot be narrower than one shard, so a
payload smaller than `k` shards could never reach the requested percentage: a 3 MiB backup in 4 MiB shards is one data
shard and one parity shard – 100% overhead for a container that asked for 10%. When parity is enabled, BOND therefore
walks the sources for their size first (metadata only, no reads) and shrinks the shards to fit, down to a 64 KiB
floor. With no parity there is no stripe to fill and the configured size stands.

That walk measures the tree, and the shards hold the *compressed* stream, so on compressible data the stripes fill less
than the estimate expected and the real overhead lands somewhat above the percentage asked for. The error is in the
safe direction – more recovery data than requested, never less – but it is an estimate, not a guarantee.

**Parity shards are sealed too.** Each is `shardLen + 16` bytes: Reed-Solomon output over the stripe's *ciphertext*
shards, then encrypted like everything else, with nonce index `1<<63 | stripe<<8 | q` so parity numbering can never
collide with data numbering under the same key. The p7e sketch stored parity raw and kept a table of digests for it;
sealing removes that table, its failure mode, and the question of what to do when the table itself rots.

**A short final stripe** codes at full width – the missing shards are implied zeros, known to both sides – and never
gets more parity shards than it has data shards. That is what stops a container far smaller than one stripe from being
mostly recovery data.

### Repair

`bond repair` reads the damaged container, rebuilds what is missing, and writes a **new** file. It never touches the
original: a repair works from a container that is by definition already suspect, and an in-place rebuild that failed
halfway would turn recoverable damage into a total loss.

The order is what makes the result trustworthy:

1. Authenticate every data and parity shard, recording which fail.
2. Decide per **stripe** whether the losses fit within that stripe's parity. The capacity is per stripe, not per
   container – ten losses spread across ten stripes are repairable; three in one stripe protected by two are not.
3. Reconstruct on the stored ciphertext, because that is what parity covers.
4. **Authenticate every rebuilt shard before writing it.** Reed-Solomon will happily produce bytes from bad input;
   only the tag knows whether they are the bytes that were lost.
5. Re-open and fully verify the repaired copy before reporting success.

Reed-Solomon reconstructs; AEAD decides whether the reconstruction is right. Never the other way around.

**Damage outside the payload is repaired too.** A repair starts from a byte-for-byte copy, so a header the reader had
to take from the mirror – or a slot table it had to take from the spare – would otherwise be reproduced faithfully in
the "repaired" file, leaving it one flip from being lost. Whichever copies authenticated are written back over both
positions. Nothing is invented: the header carries its own MAC and the slot table is re-signed under the same header
key, so this restores redundancy the container already proved it owns. It is also the one repair that works without
any recovery data at all, since it needs no parity to reconstruct anything.

---

## 6a. Volumes

A container may be split across numbered files – `backup.bond.001`, `.002`, … – because an object store happy with a
hundred 5 GB files may refuse one 500 GB file. `maxVolumeBytes` turns it on.

The split is purely physical. The payload is one logical byte range whatever it is stored in, and each volume records
which slice of it that volume holds:

```
backup.bond.001   superblock │ slots A │ slots B │ payload[0 … a) │ mirrored superblock
backup.bond.002   superblock │ payload[a … b) │ mirrored superblock
backup.bond.003   superblock │ payload[b … c) │ manifest ×2 │ mirrored superblock
```

**A volume boundary never falls inside a shard.** That costs a little unused space at the end of each file and buys a
reader that never has to stitch a shard together across two of them.

**Every volume carries two copies of its header**, so any one file identifies the set it belongs to and how many there
are. `bond restore backup.bond.003` finds the rest – which matters, because the file to hand during a recovery is
rarely the first one.

The mirror used to close only the last volume, and that was a hole worth naming. Every entry point re-reads volume 1 to
learn the shape of the set, so a single flipped bit in volume 1's header made the whole container unopenable from any
of its files, with no second opinion anywhere to fall back on. Four kilobytes per file buys back the rule the rest of
the format keeps.

Writing the spare is only half of it. The checks that run *before* a key exists – that each file is the volume it
claims to be, and that the volumes describe one unbroken payload – used to be decided against whichever copy happened
to parse first. A mirror is no use if the reader has already refused the container on the strength of the damaged copy,
so those checks now accept any copy that agrees, and the contiguity check is deferred to after unlock whenever a second
copy still exists. It runs again there, on numbers a key has vouched for.

A container written before every volume carried a mirror is read exactly as it was. The reader tells the two apart by
whether there is room between the end of a volume's payload and the end of the file, rather than by a version number –
which is also what stops `bond repair` writing a mirrored header over the last shard of a middle volume that never had
room for one.

Three things are checked before a split container is trusted, in increasing order of strength: the volumes must be
numbered as they claim; they must all carry the same container UUID, since two containers of the same shape otherwise
have interchangeable-looking files; and once a key is available, **every volume's header MAC is verified**, not only
the first. Without that last check a foreign volume passes as one of the set and is only caught later, shard by shard.

`maxVolumeBytes` bounds the payload in a volume, with a 4 MiB allowance held back for the mirrored header each volume
carries and the manifest the last one adds. A file index of a million files can exceed that allowance, in which case
the last volume is a little larger than asked for – better than refusing to finish a backup over it.

**The tail offset is a position inside the last volume**, not in the container as a whole, and every volume's header
records the same value. A reader that insisted it point past the whole 132 KiB head – which only volume 1 has – refused
every header copy of every volume in a set whose last file held less than 128 KiB of payload. That is an ordinary
shape: it is what a short final shard landing alone in its own volume looks like. The container was written, reported
as written, and could then be opened by nothing.

---

## 7. The archive namespace

Entry names are computed by BOND, per target:

1. Take the parent directory of every source and compute their longest common ancestor. Entries are stored relative
   to it: `D:\Apps\Notepad++` and `D:\Apps\7-Zip` become `Notepad++/…` and `7-Zip/…`, and a lone `D:\Photos` becomes
   `Photos/…` rather than losing its name.
2. On Windows, sources spanning drives or UNC shares have no common ancestor, so each root becomes synthetic:
   `c_drive/…`, `d_drive/…`, `unc_server_share/…`.
3. On POSIX an ancestor always exists (`/` at worst).

Two sources that would collide, or one nested inside another, are refused before anything is written. BOND does not
record where a source lived on disk anywhere in the container – only the archive-relative names above, which is all a
restore into a directory of your choosing needs.

A POSIX-style path on Windows – `/data/tools` – names no volume and binds to whatever drive happens to be current.
BOND refuses it. Backing up `C:\data` because a control file said `/data` is exactly the quiet wrong answer a backup
tool must not give.

### Extraction policy

A restore reads names written somewhere else, possibly years ago, possibly by someone who wanted them to land outside
the destination. `internal/archive/safepath.go` refuses, before a single byte is written: empty names, NUL bytes,
absolute paths, UNC paths, drive letters, `.` and `..` components, and – on Windows only – backslashes, `:*?"<>|`,
names ending in a space or dot, and the reserved device names (`CON`, `NUL`, `COM1`…). Entry types BOND's own writer
never produces – hard links, devices, fifos – are refused as well: meeting one means the stream is not what it claims
to be.

The name is judged **before** the include filter is consulted, so "it would have been skipped anyway" is never the
reason a hostile archive is accepted. An offending entry **aborts the whole restore** rather than being skipped. An
archive containing a path that tries to escape is not a backup with one bad entry; it is a backup that cannot be
trusted.

**Symlink targets are checked lexically** against the destination, never resolved through the filesystem – an attacker
who chooses both a link and its target can otherwise walk a restore out of its directory one component at a time, and
what resolution finds depends on whatever happens to exist at restore time. Symlinks are off by default.

The lexical check normalises backslashes to separators *before* deciding anything, on every platform, and that ordering
is the whole point. `FuzzCheckLink` found the version that did it the other way round: a target of `\..` is not caught
by the absolute-path test, because on Windows a *single* leading backslash is rooted at the current drive rather than
being a UNC prefix – and converting it afterwards produced `/..`, which `path.Join` then cleaned to `/`, quietly
absorbing the very component that made it an escape. The rule is applied on POSIX too. A container travels, and a
target that escapes on one system is not something to restore faithfully on another.

---

## 8. Manifest

gzip(JSON), sealed with `manifestKey` and framed as `[LE64 length][24-byte nonce][ciphertext]`, written twice.
Associated data is `"BOND-MANIFEST-V1" ‖ containerUUID`.

It holds the compression settings, the exact stream length and its SHA-256, the shard geometry, and the **file
index**: path, kind, size, mode, mtime and SHA-256 for every entry.

The p7e sketch deliberately kept names out of the manifest. That reasoning does not survive contact with the key
model: the manifest is sealed with a key derived from the same master key as the payload, so a name in the manifest is
exactly as protected as a name inside the archive. Keeping it means `bond list` answers from a few hundred kilobytes
instead of decompressing half a terabyte, and `bond restore` can check every restored file against the digest recorded
when it was read. `storeFileIndex: false` turns it off.

JSON and gzip rather than CBOR: no dependency, and a debuggable format for the one structure a future recovery effort
would most want to read by hand.

---

## 9. What survives, what does not

Everything here is a number the test suite produces, not a claim about the design. Run `go test ./internal/container/
-run BitFlip -v` and the table below is what prints.

### The bit-flip sweep

`TestSingleBitFlipIsNeverSilent` takes a real container, flips one bit at a time across 631 offsets chosen to cover
every named header field densely and every other region by a fixed count, and reads the whole thing back. Each attempt
lands in one of three outcomes: **refused**, **absorbed** (it opened and returned exactly the right bytes), or
**silent** – it opened and returned something else. A silent result is a bug, and there is no acceptable number of them
but zero.

| Region | Flips | Refused | Absorbed | Silent |
|---|---:|---:|---:|---:|
| Superblock | 286 | 0 | 286 | 0 |
| Key-slot table A | 143 | 0 | 143 | 0 |
| Key-slot table B | 16 | 0 | 16 | 0 |
| Payload | 80 | 80 | 0 | 0 |
| Manifest, copy 1 | 21 | 0 | 21 | 0 |
| Manifest, copy 2 | 21 | 0 | 21 | 0 |
| Superblock mirror | 64 | 0 | 64 | 0 |
| **Total** | **631** | **80** | **551** | **0** |

Each region is walked by a fixed count rather than by a stride running to a variable end, so those numbers are the same
on every run. They did not use to be: the sealed manifest changes length by a byte or two from one container to the
next, because the creation time it carries renders shorter whenever its nanoseconds happen to end in a zero, and that
was enough to move the totals. A table transcribed from one run of a test that reports something slightly different on
the next is not a measurement.

Read the table as one sentence: **outside the payload, a single flipped bit costs nothing.** Every region there is
stored twice, and the reader will try both. Inside the payload nothing is stored twice, so every flip is caught – and
caught is the right outcome, because that is the damage `recoveryPercent` exists to rebuild. This sweep runs with
parity off deliberately; what parity then recovers is [§6](#6-payload-shards-and-recovery-data)'s business and has its
own tests.

The same file also proves two things a sweep cannot: every truncation of a container is refused (no prefix of a
container ever reads as a whole one), and two shards swapped within the payload are refused even though both are
individually authentic – which is what the shard index in the associated data is for.

### The corruption matrix

Named cases, each its own test:

| Damage | Result |
|---|---|
| One bit in a data shard | Located to the shard; repaired if parity covers the stripe |
| A whole shard zeroed | Same |
| `p` shards lost in one stripe | Repaired |
| `p+1` shards lost in one stripe | Refused, and says which stripes – never guessed at |
| A damaged parity shard | Reported, and repaired from the data |
| A ciphertext edit parity considers healthy | Caught by the AEAD tag |
| A rebuilt shard that does not authenticate | Repair fails rather than writing it |
| A shard that rots between `verify` and `repair` | Refused, naming the shard, rather than coded into the rebuild |
| One superblock copy | Opens from the other; `repair` writes both back |
| A superblock copy that will not even parse | Same – and it is reported, so `repair` restores it |
| Bytes written into the header's reserved padding | Fails that copy's MAC; opens from the other, and `repair` scrubs it |
| Both superblock copies | Refused, loudly |
| One key-slot table | Opens from the other; `repair` writes both back |
| Both key-slot tables | Refused |
| One manifest copy | Opens from the other |
| One volume's header, in a split set | Opens from that volume's mirror; `repair` writes both back |
| A truncated volume | Refused |
| A volume from a different container | Refused at open, on the container UUID |
| A volume with a forged header | Refused at unlock; every volume's MAC is checked |
| Wrong passphrase or key file | Refused before any payload is read |

### Fuzzing

Seven targets, run as ordinary tests over their seed corpus on every `go test` and extended with `-fuzz`:

| Target | What it asserts |
|---|---|
| `FuzzUnmarshal` | A header that parses has offsets that do not overlap or overflow, and describes a payload of a possible size |
| `FuzzParseSlotTable` | A table that parses has slots of the declared sizes |
| `FuzzOpenManifest` | The unauthenticated length field cannot become an absurd allocation |
| `FuzzSafeJoin` | If a name is accepted, the path is clean and inside the destination |
| `FuzzCheckLink` | If a link is accepted, following it stays inside the destination |
| `FuzzDecodeRecoveryKey` | An accepted key is exactly 32 bytes |
| `FuzzRecoveryKeySurvivesRetyping` | Any case, hyphenation or confusable substitution decodes to the same seed |

About 64 million executions so far, one real bug: the symlink normalisation ordering in
[§7](#extraction-policy). Its failing input is committed under `internal/archive/testdata/fuzz/` and runs as a
regression case forever.

The header and slot-table targets patch a *valid* structure at a fuzzer-chosen offset rather than taking raw bytes.
Random bytes essentially never survive a magic number, so a blind target spends its whole budget on the first four
lines of the parser and never reaches the arithmetic, which is the only place anything interesting can go wrong.

### Memory

The streaming pipeline's promise is that a backup of a terabyte needs a terabyte of destination and nothing else, so
`TestMemoryDoesNotGrowWithThePayload` measures it: the same tree at 16 MiB and at 64 MiB, same geometry, peak Go heap
sampled throughout.

| Payload | Peak heap, backup | Peak heap, restore |
|---:|---:|---:|
| 16 MiB | 11.7 MiB | 3.7 MiB |
| 64 MiB | 11.9 MiB | 3.9 MiB |

Four times the data, two percent more memory. The working set is one stripe – `(k+p) × shardSize`, which is 88 MiB at
the defaults and 5.5 MiB in that test – plus the file index, which is the one thing that does grow with the backup: a
measured **40 bytes per file** in the finished container. A million files is 40 MB; `storeFileIndex: false` turns it
off. 7-Zip's own memory is separate and is a function of the compression level, not of how much is fed through it.

### Long paths

Windows' 260-character limit is where backup tools quietly lose files. BOND has a structural advantage worth naming:
**7-Zip is fed the archive through a pipe and is never handed a path at all**, so the limit only ever applies to Go's
own file access – and Go prefixes absolute paths with `\\?\` before calling the API. Tested both ways on Windows: a
352-character source path and a 611-character one round-trip byte-identically, as does a 200-character file name.

---

## 10. Threat model

**Protects against**

- A cloud operator reading the backup. Everything but the header geometry is sealed.
- Bit rot and range corruption: every shard is authenticated, and damage is located to the shard.
- A container altered in transit: the header MAC, the slot table MAC, the per-shard tags, the manifest tag and the
  key commitment all have to agree.
- A shard moved, duplicated or transplanted from another container.
- A wrong passphrase: rejected before any payload is touched.
- A half-written backup: the container is built in the working directory and renamed into place only when complete.

**Does not protect against**

- A weak passphrase. Argon2id raises the cost per guess; it cannot fix a guessable secret.
- Losing every key. That is the design.
- Malware on the machine while the backup runs, or while the passphrase is typed.
- Deletion of the object in the cloud. Parity repairs corruption, not absence; keep two copies.
- Traffic analysis of size and timing. The container's size is not hidden.
- Damage beyond the recovery capacity of a stripe. Parity repairs corruption, not deletion, and not more losses than
  it covers.
- **Rolling the key slots back.** Someone who can write to the container can destroy the newer slot table and leave
  the older one, which is authentic because it was. A key removed with `bond keys remove` therefore stops working for
  anyone who has only the container; it is not proof against someone who kept a copy of the file. `bond rekey` is the
  answer when it has to be, because it changes the master key and leaves nothing for an old slot to unwrap.

**Leaked without a key**: the file size, the container UUID, the creation time, the shard geometry, the cipher and KDF
parameters, and how many key slots of which kinds exist. Not the file names, not the sizes of individual files, not
the source paths.

---

## 11. Recovering by hand

A backup format nobody can decode without its own tool is a single point of failure. This is the procedure if the
`bond` binary is what got lost. Everything here uses documented primitives and the constants above.

1. **Read the header.** Bytes 0–4095. Check the magic. Take `cipherID` (24), `shardSize` (36), `dataShardCount` (48),
   `streamLength` (56), `containerUUID` (72, 16 bytes), `noncePrefix` (88, 16 bytes), `tailOffset` (104),
   `tailLength` (112) and `lastShardBytes` (240). If the magic is wrong, read the last 4096 bytes instead.

2. **Find the current key slot table.** Parse both 64 KiB tables at 4096 and 69632; take the one with the higher
   generation (offset 8) that has magic `BSLT`. Walk its records from offset 64 using each record's size field. On a
   container whose keys were never changed the two tables are identical, so either will do; if the newer one looks
   damaged, try the other.

3. **Recover the master key.** For a passphrase slot, compute
   `Argon2id(passphrase, salt, iterations, memoryKiB, lanes, 32)` with the values at offsets 48 and 64–75 of the
   record. That is the key-encryption key. Open the 48-byte wrapped key at offset 80 with XChaCha20-Poly1305 using
   the nonce at offset 24 and associated data
   `"BOND-SLOT-V1" ‖ containerUUID ‖ slotUUID ‖ slotType ‖ salt ‖ LE32(memKiB) ‖ LE32(iters) ‖ LE32(lanes)`.
   For a key file, the key-encryption key is `HKDF-SHA512(keyfileBytes, salt, "bond/v1/keyfile-kek", 32)` instead,
   and the associated data ends after the salt – there are no KDF parameters to bind.

4. **Derive the subkeys.** `HKDF-SHA512(fmk, salt = containerUUID, info, 32)` for each of `bond/v1/data`,
   `bond/v1/manifest`, `bond/v1/header`, `bond/v1/commit`.

5. **Decrypt the payload.** Open each shard with `dataKey`, nonce `noncePrefix ‖ LE64(i)`, and associated data
   `"BOND-DATA-V1" ‖ containerUUID ‖ LE64(i) ‖ LE32(shardSize)`. Concatenate the results and keep the first
   `streamLength` bytes.

   Where shard `i` begins depends on whether the container carries parity. With `parityID` 0 it is simply
   `135168 + i × shardSize`. With parity, read `k` at offset 40 and `p` at offset 44, and note that a full stripe
   occupies `k × shardSize + p × (shardSize + 16)` bytes: shard `i` is in stripe `i / k` at position `i % k`, so it
   starts at `135168 + (i / k) × stripeBytes + (i % k) × shardSize`. Every shard is `shardSize` long except the last,
   which is `lastShardBytes`. Parity shards can be ignored entirely unless something is damaged.

6. **Unpack.** The result is an xz stream (or a bare tar if the manifest says `"compression": "none"`).
   `xz -d < stream.xz | tar -xf -`. Any xz and any tar will do; there is nothing BOND-specific left at this point.

7. **The manifest**, if you want it: read `tailLength` bytes at `tailOffset`, skip the 8-byte length, take the next
   24 bytes as the nonce, open the rest with `manifestKey` and associated data `"BOND-MANIFEST-V1" ‖ containerUUID`,
   then gunzip. If that copy is damaged, the second one starts at `tailOffset + tailLength`. In a split container
   `tailOffset` is a position in the **last** volume, and every volume's header carries the same value.

Steps 1–6 are about eighty lines of Go against `golang.org/x/crypto`, and the same in Python against `cryptography`
and `argon2-cffi`.

---

## 12. Where the time goes

Measured on windows/amd64, 12 cores, NVMe. The tree is 135 MiB in eight files: 100 MiB of `/dev/urandom` and 35 MiB of
repetitive German prose, which is a deliberately unflattering mix – the incompressible half is what LZMA2 has to chew
through for nothing.

| Stage | Time | Throughput |
|---|---:|---:|
| Backup, `compressionLevel: 0` | 0.68 s | 199 MiB/s |
| Backup, `compressionLevel: 1` | 2.78 s | 49 MiB/s |
| Backup, `compressionLevel: 5` | 7.16 s | 19 MiB/s |
| Backup, `compressionLevel: 9` | 6.11 s | 22 MiB/s |
| `verify --quick` (SHA-384, no key) | 0.23 s | 505 MiB/s |
| `verify` (every AEAD tag + stream digest) | 0.19 s | 611 MiB/s |
| Restore (xz decode, AEAD, tar, per-file SHA-256) | 0.44 s | 307 MiB/s |

**Compression is the wall clock, by a mile.** At level 5 it is 94% of the time a backup takes. Everything BOND itself
does – tar, XChaCha20-Poly1305, Reed-Solomon, SHA-256 of the stream, SHA-384 of the file – is the remaining 6%, and
those parts are individually invisible: turning parity off saves 15 ms out of 694, and turning the checksum file off
saves 5 ms more. Both measurements are within the noise of each other.

Two consequences worth acting on. First, **`compressionLevel: 0` is the right setting for video, music and photos**;
it is 10× faster and LZMA2 saves nothing on data that is already compressed. Second, level 9 beating level 5 here is
not a mistake – the larger dictionary lets LZMA2 give up faster on the incompressible half. On genuinely compressible
data the usual ordering returns, so the levels are worth trying against your own trees rather than assumed.

Restoring is 16× faster than backing up, which is the right way round for a tool most people will use once.

### Argon2id

`bond bench-kdf` on the same machine, targeting one second per unlock:

| Profile | Memory | Passes | Lanes | Time |
|---|---:|---:|---:|---:|
| low memory | 64 MiB | 3 | 4 | 52 ms |
| default | 512 MiB | 3 | 4 | 283 ms |
| 1 GiB | 1 GiB | 3 | 8 | 429 ms |
| 2 GiB | 2 GiB | 3 | 8 | 817 ms |

Parameters are stored per slot, so raising them affects new containers and leaves old ones openable.
