# NERDME – how BOND actually works

The authoritative description of the BOND container format, version 2.0. [README.md](README.md) is the operator's
guide; this is everything underneath it.

Format 2.0 is the only format this build reads or writes. It differs from 1.0 in four places, each described where
it applies: every key slot carries a key commitment ([§4](#4-key-model)); associated data, MAC inputs and combined
secrets are length-prefixed tuples rather than concatenations ([§4](#4-key-model)); a passphrase is hashed in Unicode
normalization form C ([§4](#4-key-model)); and the stream and the manifest are padded, so a container's size no
longer gives the size of what is in it ([§6](#6-payload-shards-and-recovery-data), [§8](#8-manifest)).

## 1. The pipeline

One pass each way, nothing buffered to disk. A backup of a terabyte needs a terabyte of space and nothing else: no
temporary archive, no second copy. That space is on the destination's filesystem, because the container is assembled
in `workPath` and renamed into place, and a rename cannot cross filesystems. `bond repair` and `bond rekey` are the
two operations that do need a second full copy, since each writes a new container beside the one it reads.

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
        │  zero-padded to its Padmé length,                             │       │
        │  split into shardSize-16 chunks                               │       │
        ▼                                                               ▼       ▼
  XChaCha20-Poly1305 per shard         internal/crypto            manifest (sealed)
        │                                                                 │
        ▼                                                                 ▼
  ┌───────────────────────────── container file ──────────────────────────────┐
  │ superblock │ slots A │ slots B │ shard 0 … shard N-1 │ tail ×2 │ mirror   │
  └───────────────────────────────────────────────────────────────────────────┘
```

Restore is the same picture backwards, with one rule added: nothing that failed authentication is ever handed to the
decompressor. A shard that fails its tag is rebuilt in memory from its stripe's recovery data when the stripe allows,
and the rebuilt shard has to pass the same tag ([§6](#6-payload-shards-and-recovery-data)); where it cannot be
rebuilt, the read stops there.

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
move and never change size, adding a key rewrites 128 KiB of a terabyte file.

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
| 56 | 8 | Stream length as stored: the compressed stream padded to its Padmé length ([§6](#6-payload-shards-and-recovery-data)) |
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
| 244 | 32 | SHA-256 of this volume's payload slice as stored (sealed data and parity shards, in file order) |
| 276 | 4 | Writer signature scheme (0 = unsigned, 1 = Ed25519 + ML-DSA-65) |
| 280 | 32 | Writer fingerprint: SHA-256 of the writer's public key; zero when unsigned |
| 312 | 3373 | Writer signature: 64 bytes Ed25519, then 3309 bytes ML-DSA-65; zero when unsigned ([§4](#writer-signatures)) |
| 3685 | 411 | Reserved, zero |

Format 2.0 means exactly major 2, minor 0. Other versions – 1.0 included – and unknown flag bits are refused.

The **header MAC** is `HMAC-SHA256(headerKey, superblock with bytes 208–239 zeroed)` and covers all 4096 bytes,
reserved area included, so nothing can be smuggled into the padding.

**It is taken over the bytes as they were read**, not over a re-rendering of the fields the reader understood. The
difference is the whole of what that sentence promises. Marshalling a parsed header back out writes zeros across the
reserved region, so a MAC computed that way never looks at what is really stored there – which left 3852 bytes per
header copy that anyone could write to, on a container that would then pass `bond verify` reporting no damage at all.
Reading the MAC over the raw bytes means corruption or unauthorized data in the reserved region is still detected.
A future format must use a new declared version and is refused by this 2.0 reader rather than guessed at.

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
              "bond/v2/data"  "bond/v2/header"  "bond/v2/manifest"   "bond/v2/commit"
                dataKey        headerKey         manifestKey           commitKey
```

**`T(x₁, …, xₙ)`**, the tuple encoding, is `LE32(len(x₁)) ‖ x₁ ‖ … ‖ LE32(len(xₙ)) ‖ xₙ`. Every associated data,
every MAC input that combines more than one value, and the combined secret of the hybrid key exchange is one. Plain
concatenation is unambiguous only while every field has a fixed length, and stops being so – with every test still
passing – the day a variable-length field is placed beside another. With the lengths written down, no two different
lists of values can produce the same bytes. A label such as `"BOND-DATA-V2"` stands for its ASCII bytes.

The **File Master Key** is 32 bytes from `crypto/rand` and is never derived from a passphrase. That is what makes key
changes cheap: every slot wraps the same FMK, so a new passphrase re-wraps 32 bytes rather than re-encrypting a
terabyte.

The **container UUID is the HKDF salt**, so two containers never share a subkey even if they somehow shared a master
key.

The **key commitment** is `HMAC-SHA256(commitKey, T("BOND-COMMIT-V2", containerUUID))`, stored in the header. AEAD tags
prove a ciphertext was made with the key that opens it, but not *which* key that was; without a commitment a container
could in principle be crafted to open differently under two different secrets. The commitment is checked before
anything else is trusted. Each key slot carries a commitment of its own as well, described with the slot record
below; the two close the same gap at two levels.

**`encryptionMethod: NONE`** is not a separate code path. BOND still generates an FMK, still seals every shard, and
stores the FMK wrapped under an all-zero key-encryption key in a `plaintext` slot. The tags provide corruption
detection, not adversarial authenticity: anyone holding the container can read it, recover the FMK and create modified
content with valid tags. An external signature is required when malicious-tamper evidence matters.

The plaintext slot is never used on the container's say-so. The slot table is parsed before a key exists to
authenticate it, so whoever stores the file decides whether it lists such a slot, and a reader that tried it
unasked would open a substituted container under any passphrase the operator typed, or under none. `bond` offers
the plaintext secret only when `--allow-unencrypted` is given, and never together with another key.

`FlagUnencrypted` in the header is advisory, and `bond keys remove` refuses to delete a plaintext slot. Neither is
fussiness. The flag records what was true when the container was written and no key change may rewrite it – the
superblock does not authenticate the slot tables, and re-signing every volume header on every key change is exactly the
cost that design avoids. So flag and slots can disagree, readers must tolerate it, and anything telling an operator
whether a container is readable asks the *slots*. Removing the plaintext slot, meanwhile, looks like "encrypt this
backup now" and is not: the master key was stored in the file when it was written, and everyone who took a copy before
today still has it. `bond rekey` is the operation that changes who can read a backup.

### Key-slot table

Two tables at fixed offsets, 64 KiB each. A fresh container writes the same slots into both at generation 1, and a
key change leaves them identical again at the next generation. They differ only while a key change is in flight or
after damage, and then the higher authentic generation is the current one.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Magic `BSLT` |
| 4 | 2 | Version (2) |
| 6 | 2 | Slot count (max 32) |
| 8 | 8 | Generation |
| 16 | 4 | Bytes of records in use |
| 32 | 32 | Table MAC – `HMAC-SHA256(headerKey, table with this field zeroed)` |
| 64 | … | Slot records, packed |

Each record:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Record size |
| 4 | 2 | Record version (2) |
| 6 | 1 | Slot type: 1 passphrase, 2 key file, 3 plaintext, 4 recipient |
| 8 | 16 | Slot UUID |
| 24 | 24 | Wrapping nonce |
| 48 | 16 | Salt |
| 64 | 12 | Argon2id memory (KiB), passes, lanes |
| 76 | 4 | Wrapped length (48) |
| 80 | 32 | Key commitment |
| 112 | 48 | The sealed master key |
| 160 | 2 + n | Label length and UTF-8 label |
| … | 4 + m | Key-exchange length and bytes – recipient slots only, otherwise 0 |

Both 64 KiB tables are authenticated as the exact bytes read, including unused padding. Before Argon2 runs, a reader
also applies a local hostile-input policy: at most 1 GiB memory, 6 passes, 64 lanes and 3 GiB-passes for one derivation,
and at most 64 derivations per unlock. Equivalent header/table attempts are deduplicated, so the four header-copy ×
slot-table combinations cost one derivation rather than four, and a refused passphrase slot does not prevent a safe
key-file, plaintext or recipient slot from being tried. `--allow-expensive-kdf` bypasses these local willingness limits
but retains permanent format validity checks and emits a resource-risk warning.

The second limit counts derivations rather than their total cost, and that is deliberate. A cumulative *work* ceiling
is either above `maxSlots × 3 GiB-passes`, in which case the per-derivation cap already enforces it, or below – in which
case it refuses containers BOND itself wrote. The version that shipped with the limit at 6 GiB-passes allowed exactly
four derivations at the default profile, so a container with five passphrase slots failed to open unless the right one
came up early, reporting that its own default parameters exceeded the safety policy. What bounds the hostile case is
the memory ceiling on any single derivation; what bounds the total is that a table declares at most `maxSlots` slots
and the derivations run one after another, never concurrently.

**How a slot wraps the master key.** Whatever the slot's kind, it ends in a 32-byte key-encryption key `KEK`:

| Slot | KEK |
|---|---|
| passphrase | `Argon2id(NFC(passphrase), salt, passes, memoryKiB, lanes, 32)` |
| key file | `HKDF-SHA512(keyfile bytes, salt, "bond/v2/keyfile-kek", 32)` |
| plaintext | 32 zero bytes |
| recipient | the hybrid exchange below |

```
K_enc      = HKDF-SHA512(KEK, no salt, "bond/v2/slot-enc", 32)
K_com      = HKDF-SHA512(KEK, no salt, "bond/v2/slot-com", 32)
aad        = T("BOND-SLOT-V2", containerUUID, slotUUID, slotType, salt, params)
commitment = HMAC-SHA256(K_com, T(nonce, aad))
wrapped    = XChaCha20-Poly1305(K_enc, nonce, FMK, aad)
```

`slotType` is one byte. `params` is `LE32(memoryKiB) ‖ LE32(passes) ‖ LE32(lanes)` for a passphrase slot, the stored
key exchange for a recipient slot, and empty otherwise. Binding the cost parameters matters: without it, an attacker
could lower the recorded memory and pass count to make guessing cheaper, and the tag would not notice.

**The commitment is checked first**, in constant time, and a key that does not match it is a wrong key before
anything is decrypted. XChaCha20-Poly1305 does not commit to its key: a wrapped key can be constructed that opens
under several key-encryption keys at once. Whoever stores a container could swap in such a slot, built over a whole
set of candidate passphrases, and learn from how a reader fails which set the real passphrase is in – many guesses
for the price of one unlock. With the commitment a slot answers to exactly one key. It also separates two failures
that used to look alike: a key that matches the commitment and still cannot open the wrapped key means the slot is
damaged, not that the passphrase was mistyped, and the reader goes on to the other table.

**The passphrase is hashed in normalization form C.** The same characters reach a program as different bytes
depending on keyboard and operating system – an umlaut may arrive as one code point or as a letter and a combining
mark – and a backup written on one machine and restored on another would otherwise be refused its own passphrase.
Bytes that are not valid UTF-8 pass through unchanged.

A new passphrase must have at least twelve characters. That is a rule of the tool where a passphrase is chosen, not
of the format: a container opens with whatever it was written with.

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

### Writer signatures

A recipient slot is made from the public key alone, which is its point – and also its limit: whoever knows that key
can build a complete container the recovery key opens, and nothing in it would tell that container from one the
backup machine wrote. In a fleet the public key sits in a control file on every node, so "whoever knows it" is a
large set. A writer key is what tells the two apart.

`bond keygen --signing-key` makes one: a 32-byte seed from which an Ed25519 key and an ML-DSA-65 key are derived
(`HKDF-SHA512(seed, no salt, "bond/v2/writer-ed25519", 32)` and `… "bond/v2/writer-mldsa65" …`, the latter as the
FIPS 204 key-generation seed). The secret half stays on the machine that writes backups (`signingKey` in the control
file); the public half, `Ed25519 public ‖ ML-DSA-65 public` (1984 bytes), goes wherever restores happen. Its
fingerprint is the SHA-256 of those bytes.

Every volume header is signed, and the signature is in the header (offsets 276–3684 in [§3](#3-superblock)):

```
message   = T("BOND-WRITER-V2", header with the MAC (208–239) and the signature (312–3684) zeroed)
signature = Ed25519(message) ‖ ML-DSA-65(message, context "BOND-WRITER-V2")
```

The header MAC is computed afterwards, over the signature. The message covers everything else in the header: the
scheme and fingerprint, the container UUID, the key commitment, the volume's place in its set, its payload digest
(offset 244), and the manifest digest – which through the manifest covers the stream digest and the file index. A
reader that has unlocked the container has therefore checked, under the signature, everything it restores.

Both halves have to verify. Ed25519 holds against what is known today and ML-DSA against a quantum computer. ML-DSA-65
rather than -87 because its signature fits the header's reserved area; its category 3 against ML-KEM-1024's category
5 is a smaller gap than it looks, because a harvested ciphertext can be broken decades later, while a forged
signature has to exist before the restore that would accept it. ML-DSA signing is hedged, so two signatures of the
same header differ; a volume's two header copies are therefore one rendering written twice.

A signature proves something only against a key the reader was told to expect, which is `--expect-writer`. Without
it, `bond` reports which fingerprint a container claims and that it was not checked, and a container opened through a
recipient slot with no signature at all is reported as such. The key-slot tables are not signed – they change with
every key change – which is harmless: a slot only yields the master key the signed header commits to.

The payload digest makes one more check possible: **with nothing but the writer's public key**, `bond verify --quick
--expect-writer` confirms every volume's signature, hashes every payload slice against its signed digest, and checks
the manifest copies against theirs. That is the whole container except the slot tables, proved unchanged since it
was written by a job that holds no decryption key – which a checksum file beside the container, being as easy to
replace as the container, cannot do.

The writer key opens nothing. A machine holding one can vouch for what it writes and still cannot read it. What
changes is that a compromised machine can now sign forgeries; but a compromised writer could always write whatever
it liked, so the claim is "the machine can vouch for backups, not read them", and it holds.

## 5. Changing a key never touches the payload

This is a design requirement, so the format is built for it rather than relying on care.

The superblock **does not authenticate the slot tables**. If it did, adding a key would mean rewriting the superblock –
and in a split container, the superblock in every volume. Instead each table carries its own MAC and its own
generation counter, and a key change replaces them one after the other:

1. Unlock the master key and authenticate both header copies and both slot tables.
2. Select the highest authentic generation. Equal-generation authentic tables must be byte-identical, and the maximum
   generation cannot be incremented.
3. Build the new slot set and write the selected table's physical peer with `generation + 1`.
4. fsync, re-read, parse and authenticate the new table.
5. Write the same bytes over the table selected in step 2, and fsync, re-read and authenticate that too before
   reporting success.

At every instant one authentic table is on disk. A crash before step 4 completes leaves the previous table as the
highest authentic generation; a crash between steps 4 and 5 leaves the new one current and the previous one still
present, which running the command again clears. If only one authentic copy exists to begin with, the damaged peer
is the one written first. Total I/O for a key change on a terabyte container: 128 KiB.

Step 5 is what makes `bond keys remove` and `rotate-passphrase` mean what they say. Readers try every table that
parses, newest first, because a flipped bit can leave the newer one structurally perfect and merely unauthentic.
With the previous table left in place that same fallback let a removed key go on opening the container, with no
tampering at all, until a later key change happened to land on that copy.

What no key change can reach is a copy of the file from before it. An older slot table is genuinely authentic,
because it was, and someone who kept the old file – or a storage provider that serves it again – still has a
container the old key opens. A removed key that must stay removed is removed with `bond rekey`, which changes the
master key itself and leaves nothing for an old slot to unwrap.

Rotating the *master key* is genuinely a full rewrite, and gets its own command – `bond rekey` – that says so before
it starts. The distinction is worth insisting on: a passphrase that may have been seen is answered by
`bond keys rotate-passphrase` in milliseconds, and rekeying is for when the master key itself may be exposed, which in
practice means a restore happened on a machine that is no longer trusted.

`bond keys add|remove|rotate-passphrase` check the claim rather than making it: the payload region is hashed before
and after, and a mismatch is reported as a bug rather than shrugged off.

## 6. Payload shards and recovery data

Every data shard but the last is exactly `shardSize` bytes on disk: `shardSize - 16` bytes of compressed stream, plus
a 16-byte Poly1305 tag.

- **Nonce**: `noncePrefix ‖ LE64(shardIndex)` – 16 random bytes per container, then the index. Derived rather than
  stored: an index is unique within a container by construction, so the same nonce cannot occur twice under one key.
- **Associated data**: `T("BOND-DATA-V2", containerUUID, LE64(shardIndex), LE32(shardSize))`. Without the index a
  shard could be moved or repeated within the container and still authenticate; without the UUID a shard from another
  container under the same key would too. A tag alone notices neither.
- **The last shard is short.** It is sealed at whatever length it reached. Padding it would waste up to a full shard
  on every container – for a 444 KiB backup that was the difference between 4.13 MiB and 432 KiB – and buys nothing,
  because parity pads in memory when it computes the final stripe. Its on-disk size is recorded at offset 240.

### Padding

What the shards hold is the compressed stream followed by zeros up to its **Padmé** length:

```
padme(L) = L                                      if L < 2
E = ⌊log₂ L⌋,  S = ⌊log₂ E⌋ + 1,  b = E − S       otherwise
padme(L) = ⌈L / 2^b⌉ · 2^b
```

A container's size is visible to anyone who can list a bucket, and without padding it gives the compressed size of
the backup to the byte: enough to tell which of two known trees a container holds, or to notice that one file was
added since last month. Padmé keeps the leading bits of a length and rounds the rest away, so what remains is "about
this large". The cost falls in steps as lengths grow: at most 12.5% below 256 bytes, 6.3% up to 64 KiB, 3.2% from
there to 4 GiB and 1.6% above – where rounding up to a power of two would cost up to 100%.

The header field at offset 56 is the padded length, because the shard layout follows from it and a header is read
without a key. The exact length lives in the manifest, which is sealed. A reader hands on the first `streamLength`
bytes, and still reads and authenticates the shards that hold only padding: a restore that skipped them would be a
restore from a container nobody looked at to the end. Padding that is not zeros is refused.

The manifest is padded the same way, inside its seal ([§8](#8-manifest)), since its size follows the number of files
and the length of their names.

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

**This mapping is part of format 2.0**, not a tuning choice of the writer. The manifest records the percentage and
the header records `k` and `p`, and a reader refuses a container in which the two do not agree under exactly this
rule: for `p` from 2 upward, `k = round(100·p / percent)`; the first `p` with `k ≥ 8` is taken, and `k` is cut to
`128 − p` when the stripe would be wider than 128. A writer that chose stripes any other way would produce
containers this reader calls invalid, so a different rule is a different format version.

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
5. Re-open and fully verify the repaired copy – both copies of every piece of metadata, then every shard – and
   only then publish it.

Reed-Solomon reconstructs; AEAD decides whether the reconstruction is right. Never the other way around.

The repaired set is written under staging names beside its destination and moved into place by the same no-replace
publication a backup uses, after step 5 and not before. A repair that fails or is interrupted removes what it staged,
so a file called `backup.repaired.bond` is always a container that passed.

**The read path does the same thing in memory.** A restore, or a rekey, that meets a shard which does not
authenticate reads the rest of that stripe, authenticates every shard of it, reconstructs, and hands on the rebuilt
shard only if it opens under its own tag. Nothing is written back; the reader counts what it rebuilt and the command
reports it, because the container is exactly as damaged as before. What this buys is that a recovery does not begin
with writing a second full copy of the backup.

**Damage outside the payload is repaired too.** A repair starts from a byte-for-byte copy, so a header the reader had
to take from the mirror – or a slot table it had to take from the spare – would otherwise be reproduced faithfully in
the "repaired" file, leaving it one flip from being lost. Whichever copies authenticated are written back over both
positions, and the manifest is written back from whichever copy matched the digest in the authenticated header.
Nothing is invented: the header carries its own MAC and the slot table is re-signed under the same header
key, so this restores redundancy the container already proved it owns.

The manifest needs saying separately because it is the copy a reader is least likely to notice. Either copy opens the
container, so a reader that stops at the first one that works never looks at the second. Both are checked at unlock –
the second only against the header's digest, which costs a hash – and a damaged one is a notice like any other. It is also the one repair that works without
any recovery data at all, since it needs no parity to reconstruct anything.

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

A fully missing mirror is reported as degraded metadata on the first, middle or last volume and `bond repair` restores
it. A partial mirror is truncation, not a legacy layout. Strict writer readback requires both authenticated copies on
every newly written volume before and after publication.

Three things are checked before a split container is trusted, in increasing order of strength: the volumes must be
numbered as they claim; they must all carry the same container UUID, since two containers of the same shape otherwise
have interchangeable-looking files; and once a key is available, **every volume's header MAC is verified**, not only
the first. Without that last check a foreign volume passes as one of the set and is only caught later, shard by shard.

`maxVolumeBytes` bounds the payload in a volume, with a 4 MiB allowance held back for the mirrored header each volume
carries and the manifest the last one adds. A file index of a million files can exceed that allowance, in which case
the last volume is a little larger than asked for – better than refusing to finish a backup over it.

Because a boundary never falls inside a shard, a shard larger than that budget would be a volume larger than the
limit: a writer with one shard in hand and an empty volume has nowhere else to put it. The shard size is therefore
cut to the largest multiple of 4096 that fits, a parity shard's extra tag included, before the first byte is written.
`shardBytes` was already a maximum ([§6](#6-payload-shards-and-recovery-data)); this is one more thing it yields to.

**The tail offset is a position inside the last volume**, not in the container as a whole, and every volume's header
records the same value. A reader that insisted it point past the whole 132 KiB head – which only volume 1 has – refused
every header copy of every volume in a set whose last file held less than 128 KiB of payload. That is an ordinary
shape: it is what a short final shard landing alone in its own volume looks like. The container was written, reported
as written, and could then be opened by nothing.

Publication is no-clobber and uses atomic no-replace moves on one filesystem. The destination namespace (base,
numbered volumes and checksum sidecars) must be empty before writing begins and is checked again at commit time.
Volumes `.002` and later move first, the destination directory is synced, and `.001` moves last as the commit point,
followed by another directory sync. A reported failure triggers reverse rollback where possible. A process crash can
leave non-leading orphan volumes, which do not form a valid set and require explicit operator cleanup; BOND never
deletes or replaces an existing backup set automatically. The refusal names every file occupying the namespace, because
"something is in the way" is not something an operator can act on. Sidecars use exclusive creation; the one that
belongs to the first volume is rewritten when a key change alters that file.

What counts as the namespace is the same rule `VolumeFiles` uses to discover a set, not "ends in three digits":
`backup.bond.old.001` is a volume of `backup.bond.old` and does not block `backup.bond`. The writer's own staging files
are exempt from the commit-time recheck, which matters when `workPath` and `outputPath` name one directory – the
same-filesystem requirement makes that a natural thing to configure, and `backup.bond.partial.001` would otherwise look
like a competitor to the container it is about to become.

The no-replace move is `renameat2(RENAME_NOREPLACE)` on Linux and `renamex_np(RENAME_EXCL)` on macOS, falling back to
`link` + `unlink` where the filesystem does not implement them – NFS, several FUSE backends and pre-3.15 kernels return
`EINVAL`, `ENOSYS` or `EOPNOTSUPP`. `link` fails with `EEXIST` if the destination exists, which is the same guarantee,
and those are exactly the destinations an archival tool gets pointed at. Windows uses `MoveFileEx` without
`MOVEFILE_REPLACE_EXISTING`, which refuses an occupied target by default.

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
never produces – symlinks, hard links, devices, fifos – are refused as well: meeting one means the stream is not what it claims
to be.

Half of that list is a *restore* policy rather than a format rule, and the two must not be confused. `com1`, `a:b`,
`back\slash` and `trailing.` are ordinary file names on Linux and unusable on Windows, so a container can legitimately
contain them and a Windows restore must legitimately refuse them – one entry at a time, by name, at the moment it would
be created. Nothing that decides whether a container *opens* may apply them. `Manifest.Validate` checks its index with
`CheckPortableName`, the platform-independent half; using the full `CheckName` there made a backup written on Linux
fail to unlock on Windows, so `inspect`, `verify`, `list` and even a `--include` restore of untouched paths all reported
the manifest as invalid. A container that authenticates completely is not invalid because of where it is being read.

The name is judged **before** the include filter is consulted, so "it would have been skipped anyway" is never the
reason a hostile archive is accepted. An offending entry **aborts the whole restore** rather than being skipped. An
archive containing a path that tries to escape is not a backup with one bad entry; it is a backup that cannot be
trusted.

Archive entry names are confined **lexically** below the selected destination. Existing symlinks, junctions, reparse
points and other filesystem redirections below that destination retain normal operating-system behavior and are the
operator's responsibility. Restore into a new or suitably prepared directory when following existing redirections is
not desired. The archive itself cannot introduce a new redirection because every link entry is rejected.

At backup time `followSymlinks` defaults to true. A link target is materialized as an ordinary file or directory tree
at the link's archive path, even when the target is outside the lexical source root. Directory identity is tracked only
along the current recursion ancestry: a loop edge is omitted with a warning, while repeated non-cyclic aliases are
materialized independently. With following disabled, included links are omitted, counted and reported. Filters apply
to the link's archive path and the resolved target kind.

A Windows junction, or any other reparse point that is not a symlink, is treated as a link. `Lstat` reports those as
irregular – neither link nor directory – and read as an ordinary file a junction archives as zero bytes under a
directory's name.

What resolves to neither a file nor a directory is not archived: named pipes, sockets and device nodes are skipped
with a warning and counted, and recognised before anything is opened, since opening a FIFO for reading blocks until
something writes to it.

A name is stored as the bytes it has, whether or not they are text. The tar stream keeps them as they are; the file
index is JSON, which writes U+FFFD in place of a byte that is not valid UTF-8, so an index entry for such a name
carries it a second time as `pathBytes` (base64) and a reader goes by that. A name that is valid UTF-8 has no
`pathBytes`. Without it the index and the archive would name the entry differently, and a restore that checks one
against the other would stop there. Restoring such a name needs a system where names are bytes, which is Linux; on
Windows and macOS the entry is refused by name.

## 8. Manifest

gzip(JSON), sealed with `manifestKey` and framed as `[LE64 length][24-byte nonce][ciphertext]`, written twice.
Associated data is `T("BOND-MANIFEST-V2", containerUUID)`.

The plaintext under the seal is `LE64(n) ‖ gzip bytes (n of them) ‖ zeros`, padded to `padme(8 + n)`. A reader checks
that the total length is exactly that and that the padding is empty.

It holds the compression settings, the exact stream length (`streamLength`), the padded one (`paddedLength`, which
must equal the header's and `padme(streamLength)`), the stream's SHA-256, the shard geometry, and the **file
index**: path (and `pathBytes` for a name that is not UTF-8, [§7](#7-the-archive-namespace)), kind, size, mode,
mtime and SHA-256 for every entry.

The p7e sketch deliberately kept names out of the manifest. That reasoning does not survive contact with the key
model: the manifest is sealed with a key derived from the same master key as the payload, so a name in the manifest is
exactly as protected as a name inside the archive. Keeping it means `bond list` answers from a few hundred kilobytes
instead of decompressing half a terabyte, and `bond restore` can check every restored file against the digest recorded
when it was read. `storeFileIndex: false` turns it off.

JSON and gzip rather than CBOR: no dependency, and a debuggable format for the one structure a future recovery effort
would most want to read by hand.

## 9. What survives, what does not

Everything here is a number the test suite produces, not a claim about the design. Run `go test ./internal/container/
-run BitFlip -v` and the table below is what prints.

### The bit-flip sweep

`TestSingleBitFlipIsNeverSilent` takes a real container, flips one bit at a time across 632 offsets chosen to cover
every named header field densely and every other region by a fixed count, and reads the whole thing back. Each attempt
lands in one of three outcomes: **refused**, **absorbed** (it opened and returned exactly the right bytes), or
**silent** – it opened and returned something else. A silent result is a bug, and there is no acceptable number of them
but zero.

| Region | Flips | Refused | Absorbed | Silent |
|---|---:|---:|---:|---:|
| Superblock | 286 | 0 | 286 | 0 |
| Key-slot table A | 143 | 0 | 143 | 0 |
| Key-slot table B | 16 | 0 | 16 | 0 |
| Payload | 81 | 81 | 0 | 0 |
| Manifest, copy 1 | 21 | 0 | 21 | 0 |
| Manifest, copy 2 | 21 | 0 | 21 | 0 |
| Superblock mirror | 64 | 0 | 64 | 0 |
| **Total** | **632** | **81** | **551** | **0** |

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
| One bit in a data shard | Located to the shard; repaired if parity covers the stripe, and rebuilt in memory by a restore |
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
| One manifest copy | Opens from the other, and is reported; `repair` writes both back |
| One volume's header, in a split set | Opens from that volume's mirror; `repair` writes both back |
| A truncated volume | Refused |
| A volume from a different container | Refused at open, on the container UUID |
| A volume with a forged header | Refused at unlock; every volume's MAC is checked |
| Wrong passphrase or key file | Refused before any payload is read |

### Fuzzing

Six targets, run as ordinary tests over their seed corpus on every `go test` and extended with `-fuzz`:

| Target | What it asserts |
|---|---|
| `FuzzUnmarshal` | A header that parses has offsets that do not overlap or overflow, and describes a payload of a possible size |
| `FuzzParseSlotTable` | A table that parses has slots of the declared sizes |
| `FuzzOpenManifest` | The unauthenticated length field cannot become an absurd allocation |
| `FuzzSafeJoin` | If a name is accepted, the path is clean and inside the destination |
| `FuzzDecodeRecoveryKey` | An accepted key is exactly 32 bytes |
| `FuzzRecoveryKeySurvivesRetyping` | Any case, hyphenation or confusable substitution decodes to the same seed |

The committed seed corpora run as regression cases on every ordinary test invocation.

The header and slot-table targets patch a *valid* structure at a fuzzer-chosen offset rather than taking raw bytes.
Random bytes essentially never survive a magic number, so a blind target spends its whole budget on the first four
lines of the parser and never reaches the arithmetic, which is the only place anything interesting can go wrong.

### Memory

The streaming pipeline's promise is that a backup of a terabyte needs a terabyte of disk and no memory to match, so
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

## 10. Threat model

**Protects against**

- A cloud operator reading the backup. Everything but the header geometry is sealed.
- Bit rot and range corruption: every shard is authenticated, and damage is located to the shard.
- An encrypted container altered in transit: the header MAC, slot-table MAC, per-shard tags, manifest tag and key
  commitment all have to agree for an attacker who does not possess an unlocking secret.
- A container substituted by someone who knows the recipient's public key, when the restore expects a writer.
- A shard moved, duplicated or transplanted from another container.
- A wrong passphrase: rejected before any payload is touched.
- A half-written backup: the container is built in the working directory and renamed into place only when complete.

**Does not protect against**

- A weak passphrase. Argon2id raises the cost per guess; it cannot fix a guessable secret.
- Losing every key. That is the design.
- Malware on the machine while the backup runs, or while the passphrase is typed.
- Deletion of the object in the cloud. Parity repairs corruption, not absence; keep two copies.
- Traffic analysis of size and timing. The container's size is rounded, not hidden: Padmé padding leaves the order
  of magnitude and the leading bits, and when a container was written is plain to whoever stores it.
- Damage beyond the recovery capacity of a stripe. Parity repairs corruption, not deletion, and not more losses than
  it covers.
- Malicious modification of a `NONE` container. Its key is stored in the container, so its tags provide corruption
  detection but no provenance or adversarial authenticity; use an external signature where that property is needed.
- **Substitution of an unsigned recipient-only container.** A recipient slot needs nothing but the public key to
  create, so whoever knows that key can build a complete, valid container the recovery key opens. Such a container
  is confidential and cannot be *altered* without the master key, but nothing in it says who wrote it. A writer
  signature checked with `--expect-writer` closes this ([§4](#writer-signatures)); so does restoring through a
  passphrase or key-file slot, which cannot be made without the secret. A restore through a recipient slot with
  neither is warned about.
- **Replay.** An older container, authentic when it was written, can be served in place of a newer one, and a
  deleted one looks the same as one never written. Nothing inside a single file can say it is the latest.
- **Rolling the key slots back.** A key change replaces both slot tables, so a key removed with `bond keys remove`
  stops working for anyone who has only the current container. It is not proof against someone who kept a copy of
  the file from before, whose slot tables are authentic because they were. `bond rekey` is the answer when it has to
  be, because it changes the master key and leaves nothing for an old slot to unwrap.

**Leaked without a key**: the file size and with it the padded length of the compressed stream, the container UUID,
the creation time, the shard geometry, the cipher and KDF parameters, how many key slots of which kinds exist, and
the writer fingerprint of a signed container, the label of each slot, which is stored in the clear – do not put anything in a label that the destination should
not read. Not the file names, not the sizes of individual files, not
the source paths.

## 11. Recovering by hand

A backup format nobody can decode without its own tool is a single point of failure. This is the procedure if the
`bond` binary is what got lost. Everything here uses documented primitives and the constants above.

All integers are little-endian, and `T(…)` is the tuple encoding of [§4](#4-key-model): each value preceded by its
length as a 4-byte integer.

1. **Read the header.** Bytes 0–4095. Check the magic and that the version at offset 8 is 2. Take `cipherID` (24),
   `shardSize` (36), `dataShardCount` (48), the padded stream length (56), `containerUUID` (72, 16 bytes),
   `noncePrefix` (88, 16 bytes), `tailOffset` (104), `tailLength` (112) and `lastShardBytes` (240). If the magic is
   wrong, read the last 4096 bytes instead.

2. **Find the current key slot table.** Parse both 64 KiB tables at 4096 and 69632; take the one with the higher
   generation (offset 8) that has magic `BSLT`. Walk its records from offset 64 using each record's size field. On a
   container whose keys were never changed the two tables are identical, so either will do; if the newer one looks
   damaged, try the other.

3. **Recover the master key.** In a record, the slot type is at offset 6, the slot UUID at 8, the nonce at 24, the
   salt at 48, the Argon2id parameters at 64 (memory in KiB, passes, lanes: three 4-byte integers), the key
   commitment at 80 and the 48-byte wrapped key at 112.

   For a passphrase slot (type 1), normalize the passphrase to Unicode NFC and compute
   `KEK = Argon2id(passphrase, salt, passes, memoryKiB, lanes, 32)`. For a key file (type 2),
   `KEK = HKDF-SHA512(keyfile bytes, salt, "bond/v2/keyfile-kek", 32)`.

   Then `K_enc = HKDF-SHA512(KEK, no salt, "bond/v2/slot-enc", 32)` and `K_com` likewise with `"bond/v2/slot-com"`.
   The associated data is `T("BOND-SLOT-V2", containerUUID, slotUUID, slotType as one byte, salt, params)`, where
   `params` is the twelve parameter bytes at offset 64 for a passphrase slot and empty for a key file. If
   `HMAC-SHA256(K_com, T(nonce, aad))` is not the commitment, this is not the slot for this secret: go on to the
   next. Otherwise open the wrapped key with XChaCha20-Poly1305 under `K_enc`, the nonce and `aad`.

4. **Derive the subkeys.** `HKDF-SHA512(fmk, salt = containerUUID, info, 32)` for each of `bond/v2/data`,
   `bond/v2/manifest`, `bond/v2/header`, `bond/v2/commit`. To be sure of the key and the header before going on:
   `HMAC-SHA256(headerKey, header with bytes 208–239 zeroed)` is the 32 bytes at offset 208, and
   `HMAC-SHA256(commitKey, T("BOND-COMMIT-V2", containerUUID))` is the 32 bytes at offset 176.

5. **Decrypt the payload.** Open each shard with `dataKey`, nonce `noncePrefix ‖ LE64(i)`, and associated data
   `T("BOND-DATA-V2", containerUUID, LE64(i), LE32(shardSize))`. Concatenate the results. That is the stream followed
   by zero padding; keep the first `streamLength` bytes, where `streamLength` is the exact length in the manifest
   (step 7) – the header only has the padded one. Without the manifest, an xz decoder stops at the end of its
   stream and a tar reader at its end marker, so the padding does no harm.

   Where shard `i` begins depends on whether the container carries parity. With `parityID` 0 it is simply
   `135168 + i × shardSize`. With parity, read `k` at offset 40 and `p` at offset 44, and note that a full stripe
   occupies `k × shardSize + p × (shardSize + 16)` bytes: shard `i` is in stripe `i / k` at position `i % k`, so it
   starts at `135168 + (i / k) × stripeBytes + (i % k) × shardSize`. Every shard is `shardSize` long except the last,
   which is `lastShardBytes`. Parity shards can be ignored entirely unless something is damaged.

6. **Unpack.** The result is an xz stream (or a bare tar if the manifest says `"compression": "none"`).
   `xz -d < stream.xz | tar -xf -`. Any xz and any tar will do; there is nothing BOND-specific left at this point.

7. **The manifest**: read `tailLength` bytes at `tailOffset`, skip the 8-byte length, take the next 24 bytes as the
   nonce, and open the rest with `manifestKey` and associated data `T("BOND-MANIFEST-V2", containerUUID)`. The
   result starts with an 8-byte length `n`; the next `n` bytes are gzip, and what follows is padding. Gunzip gives
   JSON, with `streamLength`, `streamSha256` and `compression` at the top level. If that copy is damaged, the second
   one starts at `tailOffset + tailLength`. In a split container `tailOffset` is a position in the **last** volume,
   and every volume's header carries the same value.

8. **The writer**, if the container is signed (scheme 1 at offset 276) and you know whose key to expect: the
   fingerprint at 280 is the SHA-256 of that public key; the message is `T("BOND-WRITER-V2", header)` with bytes
   208–239 and 312–3684 zeroed; the first 64 signature bytes at 312 are Ed25519 over it, the remaining 3309 are
   ML-DSA-65 with context `"BOND-WRITER-V2"`. Then SHA-256 of the volume's payload slice – from 135168 in the first
   volume, 4096 in the others, for the length at offset 168 – is the 32 bytes at 244. This step needs no key.

**This procedure exists as a program.** [tools/handread](tools/handread/main.go) is these eight steps in about five
hundred lines of Go, written from this section and sharing no code with the rest of the repository: it imports
nothing of BOND's, and its only dependencies are Argon2id, XChaCha20-Poly1305, Unicode normalization, Ed25519 and
ML-DSA. Its tests
run it against a frozen container and against containers the current writer produces, with and without recovery
data, in one file and split. A constant that changed in the format without changing here would pass every other
test in the repository and fail that one, which is the reason it is kept separate.

```
go run ./tools/handread -passphrase-file pass.txt -o stream.xz backup.bond
go run ./tools/handread -keyfile usb.key backup.bond.001 backup.bond.002 | xz -d | tar -xf -
go run ./tools/handread -expect-writer writer.key.pub -passphrase-file pass.txt -o stream.xz backup.bond
```

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

Parameters are stored per slot, so a container opens with whatever it was written with. This build writes every
passphrase slot with the default profile; there is no setting for another one, and `bond bench-kdf` is a measurement
of what that profile costs on a given machine, not a way to choose. A machine that cannot spare 512 MiB for one
derivation cannot create or open a passphrase slot, and is better served by a key file or a recipient key.
