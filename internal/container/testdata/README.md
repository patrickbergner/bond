# Immutable BOND format 2.0 fixture

`v2-golden.bond` is a frozen container written by the format 2.0 implementation
on 2026-11-13. It is intentionally checked in and must not be regenerated merely
to make a compatibility test pass.

- SHA-256: `2d16b133d11e02f0172708801059d7529535ec858a05761bf553043616bd2305`
- Passphrase: `bond-v2-fixture-passphrase` (test credential; never use it for real data)
- Key file: the 32 bytes `30 31 32 … 4f` (also a test credential)
- KDF: Argon2id, 8192 KiB, 1 pass, 1 lane
- Shards of 4096 bytes, recovery data at 50% (stripes of 8 + 4), so the payload
  spans more than one stripe
- Archive: directory `fixture`, `fixture/hello.txt` and `fixture/pattern.bin`
- `hello.txt`: `BOND format 2.0 compatibility fixture` followed by LF
- `pattern.bin`: 40 000 bytes, byte `i` being `i ^ (i >> 8) ^ (i >> 16)`

Two readers are held to it: BOND's own (`golden_test.go`) and
[tools/handread](../../../tools/handread/main.go), which shares no code with BOND
and decrypts it from the procedure in NERDME §11.

The provenance generator is `tools/fixtures`. It creates a candidate fixture;
review its binary/hash diff and update this record only for a deliberate format
revision.

It cannot reproduce this file. Every container gets a random master key, UUID and
nonce prefix, random per-slot salts and nonces, and a creation timestamp of "now",
so a second run produces a different container with a different hash. That is the
point rather than a shortcoming: a fixture nobody can regenerate is one the reader
has to actually read, which is what makes it a guard against writer and reader
drifting together. It also means the provenance of these bytes is this record and
the committed hash, and nothing else — and that `tools/fixtures` overwrites the
committed fixture in place, with no confirmation, if it is ever run in this tree.

Manual recovery drill:

```text
bond inspect internal/container/testdata/v2-golden.bond
bond verify internal/container/testdata/v2-golden.bond --passphrase bond-v2-fixture-passphrase
bond restore internal/container/testdata/v2-golden.bond --to ./fixture-restore --passphrase bond-v2-fixture-passphrase
```

Confirm that `fixture-restore/fixture/hello.txt` has the contents listed above.
The command-line credential warning is expected for this public test artifact.
