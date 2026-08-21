# Immutable BOND format 1.0 fixture

`v1-golden.bond` is a frozen container written by the format 1.0 implementation
on 2026-08-21. It is intentionally checked in and must not be regenerated merely
to make a compatibility test pass.

- SHA-256: `8b8adec670fcbc01207515d51dec7354a420ac0fe6908c4efc001961731c1d07`
- Passphrase: `bond-v1-fixture-passphrase` (test credential; never use it for real data)
- KDF: Argon2id, 8192 KiB, 1 pass, 1 lane
- Archive: directory `fixture` and `fixture/hello.txt`
- File contents: `BOND format 1.0 compatibility fixture` followed by LF
- File SHA-256: `94420b37fa779197699a5d4ca9312c9f8c329361d523686762c5d5297d1d1b96`

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
bond inspect internal/container/testdata/v1-golden.bond
bond verify internal/container/testdata/v1-golden.bond --passphrase bond-v1-fixture-passphrase
bond restore internal/container/testdata/v1-golden.bond --to ./fixture-restore --passphrase bond-v1-fixture-passphrase
```

Confirm that `fixture-restore/fixture/hello.txt` has the contents and digest
listed above. The command-line credential warning is expected for this public
test artifact.
