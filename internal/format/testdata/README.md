# BOND format 2.0 known-answer vectors

`v2-vectors.json` freezes byte-level results for the format: the tuple encoding
and Padmé lengths; key derivation, commitment and AAD domains; a shard and a
key-file slot sealed with every random input fixed, so encryption is checked
byte for byte and not only decryption; the key a passphrase gives in either
Unicode form; header and slot-table MACs and serialization; recipient public
material and recovery-card text; sealed manifest framing; and Reed-Solomon
parity layout.

Inputs are deliberately patterned, public test values. `tools/fixtures`
documents how the candidate file was produced. `vectors_test.go` reconstructs
each deterministic object and opens the frozen randomized manifest frame.
Changing a vector requires an intentional format-version decision and review,
not merely regeneration after an implementation change.

## What this does not prove

These vectors are produced and consumed by the same Go constants, so they catch
drift between a version of BOND and this file. They cannot catch a change made
consistently in both: if a constant moves and the vectors are regenerated to
match, the tests still pass.

That gap is closed elsewhere. [tools/handread](../../../tools/handread/main.go)
is a decoder written from NERDME.md alone that imports nothing of BOND's, and
its tests read both `internal/container/testdata/v2-golden.bond` – a container
nobody can regenerate byte for byte – and containers the current writer
produces. A decoder in another language would be a stronger check still, and
does not exist.
