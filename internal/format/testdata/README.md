# BOND format 1.0 known-answer vectors

`v1-vectors.json` freezes byte-level results for the format's key derivation,
commitment and AAD domains; header and slot-table MACs/serialization; recipient
public material and recovery-card text; sealed manifest framing; and
Reed-Solomon parity layout.

Inputs are deliberately patterned, public test values. `tools/fixtures`
documents how the candidate file was produced. `vectors_test.go` reconstructs
each deterministic object and opens the frozen randomized manifest frame.
Changing a vector requires an intentional format-version decision and review,
not merely regeneration after an implementation change.

## What this does not prove

These vectors are produced and consumed by the same Go constants, so they catch
drift between a version of BOND and this file. They cannot catch a change made
consistently in both: if a constant moves and the vectors are regenerated to
match, the tests still pass. Closing that gap needs a decoder written from
NERDME.md alone, ideally in another language, and one does not exist yet.
`internal/container/testdata/v1-golden.bond` is the stronger guard, because a
container nobody can regenerate byte-for-byte has to be read as it is.
