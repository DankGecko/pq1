# NIST CAVP SHA-256 byte-oriented test vectors

Official NIST Cryptographic Algorithm Validation Program (CAVP) "SHA Test
Vectors for Hashing Byte-Oriented Messages" — the SHA-256 subset.

- **Source:** <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip>
  (CAVP Secure Hashing page, "SHA Test Vectors for Hashing Byte-Oriented
  Messages").
- **Downloaded:** 2026-06-12.
- **License:** Works of the U.S. federal government (NIST) — public domain
  in the United States (17 U.S.C. § 105).

| File | Contents |
|------|----------|
| `SHA256ShortMsg.rsp` | 65 (Len, Msg, MD) vectors, Len 0..512 bits (CAVS 11.0) |
| `SHA256LongMsg.rsp` | 64 (Len, Msg, MD) vectors, Len 1304..51200 bits (CAVS 11.0) |
| `SHA256Monte.rsp` | Monte Carlo seed + 100 checkpoint digests (CAVS 11.1) |

Format notes (validated empirically before wiring in):

- Lines are CRLF-terminated.
- `Len` is the message length in **bits** (always a multiple of 8 — the
  suite is byte-oriented).
- `Len = 0` is the **empty message**: the `Msg` field still reads `00` but
  contributes zero bytes.
- The Monte Carlo file follows the SHAVS MCT: per checkpoint `j`,
  `MD[0..2] := Seed`, then 1000 iterations of
  `MD[i] = SHA-256(MD[i-3] ‖ MD[i-2] ‖ MD[i-1])`; the checkpoint is
  `MD[1002]`, which also re-seeds the next checkpoint.

Consumed by `scripts/gen_cavp_vectors.py`, which embeds all vectors into
`lean/SphincsCVerify/CavpVectors.lean` for the `lake exe verify-cavp`
conformance runner (`lean/CavpMain.lean`). Run via `make verify-cavp` in
`contracts/verification/`. These files are the suite of record — do not
edit them; if NIST revises the suite, re-download and regenerate.
