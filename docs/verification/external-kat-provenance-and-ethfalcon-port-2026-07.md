# External KAT provenance & ETHFALCON-port assessment

**Status:** reference / assessment. Written 2026-07-06.
**Question answered:** "Is there anything in the ETHFALCON repo worth porting to
PQSigner (KATs, formal verification, test discipline) — *not* the Falcon signing
scheme, which we do not adopt — and do official SPHINCS+ KATs exist online?"
**Companion:** the byte-level C10↔FIPS-205 divergence is *not* re-derived here —
see [`c10-fips205-delta-audit.md`](./c10-fips205-delta-audit.md) §5 (hash
instantiation) and §6 (ADRS). This doc adds the external-provenance and
external-repo-port layer on top of that ledger.

---

## TL;DR

1. **Official KATs exist for standardized hash-based signatures** — the round-3
   SPHINCS+ submission and SLH-DSA/FIPS-205 (NIST ACVP) — **but none apply to
   C10.** Not just because of WOTS+C/FORS+C: C10's entire SHA-256 tweakable-hash
   + ADRS instantiation is a bespoke, EVM/word-aligned re-encoding that shares
   **only raw SHA-256** with the standard. Confirmed 2026-07-06 by fetch-verified
   web research + an adversarial re-read of `hash.rs`/`address.rs` against the
   `sphincs/sphincsplus` reference C (6 independent divergences, confidence high).
2. **The one official anchor that *does* apply — NIST CAVP SHA-256 — is already
   in the repo** (`contracts/verification/cavp/`, 229/229 via `make verify-cavp`).
   Everything above SHA-256 in C10 has, and can have, **no external standard
   reference** — not even our own upstream `nconsigny/SPHINCS-` produces a
   byte-matching KAT (we swapped keccak→SHA-256 and use a different `ht_idx`
   encoding). The only viable external cross-check is an *independent
   re-implementation of the exact C10 byte spec* — which we already have
   (`contracts/verification/scripts/independent_c10_signer.py`).
3. **Formal verification: nothing to port — we are far ahead.** ETHFALCON ships
   *zero* FV (no SMTChecker / Halmos / Certora / Kontrol; just `forge test` +
   a spec doc + EIP-8052). Our Lean model↔spec proofs, Kani, mutation testing and
   adversarial-review kit dominate.
4. **What *is* worth porting is ETHFALCON's test-vector *discipline* for its own
   non-standard variants** (ETHFALCON/EPERVIER are in our exact position). Two
   concrete, additive levers — (R1) per-primitive component KATs, (R2) a portable
   `.rsp`-style artifact — plus a provenance statement (R3). Details in §5.

---

## 1. The literal question — do official SPHINCS+/SLH-DSA KATs exist online?

Yes. All rows below were **fetch-verified** on 2026-07-06 (WebFetch, not cited
from memory) unless marked otherwise.

| Source | URL | Verified | Format / granularity | Applies to C10 |
|--------|-----|----------|----------------------|----------------|
| SPHINCS+ round-3 reference | `github.com/sphincs/sphincsplus` | ✅ fetched | Ships the NIST generator `PQCgenKAT_sign.c` + `vectors.py` + `SHA256SUMS`; `.rsp` **not checked in** — `make` regenerates `PQCsignKAT_*.rsp` (`count/seed/msg/pk/sk/sm`) for all 36 instances (sha2·shake·haraka × 128·192·256 × s·f × simple·robust). **Whole-signature only.** | ❌ |
| SPHINCS+ round-3 submission zip | `sphincs.org/data/sphincs+-round3-submission-nist.zip` | ⚠️ URL confirmed via search, **not** directly fetchable (binary zip + malformed HTTP header on sphincs.org) | The archive that historically ships the pre-built per-parameter-set `.rsp` files. Whole-signature. | ❌ |
| **SLH-DSA / FIPS-205 (NIST ACVP)** | `github.com/usnistgov/ACVP-Server` → `gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205` | ✅ fetched (incl. `sigGen/prompt.json`) | ACVP JSON (`prompt` / `expectedResults` / `internalProjection`); all 12 sets (SHA2·SHAKE × 128·192·256 × s·f); deterministic + non-deterministic; pure + preHash. **Whole keygen/sign/verify only — no WOTS/FORS/thash intermediates.** | ❌ |
| Project Wycheproof | `github.com/C2SP/wycheproof` | ✅ fetched | **Negative:** covers ML-DSA (Dilithium) + ML-KEM (Kyber) only. **No SLH-DSA / SPHINCS+ vectors exist.** | ❌ |
| NIST CSRC example values | `csrc.nist.gov/.../example-values` | ✅ fetched | **Negative:** signature section lists DSA/RSA/ECDSA only; no SLH-DSA example/intermediate file. | ❌ |

**Critical provenance finding:** every official suite is **whole
keygen/sign/verify** granularity. **No standards body (sphincs reference, NIST
ACVP, NIST CSRC) publishes per-primitive intermediate-value KATs** for a single
tweakable-hash `F/H/T` call, one WOTS+ chain, or a FORS tree. Only *unofficial*
third-party walkthroughs show intermediates (e.g. `di-mgt.com.au` "SPHINCS+
Example", `asecuritysite.com` FIPS-205). Any team validating a custom variant
**must self-generate** primitive-level vectors and cross-check them across its
own independent implementations — there is no external suite to download.

---

## 2. Why no official KAT anchors C10 (summary — detail in the delta-audit)

The 2026-07-06 adversarial verify agent read `sphincs-c10/src/hash.rs` +
`address.rs` and compared against the `sphincs/sphincsplus` reference C
(`ref/sha2.c`, `ref/hash_sha2.c`, `ref/sha2_offsets.h`; corroborates FIPS-205
§11.2). Verdict: **`c10_hash_layer_matches_any_standard = false`, confidence
high**, on six independent points:

| Aspect | C10 | FIPS-205 SHA-2 (cat 1) |
|--------|-----|------------------------|
| PK.seed padding | to **32 B** (`pad16`), then 32-B ADRS | to a **full 64-B block** (`toByte(0,48)`) → precomputed midstate |
| ADRS | **full 32 B**, u64 tree, 4-B layer/type | **compressed 22 B ADRSc**, 1-B layer/type, 8-B tree |
| `F`/th preimage | `sha256(pkseed₃₂‖adrs₃₂‖val₃₂)[0..16]` | `sha256(PK.seed‖0⁴⁸‖ADRSc₂₂‖M)[0..16]` |
| `H_msg` | single `sha256(seed‖root‖R‖msg‖0xFF×32)` | `MGF1-SHA256(R‖PK.seed‖SHA256(R‖PK.seed‖PK.root‖M))` |
| `PRF` (sk deriv) | `sha256(sk_seed‖"wots"/"fors"‖…)` ASCII tags | `sha256(PK.seed‖0⁴⁸‖ADRSc‖SK.seed)[0..16]` |
| scheme / params | WOTS+C count-grind (`w=8,l=43,target_sum=205`) | WOTS+ checksum (`w=16`), FIPS parameter sets |

Any one row alone breaks byte-compatibility. **The only shared building block is
raw SHA-256** (FIPS 180-4, black-box via `sha256_bytes`) — and that is already
anchored to NIST CAVP. See delta-audit §5/§6 for the line-grounded map; this
section is the external-provenance confirmation of that ledger.

**Provenance of the variant** (for the record):
- Academic origin: *SPHINCS+C* — Hülsing et al., IACR ePrint **2022/778**
  (WOTS+C / FORS+C); WOTS+C/FORS+C family also ePrint 2025/2203; few-time bound
  Fluhrer-Dang ePrint 2024/018. A public code fork located by the web research:
  `github.com/eyalr0/sphincsplusc` (fork of the official reference; six named
  instances, all `w=16`, primarily SHAKE — **does not compute over C10 params**).
- **Our actual lineage:** `github.com/nconsigny/SPHINCS-` (C10 commit `0516a11`,
  2026-04-09; upstream retired C10 for C13 — **PQSigner is C10's only active
  user**). We swapped keccak→SHA-256 and use a *different* `ht_idx` binding
  encoding, so **even our own upstream is byte-incompatible** with our C10.

Net: C10 is byte-unique to PQSigner above SHA-256. No downloadable KAT — from
NIST, from the SPHINCS+ reference, or from either SPHINCS+C fork — can validate
it. This is a structural fact, not a gap to close.

---

## 3. What we already have (current C10 test/vector posture)

| Artifact | What it anchors |
|----------|-----------------|
| `contracts/verification/cavp/SHA256{Short,Long}Msg.rsp` + `Monte.rsp` | **Official** NIST CAVP SHA-256 (the one applicable standard anchor), `make verify-cavp` |
| `contracts/smart-wallet/test/c10_test_vectors.json` (12 whole-sig vectors: 10 base + 2 near-miss +C-gate negatives) | Cross-consumed by Rust `verify`, Yul `SPHINCsC10Asm.t.sol::test_verifyAllKatVectors`, and Lean `SphincsCVerify/KatVectors.lean` |
| `sphincs-c10/tests/gen_test_vectors.rs` (deterministic keypair, `--features near-miss-gen`), `gen_bulk_vectors.rs` (SplitMix64 corpus) | Documented, reproducible generators |
| `contracts/verification/scripts/independent_c10_signer.py` + `tests/independent_signer_xcheck.rs` | **Clean-room** Python signer written from the Yul spec (not transliterated from Rust); reproduces the KAT vectors AND signs fresh msgs accepted by Rust `verify` → implementation diversity over the shared C10 byte-spec |
| Lean `execC10Asm_eq` model↔spec ∀ proof (A3.1) | Internal consistency of the Yul verifier vs its functional spec |

**Assessment:** for a byte-unique construction with no external reference, this
is already a strong, arguably *more* rigorous posture than ETHFALCON's for its
non-standard variants (we add Lean model↔spec, which ETHFALCON lacks entirely).
The gaps are narrow and specific — see §5.

---

## 4. ETHFALCON — what it does, and what's worth porting

ETHFALCON is *itself* in our position for its own non-standard EVM variants
(ETHFALCON = SHAKE→keccak, EPERVIER = recovery). Its discipline for those is the
template worth studying; the parts tied to Falcon's math (NTT, `hash_to_point`,
Gaussian `samplerz`) are not transferable.

| ETHFALCON discipline | Where | Our status |
|----------------------|-------|-----------|
| Unmodified core anchored to **official NIST KATs** | `test/falcon512-KAT.rsp`, `falconKATS.t.sol`, `test_nist_kat_files.py` | ✅ analogue in place — CAVP SHA-256 is the only unmodified core we share; nothing above it is standard |
| Non-standard variant: **self-generate `.rsp` reusing the NIST `.req` deterministic inputs**, documented generator | `pythonref/scripts/generate_kat_rsp.py` → `test/ethfalcon512-KAT.rsp` | ◑ we self-generate (JSON) but not in a portable `.rsp` + standalone-parser form → **R2** |
| **Component/sub-primitive KATs with intermediate values**, run BOTH off-chain and on-chain, standard + variant golden values side by side | `test_hash_to_point_KAT.py` (`expected_hash_NIST` vs `_RIP`); `HashToPoint{NIST,EVM}Vectors.t.sol` | ✗ **gap** — we KAT whole signatures only, not tweakable-hash boundaries → **R1** |
| **N independent implementations over one spec** | Python + C-ref + Solidity + Go (`test/go/`) | ✅ Rust + independent-Python + Yul + Lean-model (≥ theirs; Lean is stronger than a 4th runtime) |
| Formal verification | — (none) | ✅ we dominate (Lean model↔spec, Kani, mutation, adversarial-review) |
| AES-CTR-DRBG KAT harness (`katrng.c`) | `falcon/nistfalcon/KAT/` | ✗ **do not port** — our keygen is BIP-39/HMAC/sha256-seeded, not NIST-DRBG-seeded; port the *principle* (documented deterministic seed→vectors), which we already have |

---

## 5. Recommendations (prioritized)

**R1 — [Medium] Per-primitive component KAT golden vectors. ✅ LANDED 2026-07-06.**
Committed golden `contracts/smart-wallet/test/c10_primitive_kat_vectors.json` (26
vectors across all 8 primitives), cross-checked THREE ways: Rust
`sphincs-c10/tests/primitive_kat.rs` (recompute regression pin), the clean-room
`independent_c10_signer.py --check-primitives` (independence guard), and the Yul
verifier's on-chain SHA-256 layout `contracts/smart-wallet/test/C10PrimitiveKat.t.sol`
(the 6 verify-side primitives via precompile 0x02). `make -C contracts/verification
verify-primitive-kat` runs all three; a corrupted golden byte was verified to fail
all three legs (non-vacuity). Original spec follows. — Add standalone
intermediate-value vectors for each tweakable-hash boundary
(`th`, `th_pair`, `th_multi`, `h_msg`, `chain_hash`, `wots_secret`,
`fors_secret`, `wots_digest`) — input words → 16/32-byte output — cross-checked
**Rust ↔ `independent_c10_signer.py` ↔ Yul**. This is ETHFALCON's
`HashToPoint-KAT` discipline applied to our hash layer. **Value is localization /
auditor-ergonomics, not new coverage:** the existing whole-sig differential
(`verify-interp` 396-vector corpus + `independent_c10_signer.py`) and the
`check_c10_transcription.py` positional lint already *catch* a per-primitive
divergence — R1 tells you *which* primitive/offset diverged (instead of a
4008-byte haystack) and lets an auditor check one boundary without running the
stack. Concrete precedent: the A3.1 `chain_hash` bug (the Lean spec wrote the
ADRS `chain_index` field instead of `chain_pos`; delta-audit §9 / work-todo
`1257`) is exactly the class a `chain_hash` intermediate-value KAT pins directly.
(The `fcee705a` shared-FORS-forest bug is *not* a good example — it is a
`ht_idx`-binding design flaw already covered by `fors_position_binding.rs`, which
a fixed-input primitive KAT catches only if it deliberately varies `ht_idx`.)
Pure additive test rigor — no new dependency, no production change. Honest scope:
**self-generated + internally N-way cross-checked**, *not* externally conformant
(no official per-primitive KAT exists — §1). Add
`sphincs-c10/tests/primitive_kat.rs` + the per-primitive Yul asserts.

**R2 — [Medium] Portable `.rsp`-style vector artifact + standalone parser.**
Emit the C10 golden vectors (whole-sig + R1 primitives) into a documented,
self-describing text artifact decoupled from the JSON/Lean/Solidity harnesses,
with a ~30-line standalone parser (à la `test_nist_kat_files.py::parse_kat_rsp`).
An external auditor can then consume/regenerate vectors without our toolchain.
Modest effort; improves auditability of the "self-generated because no standard
exists" story.

**R3 — [Low] Provenance statement.** This doc + delta-audit §5/§6 already state
it; ensure any external/marketing claim says **"SPHINCS+C variant, parameter set
C10 — not FIPS-205/SLH-DSA"** and that KAT coverage above SHA-256 is
self-generated + N-way cross-checked by design.

**Formal verification — nothing to port.** Complementary framing to keep: the
Lean model↔spec proofs establish *internal* consistency (code matches its spec);
the KAT / cross-implementation layer establishes *external* SHA-256 conformance
(CAVP) + *implementation agreement* across Rust/Python/Yul. Proofs cannot catch a
spec that faithfully implements a non-standard thing — which is exactly why the
CAVP anchor + independent-signer diversity matter even with all our FV.

**Do NOT port:** the Falcon signing scheme (explicit non-goal); `katrng.c`
AES-CTR-DRBG harness (wrong seeding model for us); a 4th runtime re-implementation
(the Go leg) — our Lean model is the higher-value 4th artifact.

---

## Appendix — verified sources & method

- Web research + adversarial source-read run 2026-07-06 (workflow
  `wf_75c3e17f-3f6`, 4 general-purpose agents, all fetch-verified).
- Official KAT suites: `github.com/sphincs/sphincsplus`;
  `github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-*`;
  `github.com/C2SP/wycheproof` (negative); NIST CSRC example-values (negative).
- FIPS-205 SHA-2 instantiation cross-checked from `sphincs/sphincsplus` `ref/`
  (`SPX_SHA256_ADDR_BYTES=22`, 64-byte seed block, MGF1 `H_msg`, HMAC `PRF_msg`).
- Variant lineage: ePrint 2022/778 (SPHINCS+C); `github.com/eyalr0/sphincsplusc`
  (public fork); `github.com/nconsigny/SPHINCS-` (our C10 origin — see delta-audit
  addendum 2026-06-12).
- Byte-level C10↔FIPS-205 divergence: **`c10-fips205-delta-audit.md` §5/§6** (do
  not duplicate here).
