# Firmware bounded / property verification — SOTA + first slice (2026-06-29)

Scope: the *firmware* (Rust, `no_std`, `thumbv8m`) — **not** the contracts (already
covered by Halmos/Kontrol) and **not** the SPHINCS+ signing kernels (functionally
proven on the Aeneas→Lean track; the heavy SHA-256 cores choke Charon/Aeneas and
are deliberately out of scope here — see `contracts/verification/aeneas-probe/UPSTREAM_ISSUES.md`).
This doc decides *where* to point bounded/property verification, *which* tool, and
the concrete first slice. It is a decision record, not a tool advertisement.

Evidence tiers used below: **[code]** = read in-tree this pass; **[tool]** = ran the
binary; **[lit]** = 2024–2026 external source; **[claim]** = asserted, not yet executed.

---

## Bottom line

**First slice: `secure/src/tx/eip712/safe/multi_send.rs :: decode_multisend`, with
Kani, proving canonical-acceptance** — `decode_multisend(data) == Ok(payload) ⟹`
`data` is byte-exactly `MULTI_SEND_SELECTOR ‖ offset_word(==0x20) ‖ len_word(==payload.len())
‖ payload ‖ zero-pad-to-32`, nothing after, all padding zero. This is the repo's own
already-filed highest-ROI move (`contracts/verification/docs/FV_VALUE_AND_GAPS.md`
line 149 / `work-todo.md` §34: *"extend the Rust↔Lean differential + Kani to the
clear-signing decoders + counter arithmetic — the surfaces where the real HIGHs lived"*) **[code]**,
it is days-not-months, the tooling is already installed and CI-wired (`make kani`,
Kani 0.67.0 **[tool]**), and it lands precisely on the trusted-display / WYSIWYS path
that `FAITHFULNESS_AUDIT_2026-06-14.md` enumerates as **NOT COVERED** by the Lean
theft-freedom proof — the declared blind spot where all three audited HIGHs occurred.
It proves the *soundness* direction (accept ⟹ canonical), which forecloses the code's
own documented `BadPadding` "second, undisplayed payload interpretation" class over
**all** symbolic calldata, not the ~30 example unit-test inputs. **Move sequence after
slice 1:** (2) NS-pointer complete-bounds Kani proof (loop-free → genuinely *unbounded*,
resolves the documented `usize > u32` truncation residual) plus a zero-harness
`-Zmiri-tree-borrows` pass added to `make miri`; (3) a `revm`/MultiSendCallOnly
bytecode differential over the **inner** record loop (`MsRecordIter`) — the one layer
Kani-on-`decode_multisend` and round-trip injectivity structurally cannot close,
because the packed-record walk mirrors MultiSendCallOnly's hand-rolled assembly, not
standard ABI.

---

## Why multiSend framing and not the other surfaces

Decompose the multiSend WYSIWYS guarantee into **four layers** — this is what keeps
slice 1 from overclaiming:

| Layer | Code | Closed by | When |
|-------|------|-----------|------|
| 1. Outer ABI framing | `decode_multisend` + `read_u32_word` | **Kani canonical-acceptance** | **slice 1a** |
| 2. Inner packed-record walk | `MsRecordIter::next` | Kani framing soundness **+** `revm` differential | slice 1b / move 3 |
| 3. Record classification | `summarize` / `classify_record_kind` | (drags `cow_binding`) later slice | deferred |
| 4. Renderer page budget | `records_pages_total` ↔ `safe_display` | host-extract renderer (not yet) | deferred |

The outer layer (1) genuinely *closes* on-chain fidelity: Solidity's permissive
calldata decode (issue #11240, overlapping/negative tail pointers) only bites
**non-canonical** inputs, which `decode_multisend` refuses and the firmware therefore
never signs — so canonical-acceptance ⟹ unambiguous on-chain decode, no oracle
needed. **[code/lit]** Layer 2 is where a `revm` oracle earns its keep (the inner loop
is not standard ABI). Layers 3–4 are out of slice-1 extraction scope on purpose.

**Honesty note on the three enumerated HIGHs.** The HIGHs in `FV_VALUE_AND_GAPS.md`
(`approveHash` length-bypass; ERC-20 metadata mis-attribution via `v1_ms`; wrong
`decimals`) live in `display/value_page.rs`, `display/mod.rs`, `eip712/safe/verify.rs`,
`safe_display.rs` — **layer 3/4 territory**, not `decode_multisend`. **[code]** Slice 1
does **not** retroactively catch them. It closes the *framing* class (the
`BadPadding` second-payload comment) and prevents that class's regression; the
classification HIGHs are later slices that require extracting `summarize`/the
renderer (and accepting the `cow_binding` cascade).

---

## Ranked tool × surface matrix

Surfaces: **(1)** clear-sign / WYSIWYS decoders · **(2)** off-chain page-123 counter
arithmetic · **(3)** NS-pointer validation/deref · **(4)** unsafe taxonomy.
Effort: days / weeks / months. ROI relative to *where the HIGHs were*.

| Tool | Surface | Fit | Property proven | Effort | ROI | Key limit (what it CANNOT do) |
|------|---------|-----|-----------------|--------|-----|-------------------------------|
| **Kani** 0.67 (installed, CI) | (1) decoders | **best** | canonical-acceptance / no-misdecode; panic/OOB/overflow free, ∀ inputs ≤ N | **days** | **high** | bounded (N + `unwind`); crypto stubbed; no MMIO/asm/veneers |
| **Kani** | (3) NS-ptr *bounds* | **best** | accept ⟹ no `ptr+len` overflow ∧ range ⊆ NS region ∧ disjoint mailbox — **loop-free → unbounded** | days | **high** | TT/SAU check is host-stubbed `true` → proves arithmetic, not the SAU re-classification (TOCTOU half) |
| Kani | (2) counter *gate* | partial | combined-cap monotonic, fail-closed, overflow-free (extract `check_offchain_gate`) | days | med | **misses the actual HIGH** — torn-compaction rollback is below the seam in `flash.rs::compact_page`, needs a crash model |
| **Miri** (installed, CI) | (4) unsafe / (3) deref | **best (UB only)** | `static mut`/raw-ptr/FI-volatile free of OOB/uninit/aliasing/provenance UB; deref-JOIN: validate ⟹ deref in-bounds | weeks | high | UB only, not logic; existing `make miri` ns_ptr pass **never calls the deref methods** (false coverage); cat-1/3 MMIO+asm cfg'd out |
| **bolero/`arbitrary` + `revm`** | (1) layer-2 fidelity | strong | inner-loop accept ⟹ on-chain MultiSendCallOnly executes the same record set; round-trip injectivity | weeks | high | self-canonical + alloy share firmware framing assumption — only `revm` is faithful for the inner loop; verifies the *extracted copy* |
| **Creusot** (deductive) | (1) decoders | partial | accept-set **==** canonical-ABI accept-set; decode-determinism — the on-target functional spec Kani can't *express* | **months** | high (upgrade path) | safe-Rust only; needs extraction + hand loop invariants; young-verifier soundness caveat |
| **Verus** | (2) counter, unbounded | partial | unbounded counter monotonicity over `unsafe` flash store — the only tool reaching the rollback HIGH's home | months | med | `verus!`-dialect rewrite + custom toolchain; large effort for one surface |
| **Flux** (refinement) | (1)/(2) bounds | weak | array-bounds + integer-overflow, "all inputs" | weeks | **low** | none of the 3 HIGHs lived in bounds/overflow; formats already length-bounded (≤6 recs, `data_len`≤4096, caps<65536) so Kani covers the real input space; safe-only |
| Prusti / Crux-mir / MIRAI | — | skip | — | — | — | Prusti dominated by Creusot; Crux-mir dominated by Kani; MIRAI last release ~Aug 2024 (unmaintained) |
| cargo-checkct / dudect / Muscat | side-channel | adopted | constant-time on the shipped M33 binary (`make checkct`) | — | — | disjoint property class; says nothing about accept-set or counter state |

---

## First slice — exact recipe

### Target
`secure/src/tx/eip712/safe/multi_send.rs :: decode_multisend` (lines 148–211) **[code]**,
helper `read_u32_word` (132–139). Property = **canonical-acceptance (soundness
direction)**.

### Isolation seam (host-verifiable without hardware)
`sphincs-tz-secure` is a **binary crate with no lib target** that flips to `std` only
under `cfg(test)`; `cargo kani -p sphincs-tz-secure` cannot consume a `no_main`
binary. **[code/tool]** Follow the repo's own pure-logic-crate + re-export-shim pattern
(exactly how `erc20`/`names`/`selectors` were extracted):

1. Move **only** `decode_multisend` + `read_u32_word` + `enum MsError` into
   `pqsigner-tx` (next to the ERC-20 decoder it already neighbours). Verified
   dependency closure: **only** `proto::{MULTI_SEND_SELECTOR, MULTISEND_MAX_RECORDS}`
   — no hashing, no `cow_binding`. **[code]**
2. `secure/src/tx/eip712/safe/multi_send.rs` re-exports them (shim).
3. `MsRecordIter` (213–290) is **also** `cow_binding`-free — deps are
   `MS_RECORD_HEADER_LEN`, `read_u32_word`, `MsError`, `MsRecord` **[code]** — so it
   extracts cleanly as **slice 1b**. Do **not** pull `summarize` / `classify_record_kind`
   / `records_pages_total`: those drag in `cow_binding` / `mgmt_decode` / `erc20`.

`pqsigner-tx` already has the `cfg(kani)` check-cfg lint and is wired into `make kani`. **[code]**

### Harness shape (anti-vacuity is the whole game)
Assert the postcondition **only in terms of the input slice and the returned
payload** — never internal intermediates, or you re-check the function against itself.
`68 = 4 (selector) + 32 (offset word) + 32 (length word)`.

```rust
#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    #[kani::proof]
    #[kani::unwind(33)] // 28-byte read_u32_word scan + ≤32-byte pad scan + 1
    fn decode_multisend_canonical() {
        const N: usize = 160; // ≤ ~2 records; sizes BOTH unwind and SAT formula
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let s = &data[..len];

        if let Ok(payload) = decode_multisend(s) {
            // payload is borrowed from s, so address/content equality is free.
            // The non-vacuous content: the four guards are JOINTLY sufficient
            // to admit ONLY the unique canonical Solidity encoding.
            assert_eq!(s.len(), 68 + next_mult_32(payload.len()));        // exact length
            assert_eq!(&s[4..8],  &[0,0,0,0]);                            // offset word hi bytes …
            assert_eq!(read_u32_word(&s[4..36]).unwrap(), 32);           // offset == 0x20
            assert_eq!(read_u32_word(&s[36..68]).unwrap(), payload.len()); // length word == payload len
            // trailing pad bytes are all zero
            let pe = 68 + payload.len();
            for b in &s[pe..s.len()] { assert_eq!(*b, 0); }
        }
    }

    // Negative control — a green run must STILL reject this (no spurious pass):
    #[kani::proof]
    fn decode_multisend_rejects_trailing_byte() {
        // canonical frame for an empty payload is 68 bytes; +1 trailing byte ⟹ Err
        let mut buf = [0u8; 69];
        buf[..4].copy_from_slice(&MULTI_SEND_SELECTOR);
        buf[35] = 32;            // offset == 0x20
        // length word == 0, payload empty, one extra byte at [68]
        assert!(decode_multisend(&buf).is_err());
    }
}
```

`next_mult_32` is the in-crate `payload.len().next_multiple_of(32)` (no encoder, no
`alloc` — the `test_util::encode_multisend` reference is `#[cfg(test)]+alloc` and
**cannot** be the Kani reference, which is why the first property is the
assert-structure form, with round-trip injectivity deferred to the bolero slice).

### Property delivered
Soundness: **accept ⟹ canonical** ⟹ the on-device decode can never structurally
disagree with on-chain decoding, and no hidden trailing second payload can ride a
DELEGATECALL batch the user blind-confirms. Completeness (canonical ⟹ accept) is a
separate, lower-severity property (a false-reject is refuse-to-sign, not a forgery)
and is **not** claimed by this slice. Panic/OOB/overflow-freedom falls out for free as
Kani's default checks on every harness.

### Expected failure modes / sizing
- `unwind` too low ⟹ Kani fails **loudly** with an "unwinding assertion" (a soundness
  guard — never a silent pass). Set ≥ max loop iters + 1; the 28-byte zero-scan in
  `read_u32_word` plus the pad scan dominate.
- `N` drives **both** the loop unwind and the SAT formula size. Keep N ≈ 160–192
  (≤2 records); an over-large N silently fails to terminate rather than erroring.
- Pick the property deliberately: `decode_multisend` is written defensively enough
  that panic-freedom is almost surely already true — the *low-value free rider*. The
  HIGH was framing/canonicity confusion; the negative-control proof is what makes a
  green non-vacuous.

---

## Setup cost

| Item | Status |
|------|--------|
| Kani 0.67.0 | **installed**, `make kani` (Makefile:3693) runs 4 crates / 6 harnesses, CI-gated (`nightly.yml`) **[tool]** |
| Miri | **installed**, `make miri` runs `pqsigner-fi` + `pqsigner-tx-core` + `sphincs-tz-secure -- ns_ptr ptr_validate`, CI-gated (`ci.yml`) **[code]** |
| Toolchain | `nightly-2026-04-06` (`rust-toolchain.toml`) + `thumbv8m.main-none-eabi`; host nightly for Miri **[code]** |
| `cfg(kani)` registration | already in `pqsigner-tx` `Cargo.toml` (`unexpected_cfgs = check-cfg=["cfg(kani)"]`) **[code]** |
| **Makefile addition** | one line: `cargo kani -p pqsigner-tx --harness decode_multisend_canonical` into the `kani:` target |
| **Code change** | extract 3 items (`decode_multisend`, `read_u32_word`, `MsError`) to `pqsigner-tx`; leave a re-export shim in `secure` |
| Move-2 Miri step-0 | add a second `-Zmiri-tree-borrows` invocation to `make miri` — **zero harness**, immediate |

No new tool acquisition for slices 1–2. The bolero/`revm` differential (move 3) needs
the already-`workspace.exclude`'d `fuzz/` workspace + a `revm` dev-dep — weeks, gated
out of firmware builds the same way `fuzz_props.rs` is.

---

## What we deliberately do NOT do

- **No full Aeneas/Charon extraction of the SHA-256 / SPHINCS+ kernels.** Tooling-gated
  (`aeneas-probe/UPSTREAM_ISSUES.md`); the signing path is already functionally proven
  on the Lean track. Bounded/property verification stays on decoders + arithmetic by
  design.
- **No Kani on the off-chain *persistence* HIGH.** The torn-compaction cap-rollback
  lives in `secure/src/hw/flash.rs::compact_page` (residual noted ~:1554), **below** the
  pure-arithmetic seam at `cmd_sign_offchain.rs:316–341`. **[code]** Kani on the extracted
  `check_offchain_gate` proves fail-closed monotonicity but would **not** have caught
  the historical bug — that needs a power-loss/torn-write crash model (heavy) or Verus
  over the unbounded `unsafe` store (months, off-target). We extract the gate as a
  fail-closed *regression* guard and state the limit, not as a bug-finder.
- **No Flux as the HIGH-targeting pick.** Its only coverage beyond already-adopted Kani
  is bounds/overflow — a class where none of the three HIGHs lived — and the wire
  formats are length-bounded by construction, so its "proves it for ALL inputs"
  headline is largely illusory here. Cheap defense-in-depth pilot at most.
- **No Verus counter rewrite now.** Months of `verus!`-dialect rewrite for one surface;
  revisit only if the flash crash-consistency property becomes ship-blocking.
- **No claim that slice 1 closes multiSend WYSIWYS end-to-end.** It closes layer 1
  (outer framing). Layer 2 (inner record loop on-chain fidelity) needs move 3's `revm`
  differential; layers 3–4 (classification + renderer page budget) are later slices.
- **No re-pitch of Miri adoption.** Miri is already in `make miri`; the honest framing
  is "the deref `unsafe` is currently *unverified* — the existing ns_ptr pass exercises
  validation arithmetic only, never `read_into_slice`/`as_slice`/`write_from_slice`",
  and the deliverable is *extending* it (the arena-seam deref-JOIN, a separate weeks-item).
- **Renderer residual flagged, not yet touched.** `records_pages_total` (the per-record
  page budget) vs the `#[cfg(not(test))]` `safe_display` emitter is the highest
  *uncovered* WYSIWYS residual in the file — its own test comment (multi_send.rs ~:995)
  warns the renderer has no host test, so a page-count drift could silently drop/blank a
  signed page. **[code]** It needs a separate renderer host-extraction; out of slice-1 scope.

---

## Cross-references

- `contracts/verification/docs/FV_VALUE_AND_GAPS.md` — gap §"two genuinely-uncaptured
  gaps" #1; line 149 files *this exact move* (Kani + Rust↔Lean differential on
  decoders + counter). This doc is its execution plan.
- `docs/verification/security-tooling-sota-2026-06.md` — the broader 2026-06 tool survey
  (Kani/Miri/cargo-checkct adopt-now; Flux pilot). This doc narrows it to *firmware
  decoders* and a first slice.
- `secure/src/fuzz_props.rs` + `fuzz/fuzz_targets/` (11 targets) — existing proptest /
  cargo-fuzz panic-resistance on the pure crates. **Neither covers multiSend or the
  off-chain entry** — slice 1 fills the named gap. `fuzz_props.rs`'s own comment flags
  the missing `[lib]` target on `sphincs-tz-secure`; the narrow extraction here dodges it.
- `fw-manifest/tests/gen_extract_vectors.rs` + `contracts/verification/extracted/Extracted/ExtractDiffCheck.lean`
  — the in-tree non-circular Rust↔Lean extraction-differential (+ negative-control
  discipline). `decode_multisend` is pure byte-slice logic with **no** crypto, so it is
  exactly what Charon/Aeneas *can* extract — the Lean-extraction-differential is the
  available **upgrade path** above Kani-bounded, reusing this machinery verbatim
  (oracle from an independent decoder, never the firmware; permanent reject set).
- `docs/security/FAITHFULNESS_AUDIT_2026-06-14.md` — enumerates the trusted-display /
  clear-sign path as NOT COVERED by the Lean theft-freedom proof: the blind spot this
  slice begins to close.

---

*Dated 2026-06-29. Tiers: facts marked [code]/[tool] were read/run this pass;
[lit]/[claim] are external or asserted. Tool effort/ROI are engineering estimates, not
guarantees — a Kani green is a bounded proof up to N, a Miri green is UB-absence on the
exercised inputs, neither is a Lean-grade ∀.*
