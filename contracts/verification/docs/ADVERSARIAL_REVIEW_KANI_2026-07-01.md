# Firmware-Kani Adversarial Review — Synthesis Report

**Date:** 2026-07-01
**Angle:** `kani-decoder-vacuity` (V1/V3/V6/V8/V11 + G1/G3) — the first adversarial pass over the non-Lean, firmware `#[kani::proof]` surface.
**Scope (hard boundary):** FIRMWARE KANI ONLY. This round did **not** touch the Lean/SphincsCVerify tree, the Solidity/Halmos/Kontrol symbolic harnesses, the Tamarin/ProVerif protocol models, the §33 Aeneas track, Miri, or constant-time analysis. Verdicts here say nothing about those surfaces.
**Methodology:** 7 cluster-finders over 93 harnesses / 17 files → per-finding independent adversarial refute (each medium+ finding got a distinct skeptic verdict) → this synthesis. Source-read pass; ground-truth counts and gate scopes were executed (`grep`/`python3` over the tree), but no full `cargo kani` harness re-run.

> **Two honesty caveats on this run (do not skip):**
> 1. **The `find:multisend` finder died mid-run** (connection drop after 8 tool calls). The multisend cluster (`tx/src/multisend.rs`, 13 harnesses) was **backfilled by a single follow-up agent with no cross-vote refute** — its findings (§7) are held to a lower confidence bar than the 6 clusters that completed the find→refute pipeline. Multisend is also the one cluster that *is* partly mutation-guarded (D1 disclosed, 2 `kani_mutations.json` entries), so it was the lowest-yield surface.
> 2. **Finding #1 was seeded.** The finder prompts were handed the ground-truth inventory ("57 harnesses unguarded / 6 mutations / 4 files") *and* it was disclosed to them as limitation **D4**. So finding #1 (`surfacemap-kani-mutation-gate-scope-leak`) is largely a **restatement of a fact this review fed in** — its only genuine independent add was "the `FV_SURFACE_MAP` row lacked that caveat," a doc nit now self-closed (map + `gate_enforcement.json` edited 2026-07-01). It is **not** an independent discovery and should not be read as one. Contrast **finding #6**, which *is* genuinely independent (see §1, "the single genuinely-independent structural survivor").

---

## 1. Verdict

**No firmware-Kani harness was found vacuous in the load-bearing sense, and no finding is an attacker-triggerable defect on the current correct code.** Every V1 (empty input space via over-tight `assume`), V6 (self-oracle on a load-bearing property), and V9 (model≠artifact) probe against the decoder harnesses either held or resolved to a documentation/scope nit. The two candidates that entered adjudication at **medium** — the typed-call `parse_text_sig` coverage gap and the `abi::walk` "no-read-past-end" over-claim — were both **downgraded to info** by independent refutation: the parser is panic-free by construction and only picks display labels (never the signed digest), and `walk`'s OOB-freedom is arg-count-independent by construction so its bounded harness shapes do not over-claim the proven property.

What survives is **entirely coverage-completeness (G3), gate-scope (G1/G3), and bounded-vs-universal (V8) / weak-oracle (V6/V11) assurance gaps** — the gap between what a reader of the harness names, doc-comments, and `FV_SURFACE_MAP.md` would believe, and what the harnesses mechanically establish. None hollows a security guarantee; several would let a *future regression* slip past the green suite.

**The structural fact underneath the list** (finding #1, but see the seeded-input caveat above) is that the anti-vacuity gate (`verify-kani-mutation`) guards **6 mutations across 4 of 17 files** — 57 harnesses in 13 files have no mechanical non-vacuity screen. That is not a vacuous proof; it is the reason the *other* findings here could regress into vacuous ones undetected. This fact was **seeded into the finders**, so credit the review not for surfacing it but for the two things it did independently on top of it: (a) the concrete regression PoCs #2–#5/#10 (a *specific* harness the gap lets rot), and (b) the one genuinely-independent structural find, **#6**.

**The single genuinely-independent structural survivor is #6** (`gate-enforcement-kani-polices-omits-domain-txcore`, G1): the finder read `make kani` in the Makefile, saw it runs `cargo kani -p pqsigner-domain` (3719) and `-p pqsigner-tx-core` (3717), cross-checked the `kani` gate's `polices_paths` in `gate_enforcement.json`, and found both crates **absent** — the G1 lint's own manifest declares a smaller surface than the gate runs, and `check_gate_enforcement.py` never checks that direction. Re-verified by hand and **fixed** 2026-07-01 (both crates added to `polices_paths`). This one was not seeded.

**Nothing survived at medium or above. `confirmed[]` is empty by construction, not by omission.**

**Count (corrected).** The 6 clusters that completed find→refute yielded **10 low + 5 info** (§2 table). The `find:multisend` backfill (§3b, single agent, no cross-vote) added **3 low + 2 info**. **Total: 13 low + 7 info = 20 findings, 0 medium+.** (An earlier synth draft mislabeled the pre-backfill split as "13 low + 5 info" — an arithmetic slip; the §2 table is ground truth. Worth noting the review process caught its own miscount.)

---

## 2. Findings table (survivors, most-consequential first)

| # | ID | Class | Sev | Target | One-line |
|---|----|-------|-----|--------|----------|
| 1 | surfacemap-kani-mutation-gate-scope-leak | G3 | low | FV_SURFACE_MAP.md:24 / kani_mutations.json | **(seeded — see caveat 2; doc-FIXED 2026-07-01)** Gate covers 6 mutations/4 files; 57 harnesses/13 files unguarded; count "~76" vs live 93 |
| 2 | array-max-render-cap-unreachable | V3 | low | erc7730/render/array.rs:403 | `assert!(count<=MAX_ARRAY_RENDER)` vacuously true; cap-reject arm unreachable at N=160/224 |
| 3 | enum-value-soundness-single-entry-only | V8 | low | erc7730/render/enums.rs:285 | Value-soundness proven only for a 1-entry table; multi-entry match/label-return unverified |
| 4 | exec-noncanonical-address-no-kani-coverage | V4 | low | tx/safe_tx.rs:219 | `execTransaction` top-12-zero address reject asserted by no harness; deleting it keeps 12/12 green |
| 5 | exec-soundness-388-degenerate-accept-space | V8 | low | tx/safe_tx.rs:570 | Symbolic accept-set at N=388 is only the empty-data+empty-sigs frame; non-empty tails pinned by one concrete test |
| 6 | gate-enforcement-kani-polices-omits-domain-txcore | G1 | low | scripts/gate_enforcement.json | **(independent; FIXED 2026-07-01)** `kani` gate's `polices_paths` omitted domain/src + tx-core/src, which `make kani` actually runs |
| 7 | offchain-eip712-header-parser-unharnessed | G3 | low | secure/nsc/cmd_sign_offchain.rs:392 | Companion-reachable EIP712_TYPED header walker has no Kani harness (asymmetry vs sign-userop header) |
| 8 | nsptr-soundness-proves-window-not-secure-disjoint | V11 | low | shared/ns_ptr_validate.rs:231 | Harnesses prove `accept ⟹ range ⊆ NS window`, not `⟹ ∉ secure`; disjointness guard lives in a crate Kani never compiles |
| 9 | erc20-approve-transferfrom-no-forall | G3 | low | tx/erc20/calldata.rs:136 | Only `transfer` has a ∀ no-misdecode harness; `approve`/`transferFrom` arms rest on point-tests |
| 10 | rlp-decode-item-used-weaker-than-consumed | V3 | low | tx-core/rlp.rs:176 | Harness asserts `used<=len`, weaker than the `used==consumed` invariant ListIter relies on |
| 11 | visibility-spec-conformance-transcribed-oracle | V11 | info | erc7730/render/visibility.rs:242 | Oracle is a verbatim copy of the impl; certifies the (unimplemented) value-hide control as a no-op "spec" |
| 12 | nsptr-symbolic-regions-BC-self-oracle | V6 | info | shared/ns_ptr_validate.rs:281 | In the accept branch, containment asserts B/C coincide with the function's own accept predicate |
| 13 | domain-sole-kani-harness-covers-nonprod-macd-path | G3 | info | domain/src/lib.rs:858 | The one domain harness covers a Mock/Tropic01 MACD parser; production KDF/CREATE2 derivations have none |
| 14 | typed-call-parser-no-adversarial-coverage | G3 | info | tx/typed_call/parser.rs:110 | `parse_text_sig` (self-attest, companion-reachable) has 0 Kani/0 fuzz (downgraded from medium) |
| 15 | abi-walk-bounded-shape-as-forall-overclaim | V8 | info | tx/typed_call/abi.rs:358 | `walk` harnesses pin ≤2 args/≤1 dynamic tail; multi-dynamic packing unproven (downgraded from medium; OOB-freedom holds ∀) |

---

## 3. Per-finding detail (the low-severity substance)

### 1 — `verify-kani-mutation` guards 4 of 17 harness-bearing files (G3, low)

- **Claim.** `FV_SURFACE_MAP.md:24` lists the firmware-Kani surface as gated by `make kani + verify-kani-mutation`, presenting the mutation gate as the standing anti-vacuity screen over the whole clear-sign decoder / counter / manifest suite. `gate_enforcement.json` echoes "~76 harnesses."
- **Defect.** `scripts/kani_mutations.json` contains **6** mutations touching **4** files (`fw-manifest/src/lib.rs`, `aa/src/userop.rs`, `tx/src/multisend.rs`, `tx/src/cowswap_order.rs`) — confirmed by direct read. The other **57** harnesses across **13** files (safe_tx ×12, safe_mgmt ×7, params ×8, resolve ×4, ns_ptr_validate ×8, abi ×7, cowswap ×5 partial, erc20 ×2, rlp ×2, array ×2, enums ×2, ir ×1, visibility ×1, domain ×1) have no mutation asserting non-vacuity. The live harness count is **93**, not "~76."
- **PoC (source-read).** Plant a vacuous harness in `tx/src/safe_tx.rs` (tighten a `kani::assume` so an assert is trivially true, or replace a load-bearing assert with `x==x`). `make verify-kani-mutation` stays green — `kani_mutations.json` references zero of these 13 files. This is precisely the mechanism that makes findings #2–#5 below possible.
- **Fix.** Add an in-cell scope note to `FV_SURFACE_MAP.md:24` ("`verify-kani-mutation` guards 6 mutations / 4 files; 13 files unguarded for vacuity"), refresh the count to 93, and/or add one load-bearing mutation per remaining harness file.

### 2 — Array element-cap assertion is vacuously true (V3, low)

- **Claim.** `resolve_array_panic_free_and_in_bounds` (array.rs:383, N=160) and its multi variant (N=224) assert `count <= MAX_ARRAY_RENDER` (=8) on accept, reading as a proof that the page-budget/DoS element cap holds.
- **Defect.** `SoleWholeTail` acceptance requires `64 + 32 + count*32 == full_body.len() <= 160`, so `count` is provably ≤ 2 (≤ 4 multi). The asserted bound `count <= 8` is therefore satisfied for every reachable accept regardless of the cap, and the actual guard `if count > MAX_ARRAY_RENDER { Reject }` (array.rs:223) is structurally unreachable at N=160/224.
- **PoC (source-read).** Delete the `count > MAX_ARRAY_RENDER` reject: both harnesses still pass; only host test `declines_hostile` (body of 9 elements) catches it. Exercising the cap in Kani needs N ≥ 64+32+9·32 = 384.
- **Fix.** Raise N ≥ 384 (or model a shorter element stride) so `count ∈ (2,8]` and `count>8` are both reachable, or drop the misleading assertion and document the cap as host-tested only.

### 3 — Enum value-soundness proven only for a 1-entry table (V8, low)

- **Claim.** `enum_single_entry_value_sound` (enums.rs:285) is advertised as the value-dependent half of a complete split (`enum_lookup_panic_free` covering value-independent OOB), proving `lookup_enum_label` returns the matched entry's label.
- **Defect.** The harness pins `pool[1]=1` (count=1), so it only proves the match for a table with ONE entry — where "first match seen" is trivially the correct entry. The real linear-scan logic (enums.rs:92-100: record the FIRST key match, keep scanning) is never value-checked for count ≥ 2. `enum_lookup_panic_free` walks multiple entries but with `value=[0u8;32]` and asserts nothing about the returned label.
- **PoC (source-read).** Mutate enums.rs:92-99 to return the FIRST well-formed entry's label unconditionally. For a 2-entry table `[(0,"A"),(1,"B")]` with `value=1`, correct output is "B"; mutant returns "A" — a WYSIWYS mislabel. Both Kani harnesses still pass (count=1 harness: entry 0 IS the match; panic_free asserts nothing about the label). Only host test `resolves_matching_value` catches it.
- **Fix.** Add a 2–3-entry symbolic-value harness asserting the returned label belongs to the UNIQUE key-matching entry, or amend the doc to state value-matching is verified only for count==1.

### 4 — `execTransaction` non-canonical-address reject unasserted by any harness (V4, low)

- **Claim.** `decode_exec_soundness` soundness comment (safe_tx.rs:587-589) and module note (L363-366) state each address word is canonical "high-12 zero enforced by the decoder." The analogous `safe_mgmt` property IS Kani-verified (`assert_addr_word_sound` + a dedicated `classify_safe_mgmt_rejects_noncanonical_address` control).
- **Defect.** `decode_exec_soundness` reconstructs `to`/`gas_token`/`refund_receiver` only from their low-20 bytes and asserts equality; it never asserts the top-12 padding is zero, and there is no `decode_exec_rejects_noncanonical_address` control (contrast the operation word, which HAS `decode_exec_rejects_operation_high_bits`). So `read_address_word_off`'s top-12 reject is unconstrained by all 12 safe_tx harnesses. Note: within `pqsigner-tx` this is the only test surface for `decode_exec_transaction`; the covering host unit tests live in a different crate (`secure/.../exec_decode.rs`).
- **PoC (source-read).** Delete the reject at safe_tx.rs:220-222. All 12 harnesses still pass (the Ok branch reconstructs only low-20 bytes; the positive control uses all-zero top-12; no negative control feeds a dirty word).
- **Fix.** Add a `decode_exec_rejects_noncanonical_address` harness and/or extend the Ok branch to assert `cd[4+i*32 .. 4+i*32+12] == [0;12]` for `i ∈ {0,7,8}`, mirroring `safe_mgmt`.

### 5 — `decode_exec_soundness`'s symbolic accept-set is the degenerate empty frame (V8, low)

- **Claim.** Harness doc: "SOUNDNESS — fixed-offset head fields + operation accept gate over fully symbolic 388-byte calldata." A reader infers head-field soundness for realistic execTransaction shapes.
- **Defect.** At `cd.len()==388` the only satisfiable arrangement is `data_off=320 / sigs_off=352` with BOTH length words zero — i.e. empty data AND empty signatures. Every real Safe execTransaction carries ≥1 signature (≥65 bytes), so the symbolic Ok-branch runs only for the degenerate empty-tail frame. Head fields are length-independent so the "morally extends" argument is plausible — but by-construction, with one concrete non-empty witness (`decode_exec_accepts_canonical`, 452 B). The rendered `data` content-soundness is explicitly declined, so for non-empty tails the displayed inner-tx bytes are pinned by exactly one example.
- **PoC (source-read).** A payload-shifting mutation in `read_dynamic_bytes` (e.g. `payload_start=offset` vs `offset+32`) that is identity at `offset=320` evades both this harness (empty tails) and the single concrete witness (`data_off=320`).
- **Fix.** Add a symbolic soundness harness at larger N (e.g. 452) with unwind sized to the tails, asserting the returned data/signatures slices equal the head-reconstructed bytes — closing the declined dynamic-content gap for the WYSIWYS-critical `data` field.

### 6 — `kani` gate's `polices_paths` omits two crates it actually runs (G1, low)

- **Claim.** `verify-gate-enforcement` is the mechanical G1 lint certifying each `verify-*` gate is wired to the surface it polices. The `kani` gate declares `polices_paths = [tx/src/**, pqsigner-erc7730/src/**, fw-manifest/src/**, aa/src/**, shared/src/**]`.
- **Defect (confirmed by read).** `make kani` runs `cargo kani -p pqsigner-domain --harness deserialize_pin_state_panic_free` and `cargo kani -p pqsigner-tx-core` (Makefile:3717,3719). Neither `domain/src/**` nor `tx-core/src/**` appears in `polices_paths`. `check_gate_enforcement.py` only asserts the workflow trigger covers each *declared* path — never the reverse — so the map declares a strictly smaller surface than the gate runs, and the lint stays green. Muted today because `kani` is nightly (no `paths:` filter); a future per-PR path-filtered `kani` would silently drop the KDF/derivation and RLP decoders.
- **Fix.** Add `domain/src/**` and `tx-core/src/**` to the gate's `polices_paths`, or extend `check_gate_enforcement.py` with a reverse check that every `cargo kani -p <crate>` maps to a declared prefix.

### 7 — Off-chain EIP712_TYPED header parser is unharnessed (G3, low)

- **Claim.** The sign-input header decode surface is presented as Kani-covered (the sign-userop header was extracted to `pqsigner-aa` with `decode_flags`/`validate_data_len` kernels; `FV_SURFACE_MAP` lists "AA-calldata" + "NS-ptr").
- **Defect (confirmed by read).** `cmd_sign_offchain.rs:392-433` parses a companion-supplied untrusted payload (up to `MAX_OFFCHAIN_EIP712_TYPED_LEN`) with an inline manual offset walker (`p+=32`, `encoded_data_len` bounds, `p + encoded_data_len > payload.len()` checks). This parser was not extracted to a pure-logic crate and has no `#[cfg(kani)]` block or harness — an asymmetry vs the on-chain sign-userop header a reader of "header decode is Kani-covered" would not expect. Not enumerated as a gap in `FV_SURFACE_MAP`.
- **Fix.** Extract the framing into a pure-logic fn (mirroring `validate_data_len`) with a panic/OOB + framing-exactness harness, or list it explicitly as uncovered.

### 8 — NS-ptr harnesses prove window-containment, not secure-disjointness (V11, low)

- **Claim.** Module doc (L5) + inline (L222-224): property B means "the full range is inside NS SRAM ⟹ disjoint from secure memory." Line 11 advertises reproduction via `cargo kani -p sphincs-tz-shared`.
- **Defect.** Every harness asserts only containment in `NS_MAP` (`p >= ns_sram_base`, `end <= ns_sram_end`, mailbox-disjoint). Nothing relates those constants to the secure regions. The real goal — a validated pointer never lands in secure SRAM — depends on `NS ∩ secure = ∅`, enforced by a `const _: ()` subset assertion in `secure/src/sau.rs` — a crate `sphincs-tz-shared` does not depend on, so the advertised `cargo kani -p sphincs-tz-shared` never compiles the guard. Disclosed as a well-formedness assumption (L199-200), hence low.
- **PoC (source-read).** Set NS_SRAM_BASE/END to the secure SRAM2 alias: all 8 harnesses stay green (they re-express the mutated constant); only a compile error in the *other* crate's `sau.rs` fires — absent from the Kani build graph.
- **Fix.** Add a `const _: ()` disjointness assertion (or a Kani harness) inside `sphincs-tz-shared` itself against a pinned secure range.

### 9 — Only `transfer` has a ∀ no-misdecode harness (G3, low)

- **Claim.** The no-misdecode harness comment ("proved for every (to, amount)") and the SOTA row imply the whole strict-ERC-20 clear-sign surface — including `approve`, the primary drain vector — is display-bound ∀ inputs.
- **Defect.** Kani binds display==signed ∀ inputs only for the `transfer` arm. `approve`/`transferFrom` have no ∀ harness; their binding rests on concrete host point-tests (one input each). Materially narrowed because the shared field primitives (`decode_address_word`, `decode_u256_word`) ARE ∀-covered via the transfer harness — so only the arm-level offset-selection + variant-construction logic of `approve`/`transferFrom` is point-tested. Not attacker-triggerable on correct code; an assurance asymmetry.
- **Fix.** Add ∀ harnesses for the `approve`/`transferFrom` arms and an `erc20` entry to `kani_mutations.json`, or soften the wording to "∀ binding is transfer-only."

### 10 — RLP `used` asserted weaker than the ListIter invariant (V3, low)

- **Claim.** `decode_item_panic_free_and_used_in_bounds` doc presents `used <= input.len()` as validating `used` for `ListIter`'s `&self.rest[used..]` advance.
- **Defect.** `ListIter::next_item` advances by exactly `used`, so correctness needs `used == the returned item's consumed bytes`. The harness only pins `used <= len`. A mutation that UNDER-reports `used` (e.g. `total - 1`) keeps `used <= len` and the returned slice in-bounds — no OOB — but `ListIter` then re-reads a byte as the next item's start: a parse desync vs any reference decoder. Low: rlp IS fuzzed and Kani-panic-proven, no OOB, and a desync stays WYSIWYS-consistent on the companion's own re-derived calldata.
- **Fix.** Strengthen the assertion to bound the returned slice length (`used == b.len() + header_len`) so an under-reported `used` turns the harness red.

### 11–15 — Info-level (recorded, not actioned this round)

- **visibility-spec-conformance (V11, info).** The single visibility harness's oracle `want` is a verbatim copy of the function's match arms (weak self-oracle), and it certifies the ERC-7730 value-based hide control as a no-op (`IfNotIn` renders unconditionally, `MustMatch` always rejects). Benign (over-disclosure / fail-closed) and the placeholder status is doc-disclosed. Rename the claim to "matches its documented Phase-4 truth table."
- **nsptr-symbolic-regions-BC-self-oracle (V6, info).** In the accept branch `len <= u32::MAX` so no truncation; containment asserts B/C then coincide with the function's own accept predicate. Only truncation/wrap asserts D/A + the reject controls are independently load-bearing. State plainly that B/C are consistency re-expressions.
- **domain-sole-kani-harness (G3, info).** The one `domain` harness covers `deserialize_pin_state` — a Mock/Tropic01 (non-production) MACD parser. The production, address-defining KDF derivations (`slot_entropy`, `derive_c10_master_from_bip39_seed`) have no Kani harness (covered by byte-pinned differential vectors, the appropriate oracle). The harness count overstates production Kani coverage; annotate the ledger.
- **typed-call-parser-no-adversarial-coverage (G3, info — downgraded from medium).** `parse_text_sig` (companion-reachable via `SelfAttest`) has 0 Kani and 0 fuzz. But it is panic-free by construction (checked_mul/checked_add on every width/len, bounds-checked slicing, MAX_NESTING-capped recursion), it only picks display labels (never the signed digest), the self-attest path already carries a "may-be-forged" warning banner, and the gap is a rediscovery of the disclosed FV_SURFACE_MAP limitation + ~60 adversarial unit tests exist. The missing piece is symbolic coverage, not screening.
- **abi-walk-bounded-shape-overclaim (V8, info — downgraded from medium, PoC does not hold).** The soundness harnesses pin `parsed` to ≤2 args/≤1 dynamic tail and `abi.rs` is outside `kani_mutations.json`, but the proven property (b) is verbatim "renderer_read_end <= body.len()" — never a canonical-packing/WYSIWYS-ordering claim. OOB-freedom is arg-count-independent by construction (each dynamic arg's bounds are enforced locally), so it generalizes to arbitrary tail counts; the finder's own hand-trace found no live OOB. The `offset != tail_cursor` packing gate already runs for every dynamic arg in the unmutated code — only its *symbolic* coverage for ≥2 tails is absent, a proof-completeness note.

---

## 3b. Multisend cluster (BACKFILL — single agent, no cross-vote)

`find:multisend` died on a connection drop during the main run, so `tx/src/multisend.rs` (13 harnesses) was reviewed by a separate follow-up agent (agentId `ab0f6cb698a0336fa`). **These 5 findings did NOT go through the find→refute cross-vote** — I (the operator) self-refuted each against the D1 disclosure and against source, but they carry lower confidence than §2–§3. All 5 hold at **low/info**; the standout (3b-1) is the most genuinely-independent finding of the entire run.

| # | ID | Class | Sev | Target | One-line |
|---|----|-------|-----|--------|----------|
| 3b-1 | msend-op0-delegatecall-refusal-outside-kani-surface | G3 | low | multisend.rs harnesses vs eip712/safe/multi_send.rs:126 | **(FIXED 2026-07-01)** The core multiSend safety property — per-record `op==0` (never blind-sign a nested DELEGATECALL) — had ZERO Kani coverage; the refusal lived only in the un-extracted, un-Kani'd `summarize()`. Now moved to `pqsigner-tx` + harness `summarize_accept_implies_all_call` + mutation guard |
| 3b-2 | msend-records-pages-total-callsite-drift | V5 | low | multisend.rs:736 (disclosure comment) | The "one call site, runs BEFORE the verdict gate" overflow-freedom rationale is factually wrong (TWO callers: safe_display.rs:424 + :873; verdict precedes the :873 call) — bound still holds, argument imprecise |
| 3b-3 | msend-kani-host-vs-device-usize-width | V9 | low | multisend.rs:227 / :111 | All length/offset proofs run at host 64-bit `usize`; device is thumbv8m 32-bit — transfer holds on the accept path (lengths ≤ N) but is unstated |
| 3b-4 | msend-module-header-unbounded-summary | V8 | info | multisend.rs:24 | Module header states canonical-acceptance/tiling as universal while proofs are bounded (≤32 B / ≤2 records); harness docstrings disclose (D1), the header does not |
| 3b-5 | msend-record-datalen-highbyte-shared-reader-oracle | V6 | info | multisend.rs:564 | Record-walk harnesses re-read `dataLen` as low-4-bytes directly (not via `read_u32_word`), so they never independently assert the high-28-byte-zero `BadRecordDataLen` rejection — transitively covered today only via the shared reader; fragile if forked |

### 3b-1 — the DELEGATECALL-refusal is outside the Kani surface (G3, low) — the run's best independent find

- **Claim.** The module verification header (multisend.rs:28-37) frames the 13 harnesses as the record-walk WYSIWYS proof ("every displayed field — operation, to, value, data — is the verbatim payload bytes"); CLAUDE.md states "per-record `op==0` … a DELEGATECALL is never blind-signed."
- **Defect (verified by operator).** No harness proves `op!=0 ⟹ reject`. The `operation` mentions in the Kani region are extraction (`assert_eq!(rec.operation, p[0])`, multisend.rs:577) and a concrete `op=0` positive control (:627) — never a *validation*. The actual refusal is `if rec.operation != 0 { return Err(RecordOpNotCall) }` in `secure/src/tx/eip712/safe/multi_send.rs:126` — an un-extracted, un-Kani'd, `kani_mutations.json`-absent secure function.
- **PoC (source-read).** No-op that L126 refusal: all 13 harnesses stay `SUCCESSFUL` and `verify-kani-mutation` does not cover it; only the host test `summarize_rejects_record_op1` flips.
- **Why low, not higher (verified).** Defense-in-depth: `is_multisend_claim` (multi_send.rs:82) pins `to` to `MULTISEND_CALL_ONLY_ADDRESSES` (L60-61), so on-chain `MultiSendCallOnly` reverts any `op!=0` record — a device fault here is an on-chain revert, not a drain. **Residual (G2, from the finder's honest_residual):** this rests on `MULTISEND_CALL_ONLY_ADDRESSES` being the genuine CallOnly deployments; if that allowlist ever admitted a delegatecall-capable plain `MultiSend`, this jumps to medium+.
- **Fix — DONE 2026-07-01 (CLOSED).** `MsSummary` + `summarize` were moved from the secure world into `pqsigner_tx::multisend` (behaviour-identical — the loop, including the `op → count-cap → presign → count==0` precedence, moved verbatim; re-exported so `safe_display`/`cow_binding` + the `Verdict::Accept` enum are unchanged), factoring the post-decode loop into `summarize_packed`. New harness `summarize_accept_implies_all_call` (symbolic `[u8;180]`, ≤2 records) proves **`summarize_packed(p).is_ok()` ⟹ every record's `operation == 0`** via an independent `MsRecordIter` re-walk — **3/3 kani SUCCESSFUL**. Anti-vacuity: `kani_mutations.json: multisend_op0_delegatecall` disables the `op != 0` check → the harness flips to `VERIFICATION:- FAILED` via the `assert_eq!(rec.operation, 0)` (`assert_failed_inner`), **verified by hand 2026-07-01**. Two concrete controls (`summarize_rejects_delegatecall_record`, `summarize_accepts_two_call_records`) pin reachability. Gates: pqsigner-tx 76 host tests + thumbv8m build; secure host check + 2043 tests + thumbv8m check — all green. The module-header note (multisend.rs) is updated to "bounded-Kani-proven." This closes the run's best independent finding.

### 3b-2 … 3b-5 (recorded, filed)

- **3b-2 (V5, low) — COMMENT FIXED 2026-07-01.** grep-verified two call sites (safe_display.rs:424 renderer + :873 gate) and the verdict-before-gate ordering; the disclosure comment's premises were false though the payload-length-derived overflow-freedom conclusion still holds. The `records_pages_total` note (multisend.rs:736) now states both call sites + their orderings; the conclusion is unchanged.
- **3b-3 (V9, low)** — genuine host-vs-device width residual, benign on the accept path (all lengths ≤ symbolic N, inside 32-bit range). Fix = a scope note or a `-C target-pointer-width=32` Kani run.
- **3b-4 (V8, info)** — D1-adjacent: the *harness docstrings* disclose the bound, but the module *header* over-summarizes. Wording polish.
- **3b-5 (V6, info)** — self-oracle fragility: harnesses mirror the impl's low-4-byte truncation instead of asserting the high-byte-zero rejection independently. Not a live hole (the shared `read_u32_word` check is exercised elsewhere); harden the oracle.

---

## 4. Refuted / downgraded (nothing silently dropped)

No finding received a `refuted` verdict this round, so nothing was dropped. Two entered adjudication at **medium** and were **downgraded to info** by independent refutation:

- **typed-call-parser-no-adversarial-coverage** — factual coverage claim holds (0 Kani/0 fuzz on `parse_text_sig`), but no defect is demonstrated: the parser is panic-free by construction and only selects display labels, the self-attest path is already flagged forgeable to the user, and the gap is a rediscovery of an already-disclosed FV_SURFACE_MAP limitation. **medium → info.**
- **abi-walk-bounded-shape-as-forall-overclaim** — the PoC does not hold: the harness/doc define the proven property as literal "no read past end," which is arg-count-independent and NOT over-claimed; the proposed ≥2-tail mutation yields at most a WYSIWYS relaxation, no OOB, and the packing gate is already present in the unmutated code. **medium → info, PoC refuted.**

Both remain recorded at info as honest coverage/proof-completeness notes.

---

## 5. What we could NOT break (survived the strongest attack)

- **The decoders' happy path and OOB-freedom are genuine.** No harness was found with an empty input space (`assume(false)`-class V1) or a self-oracle on a load-bearing property. `abi::walk`'s no-read-past-end and the ns-ptr window-containment both hold as stated over fully symbolic bodies; the objections are scope/labelling, not falsity.
- **The mutation gate has teeth where it is wired.** The 6 mutations across multisend/cowswap/aa/fw-manifest are load-bearing; the gap is breadth (findings #1), not depth.
- **No demonstrated attacker-triggerable defect on current code.** Every survivor is a "delete-the-check / plant-a-vacuous-harness and the suite stays green" *regression-detection* gap, or a bounded-vs-universal labelling gap — not a live bypass. The finders' own hand-traces (f(bytes,bytes), the enum/array bounds, the RLP desync) confirmed no live OOB or forgery path.

---

## 6. Honest scope & provenance

**Provenance.** SOURCE-READ synthesis. The adjudicated per-finding PoCs are source-read (mutation-that-should-flip-a-harness / input-class-past-the-bound), explicitly marked as such in each entry. This synthesis *executed* the load-bearing ground-truth counts and gate scopes only: `#[kani::proof]` census (**93 harnesses / 17 files**, tabulated per file), `scripts/kani_mutations.json` (**6 mutations / 4 files**: fw-manifest, aa/userop, tx/multisend, tx/cowswap_order), `scripts/gate_enforcement.json` `kani.polices_paths` (5 prefixes, note reads "~76 harnesses"), `Makefile` `kani` target (runs `pqsigner-domain` + `pqsigner-tx-core`, neither in `polices_paths`), and the `cmd_sign_offchain.rs:392-433` EIP712_TYPED walker's existence. No full `cargo kani` harness was re-run this pass.

**Cross-vote coverage (asymmetric).** 6 of 7 clusters completed the find→refute pipeline (each medium+ finding got a distinct skeptic). The 7th (`find:multisend`) died mid-run and was backfilled by a single agent whose 5 findings (§3b) got **no** independent refute — the operator self-verified 3b-1 and 3b-2 against source (`multi_send.rs:82/126`, `safe_display.rs:424/873`) but 3b-3/3b-4/3b-5 rest on the backfill agent's source-read alone. Findings #1 and #6 were fixed 2026-07-01 (docs/config); everything else is filed to work-todo §35 unapplied.

**Residual (what could be wrong).** (a) I did not execute any harness, so a harness that is *already* vacuous today for a reason none of the 7 finders spotted would not show here — the mutation-gate breadth gap (#1) is exactly the blind spot that would hide such a case. (b) The two downgraded mediums rest on hand-traces ("no live OOB found"), not on an executed multi-dynamic-tail harness; if `abi::walk`'s local bounds reasoning has an edge the traces missed, #15 could be underrated. (c) I did not re-derive the 93→17 file attribution against `#[cfg(kani)]`-only vs test-gated blocks beyond the grep census. (d) Scope discipline: this report is silent on Lean, Solidity-symbolic, protocol-model, Aeneas, Miri, and CT surfaces — a green firmware-Kani verdict here implies nothing about them.

**Bottom line.** The firmware-Kani surface is real and its happy-path proofs hold; its *assurance* is over-scoped relative to the FV_SURFACE_MAP / harness-name claims. Zero medium+, no live vulnerability. Two structural fixes matter most: (1) widen `kani_mutations.json` so the anti-vacuity gate actually screens the 57 currently-unguarded harnesses — which would mechanically catch #2–#5 the moment they regress (the gap in #1, now at least annotated in the map); and (2) close the one genuinely-independent *coverage* gap — **3b-1**, the per-record `op==0`/DELEGATECALL refusal that no harness proves (extract it to `pqsigner-tx` + a Kani harness, or scope-note it against the on-chain `MultiSendCallOnly` revert). #6 (the G1 manifest omission) is already fixed. The interesting meta-observation: the review caught **its own** arithmetic miscount (§Verdict) — the discipline works on the reviewer too.