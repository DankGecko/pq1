Bash writes are denied in this mode, and I have no general file-write tool — the same constraint Partner A's first pass hit ("no Write tool… the authoritative deliverable is the report bytes in this response"). The orchestrator captures returned message bytes (that is how `partner-a-first-pass.md/.json` were created). So the durable deliverable is this response. I'll keep it tight to survive transport and note the limit explicitly.

All verification is complete and source-grounded. Here is the complete cross report.

---

```markdown
---
surface: fv
run_date: 2026-07-15
report_type: symmetric cross-adjudication (Partner A)
reviewer_identity: Claude Code Opus 4.8 (claude-opus-4-8)
effort: max (ultracode/ultracode-label unavailable in Claude Code 2.1.209; coordinator-recorded fallback per workflow §7)
counterpart: Partner B — GPT-5.6 SOL, ultra, Codex CLI 0.144.4
frozen_identity: PQSigner_OS.frozen @ ddc7cefc35cb54e324dac94330c6ee86f9383c90 (branch fix/sweep-2026-07-14-findings)
stage: architecture + implementation-evidence (document/research-only)
status: open
---

# FV assurance case — symmetric cross-adjudication — 2026-07-15

## 1. Receipts, provenance, and drift

**First-pass artifacts (verified at start AND immediately before reporting — no drift):**

| Artifact | Path | SHA-256 | Check |
|---|---|---|---|
| Partner A md | `partner-a-first-pass.md` | `5afe1f48…722f8` | ✅ start+end |
| Partner A json | `partner-a-first-pass.json` | `a4d5a49d…b73e4` | ✅ start |
| Partner B md | `partner-b-first-pass.md` | `9b8a4264…e8cef` | ✅ start+end |
| Neutral packet | `neutral-review-packet.md` | `74f9716f…ead82` | ✅ start+end |
| Frozen `CLAUDE.md` | — | `65cf9b10…301b4` | ✅ start+end |
| Coordinator receipts | tx-merkle-regen / canary / easycrypt-frozen-root | `d0abb9ad…`, `3ea1e0d4…`, `367ff8c5…` | ✅ all match packet |

Frozen HEAD `ref: refs/heads/fix/sweep-2026-07-14-findings → ddc7cefc…` at start and end. **NO DRIFT.** Like Partner A's first pass, I could not recompute the aggregate `ad0de135…` (recipe lives in the excluded live repo); anchors are HEAD + normative-doc hashes + read-only mount. I accept the packet's provenance correction on the MM45 diff digest (`7b019433601404…`, not `…b876…`) — a coordinator transcription error, not target drift; Partner B reproduced the corrected value.

**Provenance of this pass:** I read frozen source and hash-verified the three coordinator receipts. I independently reproduced the load-bearing disputes from source (digest functions, WOTS parameter constraints, gate mechanisms, Lean models). I did **not** run `lake`/`easycrypt`/`lean4checker`/`make verify-*` (no toolchain) — execution-only claims (Kani census, full campaigns) remain coordinator-supplied and are labelled as such. I did not inspect `/home/nicola/repos` or edit any frozen tree.

## 2. Reconciled verdict (decomposed by axis — severities not averaged)

The two first passes diverge because they answer **different questions**. Partner A asked "is `theft_free` sound?" (answer: no reproduced hole → APPROVE WITH RED-LINES). Partner B asked "does the assurance prose faithfully describe what is proven for the *shipping* design?" (answer: no, in several load-bearing places → NO-GO). Both are individually defensible; the reconciliation is the decomposition.

| Axis | Reconciled recommendation | Basis |
|---|---|---|
| **Architecture / kernel soundness** | **APPROVE with red-lines** — no V-class hole reproduced | `theft_free` decomposition sound; Claim-4 closure strict kernel-only (whitelist, Makefile:332); case is genuinely honest where it matters (A2 tautology, verifier ∀-signature "not a symbolic proof", §33 hash postulates — all self-disclosed) |
| **Implementation-evidence / claim-fidelity** | **NO-GO for promoting the frozen case as *current* evidence** | Machine-checked firmware↔chain binding is over the wrong function (CL-DIGEST); extraction freshness is false-green with a concretely stale **proven** theorem (CL-FRESH); extracted axiom gate fails open (CL-CLOSURE); EasyCrypt legs cannot instantiate C10 (CL-EC-C10) |
| **Merge** | **Unavailable** | No implementation/PR candidate in scope |
| **Production shipment** | **NO-GO** | Unchanged; independent ship-blockers (OPTIGA S-1/2/3, rollback backend) plus the above |

**Where I land relative to my own (Partner A) first pass:** Partner A's blanket "APPROVE WITH RED-LINES" was **too generous on the implementation-evidence axis** because it undercounted — it missed the wrong-digest binding, the fail-open extracted gate, and the WOTS-representability gap, and it under-rated the extraction-freshness defect. Partner B's "NO-GO" is correct **for the claim-promotion axis**, but must be read as a **claim-fidelity** verdict, not a discovered unsoundness or exploit: neither partner (nor I) found a rogue axiom, a `False` detonation, a vacuous `theft_free`, an actual signing mismatch, a Merkle-acceptance bug in current Rust, a bytecode bypass, or a crypto break. The kernel proof is sound and honest; the *packaging around it* overstates.

## 3. Complete finding map (every A-F1..F7, B-F1..F14) + coordinator items

Dedup clusters: **CL-FW** firmware version · **CL-DIGEST** signed-digest binding · **CL-FRESH** extraction freshness · **CL-CLOSURE** axiom-closure enforcement · **CL-EC-GATE** EasyCrypt gate/provenance · **CL-EC-C10** EasyCrypt-not-C10 · **CL-PROTO** protocol harness · **CL-CV** CryptoVerif abstraction · **CL-KONTROL** Kontrol scope · **CL-XHASH** cross-hash prose · **CL-POLICY** proof-after-release · **CL-LEDGER** ledgers.

| ID | Cluster | Disposition | Reconciled sev. | One-line reason (source-grounded) |
|---|---|---|---|---|
| **A-F1** | CL-EC-GATE | **CONFIRMED** | MED | `check_easycrypt.sh` skips MM45-chain (incl. only unconditional WOTS+C result + capstone) and exits 0; confirmed against the **frozen** MM45 tree by item-7 receipt (10/21, skip 11, exit 0). Subset of B-F8. |
| **A-F2** | CL-CLOSURE | **RESOLVED (premise gone)** | — | "lean4checker pending" premise dissolved by item-1 (replay completed, 58 modules, exit 0). Residual currency (`THE_CLAIM.md:62` "55 modules" vs 58) stands as LOW doc-drift. |
| **A-F3** | CL-FW | **CONFIRMED** | MED | Same finding as B-F1; A-LOW **raised** (G10 is a live, non-legacy assurance row citing a now-nonexistent CLAUDE.md "75-B" phrase). |
| **A-F4** | CL-PROTO | **CONFIRMED** | LOW | CryptoVerif lib-path (`libexec/default` vs opam `bin/default`) — the tail of B-F9; spine is the ignored return code. |
| **A-F5** | CL-EC-GATE | **CONFIRMED** | LOW | EC `README.md:57` "7 axioms" vs gate `EXPECTED_TOTAL_AXIOMS=8` (`check_easycrypt.sh:68`, incl. `uniq_g`). Doc-drift. |
| **A-F6** | CL-EC-C10 | **CONFIRMED** | LOW | `WOTS_C_EmbDischarge.ec` header calls FLAG-2 open; theorem (`:174`) discharges it. Within-file doc-drift. |
| **A-F7** | CL-EC-GATE | **CONFIRMED** | LOW | `MM45_ROOT=` prefix inert (gate reads `EC_FV_ROOT`, `:59`). **Repaired + strengthened by item-7**: frozen-root rerun reproduced skip-as-success, so A-F1/B-F8 now hold against the frozen tree, not just live repos. |
| **B-F1** | CL-FW | **CONFIRMED / NARROWED** | MED (was HIGH) | FV proves `PQFW_V1` (75-B); CLAUDE.md freezes V4 (80-B, "V1 not authoritative"); work-todo → V6 (121-B). Real currency/coverage gap. **Narrowed**: backend is an openly-unbuilt ship-blocker + every layer labels its version, so it is not "false shipping evidence." |
| **B-F2** | CL-FRESH | **CONFIRMED** | HIGH | Tx-Merkle: current Rust rejects `idx≠0`@depth0 + `checked_mul`; committed `TxMerkle/Funs.lean` retains old semantics; `verify_proof_spec` (`TxMerkleSpec.lean:214`) is a **proven** theorem over the stale model. CI never regenerates `tx/src/**` (items 2,3). Systemic false-green. |
| **B-F3** | CL-DIGEST | **CONFIRMED / NARROWED** | MED (was HIGH) | Firmware signs `compute_sphincs_digest_v06` (`cmd_sign_userop.rs:1830,1894`); the extracted "firmware↔chain binding, §33 goal-thm-1" proves `compute_user_op_hash` (userOpHash tooling; no non-test firmware caller). **Narrowed**: on-chain `sphincsDigest_field_binding` is proven and Rust/Lean 360-B layouts match field-for-field by inspection → mislabelled + **missing** machine-checked extraction, **not** a demonstrated mismatch. |
| **B-F4** | CL-POLICY | **CONFIRMED / NARROWED** | MED (was HIGH) | `README.md:255-257`: proofs need not gate shipping because frozen formats "still apply to shipped firmware" — asserted with no artifact-binding receipt. F1-F3 are counterexamples. Doc-only review → MED, but real governance red-line. |
| **B-F5** | CL-CLOSURE | **CONFIRMED / NARROWED** | MED | Extracted §33 gate greps `sorryAx` only (Makefile:401-403); canary `: False` passed (item-4). **Narrowed**: does **not** reach `theft_free`/Claim-4 (strict kernel-only whitelist, Makefile:324-332). Scoped to the extracted correspondence + corollary theorems. |
| **B-F6** | CL-EC-C10 | **CONFIRMED (decisive)** | HIGH (research) | MM45 `WOTS_TW_ES.ec:31` pins `log2_w∈{2,4,8}` (`w∈{4,16,256}`, `:61`); C10 is `LOG_W=3,W=8,L=43` (`params.rs:43-52`). No valuation satisfies both. Confirms item-11 from source. **This refutes Partner A's Appendix-A "WOTS+C genuinely unconditional for C10."** |
| **B-F7** | CL-EC-C10 | **CONFIRMED** | HIGH (research) | Capstone `SPHINCS_C.ec` composes over free reals/premises; imports paper-model FORS (deleting `FORS_C10*.ec` leaves it unchanged); no concrete `SPHINCS_PLUS_C` scheme/game. Bounds abstract, not shipped C10. Does **not** touch `theft_free` (A5 cited-TCB). |
| **B-F8** | CL-EC-GATE | **CONFIRMED** | HIGH | Superset of A-F1: exits 0 on missing dep/skip (`EC_FV_ROOT=/missing`→SKIP→0); pins **count only** (`total_axioms != 8`, `:103`) so item-6 `dmkey_ll:false` stays green; absent from `gate_enforcement.json`; standalone port byte-identical to vendored (zero diversity). |
| **B-F9** | CL-PROTO | **CONFIRMED (from source)** | MED | `scripts/check_protocol_models.py:75-82` `_run` returns `stdout+stderr`, **never reads `cp.returncode`**; families count text tokens (`t==et`, `:95`). exit-42 (item-5b) and `Install⇒Install` count-preserving tautology (item-5a) both pass. |
| **B-F10** | CL-CV | **CONFIRMED** | MED (SIMPLIFY) | CryptoVerif models full-space uniform pad (exact-0 advantage); firmware rejects all-zero → conditioned draw (≤2⁻²⁵⁶). Lean (`SplitSecrecy.lean`) already documents the distinction; other prose overstates. |
| **B-F11** | CL-KONTROL | **CONFIRMED** | MED | `THE_CLAIM.md` "transcription-free" headline vs `KONTROL_SCOPING.md` admitting concrete-wrapper/owner fixing (symbolic dynamic calldata unsupported). Claim precision, not a demonstrated bypass. |
| **B-F12** | CL-XHASH | **CONFIRMED** | MED (SIMPLIFY) | `CLAUDE.md:122` "structurally disjoint" for keccak vs SHA-256 images; both are `ByteVec 32`; Lean honestly reduces to cited `keccak_sha256_cross_separation` (`∨ BreaksHash`). Prose-precision only; Lean layer honest. |
| **B-F13** | CL-CLOSURE | **CONFIRMED / NARROWED** | MED | lean4checker is kernel/environment **replay**, not a closure-policy gate (an authorized kernel-valid axiom is indistinguishable from a rogue one by exit code). **Narrowed**: closure policy IS enforced — by the strict Claim-4 whitelist — so relabel, don't treat as an open safety hole. Item-1 confirms replay itself completed. |
| **B-F14** | CL-LEDGER | **CONFIRMED** | MED | `check_ledger_consistency.py` validates only declared rows (`check_witness_coverage([])→[]`); public artifacts disagree on tier/playbook-count/coverage. **Item-8** (stale `leanloop.toml` whitelist: Keccak-only vs live SHA-256/HMAC) and **item-9** (8 Kani harnesses/6 files absent from mutation manifest; 3 full-only groups) are concrete instances I could not independently census (no toolchain) but that fit this cluster. |

## 4. Material findings — dispositions with mechanism (deduplicated)

**CL-DIGEST (B-F3) — CONFIRMED, severity NARROWED to MED.** The single most important cross-check. Firmware signs `compute_sphincs_digest_v06` — one SHA-256 over `sender‖nonce‖sha256(initCode)‖sha256(callData)‖5×gas‖sha256(paymaster)‖entryPoint‖chainId_BE` = 360 B (`aa/src/userop.rs:687-707`; called at `cmd_sign_userop.rs:1830,1894`). The extracted, machine-checked byte-layout theorem `compute_user_op_hash_spec` (`UserOpEquivByteLayout.lean:48`) is over `compute_user_op_hash` (the EntryPoint double-keccak userOpHash, 320+96 B), whose **only** callers are the extracted model + tests (no signing-path caller in `secure/`, `nonsecure/`, `contracts/`). So the theorem the header labels "the FIRMWARE SIDE of the firmware↔chain binding (§33 goal theorem 1)" binds a companion/tooling function, not the signed digest. **Why NARROWED, not HIGH:** the on-chain side *is* modelled and proven — `sphincsDigest_field_binding` (`SphincsDigestSpec.lean:99`) gives equal-digest⇒equal-preimage `∨ BreaksHash`, "the cryptographic statement Claim 1 cites"; and the Lean `sphincsDigestPreimage` (`ValidateUserOp.lean:238-261`) has the **identical 360-B field order** as the Rust. So the defect is (a) a mislabelled theorem and (b) a *missing* machine-checked Rust→Lean extraction for the actual digest — hand-transcription stands in its place. B itself concedes "absence of proof, not an actual mismatching field." This is implementation-evidence + claim-precision, not a demonstrated signing divergence.

**CL-EC-C10 (B-F6/B-F7) — CONFIRMED decisively; reverses Partner A's Appendix A.** `WOTS_TW_ES.ec:31` declares `const log2_w : { int | log2_w = 2 \/ log2_w = 4 \/ log2_w = 8 }` and `:61 lemma val_w : w = 4 \/ w = 16 \/ w = 256`. Shipped C10 is `W=8, LOG_W=3, L=43, TARGET_SUM=205` with target-sum grinding and no standard checksum (`params.rs:3,43-55`). `log2_w=3 ∉ {2,4,8}` — C10 is **structurally outside** the parameter universe of every MM45 WOTS theorem the port imports. Even relaxing that, MM45's checksum gives `len=len1+len2`, not C10's flat 43 chains. Therefore the WOTS+C reduction — internally sound in *direction* (both partners, and I, found no inequality reversal) — is **not concrete C10 evidence**; it bounds a game in an incompatible parameter family. Partner A's Appendix-A claim ("WOTS+C genuinely the strongest… unconditional… matches paper Thm C.2/D.1… the high-value increment has landed") is true of the abstract reduction and **false as C10 evidence**. Critically, this **does not touch `theft_free`**: A5-EUFCMA/A5-ITSR are cited-TCB; the kernel proof never consumes the EasyCrypt. So the correct consequence is "cannot promote EasyCrypt as concrete C10 security evidence," not "the proof is broken."

**CL-FRESH (B-F2) — CONFIRMED; Partner A's "statement-only" narrowing REFUTED.** `TxMerkleSpec.lean:214 verify_proof_spec` and `:91 verify_proof_loop_value` are real `:= by` proofs (no `sorry`) over the extracted `verify_proof`. Current Rust `merkle.rs` added `checked_mul` and `idx==0`@depth-0 rejection; committed extraction retains root-only/overflow-precondition semantics; at depth-1 `leaf_index=2` aliases in the old model but current Rust rejects (item-2; `make extract-tx-merkle` dies in Aeneas "Unreachable"). So a **proven** theorem now describes an older implementation — Partner A's first-pass claim that this rests on "a statement-only spec, no proven theorem" is wrong and I withdraw it. Systemic reach is the real HIGH: no workflow trigger regenerates `tx/src/**`, and item-3 shows even a `PQFW_V1→V2` domain-tag change stays green through `verify-extracted`/`verify-extract-differential`.

**CL-CLOSURE (A-F2 + B-F5 + B-F13 + items 1,8) — one finding, de-averaged.** Enforcement is **strict for the headline safety closure, weak/absent elsewhere.** Claim-4 (`theft_free` family) dumps and runs `check_axiom_closure.py` with the kernel-only allowed set (Makefile:324-332) — a genuine whitelist that rejects any non-`{propext,Classical.choice,Quot.sound}` axiom. But the extracted §33 gate (Makefile:401-403), format_decimal (:424), and the `verify-audit` headline dump (:310) grep `sorryAx` only — fail-open, canary-confirmed (item-4: `unmodeled_assumption_canary : False` passed with exit 0). lean4checker (item-1: completed, 58 modules) is kernel *replay*, which by construction accepts a kernel-valid project axiom — so it is not the closure backstop it is labelled as (B-F13), but the closure policy exists elsewhere (Claim-4). Net: **no path lets a rogue axiom into `theft_free` undetected**, but the extracted-correspondence and corollary layers can silently gain one. B-F5/B-F13 CONFIRMED and scoped; A-F2's "pending" premise RESOLVED.

**CL-EC-GATE (A-F1 ⊂ B-F8, + A-F5/A-F7, items 6,7) — CONFIRMED against the frozen tree.** The gate's green line means "10/21 compiled, 11 MM45-chain skipped, no MM45 verification," and item-7's frozen-root rerun proves this is not an artifact of pointing at live repos. Count-only axiom pinning (`:103`) is defeated by an equal-count body swap (item-6). Absent from `gate_enforcement.json`. This is real and matters because two of `theft_free`'s cited axioms name this development as their spot-checkable evidence — but again, cited-TCB, so it is a provenance/enforcement defect, not a soundness one.

**CL-PROTO / CL-CV / CL-KONTROL / CL-XHASH / CL-POLICY / CL-LEDGER / CL-FW** — all CONFIRMED as tabulated; CL-CV and CL-XHASH are SIMPLIFY (the Lean layers are honest; prose overstates); CL-KONTROL/CL-LEDGER/CL-POLICY are claim-fidelity FIX-NOW; CL-FW is currency/coverage MED.

## 5. Explicit changes to Partner A's first pass (packet item 4)

Stated plainly, not softened:
1. **WOTS+C overstatement — REFUTED.** Partner A Appendix A called the WOTS+C leg "genuinely unconditional" C10 evidence and "the high-value increment landed." Source (`WOTS_TW_ES.ec:31/61` vs `params.rs`) and item-11 show C10 (`log2_w=3`) is outside MM45's `{2,4,8}`. The leg is a sound abstract reduction, **not** C10 evidence. This is my most material correction.
2. **B-F3 adopted (narrowed MED).** Partner A did not trace digest semantics (self-disclosed in its residual). The machine-checked firmware↔chain binding is over the wrong function; I adopt this as MED.
3. **B-F5 adopted (narrowed).** Partner A missed the extracted-gate fail-open; canary (item-4) confirms it. Scoped away from `theft_free`.
4. **Tx-Merkle "statement-only" — REFUTED.** `verify_proof_spec` is a proven theorem over the stale model; I withdraw Partner A's "no proven theorem rests on it."
5. **A-F2 premise RESOLVED** by item-1 (lean4checker completed over 58 modules); only the "55 modules" doc figure remains, as LOW.
6. **Verdict moved** from blanket "APPROVE WITH RED-LINES" to axis-split, with **NO-GO on implementation-evidence/claim-promotion**.

Where I hold against Partner B (severity overstated): **B-F3 HIGH→MED**, **B-F1 HIGH→MED**, **B-F4 HIGH→MED** — each anchored to consequence above, not averaged. And B-F5/B-F13 must be read as scoped to the correspondence layer, not as reaching the safety closure.

## 6. Unresolved contradictions, NO-GOs, and separate recommendations

- **Unresolved correctness/coverage contradictions carried forward:** (a) the actual signed digest (`compute_sphincs_digest_v06`) has **no** machine-checked Rust↔spec extraction (CL-DIGEST); (b) no C10-instantiable WOTS security theorem exists (CL-EC-C10); (c) the shipping FW-update format is undecided (V1 proven / V4 frozen / V6 proposed) and unproven (CL-FW). None is a demonstrated exploit; all block "current evidence" promotion.
- **NO-GOs preserved:** implementation-evidence promotion of the frozen case (NO-GO); production shipment (NO-GO; independent + above).
- **Architecture:** APPROVE the `theft_free` kernel decomposition with red-lines CL-DIGEST/CL-FRESH/CL-CLOSURE/CL-EC-C10/CL-FW; do **not** present the assurance case as current shipping evidence until they close.
- **Merge:** unavailable (no candidate).
- **Shipment:** NO-GO — no source/model result here is hardware or release authority.

## 7. Deduplicated priority list (falsifiable acceptance conditions)

**FIX NOW**
1. **CL-DIGEST** — extract & prove `compute_sphincs_digest_v06` against a Lean spec, bridge parsed request fields to the signing argument, and relabel `compute_user_op_hash_spec` as EntryPoint-v0.6 tooling only. *Accept:* a machine-checked theorem over the signed digest + per-field flip tests + a Rust-only-drift negative that turns CI red.
2. **CL-FRESH** — regenerate all `extract-*` targets in a pinned deterministic checkout; trigger on `tx/src/**` + every mirrored crate; add a negative where a Rust-only mutation makes CI red. *Accept:* `PQFW_V1→V2` and the Tx-Merkle depth-1 alias each fail CI.
3. **CL-CLOSURE** — invoke `check_axiom_closure.py` (or equivalent whitelist) for the extracted §33 + format_decimal + audit dumps; add a permanent `axiom Evil : False` negative. *Accept:* the item-4 canary fails the gate.
4. **CL-EC-GATE / B-F8** — split partial vs full EasyCrypt targets; full requires 21/21 from pinned toolchain, rejects skips/missing/prebuilt-only deps, pins normalized axiom **names+types** (not counts), enrol in `gate_enforcement.json`. *Accept:* `EC_FV_ROOT=/missing` and item-6's `dmkey_ll:false` both fail.
5. **CL-PROTO / B-F9** — treat any nonzero prover exit as fatal before parsing; pin exact query/lemma identities. *Accept:* exit-42 and the `Install⇒Install` tautology both fail.
6. **CL-FW** — mark all V1/G10 evidence LEGACY; obtain an owner decision on one schema/digest (V4 vs V6). *Accept:* all four surfaces (FV, CLAUDE.md, work-todo, G10) name one format or G10 is explicitly legacy-scoped.
7. **CL-KONTROL / CL-LEDGER / CL-POLICY** — property-granular Kontrol prose; immutable required-row registry with cardinalities + tier/version/digest fields (ingest all 15 playbooks, default absent→`UNCLAIMED`); require an artifact-binding receipt before any "verified" release label. *Accept:* deleting a witness row, or shipping without a source↔artifact receipt, fails a gate.

**SIMPLIFY**
8. **CL-CV (B-F10)** — label CryptoVerif/Tamarin as the full-space ideal core; compose the conditioned `≤2⁻²⁵⁶` transfer; scope to one leaked share + independent-RNG premise.
9. **CL-XHASH (B-F12)** — replace "structurally disjoint/impossible" with an explicit computational cross-function assumption + quantitative bound; keep `∨ break` in headlines.
10. **A-F5/A-F6** — one-line doc fixes (README "8 axioms/5 g-constraints"; align `WOTS_C_EmbDischarge.ec` header to the post-2026-07-09 discharge).

**DEFER**
11. **A-F4** — CryptoVerif lib-path dual-layout probe (local-only; CI subset is proverif+tamarin).
12. **A-F2 residual** — regenerate the "55→58 modules" figure in `THE_CLAIM.md:62`.

**OPEN RESEARCH**
13. **CL-EC-C10 (B-F6/B-F7)** — see §8.

## 8. EasyCrypt disposition + WOTS parameter-representability (packet item 7)

**Assess representability first (as required):** decisive and negative. MM45's WOTS theory is parametrically fixed to `log2_w∈{2,4,8}` (`WOTS_TW_ES.ec:31,61`); C10 ships `log2_w=3` (`params.rs:46`) with no standard checksum and target-sum grinding. **No legal concrete C10 instantiation of the imported WOTS theorems exists today.** Every downstream leg (`WOTS_C_Real`/`_Scheme`/`_Reduction`, capstone) inherits this. Any adaptive/top-level EasyCrypt work is therefore premature: it would build on a WOTS base that cannot be pointed at shipped C10.

**Disposition: CONDITIONALLY CONTINUE as milestone-gated research; ABANDON two things.**
- **Abandon** the standalone `c10-eufcma-port.frozen` as a *separate evidence repository* — its 21 files are byte-identical to the vendored copies (both partners; no reviewer/implementation diversity).
- **Abandon** completing the abstract capstone FX-skeleton/XMSS-MT port as a headline goal — multi-person-year, A5 is cited-TCB regardless, on-chain safety (`theft_free` conjunct-1) is EUF-CMA-free. That is the proof-theater the playbook warns against.
- **Preserve** the genuinely useful research: DarkSide combinatorial arithmetic, the address-embedding/FLAG-2 discharge lemmas, the honest gap analyses (`SPHINCS_C_Skeleton.ec`), and the C10-faithful FORS *game shape* (`FORS_C10.ec`, which correctly grinds/carries `R`, per item-11 — not the paper counter).
- **First milestone (gate everything else on it):** a C10-faithful **no-checksum WOTS theory** — `w=8, log_w=3, L=43`, base-w extraction, target-sum-205 predicate-conditioned antichain/order lemma — reproving WOTS/hypertree reductions over *that* theory. Only after that do interactive-WOTS closure, the adaptive XMSS hop, exact C10 FORS routing/ranges/bounded-grinder terms, and a concrete `SPHINCS_PLUS_C` scheme/game become worthwhile. **Stop/reframe if the no-checksum WOTS theory or the XMSS hop cannot close.** Honest current label: *mechanized assumptions + partial reductions*, not C10 EUF-CMA. The 130.6-bit FORS figure is arithmetic (Python), not a reduction; `~2⁻²·⁶` advantage at `q_h=2¹²⁸`.

## 9. Ranked FV-surface expansion (value · feasibility · trust-base reduction · shipping-span · opportunity cost)

1. **Actual `compute_sphincs_digest_v06` end-to-end** (CL-DIGEST). V:H·F:H·TBR:H·Span:SHORT. Closes the real firmware↔chain binding with field-flip + drift negatives. **Top pick — highest value/feasibility ratio.**
2. **Global extraction freshness** (CL-FRESH). V:H·F:H·TBR:H·Span:N/A. Deterministic all-target regen + source-symbol manifest + pinned toolchain + Rust-only-drift negative. Cheap, systemic.
3. **A3.1 verifier ∀-signature via interpreter-refinement** (Verity scaffold). V:H·F:M·TBR:H·Span:SHORT. Moves the single named on-chain residual from corpus-KAT to model↔spec deductive.
4. **Authoritative FW-update schema/state-machine** (CL-FW). V:H·F:M (blocked on V4/V6 owner decision)·Span:MED. Prove source/model first; power-cut/FI separately.
5. **Release-artifact correspondence** (CL-POLICY). V:H·Span:LONG. Bind source+config+toolchain+generated-models+binary hash+proof receipt.
6. **C10-faithful WOTS/FORS security theory** (CL-EC-C10). V:H(crypto)·F:L·research-risky. Via §8 milestones only.
7. **Persistent state / page-123 / PIN-recovery under reset.** V:H(lifecycle)·F:L-for-Lean. Model crash-atomicity + refusal/recovery as composable stable models (per item-10); require separate silicon/power-cut evidence.
8. **Clear-sign intent→rendered-pixels policy projection.** V:M-H·F:M. Prove a *frozen policy projection* (parsed-intent/display injectivity + bounded pages), not every displayed field, and never present as LCD/silicon proof (item-10).

**Reject as low-value:** completing the abstract SPHINCS+C capstone; more V1 lemmas; finite KATs as universal equivalence; full-EVM verification; abstract silicon models as shipment proof; new binary/tool pilots that have not first established Cortex-M33 + emitted-instruction support (item-10).

## 10. Honest residual (the run is invalid without this)

**Strongest attacks that FAILED (mine + inherited, re-checked):**
- No re-detonating `False`/EUF-CMA path: the axiom concludes opaque `BreaksHash`; `isForgery` is key-history-bound; Claim-4 closure is strict kernel-only. No `theft_free` vacuity reproduced (source-only, G4 ceiling).
- No actual signing mismatch: Rust `compute_sphincs_digest_v06` and Lean `sphincsDigestPreimage` are field-for-field identical (360 B). B-F3 is missing proof, not a bug.
- No inequality reversal in the EasyCrypt local lemmas (both partners independently; I did not re-run the prover).
- No current-Rust Merkle acceptance bug — current Rust rejects the alias; the defect is stale *proof* correspondence.

**Unreviewed / not reproduced (execution & provenance limits):**
- I executed no proof toolchain. Coordinator execution-negatives (items 1,4,5,6,7) I grounded in **source reads of the gate mechanism** (grep-only §33 gate; `_run` never reads `returncode`; count-only axiom pin; `EC_FV_ROOT` skip logic) — this satisfies "reproduce from frozen source" at the gate level, but I did not observe the runs.
- **Item-9 Kani census** (148 harnesses/25 files vs 140/19 enrolled; 8 harnesses/6 files unmanifested; 3 full-only groups) and **item-8 LeanLoop/`leanloop.toml`** staleness — hash-verified receipts, but I cannot census without the toolchain; folded into CL-LEDGER, not independently elevated.
- Aggregate `ad0de135…` not recomputed (recipe excluded). Halmos/Kontrol bytecode discharge, the pinned-codehash→deployed-Base binding, ProVerif/Tamarin model *content*, Miri/fuzz corpora, and all hardware/FI/SCA/silicon/release-custody surfaces — **not reviewed**; no source/model result here is hardware or release authority.
- I read no live `/home/nicola/repos` copy and did not edit any frozen tree.

**Durability limit:** no file-write tool is available in this mode (Bash writes denied; Partner A's first pass hit the identical constraint). The authoritative deliverable is these returned bytes, which the orchestrator catalogues as it did for the first pass. Digests were re-verified immediately before emission; NO DRIFT.
```