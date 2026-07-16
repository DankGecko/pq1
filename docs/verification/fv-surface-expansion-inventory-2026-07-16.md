# FV surface-expansion inventory — 2026-07-16

> Complete deduplicated inventory of formally-verifiable surfaces identified in the
> 2026-07-15 full-stack FV review corpus (coordinator + both partner first-pass/cross
> reports + the assurance-expansion roadmap + FV_VALUE_AND_GAPS / OPEN_PROOF_OBLIGATIONS /
> FV_SURFACE_MAP / THREAT_CLAIM_MAP). Compiled by a 2-reader scout workflow, deduped by id.
> `[OWNER]` = the roadmap flags a separate owner decision/plan before starting.
> Tooling reality on this box: TLA+/TLC (jar fetched), BINSEC, Kani, Miri, Lean/Aeneas,
> proverif/tamarin/cryptoverif, EasyCrypt, Halmos/Kontrol present; Apalache/Verus/Crux/SAW absent.

**47 surfaces.** Ranked value↓ then tractability↓. Many `high/high` rows in the
gate-integrity cluster were already closed by the 2026-07-16 FV-review implementation
(F1–F11); the genuinely-new proof surfaces are called out in the lead-in.


## value=high · tractability=high

### `actual-signed-digest-correspondence` — On-chain/firmware signing-digest correspondence (UserOp Type-1/Type-2)
- **Verify:** Prove the ACTUAL signed digest end-to-end: parsed sign-request fields -> firmware compute_sphincs_digest_v06 (single SHA-256, 360-B preimage) -> signing argument -> PQSmartWallet.sphincsDigest recomputation, with per-field flip tests and a Rust-only-drift negative. Residual today: the extracted headline (UserOpEquivByteLayout.compute_user_op_hash_spec) proves the EntryPoint double-keccak TOOLING helper, which has no production signing caller; the on-chain sphincsDigest_field_binding is proven and the Rust/Lean 360-B layouts match only by hand-inspection - there is NO machine-checked Rust->Lean extraction of the digest actually signed. Not a demonstrated mismatch, a missing universal bridge.
- **Tooling:** Aeneas/Lean (extract+prove digest) + Rust/Lean/Solidity differential vectors
- **First step:** Add an Aeneas extract-* target for aa::userop::compute_sphincs_digest_v06 and write a Lean spec asserting the exact 360-B field order; relabel compute_user_op_hash_spec as EntryPoint-v0.6 tooling-only.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:F2 + Ranked assurance-surface expansion #2; fv-full-stack-2026-07-15-partner-b-first-pass.md:F3 + Ranked FV-surface #1; fv-full-stack-2026-07-15-partner-a-cross.md:§4 CL-DIGEST + priority #1; fv-full-stack-2026-07-15-partner-b-cross.md:B-F3 + FIX-NOW #3; formal-verification-assurance-expansion-2026-07-15.md:P1.7

### `claim-artifact-version-ledger` — P0.2 — mechanical claim → statement → theorem → assumption-closure → digest → version → mutation ledger
- **Verify:** Every public claim resolves mechanically through claim-ID→exact-statement→theorem/query→complete assumption closure→source/model/artifact digest→tool/version/profile→gate/trigger→mutation-or-reachability witness→last dual review; reject a row if the model proves V1 while owner target is V4/V6, if prose says canonical userOpHash while code/theorem uses the project sphincsDigest, or if a historical local session is presented as a standing gate. RESIDUAL: today several claims are broader than evidence (SMAP#2 'transcription-free' wording > validate-wrapper evidence).
- **Tooling:** Lean `#print axioms` + gate scripts + digest receipts
- **First step:** Build the claim→closure table for the theft_free headline and flag every row where model-version ≠ owner target or prose-digest ≠ code-digest.
- **Refs:** ROADMAP §P0.2; FV_SURFACE_MAP.md rows 1-2; OPEN_PROOF_OBLIGATIONS.md §Group V (userOpHash vs sphincsDigest)

### `durable-counter-crash-recovery` — Durable signing-counter store crash-consistency (page-123/124 journal)
- **Verify:** Model page-123 log-structured per-slot counters (local_offchain_count, last_userop_count, registration) + page-124 PIN store: compaction, erase/program ordering, torn writes, reset/reboot recovery. Invariants: recovery yields the old OR new committed state OR fail-closed (never a security-relevant mixture); counters never decrease; release implies a prior durable charge; at most one release per charge; charged-but-unreleased (power loss after charge, before transport) is allowed and accounted. Residual: no crash-atomicity model exists; needs separate silicon/flash-ECC/brownout evidence.
- **Tooling:** TLA+/TLC (installed) for the finite crash model; optional Verus+PoWER pure journal kernel (Verus absent)
- **First step:** Write a TLA+ spec of the offchain_state.rs log-append + compaction with a crash action between every flash program/erase, and model-check monotonicity + no-partial-record recovery in TLC.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:Ranked #4; formal-verification-assurance-expansion-2026-07-15.md:P1.1 (invariants 1,5,6); fv-full-stack-2026-07-15-partner-b-first-pass.md:Ranked #7; fv-full-stack-2026-07-15-partner-b-cross.md:Ranked #4/#7

### `fail-closed-skip-and-semantic-identity-pins` — P0.3 — fail-closed on skip; pin semantic identities (axioms, ProVerif queries, Tamarin lemmas, Kani census); subprocess-failure propagation
- **Verify:** EasyCrypt full-build fails on any skipped unit/dependency and rebuilds the upstream source closure (no stale .eco); axiom NAMES/types/defining-files/consumers/realizations pinned (not counts); ProVerif query + Tamarin lemma identities + normalized verdicts pinned (not per-file counts); Kani census + mutation set generated from source; an unenrolled formal surface is a failure or reviewed local-only residual. RESIDUAL now BROKEN: the protocol driver ignores subprocess return codes (a tautological query and a synthetic exit 42 both pass), CryptoVerif's launcher uses the wrong library path, EasyCrypt compiles 10/21 and skips 11 MM45 files while exiting 0, 8 Kani harnesses/6 files + 3-of-31 mutation groups are unenrolled/full-only.
- **Tooling:** EasyCrypt/Tamarin/ProVerif/CryptoVerif (all present) native flags + gate scripts
- **First step:** Fix the protocol driver to propagate non-zero subprocess exit and pin query/lemma identities; add an EasyCrypt fail-on-skip/admit sweep (require-does-not-reverify: must compile EVERY file as a target).
- **Refs:** ROADMAP §P0.3; FV_SURFACE_MAP.md rows 4,6,9; FV_SURFACE_MAP.md §Expansion order #1

### `signed-intent-to-display-pipeline` — P1.2 — pure semantic pipeline: wire bytes → canonical intent → exact signed digest → display pages → confirm (WYSIWYS)
- **Verify:** For every supported single/batch/deploy/rotation/Safe/CoW/MultiSend/ERC-7730/EIP-712/off-chain route: each displayed authority/value/recipient/chain/nonce/gas/operation field is bound to the signed bytes; the frozen display-policy projection exposes every field needed for an informed decision (each excluded field has an explicit rule or triggers the loud blind-sign path); pagination/truncation/aliases/duplicate-names/dynamic-offsets/trailing-bytes/overflow/metadata-lookup/batch-ordering cannot create show-one/sign-another; the digest theorem uses the EXACT project sphincsDigest with EntryPoint semantics stated separately. RESIDUAL: metadata truth, pixels/panel delivery, human comprehension, and physical confirmation hardware stay OUTSIDE formal scope (separate evidence). This is FV's declared blind spot where every historical HIGH lived.
- **Tooling:** Kani (present) / Aeneas-Lean around the existing host-extracted no-heap kernels (pqsigner-tx, pqsigner-erc7730)
- **First step:** Extract secure/src/tx/eip712/safe/cow_binding.rs (orderUid.owner==Safe) — currently UNCITED/un-Kani'd per THREAT_CLAIM fn3 — and Kani-prove that binding plus gas-lane disambiguation, with a mutation that hides a page or rebinds a field forced to fail.
- **Refs:** ROADMAP §P1.2; FV_SURFACE_MAP.md §Expansion order #2; FV_VALUE_AND_GAPS.md §3 (real HIGHs in clear-sign); THREAT_CLAIM_MAP.md S-DISPLAY-VS-SIGN[^4], S-CLEAR-SIGN-DECODE-DRIFT[^3]

### `sphincs-digest-onchain-firmware-bridge` — P1.7 / Group V — production compute_sphincs_digest_v06 ↔ contract PQSmartWallet.sphincsDigest byte-exact bridge
- **Verify:** Prove the firmware compute_sphincs_digest_v06 preimage equals the deployed PQSmartWallet.sphincsDigest preimage byte-for-byte, and that the parsed handler path passes EXACTLY that digest to signing. RESIDUAL: today this rests only on KAT/corpus agreement; prose broadly says 'userOpHash' while the deployed wallet IGNORES the canonical keccak hash and binds the project sphincsDigest — an exact-artifact correspondence is owed.
- **Tooling:** Lean + differential/KAT (both preimages are concrete byte layouts)
- **First step:** Extract both preimage builders and prove structural byte-equality in Lean with a KAT cross-check against the deployed contract.
- **Refs:** ROADMAP §P1.7; FV_SURFACE_MAP.md §Expansion order #2; OPEN_PROOF_OBLIGATIONS.md §Group V + historical-plan notice


## value=high · tractability=medium

### `a31-verifier-forall-refinement` — A3.1 SPHINCS+C10 Yul verifier ForAll-equivalence (on-chain)
- **Verify:** Move A3.1 from tier-C corpus-KAT to a deductive kernel model<->spec ForAll-equivalence of the C10 verifier via interpreter-refinement (Verity-style execC10Asm), so the verifier is proven correct on all inputs with opaque hash, not just the KAT corpus. Residual: model<->spec ForAll is reportedly already CLOSED on master; the genuine remaining residual is the R1 bytecode<->AST transcription (cited-TCB) - distinct from surface source-to-deployed-bytecode-r1b which is the general contract transcription leg.
- **Tooling:** Lean (interpreter-refinement over the Yul/AST model)
- **First step:** Confirm the current state of execC10Asm_eq model<->spec closure on master and scope the residual precisely to the R1 bytecode<->AST transcription that would remain cited-TCB.
- **Refs:** fv-full-stack-2026-07-15-partner-a-first-pass.md:Appendix B #1 (top pick); fv-full-stack-2026-07-15-partner-a-cross.md:§9 Ranked #3

### `current-source-freshness-gate` — P0.1 — proof/artifact freshness: current-source ↔ generated/extracted-Lean identity
- **Verify:** Every generated/extracted artifact regenerates byte-for-byte from the exact current source in a clean env or the gate fails; a semantic Rust mutation (domain tag) must turn it red; security-policy constants and theorem statements pinned independently of the impl they constrain. RESIDUAL: false-green freshness is currently REPRODUCED (SMAP#3: current Tx-Merkle Rust differs semantically from committed extraction, regeneration fails, a Rust domain-tag mutation passes both gates); the committed differential stays valid only as an independent KAT/translation layer AFTER a real regen gate exists.
- **Tooling:** gate script + pinned Charon/Aeneas regeneration + Kani/differential cross-check
- **First step:** Charon/Aeneas are NOT on PATH here — first pin+reinstall the exact extractor toolchain, wire a `regenerate-and-diff` target, then add the domain-tag Rust mutation as a must-be-red test.
- **Refs:** ROADMAP §P0.1; FV_SURFACE_MAP.md row 3; FV_VALUE_AND_GAPS.md §Current open assurance gaps

### `durable-usage-accounting-model` — P1.1a — durable usage-accounting state machine (page-123/124 counters, compaction, crash recovery) — ROADMAP's HIGHEST-VALUE new surface
- **Verify:** Over page-123/124 records + compaction + erase/program ordering + torn writes + corruption/ECC + reset/reboot recovery: every generated signing query consumes the correct aggregate lifetime budget; release implies a prior durable charge; ≤1 release per charge; counters never decrease; charged-but-unreleased (power-loss-after-charge) is legitimately allowed and explicitly accounted; monotonicity holds across per-slot/bootstrap/off-chain/on-chain/aggregate-per-public-key counters and EVERY signature-release route. RESIDUAL: TLC gives crash traces + BOUNDED invariant checking only; the all-length proof needs the inductive-invariant path (Apalache — ABSENT here) or the linked pure-Rust transition kernel via Kani/Aeneas. Firmware compaction atomicity (single-page erase-then-replay, not two-phase) is currently unverified.
- **Tooling:** TLA+/TLC for crash traces (tla2tools NOT yet on PATH) + pure-Rust transition kernel via Kani (present) for the universal monotonicity leg
- **First step:** Install tla2tools.jar; extract the page-123/124 RMW+compaction into a pure transition kernel; TLC-model torn-write/reset/reboot against the invariant-5 charge-before-release properties, then Kani the kernel for the no-decrease universal leg.
- **Refs:** ROADMAP §P1.1 (invariants 1,2,5,6) + §P2 TLC pilot; FV_SURFACE_MAP.md §Expansion order #3; THREAT_CLAIM_MAP.md S-PAGE123-TEAR, S-OFFCHAIN-OVERSPEND, S-SLOT-STATE-CORRUPT

### `firmware-update-rollback-boot-statemachine` **[OWNER-GATED]** — Owner-selected firmware update / rollback / A-B boot state machine
- **Verify:** Specify and verify the CURRENT (not V1) firmware-update format + state machine: exact domain-tag/version/length/field order, signed-vs-hashed bytes, target partition identity, rollback/version-floor + A/B journal transitions, power-cut at every erase/program/commit boundary, abort/retry/recovery, cross-version compatibility, key/authority rotation; ProVerif authenticity model over the SAME current message structure. Residual: authoritative format is undecided (FV proves legacy PQFW_V1/75B; CLAUDE.md freezes V4/80B; work-todo proposes V6/121B); the whole update backend is an open ship-blocker.
- **Tooling:** TLA+/TLC (state machine) + ProVerif (authenticity over current message)
- **First step:** Do NOT model yet - first drive the owner V4-vs-V6 schema/digest decision to freeze the transition semantics, then TLA+ the chosen manifest+boot-selection with a power-cut action.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:Ranked #5 + F4; formal-verification-assurance-expansion-2026-07-15.md:P1.3 + P1.1; fv-full-stack-2026-07-15-partner-b-first-pass.md:F1 + Ranked #3; fv-full-stack-2026-07-15-partner-a-first-pass.md:F3

### `provisioning-wipe-rma-authority` **[OWNER-GATED]** — Provisioning / first-boot / wipe / re-pairing / RMA authority lifecycle
- **Verify:** Model factory->transit->first-boot->RDP/BHK/option-byte transitions and the wipe/seed-recovery/re-pairing/key-rotation/RMA authority graph. Invariants: no partially-provisioned or partly-wiped state releases a signature or key; wipe/recovery/RMA cannot resurrect an older key, pairing, counter, or policy; compromise-before/after-provisioning timing. Residual: the first-boot rdp2-self-lock ceremony is production-quarantined (unstable/unapproved), so the transition semantics are not yet frozen; silicon/option-byte/physical-erase behavior stays as hardware assumptions.
- **Tooling:** TLA+/TLC (authority state machine) + Tamarin (compromise timing / replay)
- **First step:** Wait on the owner freeze of the first-boot ceremony, then Tamarin-model the wipe->re-pair authority edges with an attacker who can interrupt any transition.
- **Refs:** formal-verification-assurance-expansion-2026-07-15.md:P1.1 + P1.6; fv-full-stack-2026-07-15-partner-b-first-pass.md:Ranked #7; fv-full-stack-2026-07-15-partner-b-cross.md:OPEN-RESEARCH

### `query-budget-lifetime-cap` — Aggregate per-public-key lifetime signature cap composition
- **Verify:** Compose EVERY signature-release route (bootstrap Type-1, counterfactual, off-chain EIP-1271/6492, cross-chain reuse, batch, rotation, recovery) onto one aggregate per-public-key lifetime counter; state which threat curve and which cryptographic assumption requires the 2^16 cap (MAX_BOOTSTRAP_USES/MAX_SLOT_USES + MAX_OFFCHAIN_GAP=100) and prove the operational system enforces that premise. Residual: current Lean CreditLedger is per-index; the whole-route composition + the crypto justification are not proven; NIST SP 800-230 (2^24 limited-use SLH-DSA) is corroboration only, not C10 validation.
- **Tooling:** Lean (extend CreditLedger) or TLA+/TLC
- **First step:** Enumerate all sign/offchain code paths that bump a counter and draft the single aggregate-per-pubkey invariant they must jointly maintain, keeping the per-index Gap-2 credits-merge lemma.
- **Refs:** formal-verification-assurance-expansion-2026-07-15.md:P1.5; fv-full-stack-2026-07-15-coordinator.md:Ranked #4; fv-full-stack-2026-07-15-partner-b-cross.md:Ranked #4

### `query-budget-lifetime-theorem` — P1.5 — aggregate per-public-key lifetime counter over EVERY signature-producing path
- **Verify:** Compose bootstrap/counterfactual/off-chain/cross-chain-reuse/batch/recovery signing paths with one aggregate per-public-key lifetime counter; state which threat curve and which cryptographic assumption requires the cap, then prove the operational system enforces that premise. RESIDUAL: NIST SP 800-230 IPD (2^24 limited-use SLH-DSA) corroborates that lifetime counts can be load-bearing proof premises but does NOT validate C10 or PQSigner's chosen 2^16 cap; the operational-enforcement side lives in the durable-accounting model.
- **Tooling:** Lean (compose with existing on-chain combined-cap invariant Invariants.lean) + link to durable-usage-accounting-model
- **First step:** Enumerate every signature-release route and prove each consumes the correct aggregate budget in the Lean model, then bind to the C10 birthday/threat curve that motivates 2^16.
- **Refs:** ROADMAP §P1.5; ROADMAP §Primary sources (SP 800-230); CLAUDE.md Invariant #7 (MAX_*_USES=65536)

### `shipping-thumb-ct-binsec` — P1.8 — constant-time on selected load-bearing Thumb symbols from the SHIPPING compiler/profile
- **Verify:** Run BINSEC/Rel on selected load-bearing Thumb symbols/objects emitted by the shipping profile (opt=s, LTO, codegen-units, features, linker script) with pinned entry points/bytes and secret/public classification. RESIDUAL/NO-GO: FIRST demonstrate the analyzer semantics cover the emitted Cortex-M33 instruction subset; NOT a whole post-LTO shipping-ELF theorem while symbol extraction/relocation/unsupported M-profile instructions stay outside the checked artifact; binary CT is NOT physical SCA resistance and does NOT close S-SCA-PRF-LEAK (the sole UNCLAIMED threat) nor S-CT-BRANCH physically.
- **Tooling:** BINSEC (present; checkct wrapper NOT on PATH)
- **First step:** Pick one symbol (subtle compare in crypto::c10_sign_verified or the PIN path), extract its Thumb, and first prove BINSEC decodes the emitted Cortex-M33 instruction subset before asserting CT.
- **Refs:** ROADMAP §P1.8 + §no-go 'binary CT ≠ physical SCA'; FV_SURFACE_MAP.md row 7; THREAT_CLAIM_MAP.md S-CT-BRANCH, S-SCA-PRF-LEAK (UNCLAIMED)

### `signed-intent-display-projection` — Clear-signing: signed-intent -> trusted-display page projection
- **Verify:** Extract a pure pipeline wire-bytes -> canonical decoded intent -> exact signed preimage/digest -> display-page model -> confirm decision, and prove for every route (single/batch/deploy/rotation/Safe/CoW/MultiSend/ERC-7730/EIP-712/off-chain): each displayed authority/value/recipient/chain/nonce/gas/operation field is bound to the signed bytes; the frozen display-policy projection exposes the decision-required fields or triggers the loud blind-sign path; pagination/truncation/aliases/duplicate-names/dynamic-offsets/trailing-bytes/overflow cannot create show-one/sign-another; the digest theorem uses the exact project digest. Residual: metadata truth, pixels/panel delivery, human comprehension, and confirm hardware stay non-formal.
- **Tooling:** Kani or Aeneas/Lean around the existing host-linkable no-heap render kernels (Crux-MIR/Vest diversity pilots absent)
- **First step:** Start with the highest-risk shared kernel - CoW owner/order-UID binding + gas-lane disambiguation - and add a Kani harness that mutates a field binding or hides a page and must fail.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:Ranked #2; formal-verification-assurance-expansion-2026-07-15.md:P1.2; fv-full-stack-2026-07-15-partner-b-first-pass.md:Ranked #8; fv-full-stack-2026-07-15-partner-a-cross.md:§9 Ranked #8; fv-full-stack-2026-07-15-partner-b-cross.md:Ranked #6

### `txmerkle-freshness-reproof` — Aeneas-extracted Tx-Merkle verifier (and mirrored decoder freshness)
- **Verify:** Regenerate the Tx-Merkle extraction from current Rust and prove the stricter current semantics: checked_mul overflow rejection and idx==0-at-depth-0 rejection, including the depth-1 leaf_index=2 alias NEGATIVE. Residual: the committed proven theorem verify_proof_spec/verify_proof_loop_value describes the OLD (aliasing/overflow-permissive) model; `make extract-tx-merkle` currently dies in Aeneas with 'Unreachable' on verify_proof; ~15 mirrored crate functions may be similarly stale (systemic).
- **Tooling:** Aeneas/Lean (Charon+Aeneas regeneration then re-prove)
- **First step:** Reproduce the Aeneas 'Unreachable' failure on verify_proof, minimize it, and get a clean regeneration of tx/src/erc20/merkle.rs before re-proving root-equality with the checked_mul + idx==0 refinements.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:F1; fv-full-stack-2026-07-15-partner-b-first-pass.md:F2 + Ranked #2; fv-full-stack-2026-07-15-partner-a-cross.md:§4 CL-FRESH; fv-full-stack-2026-07-15-partner-b-cross.md:B-F2 + FIX-NOW #2; formal-verification-assurance-expansion-2026-07-15.md:P0.1


## value=high · tractability=low

### `c10-native-wots-theory` **[OWNER-GATED]** — C10-native (checksum-free) WOTS EUF-CMA theory (EasyCrypt)
- **Verify:** Define and prove an exact C10 WOTS theory - w=8, log_w=3, L=43, no standard checksum, base-w extraction, u32-BE counter, target sum 205, 10M cap - replacing MM45's global checksum encoding with a precise target-sum-conditioned antichain/order lemma, and reprove the WOTS/hypertree reductions over that theory. Residual: shipped C10 (log2_w=3) is structurally OUTSIDE MM45's parametric universe log2_w in {2,4,8}; no legal concrete C10 instantiation of the imported WOTS theorems exists today, so this blocks all downstream C10 EasyCrypt legs. Several expert-months, plausibly person-year scale.
- **Tooling:** EasyCrypt (present in gate infra; research-scale)
- **First step:** Pass the C10 representability stop/go gate first: show the imported WOTS foundation can express w=8/log_w=3/L=43/target-sum without a foundational rewrite, or preserve the work and stop.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:F6 + EasyCrypt decision stage 2; fv-full-stack-2026-07-15-partner-b-first-pass.md:F6 + continuation #2; fv-full-stack-2026-07-15-partner-a-cross.md:§8 milestone 1; fv-full-stack-2026-07-15-partner-b-cross.md:EasyCrypt disposition; formal-verification-assurance-expansion-2026-07-15.md:EasyCrypt stage 2

### `deployed-bytecode-residual-r1` — P1.7 — A3.1 R1 source→deployed-bytecode transcription (the SOLE remaining A3.1 residual)
- **Verify:** Continue the COMPOSITIONAL Lean-interpreter / KEVM / Kontrol route to close the R1 bytecode↔AST transcription and bind every session to codehash/compiler/solver/deployed-bytecode receipts. RESIDUAL/NO-GO: must NOT add a generic new Solidity source verifier while the exact deployed-bytecode bridge stays open (explicit no-go), and must NOT be reported as whole-target verification; solc/Yul/deployed-bytecode identity remains the boundary.
- **Tooling:** KEVM/Kontrol (present) + compositional Lean interpreter
- **First step:** Pin the deployed codehash + solc/solver receipts and stand up a KEVM/Kontrol equivalence session for SPHINCsC10Asm as the first object.
- **Refs:** ROADMAP §P1.7 + §no-go 'another Solidity source verifier'; FV_SURFACE_MAP.md row 2; OPEN_PROOF_OBLIGATIONS.md §Group B (A3)

### `firmware-ab-rollback-state-model` **[OWNER-GATED]** — P1.1b / P1.3 — A/B firmware + manifest + OTP version-floor + rollback/abort/recovery state machine
- **Verify:** Model A/B state, pending/committed manifests, OTP/version floor, rollback, abort, recovery, and power-cut at every erase/program/commit boundary; prove invariant #2 (no reset/power-cut trace decreases an accepted firmware version or durable count) and cross-version compatibility. RESIDUAL: the EXACT manifest schema (domain-tag/version/length/field-order, signed-vs-hashed bytes, target-partition identity) is OWNER-GATED until the V4/V6 owner-document conflict is resolved; only V1 evidence exists today (S-FW-PREIMAGE-EXPAND is PARTIAL-legacy-V1-only); the anti-rollback is single-layer OTP-floor (claimed OPTIGA E1E0 cross-check ABSENT in cmd_fw_commit.rs).
- **Tooling:** TLA+/TLC (jar not yet on PATH) + Tamarin for adversarial ordering
- **First step:** Model only the STABLE A/B-journal + OTP version-floor + power-cut transitions in TLA+ with invariant #2 as a skeleton, pending owner freeze of the V4/V6 schema (do not formalize the manifest layout before the owner resolves it).
- **Refs:** ROADMAP §P1.3 + §P1.1 (A/B); FV_SURFACE_MAP.md §Expansion order #4; THREAT_CLAIM_MAP.md §controlling-overrides + S-FW-ROLLBACK, S-FW-UNSIGNED

### `provisioning-wipe-recovery-authority-model` **[OWNER-GATED]** — P1.1c / P1.6 — factory/transit/first-boot/SE-pairing/BHK/RDP/option-byte + wipe/seed-recovery/re-pairing/key-rotation/RMA authority
- **Verify:** Prove invariant #3 (no partially-provisioned or partly-wiped state releases a signature or key) and invariant #4 (wipe/recovery/RMA cannot resurrect an older key, pairing, counter, or policy), with compromise-before/after-provisioning, partial-counter-reset, and abnormal-reset traces. RESIDUAL: the first-boot/BHK/RDP/option-byte transition semantics are NOT frozen (CLAUDE.md: first-boot rdp2-self-lock is production-quarantined pending handoff/recovery/E140-order/silicon gates), so a faithful model can't be built now; silicon counter/reset behavior stays an HW-receipt assumption.
- **Tooling:** Tamarin (present) for compromise-timing/authority + TLA+/TLC
- **First step:** Blocked on owner sign-off of frozen transition semantics; until then, draft the Tamarin authority skeleton (factory→first-boot→rotate) as a design artifact only.
- **Refs:** ROADMAP §P1.1 (invariants 3,4) + §P1.6 + §no-go 'unstable lifecycle before owner freeze'; THREAT_CLAIM_MAP.md OUT-OF-SCOPE ship-blockers S-1/S-2/S-3

### `release-artifact-provenance-chain` — Release-artifact / source-to-binary provenance correspondence
- **Verify:** Bind source + configuration + toolchain + generated/extracted models + binary/ELF hashes + proof receipt as ONE checked correspondence chain (reproducible build -> signed release), and REVERSE the README 'proofs after release apply for free because formats are frozen' policy: either proofs gate the release claim, or any retrospective 'verified' label must bind the exact shipped artifact digest to source/config/toolchain/generated-models/closure/receipt. Residual: no release candidate/ELF/reproducible-release/source-to-binary theorem/signing-custody evidence exists yet; span is long.
- **Tooling:** Reproducible-build + machine-readable receipt/manifest (not a prover); fwmeasure/xtask
- **First step:** Define the receipt schema (source/model/dep/compiler/ELF/config digests + tool versions + closure + drift) and emit it from the reproducible-build path for one component.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:Ranked #3 + F4 + Not-reviewed(release); formal-verification-assurance-expansion-2026-07-15.md:P0.4 + Priority-1 exec; fv-full-stack-2026-07-15-partner-b-first-pass.md:F4 + Ranked #4; fv-full-stack-2026-07-15-partner-b-cross.md:Ranked #3 + FIX-NOW #9

### `source-to-deployed-bytecode-r1b` — Contract source -> deployed-bytecode transcription (R1b) + live-chain codehash binding
- **Verify:** Close the general source->deployed-bytecode residual (R1b) through the compositional Lean-interpreter/KEVM/Kontrol route: bind solc/Yul/deployed bytecode to the proven source model, and bind the pinned codehash to the live Base Mainnet deployed code. Residual: today cited-TCB; every local session must carry codehash/compiler/solver/harness/deployed-bytecode receipts; do NOT add a generic Solidity verifier that proves another source model while leaving the bytecode leg open.
- **Tooling:** Kontrol/KEVM (source->bytecode), reproducible codehash check
- **First step:** Re-fetch the live Base Mainnet codehash for the verifier/wallet and confirm it still equals the pinned DeployedBytecodeReproCheck value before extending the transcription proof.
- **Refs:** formal-verification-assurance-expansion-2026-07-15.md:P1.7 (row 2 residual R1b); fv-full-stack-2026-07-15-partner-a-first-pass.md:Honest-residual (Halmos/Kontrol + codehash->Base binding); fv-full-stack-2026-07-15-coordinator.md:Ranked #6


## value=medium · tractability=high

### `durable-proof-receipts` — P0.4 — machine-readable replayable receipts for heavy/local gates
- **Verify:** Halmos, Kontrol, EasyCrypt, lean4checker, CryptoVerif, and binary-CT gates each emit a receipt binding source/model/dependency/compiler/bytecode-ELF/config digests + exact tool/solver versions + command line + query/theorem/harness identity + result + environment/evidence-tier + start/end drift. RESIDUAL: today a prose 'session once passed' is historical evidence, not a replayable artifact.
- **Tooling:** receipt-schema harness invoked by each gate
- **First step:** Define the receipt JSON schema and wire it into `make verify-bytecode`/Kontrol/Halmos runs first (Foundry/kontrol/halmos are present).
- **Refs:** ROADMAP §P0.4; FV_SURFACE_MAP.md row 2 (durable versioned proof receipts)

### `firmware-bounded-verification-coverage` — Firmware Kani/Halmos/Kontrol bounded-property coverage (decoders + counters)
- **Verify:** Prove NEW bounded properties on the exact firmware decoder/counter code where the real HIGH-severity bugs historically lived - starting with multiSend canonical-acceptance (per-record op==0, <=6 records, exact framing, pinned MultiSendCallOnly) extracted into pqsigner-tx as a Kani proof, then off-chain counter sequence/interleave. Residual: this is statement-strength/architecture-width coverage (bounded implementation evidence, NOT universal), distinct from the stale-census/manifest gate fix; must not be promoted as universal proof.
- **Tooling:** Kani (installed, `make kani` wired) + Halmos/Kontrol
- **First step:** Extract secure/src/tx/eip712/safe/multi_send.rs decode into pqsigner-tx and write the multiSend canonical-acceptance Kani harness.
- **Refs:** fv-full-stack-2026-07-15-partner-b-cross.md:Ranked #7; formal-verification-assurance-expansion-2026-07-15.md:surface-map row 4 (Firmware Kani residual); fv-full-stack-2026-07-15-coordinator.md:Not executed (fresh full Kani campaign)

### `trustzone-linker-map-proof` — P1.9 — generated SAU/IDAU/GTZC + linker-map placement/pointer-contract proof (P1.9)
- **Verify:** Prove GENERATED interval/config evidence bound to the exact linker map/register artifact: SAU/IDAU/GTZC regions+permissions; linker-map placement of secrets, NSC veneers, vector tables, stacks, shared buffers; cross-world pointer range/overflow + gateway contracts; interrupt/exception ownership; exact production register images + feature combos. RESIDUAL/NO-GO: explicitly NOT whole STM32U5 semantics — peripheral behavior, un-modeled CMSE instruction semantics, and silicon errata remain assumptions/target evidence.
- **Tooling:** generated-fact checker over .map + SECCFGR images + Kani (present) for the pointer range/overflow rules (existing SAU/NS-window compile-time subset assert)
- **First step:** Emit the SAU/GTZC region table + parse the shipping .map, assert every secret/veneer lies in a Secure region with no NS overlap, and bind the facts to the map/register digest.
- **Refs:** ROADMAP §P1.9 + §no-go 'whole STM32U5 binary verification'; FV_SURFACE_MAP.md row 5; THREAT_CLAIM_MAP.md S-NS-SECRET-LEAK, S-SRAM-NS-READ


## value=medium · tractability=medium

### `create2-address-chain-independence` — Group W I-7 — full CREATE2 wallet-address chain-independence (currently only SALT proven)
- **Verify:** Prove the CREATE2 address keccak256(0xff‖deployer‖salt‖keccak256(initCode)) is chain-independent. RESIDUAL: only the SALT preimage is proven chain-free (rfl); the address-level theorem create2Address_chain_independent is CONDITIONAL on cited EVM-TCB facts deployer1=deployer2 (singleton factory) and initCodeHash1=initCodeHash2 (frozen initCode) — the chain-freeness of the deployer address and keccak256(initCode) is cited-TCB, not modelled in Lean.
- **Tooling:** Lean (+ deployment receipt for the two EVM-TCB premises)
- **First step:** Model the singleton-factory deployment + frozen-initCode facts (or bind them to a deployment receipt) to discharge deployer= and initCodeHash= premises.
- **Refs:** OPEN_PROOF_OBLIGATIONS.md §Group W I-7 + §Status W row; CLAUDE.md Invariant #6

### `cross-hash-separation-game` — Keccak / SHA-256 cross-function separation (off-chain binding, OC2)
- **Verify:** Replace the 'structurally disjoint / structurally impossible' prose with an explicit computational cross-function collision/preimage GAME and quantitative bound (both outputs inhabit the same ByteVec 32 codomain), keep the '... OR BreaksHash' conclusion in headlines, and mark OC2 partial/cited-TCB. Residual: the correct quantitative bound depends on whether the target is fixed or both messages vary - it is not automatically a 2^-256 statement.
- **Tooling:** Lean (Wallet/OffchainBinding.lean + Crypto/Assumptions.lean) + optional CryptoVerif/EasyCrypt game
- **First step:** Define a distinct keccak_sha256_cross_separation game token in Assumptions.lean with an explicit advantage parameter and thread it through OffchainBinding.
- **Refs:** fv-full-stack-2026-07-15-partner-b-first-pass.md:F12; fv-full-stack-2026-07-15-partner-b-cross.md:B-F12; fv-full-stack-2026-07-15-partner-a-cross.md:§4 CL-XHASH; formal-verification-assurance-expansion-2026-07-15.md:SIMPLIFY

### `directional-pin-reconcile-model` — P1.6 — replace the symmetric PIN model with the exact DEPLOYED directional page-124/E120 reconcile
- **Verify:** Model the exact deployed directional reconcile: gated_unlock precharges MCU page-124, a wrong attempt advances OPTIGA E120 + SE050 UserID, boot wipes when E120>page124 (MCU lead = conservatively-charged power-cut state), and the production SE050 UserID DENIES attempt-reads (SW=0x6986) so it is NOT a reconcile input; each correspondence premise needs a positive existence witness and a negative mutation. RESIDUAL: the current tamarin/pin_lockstep.spthy is symmetric/abstract and (by its own caveats) overstates the deployed directional reconcile and models neither the wrong-PIN bump rule nor where the compare executes; silicon counter/reset behavior stays an HW-receipt assumption; three-way boot reconciliation is explicitly NOT claimed.
- **Tooling:** Tamarin (present) — make the existing symmetric model directional
- **First step:** Rewrite pin_lockstep.spthy directionally (drop SE050 as a reconcile input) and add the negative mutation: a symmetric-reconcile variant must FAIL.
- **Refs:** ROADMAP §P1.6; CLAUDE.md Invariant #2; THREAT_CLAIM_MAP.md S-PIN-COMPARE-SW[^7], S-PIN-BRUTE

### `entropy-signing-randomness-lifecycle` — P1.4 — opt_rand / secret-keyed R grinding / TRNG-KDF failure lifecycle vs the ideal reduction distributions
- **Verify:** Model and connect the ideal distributions used in reductions to the exact production derivation of opt_rand, secret-keyed R grinding, and every fallback/retry/domain-separation policy under TRNG/KDF failure/bias/reuse/conditioning. RESIDUAL: the conditioned fresh-R, no-FORS-counter ideal draw is NOT yet a proved refinement of the shipped BOUNDED production grinder (the load-bearing gap for the EasyCrypt FORS work).
- **Tooling:** EasyCrypt (present, ties to FORS) + a production-grinder transition model + tests
- **First step:** Specify the shipped R-grinder as a transition system and state the refinement obligation to the conditioned ideal draw consumed by the FORS reduction.
- **Refs:** ROADMAP §P1.4; ROADMAP §EasyCrypt stage 2 (representability stop/go); FV_SURFACE_MAP.md row 9

### `entrypoint-v06-nonce-replay-boundary` — P1.7 — EntryPoint v0.6 nonce/replay boundary (same-nonce Type-2 reuse), currently undischarged cited-TCB (defeater D2)
- **Verify:** State or prove the exact EntryPoint v0.6 nonce/replay boundary that blocks same-nonce Type-2 signature reuse. RESIDUAL: the distinct-nonce case IS covered in-model (sphincsDigest binds nonce), but same-nonce protection rests WHOLLY on cited-TCB EntryPoint v0.6 NonceManager — the entrypoint_no_replay axiom was REMOVED 2026-06-14 (handleOp never reads op.nonce), so deployed discharge is not done.
- **Tooling:** Kontrol/Halmos (present) against EntryPoint, or an explicit named-TCB leaf + receipt
- **First step:** Either Kontrol-model the EntryPoint nonce boundary or restate it as an explicit named-TCB leaf bound to a deployed-EntryPoint receipt.
- **Refs:** ROADMAP §P1.7; OPEN_PROOF_OBLIGATIONS.md §Group B (A2); THREAT_CLAIM_MAP.md S-USEROP-REPLAY[^10]

### `firmware-signer-serialization-refinement` — P1.7 / Group V — production Rust/firmware signer + serialization refines the Lean reference signer (independent-signer bridge)
- **Verify:** Prove production Rust/firmware signing and serialization refines Signer.sign / the Lean model rather than relying only on KAT/corpus agreement. RESIDUAL: Spec.Signer.sign is noncomputable/verifier-derived and cross-checked ONLY by the Rust reference signer's 10-vector KAT + bulk tests, NOT kernel-anchored to the firmware signer (bridge-(b) open); none of this is in theft_free's closure (which uses only accept⇒verifier-true + A5).
- **Tooling:** Aeneas/Lean (Charon/Aeneas NOT on PATH — needs pinned reinstall) + differential/KAT
- **First step:** State the refinement Signer.sign ↔ firmware signer, drive it via the extracted Rust + KAT, then attempt kernel anchoring of the noncomputable signer.
- **Refs:** OPEN_PROOF_OBLIGATIONS.md §Group V + §Status V row; FV_SURFACE_MAP.md row 3 (independent signer bridge)

### `lifecycle-composition-invariants` **[OWNER-GATED]** — P1.1 — compose only the STABLE cross-model invariants across the three linked machines
- **Verify:** Compose the durable-accounting, firmware-rollback, and provisioning/wipe machines through frozen interfaces and prove only the stable cross-model invariants (the six candidate invariants, incl. interrupts/exceptions/resource-exhaustion cutting a security transition). RESIDUAL: full composition inherits the owner-gate of its least-stable leg (firmware-schema + provisioning); only the counter-only invariants (durable-usage-accounting-model) are buildable now.
- **Tooling:** cross-model invariant composition (TLC/Tamarin/Lean)
- **First step:** Freeze the interface between the durable-counter kernel and the (skeleton) firmware/provisioning machines and state the shared invariants; prove the counter-only subset now.
- **Refs:** ROADMAP §P1.1 'Recommended split' + candidate invariants 1-6

### `seed-split-conditioned-transfer` — Dual-chip seed-split secrecy: ideal-model -> deployed conditioned distribution
- **Verify:** Compose the CryptoVerif full-space uniform-pad OTP secrecy (exact 0 advantage) with the conditioned-distribution transfer for the deployed rule that REJECTS the all-zero pad (distance <=2^-256), and scope the claim to a single leaked share under an independent-RNG premise plus the encrypted co-resident-secret residual. Residual: SplitSecrecy.lean/G9 already document the distinction; other prose/gate labels overstate the ideal model as deployed equivalence (SIMPLIFY).
- **Tooling:** Lean (extend Crypto/SplitSecrecy.lean) + CryptoVerif (label ideal core)
- **First step:** Add a Lean lemma bounding the statistical distance between the all-zero-rejecting draw and the uniform pad by 2^-256 and cite it from the CryptoVerif ideal result.
- **Refs:** fv-full-stack-2026-07-15-partner-b-first-pass.md:F10; fv-full-stack-2026-07-15-partner-b-cross.md:B-F10; fv-full-stack-2026-07-15-partner-a-cross.md:§4 CL-CV; formal-verification-assurance-expansion-2026-07-15.md:SIMPLIFY

### `shipping-binary-fault-model` — P1.8 — one/two-fault property on selected shipping Thumb (FI hardening of the signer)
- **Verify:** Use the existing exact-Thumb rainbow/FI route to prove a one/two-fault selected-binary property — e.g. the c10_sign_verified double-compute→byte-compare→verify-before-release chain still refuses to release an unverified sig under one instruction-skip — bounded to an explicit instruction-skip/data-fault model + budget. RESIDUAL/NO-GO: must NOT infer voltage/clock/EM/laser resistance (S-FI-SIG-GRAFT, S-PIN-GLITCH stay physical, out-of-FV-scope); add a NEW binary engine only after an M-profile/fault-semantics feasibility proof; post-LTO disassembly + physical campaigns remain separate evidence.
- **Tooling:** rainbow/FI (Ledger Donjon; skill + venv present)
- **First step:** rainbow-sweep instruction-skip over the fi::CfiCounter gate in crypto::c10_sign_verified on the shipping Thumb and confirm no single skip releases an unverified signature.
- **Refs:** ROADMAP §P1.8 (fault) + §P2 rainbow/FI pilot; CLAUDE.md §FI-hardened signing; THREAT_CLAIM_MAP.md S-FI-SIG-GRAFT (OUT-OF-SCOPE)

### `trustzone-linker-config-proof` — TrustZone SAU/GTZC + linker-map placement (generated-fact proof)
- **Verify:** Prove generated interval/configuration evidence bound to the exact linker map + register image: SAU/IDAU/GTZC regions and permissions; linker-map placement of secrets, NSC veneers, vector tables, stacks, shared buffers; cross-world pointer range/overflow rules and gateway contracts; interrupt/exception ownership; exact production register images per feature combination. Residual: extends the existing Kani-proven NS-pointer window-check + SAU/NS-window compile-time subset assert; peripheral behavior, unmodeled CMSE instruction semantics, and silicon errata stay assumptions.
- **Tooling:** Generated-fact checker + Kani/Lean (NS-pointer proofs already host-linkable)
- **First step:** Generate the SAU/GTZC region table from sau.rs at build time and assert it is a subset of the allowed secret/NS placement intervals derived from the linker map.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:Ranked #6; formal-verification-assurance-expansion-2026-07-15.md:P1.9

### `wallet-validateuserop-symbolic-transcription` — PQSmartWallet.validateUserOp bytecode properties (retire concrete-wrapper transcription)
- **Verify:** Represent A3.2/A3.3/A3.4 at property granularity and replace the concrete-wrapper/fixed-owner-index Kontrol harness with symbolic wrapper-decode, selector/role split, full-frame semantics, batch bounds, replay and cap checks - so the 'transcription-free' headline actually holds instead of being scoped away in KONTROL_SCOPING. Residual: symbolic dynamic calldata is currently unsupported, forcing concrete wrappers; the gap is claim-precision, not a demonstrated bypass.
- **Tooling:** Kontrol/Halmos (symbolic bytecode)
- **First step:** Enumerate the concrete-vs-symbolic fields in KontrolValidateUserOp.t.sol and pick one (wrapper offset/length decode) to lift from concrete to symbolic.
- **Refs:** fv-full-stack-2026-07-15-partner-b-first-pass.md:F11; fv-full-stack-2026-07-15-partner-b-cross.md:B-F11; fv-full-stack-2026-07-15-partner-a-cross.md:§4 CL-KONTROL


## value=medium · tractability=low

### `crux-saw-diversity-pilot` — P2 pilot — Crux-MIR + Cryptol/SAW implementation-diversity check vs an independent spec
- **Verify:** On ONE NS-pointer/parser or crypto primitive, check the implementation against an INDEPENDENTLY written spec so diversity can find a mismatch existing Kani/Aeneas miss. RESIDUAL/CAVEAT: value only if it finds something the current bounded assertions cannot; stop if it merely duplicates them.
- **Tooling:** Crux-MIR + Cryptol/SAW — ALL absent on this box (crux/crux-mir/saw/cryptol not installed)
- **First step:** Install Crux-MIR; target shared/src/ns_ptr_validate.rs against a hand-written spec and diff against the existing 8 Kani harnesses.
- **Refs:** ROADMAP §P2 (Crux-MIR+Cryptol/SAW row)

### `device-invariant-model-to-rust-span` — FV_VALUE_AND_GAPS #1 — spanning theorem from invariants #1-#4 abstractions down to secure-crate Rust
- **Verify:** A spanning theorem from the proven abstractions (#1 seed-split IT one-time-pad SplitSecrecy.lean + CryptoVerif; #2/#3/#4 PIN-lockstep/tunnel/isolation via the 5 ProVerif + 3 Tamarin models) down to the secure-crate Rust that implements them. RESIDUAL: there is NO such span today — it is an honest cited-TCB interface (like A2/A4), and it is NOT an Aeneas job (these are secrecy/reachability, not functional correctness); dual_se.rs, offchain_state.rs flash RMW, and the SE drivers stay design-proven-only. The paired pragmatic mitigation (Kani on the extractable decoders/counters) is DONE; the span stays open.
- **Tooling:** no single clean tool — documented multi-tool composition gap (Lean secrecy cores + Kani on the extractable halves)
- **First step:** Scope which sub-properties are mechanizable now (offchain_state.rs counter arithmetic overlaps durable-usage-accounting; page-123 cap/gap logic stays deferred in unextractable unsafe flash RMW) and file the remainder as an explicit cited-TCB residual.
- **Refs:** FV_VALUE_AND_GAPS.md §Current open gaps item 1 + UPDATE 2026-07-01; THREAT_CLAIM_MAP.md S-SEED-SPLIT, S-PIN-COMPARE-SW, S-SE-TUNNEL-SNOOP, S-NS-SECRET-LEAK

### `easycrypt-c10-eufcma-continuation` **[OWNER-GATED]** — Surface #9 / EasyCrypt — concrete C10 EUF-CMA reduction (staged research track, stages 2-7)
- **Verify:** Instantiate the actual SPHINCS+C10 scheme and compose adaptive WOTS+C10, FORS+C10, XMSS-MT, and FX over a common adversary without free probability placeholders. RESIDUAL (all OPEN): the full gate compiles 10/21 and SKIPS 11 MM45-dependent WOTS/XMSS-MT/SPHINCS files while exiting 0; imported WOTS params EXCLUDE C10 (w=8, log2_w=3, l=43, no standard checksum); the capstone's batch WOTS+C advantage does not upper-bound the ADAPTIVE interactive game; the interactive WOTS file has an admitted first hop; FORS+C index/router lacks concrete range/order/pool invariants and the multi-scheme leaves keygen/sign/verify abstract; ITSRC10 and quantitative/ROM/finite-grind bridges stay conditional. Payoff is stronger crypto-ASSUMPTION assurance, NOT a stronger theft_free conjunct.
- **Tooling:** EasyCrypt (present; heavy — require-does-not-reverify soundness trap means only compile-EVERY-file + admit-sweep is a sound gate)
- **First step:** Stage-1 honesty gate (fail-on-skip/admit/stale-.eco, rebuild upstream source closure, pin axiom identities/types) — this stage overlaps P0.3 and is NOT owner-gated; stages 2-7 require an owner stage decision + independent expert review + stop/preserve gate.
- **Refs:** ROADMAP §EasyCrypt continuation stages 1-7 + §no-go 'EasyCrypt file compilation ≠ full proof'; FV_SURFACE_MAP.md row 9

### `entrypoint-a2-bytecode-discharge` — Deployed EntryPoint v0.6 boundary (A2 assumption)
- **Verify:** Discharge A2 (entrypoint_honest), currently a self-disclosed tautology over handleOps: prove the deployed EntryPoint v0.6 bytecode refines the honest handleOps model, and state/prove the exact EntryPoint nonce/replay boundary. Residual: the genuine assumption is the un-discharged deployed-EntryPoint bytecode; Partner A estimates 8-12 months; must avoid an unbounded 'verify the whole EVM' project.
- **Tooling:** Kontrol/KEVM/Halmos (bytecode symbolic execution)
- **First step:** Scope a bounded EntryPoint v0.6 nonce/replay property that a Kontrol harness can state without modeling the full EVM, and pin the target EntryPoint codehash.
- **Refs:** fv-full-stack-2026-07-15-partner-a-first-pass.md:Appendix B #5 + Invariant-trace V2; fv-full-stack-2026-07-15-coordinator.md:Ranked #6; fv-full-stack-2026-07-15-partner-b-first-pass.md:Ranked #5; formal-verification-assurance-expansion-2026-07-15.md:P1.7

### `forsc-quantitative-backbone` **[OWNER-GATED]** — FORS+C10 quantitative ITSR backbone (EasyCrypt)
- **Verify:** Mechanize the FORS+C quantitative bound - the k-fold product, binomial mixture, and (q_h+1) union bound - so the shipped-parameter margin becomes a proof rather than a Python script (forsc_grinding_margin.py), under the nonstandard unbounded-in-EC ITSRC10 assumption. Residual: current ~130.6-bit figure is a query WORK FACTOR from checked arithmetic, not a proved advantage bound (~2^-2.6 advantage at q_h=2^128); the FORS+C 143-bit vs 130.6-bit figures also need reconciling as different objects; FORS routing/range/pool/keygen model stays abstract until this closes.
- **Tooling:** EasyCrypt (research-scale)
- **First step:** Reconcile the 143-bit vs 130.6-bit FORS figures in one place, then scope the (q_h+1) union-bound lemma as the first mechanization target on top of the C10 FORS game shape (FORS_C10.ec).
- **Refs:** fv-full-stack-2026-07-15-partner-a-first-pass.md:Appendix A/B #2 + Suspicions (143 vs 130.6); fv-full-stack-2026-07-15-coordinator.md:EasyCrypt decision stage 4 + FORS 130.6 note; formal-verification-assurance-expansion-2026-07-15.md:P1.4 + EasyCrypt stage 4

### `shipping-binary-constant-time` — Shipping-profile binary constant-time (selected Thumb symbols)
- **Verify:** Run checkct/BINSEC on selected load-bearing Thumb symbols/objects emitted by the shipping compiler+profile (opt=s, LTO, codegen-units=1, features, linker script) with pinned entry points and secret/public classifications. Residual: MUST first demonstrate the analyzer semantics cover the emitted Cortex-M33 M-profile instruction subset; this is NOT a whole post-LTO ELF theorem while symbol extraction/relocation/unsupported M-profile instructions remain outside the checked artifact; binary CT is NOT physical SCA resistance.
- **Tooling:** binsec / cargo-checkct (installed)
- **First step:** Pick one shipping-built Thumb symbol (e.g. subtle constant-time compare in c10_sign_verified) and confirm BINSEC/checkct disassembles its full instruction set before attempting a CT assertion.
- **Refs:** fv-full-stack-2026-07-15-coordinator.md:Ranked #6; formal-verification-assurance-expansion-2026-07-15.md:P1.8

### `target-only-unsafe-mmio-concurrency` — Surface-map row #5 — target-only unsafe (CMSE veneers, raw MMIO, interrupt/concurrency) excluded from host Miri/Kani
- **Verify:** Establish UB/aliasing/concurrency assurance for the highest-risk unsafe that is thumbv8m-cfg'd OUT of the host build. RESIDUAL: host reachability EXCLUDES CMSE veneers, raw MMIO, interrupt/concurrency, and the on-target NS-pointer ABI; only the NS-pointer window validator was cleanly extractable and Kani/Miri-checked. Host Miri is dynamic-UB evidence, NOT a whole-target guarantee, and there is no target-Miri on this box.
- **Tooling:** weak on this box — Miri host-only cannot reach target code; funnel raw MMIO through hw::mmio::{Reg32,RoReg32} to shrink the surface; per-block extract-to-host vs cited-TCB-with-target-test
- **First step:** Enumerate the target-only unsafe blocks and, per block, decide extractable-to-host (like ns_ptr_validate) vs cited-TCB-with-on-target-test.
- **Refs:** FV_SURFACE_MAP.md row 5; ROADMAP §nine-row surface map #5; FV_VALUE_AND_GAPS.md §UPDATE 2026-07-01 residual (b)

### `verus-power-flash-journal-pilot` — P2 pilot — Verus + PoWER on one pure flash-journal/page-state kernel
- **Verify:** Prove crash invariants on ONE stable, pure flash-journal/page-state kernel with explicit STM32 flash assumptions and show it links to usable Rust at acceptable annotation cost. RESIDUAL/CAVEAT: PoWER's persistent-memory model must be ADAPTED to STM32 flash program/erase/ECC/brownout, not copied unchanged; stop if it duplicates the implementation or the solver/toolchain maintenance exceeds the assurance gain; do NOT launch multiple Rust-framework migrations at once.
- **Tooling:** Verus + PoWER methodology — Verus is NOT installed on this box
- **First step:** Install Verus; port the durable-counter transition kernel, prove one crash invariant, and compare annotation cost against the Kani route (same shared target).
- **Refs:** ROADMAP §P2 (Verus+PoWER row) + §P1.1 note on PoWER/Apalache; ROADMAP §Primary sources (PoWER OSDI 2025)


## value=low · tractability=medium

### `nanoda-lean-comparator-pilot` — P2 pilot — independent Lean checker (Nanoda) replay of the pinned export
- **Verify:** An independent checker accepts the pinned Lean export format, adding kernel-replay diversity beyond lean4checker. RESIDUAL/NO-GO: this does NOT validate theorem INTENT (a second checker/mutation/KAT/LLM is explicitly not evidence the theorem states the intended real-world property); stop if it is not compatible with the pinned Lean format.
- **Tooling:** Nanoda / Lean comparator — not installed (Lean/lake present)
- **First step:** Install nanoda, export the theft_free closure, and confirm it accepts the pinned export format.
- **Refs:** ROADMAP §P2 (Nanoda/Lean comparator row) + §no-go 'second Lean checker ≠ intent'; FV_SURFACE_MAP.md row 1 (lean4checker replay of 58 modules)


## value=low · tractability=low

### `refinedrust-raw-pointer-pilot` **[OWNER-GATED]** — P2 pilot — RefinedRust on a small pure raw-pointer helper (DEFERRED)
- **Verify:** Only for a small pure raw-pointer helper (NOT CMSE/MMIO veneers) whose ownership/aliasing/lifetime property the current host checks cannot express. RESIDUAL/CAVEAT: explicitly DEFERRED — do not start while the CMSE ABI, volatile/MMIO semantics, or annotation cost dominate.
- **Tooling:** RefinedRust — not installed and roadmap-deferred
- **First step:** Hold as a watch item; do not start until the CMSE-ABI/MMIO/annotation-cost deferral conditions clear.
- **Refs:** ROADMAP §P2 (RefinedRust deferred row)

### `vest-parser-feasibility-pilot` — P2 pilot — Vest verified-parser feasibility for one fixed-buffer wire format
- **Verify:** Feasibility ONLY: does Vest's generated parser emit no_std output whose alloc/link behavior fits the shipping zero-allocation firmware and improve canonical framing. RESIDUAL/CAVEAT: stop if the zero-allocation/runtime assumptions do not fit the firmware environment.
- **Tooling:** Vest — not installed (Rust tool, buildable but no_std/alloc fit unproven)
- **First step:** Generate a Vest parser for the 17-byte off-chain header and inspect the no_std/alloc/link output against the firmware constraints.
- **Refs:** ROADMAP §P2 (Vest row); ROADMAP §Primary sources (Vest USENIX 2025)

