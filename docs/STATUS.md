# PQSigner — STATUS (start here)

> **The front door.** Read this first. It's a **router, not an encyclopedia**: §0 maps *where the truth
> lives* (one owner per concern — everyone else links); §A–§D are the **security/verification frontier**,
> the one slice this file owns directly. Detail lives in the linked docs, not here.
>
> **Freshness.** §A–§D are a snapshot **reconciled against the repo on 2026-06-17** (`security-frontier-reconcile`
> workflow). They are only trustworthy if re-reconciled — a stale STATUS is worse than none. Re-run that
> workflow over a slice before relying on its rows, and trust the **evidence pointer, not the prose**.
>
> **Scoped rollback/process/SE update (2026-07-14).** This correction
> reconciled §0's planning/rollback owners, the full AT-A-GLANCE summary, §A
> `FW-RB`, `S-1..S-7`, `S-4`, `HIGH-1`, `MED-2`, and Claim 3, plus their
> affected §B/§D mirrors. Rollback evidence is Draft 1.1 commit `93da7567`,
> SHA-256 `743bc156…3d7ad`, its bounded deletion receipt, and the planning-
> workflow review; `MED-2` was checked against commit `f8effd45`. No other
> §A–§D row was refreshed, and this does not supersede the 2026-06-17 full-
> frontier snapshot.

> **FV correction — 2026-07-15.** The current full-stack adversarial review is
> [`fv-full-stack-2026-07-15-coordinator.md`](security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md),
> with the nine-surface inventory in
> [`FV_SURFACE_MAP.md`](../contracts/verification/docs/FV_SURFACE_MAP.md) and the
> sourced expansion roadmap in
> [`formal-verification-assurance-expansion-2026-07-15.md`](verification/formal-verification-assurance-expansion-2026-07-15.md).
> Individual Lean results remain scoped and kernel-valid, but current
> end-to-end assurance promotion is blocked by extraction freshness, the actual
> signed-digest bridge, extracted closure policy, protocol-driver semantics,
> and EasyCrypt gate/parameter correspondence. EasyCrypt reproduced 10/21
> compiled with 11 skips and success; its imported WOTS theorem excludes C10's
> `log2_w=3`. The source census is 148 Kani harnesses/25 files; mutation-enrolled
> files contain 140/19, with eight/six outside and three of 31 groups full-only.
> No fresh full Kani campaign was run. V1 is legacy evidence; V4 versus V6
> remains an owner conflict, not a selected implementation target.

## §0 — Where the truth lives (doc map)

One concern → one **owner** doc. If a fact lives in two docs it *will* drift (it did: S-1/S-2/S-3 status was
in four places). The rule: **owners hold the fact; everything else links.**

| Concern | Owner (source of truth) | Notes |
|---------|------------------------|-------|
| Non-negotiable invariants · code conventions · key-file map · KDF tags | **`CLAUDE.md`** | the LLM operating contract; the "do / never" rules |
| Engineering planning · scope/requirements change control · convergence · dual-model adversarial review | **`docs/planning-and-review-workflow.md`** | `AGENTS.md` is the mandatory agent router; this owner doc holds the process |
| Security-review playbook routing · additive lenses · finding-record lifecycle | **`docs/security/adversarial-review/README.md`** | surface playbooks discover candidates; the planning workflow exclusively owns exact-pair cross dispositions and convergence |
| External architecture · per-device shipping checklist | **`README.md`** | auditor/integrator altitude |
| Reversible dev backlog · the dated Completion Log | **`docs/work-todo.md`** | "what got done when" |
| **Irreversible** factory/silicon burn ceremony (OPTIGA LcsO, OTP/WRP/RDP, SCP03 PUT-KEY) | **`docs/production-todo.md`** | ⚠ NOT merged with work-todo — different lifecycle/reader |
| Security + verification frontier (done/left/why) | **this file (§A–§D)** | reconciled pointer index |
| Tools & systems an agent can use (+ gaps) | **`docs/tooling-and-systems.md`** | the capability manifest |
| Adversary tiers · trust boundaries · falsifiable Claims | **`docs/security/threat-model.md`** | |
| Ship-blocker provenance (`C-n → S-n`) | **`docs/security/security-review-2026-05.md`** | the audit that named S-1..S-7 |
| Hardening requirements ("what must hold") | **`docs/security/HARDENING.md`** | |
| EVT bench-attack pass/fail bars | **`docs/security/red-teaming.md`** | the on-copper test matrix |
| Empirical on-silicon SE050 status | **`docs/secure-elements/se050-silicon-findings.md`** | |
| Provisioning ceremony (untrusted-CM) | **`docs/provisioning/provisioning-reference.md`** | |
| A/B rollback architecture candidate and physical/resource gates | **`docs/security/a-b-firmware-rollback-architecture.md`** | Draft 1.1 is pending exact-digest dual review + owner approval; its frozen technical text is preserved as a research candidate only, while any embedded reviewer-runtime/choreography text is superseded by `docs/planning-and-review-workflow.md`. Bounded deletion receipt: `docs/security/fw-rollback-draft11-deletion-gate-2026-07.md`. Draft 0.9 is historical at tag `rollback-architecture-v0.9`; receipts: `docs/security/a-b-firmware-rollback-review-receipt-2026-07.md` and `docs/security/fw-rollback-draft09-host-model-receipt-2026-07.md` |
| Companion integration · clear-signing | `docs/companion/companion-app-integration.md` + the `companion-*` deltas | firmware side: `docs/companion/erc7730-integration.md` |
| FV strategy / what full proof requires | **`docs/verification/how_to_math_proof_secureness.md`** | live proof state: `contracts/verification/` (`THE_CLAIM.md`) |
| FV target ranking · security-tooling adoption | `docs/verification/verification-targets-2026-06.md` · `docs/verification/security-tooling-sota-2026-06.md` (= §34) | |
| C10 ↔ FIPS-205 deviations | **`docs/verification/c10-fips205-delta-audit.md`** | keeps public claims accurate |
| SCA/FI tooling & harnesses | `docs/tooling-and-systems.md` + `tools/sca/DONJON-RUST-TOOLING.md` | |
| Quarantined historical docs (stale / superseded / completed handoffs) | **`docs/archive/`** (+ its `README.md` index) | NOT current guidance; each README row names the live successor. Don't merge archived content forward (several state a superseded signing primitive) |

**Ownership rule of thumb for any edit:** before writing a status/fact into a doc, ask *"is this doc the
owner of this concern?"* If not, link to the owner instead of restating — that's what keeps this tree from
re-drifting.

> **Two rules that make it trustworthy** (this repo's checkboxes have lied in both directions repeatedly):
> 1. **Every `DONE` row carries a spot-checkable evidence pointer** — a commit, a `file:line`, a `make`
>    target, or a test name you can run. Trust nothing; verify the pointer.
> 2. **Every open row carries a `blocked-on` tag** so "what can I actually do from the keyboard right now"
>    is answerable at a glance:
>    `code` = keyboard-doable now · `compute` = doable but heavy CPU/time · `bench` = needs the physical
>    STM32U585 / glitch rig · `factory` = needs HSM key-custody or a release pipeline · `research` =
>    long-horizon or a separate project.
>
> **Verification depth.** Where a reconciler *ran* the tool, the row says so (ProVerif/Tamarin, cargo-fuzz
> corpus, git archaeology). Where it confirmed *existence* of harness + commit but did not re-execute a heavy
> toolchain (Kani/CBMC, cargo-checkct/binsec, Kontrol/KEVM), the row notes "asserted by commit, not re-run."

---

## AT A GLANCE

- **The real ship gate is NOT a tooling track** — it includes **firmware
  rollback Foundation A** (legacy OTP/A-B path is production-fenced; Draft 1.1
  exact-digest approval, implementation, separate physical FLASH and
  static-RAM/worst-case-stack fit, and physical
  journal/ECC/OTP receipts remain open), **OPTIGA silicon (S-1/S-3 LcsO ratchet) + S-2 closure of the real type-`0x11` pool and device-certificate retype boundary under a selected factory policy**, the **first-boot final SE pairing/rotation closure
  (HIGH-1; a journaled candidate exists, but its authenticated factory handoff,
  old/new/KVN recovery proof, E140 order, and silicon receipts remain open)**,
  and the **S-5 bus capture**.
- **Keyboard-doable security work right now (`blocked-on: code`):** HIGH-1's
  candidate handoff/recovery review and crash-safe durable-state validation,
  `make checkct` CI enrollment, S-4's remaining
  documentation/code items, the optional Lean credits corollary, mutation
  testing, and the Draft-1.1 review/model work named by `FW-RB`. The detailed
  §B table—not this summary—is authoritative; previously listed hevm, KAT,
  ClusterFuzzLite, security-review Action, prod-config, and most ToB-pilot work
  are already closed or deliberately deprioritized there.
- **The big compute item:** the full ~40h FI fault-sweep campaign (harnesses built, only smoke-run).
- **Stale-doc flag found during reconcile:** `docs/secure-elements/se050-silicon-findings.md` still says lockout SW `0x6982`; the
  live post-revert code maps `0x6986` (`ef3d00da`). Worth a 2-minute sync.

---

## A. SHIP GATE — must close before any unit leaves the bench

`docs/production-todo.md` owns the OPTIGA bench/factory spec; `docs/security/security-review-2026-05.md` owns the
`C-n → S-n` finding provenance; `docs/security/red-teaming.md` owns the bench pass/fail bars.

| ID | Item | Status | Blocked-on | Evidence (spot-check) | What remains |
|----|------|--------|-----------|------------------------|--------------|
| **FW-RB** | A/B rollback + anti-rollback root | Draft 1.1 research candidate; implementation **NO-GO** | **code + bench + factory** | Draft 1.1 commit `93da7567`, SHA `743bc156…3d7ad`; bounded host deletion receipt; exact-digest Opus/GPT reviews and owner approval remain pending; build.rs + Rust compile gates cover production secure/FSBL, factory/rehearsal, and explicit bench opt-in; `prod-check-ship` is an expected-failure CI gate | Obtain both exact Draft-1.1 architecture reviews + owner approval; implement and adversarially review the selected contract. The physical FSBL FLASH LOAD span must meet the candidate's proposed 38,912-B target (40,960-B hard ceiling), and separately `OPEN-RAM-1` must close the static-RAM + worst-case-stack envelope. Close `OPEN-PIN-HW-1`, `OPEN-JRN-HW-1`, `OPEN-JRN-DUR-1`, `OPEN-FLASH-HW-1`, `OPEN-ECC-1`, `OPEN-RAM-1`, `OPEN-OTP-1..3`, `OPEN-REL-1`, and `OPEN-C10-1`; then obtain separately authorized Section-13 silicon/factory receipts. Legacy 1,024-bit tally and current try-once claims are rejected. |
| **S-1** | F1D0 `Change=ALW` → desolder PIN brute-force | partial | **bench** | `secure/src/nsc/mod.rs` feature fence `optiga-lock-operational`; `secure/src/optiga/apdu.rs::build_metadata_auth_ref_luc`; `secure/src/optiga/mod.rs::OptigaTrustM::verify_and_lock` (commit `832a369d`) | Irreversible **LcsO=Op ratchet** + sacrificial-part validation on fresh silicon. During the rollback quarantine, a non-production STM32 image can compile only with explicit `legacy-fw-rollback-unsafe`, while production and factory shapes are blocked; this is bench capability, not a shippable escape. |
| **S-2** | Empty/unratcheted type-`0x11` trust-anchor slots can authorize attacker-signed Protected Updates | partial | **factory** | `secure/src/optiga/reset.rs::{TRUST_ANCHOR_OID,TRUST_ANCHOR_CERT}` documents the retired, mis-targeted `0xE0E3` sample-key helper; `secure/src/nsc/mod.rs` fences `OPTIGA_RESET_OIDS_RETIRED` and `OPTIGA_S2_PRODUCTION_BLOCKED`; fail-closed candidate `secure/src/optiga/mod.rs::OptigaTrustM::lockdown_ta_pool` names `{0xE0E8,0xE0E9,0xE0EF}` | Pin the SKU/revision inventory; select a reviewed HSM-anchor or irreversible-neutralization policy for the real type-`0x11` pool; close every unused surface; and ratchet `0xE0E1..=0xE0E3` as device-cert objects without retyping them. The observed `0xE0E3` is a full type-`0x12` device cert, so the old helper is a no-op; that correction does not close the real pool. |
| **S-3** | Default build has no silicon-enforced PIN lockout | partial; weak-profile production fence closed | **bench + factory** | `secure/src/nsc/mod.rs` fence string ``Production OPTIGA builds require `optiga-hw-counter```; `secure/src/optiga/apdu.rs::{build_metadata_auth_ref_luc,OID_PIN_CTR}`; `make optiga-hw-counter-e2e` PASSED 2026-04-22 | Freeze and authorize the final F1D0/E120 metadata and lifecycle profile, then validate the LcsO ratchet, reset/power-cut behavior, and limit boundary on named sacrificial parts. Under `optiga-hw-counter`, F1E1 remains a provisioning/reset sentinel and is not lockout authority. |
| **S-5** | SCP03 response unprotected (`half_E` plaintext on I²C) | **done** (code+func-silicon) | bench | `secure/src/se050/scp03.rs::{establish,unwrap_response}`; `secure/src/se050/apdu.rs::send_apdu`; tests `secure/src/se050_under_test/pure_tests.rs::{positive_scp03_external_authenticate_p1_is_0x33,positive_scp03_unwrap_response_exists}`; B-U585I functional round-trip recorded in the SE050 stress evidence | Only the dedicated **logic-analyzer bus capture** confirming no plaintext on the wire (`docs/security/red-teaming.md` §5.1). |
| **S-6** | Admin-delete on USERID → seed theft | **done** | none | `secure/src/se050/mod.rs::Se050::store_objects` calls `write_userid(..., None)`; tests `secure/src/se050_under_test/pure_tests.rs::{negative_admin_userid_provisioning_uses_no_admin_ref,negative_user_userid_has_no_admin_ref_post_s6}` and stress `userid_no_admin_delete` | — |
| **S-7a/b/c** | max_attempts=0 footgun; `0x6986`→Ok mis-map; extended-Lc 2-byte Le | **done** | none | `secure/src/se050/apdu.rs::{write_userid,delete_object,send_apdu}`; stress `pin_unlimited_no_lockout` | — |
| **S-7d** | Empirical UserID-lockout SW mapping | **done** (on silicon) | none | commit `ef3d00da` (Runs 3-4, B-U585I); `secure/src/se050/apdu.rs::create_session` maps `0x6986` to `AuthMethodBlocked`; stress `userid_silicon_lockout` and `pin_counter_persists_across_reinit` | ⚠ **was marked open** — actually run. `0x6982` was a reverted red herring. **`docs/secure-elements/se050-silicon-findings.md` is stale (says 0x6982) — sync it.** |
| **S-4** | OPTIGA lower-sev cleanups (5 sub-items) | partial | bench + code | `secure/src/optiga/apdu.rs::{build_metadata_protected,build_metadata_counter,OID_COUNTER}`; current authority names E120 as lockout and F1E1 as the provisioning/reset sentinel | The remaining sentinel lifecycle/replacement choice needs design + bench evidence; irreversible items need the board. |
| **HIGH-1** | SCP03 default-keyed with PUBLISHED AN12436 factory keys (dev) → bus attacker extracts `half_E` | partial; journaled first-boot candidate exists, production closure OPEN | **code + factory + bench** | `secure/src/nsc/mod.rs` fence string ``Candidate SE050 profile is incomplete without non-public SCP03 transport keys``; `secure/src/first_boot/`; `secure/src/se050/mod.rs::{rotate_scp03_transport_to_final,rekey_admin_transport_to_final}`; `secure/src/scp03_logic.rs::keys_are_factory_default` | The published-key fallback is compile-fenced and the candidate implements BHK-rooted SE050 rotation plus persisted-salt OPTIGA rotation. It is not a reviewed ceremony: close the authenticated per-unit transport handoff/receipt, authenticate-before-rotate rule, old/new/KVN recovery proof, E140 order, and silicon validation. No production authority until those gates close. |
| **MED-2** | `e2e-test`/`dev-testkey` escape hatches ship fixed secrets; no prod-check CI gate | **done 2026-06-18** | none | `secure/src/nsc/mod.rs` `mode-production` incompatibility fence strings; `make prod-check`; per-push `prod-config-gate` CI job (`f8effd45`) | — |
| — | **Claim 3 (PIN gate) is PROVISIONAL** | — | bench | `docs/security/threat-model.md` Claim 3 | After S-1 closes, re-establish the on-board three-way per-attempt leg with `pin-gate-hw-counter-e2e` on a ratcheted sacrificial part. The directional boot branches remain open pending a separate cold-reboot silicon receipt. |

---

## B. ACTIVE FRONTIER — open / partial assurance work, grouped by what unblocks it

### `blocked-on: code` — doable from the keyboard now

| Area | Item | Status | Evidence / where | Source |
|------|------|--------|------------------|--------|
| CI | Prod-config gate rejecting `e2e-test`/`dev-testkey` fixed secrets (MED-2) | **DONE 2026-06-18, CI-green** | `mode-production`+`e2e-test`/`+dev-testkey` `compile_error!` fences (`nsc/mod.rs`) + `make prod-check` (cargo-tree feature resolution; catches transitive `dev-testkey→otp-hardcoded-master-key`) wired into `release` + the per-push `prod-config-gate` CI job (green on master `f8effd45`) | audits/tz-tamper |
| cargo-checkct | a CI gate (driver coverage now complete) | partial | **`driver_saes` DONE 2026-06-18** (proves SECURE on binsec — the Tier-1 SAES-CMAC(DHUK) framing incl. `double_l`'s secret-MSB reduction is branchless on thumbv8m); 4 SECURE drivers (kdf/fors/th/saes); `make checkct` EXISTS (`Makefile:3620`). Remaining = a CI job (binsec needs a local opam switch, so kept host-local for now) | sota §1 |
| on-chain Yul | **hevm equivalence** of `SPHINCsC10Asm` vs a reference Solidity verifier | **deprioritized — redundant 2026-06-18** | Marginal value ≈ 0 over the existing stack: A3.1 proves `execC10Asm = Spec.verify` **∀-input in-kernel** (Yul-model = the SPEC — a STRONGER reference than "= another Solidity impl"; §A3.1 row), Kontrol/KEVM discharges the **deployed-bytecode** level 30/30 (same level hevm targets, same KEVM-class engine), the transcription lint guards source↔model, the clean-room signer (row below) adds cross-impl differential. hevm would only prove "Yul ≡ a reference verifier" (a new impl that itself needs trust) and would NOT close the residual bytecode↔model SHA-256 axiom (the shared A1 ceiling). Cost = a from-scratch ~hundreds-of-line reference verifier (days) + hevm install for ~0 net assurance. Revisit only if a 2nd independent bytecode-equivalence engine is specifically wanted. halmos side done (39 rules). | sota §2 |
| on-chain Yul | KAT oracle — independent-source leg | **DONE 2026-06-18** | A clean-room SHA-256-C10 signer landed: `contracts/verification/scripts/independent_c10_signer.py` — written from the deployed `SPHINCsC10Asm.sol` + the documented PRF preimages (`sphincs-c10/src/hash.rs`/`fors.rs`), NOT a transliteration of the Rust signer (and NOT signer.py's `c10` config, whose FORS ADRS is the pre-fix shared-forest layout, not PQSigner's `htIdx`-bound one). VALIDATED: reproduces the Rust `pk_root` + ALL 4 valid KAT vectors BYTE-FOR-BYTE + round-trips fresh messages; and `sphincs-c10/tests/independent_signer_xcheck.rs` confirms the EXISTING Rust verifier accepts FRESH independent-signer output. `make -C contracts/verification verify-independent-signer` (+ CI host-tests step). Honest scope: implementation diversity over the SHARED C10 spec (no second spec exists), not a second spec. | sota §2 |
| CI / fuzz | ClusterFuzzLite over the 12 fuzz targets | **done (build CI-validated)** | `.clusterfuzzlite/{project.yaml,Dockerfile,build.sh}` + `cflite-pr.yml` (code-change, hard gate) + `cflite-batch.yml` (scheduled). **Build proven green 2026-06-18** (batch run `27770338025`, `Build fuzzers`=success after wiring `github-token` for the private-repo clone); `cflite-pr` promoted off `continue-on-error`. First real PR will exercise the code-change run_fuzzers path | trezor-comp |
| CI | `claude-code-security-review` GitHub Action (ext-contributor-gated) | **done 2026-06-18** | `.github/workflows/security-review.yml` — SHA-pinned (`@0c6a49f1`), fork-guarded (`head.repo==repository`), `pull_request` NOT `_target`, no-ops without `ANTHROPIC_API_KEY`; advisory-only (never a merge gate) | sota §8 |
| ToB skills | Pilot tail: mutation/property/differential/variant/entry-point/supply-chain/agentic-actions/seatbelt/fp-check | **mostly covered 2026-06-18 (methodology substitute)** | the plugins aren't `/plugin install`ed, but the METHODOLOGY ran as a fan-out workflow (`tob-methodology-security-audit`, **14 findings / 0 FP** → the supply-chain fixes in `5b295e52` + `eb416ccf`). Covered: supply-chain-risk / agentic-actions / entry-point / variant / fp-check(=the Verify phase). seatbelt-sandboxer = macOS-N/A (Linux analog `tools/sca/run-isolated.sh` landed). Genuinely OPEN: **mutation-testing** (no gambit/vertigo mutant runner on the contracts) | sota §11 |
| OPTIGA | S-4 items 2 (plaintext VK-read confirm) / 3 (duress-PBS caveat in threat-model) / 5 (F1D5↔F1E1 naming) | open | doc/code | work-todo S-4 |
| Lean FV | Optional global credits-native aggregate corollary (`#executes ≤ #validates`) | open (low-pri) | not written; skeleton `Theorems.lean:696-706` | faithfulness P2 |

### `blocked-on: compute` — doable but heavy

| Area | Item | Status | Evidence | Source |
|------|------|--------|----------|--------|
| FI/SCA | **Full FI fault-sweep campaign** (14 rainbow harnesses × full width × all fault models, ~40h+) | partial — harnesses built, **only smoke-run** | `tools/sca/fault_sweep_*.py` (14); `make -C tools/sca c10-sign`; commits `8d8b9af7`(smoke)/`3891237b` are NOT full coverage | sota §0; README §C10-sign |

### `blocked-on: bench` — needs the physical board / glitch rig

| Area | Item | Status | Evidence | Source |
|------|------|--------|----------|--------|
| SCA | dudect DWT Welch t-test on real U585 (`verify()`/KDF) | open | no make target / artifact | sota §1 |
| SCA | lascar/scared CPA — **on-silicon** SHA-2 PRF DPA sufficiency (emulated half done: F-9 found+fixed) | partial | `make kdf`/`f9-*`; emulated = software-AES stand-in | work-todo §18b(b) |
| FI/SCA | Hardware bench: ChipWhisperer-Husky + ChipSHOUTER-PicoEMP | open | listed adopt-now, nothing acquired | sota §SCA-rigs |
| OPTIGA | S-1 / S-3 LcsO=Op ratchet + sacrificial-part validation | open | `production-todo.md` | sec-review |
| SE050 | S-5 logic-analyzer bus capture | open | `red-teaming §5.1` | — |

> **Resolved sub-question:** "no public STM32U5 RDP/TZ glitch result exists" has **flipped** — the
> Masaryk/Šimoník thesis demonstrates ~76% PIN-glitch bypass on STM32U5 silicon (`work-todo:1050`),
> invalidating Donjon's prior statement. The *our-board* bench campaign is still open; the literature question is answered.

### `blocked-on: factory` — needs a factory policy/ceremony, key custody, or a release pipeline

| Area | Item | Status | Source |
|------|------|--------|--------|
| OPTIGA | S-2 real type-`0x11` pool + device-certificate retype closure; select HSM-anchor or irreversible neutralization policy | open | production-todo S-2 |
| supply-chain | cargo-vet audit set + SLSA provenance / cosign→Rekor on release | open | sota §8 |
| provisioning | Factory provisioning automation (per-device SCP03 + PBS) | open | threat-model §9.2 |

### `blocked-on: research` — long-horizon / separate project

| Area | Item | Status | Evidence / note | Source |
|------|------|--------|-----------------|--------|
| Lean FV | **A3.1** deductive interpreter-refinement closure (the verifier ∀-theorem) | **model-side ∀ CLOSED 2026-06-18** (was "partial") | `execC10Asm = nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel` proven **∀-input, kernel-clean** (`execC10Asm_eq`, commit `940d43e8`) ⇒ `execC10Asm = Spec.verify` on N-masked keys; adversarially reviewed (`contracts/verification/docs/findings/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md`) + positional transcription lint (`make verify-transcription`, `064357d5`/`229e1b3d`). RESIDUAL is NOT open proof work — two documented trust boundaries: the bytecode↔model axiom `solidityVerifier_compiles_correctly` (`discharged-bytecode-partial`: Halmos input-gates + 396-vector KAT/mutant differential; full ∀-body symbolic = the **A1 uninterpreted-SHA-256 ceiling**) and the `c10Program`↔`.sol` transcription (now lint-guarded + corpus). Interpreter is in `lean/SphincsCVerify/Interpreter/` (the `contracts/verity/` scaffold from old subtasks was superseded). | verity / how_to_math_proof |
| Lean FV | Real-valued / probability-monad quantitative bound (deeper half of E) | open | log-domain floor done (`Crypto/Quantitative.lean`); `Pr[forge]≤ε` half absent | FV-frontier(b) |
| Lean FV | `deserialize_pin_state` as a proven Aeneas rank | open | source `domain/src/lib.rs:739`; not extracted (Kani already proves panic-freedom) | handoff-pinstate |
| Lean FV | Extend Aeneas into `domain` derivation (`slot_entropy`/`derive_c10_slot_seeds`) | open | needs `sha256_bytes` refactor first | FV-frontier |
| Firmware FV | LeanLoop roadmap (goal-splitting / prover ensembling / lean-lsp MCP tier) | open | separate repo | sota §3 |
| Crypto | ML-KEM-1024 inner wrap (Claim 7 / CRQC bus-capture residual) | descoped — residual ACCEPTED (owner, 2026-07-07) | Grover-2⁶⁴/Cat-1 bound accepted; per-device SCP03/PBS rotation (work-todo #11 / §9.2) now load-bearing for the static-leak residual; prototype retained feature-gated | threat-model §9.1, work-todo #9 |
| Platform | Boot-time SE attestation; MPU privilege-banking | open | HARDENING §3.4 / threat-model §9.4, §9.9 | — |

---

## C. DONE — verified, with evidence

Compact ledger of security/verification items confirmed complete against the repo. Spot-check the pointer.

| Area | Item | Evidence | Depth |
|------|------|----------|-------|
| Supply-chain | cargo-deny `advisories+bans+sources` in CI + `make invariant-gates` | `deny.toml`; `ci.yml:68-71`; `Makefile:3515` (`ca28eda7`) | re-read configs |
| Fuzzing | cargo-fuzz campaign, 12 targets, 0 artifacts, `make fuzz-all` | `fuzz/fuzz_targets/` (12); four tracked selector-gate seeds plus ignored local/generated corpora; `fuzz/README.md` | fail-closed campaign re-run 2026-07-13 |
| Supply-chain | `make sbom` (CycloneDX sidecar) | `Makefile:3528-3532`; cargo-cyclonedx installed | target exists |
| Firmware FV | Kani (≈70 harnesses — exhaustive decoder-DECISION fence over the extracted clear-sign + FW-update crates) + Miri (0-UB incl. secure-crate NS-ptr + tree-borrows) + `revm`/MultiSendCallOnly bytecode differential | `make kani`/`make miri`; `#[kani::proof]` across `pqsigner-tx`(multiSend/CoW/typed-call/SafeTx/Safe-mgmt/erc20), `pqsigner-erc7730`, `sphincs-tz-shared`(NS-ptr), `fw-manifest`(rollback+preimage), `pqsigner-domain`/`aa`/`tx-core`; work-todo §34 Completion Log (slices 1-10 + fw-manifest, 2026-06-30→07-01) | **CI-gated** (2026-06-18): Miri per-push (`ci.yml` `miri` job), Kani nightly (`nightly.yml`). Kani was not rerun on the ERC-7730 merged snapshot; 58/60 is inherited pre-transplant evidence (zero counterexamples; two 900 s no-verdict timeouts). See `docs/work-todo.md` `[erc7730-kani-tractability]`. Coverage frame + honest residuals: `FV_VALUE_AND_GAPS.md` UPDATE 2026-07-01 |
| CI / UI | ui-capture golden-screenshot regression gate | `make ui-golden` (`Makefile`); producer `ui/capture.rs`, comparator `tools/ui_fixture.py`, fixtures `tests/ui_fixtures.json` | **target added 2026-06-18** — LOCAL/manual gate, **wired but not yet run to completion** (the regen run was killed mid-QEMU at 11 min; full-e2e capture is too slow over QEMU semihosting → not CI-gated; a dedicated short-capture scenario is the CI-viable follow-up) |
| CI / repro | Reproducible-build byte-diff gate | `make verify-repro` (`Makefile:1912`); `nightly.yml` `verify-repro` job | **wired 2026-06-18** — was capability-only (Makefile comment falsely claimed per-PR); now nightly-gated |
| Protocol | ProVerif (17 RESULTs) + Tamarin (**8 lemmas**) | `make proverif`/`make tamarin`; `4beebec7`,`118665bf`,`86291fd7`,`3f82f560`; **+`fw_update_authenticity.pv`** (FW-update no-forgery + domain-separation PROVEN under a cross-protocol-reuse adversary, 2026-06-26) **+`seed_split_xor.spthy`** (dual-SE XOR seed-split secrecy info-theoretic via `builtins: xor` — single-SE compromise leaks nothing; positive control both-compromise leaks; 2026-06-26) | **both provers re-run end-to-end** |
| SCA | cargo-checkct: 4 SECURE CT proofs (kdf/fors/th/**saes**) | `checkct/driver_{kdf,fors,th,saes}`; `driver_saes` proves SECURE on binsec 2026-06-18 (Tier-1 SAES-CMAC framing) | binsec re-run for driver_saes; kdf/fors/th from `b0944ecf` |
| SCA | Muscat pilot — full-10M TVLA reproduces lascar, CPA flat | `muscat/pqsigner_tvla_cpa.rs` (`23e72bd4`) | cross-check on emulated traces (not silicon) |
| ToB skills | zeroize-audit (clean); ct_analyzer → CT-1 found+fixed; semgrep rules hand-authored | `8184d4b5`; fix `shuffle.rs:181` (`0d432f8f`); `.semgrep/pqsigner-invariants.yml` | commits + live fix |
| Lean FV (A5) | EUF-CMA restated consistently; `theft_free` re-derived; sha256→collision-resistance; 3 shapes→opaque | `Crypto/EUFCMA.lean:123`, `Assumptions.lean:101-170` (`4ba5be10`,`83776287`); `make verify-audit` = 11 axioms, 0 sorryAx | gate asserted |
| EasyCrypt (A5, WOTS+C leg) | **WOTS+C multi-instance EU-naCMA MACHINE-CHECKED and now UNCONDITIONAL** against MM45's *real* WOTS-TW theorem: `Pr[M_EUF_NACMA_WOTSC_L] ≤ Pr[S_TCR_C] + Pr[M_EUF_GCMA_WOTSTWESNPRF]` — real games, **no free reals, 0 admit, no embedding hypothesis**. Matches the paper's Thm C.2 exactly. FLAG-2 (`emb_disj_wgpidxs`) **discharged 2026-07-09** by re-basing the stack onto the concrete `FSSLXMTWES.WTWES` instance and defining `emb_tw`. | `~/repos/c10-eufcma-port` (out-of-tree) `c5fa41a`: `WOTS_C_Real.ec::emb_disj_concrete` + `WOTS_C_Bridge.ec::emb_disj_wgpidxs_holds`; `WOTS_C_EmbDischarge.ec:173 D1_MEUFNACMA_WOTSC_MM45_embthfc` (premises 3→2, conclusion byte-identical) | **done (leg)** — only residual side-conditions are `c <= p_tgts` (parameter) and the definitional encode-compat. Anti-vacuity: RHS→`0%r` fails; `nonvac_guard` + `emb_off_range` proven; `thfc`/`predC` stay abstract. A5-EUFCMA stays `cited-tcb` (composition `hfx` + FORS+C leg still open). Gate: compile EVERY `.ec` as a target |
| EasyCrypt (A5, FORS+C leg) | **A5-ITSR RESTATED 2026-07-10 → `ITSRC10`, a NAMED NONSTANDARD assumption** (standard ITSR + conditioning of the message key). It was cited to Barbosa et al. §6 Thm 2 = *plain* ITSR for *standard* SPHINCS+ — a different scheme. The published SPHINCS+C paper has **no FORS+C theorem** (§IV: *"we can use the previous ITSR analysis"*; §V: *"straightforward"*), and **MM45 never bounds ITSR either** — its top theorem carries `Pr[MCO_ITSR.ITSR(…)]` as an *unreduced term*. So the honest closure was never a reduction. **Now backed by more than the paper or MM45 offer:** the assumption is mechanized as a game (`FORS_C10.ec`, C10-faithful, 0 admit), its combinatorial core is machine-checked (`DarkSide.ec`, 0 admit: `cover_pr` proves `DS_γ` *is* the coverage probability; `forsc_le_fors` proves the paper's central claim `DS^(k-1)·(1/t) ≤ DS^k`), and a black-box reduction to the standard assumption costs **~102 bits** — so the nonstandard form is necessary. | `AXIOM_STATUS.json` A5-ITSR (+`mechanized-assumption` artifact); `Crypto/Assumptions.lean` `axiom ITSR_F` docstring; c10-eufcma-port `0eae219`; `make -C contracts/verification verify-forsc-margin` (WORK FACTOR 130.6 bits FORS+C vs 128.5 plain — hash queries needed, **not** an advantage; at q_h = 2^128 the advantage is 2^-2.6) | **restated, still `cited-tcb`** — the citation now names an assumption we defined, mechanized and concretely analysed, instead of a theorem about a different scheme. Residual: like plain ITSR it is unbounded inside EasyCrypt (no stdlib concentration inequalities); k-fold product / binomial mixture / (q_h+1) union bound not mechanized |
| EasyCrypt (A5, blast radius) | FORS+C **never weaker than plain FORS at C10's params**: `ratio = p_FORS+C/p_FORS = 1/(t_last·DS_γ) ≤ 1` since `DS_γ ≥ 1/t`; C10 has `t_last = t = 2^11` (equality boundary) → identical at γ=1 (`2^-143`), better by `~log2 γ` beyond. Forced-zero enforced by **both** verifiers. | `make -C contracts/verification verify-forsc-margin` (wired-in negative control: FAILS if `t_last < t`); `hypertree.rs:374`, `SPHINCsC10Asm.sol:86`; test `negative_forced_zero_fors_index_is_enforced_in_emitted_sig` | **gate added 2026-07-09** — a **computed margin, NOT a reduction**; bounds the blast radius of the row above. Does not discharge A5-ITSR |
| Lean FV (faithfulness) | cap-bootstrap survivor; Gap-3 domain sep; Gap-2 per-step credits; Gap-4 upgrade-unreachable; A4 content; Gap-1 lint | `Invariants.lean:580`, `OffchainBinding.lean:87`, `Theorems.lean:726`, `UpgradeSafety.lean:96` (2026-06-14) | files exist |
| Lean FV (faithfulness) | Scope-honesty headline write-up | `THE_CLAIM.md:149-153` | ⚠ **was marked open** — actually done (checkbox lag) |
| Lean FV (Pass-2) | lean4checker gate; FV-invariant lints; 2 KAT near-miss vectors | `make verify-lean4checker`/`verify-fv-lints`; `KatVectors.lean:59-63` | targets exist |
| Lean FV (Pass-2) | Kontrol/KEVM discharge A3.2/A3.3/A3.4 (30/30) on deployed bytecode | `7042de2d`,`b8cf51a8`,`2f675244`,`451a3ce2`,`df1c08e9`; backend installed | commit chain; re-run = compute |
| Lean FV (Pass-2) | Quantitative log-domain floor (96-bit @ 2^16 cap, cap load-bearing) | `Crypto/Quantitative.lean` (axiom-free) | partial item — real-valued half open (§B) |
| Audits | 2026-06-09 firmware-signing audit (12 findings) + 4 parallel paper-audits (2026-06-11) | `docs/security/security-audit-2026-06-firmware-signing.md` (all resolved); `docs/security/audits/*` | as-resolved record (except HIGH-1/MED-2 in §A) |

---

## D. RESEARCH-CORPUS MAP — research/design docs → live work they justify

So "fill the gaps from the deep researches" is a lookup, not archaeology. Each doc's **source-of-truth** column
says what it authoritatively owns (don't duplicate it — link it).

| Doc | Covers | Live items it owns / spawned | Source-of-truth for |
|-----|--------|------------------------------|----------------------|
| `docs/verification/security-tooling-sota-2026-06.md` | 2026-06 3-pass SOTA sweep (~250 systems) | Owns **§34**; spawned the whole adopt-now shortlist + FI/SCA/protocol items | The adopt/pilot/skip decision matrix; "FI countermeasure already closed"; Binsec/Rel NO-GO |
| `docs/verification/verification-targets-2026-06.md` | 12 ranked pure-logic FV targets (R1–R12) | Feeds `goals.leanloop.toml` one at a time (the FV frontier) | The FV-target ranking + KAT-anchor map driving §33/A3.1 |
| `docs/security/threat-model.md` | STRIDE; T0–T7 tiers; S0–S7 assets; Claims 1–7; §9 live caveats | §9.1 ML-KEM (ACCEPTED residual 2026-07-07, no longer open), §9.2 provisioning, §9.4 boot-attest, §9.9 MPU; **Claim 3 provisional until S-1** | Adversary taxonomy + falsifiable security-claim contract |
| `docs/security/security-review-2026-05.md` | 2026-05 firmware code-review | **Originated S-1..S-7** (`C-4→S-1`, `C-5→S-2`, … `C-9→S-7`) + H-5/H-6/M-2/M-3 carry-overs | The `C-n → S-n` ship-blocker derivation |
| `production-todo.md` | Factory irreversible-burn TODO | The **bench/factory closure of S-1/S-2/S-3** + E140/F1D1-4/global-LcsO ratchets | **OPTIGA LcsO bench spec + factory burn ceremony** (the metadata bytes) |
| `docs/provisioning/provisioning-reference.md` | Hardened provisioning research (untrusted-CM) | Corrects S-1/S-2 defaults: F1D0's candidate locked shape uses `LcsO<op>` rather than ALW; observed `0xE0E3` is a full type-`0x12` device cert; candidate type-`0x11` pool is `{0xE0E8,0xE0E9,0xE0EF}`; production `0xE0E0` is device identity, not a wallet trust anchor | Provisioning research inputs + corrected OPTIGA object inventory; not an executable ceremony |
| `docs/security/red-teaming.md` | EVT bench-attack matrix | Bench tasks: §5.1 S-5 bus capture, §5.4 S-1/2/3 lockdown, §5.5 S-7d, §6.3 TAMP | The physical pass/fail bars + required instruments |
| `docs/security/audits/*-20260611-*.md` | 4 parallel adversarial paper-audits | se-tunnels HIGH-1 (SCP03 factory keys) — published-key fallback is **code-fenced since the audit** (`secure/src/nsc/mod.rs`, fence string ``Candidate SE050 profile is incomplete without non-public SCP03 transport keys``); a journaled first-boot candidate now exists, while handoff/recovery/E140/silicon production closure remains open; tz-tamper MED-2 (prod-config gate, closed by `f8effd45`); rest resolved-in-commit | The 2026-06-11 four-domain audit record (as-found — verify against current code) |
| `docs/security/security-audit-2026-06-firmware-signing.md` | WYSIWYS signing/display audit | None open — 12 findings resolved 2026-06-10 (C-1 native-ETH-value page) | The to/value/data→digest binding soundness proof |
| `docs/secure-elements/se050-silicon-findings.md` | First on-silicon SE050 stress run (2026-05-28) | S-5 round-trip evidence; S-7d mapping ⚠ **stale: says 0x6982, code now 0x6986** | Empirical on-silicon SE050 status |
| `docs/verification/c10-fips205-delta-audit.md` | FIPS-205 ↔ C10 deviation map | Scopes A3.1 (Lean spec ↔ Yul byte-layout); Rust↔Yul agree byte-for-byte | C10↔FIPS-205 deviation ledger |
| `archive/handoff-verity-c10-verifier.md` + `archive/verity-v0.1.0-primitive-map.md` | Verity Yul-verifier port — **archived 2026-06-18: the Verity-EDSL re-authoring approach was superseded by the live Aeneas→Lean extraction track** | The (now-secondary) multi-quarter Phase 0–7 plan to prove Yul refines the Lean reference | Historical: the EDSL-port route, kept for provenance (the active route is §FV / `docs/verification/verification-targets-2026-06.md`) |
| `docs/verification/how_to_math_proof_secureness.md` | What full FV of the wallet requires | The 3-piece decomposition (Lean ref + Yul-refines + 4337 scaffolding) | The overarching FV strategy + TCB boundaries |
| `docs/verification/lean-verification-research-2026-06.md` | AI-aided-Lean tooling research | Decision: stay on Aeneas; Lean-Squad orchestration; refuted-claims list | The extraction-tool decision + realistic close-rates |
| `docs/verification/spec-assurance-research-2026-06.md` | Spec-assurance + mutation-testing research | `leanloop mutate`/`kat`/`vet` design; spec-review checklist | The spec-strength tooling design rationale |
| `docs/security/production-security.md` | Bundles A–E → actionable plan | work-todo #18–22 + #24 (FI/key-mgmt/SCA/USB/supply-chain/root-key) | Bundle→backlog mapping + root-key tiering decisions |
| `docs/security/HARDENING.md` | Consolidated "what we do" requirements | §3.4 boot-attest, §3.5 provisioning gaps (= threat-model §9.4 / work-todo #8/#22) | The normative hardening-requirements checklist |
| `docs/security/brownout-hardening.md` | Brownout/glitch design + rollout | Staged rollout; FI double-compute (#18) | The power-interruption recovery taxonomy |
| `research-bundles/A–F` | 6 deep-research prompt bundles | A→#18 FI, B→#20 key-mgmt, C→#18 SCA, D→#19 USB, E→#22 supply-chain, F→Trezor | The reproducible research-question + code-snapshot bundles |

---

## How this was built / how to extend

Reconciled by a fan-out workflow (`security-frontier-reconcile`, run `wf_718a4bc1-be4`, 2026-06-17): 7 agents
each verified one cluster against the repo + 1 mapped the corpus. To extend to another slice (companion / UI /
hardware), re-run the same shape over that slice's work-todo sections. **Re-verify before trusting any row
older than the last commit it cites** — the whole point of this file is that the pointer, not the prose, is the truth.
