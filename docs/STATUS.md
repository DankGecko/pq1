# PQSigner — STATUS (start here)

> **The front door.** Read this first. It's a **router, not an encyclopedia**: §0 maps *where the truth
> lives* (one owner per concern — everyone else links); §A–§D are the **security/verification frontier**,
> the one slice this file owns directly. Detail lives in the linked docs, not here.
>
> **Freshness.** §A–§D are a snapshot **reconciled against the repo on 2026-06-17** (`security-frontier-reconcile`
> workflow). They are only trustworthy if re-reconciled — a stale STATUS is worse than none. Re-run that
> workflow over a slice before relying on its rows, and trust the **evidence pointer, not the prose**.

## §0 — Where the truth lives (doc map)

One concern → one **owner** doc. If a fact lives in two docs it *will* drift (it did: S-1/S-2/S-3 status was
in four places). The rule: **owners hold the fact; everything else links.**

| Concern | Owner (source of truth) | Notes |
|---------|------------------------|-------|
| Non-negotiable invariants · code conventions · key-file map · KDF tags | **`CLAUDE.md`** | the LLM operating contract; the "do / never" rules |
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

- **The real ship gate is NOT a tooling track** — it's **OPTIGA silicon (S-1/S-3 LcsO ratchet) + the S-2
  factory trust-anchor cert**, plus the **SCP03 per-unit PUT-KEY ceremony (HIGH-1, code-fenced)** and the
  **S-5 bus capture**. All factory/bench. Everything else is assurance depth, not a blocker.
- **Keyboard-doable security work right now (`blocked-on: code`):** the S-3 soft-counter compile-fence, the
  `make checkct` CI gate + SAES-CMAC driver, hevm-equiv, the independent-source KAT oracle leg, a
  ClusterFuzzLite job, the `claude-code-security-review` Action, the prod-config CI gate (MED-2), and the ToB
  skill-pilot tail.
- **The big compute item:** the full ~40h FI fault-sweep campaign (harnesses built, only smoke-run).
- **Stale-doc flag found during reconcile:** `docs/secure-elements/se050-silicon-findings.md` still says lockout SW `0x6982`; the
  live post-revert code maps `0x6986` (`ef3d00da`). Worth a 2-minute sync.

---

## A. SHIP GATE — must close before any unit leaves the bench

`docs/production-todo.md` owns the OPTIGA bench/factory spec; `docs/security/security-review-2026-05.md` owns the
`C-n → S-n` finding provenance; `docs/security/red-teaming.md` owns the bench pass/fail bars.

| ID | Item | Status | Blocked-on | Evidence (spot-check) | What remains |
|----|------|--------|-----------|------------------------|--------------|
| **S-1** | F1D0 `Change=ALW` → desolder PIN brute-force | partial | **bench** | fence `nsc/mod.rs:268-282` (commit `832a369d`); `Auto(F1D0)` builder `apdu.rs:1089`; `verify_and_lock` `optiga/mod.rs:799` | Irreversible **LcsO=Op ratchet** + sacrificial-part validation on fresh silicon. ⚠ fence keyed to `mode-production` ALONE — a release `stm32u585` image that omits it ships S-1-open (convention, not enforced). |
| **S-2** | Public Infineon **sample** trust-anchor at `0xE0E3` → SetObjectProtected bypass | partial | **factory** | sample cert `optiga/reset.rs:33-38`; reset-oids fence `nsc/mod.rs:229-243`; `lockdown_ta_pool` `optiga/mod.rs:1772` | Production **PQ1-factory-HSM** trust-anchor cert (key-custody). NOTE: repo's own correction — `0xE0E3` is a non-writable device-cert slot; `docs/provisioning/provisioning-reference.md` says only `0xE0E0` ships a sample anchor. Weakens the specific path, doesn't close S-2. |
| **S-3** | Default build has no silicon-enforced PIN lockout | partial | **bench** + code | hw-counter-required fence `nsc/mod.rs:205-222`; LUC `Execute=LUC(E120)` `apdu.rs:1075`; `make optiga-hw-counter-e2e` PASSED 2026-04-22 | ⚠ **CORRECTION:** the claimed `build_metadata_counter` production gate **does NOT exist** (grep-confirmed) — fencing the weak soft-counter path is still **code-doable** work. Plus the LcsO=Op ratchet (bench). |
| **S-5** | SCP03 response unprotected (`half_E` plaintext on I²C) | **done** (code+func-silicon) | bench | `P1=0x33` `se050/scp03.rs:269`; `unwrap_response` `:518`; round-trip on B-U585I `work-todo:2397`; tests `scp03_logic.rs` | Only the dedicated **logic-analyzer bus capture** confirming no plaintext on the wire (`red-teaming §5.1`). |
| **S-6** | Admin-delete on USERID → seed theft | **done** | none | `mod.rs:1690-1706` (`admin_ref=None`); stress test `userid_no_admin_delete` PASS | — |
| **S-7a/b/c** | max_attempts=0 footgun; `0x6986`→Ok mis-map; extended-Lc 2-byte Le | **done** | none | `apdu.rs:484-486` / `:908-924` / `:263-271`; stress `pin_unlimited_no_lockout` | — |
| **S-7d** | Empirical UserID-lockout SW mapping | **done** (on silicon) | none | `git ef3d00da` (Runs 3-4, B-U585I); `create_session` maps `0x6986`→`AuthMethodBlocked` `apdu.rs:679-692` | ⚠ **was marked open** — actually run. `0x6982` was a reverted red herring. **`docs/secure-elements/se050-silicon-findings.md` is stale (says 0x6982) — sync it.** |
| **S-4** | OPTIGA lower-sev cleanups (5 sub-items) | partial | bench + code | `Conf(E140)` DoS branch live `apdu.rs:907`; F1D5/F1E1 naming split `apdu.rs:161` vs `mod.rs:37` | Items 2/3/5 are doc/code-doable now; item 1 needs a design+bench tradeoff; item 4 needs the board. |
| **HIGH-1** | SCP03 default-keyed with PUBLISHED AN12436 factory keys (dev) → bus attacker extracts `half_E` | partial (code fenced) | **factory** | prod fence `nsc/mod.rs:378-388` (forces `se050-derived-scp03`); rotation wired `main.rs:1613`; anti-factory-key guard `scp03_logic.rs:252` | ⚠ **Corrected from the audit's as-found "open back-door" — code half is CLOSED** (same fence shape as S-1/S-3: factory keys dev-only, production won't compile without derived keys). Remaining = the per-unit `se050-rotate-scp03` **PUT KEY ceremony on silicon** + validation that rotation takes. |
| **MED-2** | `e2e-test`/`dev-testkey` escape hatches ship fixed secrets; no prod-check CI gate | OPEN | code | `docs/security/audits/tz-tamper-debug-20260611-*.md` MEDIUM-2 | A CI/prod-config gate. |
| — | **Claim 3 (PIN gate) is PROVISIONAL** | — | bench | `docs/security/threat-model.md` Claim 3 | Re-establish via `pin-gate-hw-counter-e2e` on a ratcheted sacrificial part once S-1 closes. |

---

## B. ACTIVE FRONTIER — open / partial assurance work, grouped by what unblocks it

### `blocked-on: code` — doable from the keyboard now

| Area | Item | Status | Evidence / where | Source |
|------|------|--------|------------------|--------|
| OPTIGA | S-3 soft-counter `build_metadata_counter` compile-fence | open | `apdu.rs:971` ungated; `production-todo.md:188` | sec-review C-6 |
| CI | Prod-config gate rejecting `e2e-test`/`dev-testkey` fixed secrets (MED-2) | open | `docs/security/audits/tz-tamper-debug-20260611-*.md` | audits/tz-tamper |
| cargo-checkct | a CI gate (driver coverage now complete) | partial | **`driver_saes` DONE 2026-06-18** (proves SECURE on binsec — the Tier-1 SAES-CMAC(DHUK) framing incl. `double_l`'s secret-MSB reduction is branchless on thumbv8m); 4 SECURE drivers (kdf/fors/th/saes); `make checkct` EXISTS (`Makefile:3620`). Remaining = a CI job (binsec needs a local opam switch, so kept host-local for now) | sota §1 |
| on-chain Yul | **hevm equivalence** of `SPHINCsC10Asm` vs a reference Solidity verifier | open | no hevm harness/binary; halmos side done (39 rules) | sota §2 |
| on-chain Yul | KAT oracle — independent-source leg | partial | 3-way *shared-corpus* differential runs (Rust JSON → Yul `SPHINCsC10Asm.t.sol` + Lean `verify-test-vectors`), but vectors are self-generated by the `sphincs-c10` crate (self-consistency, not independent). **Path found 2026-06-18:** `SPHINCS-/script/signer.py` is a parameterizable reference signer with an exact `c10` param config (h18/d2/a11/k13/w8/target_sum205) — the only gap is it hashes with **keccak256** vs PQSigner's **SHA-256**, so the independent leg = port signer.py's hash/ADRS to SHA-256-C10 then feed its vectors to all 3 verifiers. Careful multi-hour port (not a scaffold) | sota §2 |
| CI / fuzz | ClusterFuzzLite time-boxed job over the 11 fuzz targets | open | substrate done (`make fuzz-all`, 11 targets, committed corpus); no `.clusterfuzzlite/` config yet | trezor-comp |
| CI | `claude-code-security-review` GitHub Action (ext-contributor-gated) | open | absent from `.github/workflows/` | sota §8 |
| ToB skills | Pilot tail: mutation-testing, property-based-testing, differential-review, variant-analysis, entry-point-analyzer, supply-chain-risk-auditor, agentic-actions-auditor, seatbelt-sandboxer, fp-check | open | zero run-evidence (2 headline + semgrep done; see §C) | sota §11 |
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

### `blocked-on: factory` — needs HSM key-custody or a release pipeline

| Area | Item | Status | Source |
|------|------|--------|--------|
| OPTIGA | S-2 production PQ1-factory-HSM trust-anchor cert | open | production-todo S-2 |
| supply-chain | cargo-vet audit set + SLSA provenance / cosign→Rekor on release | open | sota §8 |
| provisioning | Factory provisioning automation (per-device SCP03 + PBS) | open | threat-model §9.2 |

### `blocked-on: research` — long-horizon / separate project

| Area | Item | Status | Evidence / note | Source |
|------|------|--------|-----------------|--------|
| Lean FV | **A3.1** deductive interpreter-refinement closure (the verifier ∀-theorem) | partial — slices landed | interpreter + byte-memory + KAT-thru (396/396) + H_msg/FORS-climb/tree-body + ADRS bridge done (`797c2699…d3dd141b`); `execC10Asm = Spec.verify` ∀-input NOT proven; note: `contracts/verity/PQSigner/` workbench named in subtasks does NOT exist — work is in `lean/SphincsCVerify/Interpreter/` | verity / how_to_math_proof |
| Lean FV | Real-valued / probability-monad quantitative bound (deeper half of E) | open | log-domain floor done (`Crypto/Quantitative.lean`); `Pr[forge]≤ε` half absent | FV-frontier(b) |
| Lean FV | `deserialize_pin_state` as a proven Aeneas rank | open | source `domain/src/lib.rs:739`; not extracted (Kani already proves panic-freedom) | handoff-pinstate |
| Lean FV | Extend Aeneas into `domain` derivation (`slot_entropy`/`derive_c10_slot_seeds`) | open | needs `sha256_bytes` refactor first | FV-frontier |
| Firmware FV | LeanLoop roadmap (goal-splitting / prover ensembling / lean-lsp MCP tier) | open | separate repo | sota §3 |
| Crypto | ML-KEM-1024 inner wrap (Claim 7 / CRQC bus-capture residual) | open | closes SCP03/Shield static-leak residual | threat-model §9.1 |
| Platform | Boot-time SE attestation; MPU privilege-banking | open | HARDENING §3.4 / threat-model §9.4, §9.9 | — |

---

## C. DONE — verified, with evidence

Compact ledger of security/verification items confirmed complete against the repo. Spot-check the pointer.

| Area | Item | Evidence | Depth |
|------|------|----------|-------|
| Supply-chain | cargo-deny `advisories+bans+sources` in CI + `make invariant-gates` | `deny.toml`; `ci.yml:68-71`; `Makefile:3515` (`ca28eda7`) | re-read configs |
| Fuzzing | cargo-fuzz campaign, 11 targets, 0 crashes, `make fuzz-all` | `fuzz/fuzz_targets/` (11); 1.7M corpus; `fuzz/README.md:105` | corpus checked |
| Supply-chain | `make sbom` (CycloneDX sidecar) | `Makefile:3528-3532`; cargo-cyclonedx installed | target exists |
| Firmware FV | Kani (6 harnesses) + Miri (0-UB incl. secure-crate NS-ptr) | `make kani`/`make miri` `Makefile:3545-3566`; `#[kani::proof]`×6; `38a097d8`,`242feda9`,`69257ff0` | **now CI-gated** (2026-06-18): Miri per-push (`ci.yml` `miri` job), Kani nightly (`nightly.yml`) |
| CI / UI | ui-capture golden-screenshot regression gate | `make ui-golden` (`Makefile`); producer `ui/capture.rs`, comparator `tools/ui_fixture.py`, fixtures `tests/ui_fixtures.json` | **target added 2026-06-18** — LOCAL/manual gate (full-e2e capture is 10+ min over QEMU semihosting → not CI-gated; a dedicated short-capture scenario is the CI-viable follow-up) |
| CI / repro | Reproducible-build byte-diff gate | `make verify-repro` (`Makefile:1912`); `nightly.yml` `verify-repro` job | **wired 2026-06-18** — was capability-only (Makefile comment falsely claimed per-PR); now nightly-gated |
| Protocol | ProVerif (17 RESULTs) + Tamarin (6 lemmas) | `make proverif`/`make tamarin`; `4beebec7`,`118665bf`,`86291fd7`,`3f82f560`; **+`fw_update_authenticity.pv` 2026-06-18** (FW-update no-forgery + domain separation, 2 RESULTs green) | **both provers re-run end-to-end** |
| SCA | cargo-checkct: 4 SECURE CT proofs (kdf/fors/th/**saes**) | `checkct/driver_{kdf,fors,th,saes}`; `driver_saes` proves SECURE on binsec 2026-06-18 (Tier-1 SAES-CMAC framing) | binsec re-run for driver_saes; kdf/fors/th from `b0944ecf` |
| SCA | Muscat pilot — full-10M TVLA reproduces lascar, CPA flat | `muscat/pqsigner_tvla_cpa.rs` (`23e72bd4`) | cross-check on emulated traces (not silicon) |
| ToB skills | zeroize-audit (clean); ct_analyzer → CT-1 found+fixed; semgrep rules hand-authored | `8184d4b5`; fix `shuffle.rs:181` (`0d432f8f`); `.semgrep/pqsigner-invariants.yml` | commits + live fix |
| Lean FV (A5) | EUF-CMA restated consistently; `theft_free` re-derived; sha256→collision-resistance; 3 shapes→opaque | `Crypto/EUFCMA.lean:123`, `Assumptions.lean:101-170` (`4ba5be10`,`83776287`); `make verify-audit` = 11 axioms, 0 sorryAx | gate asserted |
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
| `docs/security/threat-model.md` | STRIDE; T0–T7 tiers; S0–S7 assets; Claims 1–7; §9 live caveats | §9.1 ML-KEM, §9.2 provisioning, §9.4 boot-attest, §9.9 MPU; **Claim 3 provisional until S-1** | Adversary taxonomy + falsifiable security-claim contract |
| `docs/security/security-review-2026-05.md` | 2026-05 firmware code-review | **Originated S-1..S-7** (`C-4→S-1`, `C-5→S-2`, … `C-9→S-7`) + H-5/H-6/M-2/M-3 carry-overs | The `C-n → S-n` ship-blocker derivation |
| `production-todo.md` | Factory irreversible-burn TODO | The **bench/factory closure of S-1/S-2/S-3** + E140/F1D1-4/global-LcsO ratchets | **OPTIGA LcsO bench spec + factory burn ceremony** (the metadata bytes) |
| `docs/provisioning/provisioning-reference.md` | Hardened provisioning ceremony (untrusted-CM) | Corrects S-1/S-2 defaults: F1D0 ships `LcsO<op` not ALW; only `0xE0E0` ships a sample anchor | Provisioning ceremony shape + corrected OPTIGA default-state |
| `docs/security/red-teaming.md` | EVT bench-attack matrix | Bench tasks: §5.1 S-5 bus capture, §5.4 S-1/2/3 lockdown, §5.5 S-7d, §6.3 TAMP | The physical pass/fail bars + required instruments |
| `docs/security/audits/*-20260611-*.md` | 4 parallel adversarial paper-audits | se-tunnels HIGH-1 (SCP03 factory keys) — **code-fenced since the audit** (`nsc/mod.rs:378`), factory ceremony remains; tz-tamper MED-2 (prod-config gate, open); rest resolved-in-commit | The 2026-06-11 four-domain audit record (as-found — verify against current code) |
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
