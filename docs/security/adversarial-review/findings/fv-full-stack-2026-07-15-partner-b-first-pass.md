---
surface: multi
run_date: 2026-07-15
reviewer_role: Partner B
reviewer_identity: GPT-5.6 SOL
effort: ultra
backend: Codex CLI 0.144.4
scope: "Frozen PQSigner OS FV assurance case; Lean and extracted Lean; Rust/Solidity correspondence; Halmos/Kontrol claims; protocol-model gates; all 21 EasyCrypt files and frozen MM45 dependencies; CI, provenance, status, and claim ledgers; intersecting security playbooks"
stage: multi-stage
frozen_identity: "neutral packet sha256:74f9716f744dbab0d376096a05fc75db28e008d389ff2ddb749df8e1c54ead82; reviewer canonical tuple sha256:dabcea4b5dc6eacc34bda9f8eedb57792ef12fb03e0f6bfd321c82b2a9fd6e41"
status: open
---

# Adversarial-review findings — multi — 2026-07-15

## Summary

**Fourteen confirmed-real findings: eight HIGH, six MED; zero false positives and zero accepted/by-design dispositions.**

**Verdict:** NO-GO for promoting the frozen FV assurance case as current implementation or release evidence. Useful kernel proofs, conditional reductions, corpus evidence, and protocol models exist, but several headline claims bind the wrong version, wrong function, stale extraction, abstract rather than C10 games, or fail-open gates.

This is primarily an assurance-integrity verdict. I did **not** establish a present rogue Lean axiom, a current Rust Merkle acceptance bug, a wallet-bytecode bypass, a cryptographic break, or a live-device exploit. Production firmware update is already fenced by the project.

I inspected source/models deeply and executed narrow read-only synthetic negatives. The large Lean, EasyCrypt, protocol, and differential results named in the packet were supplied by the orchestrator and are not presented as my executions. The LeanLoop assurance discipline informed the separation between statement pins, kernel builds, closure whitelists, mutation/KAT evidence, and implementation correspondence.

## Reviewer and frozen-target receipt

- **Reviewer:** Partner B; GPT-5.6 SOL; `ultra`; Codex CLI `0.144.4`.
- **Neutral counterpart disclosure:** Claude Code Opus 4.8 independently reviewed the same frozen packet. Its installed CLI lacks the workflow-requested `ultracode` label, so its recorded fallback is `max`. Its report and verdict were mutually withheld. I did not seek, read, infer, or defer to them.
- **Prompt digest:** `/tmp/pqsigner-fv-review-20260715.CP6pgR/neutral-review-packet.md` — `74f9716f744dbab0d376096a05fc75db28e008d389ff2ddb749df8e1c54ead82`, exactly matching the requested digest.
- **Initial reviewer identity:** canonical tuple `dabcea4b5dc6eacc34bda9f8eedb57792ef12fb03e0f6bfd321c82b2a9fd6e41`.
- **Final reviewer identity:** same tuple, immediately before reporting.
- **Drift result:** **NO DRIFT during the review interval.** One packet receipt field was already inconsistent at entry, as detailed below.
- **Aggregate recipe:** SHA-256 of an LF-terminated ordered tuple containing packet digest; packet-supplied content digests; each tree’s branch, HEAD, and `git diff --binary HEAD` digest; PQ’s `git status --porcelain=v1 --untracked-files=all` digest; and the three normative-document digests.
- **Target mutation:** none. No target file was written or modified.

| Tree | Branch / HEAD | Content or status receipt | Tracked-diff SHA-256 |
|---|---|---|---|
| PQSigner OS | `fix/sweep-2026-07-14-findings` / `ddc7cefc35cb54e324dac94330c6ee86f9383c90` | packet content `ad0de1355cc02c47be65c586d60ae1b4d5bc71fe540a29b2ebdea967e97aa10d`; reviewer porcelain-status `d1b72a5c68dc2488479f847e1c20eab770b1b545fba81e23eaeaaa169a9589cd` | `6d9a66f6832ce47fa20762480433349ff0b2b9831e9adb2991199ff3278422a4` |
| C10 EasyCrypt port | `master` / `70974e90723153a0af151626b5921dd33a025773` | packet content `0793c04257c5f9dc2ac32e48f34e19426836944d7c9cb63e04f64ca662ea20ff` | empty |
| MM45 SPHINCS+ | `master` / `a28e4c53897a4bb57b575a177225862d48f824b7` | `easycrypt.project` modified | `7b019433601404906510abf06771c837c88c6aa6bd9d85282429021231f3bdf3` |
| MM45 XMSS | `master` / `fa90ebc250be32262bf88f9bcf7b9375dc04dc11` | clean | empty |

The packet claims the MM45 SPHINCS+ diff digest is `7b019433b87644c7914f166f8e8397f1665bf22d9fec38455c9ae55ac509a70f`; the frozen tree reproducibly yields `7b019433601404906510abf06771c837c88c6aa6bd9d85282429021231f3bdf3`. HEAD, modified path, file contents, and the latter digest remained stable from entry to exit. This is a pre-existing packet/provenance defect, not review-time drift. The packet also supplies a live-status digest without its recipe; the ordinary porcelain recipe above does not reproduce it. Conclusions here are therefore bound to the reviewer tuple and actual read-only trees, not the inconsistent field.

Normative hashes rechecked at exit:

- `CLAUDE.md`: `65cf9b101d1c7ea8dbcec117ba223b611fefabadbcce6c6c38814f52778301b4`
- `docs/planning-and-review-workflow.md`: `04d74fcd89eaca0d83498c7b65b2965e20d71f1e2755ec3196ec22a6d6288688`
- `docs/verification/fv-adversarial-review-playbook.md`: `254e4178e8693d0ae3a6a5b8be8d32ff84e2ebcd8ea8fbe4bbe8dfa6e90b6221`

**Stage and non-goals:** executing document/research-only architecture and implementation-evidence review. It does not authorize implementation, merge, shipment, hardware mutation, release signing, publication, or external state changes.

## Commands, environment, and evidence level

| Command / inspection | Environment + exact configuration | Result / receipt | Evidence level | Executed? |
|---|---|---|---|---|
| `sha256sum`, `git rev-parse`, branch, status, and `git diff --binary HEAD` checks | Four frozen trees; Git `2.54.0` | Entry/exit reviewer tuple identical; packet receipt discrepancy recorded above | source/provenance | RUN |
| `rg`, `rg --files`, `nl -ba`, `jq`, `find`, `git log`, `git diff` | Frozen PQ, C10, and both MM45 trees | Inspected Lean, extracted Lean, Rust, Solidity, all 21 EasyCrypt files, scripts, workflows, Makefiles, and ledgers | source/model | INSPECTED ONLY |
| Tx-Merkle source-history comparison | Current Rust versus committed extracted Lean and its source-era history | Concrete alias/overflow semantic drift reproduced from source | source/provenance | RUN |
| Synthetic protocol-runner return-code negative | Python `3.12.3`; monkeypatched `subprocess.run` returns 42 plus expected prover text | ProVerif, Tamarin, and CryptoVerif checks all returned empty failure lists | host harness | RUN |
| Synthetic extracted-closure negative | Python `3.12.3`; fabricated closure containing `Evil.backdoor` | Current `sorryAx` predicate accepts; strict whitelist-equivalent rejects | host harness | RUN |
| `EC_FV_ROOT=/definitely/missing ... check_easycrypt.sh` | Frozen script; exits before any `.eco` deletion | Printed `SKIP`; exit status 0 | host harness | RUN |
| `ec_sweep.py`, dependency inspection, and cross-tree `cmp` | All 21 vendored and standalone EasyCrypt files | 2 admitted files, 8 axioms, 9,602 lines; corresponding copies byte-identical | source/model | RUN |
| Lean build/audit/ledger/lints, proof mutation, extracted build/differential | Writable byte-identical execution copy | Passed as recorded in packet; 17 axioms, 18 closures, five pins/witnesses; eight mutations; 6+55 differential vectors | fresh host, supplied | SUPPLIED BY ORCHESTRATOR |
| EasyCrypt pins/margin/full wrapper | Writable byte-identical execution copy and combined MM45 tree | Pins/margin passed; full wrapper compiled 10/21, skipped 11, exited 0 | fresh host/model, supplied | SUPPLIED BY ORCHESTRATOR |
| Protocol models | Writable byte-identical execution copy | ProVerif/Tamarin passed; wrapper failed CryptoVerif path; exact manual CryptoVerif model passed | fresh host/model, supplied | SUPPLIED BY ORCHESTRATOR |
| `verify-lean4checker` | Writable byte-identical execution copy | Still running at freeze; no final receipt | host/kernel | SKIPPED/PENDING |
| Full extraction regeneration, full Kani/Halmos/Kontrol, physical FI/SCA, silicon, release checks | Not authorized or not supplied | No fresh evidence | target/hardware/operational | SKIPPED |

## Stage-specific recommendations

These recommendations bind only the exact reviewer tuple above.

| Stage | Recommendation | Exact subject/digest | Evidence and remaining gate |
|---|---|---|---|
| Architecture | **NO-GO** for treating the current FV case as coherent current assurance; research/open-decision work may continue under red lines | `dabcea4b…` | Resolve V1/V4/V6 ownership; prove the actual signed digest; reclassify EasyCrypt as partial research; repair claim boundaries |
| Implementation | **NO-GO** for promoting the frozen evidence as implementation correspondence | `dabcea4b…` | F1–F9 require fixes and fail-closed reruns; no implementation is authorized by this report |
| Merge | **Unavailable; no favorable recommendation** | No merge candidate was in scope | A digest-bound implementation candidate and fresh dual review are required |
| Production shipment | **NO-GO; authority unavailable** | No release candidate or artifact receipt was supplied | Existing production fences remain; no hardware, release, reproducibility, signing-custody, or shipped-artifact proof was established |

## Findings

### F1 — Retired `PQFW_V1` proof is presented as current firmware assurance

- **Status:** 🔲 OPEN
- **Mode / severity:** V9 · V11 · G2 · FW1 · FW2 · FW10 · BR1 · **HIGH**
- **Location / stable anchor:** `CLAUDE.md:313-315,345`; `fw-manifest/src/lib.rs:1-14,112-137,167-173,203-216`; `contracts/verification/extracted/Extracted/FwManifestSpec.lean:1-10,46-53,75-136`; `contracts/verification/docs/ASSURANCE_CASE.md:334-352`; `THREAT_CLAIM_MAP.md:31,49-50`; `docs/security/a-b-firmware-rollback-architecture.md:1793-1849`
- **Mechanism:** Current assurance rows credit a theorem about the retired 75-byte `PQFW_V1` bench preimage against the unimplemented production update design.
- **Prerequisites:** A reviewer or release process relies on G10/current threat rows; exploitation would additionally require bypassing the project’s existing production fence.
- **Consequence:** False evidence for slot binding, security-epoch rollback resistance, image-length binding, vendor-key binding, and the selected production schema.
- **Introduced here?:** UNKNOWN — V1 is historical; the frozen snapshot contains the current overclaim.
- **Failure-path trace:** legacy `PQFW_V1 || version || secure_hash || nonsecure_hash` proof → current G10/threat coverage → approval of a different slot/epoch-aware design → missing fields are assumed proven.
- **PoC (falsifiable):** Holding V1’s version and hashes fixed while changing `physical_slot` or `security_epoch` leaves the proved 75-byte preimage unchanged. The same change alters both proposed production schemas.
- **Evidence provenance:** Source contradiction inspected. No firmware update was executed.
- **Stage impact:** Architecture and implementation-evidence blocker; merge/shipment unavailable.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Mark all V1/G10 evidence `LEGACY` and remove it from current covered rows. Obtain an owner decision on one exact schema/digest. The current owners conflict: `CLAUDE.md` freezes V4/80 bytes, while the more-specific unapproved architecture candidate proposes V6/121 bytes. Then implement, extract, prove, and differentially test exact tag/length/order/slot/version/epoch/image/vendor-key binding and explicit legacy rejection.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F2 — Rust-to-Lean freshness is false-green; Tx-Merkle is concretely stale

- **Status:** 🔲 OPEN
- **Mode / severity:** V9 · V10 · V11 · G1 · G2 · BR11 · **HIGH**
- **Location / stable anchor:** `tx/src/erc20/merkle.rs:40-45,67-71,101-117`; `Extracted/TxMerkle/Funs.lean:43-50,84-100`; `Extracted/TxMerkleSpec.lean:206-245`; `.github/workflows/lean-extracted.yml:21-40,110-129`; `contracts/verification/Makefile:374-405,428-694,638-654`
- **Mechanism:** CI builds committed extraction but does not regenerate any of roughly fifteen mirrored functions; a current Rust semantic fix is absent from the proved Lean.
- **Prerequisites:** A Rust mirror changes without manually running its `extract-*` target; CI remains green.
- **Consequence:** Theorems continue proving an older implementation while assurance prose claims Rust drift is caught.
- **Introduced here?:** YES for the demonstrated semantic drift: the Rust hardening postdates the extracted source snapshot; the systemic CI weakness is older.
- **Failure-path trace:** Rust adds checked multiplication and high-index rejection → `tx/src/**` does not trigger the workflow → no extraction runs → old Lean builds and proves root equality only → green assurance receipt.
- **PoC (falsifiable):** With depth 1, a valid left-leaf proof, and `leaf_index=2`, the old extraction consumes the low bit and returns root equality after one step. Current Rust leaves `idx=1` and returns false because `idx == 0` fails. The extracted theorem also still assumes multiplication overflow cannot occur, while current Rust returns false via `checked_mul`.
- **Evidence provenance:** Source/history comparison executed; no Aeneas regeneration was run.
- **Stage impact:** Implementation evidence and any merge relying on extraction correspondence.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Maintain an exact source-symbol→generated-file manifest; run all extraction targets in an isolated deterministic checkout; require byte-identical outputs; include `tx/src/**` and every mirrored crate in triggers; execute the Rust oracle with `GEN=1`; pin Charon/Aeneas/toolchains; and add a negative test proving a Rust-only mutation makes CI red. Regenerate Tx-Merkle and prove checked-overflow and `idx==0`, including the alias negative.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F3 — The extracted UserOperation theorem proves the wrong digest

- **Status:** 🔲 OPEN
- **Mode / severity:** V3 · V9 · V11 · OC2 · SOL1 · **HIGH**
- **Location / stable anchor:** `Extracted/UserOpEquivByteLayout.lean:1-10,28-50`; `contracts/verification/Makefile:439-451`; `aa/src/userop.rs:503-510,523-540,678-706`; `secure/src/nsc/cmd_sign_userop.rs:1816-1835,1871-1896`; `contracts/smart-wallet/src/PQSmartWallet.sol:366-396,484-490`
- **Mechanism:** The theorem and extraction cover EntryPoint’s tooling-only double-keccak `compute_user_op_hash`, while firmware signs and Solidity verifies `compute_sphincs_digest_v06`, a different SHA-256 preimage.
- **Prerequisites:** The theorem is cited as firmware↔chain signing correspondence.
- **Consequence:** The central “device signs exactly what the wallet verifies” claim remains unproved.
- **Introduced here?:** UNKNOWN — present in the frozen claim/extraction selection.
- **Failure-path trace:** parsed sign request → firmware builds `AaUserOpParamsV06Sha256` → signs `compute_sphincs_digest_v06` → wallet ignores supplied `userOpHash` and recomputes the custom digest; the extracted theorem instead branches to an unused tooling function.
- **PoC (falsifiable):** The extraction target names `pqsigner_aa::userop::compute_user_op_hash`; both Type 1 and Type 2 firmware call `compute_sphincs_digest_v06`. Rust explicitly says the former is ignored by on-chain validation.
- **Evidence provenance:** Full source trace inspected; no signing execution or Solidity campaign run.
- **Stage impact:** Architecture headline and implementation correspondence.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Relabel the existing theorem as EntryPoint-v0.6 tooling compatibility only. Extract and prove `compute_sphincs_digest_v06` against an exact Lean/Solidity layout, then bridge parsed firmware request fields through the actual signing argument. Add per-field flip tests, Rust↔Lean↔Solidity differential vectors, and a Rust-only drift negative.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F4 — Public policy permits proof-after-release without artifact correspondence

- **Status:** 🔲 OPEN
- **Mode / severity:** G2 · G5 · BR1 · BR3 · BR11 · **HIGH**
- **Location / stable anchor:** `README.md:253-257`
- **Mechanism:** The README states proofs need not gate shipping because frozen parameters and formats make later proofs apply to already-shipped firmware.
- **Prerequisites:** A release ships before proof and lacks a receipt connecting shipped bytes to the later-proved source/model.
- **Consequence:** A later theorem can be sound yet irrelevant to the released artifact.
- **Introduced here?:** NO — pre-existing policy statement.
- **Failure-path trace:** release artifact built from source/configuration X → later theorem proves source/model Y → frozen parameter names are treated as equality evidence → release inherits an unsupported “verified” label.
- **PoC (falsifiable):** F1–F3 are direct counterexamples: the same nominal product contains V1/V4/V6 schema divergence, stale extraction, and two distinct UserOperation digest functions despite frozen interface prose.
- **Evidence provenance:** Policy and correspondence sources inspected.
- **Stage impact:** Release governance; production shipment blocker.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Reverse the statement. Either proofs gate release, or post-hoc evidence must bind the exact shipped artifact digest to exact source, configuration, toolchain, generated/extracted models, and proof receipt, with the residual TCB stated.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F5 — Extracted axiom gate fails open for arbitrary new axioms

- **Status:** 🔲 OPEN
- **Mode / severity:** V4 · V6 · G1 · G3 · **HIGH**
- **Location / stable anchor:** `contracts/verification/Makefile:395-403,417-426`; `contracts/verification/scripts/check_axiom_closure.py:1-60`
- **Mechanism:** The default and heavy extracted gates reject only `sorryAx`; they do not invoke the existing closure whitelist, require exact theorem identities, or require any closure records.
- **Prerequisites:** A tracked theorem gains a kernel-valid project axiom other than `sorryAx`.
- **Consequence:** CI may report “axiom-discipline passed” while the trusted base silently expands.
- **Introduced here?:** UNKNOWN — present in the frozen gate.
- **Failure-path trace:** add `axiom Evil.backdoor` → theorem consumes it → `#print axioms` includes it → grep sees no `sorryAx` → gate succeeds.
- **PoC (falsifiable):** For synthetic output `'Synthetic.headline' depends on axioms: [propext, Evil.backdoor]`, the current predicate evaluates as pass; the strict-whitelist-equivalent reports `Evil.backdoor`.
- **Evidence provenance:** Source-level synthetic evaluation executed. The orchestrator’s current closure dump was green; this finding does not allege a present rogue axiom.
- **Stage impact:** Implementation and merge assurance gate.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Invoke strict closure checking for default and heavy tiers; pin exact theorem identities, cardinalities, and allowed closures; fail on zero/missing/duplicate records; inventory source axiom declarations; and add a permanent negative where a tracked theorem consumes `axiom Evil : False`.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F6 — The WOTS EasyCrypt theorem cannot instantiate C10 parameters

- **Status:** 🔲 OPEN
- **Mode / severity:** V3 · V9 · V11 · **HIGH**
- **Location / stable anchor:** `sphincs-c10/src/params.rs:3,43-52`; `sphincs-c10/src/wots.rs:148-169`; MM45 `proofs/WOTS_TW_ES.ec:31-43,60-66,569-576`; `easycrypt/drafts/WOTS_C_Real.ec:32-48,149-168,205`; `WOTS_C_Scheme.ec:56-67,91-103`; `WOTS_C_Reduction.ec:460-466`; `WOTS_C_EmbDischarge.ec:174-194`
- **Mechanism:** The imported MM45 theorem covers checksum WOTS with `w∈{4,16,256}`; shipped C10 uses `w=8`, `log_w=3`, `L=43`, no checksum, and a constant-sum validity condition.
- **Prerequisites:** The generic port is cited as a theorem about shipped C10.
- **Consequence:** The claimed WOTS+C security leg has no legal concrete C10 instantiation.
- **Introduced here?:** NO — the research port openly carries abstract parameters; the assurance promotion is the defect.
- **Failure-path trace:** instantiate C10 → inherit MM45 parameter constraints → contradiction at `w=8`; encoding/counter/predicate remain abstract → conditional theorem is reported as concrete C10 evidence.
- **PoC (falsifiable):** C10 requires `w=8`, while MM45 proves `w=4 ∨ w=16 ∨ w=256`. No valuation satisfies both. Even hypothetically adding `log_w=3`, MM45’s checksum gives `len=43+3=46`, not C10’s 43 chains.
- **Evidence provenance:** All relevant port and MM45 theories inspected.
- **Stage impact:** A5 architecture/implementation evidence; release-blocking if cited as concrete security proof.
- **Disposition:** CONFIRMED_REAL
- **Classification:** OPEN RESEARCH
- **Required correction:** Define exact C10 WOTS: `w=8`, `log_w=3`, `L=43`, no checksum, base-w extraction, u32-BE counter, target sum 205, and 10M cap. Replace global checksum encoding with the precise predicate-conditioned antichain/order lemma and reprove WOTS/hypertree reductions over that theory.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F7 — EasyCrypt capstone is disconnected conditional arithmetic, not C10 EUF-CMA

- **Status:** 🔲 OPEN
- **Mode / severity:** V3 · V5 · V6 · V8 · V9 · V11 · **HIGH**
- **Location / stable anchor:** `SPHINCS_C.ec:20-31,134-142,154-237`; `SPHINCS_C_Skeleton.ec:12-71,90-101,130-151`; `WOTS_C_Multi.ec:54-106`; `XMSSMT_C_Bridge.ec:31-107`; `WOTS_C_Interactive.ec:682-743`; `FORS_C10.ec:154-208`; `FORS_C10_Multi.ec:116-188,472-490`; `FORS_C_TreePort.ec:1479-1535,1668-1701`; `Grind.ec:44-69,108-115`
- **Mechanism:** The capstone has no concrete C10 scheme or forgery game; its WOTS result is batch-only, its C10 FORS routing is underconstrained, its tree leg remains admitted/disconnected, and its grinder is unbounded relative to production.
- **Prerequisites:** Conditional arithmetic and mechanized assumptions are presented as a closed C10 reduction.
- **Consequence:** Neither A5-EUFCMA nor A5-ITSR is discharged for shipped C10.
- **Introduced here?:** NO — several draft files honestly describe these gaps; the current “done/unconditional” framing overstates them.
- **Failure-path trace:** abstract adversary/probabilities → batch WOTS bound → no sound adaptive XMSS bridge → paper FORS rather than C10 FORS enters capstone → tree inequality and bridge inequalities remain premises → arithmetic transitivity yields a bound over free reals.
- **PoC (falsifiable):**
  - Deleting `FORS_C10.ec` and `FORS_C10_Multi.ec` leaves `SPHINCS_C.ec` unchanged because it imports paper-model `FORS_C_Multi`.
  - In a two-layer hypertree, the upper WOTS message depends on lower-layer public keys learned only after the batch game’s `choose()`, so the proved batch notion cannot feed MM45’s adaptive XMSS game.
  - For `k=13`, `g(y)=[(99,100,0),…,(99,112,0)]` satisfies the current five FORS structural axioms while using an out-of-range instance and wrong tree IDs.
  - If the first valid counter is 10,000,001, `Grind.ec` finds it; production WOTS/FORS stops at 10,000,000 and aborts.
- **Evidence provenance:** All 21 EasyCrypt files and dependency graph inspected. No claim of an inequality reversal in the useful local lemmas.
- **Stage impact:** Cryptographic architecture evidence.
- **Disposition:** CONFIRMED_REAL
- **Classification:** OPEN RESEARCH
- **Required correction:** Define a concrete `SPHINCS_PLUS_C` scheme and EUF-CMA game; derive all adversaries from one top-level forger; close interactive WOTS and the XMSS hop; use exact C10 FORS parser/ranges/order/pool sizes; relate bounded secret-keyed grinding to its conditioned distribution with abort/query terms; close the tree extraction; and reprove all six top-level FX hops without admits or free bridge premises.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F8 — EasyCrypt gate, cache, assumptions, and snapshot provenance fail closedness

- **Status:** 🔲 OPEN
- **Mode / severity:** V5 · G1 · G3 · G4 · BR1 · BR3 · BR4 · BR11 · **HIGH**
- **Location / stable anchor:** `contracts/verification/scripts/check_easycrypt.sh:12-46,61-68,89-130,135-200`; `scripts/check_gate_enforcement.py:220-253`; EasyCrypt `README.md:28-58`; `PROVENANCE.md:6-11`
- **Mechanism:** The purported all-file gate exits zero for missing dependencies and skips, trusts the mere presence of a dependency `.eco`, pins only aggregate axiom counts, and is absent from enforcement metadata.
- **Prerequisites:** Missing or stale MM45 dependencies/toolchain, a pre-existing `.eco`, or an assumption mutation preserving total count.
- **Consequence:** A green receipt can mean 10/21 files compiled, no MM45-chain verification, stale cached theories, or a materially changed trusted base.
- **Introduced here?:** UNKNOWN — present in the frozen gate/provenance design.
- **Failure-path trace:** dependency absent/stale → script chooses successful `SKIP` or cached import → draft target sees imported statements without rebuilding proofs → final line reports `OK` → status claims every target compiles.
- **PoC (falsifiable):**
  - `EC_FV_ROOT=/definitely/missing ... check_easycrypt.sh` exits 0.
  - The supplied nominal run compiled 10/21, skipped 11, and exited 0.
  - Replacing one permitted axiom with `axiom boom : false` while preserving total count 8 leaves the pin logic satisfied.
  - The standalone port’s 21 files are byte-identical to the vendored copies, so it adds no independent evidence diversity.
  - The packet’s MM45 SPHINCS+ diff digest does not reproduce from the frozen tree.
- **Evidence provenance:** Missing-dependency negative executed; all-file sweep and cross-tree comparisons executed; nominal 10/21 receipt supplied.
- **Stage impact:** Implementation, merge, and release provenance.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Separate partial and full targets. Full must require 21/21, rebuild every transitive source target in an immutable pinned toolchain, reject skips/missing/prebuilt-only dependencies, pin dependency commits and normalized axiom names/statements, emit exact theorem/dependency/tool receipts, and be enrolled as a blocking or honestly designated release gate with negative controls. Repair and re-freeze the snapshot receipt.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F9 — Protocol-model harness ignores prover exit status

- **Status:** 🔲 OPEN
- **Mode / severity:** V7 · G1 · G3 · **MED**
- **Location / stable anchor:** `scripts/check_protocol_models.py:75-128`; root `Makefile:4113-4126,4128-4142`
- **Mechanism:** `_run` returns output without examining `subprocess.run.returncode`; verdict checks accept expected strings/counts from a failed process.
- **Prerequisites:** A prover exits nonzero after printing cached/partial/expected text, or a wrapper masks the prover status.
- **Consequence:** Protocol assurance can remain green after a tool crash or failed invocation.
- **Introduced here?:** UNKNOWN.
- **Failure-path trace:** prover emits expected tokens → exits 42 → harness discards status → count/text check passes → aggregate reports OK.
- **PoC (falsifiable):** Monkeypatching every subprocess to return code 42 with its expected output yielded `proverif failures=[]`, `tamarin failures=[]`, and `cryptoverif failures=[]`.
- **Evidence provenance:** Synthetic host negative executed. The exact CryptoVerif model itself passed in the orchestrator’s manual invocation.
- **Stage impact:** Implementation gate; no underlying-model defect established.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Treat every nonzero exit as fatal before parsing; use direct invocations or `check=True`; remove status-masking pipelines; verify exact query/lemma identities, not counts alone; and add expected-output-plus-exit-42 negatives for all three families. Resolve CryptoVerif’s library relative to the selected binary—the current wrapper incorrectly chooses `libexec/default` while the installed layout uses `bin/default`.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F10 — CryptoVerif proves an ideal full-space share, not the deployed nonzero-share distribution

- **Status:** 🔲 OPEN
- **Mode / severity:** V3 · V9 · G2 · EK1 · EK2 · **MED**
- **Location / stable anchor:** `contracts/verification/cryptoverif/seed_split_secrecy.cv:5-26,29-45`; `secure/src/dual_se.rs:95-135`; `Crypto/SplitSecrecy.lean:35-63,188-215`; root `Makefile:4113-4116`
- **Mechanism:** CryptoVerif samples an unconstrained uniform pad and proves exact zero advantage; deployed firmware rejects the all-zero pad and therefore samples a conditioned distribution.
- **Prerequisites:** The idealized result is quoted as exact deployed secrecy.
- **Consequence:** The actual half-E statement is statistical, not exact: one entropy value is excluded, with distance bounded by approximately `2^-256`. The model also leaks one share, not all state available under full-chip compromise.
- **Introduced here?:** NO — Lean already documents the distinction; other prose/gate labels overstate it.
- **Failure-path trace:** full-space OTP model → exact-zero result → mapped directly to nonzero-rejection firmware → omitted conditioning transfer and hardware randomness premise.
- **PoC (falsifiable):** Observing `half_E=v` under the deployed nonzero-mask rule excludes `entropy=v`; under the CryptoVerif full-space model it does not.
- **Evidence provenance:** Model, firmware, Lean, and claim source inspected.
- **Stage impact:** Architecture claim precision.
- **Disposition:** CONFIRMED_REAL
- **Classification:** SIMPLIFY
- **Required correction:** Label CryptoVerif/Tamarin as the full-space ideal core and formally compose the conditioned-distribution `≤2^-256` transfer, or model it quantitatively. Scope the claim to a leaked share and state the independent RNG and encrypted co-resident-secret assumptions.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F11 — Kontrol transcription retirement is overclaimed

- **Status:** 🔲 OPEN
- **Mode / severity:** V9 · G2 · G5 · SOL1 · SOL6 · **MED**
- **Location / stable anchor:** `contracts/verification/docs/THE_CLAIM.md:35-49,90-102,136-147`; `KONTROL_SCOPING.md:3-17`; `kontrol/test/KontrolValidateUserOp.t.sol:12-35,88-187`; `AXIOM_STATUS.json` A3.2 `status_detail`
- **Mechanism:** Public claim prose says all four control-flow bridges are transcription-free, while the scoped evidence admits concrete valid wrappers, concrete owner roles, and remaining wrapper/full-frame transcription assumptions.
- **Prerequisites:** The headline is consumed without the scoping document.
- **Consequence:** A bounded symbolic envelope is promoted to full bytecode↔Lean equivalence.
- **Introduced here?:** NO — the scoped caveat exists, but the public SSOT does not preserve it.
- **Failure-path trace:** concrete wrapper passes offset/length/tail gates by construction → symbolic verdict/counters prove non-bypass inside that envelope → prose generalizes to all wrapper decode and role-split behavior.
- **PoC (falsifiable):** `KontrolValidateUserOp` explicitly fixes the wrapper and owner index per rule because symbolic dynamic calldata is unsupported; `KONTROL_SCOPING.md` says those transcription elements remain Halmos-only.
- **Evidence provenance:** Source/harness inspection only; Kontrol was not rerun.
- **Stage impact:** Claim precision, not a demonstrated wallet bypass.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Represent A3.2/A3.3/A3.4 at property granularity: concrete versus symbolic fields, wrapper decode, selector/role split, full-frame semantics, batch bounds, engine, codehash, and residual transcription. Generate public prose from that record.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F12 — Cross-hash separation is computational, not structurally impossible

- **Status:** 🔲 OPEN
- **Mode / severity:** V3 · G2 · G5 · OC2 · **MED**
- **Location / stable anchor:** `CLAUDE.md:122`; `docs/security/adversarial-review/offchain-signing-adversarial-review.md:5,18`; `Wallet/OffchainBinding.lean:38-54,96-118`; `Crypto/Assumptions.lean:80-88`
- **Mechanism:** Prose describes keccak/SHA-256 message images as structurally disjoint, but both inhabit the same 256-bit codomain and Lean must assume a cross-hash separation axiom.
- **Prerequisites:** An assurance reader interprets “structurally impossible” as type- or domain-level disjointness.
- **Consequence:** A computational assumption and its quantitative bound are hidden behind structural language.
- **Introduced here?:** NO.
- **Failure-path trace:** distinct outer hash names → prose asserts impossible equality → theorem actually concludes inequality **or** `BreaksHash` → generic opaque token carries the unquantified residual.
- **PoC (falsifiable):** `keccak256` and `sha256` both return `ByteVec 32`; no tag bit or disjoint type prevents equal outputs. The Lean theorem cannot prove inequality unconditionally and invokes `keccak_sha256_cross_separation`.
- **Evidence provenance:** Source/theorem inspection.
- **Stage impact:** Architecture and public assurance wording.
- **Disposition:** CONFIRMED_REAL
- **Classification:** SIMPLIFY
- **Required correction:** Replace “structurally impossible” with an explicit computational cross-function collision assumption. Define a distinct game/token and quantitative bound, preserve the `∨ break` conclusion in headlines, and mark OC2 partial/cited-TCB.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F13 — Lean4checker is labeled as an exact closure backstop but only kernel replay is gated

- **Status:** 🔲 OPEN
- **Mode / severity:** V4 · G2 · G3 · **MED**
- **Location / stable anchor:** `contracts/verification/Makefile:155-164`; `scripts/run_lean4checker.sh:8-34,86-117`
- **Mechanism:** The repository calls the target “true axiom closure,” but the harness only requires per-module kernel replay to exit zero and never compares theorem dependencies with an allowlist.
- **Prerequisites:** A new kernel-valid axiom declaration is added and consumed.
- **Consequence:** Kernel/environment integrity can be mistaken for proof of an exact trusted-base closure.
- **Introduced here?:** UNKNOWN.
- **Failure-path trace:** declare legitimate Lean axiom → theorem depends on it → environment remains kernel-valid → replay accepts declarations → exit-only harness has no project-specific closure comparison.
- **PoC (falsifiable):** A module containing `axiom Evil : False` and `theorem t : False := Evil` is kernel-valid as an axiomatized theory. An exit-only replay cannot distinguish it from an authorized project axiom without an explicit dependency policy.
- **Evidence provenance:** Frozen harness inspected; the orchestrator’s run remained pending. No external checker source was used as evidence.
- **Stage impact:** Assurance description and pre-release gate.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Relabel the current target as independent kernel/environment replay. Compose it with exact dependency traversal and closure whitelist/cardinality checks, pin the checker commit/binary, and add negatives distinguishing forged unchecked declarations from a kernel-valid extra axiom.
- **Resolution:** UNRESOLVED in this frozen first pass.

### F14 — Claim ledgers are stale, incomplete, and deletion-tolerant

- **Status:** 🔲 OPEN
- **Mode / severity:** G1 · G2 · G5 · PC11 · BR11 · **MED**
- **Location / stable anchor:** `scripts/check_ledger_consistency.py:157-175,305-380`; `THREAT_CLAIM_MAP.md:1-21`; `REVIEW_PROVENANCE.md:70-74`; `FV_SURFACE_MAP.md:3-48`; `docs/security/adversarial-review/README.md:10-30`; `THE_CLAIM.md:103-106,248-331`; `ASSURANCE_CASE.md:219-239,381-389`; `OPEN_PROOF_OBLIGATIONS.md:56-165`; `docs/STATUS.md:147-150,174`
- **Mechanism:** Consistency checks validate only rows already declared, while public/status artifacts disagree about theorem state, evidence tier, playbook count, extraction coverage, and EasyCrypt closure.
- **Prerequisites:** A required row is deleted, omitted, or left stale while declared rows remain structurally valid.
- **Consequence:** Gate output can be green while the claim inventory loses mandatory properties or public prose reports superseded evidence.
- **Introduced here?:** NO — accumulated documentation and gate-coverage drift.
- **Failure-path trace:** delete/omit witness or claim row → checker iterates only remaining rows → zero errors → generated receipt reports consistency → stale prose remains authoritative.
- **PoC (falsifiable):** `check_witness_coverage({"witness_coverage":[]}, {})` returns an empty error list. Separately, `THREAT_CLAIM_MAP` claims completeness from nine playbooks while the current index has fifteen.
- **Evidence provenance:** Source-level checker invocation and ledger comparison.
- **Stage impact:** Architecture inventory, implementation evidence, and release governance.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW
- **Required correction:** Establish an immutable required property/theorem/hypothesis registry with minimum exact cardinalities and semantic fields for artifact, version, digest, evidence tier, and TCB. Generate narrative views from it; ingest all fifteen playbooks; default unknown/absent IDs to `UNCLAIMED`; archive historical prose; and add deletion/staleness negatives.
- **Resolution:** UNRESOLVED in this frozen first pass.

## EasyCrypt all-21-file disposition

The corresponding standalone and vendored files are byte-identical. The following evaluates theorem value, not merely syntactic compilation.

| File | Independent disposition |
|---|---|
| `DarkSide.ec` | Fixed-load/product/union arithmetic appears direction-correct; binomial mixture and concrete game linkage remain external. |
| `FORS_C.ec` | Abstract paper counter model; not C10. |
| `FORS_C10.ec` | Explicit conditioned-key game, but routing axioms and quantitative ITSR bound are insufficient. |
| `FORS_C10_Multi.ec` | Useful conditional hop; pool/routing/tree semantics remain abstract and ITSRC10 unreduced. |
| `FORS_C_Multi.ec` | Paper-model composition carrying an explicit tree premise; not C10. |
| `FORS_C_Tree.ec` | Prose characterization; no security theorem. |
| `FORS_C_TreePort.ec` | One admit, nine structural premises, paper model, disconnected from capstone. |
| `Grind.ec` | Sound finite-enumeration lemmas; not the shipped 10M-bounded search. |
| `SPHINCS_C.ec` | Arithmetic composition over free reals/premises; no concrete scheme theorem. |
| `SPHINCS_C_Skeleton.ec` | Useful gap analysis and arithmetic; confirms six missing game hops. |
| `STCR_C.ec` | Coherent abstract S-TCR(+C) game; no concrete C10 hash instantiation. |
| `WOTS_C_Bridge.ec` | Inequality direction appears sound; inherits incompatible parameters and abstract encoding. |
| `WOTS_C_EmbDischarge.ec` | Address embedding discharged; parameter and encoding premises remain. |
| `WOTS_C_Flag2Discharge.ec` | Useful address-separation proof; presentation is partially stale/redundant. |
| `WOTS_C_Interactive.ec` | Correct target notion; one admitted operational hop, strong well-formedness premise, no second hop. |
| `WOTS_C_Multi.ec` | Batch D.1 result appears internally sound; unsuitable for adaptive XMSS composition. |
| `WOTS_C_Real.ec` | Imports incompatible MM45 WOTS parameters; C10 counter, predicate, serialization, and encoding remain abstract. |
| `WOTS_C_Reduction.ec` | Useful conditional reductions; universal encoding premise is undisclosed concrete work. |
| `WOTS_C_Scheme.ec` | Scheme over MM45’s checksum parameter universe, not C10. |
| `XMSSMT_C_Bridge.ec` | Accurate diagnosis and arithmetic lemma; no security bridge. |
| `XMSSMT_C_Scheme.ec` | Definitions/correctness gates only; no security proof and inherits WOTS mismatch. |

I found no inequality reversal in the batch WOTS bridge, D.1 arithmetic composition, `DarkSide.forsc_le_fors`, its product/union bounds, or `ITSRC10_le_noC_SAME_ORACLE`. `XMSSMT_C_Bridge.ec` correctly refuses the invalid interactive≤batch direction. These are worthwhile research results, but they do not provide concrete C10 closure.

## EasyCrypt continuation assessment

Do **not** continue maintaining the standalone port as a separate evidence repository: it duplicates the vendored tree and provides no implementation or reviewer diversity.

Preserve useful games, address lemmas, DarkSide arithmetic, and gap analyses in one canonical research tree. Continue only as milestone-gated research:

1. Make the build/provenance gate immutable and fail-closed.
2. Prove an exact no-checksum C10 WOTS theory and its predicate-conditioned encoding lemma.
3. Close interactive WOTS and the adaptive XMSS composition.
4. Model exact C10 FORS parsing, routing, ranges, pool sizes, bounded grinding, and its ROM/ITSR/query terms.
5. Define the concrete top-level scheme/game and reprove the six FX hops.
6. Produce a clean 21/21 source-built receipt with closed concrete theorem identities.

Stop or reframe the effort if milestones 2–3 cannot be closed; further abstract capstone arithmetic would be low-value proof theater. This is likely a substantial multi-month specialist proof effort. The current honest label is **mechanized assumptions and partial reductions**, not C10 EUF-CMA verification. The reported 130.6-bit FORS work factor is arithmetic, not a reduction, and the supplied `q_h=2^128` figure gives only about `2^-2.6` advantage.

## Ranked FV-surface expansion/refinement

| Rank | Target | Security value / feasibility / proof-to-shipping span |
|---:|---|---|
| 1 | Actual `compute_sphincs_digest_v06` end-to-end | Highest immediate value and good feasibility: parsed request → firmware SHA-256 bytes → signing argument → Solidity recomputation, with field-flip and source-drift negatives |
| 2 | Global extraction freshness | High trust-base reduction and good feasibility: deterministic all-target regeneration, source-symbol manifest, current Rust oracle, exact toolchain pins |
| 3 | Authoritative firmware-update schema/state machine | High value but blocked on owner decision between V4/V6; prove source/model first, then separately power-cut/hardware behavior |
| 4 | Exact release-artifact correspondence | High proof-to-shipping span: bind source, configuration, generated files, compiler/toolchain, binaries, hashes, and proof receipt |
| 5 | Deployed EntryPoint-v0.6 validate→execute/replay/cap properties | Targeted bytecode properties are valuable; avoid an unbounded “verify the whole EVM” project |
| 6 | Concrete C10 security game | High cryptographic value but costly and research-risky; proceed only through the EasyCrypt milestones above |
| 7 | Persistent page-123/update journal/PIN recovery under reset | High lifecycle value; model crash atomicity and refusal/recovery, then require separate silicon/power-cut/FI evidence |
| 8 | Clear-sign intent→rendered pixels | Prove parsed intent/display injectivity and bounded pages-to-pixels at source/model level; do not misrepresent it as LCD/silicon evidence |

Low-value work to reject: more V1 lemmas; finite KATs described as universal equivalence; abstract-real capstones without concrete games; broad full-EVM verification; abstract silicon models presented as shipment proof; or high-memory proof maintenance without freshness and release correspondence.

## Suspicions (unverified — no PoC)

- Other extracted ranks may be stale for the same systemic reason as Tx-Merkle. I did not promote them without a concrete semantic delta.
- The actual firmware/Solidity sphincs-digest layouts appear intended to match by source inspection, but the missing theorem leaves room for a field-width/order bug; no mismatch was independently demonstrated.
- Persistent-state, provisioning, recovery, PIN directionality, clear-sign display, and update state machines likely contain further proof/implementation gaps, but the packet did not provide sufficient fresh executable evidence to elevate a new defect.

## Invariant and failure-path trace

| In-scope lens | Strongest attempted path | Result |
|---|---|---|
| FV V1/V2/V4/V7 | Looked for `False`, `sorry`, hidden closure expansion, hollow theft theorem, and prover false-greens | No present rogue axiom or theft-theorem vacuity established; F5/F9/F13 show future/current gate weaknesses |
| FV V3/V5/V6/V8/V9/V11 | Followed exact functions, versions, ranges, games, dependencies, and source/model bridges | F1–F3 and F6–F8 break current correspondence/composition claims |
| FV V10 and G1–G5 | Compared corpus evidence with universal language; tested skip/deletion/status negatives | F2, F4, F5, F8, F9, and F14 confirmed false-green or overclaim paths |
| Firmware update / lifecycle / build / production | Traced V1→V4/V6, rollback fields, proof-after-release, receipt/cache behavior | Current implementation remains production-fenced; proof and owner artifacts conflict |
| Offchain / onchain / clear-sign / UI / USB / TrustZone / runtime | Followed request parsing to signed digest and wallet verifier; inspected bytecode-evidence envelopes | Actual digest theorem missing; Kontrol scope overclaimed; no gateway/display/runtime exploit established |
| Entropy / key lifecycle / secure element | Compared ideal share model with nonzero firmware distribution and co-resident-secret scope | Exact-zero deployed claim narrowed by F10; no RNG or chip compromise experiment run |
| FI/SCA / silicon | Checked whether source/model claims were being promoted to hardware authority | No such authority is granted here; physical FI, SCA, remanence, option-byte, and silicon evidence remain unreviewed |

Applicable failure modes explicitly exercised:

- **Malformed/range state:** Tx high-index alias; EasyCrypt FORS out-of-range instance/tree IDs.
- **Trust-boundary crossing:** parsed firmware request to the actual signing digest and Solidity verifier.
- **Downgrade/version:** legacy V1 evidence promoted to V4/V6.
- **Fallback/skip:** EasyCrypt missing dependencies/cache; protocol nonzero exits; closure rows and ledgers omitted.
- **Reset/power cut/recovery:** identified as high-priority residual; not executed or proven.
- **Resource bounds:** production 10M grinder versus total enumeration; high-memory proof carve-out remained nonblocking.
- **Release boundary:** later proof versus exact shipped artifact, toolchain, and generated-source correspondence.

## Cross-adjudication

Not performed. This is the mutually withheld first pass. No counterpart report, verdict, path, or digest was accessed. Cross-adjudication must occur only after both first-pass byte streams and hashes are frozen.

## Honest residual

1. **What I tried to break and could not**

   - I did not find a present arbitrary axiom or `sorryAx` in the supplied default theorem closures; the orchestrator’s build/audit/ledger run was green.
   - I did not derive `False` or establish that `theft_free` is vacuous. The supplied eight proof mutations behaved as expected.
   - Current Rust Tx-Merkle rejects high-index aliases; the defect is stale proof correspondence, not current Rust acceptance.
   - The relevant Rust, firmware, and Solidity sources appear to use the same intended custom sphincs-digest concept; I found absence of proof, not an actual mismatching field.
   - I did not find an inequality reversal in the useful EasyCrypt local lemmas named above.
   - The exact CryptoVerif model manually passed when invoked with the correct library path; F9 concerns its wrapper, and F10 its abstraction boundary.
   - Kontrol’s scoped non-bypass properties are meaningful; F11 concerns the broader transcription-free headline, not a demonstrated bypass.

2. **What I did not look at or rerun**

   - No full fifteen-target Aeneas regeneration, full extracted high-memory proof, complete Lean4checker result, full Kani census, Halmos/Kontrol campaign, clean 21/21 EasyCrypt build, or cold MM45 dependency build.
   - No hardware, FI injection, SCA/TVLA, bus capture, SRAM remanence, reset/power-cut, silicon option-byte, provisioning/RMA, factory, HSM, reproducible-release, or signing-key-custody ceremony.
   - No live chain/deployment state, EntryPoint bytecode outside the targeted source trace, or full repository line-by-line product-code audit.
   - No web search or mutable `/home/nicola/repos` working copy was used.
   - No counterpart report was inspected.

3. **Provenance and limits**

   - My direct executions were identity checks and narrow host-level synthetic negatives. Large green proof/model receipts were supplied by the orchestrator and labeled accordingly.
   - Source/model review cannot establish hardware behavior, compiler correctness, deployed-bytecode identity, or shipping-artifact provenance.
   - Current EasyCrypt results support generic conditional reasoning and assumption analysis, not a concrete shipped-C10 security theorem.
   - The packet’s MM45 diff receipt is inconsistent; this report is bound to the independently recorded reviewer tuple.
   - Architecture, implementation, merge, production shipment, hardware action, release signing, and all external writes remain separately gated and unauthorized.