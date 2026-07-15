# PQSigner OS formal-verification symmetric cross-adjudication report

**Reviewer:** Partner B, GPT-5.6 SOL, `ultra` effort, Codex CLI 0.144.4  
**Review stage:** architecture and implementation-evidence cross-adjudication  
**Date:** 2026-07-15  
**Authority:** document/research only; no implementation, merge, release, or shipment authority

## Executive conclusion

Partner A’s architecture/implementation approval with red lines does **not** survive cross-adjudication. Four independently supported HIGH assurance defects remain:

- source-to-proof freshness can report old extracted Rust as current;
- the extracted UserOperation headline proves the tooling double-keccak hash, not the digest actually signed;
- the extracted-proof gate accepts a consumed arbitrary `False` axiom;
- the EasyCrypt WOTS theorem cannot instantiate shipped C10 parameters, while its gate can return full success after compiling only 10 of 21 targets.

These are assurance-integrity and correspondence failures. They do **not** establish a deployed forgery, wallet bypass, current Rust Tx-Merkle acceptance bug, Lean kernel failure, or hardware/release compromise.

| Stage | Recommendation | Scope |
|---|---|---|
| Architecture | **NO-GO** | Do not present the current FV architecture as end-to-end assurance for the current device. Legacy firmware-update, actual signing-digest, and C10 proof bridges are not current/concrete. Individual scoped Lean/model results remain usable under their stated assumptions. |
| Implementation evidence | **NO-GO** | False-green extraction, closure, protocol, EasyCrypt, and ledger mechanisms prevent promotion of the frozen evidence set as current and closed. |
| Merge | **NO-GO / unavailable** | No merge candidate was supplied. Do not approve any change claiming these assurance defects closed until the acceptance tests below pass. Unrelated merges were not assessed. |
| Shipment | **NO-GO / no authority** | Existing production fences already block shipment. This source-and-receipt review cannot establish binary, silicon, hardware, release-signing, or distribution readiness. |

No original finding was wholly refuted: fourteen are confirmed and seven are narrowed. “Narrowed” often means the assurance failure survives but a claimed product consequence or severity did not.

## Frozen identity and evidence provenance

### Immutable inputs

- [Neutral packet](/tmp/pqsigner-fv-review-20260715.CP6pgR/neutral-review-packet.md):  
  `74f9716f744dbab0d376096a05fc75db28e008d389ff2ddb749df8e1c54ead82`
- [Cross-adjudication packet](/tmp/pqsigner-fv-review-20260715.CP6pgR/cross-adjudication-packet.md):  
  `cf2bdc6c1e911019155c007f9a34c8f275fc109f4c7ea7a31aa20cbbfef49972`
- [Partner A first pass](/tmp/pqsigner-fv-review-20260715.CP6pgR/partner-a-first-pass.md): 41,535 bytes, 227 lines,  
  `5afe1f48de1847281bdbb3e10e5ce2f9e18e4faff95c34599a1c755be19722f8`
- [Partner A JSON envelope](/tmp/pqsigner-fv-review-20260715.CP6pgR/partner-a-first-pass.json):  
  `a4d5a49d29697b503922abf74ffb6658170f6fa81198f6ec98e9fa979e9b73e4`
- [Partner B first pass](/tmp/pqsigner-fv-review-20260715.CP6pgR/partner-b-first-pass.md): 49,814 bytes, 462 lines,  
  `9b8a4264ee8430075466ab43e60904496408df67e0563d16a48906b2eb8e9cef`

All report digests and sizes matched before reading the opposing report and again immediately before this report.

The three material supplemental receipts also remained unchanged:

- [Tx-Merkle regeneration](/tmp/pqsigner-fv-review-20260715.CP6pgR/tx-merkle-regen.log):  
  `d0abb9ad7695b361bc0ef64abb7b4318d2769271ac1fa1617f6a193380947ff9`
- [Arbitrary-axiom canary](/tmp/pqsigner-fv-review-20260715.CP6pgR/extracted-unmodeled-assumption-canary.log):  
  `3ea1e0d4330317294a46d1f38a38f39223a25ea339d5eedfd8dcc70a2c979362`
- [Corrected EasyCrypt root run](/tmp/pqsigner-fv-review-20260715.CP6pgR/easycrypt-correct-frozen-root.log):  
  `367ff8c538e898386ee7fef749d9cf6b60808d5449d6d2a151a41581cfed9056`

### Frozen-tree checks

At entry and exit, the primary tree independently reproduced:

- HEAD: `ddc7cefc35cb54e324dac94330c6ee86f9383c90`
- tracked-diff SHA-256: `6d9a66f6832ce47fa20762480433349ff0b2b9831e9adb2991199ff3278422a4`
- reviewer content-inventory checksum:  
  `088303c29fdec7684f654a8b3cd4fd8311c50e40349709b0b140e52fa4b1649e`
- ordinary `git status --porcelain=v1 --untracked-files=all` checksum:  
  `d1b72a5c68dc2488479f847e1c20eab770b1b545fba81e23eaeaaa169a9589cd`

The reviewer inventory checksum was computed over sorted tracked and untracked filenames with their SHA-256 values. The packet’s aggregate content digest `ad0de135…` and freeze-time status digest use an unspecified serialization recipe, so I preserve them as packet-supplied identities rather than claiming independent reproduction.

Final sibling checks:

| Frozen tree | HEAD | Tracked diff |
|---|---|---|
| C10 EasyCrypt port | `70974e90723153a0af151626b5921dd33a025773` | empty |
| MM45 SPHINCS+ | `a28e4c53897a4bb57b575a177225862d48f824b7` | `7b019433601404906510abf06771c837c88c6aa6bd9d85282429021231f3bdf3` |
| MM45 XMSS | `fa90ebc250be32262bf88f9bcf7b9375dc04dc11` | empty |

The MM45 SPHINCS+ value corrects the neutral packet’s `7b019433b876…` transcription. HEAD, modified file, and content did not drift.

Normative hashes also matched at exit:

- `CLAUDE.md`: `65cf9b10…78301b4`
- planning/review workflow: `04d74fcd…6288688`
- FV adversarial-review playbook: `254e4178…e90b6221`

No target file was edited, and `/home/nicola/repos` was not inspected.

## Finding-by-finding adjudication

### Partner A findings

| ID | Verdict | Calibrated impact | Cross-adjudication |
|---|---|---:|---|
| A-F1 | **CONFIRMED** | MED | [check_easycrypt.sh](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/scripts/check_easycrypt.sh:119) exits successfully for absent dependencies/skips and prints `OK`; the corrected receipt compiled 10/21 and skipped the WOTS/capstone chain. This is false-green assurance, not a demonstrated forgery. |
| A-F2 | **NARROWED** | LOW | Supplemental replay exited 0 across all 58 modules, removing the pending-kernel-replay premise. [THE_CLAIM.md](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/docs/THE_CLAIM.md:58) remains stale at 55. Kernel replay still does not establish exact project closure; that survives as B-F13. |
| A-F3 | **CONFIRMED** | MED, raised from LOW | [ASSURANCE_CASE G10](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/docs/ASSURANCE_CASE.md:334) presents V1 as new/current, while [CLAUDE.md](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/CLAUDE.md:313) calls it legacy and names V4, and [work-todo.md](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/docs/work-todo.md:1251) describes V6 as an unapproved research candidate. This is a current assurance-row contradiction, though production remains fenced. |
| A-F4 | **CONFIRMED** | LOW | The root [Makefile](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/Makefile:4119) assumes `libexec/default`, while the supplied installation required `bin/default`; CryptoVerif paths are absent from gate enforcement. The exact model passed manually, and CryptoVerif is documented local-only, so this is portability/enrollment rather than model failure. |
| A-F5 | **CONFIRMED** | LOW | EasyCrypt README says seven axioms/four `g` constraints; source and gate contain eight/five. The more serious fact—that a count-preserving `dmkey_ll : false` mutation passes—belongs to B-F8. |
| A-F6 | **CONFIRMED** | LOW | `WOTS_C_EmbDischarge.ec` says FLAG-2 remains open, while its later theorem consumes the proved embedding lemma. The theorem still has an explicit encoding-compatibility premise; it is not a concrete C10 instantiation. |
| A-F7 | **NARROWED** | LOW; provenance limb repaired | The original receipt set inert `MM45_ROOT` although the driver reads `EC_FV_ROOT`. The corrected immutable-root receipt repairs this provenance defect. It simultaneously confirms A-F1/B-F8 because it still reports 10/21 plus 11 skips. |

### Partner B findings

| ID | Verdict | Calibrated impact | Cross-adjudication |
|---|---|---:|---|
| B-F1 | **NARROWED** | MED, reduced from HIGH | Retired V1 is genuinely presented as current assurance, overlapping A-F3. The first pass overstated the asserted fields: G10 does not explicitly claim every slot/epoch/length/vendor-key property, and no deployed updater exists. The defect blocks current assurance promotion, not evidence of an update exploit. |
| B-F2 | **CONFIRMED** | HIGH assurance/correspondence | Current [merkle.rs](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/sphincs-c10/src/merkle.rs:40) uses checked multiplication and rejects remaining indices; committed [TxMerkleSpec.lean](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/extracted/Extracted/TxMerkleSpec.lean:206) proves the older behavior in which depth-1 index 2 aliases index 0. Regeneration fails, and CI paths do not require regeneration on the mirrored Rust source. The current Rust is stricter, so no current product bypass was shown. |
| B-F3 | **CONFIRMED** | HIGH wrong-property proof; consequence narrowed | [UserOpEquivByteLayout.lean](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/extracted/Extracted/UserOpEquivByteLayout.lean:1) calls tooling `compute_user_op_hash` the firmware side. [userop.rs](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/aa/src/userop.rs:503) says that double-keccak value is tooling-only; the secure handler signs `compute_sphincs_digest_v06`, and [PQSmartWallet.sol](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/smart-wallet/src/PQSmartWallet.sol:366) recomputes the SHA-256 digest. An exact Rust/Solidity vector test and a matching handwritten Lean wallet model prevent an inference that implementations currently disagree; the universal source-to-handler-to-contract bridge is missing. |
| B-F4 | **NARROWED** | MED, reduced from HIGH | README’s “proofs after release still apply because formats are frozen” is unsupported by B-F1–F3. A project may ship honestly without FV; what is invalid is retroactively applying a verified claim without binding the exact shipped artifact, source, configuration, extraction, tools, and receipt. |
| B-F5 | **CONFIRMED** | HIGH assurance-gate integrity | The extracted gate rejects only `sorryAx`; its strict parser is not invoked. The canary receipt shows a theorem consuming `unmodeled_assumption_canary : False`, printing it in the closure, while both extracted and FV-lint targets report success. This does not allege a rogue axiom in the restored frozen tree. |
| B-F6 | **CONFIRMED** | HIGH assurance/promotion blocker | Shipped C10 uses `w=8`, `log_w=3`, 43 checksum-free chains and target sum 205. MM45 `WOTS_TW_ES.ec` permits log values 2/4/8, hence `w=4/16/256`, and standard checksum WOTS. Even adding log 3 would produce 43 message plus three checksum digits. The imported theorem has no legal shipped-C10 instantiation. This is not evidence that MM45’s generic theorem is false or that C10 is forgeable. |
| B-F7 | **NARROWED** | MED currently; HIGH if promoted | `SPHINCS_C.ec` is conditional arithmetic over abstract probabilities/bridges, imports paper-model FORS in the capstone, and lacks an exact C10 scheme/forger, bounded-grinder transfer, router ranges and adaptive WOTS/XMSS bridge. Supplemental evidence corrects the first pass: the C10 FORS drafts do carry/grind `R`; they do not blindly retain the paper counter. The open/conditional state is already disclosed in the EasyCrypt README, `AXIOM_STATUS`, and `STATUS`, so this is open research rather than a hidden completed-proof defect. |
| B-F8 | **CONFIRMED** | HIGH assurance-gate integrity | Full success can mean 10/21; `.eco` presence is trusted without causal source/toolchain evidence; only aggregate axiom count is pinned; `dmkey_ll : false` survives; and the gate is unenrolled. Two subclaims are withdrawn: the MM45 digest discrepancy was a packet typo, and byte-identical vendored/standalone sources lack diversity but are not themselves unsound. |
| B-F9 | **CONFIRMED** | MED | [check_protocol_models.py](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/scripts/check_protocol_models.py:75) discards subprocess return codes and accepts count/text results. Supplemental negatives show exit 42 plus expected text passes all families, and a same-count tautological query substitution passes. The unmodified models themselves were not thereby falsified. |
| B-F10 | **NARROWED** | LOW/MED | CryptoVerif proves exact OTP secrecy for a full-space uniform share, while firmware rejects zero. [SplitSecrecy.lean](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/lean/SphincsCVerify/Crypto/SplitSecrecy.lean:35) and G9 already disclose the statistical transfer, uniform/independent entropy premise, and co-resident master-secret residual. The CV header and gate label overstate deployed equivalence; no Rust defect follows. |
| B-F11 | **CONFIRMED** | MED | [THE_CLAIM.md](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/docs/THE_CLAIM.md:35) says all four bridges are transcription-free, while [KONTROL_SCOPING.md](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/docs/KONTROL_SCOPING.md:3) preserves concrete wrappers, role choices and full-frame transcription for affected properties. Several scoped results remain genuine; no wallet bypass was demonstrated. |
| B-F12 | **CONFIRMED** | MED | Prose says the SHA-256 and keccak images are structurally disjoint, but both return 32 bytes. [OffchainBinding.lean](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/lean/SphincsCVerify/Wallet/OffchainBinding.lean:45) explicitly assumes cross-hash separation and concludes inequality or `BreaksHash`. The correct quantitative game depends on whether the target is fixed or both messages vary; it is not automatically a `2^-256` statement. |
| B-F13 | **CONFIRMED** | MED | [run_lean4checker.sh](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/scripts/run_lean4checker.sh:103) checks fresh kernel replay exit status, not project dependency allowlists. The completed 58-module replay strengthens kernel/environment validity but cannot reject a kernel-valid added axiom. Calling it “true axiom closure” conflates distinct checks. |
| B-F14 | **NARROWED** | MED | [check_ledger_consistency.py](/tmp/pqsigner-fv-review-20260715.CP6pgR/PQSigner_OS.frozen/contracts/verification/scripts/check_ledger_consistency.py:157) iterates declared collections, so an empty witness collection passes. Counts and surface inventories are stale. Narrowing: the flagship closure has a separate hard pin; `THREAT_CLAIM_MAP` labels itself a snapshot; and nightly crate-wide Kani enrolls all 148 current harnesses. The mutation manifest, not main Kani enrollment, covers 140 harnesses/19 files and misses eight harnesses in six files; 28/31 mutation groups are default/nightly and three are full-only. |

## Framing corrections after cross-review

My first-pass conclusions change in these material ways:

- B-F1 drops from HIGH to MED because the legacy proof is explicitly fenced in other owner documents and G10 does not claim every field named in my first report.
- B-F3 remains HIGH as a wrong-property/correspondence defect, but I withdraw any implication that Rust and Solidity currently compute different signed digests. The concrete vector and handwritten Lean wallet model are counterevidence to that stronger claim.
- B-F4 drops to MED: FV need not gate every honest release, but retrospective FV language requires exact artifact correspondence.
- B-F7 drops to MED in its current research state. The C10 FORS drafts correctly use `R`, and current owner artifacts already disclose that composition is open.
- B-F8 no longer relies on the MM45 digest mismatch or duplicated-source argument.
- B-F10 drops because current Lean and G9 already preserve the conditioned-distribution and hardware assumptions.
- B-F14 is narrowed because the primary Kani run is broader than the mutation manifest and some flagship minimums are hard-pinned.

Partner A’s framing also requires correction:

- Explicit version labels and production fences do not make a “NEW/current” assurance row about V1 harmless.
- `TxMerkleSpec` is not merely a statement: it genuinely proves the stale extracted behavior, making freshness more—not less—important.
- A green kernel/model run does not answer whether the checked theorem corresponds to current source or whether its exact assumptions are authorized.
- “No V-class soundness hole found” was valid only for the theorem bodies and gates A inspected; it does not survive the extraction and arbitrary-axiom negatives.

## Deduplicated remediation priorities

### FIX NOW

1. **Make the firmware-update claim inventory truthful.**

   Mark every V1 theorem and G10 row `LEGACY/NONSHIPPING`. Resolve V4 versus V6 through the required owner/review process, or explicitly state that no production schema is selected.

   **Acceptance:** CLAUDE, work-todo, assurance case, threat map and theorem metadata agree on exact tag, bytes, version and status. A future selected implementation must prove exact slot, rollback `R`, epoch `E`, lengths, hashes, vendor-key identity and legacy rejection.

2. **Make extracted artifacts demonstrably current.**

   Maintain a total source-symbol→generated-file→theorem registry; require deterministic clean regeneration and byte identity on every mirrored-source change, including `tx/src/**`.

   **Acceptance:** current Tx-Merkle extraction succeeds from a clean checkout; the theorem rejects overflow and residual indices exactly as Rust does; depth-0 index 1, depth-1 index 2 and multiplication-overflow vectors agree; a Rust-only behavior mutation makes CI red.

3. **Prove the digest actually signed.**

   Relabel `UserOpEquivByteLayout` tooling-only. Extract `compute_sphincs_digest_v06` and the parsed handler data flow through the signing argument; connect it to the exact Solidity recomputation.

   **Acceptance:** one current-source theorem spans wire fields → parser → signing digest → contract digest. Every relevant field-flip changes the expected bytes/digest, and Rust/Lean/Solidity differential tests plus freshness negatives pass.

4. **Separate kernel replay from exact closure policy.**

   Keep the completed 58-module checker receipt, but relabel it kernel/environment replay. Add exact per-theorem closure identities, cardinalities and declaration inventory to default and heavy extracted gates.

   **Acceptance:** missing, duplicate and zero closure records fail; a forged unchecked declaration fails replay; a kernel-valid consumed `axiom Evil : False` passes replay but fails closure policy.

5. **Repair protocol/CryptoVerif gate semantics.**

   Preserve subprocess exit status, avoid status-masking pipelines, pin normalized query/lemma identities rather than counts, and support the documented CryptoVerif installations.

   **Acceptance:** exit 42 with expected text, same-count tautology substitution, missing result and duplicate result all fail; the unmodified models pass under both supported library layouts.

6. **Make EasyCrypt full verification fail closed.**

   Split explicitly named partial and full targets. Full means exactly 21/21, zero skips, source-built or causally attested dependencies, exact tool/dependency hashes, and semantic axiom pins.

   **Acceptance:** absent MM45 source, stale/prebuilt-only `.eco`, a count-preserving false axiom, an omitted target or a skip all make full verification fail. A partial run must never print the full-success label.

7. **Replace deletion-tolerant inventories with a required registry.**

   Generate narrative views and counts from immutable required IDs and semantic fields.

   **Acceptance:** deleting a whole collection or mandatory ID fails; generated figures report 58 Lean modules, 148 Kani harnesses/25 files, 31 mutation groups with 28 default and three full-only, and eight unmutated harnesses in six files; all 15 playbooks are represented.

8. **Correct public claim precision.**

   Scope Kontrol results property-by-property; replace “structurally impossible” cross-hash wording with an explicit game; label CryptoVerif’s result ideal/full-space; update EasyCrypt counts and FLAG-2 prose; remove fixed historical counts where generated facts are possible.

   **Acceptance:** public headlines preserve every concrete-wrapper, cited-TCB, computational-break and source-only residual present in the scoped records.

9. **Correct proof-after-release governance.**

   **Acceptance:** either proof evidence gates the release claim, or any retrospective “verified” label binds the exact shipped artifact digest to source, configuration, toolchain, generated artifacts, dependencies, theorem closure and receipt. An honestly unverified release remains possible only if it is labeled as such and separately authorized.

### DEFER

- Full Kani mutation breadth, fresh complete Halmos/Kontrol campaigns and broad corpus expansion should follow gate-integrity repairs. Their eventual acceptance requires current manifests, exact engine/config receipts and explicit boundedness; corpus success must not be described as universal proof.
- Do not rerun expensive top-level EasyCrypt campaigns until the C10 representability gate below is resolved.
- Do not expand LeanLoop-derived claims until its unsolved-negation classifier and KAT configuration receive a real end-to-end negative. The supplied LeanLoop observations are coordinator-supplied; no authorized immutable LeanLoop source tree was available here.

### SIMPLIFY

- Maintain one generated assurance registry and derive the nine combined assurance-surface views from it.
- Keep CryptoVerif’s ideal OTP theorem and a small explicit conditioned-distribution transfer rather than pretending the ideal model is deployed firmware.
- Use a dedicated quantitative cross-function collision/preimage game; do not pursue impossible structural type separation between two 256-bit outputs.
- Prove a frozen display security-policy projection—recipient, amount, chain, selector/value and warnings—not mechanically every signed field.
- Model lifecycle and durable state as small stable transition systems with refinement lemmas, rather than one giant device theorem.

### OPEN RESEARCH

- Exact C10-native WOTS, FORS and top-level EUF-CMA reductions.
- Crash-consistent signing accounting and monotonic state across power loss.
- Exact selected firmware-update schema composed with boot selection and rollback monotonicity.
- Source-to-binary proof pilots only after demonstrating Cortex-M33 and emitted-instruction support on a representative secure function.
- Trusted-display source/policy-to-rendered-output binding and release-artifact provenance. Hardware legibility, touch integrity, SE policy, fuses and physical erase remain outside source proof.

## EasyCrypt disposition

**Disposition: PRESERVE, but pause adaptive/top-level continuation pending a C10 representability gate.**

Useful local work should not be discarded: address separation, FLAG-2 discharge, C10 `R`-based FORS drafts and local combinatorial lemmas retain research value. They must not be promoted as a near-closed concrete C10 proof.

The WOTS mismatch is dispositive:

- production: `w=8`, `log_w=3`, 43 checksum-free chains, target sum 205, u32-BE bounded grinding;
- imported MM45 theorem: `w=4/16/256`, standard checksum WOTS.

No bridge premise can turn an illegal instantiation into a concrete theorem. The required order is therefore:

1. fix the build/provenance gate and semantic pins;
2. define and prove an exact C10 WOTS theory;
3. prove exact C10 FORS routing and the bounded secret-keyed-grinder transfer;
4. only then resume adaptive XMSS and one concrete top-level C10 scheme/game.

If the exact WOTS milestone fails or its cost remains disproportionate, preserve the port as research and abandon the claim of a concrete complete C10 port. This is reasonable because A5 remains disclosed cited-TCB and the main Lean safety conjunct does not consume EUF-CMA.

## Ranked missing/refined assurance surfaces

| Rank | Surface | Security value | Feasibility | TCB reduction | Proof-to-shipping span | Opportunity cost |
|---:|---|---|---|---|---|---|
| 1 | Extraction, closure and receipt meta-assurance | Very high | High | Very high | Enables every source-proof claim | Low |
| 2 | Actual signing correspondence, parser to contract digest | Very high | Medium | High | Wire/source → signer → on-chain validation | Medium |
| 3 | Release artifact and source-to-binary provenance | Very high | Medium/low | High | Source → ELF/config → signed release | High |
| 4 | Durable generated/charged/released signing state | Very high | Medium/low | High | Model → persistent state → user-visible release | High |
| 5 | Selected firmware update, rollback and boot composition | High | Medium | High | Signed manifest → boot choice → monotonic rollback | High |
| 6 | Frozen trusted-display policy projection | High | Medium | Medium | Signed intent → rendered confirmation; hardware residual | Medium |
| 7 | Current Kani/Kontrol/Halmos mutation coverage | Medium/high | High | Medium | Bounded implementation evidence only | Low/medium |
| 8 | Seed-split transfer and cross-hash game cleanup | Medium | High | Medium | Architecture/model claim; entropy hardware remains | Low |
| 9 | Full C10-native cryptographic reduction | High in isolation | Low | Medium | Weak until exact source/binary bridges exist | Very high |

Proof-theater red lines are explicit: no corpus-to-universal promotion, no giant lifecycle theorem over unstable state, no display-every-field requirement, and no binary-verification claim until the tool actually supports Cortex-M33 emitted instructions.

## Honest residual

### Strong attacks that failed

- No current rogue axiom or `sorry` was found in the restored frozen Lean tree. Supplied build/audit receipts were green, and fresh independent replay accepted all 58 modules.
- No vacuity, inconsistency or reversed game inequality was demonstrated in the flagship `theft_free` theorem or its present closure.
- Current Rust and Solidity actual UserOperation digest logic appear aligned: the concrete Rust-generated vector validates in Solidity, and the handwritten Lean wallet model represents that digest. The defect is missing universal/current-source correspondence.
- Current Rust Tx-Merkle code is stricter than the stale extracted proof. No current acceptance bypass was demonstrated.
- The unmodified ProVerif/Tamarin/CryptoVerif models were not falsified; the reproduced failures concern harness truthfulness and claim scope.
- MM45’s generic WOTS theorem was not shown false, and no C10 forgery was produced. The failure is representability and top-level applicability.
- No Kontrol wallet bypass, practical SHA/keccak cross-collision, seed-share recovery, chip extraction or firmware-update exploit was demonstrated.

### Unreviewed or unexecuted surfaces

- No successful full Aeneas regeneration; the focused Tx-Merkle regeneration failed.
- No fresh full Kani campaign, full mutation campaign, Halmos/Kontrol campaign, Miri/fuzz campaign, constant-time/assembly audit or SCA/FI campaign.
- No binary, boot ROM, linker, Cortex-M33 emitted-instruction, silicon, SE configuration, TRNG, fuse, persistent-flash atomicity or trusted-display hardware evidence.
- No release candidate, ELF, reproducible build, signing-key custody, release-signature, branch-protection or distribution evidence.
- No clean 21/21 EasyCrypt rebuild was produced; the corrected run is a supplied receipt and remains 10/21.
- No external paper or live repository was used to fill gaps.

### Execution and provenance limits

This report rests on immutable source inspection, independently repeated hashes/censuses, and coordinator-supplied execution receipts whose scripts and relevant outputs were inspected. It does not convert host execution into universal proof or source proof into binary/hardware authority. The frozen PQ tree includes tracked and untracked snapshot content; the packet’s aggregate content digest recipe was not supplied, so the independently reproducible HEAD, tracked-diff and per-file inventory checks are reported separately.

The surviving NO-GOs are therefore precise: **the current assurance case cannot be promoted as current, exact, closed or shipment-authorizing.** They are not a claim that the frozen product has already been exploited or that every contained theorem is invalid.