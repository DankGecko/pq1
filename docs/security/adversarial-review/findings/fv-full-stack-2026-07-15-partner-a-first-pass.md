work-todo.md sharpens F3 decisively — and reveals a *third* version: work-todo.md:1256-1259 says the legacy 75-B `PQFW_V1` is bench-only, Draft-0.9's `PQFW_V4` (80-B) "is **not** the current replacement," and the current direction is `PQFW_V6` (121-B). So the frozen tree's own normative docs disagree on the authoritative FW-update format (FV+AxiomCheck=V1 · CLAUDE.md=V4 · work-todo=V4-superseded→V6), and the only FV coverage is over the one format CLAUDE.md calls "not authoritative." All disclosed at leaf level, firmware-surface, whole backend is an open ship-blocker → **F3 = LOW** (doc-currency + cross-doc version inconsistency), with a disclosed G3 coverage note. STATUS.md carries no FW/EasyCrypt overclaim.

I have everything required. Digests re-verified clean. Here is my complete first-pass report.

---

```markdown
---
surface: fv
run_date: 2026-07-15
reviewer_role: Partner A
reviewer_identity: Claude Code Opus 4.8 (claude-opus-4-8)
effort: max (ultracode label unavailable in Claude Code 2.1.209; coordinator-recorded fallback per workflow §7)
backend: Claude Code 2.1.209
scope: The FV assurance case itself — claim inventory (THE_CLAIM/ASSURANCE_CASE/AXIOM_STATUS), the Lean theft_free closure, the EasyCrypt SPHINCS+C EUF-CMA port (21 files), the §33 Aeneas-extracted tree, protocol-model + gate-enforcement wiring, and firmware-version provenance. V1–V11 / G1–G5 catalog.
stage: architecture + implementation-evidence (document/research-only)
frozen_identity: PQSigner_OS.frozen @ ddc7cefc35cb54e324dac94330c6ee86f9383c90 (branch fix/sweep-2026-07-14-findings)
status: open
---

# Adversarial-review findings — FV assurance case — 2026-07-15

## Summary

**7 findings: 4 confirmed-real (all provenance/enforcement/currency class — none is a soundness hole in `theft_free`), 3 doc-drift; 0 false-positive.** One-line verdict: **the FV assurance *architecture* is coherent and unusually honest — I found no V1–V11 vacuity hole and reproduced no unsoundness — but its *provenance layer* overstates reproducibility.** The single strongest attack: the `verify-easycrypt` gate that is cited *by two of `theft_free`'s own axioms* green-lights while skipping the exact files carrying the one unconditional EasyCrypt result and the capstone (F1). Secondary: the `#print axioms` completeness backstop is not freshly established on the frozen content (F2), and the firmware-update FV covers a format the tree's own docs disagree about (F3).

**Provenance of this pass:** I **read source and inspected orchestrator-supplied receipts**; I did **not** execute `lake`/`easycrypt`/`halmos`/`kontrol`/`lean4checker`/`make verify-*` myself (the sandbox blocks `git` and unrestricted shell; no EasyCrypt/Lean toolchain). Every "gate does X" statement is either a source read of the driver script or a classified orchestrator receipt, labelled as such. A source-only pass is G4-limited: I cannot see a smuggled `native_decide`/`@[extern]`/`admit` that a real run would surface.

## Reviewer and frozen-target receipt

- **Reviewer:** Claude Code Opus 4.8 (`claude-opus-4-8`), effort `max`, backend Claude Code 2.1.209, **Partner A**. The workflow specifies Partner A at `ultracode`; that label is not exposed by the installed CLI, and the coordinator recorded the `max` fallback before launch (workflow §7 permits a recorded substitution).
- **Neutral counterpart disclosure (given before this pass):** "GPT-5.6 SOL at ultra effort is independently reviewing this same frozen packet. Do not infer its verdict or defer to it." I did not read, seek, or infer the other reviewer's output (`partner-b-first-pass.md` is present in the packet root; I did not open it).
- **Initial identity (before reading):** HEAD `ddc7cefc35cb54e324dac94330c6ee86f9383c90`; branch `fix/sweep-2026-07-14-findings` (via `.git/HEAD` + `.git/refs`, since `git` is blocked); CLAUDE.md `65cf9b10…301b4`, planning-and-review-workflow.md `04d74fcd…8688`, fv-adversarial-review-playbook.md `254e4178…6221` (all three = packet). Sibling trees: c10-eufcma-port `70974e90…`, FV-SPHINCSPLUS-EC `a28e4c53…`, FV-XMSS-EC `fa90ebc2…`, MM45_ROOT.frozen = symlinks to the two MM45 trees — all = packet.
- **Final identity (immediately before reporting):** re-hashed the three normative docs → **identical**; HEAD ref → `ddc7cefc…` **identical**. Frozen trees are mounted read-only (`dr-xr-xr-x`).
- **Drift result:** **NO DRIFT.**
- **Aggregate-digest caveat (honest):** I could **not** independently reproduce the packet's aggregate content digest `ad0de135…aa10d`. Its recipe is not in the frozen packet (it lives in the excluded `/home/nicola/repos` orchestration tree), and the sandbox blocks the `find|xargs|sha256sum` pipeline. My tamper-evidence is therefore: HEAD×4 + branch + 3 normative-doc SHA-256 + the read-only mount — not a recomputed `ad0de135…`.
- **Plan/spec/prompt digests:** neutral packet `/tmp/pqsigner-fv-review-20260715.CP6pgR/neutral-review-packet.md`; my role prompt `partner-a-prompt.md`. (Not re-hashed; supplied by orchestrator.)
- **Stage and non-goals:** document/research-only FV assurance review at architecture + implementation-evidence stages. **Non-goals:** no implementation, merge, shipment, hardware mutation, release signing, or external write. Merge and production-shipment verdicts are **unavailable** (nothing is being merged/shipped in this review).

## Commands, environment, and evidence level

| Command / inspection | Environment + cfg | Result / receipt | Evidence level | Executed? |
|---|---|---|---|---|
| `sha256sum` 3 normative docs (×2, start+end) | frozen tree | all 3 = packet, no drift | source | **RUN (me)** |
| `.git/HEAD`, `.git/refs/…` for all 4 trees | frozen trees | all HEADs = packet | source | **RUN (me)** |
| `git rev-parse`, `find\|xargs sha256sum` | — | **DENIED** by sandbox (git + find pipelines blocked) | — | BLOCKED |
| Read: THE_CLAIM / ASSURANCE_CASE / AXIOM_STATUS / EUFCMA.lean / SPHINCS_C.ec / WOTS_C_EmbDischarge.ec / check_easycrypt.sh / run_lean4checker.sh / gate_enforcement.json / STATUS.md / work-todo.md / AxiomCheck.lean / TxMerkleSpec.lean | frozen tree | see Findings | source | **RUN (me)** |
| Glob: `SphincsCVerify/**/*.lean`; `easycrypt/drafts/*.ec`; MM45 `.eco` | frozen trees | 58 Lean modules; 21 `.ec`; **no `.eco` in FV-SPHINCSPLUS-EC.frozen** | source | **RUN (me)** |
| `make verify-build/audit/ledger-consistency/fv-lints` | exec copy | exit 0; 17 axioms / 18 closures / 5 pins / 5 witnesses; 0 tactic `sorry` | model | **orchestrator receipt** (I re-derived the 17/18/5/5 counts from AXIOM_STATUS.json — they match) |
| `make verify-proof-mutation` (default 8) | exec copy | exit 0, expected accept/reject | model | **orchestrator receipt** (not re-run) |
| `make verify-extracted / verify-extract-differential` | exec copy | exit 0; no `sorryAx` on project closures; 6 `signed_preimage` + 55 `format_decimal` vectors | model | **orchestrator receipt** |
| `make verify-easycrypt-pins`; `verify-forsc-margin` | exec copy | 8 axioms + 2 admitted files; ~130.6-bit **work factor**, ~2⁻²·⁶ advantage @ q_h=2¹²⁸ | model | **orchestrator receipt** (I confirmed the 8/2 pins from `check_easycrypt.sh:64-68`) |
| `MM45_ROOT=… make verify-easycrypt` | exec copy | exit 0, **10/21 compiled, 11 MM45-chain SKIPPED** (WOTS, SPHINCS_C.ec, XMSSMT_C_Bridge.ec) | model | **orchestrator receipt** — see F1 |
| `make verify-gate-enforcement` | exec copy | exit 0 over 21-entry manifest | model | **orchestrator receipt** — see F1/F4 |
| `make verify-protocol-models` | exec copy | ProVerif/Tamarin pass; **nonzero at CryptoVerif** (`…/checkct/libexec/default.cvl` absent); manual `-lib …/bin/default` → `RESULT Proved secrecy of seed` | model | **orchestrator receipt** — see F4 |
| `make verify-lean4checker` | exec copy | **PENDING at freeze** (per-module `--fresh` replay began) | — | **orchestrator receipt: NOT COMPLETED** — see F2 |
| `make extract-tx-merkle` (regen) | exec copy | **Error 1** — Aeneas "Unreachable" on `verify_proof`, partial Lean file | model | **orchestrator receipt** (`tx-merkle-regen.log`) |
| lean4checker-style replay of extracted tree | exec copy | `Aeneas/Std/Slice.lean`, `StringIter` "uses `sorry`" (stdlib, off project paths) | model | **orchestrator receipt** (`extracted-unmodeled-assumption-canary.log`) |

Tool identities I can establish: Claude Code 2.1.209 (mine). From receipts (not my execution): Codex CLI 0.144.4, CryptoVerif 2.12, halmos 0.3.4.dev, kontrol 1.0.247/K v7.1.333, EasyCrypt r2026.02 + Alt-Ergo 2.6.0, Lean v4.22.0. I did not fabricate versions for tools I did not run.

## Stage-specific recommendations

Recommendations for frozen digest `ddc7cefc…`, not authority to implement/merge/ship/mutate.

| Stage | Recommendation | Exact subject | Evidence and remaining gate |
|---|---|---|---|
| Architecture | **APPROVE WITH RED-LINES** | FV assurance case @ `ddc7cefc…` | The claim decomposition and cited-TCB structure are sound (no V-class hole found). Red-lines are **evidence-fidelity**, not architecture-soundness: F1 (EasyCrypt gate must not green-light while skipping load-bearing files), F2 (lean4checker backstop currency), F3 (FW-update version-consistency across docs). |
| Implementation (evidence fidelity) | **APPROVE WITH RED-LINES** | the executed FV gates | F1 + F4 are gate-wiring defects; F1/F2 mean the EasyCrypt and lean4checker evidence must **not** be presented as "reproduced from the frozen packet" until the gate compiles the MM45-chain and a fresh lean4checker over 58 modules completes. |
| Merge | **unavailable** | — | No implementation/PR under review; this is a document/research-only FV pass. |
| Production shipment | **unavailable — out of scope for this review** | — | Not adjudicated here; separately, CLAUDE.md ship-blockers (OPTIGA S-1/2/3, rollback backend) are independently open. |

## Findings

### F1 — `verify-easycrypt` green-lights while skipping the load-bearing WOTS+C leg and the capstone; the ledger prose it backs overstates reproducibility
- **Status:** 🔲 OPEN
- **Mode / severity:** G1 (gate-enforcement) + G4 (provenance) · **MED**
- **Location / stable anchor:** `contracts/verification/scripts/check_easycrypt.sh:164-194` (skip logic) vs `contracts/verification/docs/AXIOM_STATUS.json` A5-EUFCMA (`:453`) / A5-ITSR (`:482`) + `Makefile:112-114` ("compiles EVERY .ec AS A TARGET (mandatory)"); load-bearing target `easycrypt/drafts/WOTS_C_EmbDischarge.ec:174` (`D1_MEUFNACMA_WOTSC_MM45_embthfc`) + capstone `easycrypt/drafts/SPHINCS_C.ec:154`.
- **Mechanism:** When `SPHINCS_PLUS.eco` is absent and `FORCE_MM45≠1`, the gate skips every MM45-chain draft (`WOTS_C_*`, `SPHINCS_C`, `XMSSMT_C_*`) and **exits OK**. `FV-SPHINCSPLUS-EC.frozen` ships `proofs/SPHINCS_PLUS.ec` but **no `.eco`**, and the script's own header (`:30-46`) states that `.eco` "CANNOT be built fresh on this box AT ALL" (needs z3 4.13.x / MM45's docker). So on the frozen packet the gate *always* skips the 11 files — including the **only unconditional result in the entire port** (`D1_MEUFNACMA_WOTSC_MM45_embthfc`, the WOTS+C leg the README calls "unconditional… 0 admit") and the capstone. The two `theft_free` axioms (A5-EUFCMA, A5-ITSR) cite this development as their spot-checkable evidence; the gate's stated purpose (script `:5-10`) is to make that evidence checkable "per STATUS.md rule #1."
- **Prerequisites:** Any reviewer reproducing from the frozen packet without MM45's exact docker/z3-4.13.x toolchain — i.e. the packet's own execution environment (the supplied receipt confirms 10/21 compiled, 11 skipped, even with an MM45 tree present).
- **Consequence:** **Assurance/provenance, not funds.** `theft_free` is **not** weakened — A5 is cited-TCB regardless and the kernel proof does not consume the EasyCrypt. But the claim that the WOTS+C/capstone legs are independently checkable from this packet is false: they are author-attested + text-swept (`ec_sweep.py` counts `admit`/`axiom` tokens) but **not compiled** here, and EasyCrypt `require` does not re-verify (README `:14-17`). Compounding it, **`verify-easycrypt` is absent from `scripts/gate_enforcement.json`** (0 entries), so the G1 lint tracks nothing about it — unlike `checkct`/`verify-bytecode`, which at least carry a `local_documented` entry.
- **Introduced here?:** UNKNOWN (subsystem vendored 2026-07-10; the skip logic predates the frozen HEAD).
- **Failure-path trace:** frozen packet → `SPHINCS_PLUS.eco` absent (forced) → `skip_sp=1` → the SP-dependent set (computed from the require graph, `:144-163`) is skipped loudly → `fail=0` → `=== verify-easycrypt OK (stdlib chain; 11 MM45-chain SKIPPED) ===`, exit 0. A green line the ledger prose reads as "every file compiled."
- **PoC (falsifiable):** (1) `SPHINCS_C.ec:124` + `WOTS_C_EmbDischarge.ec:136` = `require import SPHINCS_PLUS` ⇒ both are in the skip set. (2) `Glob '**/*.eco'` on `FV-SPHINCSPLUS-EC.frozen` = empty. (3) `check_easycrypt.sh:165` gates the skip on that `.eco`. (4) Orchestrator receipt: "10 of 21… 11 MM45-chain SKIPPED." (5) `AXIOM_STATUS.json:482` says the gate "compiles EVERY .ec AS A TARGET (mandatory)" with no skip caveat. Falsified if a fresh `FORCE_MM45=1 make verify-easycrypt` over the frozen MM45 tree exits 0 with the WOTS_C_* / SPHINCS_C files reported `ok`.
- **Evidence provenance:** source read of the driver + Makefile + ledger + `.ec` files (me); the 10/21 outcome is an orchestrator receipt (I did not run EasyCrypt).
- **Stage impact:** implementation-evidence / provenance (red-line); not merge/shipment.
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW (provenance)
- **Required correction:** either (a) vendor a hash-pinned prebuilt `SPHINCS_PLUS.eco` (or a CI job matching MM45's toolchain) so the MM45-chain actually compiles from the packet, **or** (b) correct `AXIOM_STATUS.json` A5-EUFCMA/A5-ITSR + `Makefile` to state that on a box without MM45's z3-4.13.x the gate verifies **only** the stdlib chain and the WOTS+C/capstone legs are author-attested-not-reproduced. Add a `local_documented` entry for `verify-easycrypt` to `gate_enforcement.json`. Acceptance: the two axiom entries' "compiles EVERY .ec (mandatory)" prose matches what the gate does in the reproduction environment.

### F2 — The `#print axioms` completeness backstop (lean4checker) is not established on the frozen content; the one doc claiming completion cites a stale receipt
- **Status:** 🔲 OPEN
- **Mode / severity:** G4 (tool-trust currency) · **MED**
- **Location / stable anchor:** orchestrator receipt "verify-lean4checker … **still running when this packet froze** … treat it as pending"; `THE_CLAIM.md:62` ("kernel re-check ACCEPTED every declaration across all **55 modules**"); `scripts/run_lean4checker.sh:103` (dynamic module discovery); `Glob SphincsCVerify/**/*.lean` = **58 modules**.
- **Mechanism:** Lean v4.22.0 is inside the pre-#8842 `collectAxioms` under-report window (disclosed, `run_lean4checker.sh:8-13`), so `verify-audit`/`#print axioms` **can under-report** the true closure. The sole discharge is `verify-lean4checker` (external kernel replay). **On the frozen content that discharge is PENDING** (never completed in this review). `THE_CLAIM.md:62` discharges the caveat by citing a 2026-07-02 completion "across all 55 modules"; the frozen tree now has 58 `SphincsCVerify` modules, and the runner enumerates modules dynamically — so the cited run covered a strictly smaller module set than the frozen tree.
- **Prerequisites:** Trusting "the 11-axiom `theft_free` closure is a kernel fact, not a `#print` artifact" from the frozen packet.
- **Consequence:** The headline claim "closure is not a `#print`-only artifact" (`THE_CLAIM.md:62`) is **not currently backed** on the frozen bytes. **Tempering (checked):** `STATUS.md:179` lists lean4checker only as "targets exist" (**not** completed) and `:180` says "re-run = compute" — so the live status ledger does **not** propagate the completion overclaim; it is contained to `THE_CLAIM.md`. The 3 delta modules are most plausibly corollary-scope (`Crypto/Quantitative`, `Wallet/CreditLedger`, `Crypto/SplitSecrecy`, `Wallet/UpgradeSafety`), not `theft_free`'s own 11-name closure — so this is a currency gap, not demonstrated unsoundness.
- **Introduced here?:** NO (module count grows over time; the doc figure is a point-in-time receipt).
- **Failure-path trace:** frozen freeze → fresh lean4checker started, **not finished** → no receipt → the under-report caveat's discharge rests on a 2026-07-02 run over 55 modules ≠ the 58-module frozen tree.
- **PoC (falsifiable):** `THE_CLAIM.md:62` "55 modules" vs 58 files under `SphincsCVerify/`; packet "treat it as pending." Falsified by a completed `make verify-lean4checker` over the frozen tree printing "ACCEPTED every declaration across 58 module(s)."
- **Evidence provenance:** source read (me) + orchestrator PENDING receipt. **I cannot run lean4checker (no toolchain) — G4 execution ceiling.**
- **Stage impact:** implementation-evidence / provenance (red-line).
- **Disposition:** CONFIRMED_REAL (currency)
- **Classification:** FIX NOW (rerun) + KEEP (the caveat is honestly documented)
- **Required correction:** complete `verify-lean4checker` over the frozen 58-module tree and update `THE_CLAIM.md:62` to the real count (or generalise "every module" and drop the fixed "55"). Bonus: fix the umbrella-replay `_proof_` collision (`run_lean4checker.sh:86-100`) so it is a single-pass CI-able gate rather than a ~40-60 min manual sweep. Acceptance: a dated completed receipt over the frozen module set.

### F3 — Firmware-update FV covers `PQFW_V1`, but the tree's own normative docs disagree on the authoritative format; the assurance case cites a superseded CLAUDE.md phrase
- **Status:** 🔲 OPEN
- **Mode / severity:** G2 (cited-fact drift) + G3 (coverage), both **disclosed** · **LOW**
- **Location / stable anchor:** `ASSURANCE_CASE.md:335` (G10 cites 'the CLAUDE.md "frozen 75-B preimage"'); `extracted/Extracted/AxiomCheck.lean:118-122` + `FwManifestSpec` (FV over the "frozen 75-B `PQFW_V1` preimage"); `CLAUDE.md` FW-update paragraph ("the exact 80-byte … `PQFW_V4` … preimage … The legacy 75-byte V1 format is not authoritative"); `work-todo.md:1256-1259` ("Draft 0.9 proposed manifest-v4/`PQFW_V4`; it is **not** the current replacement" → `PQFW_V6`, 121-byte).
- **Mechanism:** Three different FW-update preimage formats are named as the reference across the frozen tree's own docs: the **FV proves over V1 (75-B)**, **CLAUDE.md names V4 (80-B) as the frozen target and calls V1 "not authoritative,"** and **work-todo.md says V4 is superseded and the direction is V6 (121-B)**. G10's cited basis — a CLAUDE.md "frozen 75-B preimage" phrase — no longer exists in current CLAUDE.md (which moved to V4). And `layout_domain_tag_prefix` proves cross-protocol separation for the literal tag `PQFW_V1`, which the shipping design does not use.
- **Prerequisites:** Reading G10 as evidence for the *shipping* firmware-update integrity.
- **Consequence:** Documentation coherence / assurance currency only. **Not** load-bearing for `theft_free` (firmware surface, off the on-chain tree); the whole rollback backend is an open ship-blocker (CLAUDE.md; `work-todo.md:1142-1148`), and every layer *labels* its version (AxiomCheck:119, ASSURANCE_CASE:340). `STATUS.md` carries no "firmware-update proven/shipping-covered" row — so there is no shipping overclaim, which is why this is LOW, not a "retired-version-as-shipping-evidence" MED.
- **Introduced here?:** NO (V1 FV predates the V4/V6 design moves; the docs drifted apart).
- **Failure-path trace:** design moves V1→V4→V6 across commits; the V1 FV + its ASSURANCE_CASE anchor were not re-scoped, leaving a stale cross-reference + a coverage gap over the current target.
- **PoC (falsifiable):** the four anchors above name V1 / V4 / V6 for the same "firmware-update signed preimage." Falsified if current CLAUDE.md still contains a "frozen 75-B preimage" phrase (it does not — it says 80-B V4) or if G10 is re-proved over the shipping format.
- **Evidence provenance:** source read (me), cross-document.
- **Stage impact:** architecture-adjacent (coverage/currency); documentation.
- **Disposition:** CONFIRMED_REAL (doc-currency + cross-doc inconsistency)
- **Classification:** FIX NOW (cheap doc re-scope) + OPEN RESEARCH (re-prove over the shipping format once V4/V6 is chosen)
- **Required correction:** in `ASSURANCE_CASE.md` G10, replace the superseded CLAUDE.md citation with "legacy `PQFW_V1` (75-B), bench-only — does **not** cover the shipping V4/V6 target," and reconcile CLAUDE.md (V4) with work-todo.md (V6) so one authoritative FW-update format is named. Acceptance: all four surfaces name the same authoritative format, or G10 is explicitly scoped as legacy.

### F4 — `cryptoverif` make target hard-codes the nix `libexec/default` lib layout; breaks against the opam-checkct `bin/default` layout, and its model surface is unpoliced
- **Status:** 🔲 OPEN
- **Mode / severity:** G1/G4 (gate wiring + tool resolution) · **LOW**
- **Location / stable anchor:** `Makefile:4122-4123` (`p=$(dirname $(dirname $(readlink -f $(command -v cryptoverif)))); cryptoverif -lib $$p/libexec/default …`); `scripts/gate_enforcement.json:100-103` (`verify-protocol-models` polices only `proverif/**` + `tamarin/**`, omits `cryptoverif/**`).
- **Mechanism:** The target derives the CryptoVerif library path from the binary location assuming the nix `.../libexec/default` layout. When `cryptoverif` resolves to the opam `checkct` switch, the lib lives at `.../bin/default`, so `-lib …/libexec/default` → CryptoVerif appends `.cvl` → `…/checkct/libexec/default.cvl`, which does not exist → nonzero exit. Separately, no gate's `polices_paths` covers `contracts/verification/cryptoverif/**`, so an edit to `seed_split_secrecy.cv` triggers nothing.
- **Prerequisites:** Running the default `make verify-protocol-models` on a box where `cryptoverif` comes from the checkct opam switch rather than nix.
- **Consequence:** Local gate breakage only. The **property holds** — the orchestrator's manual `-lib …/bin/default` invocation printed `RESULT Proved secrecy of seed` / `All queries proved.` CryptoVerif is documented local-only (`Makefile:4136`; CI subset = `proverif,tamarin`), so CI is unaffected; the defect is a wrong path assumption + a manifest coverage gap.
- **Introduced here?:** UNKNOWN.
- **Failure-path trace:** `command -v cryptoverif` → opam-checkct bin → `dirname dirname` → switch root → `-lib …/libexec/default` → CVL not found → exit 1 (even though the model proves under the correct `bin/default`).
- **PoC (falsifiable):** orchestrator receipt (nonzero at CryptoVerif; manual `bin/default` → proved) + `Makefile:4122-4123` + `gate_enforcement.json:100-103`. Falsified if the target resolves the lib path for both nix and opam layouts.
- **Evidence provenance:** source read (me) + orchestrator receipt (I did not run CryptoVerif).
- **Stage impact:** implementation-evidence (LOW).
- **Disposition:** CONFIRMED_REAL
- **Classification:** FIX NOW (small)
- **Required correction:** probe both `libexec/default` and `bin/default` (or query `cryptoverif -help`/a known lib env), and add `contracts/verification/cryptoverif/**` to `verify-protocol-models` `polices_paths`. Acceptance: `make verify-protocol-models` exits 0 with CryptoVerif on either install layout.

### F5 — EasyCrypt README pins "7 axioms / four structural constraints on `g`"; the gate and the live sweep pin 8 (the fifth, `uniq_g`)
- **Status:** 🔲 OPEN
- **Mode / severity:** doc-drift · **LOW**
- **Location / stable anchor:** `easycrypt/README.md:57` ("**7 axioms** … four structural constraints on `g`") vs `scripts/check_easycrypt.sh:68` (`EXPECTED_TOTAL_AXIOMS=8`, listing `size_g,eqiks_g,neqisvs_g,rng_g,uniq_g`) + `FORS_C10.ec:166-192` (five `g` axioms incl. `uniq_g`) + orchestrator `verify-easycrypt-pins` receipt ("eight axioms").
- **Mechanism:** `uniq_g` was added in the 2026-07-10b review (the F1 fix that excluded the vacuous `nseq k z` model, per `AXIOM_STATUS.json:482`); the README's count predates it.
- **Consequence:** A reader trusting the README under-counts the port's live axiom base by one and misses that a real vacuity was found+fixed there. No soundness impact.
- **PoC:** README "7" vs gate "8" vs `FORS_C10.ec` five `g`-axioms. **Disposition:** CONFIRMED_REAL. **Classification:** FIX NOW (one line). **Required correction:** README → "8 axioms … five structural constraints on `g` (incl. `uniq_g`)."

### F6 — `WOTS_C_EmbDischarge.ec` header describes FLAG-2 as an open standing hypothesis; the theorem below discharges it
- **Status:** 🔲 OPEN
- **Mode / severity:** doc-drift (within-file) · **LOW**
- **Location / stable anchor:** `WOTS_C_EmbDischarge.ec:27-122` (header: FLAG-2 "NOT reachable… stays an unproven-but-satisfiable hypothesis") vs `:174-195` (theorem takes **no** `emb_disj_wgpidxs` premise; proof calls `emb_disj_wgpidxs_holds`) + `SPHINCS_C.ec:56-62` + README `:49` (both: FLAG-2 discharged 2026-07-09 by the concrete rebase).
- **Mechanism:** The header narrative predates the 2026-07-09 rebase that defined `emb_tw` on the concrete `FSSLXMTWES.WTWES` instance and proved `emb_disj_wgpidxs_holds`; it was not updated when the theorem became unconditional.
- **Consequence:** The file's own prose contradicts the theorem it heads; a reader could conclude the WOTS+C leg is still one-hypothesis-conditional. The compiled theorem is what matters (unconditional modulo `c ≤ p_tgts` + the definitional encode-compat identity). No soundness impact. **PoC:** header vs theorem signature. **Disposition:** CONFIRMED_REAL. **Classification:** FIX NOW (align header to the post-rebase state).

### F7 — The packet's `MM45_ROOT=` env prefix is inert against the frozen gate (which reads `EC_FV_ROOT`)
- **Status:** 🔲 OPEN
- **Mode / severity:** provenance-of-receipt · **LOW**
- **Location / stable anchor:** `check_easycrypt.sh:59` (`EC_FV_ROOT="${EC_FV_ROOT:-$HOME/repos/c10-eufcma-port}"`) + `README.md:39` (documents `EC_FV_ROOT`), with **no** `MM45_ROOT` reference in `Makefile` or script; packet fresh-run command used `MM45_ROOT=/…/MM45_ROOT.frozen`.
- **Mechanism:** The frozen gate reads `EC_FV_ROOT`, not `MM45_ROOT`. Setting `MM45_ROOT` leaves `EC_FV_ROOT` at its default `$HOME/repos/c10-eufcma-port` (the excluded live repo). Since the run reached the compile loop and skipped (rather than "SKIP: MM45 reference proofs not found"), it most likely used the **live** `~/repos` MM45 clones, not `MM45_ROOT.frozen`.
- **Consequence:** The packet's belief that the EasyCrypt gate ran against the frozen MM45 tree is unverified; it probably ran against the live (mutable, excluded) repo. **Outcome-invariant** — both lack a buildable `SPHINCS_PLUS.eco`, so the MM45-chain skips either way — but the receipt's provenance is weaker than stated.
- **PoC:** `check_easycrypt.sh:59` reads `EC_FV_ROOT`; `Grep MM45_ROOT Makefile` = no matches. **Disposition:** CONFIRMED_REAL (receipt-provenance). **Classification:** FIX NOW (packet should set `EC_FV_ROOT=/…/MM45_ROOT.frozen`). I could not verify the live repo's contents (correctly excluded).

## Suspicions (unverified — no PoC)

- **Two different FORS+C bit-numbers.** `Crypto/Quantitative.lean` / ASSURANCE_CASE:268 cite "FORS+C 143" bits; `forsc_grinding_margin.py` reports "130.6-bit **work factor**." Likely different objects (min-arithmetic over cited upstream inputs vs binomial-mixture query-work), both "cited, not re-derived," but I did not reconcile them. Worth an explicit note in one place that they measure different things.
- **The ~2⁻²·⁶ advantage @ q_h=2¹²⁸** (A5-ITSR, receipt) is close to the security floor and, per the F3-2026-07-10b correction, there is "no operational cap on offline hashing, so no `Q_H_CAP` is asserted." Whether the C10 params retain a comfortable margin against a well-resourced offline adversary is an EasyCrypt-quantitative question the port explicitly leaves open — I could not settle it source-only.
- **`emb_disj_wgpidxs_holds` / `emb_disj_concrete` genuinely close 0-admit** under a real prover: I read the source (no `admit` tokens) but the file is in the un-compilable MM45-chain, so I cannot confirm the proof scripts actually close (F1's ceiling applied to the substance).

## Invariant and failure-path trace

- **Soundness of `theft_free` (V1–V11 walk, source-only):** conjunct-1 (safety) closure = A2 + A3.1 + A5×4 + kernel; A1/A4 are non-consumed `have`-markers (deleting them leaves it proven — the proof-mutation gate asserts this, receipt). **V1/V6:** the C9 witness set (`combinedCapInvariant_empty/_initialised`, `H_adrs/H_sib_dischargeable`, `execute_step_satisfiable`) is present and pinned. **V2:** A2 (`entrypoint_honest`) is a self-disclosed tautology over `handleOp` — carries a name, not strength; the genuine assumption is the un-discharged deployed-EntryPoint bytecode. **V7:** the ex-`False` axioms (EUF-CMA, `sha256_injective`) were restated to opaque `BreaksHash` / `∨ BreaksHash` — verified at source (EUFCMA.lean:172-178; A5-collision entry). **V8:** A3.1 is honestly tier-C (corpus-KAT, not ∀-symbolic) — disclosed, not hidden. I found **no** V-class hole; this is a source-read verdict with the G4 ceiling below.
- **EUF-CMA "resolved" (highest-scrutiny):** confirmed at source — the axiom concludes opaque `BreaksHash` (never `False`), `isForgery` carries `KeyHistory` (empty-transcript detonator unformable), guard lemmas + the P9 non-operational ceiling are exemplarily documented (EUFCMA.lean:100-171). **I cannot confirm "the old detonator no longer type-checks" without running Lean — G4 ceiling.**
- **Extracted tree:** the Aeneas `Std.Slice`/`StringIter` `sorry` is **disclosed** (`AxiomCheck.lean:4-7`, off project proof paths) — not a hidden trust item. The `verify_proof` extraction regen-fail (`tx-merkle-regen.log`) is over a **statement-only** spec (`TxMerkleSpec.lean:1`) — no proven theorem rests on the stale extraction; a WIP freshness gap, not a stale proof.
- **Power-cut / downgrade / resource paths:** out of scope for the on-chain FV tree (these are firmware invariants #2/#3/#4 + rollback, with zero Lean coverage by design — see Honest Residual).

## Cross-adjudication

Not performed (mutually-withheld first pass). To be completed in a separate artifact after both first-pass reports freeze.

## Honest residual (the run is INVALID without this)

**1. What I tried to break and COULDN'T.**
- **`theft_free` soundness (V1–V11).** Strongest failed attack: hunt for a re-detonating EUF-CMA/`False` path. The axiom concludes opaque `BreaksHash`, `isForgery` is key-bound, and the ledger pre-discloses every vacuity class (A2 tautology, A3.1 corpus, A4 marker, P9 non-operational). No hole — but source-only (G4).
- **The WOTS+C reduction math.** `D1_MEUFNACMA_WOTSC_MM45_embthfc` bounds the real game by MM45's real `M_EUF_GCMA_WOTSTWESNPRF` + `S_TCR_C`, sound direction, 0 `admit` tokens, FLAG-1 a legitimate definitional specialization. I could not fault the reduction on paper; I could only show it is **unreproducible from the packet** (F1), not wrong.
- **Ledger counts.** I re-derived 17 axioms / 18 closures / 5 pins / 5 witnesses from AXIOM_STATUS.json — they match the fresh `verify-ledger-consistency` receipt exactly. No drift.

**2. What I did NOT look at (next round's targets).**
- **Executed nothing myself.** No `lake`/`easycrypt`/`halmos`/`kontrol`/`lean4checker`/`make verify-*`. Every gate verdict is a source read of the driver or a classified orchestrator receipt.
- **The Halmos/Kontrol bytecode discharge (A3.2/3.3/3.4)** and the **pinned-codehash → deployed Base Mainnet** binding (G2 reality drift: is `0x31e49D24…`/`0xdDE4…` still the live code?) — read the ledger, did not re-run or re-fetch chain state.
- **Kani/Miri firmware surfaces**, the ProVerif/Tamarin models' *content* (only the CryptoVerif wiring), the differential/fuzz corpora, `PROOF_MAP.md`, `TRUST_ASSUMPTIONS.md`, `THREAT_CLAIM_MAP.md`, the prior FV findings docs — inspected shallowly or not at all.
- **Packet Section-4 sub-items on the firmware surface — NOT traced (so "no finding" ≠ "clean"):** EntryPoint/userOp digest semantics beyond the A2 note; PIN directionality (invariant #2); clear-sign intent/display faithfulness; recovery/provisioning; the rollback/update state machine beyond the F3 version cross-check. These are firmware/hardware surfaces **outside the Lean FV tree** and have zero Lean coverage by design (ASSURANCE_CASE §5) — they belong to the sibling firmware playbooks, not this FV pass.
- **EasyCrypt substance I read but could not compile:** the 11 MM45-chain files' proof scripts (F1 ceiling). My Section-5 verdict below is source-read + receipt, not an executed check.

**3. Provenance and limits.** This is a **source-read + receipt-classification** pass, **not an executing** one — its "no V1–V11 hole" carries exactly the G4 ceiling the playbook names (a smuggled `native_decide`/`@[extern]`/`admit` evades a source read). The sandbox blocked `git` and `find|xargs` (worked around via `.git` file reads; aggregate `ad0de135…` digest **not** independently reproduced — recipe is in the excluded live repo). I did not read the other reviewer's report. Remaining gates before any stage advance: complete `verify-lean4checker` on the frozen tree (F2); make the EasyCrypt WOTS+C/capstone reproducible or re-scope its ledger prose (F1); reconcile the FW-update version surfaces (F3). Merge and production-shipment remain **unavailable** from this review.

## Appendix A — Required EasyCrypt assessment (packet Section 5), with cost/limits

**Verdict per leg (source-read + `verify-easycrypt-pins`/`forsc-margin` receipts; the compile leg is F1-limited):**
- **WOTS+C — genuinely the strongest.** `D1_MEUFNACMA_WOTSC_MM45_embthfc` (WOTS_C_EmbDischarge.ec) bounds the **real** multi-instance d-EU-naCMA game by MM45's **real** `M_EUF_GCMA_WOTSTWESNPRF` + `S_TCR_C`; sound direction, 0 `admit`, unconditional modulo `c ≤ p_tgts` + the definitional encode-compat identity; FLAG-1 discharged definitionally (legitimate specialization), FLAG-2 via `emb_disj_wgpidxs_holds`. Matches paper Thm C.2/D.1. **But unreproducible from the packet (F1).**
- **Reduction direction:** sound throughout (LHS game ≤ Σ RHS real games; no flip) — confirmed on the capstone (`SPHINCS_C.ec:206-237`) and the WOTS+C bound.
- **Interactive vs batch WOTS games:** the **load-bearing** game is the non-adaptive/batch `M_EUF_NACMA_WOTSC_L`. The **interactive** S-TCR(+C) sim (`WOTS_C_Interactive.ec`) is **orphaned with 1 `admit`** — scaffold, required by nothing, disclosed. Correct choice (D.1 states the non-adaptive notion).
- **FORS multi-instance composition:** routed through `FORS_C_Multi.MFORSC`/`EUFCMA_MFORSC` (cloned as `M` in the capstone). The three tree terms (`mtree_*`) are **explicit `forall`-bound premises**, not free abstract ops — the fix after a real PoC (cloning with `mtree_* ← 0%r` had made the bound *false*/vacuous; PROVENANCE 2026-07-09). A true conditional, non-vacuous.
- **FORS+C core:** C10-faithful game (`FORS_C10.ec`) + machine-checked combinatorial core (`DarkSide.ec`: `cover_pr`, `forsc_le_fors`) — this mechanizes a claim the paper only asserts informally (there is **no** FORS+C theorem in SPHINCS+C S&P 2023). **The tight bound is OPEN** (k-fold product, binomial mixture, (q_h+1) union bound not mechanized); rests on the nonstandard **`ITSRC10`** assumption (unbounded inside EC, like MM45's own plain ITSR).
- **Capstone (`SPHINCS_C.ec`):** an **honest conditional composition, not a security proof.** `p_sphincs_c` is a free abstract real; `hfx` (FX skeleton) + `hbridge` (XMSS-MT) are premises = the multi-person-year remainder; no `SPHINCS_PLUS_C` scheme module exists; the shared-adversary construction is inside `hfx`/`hbridge`, not proven. Faithful in *shape* (term-for-term vs MM45's `EUFCMA_SPHINCS_PLUS_FX`).
- **admits / axioms / clones:** 2 `admit` (both orphaned: `FORS_C_TreePort.ec:1531`, `WOTS_C_Interactive.ec:743`); **8 live axioms** (`dpp_ll`, `dmkey_ll`, `good_pos`=p_ν, and five structural `g`-axioms incl. `uniq_g`); clones `MFORSC→M`, `STCR_C` into `WOTS_C_Real`. A **real vacuity was found+fixed** here (the original 4 `g`-axioms admitted `nseq k z`, making `neqisvs_g` vacuous — closed by `uniq_g`, 2026-07-10b).
- **`.eco` cache trust:** the vendored `drafts/` ship **no** `.eco` and the driver deletes them before compiling (`check_easycrypt.sh:175,193`) — no stale-cache risk there. The load-bearing cache is the MM45 `SPHINCS_PLUS.eco`, which the frozen tree lacks (so the skip is *forced*, no stale artifact — but see F1).
- **Vendored vs standalone port:** the in-repo `contracts/verification/easycrypt/` is cited at `c5fa41a`; the standalone `c10-eufcma-port.frozen` is `70974e9`. I did not byte-diff them (the gate compiles the vendored `drafts/`; the packet points the audit at the standalone port). Worth a divergence check next round.

**Is continuing the separate C10 port worthwhile? — DEFER the capstone; do two narrow pieces.** The high-value increments have **landed**: the WOTS+C leg is genuinely unconditional against MM45's real theorems, and the FORS+C combinatorial core + concrete margin mechanize a gap the *paper leaves informal* — real, original contributions. The remaining bulk (porting the FX skeleton + XMSS-MT bridge to build the `SPHINCS_PLUS_C` scheme module) is **low marginal value**: A5 is **cited-TCB regardless** (the kernel `theft_free` never consumes the EasyCrypt), it would still bottom out at MM45's standard-SPHINCS+ axioms + the unbounded-in-EC `ITSRC10`, and on-chain safety (conjunct 1) is EUF-CMA-free. Completing the capstone is the archetypal low-value proof-theater the playbook warns against. **Worthwhile narrow continuation:** (1) make the WOTS+C/capstone legs **reproducible by the gate** (F1) — cheap, high provenance value; (2) mechanize the **FORS+C quantitative backbone** (the (q_h+1) union bound + binomial mixture), because the shipped-param margin (~2⁻²·⁶ @ q_h=2¹²⁸) currently rests on a Python script, not a proof, and is the real residual uncertainty for C10.

## Appendix B — Ranked FV-surface expansion (packet Section 6)

Scored L/M/H on Value · Feasibility · Trust-base-reduction · Proof-to-shipping span.

1. **A3.1 verifier ∀-signature via interpreter-refinement (Verity-style; `contracts/verity/` scaffold).** V:H · F:M · TBR:H · Span:SHORT. Closes the single named on-chain residual (verifier ∀-equivalence, today tier-C corpus) deductively with opaque hash — moves A3.1 from cited-corpus to kernel model↔spec, leaving only the model↔bytecode transcription. **Top pick.**
2. **FORS+C quantitative backbone in EasyCrypt.** V:M-H · F:M · TBR:M · Span:MED. Turns the shipped-param margin from a Python receipt into a proof; the real residual for the nonstandard `ITSRC10`.
3. **Make the EasyCrypt WOTS+C/capstone gate-reproducible (F1 fix).** V:M · F:M-H · TBR:L · Span:N/A. Cheap; converts the one unconditional result from author-attested to independently checkable.
4. **Complete + CI-ify lean4checker (F2 fix + umbrella-collision rename).** V:M · F:H · TBR:L(closes the under-report currency) · Span:N/A.
5. **A2 EntryPoint deployed-bytecode discharge (Kontrol vs mainnet EntryPoint).** V:M · F:L (8–12 mo) · TBR:M · Span:SHORT. High cost — defer.
6. **Device invariants #2/#3/#4 + clear-sign display.** V:H(device security) · F:L-for-Lean. **Not** a Lean-FV target — better served by the ProVerif/Tamarin models + Kani + silicon E2E; forcing them into Lean would be proof-theater. Route to the sibling firmware playbooks.
- **REJECT as low-value:** completing the SPHINCS+C capstone FX-skeleton/XMSS-MT port (multi-person-year; A5 cited-TCB regardless; on-chain safety EUF-CMA-free).
```

I've delivered the complete first-pass report above. Two closing process notes, stated plainly rather than buried:

- **Digest discipline:** verified before reading and again immediately before reporting — HEAD `ddc7cefc…`, branch, and all three normative-doc SHA-256 are byte-identical across both checks; **no drift**. The one honest gap is that I could not independently reproduce the packet's aggregate `ad0de135…` (its recipe lives in the excluded live repo, and the sandbox blocked the hashing pipeline) — my anchors are HEAD×4 + branch + 3 doc hashes + the read-only mount.
- **Durability:** I have no Write tool and `git`/`find`-pipeline Bash calls are blocked in this mode, so the authoritative deliverable is the report bytes in this response (the workflow has the orchestrator catalogue the returned first-pass bytes). I did not read, seek, or infer `partner-b-first-pass.md`.

The headline for the orchestrator: **no soundness hole in `theft_free` was found or reproduced (source-only, G4-limited); the four confirmed findings are all provenance/enforcement/currency defects**, the strongest being F1 — the EasyCrypt gate cited *by two of `theft_free`'s own axioms* reports OK while skipping the only unconditional result and the capstone, which are therefore unreproducible from this frozen packet.