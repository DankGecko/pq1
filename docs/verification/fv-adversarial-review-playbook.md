# FV adversarial-review playbook + "green ≠ sound" master guide

**Purpose.** Two jobs in one document: (A) a reusable recipe + copy-paste **master prompt** for running an EF-style adversarial pass over PQSigner's formal verification on demand; (B) the standing discipline that stops the **"it compiles green but doesn't mean it's sound"** trap from fooling us again.

> **The thesis, stated once.** A `lake`-green tree, a clean `#print axioms`, and a confident self-assessment are *consistency* signals, not *soundness* signals. Every gate the project runs is **green precisely on the vacuous, tautological, and undischarged-but-advertised proofs** — because those proofs *do* compile and *do* have the expected axiom set; they just don't constrain anything. The EF swarm found 31 such gaps that our green CI could not see. You cannot catch your own vacuity with a gate you designed, because the gate encodes the assumptions you didn't think to question. So the goal is **never "be sure."** It is: automate the mechanical vacuity classes into per-commit gates, run an adversarial pass on a cadence for the semantic classes no gate can catch, keep occasional genuine externality, and report confidence as *eliminative* (every doubt is a tracked defeater, discharged or accepted — never indefeasible).

---

## Part A — The "green ≠ sound" failure catalog

These are the ways a Lean theorem can be `lake`-green yet say nothing (or less than advertised). For each: what it looks like, the EF finding it actually *was*, how to **detect** it, and whether detection is automatable. **A theorem is only as strong as the weakest row it survives.**

| # | Green-but-hollow mode | What it looks like | Was (EF) | Detection | Auto? |
|---|---|---|---|---|---|
| V1 | **Vacuous antecedent** | `∀x, P x → Q x` with `P` unsatisfiable — `Q` is never actually checked | P9 (`isForgery` unsatisfiable for honestly-signable msgs) | Prove `∃x, P x` (a **satisfiability witness**). Can't ⇒ vacuous. | ✅ witness lemma |
| V2 | **Tautological axiom/hypothesis** | An `axiom`/premise that is *provable* over the model, so it adds no constraint | P2 (`entrypoint_honest` tautology over `handleOp`) | Try to prove the axiom *as a theorem* with kernel-only `#print axioms`. If it closes ⇒ the axiom carries zero information. | ✅ "re-provable-kernel-only" lint |
| V3 | **Trivial conclusion** | `Q = True` / always-holds — theorem says nothing | pre-2026 `: True` placeholders | `lint_axioms` (no `True`-typed axiom) + `lint_placeholders.py` (no `True := trivial`) + a **refutation test** (`∃ inputs, ¬Q` constructible) | ✅ exists + ⚠ refutation gap |
| V4 | **Dead conjunct / unused premise** | `A ∧ B` where deleting `B` (or an axiom) breaks nothing downstream | P9 (EUF-CMA conjunct detached from the safety conjunct) | **Proof-mutation**: delete each axiom/conjunct, re-`lake build`, **expect failure**. Still green ⇒ dead. | ✅ `make verify-proof-mutation` |
| V5 | **Undischarged-but-advertised hypothesis** | Theorem conditional on a free hypothesis the ledger calls "proven/closed" | P1 (`hInv` "kernel-proven" — was a free hyp) | **Ledger-consistency**: diff each theorem's *actual* closure + headline statement-shape (signature pin) against what `AXIOM_STATUS` *advertises*. | ✅ `make verify-ledger-consistency` |
| V6 | **Stub / placeholder definition** | `def f := <all-zero/arbitrary>` makes a round-trip predicate unsatisfiable or trivially-true | P9 (`Spec.Signer.sign` all-zero stub) | The def must (a) round-trip with a **real witness** and (b) be cross-checked against an **independent oracle** (KAT), not be self-derived. | ⚠ partial (`honest_consistent` did it; not enforced) |
| V7 | **Over-strong / latent-false axiom** | An axiom that, if false, makes everything provable (`… → False`) | pre-2026-06-14 EUF-CMA `→ False` | **BreaksHash firewall** (`lint_fv (b)`: no `¬ BreaksHash` / `→ False` on a proof path) | ✅ `lint_fv (b)` |
| V8 | **Wrong-shape quantifier** | `∃` witness where the claim needs `∀` (binds one case, not all) | P6 (TxFlow existential vs all-calldata) | Read the statement adversarially: does the quantifier match the *threat*? **No gate** — needs the swarm. | ❌ adversary |
| V9 | **Model ≠ deployed artifact** | Theorem about a Lean model that doesn't faithfully mirror the bytecode/firmware/transcription | the LeanModel.sol ↔ Lean TCB; Charon-LLBC | **Differential KAT** (same vectors through model + artifact) + codegen the bridge + an **independent engine** (Kontrol vs Halmos). Not a pure-Lean check. | ⚠ partial (Aeneas diff-gate, Kontrol) |
| V10 | **`#print axioms` bypass** | `native_decide`/`decide +native`/`ofReduceBool`/`@[csimp]`/`@[extern]` smuggle an axiom invisibly (lean4 #7463) | (latent) | **banned-tactic grep**, comment-stripped | ✅ `lint_fv (a)` |
| V11 | **Right spec? captures the real threat?** | The theorem is sound and non-vacuous but proves the *wrong property* | (the deepest class) | Adversary + externality + the assurance-case decomposition. **No tool catches "you modeled the wrong thing."** | ❌ adversary + external |

**Read this catalog as the answer to "how do we not get fooled by green":** V1–V3, V7, V10 were *covered* already; **V4 and V5 — the EF findings (P9-dead-conjunct, P1-undischarged-advertised) that recurred — are now closed by two BUILT gates** (`make verify-proof-mutation` + `make verify-ledger-consistency`, 2026-06-29; see Part B). V1/V6 are now enforced too (`verify-ledger-consistency` C9 witness-coverage, 2026-06-29) — so **every mechanical vacuity class V1–V7, V10 is gated**. **V8/V9/V11 are irreducibly the adversary's job** — no gate ever catches them; that is Part B / the portable kit, not a CI check. Do not let "we have mutation + ledger gates now" become the next version of "we thought we were in a good place": the gates stop you *re-discovering* the same vacuity; they do not make you *sure*.

---

## Part A2 — System-level soundness gaps (G1–G5): "the theorem is sound — so are we safe?"

V1–V11 all ask one question: **is this Lean *theorem* hollow?** The 2026-07-01 adversarial round ([`contracts/verification/docs/ADVERSARIAL_REVIEW_2026-07-01.md`](../../contracts/verification/docs/ADVERSARIAL_REVIEW_2026-07-01.md)) found, for a hardened tree, the answer is *no* — every mechanical vacuity class held. But its **HIGH finding was not a V-class at all**: `verify-ledger-consistency` — the gate advertised to police ledger drift — **never ran** on `AXIOM_STATUS.json`-only edits (its CI `paths:` filter omitted `docs/**`), demonstrated on three merged commits. A sound theorem behind a gate that never fires is *exactly* as dangerous as a hollow one: both are green, both overstate. So there is a **second axis** the V-catalog cannot see — the failure modes of the assurance *system* around a sound proof. **A green proof whose gate is unwired, resting on a stale cited fact, covering half the threat surface, checked by a possibly-buggy tool, and bounding only a shape and not a probability — is still a tree that overstates.**

**Honesty note (this catalog's own discipline):** the `Was` column distinguishes what *this round found* from what is *reasoned-latent* — precisely so the G-catalog does not become the checklist-overconfidence the playbook exists to fight. **Only G1 and G3 are evidenced; G2/G4/G5 are latent/reasoned/already-disclosed classes worth watching, not discoveries.** Dressing a reasoned class as a finding is a mild version of the exact failure mode below.

| # | System-level gap | What it looks like | Was | Detection | Auto? |
|---|---|---|---|---|---|
| G1 | **Gate-enforcement vacuity** | the anti-vacuity gate exists + is green-when-run, but never RUNS on the diff it polices — path-filtered out, `continue-on-error`, `workflow_dispatch`-only, unwired, or not a required check on the protected branch | **FOUND 2026-07-01 (HIGH, F1):** `verify-ledger-consistency` matched no positive `paths:` on ledger-only edits + `ci.yml` path-ignores `contracts/verification/**` + nightly never called it (PoC: 3 merged ledger-only commits); `verify-storage-mutators` unwired. (Separately catalogued outside the F1 review — in `FV_SURFACE_MAP.md` + the `gate_enforcement.json` manifest — `checkct` ships `workflow_dispatch`+`continue-on-error`.) | **CI-wiring audit** per `verify-*` gate: (a) a job invokes it, (b) its trigger `paths:` cover the surface it polices, (c) it is blocking (no `continue-on-error` / not manual-only), (d) it is a required status check on `master`. PoC: a merged diff that touched the policed surface without triggering the gate. | ✅ a gate-enforcement lint — **BUILT 2026-07-01** (`make verify-gate-enforcement`, per-PR in `ci.yml`; catches the exact F1). `scripts/check_gate_enforcement.py` parses the live workflow YAML and regex-matches `make <target>` in each job's `run:` text (it does not parse the Makefiles themselves — target *existence* is not checked). |
| G2 | **Cited-TCB reality drift** | a cited (unmodeled) assumption is stale/false about the DEPLOYED world — not latent-false in Lean, but wrong about reality (a pinned codehash the chain no longer serves; a "singleton factory" that got a second deployment; an "EVM fact" a fork changed) | latent — `DEPLOYED_BYTECODE_PIN_CAVEAT.md` already flags the pin; not exercised this round | re-validate each cited-TCB leaf against REALITY on a cadence (re-fetch the deployed codehash, confirm the factory is singleton). A green Lean proof about a stale artifact proves nothing *deployed*. | ⚠ partial (a pin-freshness check) |
| G3 | **Coverage-completeness gap** | a threat in the model has NO claim — the tree proves a lot about X and nothing about Y, and the absence is invisible because there is no "missing claim" to turn red | evidenced (pre-round): the device-invariant #1–#4 span + the firmware decoders where the real HIGHs lived (`FV_VALUE_AND_GAPS.md` gap #1) — invisible to every per-theorem gate until surfaced by hand | a threat-model → claim **map**: enumerate threats, map each to a covering claim, flag the unclaimed. The assurance-case decomposition covers EXISTING claims; this covers the MISSING ones. | ❌ adversary + threat-map |
| G4 | **Verification-tool trust** | the checker itself (CBMC/Kani, Halmos/KEVM, binsec, the Lean kernel + `#print axioms`) has a soundness bug or a disclosed limitation → a false green the proof cannot see | reasoned / partial-overlap V10: the `#print axioms` v4.22.0 under-report is disclosed (backstop `lean4checker` — but MANUAL, not CI → itself a G1); the symbolic-harness `.t.sol` legs were taken at face value this round, not shown broken | cross-tool corroboration (independent engines on the SAME artifact — Kontrol vs Halmos), tool-version pinning + known-bug tracking, and the completeness backstop actually RUN (not manual). No single tool's green is self-certifying. | ⚠ partial (cross-engine + lean4checker) |
| G5 | **Qualitative-shadow / quantitative gap** | the proof captures the STRUCTURE of a security argument but omits the concrete bound — a reduction's *shape* without the `Pr ≤ ε` advantage, presented as if it were the quantitative guarantee | already-disclosed (not a hole): A5's EUF-CMA is explicitly tagged "the qualitative shadow of the Barbosa et al. ASIACRYPT 2024 game … the quantitative `Pr ≤ ε` bound is not formalised (cited, out of scope)" | for each crypto claim: is the adversary's ADVANTAGE bounded, or only the reduction's shape? A qualitative shadow is legitimate — but must be DISCLOSED as a leaf, never *implied* to be the quantitative bound. | ❌ disclosure discipline |

**Read G1–G5 as the answer to "the theorem is sound — so are we safe?": not yet.** On a hardened tree the frontier moves *up a level* — from "is the proof hollow" to "is the assurance actually **enforced** (G1), **current** (G2), **complete** (G3), **tool-trustworthy** (G4), and **quantitative** (G5)." The 2026-07-01 round is the proof of the shift: **zero V1–V11 holes, one HIGH G1.** When the mechanical *and* the semantic vacuity classes are all held, the next thing that overstates is the *system*, not the theorem.

---

## Part B — The standing two-layer discipline

### Layer 1 — automate every mechanical vacuity class (per-commit, fail-closed)

Already in place: `lint_fv` (a-escape-hatch / b-BreaksHash-firewall / c-exact-closure / d-opaque-guard), `lint_axioms` (no `True`-typed), `lint_placeholders.py`, `verify-audit` (no-`sorryAx` + `check_axiom_closure.py` Claim-4 kernel-only), `dump_axioms` `*_nonvacuous` witnesses (by convention), `cargo-mutants` (Rust). Of the three automatable gaps, **two are now BUILT** (2026-06-29); the third remains:

**Path note:** the two FV-tree scripts below live at `contracts/verification/scripts/` (invoked via `make -C contracts/verification`); the G1 gate-enforcement trio (`check_gate_enforcement.py`, `gate_enforcement.json`, `kani_mutations.json`) lives at repo-root `scripts/`. The bare `scripts/` prefix in this file therefore denotes different directories per gate — resolve against the owning Makefile.

1. **Proof-mutation gate — ✅ BUILT (`make verify-proof-mutation`).** The proof-side analogue of `cargo-mutants`: `contracts/verification/scripts/check_proof_mutations.py` drives the manifest `lean/scripts/proof_mutations.json`, deleting (by rename) each load-bearing axiom and weakening key lemmas, then asserting the rebuild **reacts as the ledger claims** — a load-bearing axiom's removal must break the build; a non-consumed A1/A4 marker's removal must stay green AND drop *exactly* the advertised axiom from `theft_free`'s closure; the zero-consumer A3.4 must stay green; the P1 `reachable_implies_combinedCap` must be load-bearing for the reachable headline. Each mutation asserts it **materially changed the file** (a no-op is a HARD FAIL, never a skip), does a full transitive rebuild (no stale-cache false pass), and **always reverts**; a permanent **canary** must trip or the harness is declared void. It *executes the ledger's own falsifiability prose* — the prose claims become mechanical tests. Tiers: `MUTATIONS=quick|default|full`.
2. **Ledger-consistency gate — ✅ BUILT (`make verify-ledger-consistency`).** `contracts/verification/scripts/check_ledger_consistency.py` makes `AXIOM_STATUS.json` falsifiable against the live Lean truth: a machine-readable `closures` block (exact-set per theorem) + `signature_pins` (headline statement-shape — catches a re-introduced raw `hInv` that closure checks can't see) are diffed against `dump_axioms.lean`, the Lean source, the per-status summary counts, and the `lint_fv` THEFT_EXPECTED pin (single authoritative source — no 5th drift surface). Plus no-undocumented / no-phantom axiom + status hygiene. Ships a wired-in `--self-test` negative control. *Caveat in the header:* `#print axioms` under-reports in lean v4.22.0; `make verify-lean4checker` is the completeness backstop — this gate guards advertised-vs-`#print-axioms` consistency, not the under-report gap. (Already surfaced + fixed one real gap on first run: an undocumented `solidityWalletExecuteBatch` axiom.)
3. **Enforced non-vacuity-witness coverage (closes V1/V6 systematically) — ✅ BUILT (`verify-ledger-consistency` C9, 2026-06-29).** The `*_nonvacuous` convention is now a *requirement*: the ledger's `witness_coverage` block pins each headline hypothesis to a hand-written witness lemma (e.g. `combinedCapInvariant_empty` witnesses `theft_free_bytecode`'s `hInv`; `H_adrs/H_sib_dischargeable` the FORS-climb bounds; `execute_step_satisfiable` the Claim-4 credit), and C9 fails CI if a witness drops from `dump_axioms.lean` OR its `#print axioms` closure leaves **kernel-only** (a witness resting on a project axiom could be circular — witnessing the very assumption). **Adapted, not literally ported,** from LeanLoop's `vet` HYP probe: LeanLoop finds witnesses mechanically with `plausible`, but PQSigner's `lean/` is deliberately **mathlib-free** (the load-bearing invariant that makes a false axiom non-detonatable — pulling in Plausible would break it), so we enforce the *existing hand-witnesses* instead. Residual: the witness set is the headline-hypothesis scope, not yet *every* predicate (the two `private` C10 interpreter witnesses aren't externally pinnable and stay covered by the proof-mutation full rebuild).

4. **Gate-enforcement lint — ✅ BUILT 2026-07-01 (`make verify-gate-enforcement`; closes G1).** The 2026-07-01 round's HIGH finding (F1) is that a gate can be green-when-run yet never RUN. That is a *mechanical* class — exactly what Layer 1 automates — so leaving it to the adversary would itself be a G1 (a prose gate that never executes). `scripts/check_gate_enforcement.py` + manifest `scripts/gate_enforcement.json`: each soundness gate declares what surface it polices + where it must run; the checker parses the live workflow YAML + Makefiles and asserts (a) a job invokes it, (b) its trigger `paths:` cover the policed surface (the F1 check), (c) it is blocking (no `continue-on-error` / not `workflow_dispatch`-only), else `enforcement=local_documented` with a `why` (a NOTE, never silent). Fail-closed; ships a `--self-test` negative control. **Validated:** passes the current tree, the self-test catches a broken gate, and it re-flags the *exact* F1 when `docs/**` is stripped from `lean-fv.yml`. Wired per-PR in `ci.yml` (a G1 lint that is not itself CI-enforced would be its own G1).

The mechanical anti-vacuity layer for the *theorem-level* classes (V1–V7, V10) is complete; the 2026-07-01 round surfaced one new *system-level* mechanical class (G1) not yet mechanized (item 4 above). What no gate closes is below.

### Layer 2 — the adversarial swarm (for V8/V9/V11 no gate can catch)

The mechanical gates make the *vacuity* class non-recurring. They do **nothing** for "wrong quantifier," "model ≠ artifact," or "wrong spec." Those need an adversary. The recipe (validated: the 62-agent verify+adversarial pass this engagement ran *converged* with an independent 11-agent sweep):

- **Adversarial framing** — agents tasked to **refute** ("find where the proof says less than the marketing; where the gate is green but the claim is hollow"); default-to-guilty.
- **Model diversity** — ≥3 independent models; convergence is signal, divergence surfaces a blind spot one model shares with you.
- **PoC-required** — every finding carries a *runnable* artifact: a Lean snippet proving a hypothesis unsatisfiable, a "delete this conjunct and the theorem still holds," a `#print axioms` showing an advertised premise absent, a Rust test showing a fail-open. **No PoC ⇒ filtered.**
- **Adversarial cross-vote** — a *second* agent tries to refute each finding (this is what caught the two dangerous "fixes" — the F8 plaintext-downgrade and the P1 prove-a-false-statement traps).
- **Claims-inventory anchor** — attack the *specific* claims in `ASSURANCE_CASE.md` / `AXIOM_STATUS.json` / `THE_CLAIM.md`, walking the V1–V11 catalog against each.
- **Honest residual output** — the run MUST end with *"what we could not break"* AND *"what we did NOT look at"* (modalities not run, claims unverified, artifacts unread). The latter becomes the next round's targets. A pass that only reports findings and implies "the rest is fine" is itself overconfidence.

### Layer 3 — keep occasional genuine externality

An in-house swarm reads our docs and inherits our framing, so it shares *some* blind spots (V11 especially). Budget a periodic external red-team (like the EF). The in-house layers make those external passes find *less* — never *nothing*.

---

## Part C — THE MASTER PROMPT (copy-paste / workflow brief)

> **Now packaged as a runnable, framework-agnostic kit:** `contracts/verification/adversarial-review/`. The prompt below is mirrored (self-contained, with the V1–V11 catalog + a strict JSON findings schema) in `adversarial-review/PROMPT.md`; the angles/targets/cross-vote live in `protocol.json`; and `run_review.py` drives it through **any** backend — `--backend claude`, `--backend codex`, or `--backend generic --cmd '…'` for a raw model or a future system. So you are not locked to Claude Code: `python3 run_review.py --backend codex --reviewers 3 --quorum 2`. Self-test with no LLM: `--backend generic --cmd 'cat tests/canned_findings.json' --self-test-ok`. See `adversarial-review/README.md`. The copy-paste form below remains for a quick one-off paste into any chat.

Paste this to a fresh agent (or use it as the per-agent brief in an N-way swarm workflow; rotate models). Fill the `{{…}}` slots.

```
ROLE: You are an adversarial formal-verification reviewer of PQSigner_OS. Your job
is to BREAK the soundness/meaningfulness of its FV, NOT to confirm it. Default to
"this claim is hollow until I prove otherwise." A green `lake build`, a clean
`#print axioms`, and confident docstrings are CONSISTENCY signals, not soundness —
treat them as the thing to attack.

TARGET (read first, in this order):
  - contracts/verification/docs/ASSURANCE_CASE.md, THE_CLAIM.md, AXIOM_STATUS.json,
    PROOF_MAP.md, OPEN_PROOF_OBLIGATIONS.md  — the CLAIMS INVENTORY you must attack.
  - contracts/verification/lean/SphincsCVerify/  — the proofs (headline theft_free,
    theft_free_bytecode{,_reachable}, the corollaries, the cited axioms A1/A2/A3.*/A4/A5).
  - docs/verification/fv-adversarial-review-playbook.md §A  — the failure catalog
    (V1–V11) that is your ATTACK SURFACE.
SCOPE THIS RUN: {{e.g. "the EUF-CMA / signer claims" | "the bytecode bridge axioms"
  | "the whole theft_free closure" | "the firmware fail-open paths"}}.

SURFACE NOTE (2026-07-01): the TARGET above is the **Lean on-chain surface ONLY** — that
is 2 of the 8 FV surfaces (see contracts/verification/docs/FV_SURFACE_MAP.md; a second round
has since covered the firmware Kani surface too — ADVERSARIAL_REVIEW_KANI_2026-07-01.md — so
the map now reads ~3 of 8 reviewed). The
firmware Kani, Miri, the protocol models (ProVerif/Tamarin/CryptoVerif), CT/SCA (checkct),
the Aeneas §33 extraction, and the differential/fuzz corpus have NEVER been adversarially
reviewed. To review one, set SCOPE to it AND swap the claims inventory: the Kani harnesses
+ scripts/kani_mutations.json (V1/V3/V8 — a harness that asserts nothing / is bounded
trivially / samples where ∀ is needed); the protocol .pv/.spthy + their expected verdicts
(V2 tautological query); the checkct/.t.sol drivers; the extracted/ §33 ranks. The V1–V11
catalog transfers unchanged — only the artifacts change. The FIRST such profile is BUILT: the `kani-decoder-vacuity` angle in `contracts/verification/adversarial-review/protocol.json` (run `python3 run_review.py --angle kani-decoder-vacuity`) — its `instructions` field is the per-surface V-mode manifestation (V1 empty-assume · V3 no-assert · V6 self-oracle · V8 bounded-N-as-∀ · V11 gate≠renderer · G3 uncovered decoders). Model each new surface angle on it; the persona (`PROMPT.md`) is shared.

ATTACK PROTOCOL — walk EVERY V1–V11 mode against each claim in scope:
  V1 vacuous antecedent · V2 tautological axiom/hyp · V3 trivial conclusion ·
  V4 dead conjunct/unused axiom · V5 undischarged-but-advertised hypothesis ·
  V6 stub/self-derived definition · V7 over-strong/latent-false axiom ·
  V8 wrong-shape quantifier (∃ where ∀ is needed) · V9 model ≠ deployed artifact ·
  V10 `#print axioms` bypass (native_decide/ofReduceBool/csimp/extern) ·
  V11 wrong spec — does the theorem capture the REAL threat the marketing implies?

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a Lean snippet that compiles and shows the hypothesis is unsatisfiable
    (`example : ¬ ∃ x, P x` ) or the conjunct is deletable (the theorem re-proves
    without it), or `#print axioms <thm>` showing an advertised premise is absent;
  - a concrete witness the predicate should fire on but doesn't (or vice-versa);
  - a Rust/Foundry test or a fault/SCA model showing a fail-open;
  - a diff between what a ledger ADVERTISES and what `#print axioms` / the theorem
    signature ACTUALLY shows;
  - a GATE-ENFORCEMENT PoC (G1): a merged diff (git SHA) that touched a policed
    surface WITHOUT triggering the gate, or a workflow `paths:` / `continue-on-error` /
    `workflow_dispatch` clause showing the gate cannot fire on the relevant change.
  No PoC ⇒ do not report it as a finding (list it under "suspicions, unverified").

RULES:
  - Verify against the CURRENT tree, not docs alone; re-read the cited Lean — do not
    trust quotes. Check git log for recent changes.
  - Distinguish "ships-broken" from "pre-production caveat behind a fence" (CLAUDE.md).
  - For each finding give: which V-mode, the exact file:line, the PoC, the
    disposition (CONFIRMED_REAL / FALSE_POSITIVE / ALREADY_FIXED / OPEN_RESEARCH),
    severity, and a proposed fix — flagging if the fix would break an invariant,
    regress a green proof, introduce a sorry/axiom, or "fix" correct code.

OUTPUT — file findings so they can be catalogued + worked through (see
docs/security/adversarial-review/findings/README.md):
  Write a dated report to docs/security/adversarial-review/findings/<surface>-<YYYY-MM-DD>.md
  from findings/TEMPLATE.md — everything below (findings + the honest residual) goes IN it.
  Report frontmatter `status: open`; EACH finding gets its own `Status:` line (start 🔲 OPEN)
  + a falsifiable PoC. Add one row to the Catalogue table in findings/README.md. As findings
  are worked through, whoever handles each flips its `Status:` (✅ FIXED / ☑️ ACCEPTED /
  🚫 INVALID / ⏸ DEFERRED) + a Resolution (commit+date or why), and sets the report
  `status: resolved` once none remain OPEN. work-todo.md stays the action list; findings/ is
  the review record — cross-link them.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — the claims that survived, and the
     strongest single PoC-attempt that failed, per claim.
  2. "What I did NOT look at" — modalities not run, claims unverified, artifacts
     unread, V-modes not exhausted. This is the next round's target list.
  3. "PROVENANCE — did this pass EXECUTE the checkers, or read source only?" State
     plainly whether you ran `lake build` / `#print axioms` / `lean4checker` /
     `make verify-*`, or reasoned from source + the committed ledger alone. A
     source-only pass is G4-limited: "no finding" from a NON-EXECUTING pass is much
     weaker (a smuggled `native_decide`/`@[extern]` axiom evades both `#print` and a
     source read). The 2026-07-01 round was source-read-only — so its own "no
     V1–V11 hole" carries exactly that ceiling.
  Never imply "the rest is fine." Absence of a finding is not evidence of soundness.
```

**Running it as a swarm** (replicates the EF pass): the portable kit does the fan-out for you — `run_review.py --reviewers 3 --quorum 2` runs N independent passes per angle and cross-votes (a finding ≥quorum reviewers raise is "confirmed"; the rest are sub-quorum triage). For model diversity, run it twice across **two** backends (`--backend claude` then `--backend codex`) so a single model's blind spot doesn't become yours, and union the `out/report.md` honest-residual blocks into the next round's targets. (If you prefer to drive it from inside Claude Code instead of the CLI, the `Workflow` tool's `parallel()` + a `phase('CrossCheck')` is the equivalent mechanical shape; rate-limit-gentle batching ≤2 concurrent avoids the throttle.)

---

## Part D — Cadence + honest calibration

- **Per-commit:** the Layer-1 gates — now including `make verify-proof-mutation` + `make verify-ledger-consistency` (BUILT); enforced witnesses remains to build. (proof-mutation is slow → run it on FV-touching PRs / nightly, not every commit; ledger-consistency is fast.)
- **Per-FV-PR / weekly:** run the Part-C swarm (`adversarial-review/run_review.py`) scoped to the changed angle; require the honest residual.
- **Per-milestone / pre-external-claim:** full-scope swarm + a genuine external red-team.
- **Calibration discipline (eliminative argumentation):** in `ASSURANCE_CASE.md`, every claim decomposes to PROVEN / CORPUS-VALIDATED / CITED-TCB-ASSUMED leaves, and **every residual is an explicit, tracked *defeater*** (a doubt that must be discharged or accepted). You never assert indefeasibility; the strongest credible claim is "here is every doubt we could surface, and what we did with each." That sentence — not a green checkmark — is what an external auditor should be handed.

## Part E — the one-line gut check before you ever say "we're in a good place"

> For each headline claim: *if I deleted the proof body / weakened the key axiom / fed the predicate an input it should reject — would something turn red?* If you don't **know** the answer is yes (and ideally have a gate that proves it), you are not in a good place — you are green. The two are not the same.

> **The G-level twin (added after the 2026-07-01 round).** And one level up: *if I broke the gate's wiring, let the cited codehash go stale, or left a threat unclaimed — would anything turn red?* For gate-wiring the answer was **no** (F1: the ledger gate never fired on ledger-only edits until an adversarial pass found it by hand). A sound theorem behind a gate that never runs is a green tree that overstates. **"Enforced" is not "green" either** — and it is the level the frontier moves to once the theorem-level classes all hold.

---

## Part F — where this playbook stops (the boundary, stated on purpose)

Completeness is not a state this playbook can reach — claiming it would be the exact overconfidence Parts A/A2 catalog. So this section names the boundary, because an *unstated* boundary is itself a G3 (a gap with no red row).

1. **Surface scope — the review reaches ~3 of 8 FV surfaces.** The master-prompt TARGET is the Lean on-chain tree (2 surfaces); a second round has since covered the firmware Kani surface ([`ADVERSARIAL_REVIEW_KANI_2026-07-01.md`](../../contracts/verification/docs/ADVERSARIAL_REVIEW_KANI_2026-07-01.md)). [`FV_SURFACE_MAP.md`](../../contracts/verification/docs/FV_SURFACE_MAP.md) enumerates the whole surface; Miri / protocol models / CT-SCA / Aeneas §33 / differential-fuzz still have **never had a first adversarial pass**. Every "no hole found" is scoped to what was targeted — never the whole stack. Extending the TARGET (the surface note in Part C) is the standing next-round work. **Beyond the FV surface entirely, the sibling adversarial-review playbooks in [`docs/security/adversarial-review/`](../security/adversarial-review/README.md) cover the firmware/hardware/on-chain attack surfaces (clear-signing decoders, TrustZone gateway, SE drivers, SCA/FI, firmware-update + secure-boot, USB + compromised-companion, off-chain signing, on-chain Solidity, trusted-UI, silicon-lockdown hardening-depth) — same discipline, tailored per-surface catalogs.**

2. **What is now mechanized vs still the adversary's.** The theorem-level vacuity classes V1–V7/V10 are gated; the *system-level* **G1 (gate-enforcement) is now gated too** (`make verify-gate-enforcement`, 2026-07-01). What no gate closes, and never will: **V8/V9/V11** (wrong quantifier / model ≠ artifact / wrong spec) and **G2/G3/G5** (cited-TCB reality drift / coverage-completeness / qualitative↔quantitative gap). Those are irreducibly the adversary + the *external* red-team (Layer 3). The in-house layers make an external pass find *less*, never *nothing*.

3. **Two artifacts the catalog still only names.** G3's threat-model → claim *map* does not yet exist (so "is this threat unclaimed?" is answerable only by hand), and there is no *review-provenance ledger* (which claim was reviewed, at what depth — source-read vs executing — when), so a stale source-only "no finding" can masquerade as durable assurance. Building these is the honest continuation of this playbook.

**The one-sentence boundary.** *This playbook can tell you that no covered claim on the Lean surface is hollow or unenforced as of the last executing pass — it cannot tell you the uncovered surfaces are sound, the cited facts are current, the threat model is complete, or that a non-executing pass proved anything.* That sentence — not a green tree — is what to hand an auditor.
