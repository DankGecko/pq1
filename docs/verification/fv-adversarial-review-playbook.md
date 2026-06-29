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

## Part B — The standing two-layer discipline

### Layer 1 — automate every mechanical vacuity class (per-commit, fail-closed)

Already in place: `lint_fv` (a-escape-hatch / b-BreaksHash-firewall / c-exact-closure / d-opaque-guard), `lint_axioms` (no `True`-typed), `lint_placeholders.py`, `verify-audit` (no-`sorryAx` + `check_axiom_closure.py` Claim-4 kernel-only), `dump_axioms` `*_nonvacuous` witnesses (by convention), `cargo-mutants` (Rust). Of the three automatable gaps, **two are now BUILT** (2026-06-29); the third remains:

1. **Proof-mutation gate — ✅ BUILT (`make verify-proof-mutation`).** The proof-side analogue of `cargo-mutants`: `scripts/check_proof_mutations.py` drives the manifest `lean/scripts/proof_mutations.json`, deleting (by rename) each load-bearing axiom and weakening key lemmas, then asserting the rebuild **reacts as the ledger claims** — a load-bearing axiom's removal must break the build; a non-consumed A1/A4 marker's removal must stay green AND drop *exactly* the advertised axiom from `theft_free`'s closure; the zero-consumer A3.4 must stay green; the P1 `reachable_implies_combinedCap` must be load-bearing for the reachable headline. Each mutation asserts it **materially changed the file** (a no-op is a HARD FAIL, never a skip), does a full transitive rebuild (no stale-cache false pass), and **always reverts**; a permanent **canary** must trip or the harness is declared void. It *executes the ledger's own falsifiability prose* — the prose claims become mechanical tests. Tiers: `MUTATIONS=quick|default|full`.
2. **Ledger-consistency gate — ✅ BUILT (`make verify-ledger-consistency`).** `scripts/check_ledger_consistency.py` makes `AXIOM_STATUS.json` falsifiable against the live Lean truth: a machine-readable `closures` block (exact-set per theorem) + `signature_pins` (headline statement-shape — catches a re-introduced raw `hInv` that closure checks can't see) are diffed against `dump_axioms.lean`, the Lean source, the per-status summary counts, and the `lint_fv` THEFT_EXPECTED pin (single authoritative source — no 5th drift surface). Plus no-undocumented / no-phantom axiom + status hygiene. Ships a wired-in `--self-test` negative control. *Caveat in the header:* `#print axioms` under-reports in lean v4.22.0; `make verify-lean4checker` is the completeness backstop — this gate guards advertised-vs-`#print-axioms` consistency, not the under-report gap. (Already surfaced + fixed one real gap on first run: an undocumented `solidityWalletExecuteBatch` axiom.)
3. **Enforced non-vacuity-witness coverage (closes V1/V6 systematically) — ✅ BUILT (`verify-ledger-consistency` C9, 2026-06-29).** The `*_nonvacuous` convention is now a *requirement*: the ledger's `witness_coverage` block pins each headline hypothesis to a hand-written witness lemma (e.g. `combinedCapInvariant_empty` witnesses `theft_free_bytecode`'s `hInv`; `H_adrs/H_sib_dischargeable` the FORS-climb bounds; `execute_step_satisfiable` the Claim-4 credit), and C9 fails CI if a witness drops from `dump_axioms.lean` OR its `#print axioms` closure leaves **kernel-only** (a witness resting on a project axiom could be circular — witnessing the very assumption). **Adapted, not literally ported,** from LeanLoop's `vet` HYP probe: LeanLoop finds witnesses mechanically with `plausible`, but PQSigner's `lean/` is deliberately **mathlib-free** (the load-bearing invariant that makes a false axiom non-detonatable — pulling in Plausible would break it), so we enforce the *existing hand-witnesses* instead. Residual: the witness set is the headline-hypothesis scope, not yet *every* predicate (the two `private` C10 interpreter witnesses aren't externally pinnable and stay covered by the proof-mutation full rebuild). The mechanical anti-vacuity layer is now complete; what no gate closes is below.

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
    signature ACTUALLY shows.
  No PoC ⇒ do not report it as a finding (list it under "suspicions, unverified").

RULES:
  - Verify against the CURRENT tree, not docs alone; re-read the cited Lean — do not
    trust quotes. Check git log for recent changes.
  - Distinguish "ships-broken" from "pre-production caveat behind a fence" (CLAUDE.md).
  - For each finding give: which V-mode, the exact file:line, the PoC, the
    disposition (CONFIRMED_REAL / FALSE_POSITIVE / ALREADY_FIXED / OPEN_RESEARCH),
    severity, and a proposed fix — flagging if the fix would break an invariant,
    regress a green proof, introduce a sorry/axiom, or "fix" correct code.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — the claims that survived, and the
     strongest single PoC-attempt that failed, per claim.
  2. "What I did NOT look at" — modalities not run, claims unverified, artifacts
     unread, V-modes not exhausted. This is the next round's target list.
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
