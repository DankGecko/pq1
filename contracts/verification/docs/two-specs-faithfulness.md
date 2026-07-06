# The Two Specs — Verifier vs Signer, and the Faithfulness Bridges

*For future reference — the open question behind FV-#4's completeness result
(`verify_signs` / `honest_consistent`). Nothing here is urgent or a soundness
problem; it is the thing to think about when deciding whether/how to strengthen
the completeness claim.*

## TL;DR

The SPHINCS+C10 verification stack contains **two distinct Lean specifications**,
and their faithfulness to reality stands on very different ground:

| Spec | Lean | Models | Anchored to reality? |
|------|------|--------|----------------------|
| **Verifier** | `Spec.Hypertree.verify`, `Spec.Wots.pkFromSig`, `Spec.Fors.reconstructForsPk`, … | the on-chain `SPHINCsC10Asm.verify` (and the Rust/firmware verifier) | **YES** — A3.1 (`execC10Asm = spec`) + the independent-KAT leg |
| **Signer** | `Spec.Signer.sign` (+ `grindR`, `findCount`, `Spec.Treehash.*`) | the firmware signer (`sphincs-c10/src/…::sign`) | **NO** — hand-written, `noncomputable`, *verifier-derived* |

Two theorems use them:

- **Safety** — `Spec.Theorems.theft_free`. Uses **only the verifier spec**
  (acceptance ⇒ verifier-returned-true ⇒ EUF-CMA). Never mentions the signer
  spec.
- **Completeness** — `Spec.Theorems.verify_signs` / `honest_consistent`.
  **Connects the two**: what the signer produces, the verifier accepts.

The whole point of this note: completeness's real-world meaning depends on the
signer spec being faithful, and right now **it is assumed, not checked**.

## Bridge (a): the verifier spec IS anchored — REAL

`Spec.…verify` is tied to the deployed contract:

- **A3.1** (`Interpreter/C10Refine.lean`, `execC10Asm_eq`): the statement-for-
  statement Yul transcription of `SPHINCsC10Asm.verify` provably equals the
  declarative verifier spec, **∀-input**, with SHA-256 kept opaque. Kernel-clean.
  Residual trust = the hand transcription (diff-checkable, lint-gated) + A1/A4/A5.
- **Independent-KAT leg**: a clean-room Python signer + the Rust verifier
  accept/reject the same KAT vectors byte-for-byte; `lake exe verify-test-vectors`
  runs the executable Lean verifier over them.

So "verifier spec = the on-chain verifier" is well-supported.

## Bridge (b): the signer spec is NOT anchored — ASSUMED

`Spec.Signer.sign` is:

- **hand-written** — a declarative model, not extracted from nor cross-checked
  against the firmware/Rust signer;
- **`noncomputable`** ("not intended to be executed") — so it can't be run
  against KATs directly;
- **verifier-derived** — it was *completed* (2026-06-29, commit `b75e5a47`) by
  reverse-engineering it to emit the verifier's own reconstruction shapes
  (`mtAuthPath` / `forsMtAuthPath` / `keygenPk`-chains), precisely so the
  round-trip hypotheses of `fors_pk_roundtrip` / `hypertree_roundtrip` discharge
  **by construction**.

**Consequence:** the completeness proof *cannot detect an unfaithful-but-self-
consistent `sign`.* If `sign` mis-derived an ADRS or used the wrong hash
convention, but the *same* wrong convention the verifier reconstruction uses,
the round-trip would still hold. So `honest_consistent` read as "firmware
signatures are accepted on-chain" rests on the **assumed** bridge
"spec-`sign` = the real firmware signer", which nothing currently checks.

### Why this is not a soundness hole

- The prior `sign` was a zero-array stub (already unfaithful); completing it
  introduced no false claim — it made an un-anchored, verifier-derived `sign`
  *load-bearing for the completeness claim*, that's all.
- Completeness is **not** in `theft_free`'s dependency closure → **safety is
  entirely unaffected**. A wrong signer can never make the wallet *accept a
  forgery*; at worst it would make the wallet *reject its own honest signatures*
  (a liveness/usability bug), and even that only if the signer and verifier
  disagree — which is exactly what an anchor would catch.
- Honest reading: *"the spec signer round-trips with the (anchored) spec
  verifier"* — a real structural result, just not yet pinned to the firmware at
  the signer end.

## The thinking task: how to anchor the signer spec (bridge (b))

To upgrade bridge (b) from *assumed* to *supported*, pick one (roughly
increasing cost / strength):

1. **KAT cross-check against the executable signer (cheapest meaningful step).**
   The independent-KAT leg already exercises the *executable* (Rust/Python)
   signer. Add a computable mirror of `Spec.Signer.sign` and a differential test
   that it reproduces the KAT signatures byte-for-byte — turning "verifier-derived
   `sign`" into "`sign` reproduces the same signatures the firmware emits". This
   does not need a Lean proof; a tested computable mirror + the existing KAT
   oracle already discharges most of the worry.

2. **`serialise`/`deserialise` + deployed path.** `Spec.Signature.serialise` /
   `deserialise` round-trips (`Bytes.lean`). Connect `sign`'s structured output
   through serialisation to the exact 4128-byte wire blob the firmware emits and
   the deployed verifier consumes, so the signer spec is pinned to the same bytes
   the anchored verifier path consumes.

3. **Extract the real signer (strongest, most work).** Aeneas-extract
   `sphincs-c10/src/…::sign` (as already done for other primitives) and prove the
   extracted model equals `Spec.Signer.sign`. This is the signer-side analogue of
   what A3.1 does for the verifier.

A sensible target: **(1) now** (cheap, catches the realistic failure mode — a
convention mismatch between signer and verifier), **(3) eventually** if the
completeness leg is ever promoted to a shipped guarantee rather than an internal
usability check.

## Pointers

- Theorem + inline trust-base note: `lean/SphincsCVerify/Verifier/HonestConsistent.lean`.
- Stack: `Spec/Signer.lean`, `Spec/SignerPost.lean`, `Spec/Treehash.lean`,
  `Verifier/{Merkle,Wots,Fors,Hypertree}Roundtrip.lean`.
- Scope + historical plan: `handoff-verify-signs-completeness.md` (CLOSED banner).
- Axiom tracking: `lean/scripts/dump_axioms.lean` (`honest_consistent` entry,
  closure `[propext, Classical.choice, Quot.sound]` — no new axiom).
- Verifier anchor (bridge (a)): `A3_1_CLOSURE_PATH.md`,
  `findings/A3_1_ADVERSARIAL_REVIEW_2026-06-18.md`, `THE_CLAIM.md`.
- Follow-up task: `docs/work-todo.md` → "FV-frontier follow-ups" →
  "Anchor `Spec.Signer.sign`".
