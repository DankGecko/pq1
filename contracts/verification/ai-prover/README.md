# §33 AI-prover loop

Drives a headless Claude Code agent to close ONE Lean proof obligation in
`contracts/verification/extracted/`, then GATES the result on the Lean
kernel and the axiom discipline. The kernel re-check is the trust
boundary: a wrong AI proof simply fails to compile, so AI output can
never compromise soundness (the same model as the rest of §33).

## Run one obligation
```
bash ai-prover/ai_prove.sh Extracted.Bits "Prove lor_eq_add_disjoint ... (see Bits.lean)"
```
The driver: snapshots `Extracted/`, runs the agent (restricted tools),
then requires (1) `lake build <module>` to succeed and (2) `#print axioms`
to show NO `sorryAx`. On any failure it rolls back. Validated 2026-06-10:
the axiom gate flags `sorryAx` on a stubbed lemma and passes a clean one.

## Permission model
By default NO `--dangerously-skip-permissions` (rejected by the agent
safety classifier when invoked interactively, and unsafe in general). A
scheduled CI runner that executes this in an ISOLATED sandbox (fresh
container, no secrets, restricted network) sets `AI_PROVE_SANDBOXED=1`
to add the bypass — appropriate only because the sandbox, not the
prompt, is the containment boundary there.

## Targets (open obligations to grind)
- `Extracted/Bits.lean` :: `lor_eq_add_disjoint` — the disjoint-OR=ADD
  fact, foundation of the read_bits_le accumulator invariant (the FORS
  bit-extraction functional spec, CWE-347 closure). Hand-attempted
  2026-06-10: the disjointness step proves easily; the `land=0 ⟹
  lor=add` bridge needs a non-obvious Mathlib lemma / from-scratch
  testBit proof — exactly the broad-search, iterate-against-the-compiler
  work this loop is for.
- See `Extracted/ForsExtractWIP.lean` for the full read_bits_le
  functional-spec roadmap once `lor_eq_add_disjoint` lands.

## Design notes
Mirrors the Lean-Squad pattern (research:
`docs/lean-verification-research-2026-06.md`) adapted to this
make-driven repo. `PROMPT_TEMPLATE.md` carries the project's proven
tactic patterns (loop.spec_decr_nat, step*, SetSliceLemmas, …) so the
agent reuses them instead of rediscovering.

---
**LEGACY (2026-06-11):** superseded by **LeanLoop**
(github.com/Nicola-Ceornea/LeanLoop) — the generalized, gated prover loop.
This repo now drives proofs via `contracts/verification/leanloop.toml` +
`goals.leanloop.toml` (see work-todo §33). The kernel/axiom gates pioneered
here live on in LeanLoop's audit module.
