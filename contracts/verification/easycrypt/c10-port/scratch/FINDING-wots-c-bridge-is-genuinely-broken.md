# FINDING — `WOTS_C_Bridge.ec` is genuinely broken, not budget-starved

2026-08-18. Diagnosis requested after the file was found not to compile while its
header claims a completed proof.

---

## VERDICT: GENUINE BREAK. Not a prover-budget artefact.

The natural hypothesis was budget. This repo has precedent — `EncoderBridge.pow8`
carries a comment recording an `smt()` that "timed out under full-chain load while
passing cold", rewritten to be deterministic because a flaky proof makes every
receipt containing it a measurement of machine load rather than of the proof. And
the failing tactic is exactly that shape:

```
cdrafts-split/WOTS_C_Bridge.ec   (:659 in the file state measured below)
  by rewrite hoq; do ! split; smt().
```

a **terminal `smt()`**. So it was tested rather than assumed.

**Measured, at r2026.02 in the container:**

| run | file state | options | result |
|---|---|---|---|
| default | pre-note | gate defaults | `[critical] :659 cannot prove goal (strict)`, `__RC=1`, no `.eco` |
| extended | pre-note | `-timeout 120 -max-provers 8` | **same line, same error**, `__RC=1`, no `.eco`, **wall 2592 s** |
| default (re-run) | post-note | gate defaults | same tactic, same error, reported at **`:693`**, `__RC=1`, no `.eco` |

Forty-three minutes at a 120-second per-call budget across eight provers, failing
identically. **The budget hypothesis is refuted.**

**Read the receipts with their file state attached.** `bridge_timeout.out` prints
`:659` and `bridge.out` prints `:693` — the two runs are on *different versions of
the file*, because the status-correction note (39 lines, added between them) sits
above the failing tactic. Same tactic, same error, same `disj_wgpidxs` step. The
line numbers disagree; nothing else does. This is the third time in this one
correction that a line reference went stale under its own edit, which is the
reason everything here is anchored on tactic text.

## THE MECHANISM — named by the repo's own commit message

```
$ git log -1 --date=short -- cdrafts-split/WOTS_C_Bridge.ec
fe2b22f 2026-08-01  fix(split): route (D) retypes in the NON-CERTIFIED bridge/multi side-files
```

Route (D) — the message-type split that widened `msgWOTS` to the 256-bit
`mdgstblock` — landed the same day (`ea1087f`, 2026-08-01), touching both
`base-c10-split/WOTS_TW_ES.ec` and `cdrafts-split/WOTS_C_Real.ec`.

So the side-files were **retyped to keep them type-correct** under the split. The
commit message calls them "NON-CERTIFIED", and the gate does not build them — so
the retype made the file **typecheck** without anyone confirming it still
**proves**.

The header's claim dates from *before* that change:

```
:379   PROOF STATUS (2026-07-08): PROVED IN FULL — ZERO admits.
```

**2026-07-08 proof status; 2026-08-01 retype; never re-verified.**

Note the contrast that makes this diagnosis specific rather than generic:
`WOTS_C_Multi.ec` went through the *same* retype in the *same* commit and **does**
compile (`__RC=0`, now gated). The retype worked there and not here.

## WHAT I AM NOT CLAIMING

* **Not** that the proof passed before the retype. The header asserts it, and the
  dates are consistent, but I did not reconstruct a pre-split checkout (old file
  against new dependencies fails for type reasons; a clean test needs both sides
  rolled back). So "broken *by* the retype" is the strongly-indicated cause, not a
  demonstrated one.
* **Not** that the goal at that tactic is false. `smt` failing is not a refutation. It
  may be provable with different hints, a restructured step, or by hand.
* **Not** that anything certified is affected. `WOTS_C_Bridge`,
  `WOTS_C_EmbDischarge` and `SPHINCS_C` are all outside `closure-c10-split.txt`;
  the gate is GREEN at `45b788a6…` without them.

## WHY IT MATTERS ANYWAY

`D1_bridge_WOTSTW` (`:433`, `qed` `:707` — the failing line is inside its own
proof) is the head of the chain that connects the `STCRC_WC.Col` world to the
repo's `FC` world: `D1_bridge_WOTSTW` → `D1_MEUFNACMA_WOTSC_MM45` (`:719`) →
`..._embthfc` (`WOTS_C_EmbDischarge.ec:174`) → consumed at `SPHINCS_C.ec:252`.

That is the chain I previously mis-reported as absent. It exists — and its first
link does not currently compile, while advertising that it does.

## THE ACTIONABLE PART

The defect that allowed this is **not** the failing `smt()`. It is that a file
carrying a "PROVED IN FULL" header sits outside the gate, so a mechanical retype
could break it silently and the header keeps asserting the old status. Options,
cheapest first:

1. **Correct the header** to state the measured status. One line, no proof work,
   removes a false claim from the tree today.
2. **Gate it** — but only *after* it compiles; adding a red file to the closure
   turns the gate red by construction.
3. **Repair the failing step**, then (2). This is real proof work of unknown size: the goal
   is a `disj_wgpidxs` bookkeeping step, and the surrounding context was retyped
   under the split.

(1) is unambiguous and I would do it regardless of whether (3) is attempted.
