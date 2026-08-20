# FINDING — `GprocT1Opre` fails under GATE LOAD on either driver, and passes cold

2026-08-19/20, observed while gating the policy-cap fence. Recorded because a gate
phase that can fail on an unchanged tree makes every receipt containing it partly a
measurement of machine load rather than of the proofs.

---

## THE OBSERVATION

Same file, same toolchain, same prover set, **zero source changes** between the runs
(`git diff HEAD -- cdrafts-split/GprocT1Opre.ec` empty at both):

| run | identity | PHASE 1 (compile) | PHASE 1e (cli) |
|---|---|---|---|
| `gate_run1_scope.log` | `bcb2f295` | `OK GprocT1Opre` | `OK GprocT1Opre (cli, 880 cmds)` |
| `gate_run2_scope.log` | `bcb2f295` | `OK GprocT1Opre` | `OK GprocT1Opre (cli, 880 cmds)` |
| **`gate_run1_fence.log`** | `2fcbf2ef` | `OK GprocT1Opre` | **`FAIL … 473 diagnostic(s)`** |
| `gate_run2_fence.log` | `2fcbf2ef` | `OK GprocT1Opre` | `OK GprocT1Opre (cli, 880 cmds)` |
| `gate_run3_fence.log` | `84ebde0d` | `OK GprocT1Opre` | `OK GprocT1Opre (cli, 880 cmds)` |

The failing diagnostics were `cannot prove goal (strict)` and `[by]: cannot close
goals` — an **smt** failure, not a syntax or typing failure. `CLI_DISAGREEMENTS` went
`0 -> 1 -> 0`.

## WHAT IS AND IS NOT ESTABLISHED

**Established:** the `cli` leg of PHASE 1e is **not deterministic** on this machine at
this toolchain. **One run in five** disagreed with the compile driver on a file nobody had
touched.

**Not established: the cause.** The leading hypothesis is prover load/timeout, which
has in-repo precedent — `EncoderBridge.pow8` carries a comment recording an `smt()`
that "timed out under full-chain load while passing cold", rewritten to be
deterministic *because a flaky proof makes every receipt a measurement of machine
load*. Consistent with that: during run 1 of the fence I was also running
`docker exec ec-grind python3 tools/policy_cap_fence.py` and other probes **in the
same container**; during run 2 I deliberately ran nothing. That is suggestive, but it
is a quasi-experiment with one trial per arm, not a controlled measurement, and I am
not claiming it as the cause.

**One state difference was found and RULED OUT.** `gate_run1_fence.log` reports
`ECO_PURGED=37` while the others report `38`, `38` and `0` — a real difference in the receipt,
worth chasing. It is fully explained: a cleanup step deleted
`cdrafts-split/C10DeployedScope.eco` between the runs, so one fewer `.eco` existed at
purge time. And it **cannot be causal**: all five runs report `ECO_REMAINING=0`, so
every run began from an identical zero-`.eco` state regardless of how many were purged.
Chased on an external reviewer's prompt; a good lead with a negative result.

**Also not established:** whether the 473 diagnostics were one root failure cascading
or 473 independent ones. Only the first two lines were captured by the gate's own
truncation.

## WHY THIS MATTERS MORE THAN ONE RED RUN

The gate's value is that GREEN means something. A phase that flakes has three bad
consequences, in increasing order of seriousness:

1. A real regression can be dismissed as "probably the flake" — the reverse of what
   happened here.
2. **The re-run-until-green reflex.** The correct response to run 1 was to re-run and
   *report both*, which is what happened. The tempting response is to re-run and keep
   the green one, which converts the gate into a slot machine.
3. It undermines the byte-identical-receipt discipline this tree relies on elsewhere
   (four consecutive byte-identical GREEN runs were previously used as evidence that
   a change was isolated).

## WHAT I DID, AND WHAT I DID NOT DO

**Did:** published BOTH receipts (`gate_run1_fence.log` RED, `gate_run2_fence.log`
GREEN), stated the failure in the commit message rather than only the success, and
confirmed the file was untouched before attributing anything.

**Did not:** re-run repeatedly to manufacture a clean pair, or silently drop the RED
log. Both receipts are vendored.

## THE ACTIONABLE PART

Not urgent — nothing certified is wrong, and the compile driver (the authoritative
one) passed in all four runs. But if the `cli` cross-check is to stay a gate phase:

1. **Pin its budget.** Give the cli leg an explicit `-timeout` / `-max-provers` the
   way the bridge diagnosis run did, so it is not at the mercy of ambient load.
2. **Report a cli disagreement as its own status**, distinct from a proof failure —
   a driver disagreement on an unchanged file is a *toolchain* signal, not a
   mathematical one.
3. **Or make the offending step deterministic**, the fix already applied once in this
   repo to `EncoderBridge.pow8`.

Until one of those is done, treat a lone `CLI_DISAGREEMENTS=1` on an unchanged tree as
**unexplained**, and re-run — but publish both receipts, every time.


---

## UPDATE 2026-08-20 — it is NOT the cli leg, and it IS a budget problem. Measured.

Both of my earlier framings were wrong, in opposite directions.

**Framing 1 (too narrow):** *"the `cli` leg of PHASE 1e is not deterministic."* Refuted —
on 2026-08-20 `GprocT1Opre` failed **PHASE 1, the COMPILE driver**, while
`CLI_DISAGREEMENTS=0` in the same run. It is the FILE, not the leg.

**Framing 2 (too alarming):** *"a closure member contains a proof step that does not
reliably discharge."* Also refuted, and this is the one I would have published had I
stopped at the failure. Compiled **in isolation with a pinned budget**
(`-timeout 60 -max-provers 4`, nothing else running):

| run | result |
|---|---|
| 1 | 0 critical, `.eco` produced |
| 2 | 0 critical, `.eco` produced |
| 3 | 0 critical, `.eco` produced |

**3/3 clean, ~4 minutes each.** The proof discharges reliably when given room.

## THE ACTUAL DIAGNOSIS

`GprocT1Opre.ec` needs ~4 minutes of prover time **on its own**. Inside a full gate run
it competes with 33 other closure members across 25 prover configurations. It sits close
enough to its budget that contention tips it over — on **either** driver, which is
exactly why it looked like a cli-leg problem the first time.

Tally across seven full-gate runs: **2 failures** (one cli with 473 diagnostics, one
compile), 5 passes, file byte-unchanged throughout (`git diff HEAD` empty each time).
Plus 3/3 cold passes in isolation.

This is the `EncoderBridge.pow8` pattern this repo already documents — *"timed out under
full-chain load while passing cold"*, rewritten to be deterministic precisely because a
flaky proof makes every receipt a measurement of machine load.

## WHAT THIS DOES AND DOES NOT MEAN

**Does not mean** the certified artifact is wrong. The proof is fine; the compile driver
passed in 5 of 7 runs and 3 of 3 cold.

**Does mean** any single GREEN receipt containing this file is partly a measurement of
machine load, and that a real regression in it could be waved away as "the known flake" —
the reverse of what happened here.

## THE FIX, in the repo's own idiom

1. **Pin the budget for this file** — an explicit `-timeout`/`-max-provers` for
   `GprocT1Opre` in PHASE 1, so it is not at the mercy of ambient load. Cheapest.
2. **Or make the offending step deterministic**, as was done once for
   `EncoderBridge.pow8`.
3. **Report a load-induced failure distinctly** from a proof failure, so the two cannot
   be confused in either direction.

Not done here: this change was about cone coverage, and folding an unrelated gate-timing
fix into it would make the receipt harder to read, not easier. Named as the next unit.
