# FINDING — a certified-chain member's `cli` check failed on an UNCHANGED tree, then passed

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
