# RECEIPT — SMT hardening of the leaves, 2026-07-28

Two load-sensitive `smt()` calls eliminated; the rest MEASURED rather than
assumed. Cache-invalidated (`ECO_PURGED=26`), 4 base + 15 closure + 7 leaves =
**26 files**, `CLOSURE_COMPILED == EXPECTED`, `WIRE_FAILURES=0`.

```
### ECO_PURGED=26  (0 is fine on a clean tree; >0 means the cache was stale)
OK   base/WOTS_TW_ES 128s
OK   base/FL_SL_XMSS_MT_ES 601s
OK   base/FORS_ES 400s
OK   base/SPHINCS_PLUS 179s
OK   Grind 0s
OK   STCR_C 1s
OK   WOTS_C_Real 2s
OK   WOTS_C_Scheme 3s
OK   XMSSMT_C_Scheme 2s
OK   WOTS_C_Reduction 4s
OK   WOTS_C_Interactive 31s
OK   XmssmtCC_All 756s
OK   RtopCSoundness 33s
OK   FxChain 71s
OK   FORS_C10 1s
OK   FORS_C10_Multi 1s
OK   GprocFORSC10 11s
OK   SphincsC10CapstoneWired 3s
OK   SphincsC10Content 4s
### CLOSURE_COMPILED=15 EXPECTED=15
### LEAVES (gated, NOT wired into the chain)
OK   leaf/EncoderBridge 2s
OK   leaf/Proj129 2s
OK   leaf/Extraction 2s
OK   leaf/Composition 2s
OK   leaf/PremiseReduction 2s
OK   leaf/Identification 1s
OK   leaf/ThCWidth 1s
### WIRE_FAILURES=0
WIREDONE
```

## The measurement that mattered

I first classified the remaining `smt()` calls **by inspection**, concluded only
one was in the risky class, fixed it, and a 4-burner stress run showed 0/5
failures. That looked finished. **It was wrong.**

At full 24-core saturation `Proj129` failed **5/5** while every other leaf passed
5/5. Controlled before/after, same harness (`stress_leaves.sh`, committed):

| leaf | before fix | after fix |
|---|---|---|
| **Proj129** | **5/5 failures** | **0/5** |
| EncoderBridge, Extraction, Composition, PremiseReduction, Identification, ThCWidth | 0/5 | 0/5 |

## The two sites, and why they were hard for SMT

1. `8 = 2^3` (`EncoderBridge:115`, `Proj129:130,133`, `Identification:158`) —
   concrete exponentiation. Now the shared deterministic `pow8`.
2. `Proj129.ec:89`, `rewrite ih; first 2 by smt(ltz_divLR gt0_wd exprS divz_ge0)`
   — reasoning about `wd^l` vs `wd^(l+1)` with a **SYMBOLIC exponent**. This was
   the site that actually failed, and it is much harder than any concrete power.
   Discharged by hand: `0 <= n %/ wd < wd^l` from `n < wd^(l+1)` via
   `ltz_divLR` + `exprS` + `mulzC`; `0 <= c < wd` was already in context.

Note (1) was NOT the cause of the observed failure. Inspection pointed at the
wrong site; only measurement found the right one.

## What was NOT done

The remaining ~18 bare `smt()` calls are **not** eliminated. They survive full
saturation 5/5, so they are **empirically robust** — a stronger and more honest
statement than the earlier "probably robust". They are small linear goals where
SMT is the appropriate tool.

## Harness design note

`stress_leaves.sh` loads the box with **CPU burners, not concurrent EasyCrypt
runs**. Parallel compiles would race on the same `.eco` files and produce
corruption rather than the timing pressure being tested — a different failure
mode that would have masked this one.

## Mechanism NOT settled

The stress data shows load-sensitivity, but the original failure occurred at the
LOW load of an ordinary wire run (~5 processes on 24 cores), which saturation
does not explain. Inherent SMT nondeterminism is equally consistent with the
evidence. The deterministic fix removes the risk either way; the mechanism is
not established and should not be quoted as if it were.

`Pr[G /\ COLL]` remains uncharged. `WOTS_TW_ES.ec:1353` remains ADMITTED.
**C10 is not proven at deployed parameters.**
