# RECEIPT — `SphincsC10Content` in the closure, N1 discharged, 2026-07-28

Cache-invalidated (`ECO_PURGED=26`), every file an EXPLICIT target:
**4 base + 15 closure + 7 leaves = 26 files**, `CLOSURE_COMPILED == EXPECTED`
asserted, `WIRE_FAILURES=0`.

`SphincsC10Content.ec` had **never been compiled as a target** before today. It
holds every anti-vacuity result in the development, and its absence meant the
certified closure contained **no statement that the capstone is non-vacuous**.
It is now closure entry 15. Census: **0 admits, 0 axiom declarations.**

```
### ECO_PURGED=26  (0 is fine on a clean tree; >0 means the cache was stale)
OK   base/WOTS_TW_ES 126s
OK   base/FL_SL_XMSS_MT_ES 570s
OK   base/FORS_ES 401s
OK   base/SPHINCS_PLUS 177s
OK   Grind 1s
OK   STCR_C 0s
OK   WOTS_C_Real 3s
OK   WOTS_C_Scheme 3s
OK   XMSSMT_C_Scheme 2s
OK   WOTS_C_Reduction 4s
OK   WOTS_C_Interactive 29s
OK   XmssmtCC_All 764s
OK   RtopCSoundness 34s
OK   FxChain 69s
OK   FORS_C10 1s
OK   FORS_C10_Multi 1s
OK   GprocFORSC10 11s
OK   SphincsC10CapstoneWired 4s
OK   SphincsC10Content 4s
### CLOSURE_COMPILED=15 EXPECTED=15
### LEAVES (gated, NOT wired into the chain)
OK   leaf/EncoderBridge 1s
OK   leaf/Proj129 4s
OK   leaf/Extraction 2s
OK   leaf/Composition 2s
OK   leaf/PremiseReduction 2s
OK   leaf/Identification 2s
OK   leaf/ThCWidth 1s
### WIRE_FAILURES=0
WIREDONE
```

## N1 is now a THEOREM, not a premise

`EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL` carried four N-premises. It now carries
**three** (N2, N3, N4). N1 —

```
forall dgt, predC dgt <=> digitsum (encode_msgWOTS dgt) = target_sum
```

— was unprovable for **three independent reasons**, all of which had to go:

1. `predC` was abstract — fixed by the tie (commit `2170f77`).
2. `digitsum` (bigi over indices, `SphincsC10Content`) and `cw_sum` (sumz over
   the list, `WOTS_C_Real`) are **the same quantity** with **no bridge lemma**.
   Now `cw_sum_digitsum`.
3. The lemma **bound `(target_sum : int)` as a parameter**, SHADOWING the global
   `target_sum` the tie introduced. So even with 1 and 2 fixed, N1 could not be
   discharged *in place*. The binder is removed.

Result: `N1_holds`, and the premise is gone from the statement.

## A FLAKY PROOF, found by the failing run — and it invalidated earlier receipts

The first run with the 15-entry closure reported `FAIL leaf/Proj129 rc=1` at

```ec
have h8 : 8 = 2 ^ 3 by smt().
```

Standalone recompilation gave `rc=0` with identical include paths, and **5/5 cold
runs passed on an idle machine**. So the goal is trivial but the *proof* was
nondeterministic: it timed out under full-chain load. **The run was measuring
machine load, not the proof** — which means any receipt containing that lemma was
untrustworthy, including several produced earlier today.

Found in **three** places, not just the one that failed
(`EncoderBridge.ec:115`, `Proj129.ec:130,133`). All three now use a shared,
deterministic `pow8` with **no SMT call at all**:

```ec
lemma pow8 : 8 = 2 ^ 3.
proof. by rewrite (_ : 3 = 2 + 1) 1:// exprS 1:// (_ : 2 = 1 + 1) 1:// exprS 1:// expr1. qed.
```

`Proj129` also got faster: 10s -> 4s.

**Remaining flakiness surface, stated rather than glossed:** the leaves still
contain ~22 bare `smt()` calls. The ones fixed were the known-flaky class
(concrete exponentiation); the rest are small linear-arithmetic goals and are
*probably* robust — but that is not established, and this incident shows the
failure mode is real, silent, and load-dependent.

## Not established

`Pr[G /\ COLL]` remains uncharged. `WOTS_TW_ES.ec:1353` remains ADMITTED. N2
remains a premise and is **independent** (`FINDING-n2-is-independent.md`).
`SphincsC10Content`'s own header records that its N1 witness is existential over
the target and **not** at the deployed `TARGET_SUM = 205` — the same caveat this
session reached independently. **C10 is not proven at deployed parameters.**
