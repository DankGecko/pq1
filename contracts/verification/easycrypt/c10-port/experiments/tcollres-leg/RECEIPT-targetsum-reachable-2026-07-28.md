# RECEIPT — full chain with `TargetSumReachable` discharged, 2026-07-28

`target_sum` was a FREE `const int`. It is now DEFINED as `cw_sum (encode_msgWOTS
tgt_witness)`, so `TargetSumReachable` is a theorem (`targetSumReachable`), with
**zero new axioms**.

Cache-invalidated (`ECO_PURGED=25`), every file an EXPLICIT target: 4 base + 14
closure + 7 leaves = **25 files**, `CLOSURE_COMPILED == EXPECTED`, `WIRE_FAILURES=0`.
Timings are normal throughout this run (contrast the previous receipt, whose
`FORS_ES 57849s` was a machine-suspend artifact).

```
### ECO_PURGED=25  (0 is fine on a clean tree; >0 means the cache was stale)
OK   base/WOTS_TW_ES 122s
OK   base/FL_SL_XMSS_MT_ES 568s
OK   base/FORS_ES 388s
OK   base/SPHINCS_PLUS 168s
OK   Grind 0s
OK   STCR_C 1s
OK   WOTS_C_Real 2s
OK   WOTS_C_Scheme 2s
OK   XMSSMT_C_Scheme 3s
OK   WOTS_C_Reduction 3s
OK   WOTS_C_Interactive 26s
OK   XmssmtCC_All 711s
OK   RtopCSoundness 32s
OK   FxChain 70s
OK   FORS_C10 1s
OK   FORS_C10_Multi 3s
OK   GprocFORSC10 13s
OK   SphincsC10CapstoneWired 3s
### CLOSURE_COMPILED=14 EXPECTED=14
### LEAVES (gated, NOT wired into the chain)
OK   leaf/EncoderBridge 4s
OK   leaf/Proj129 10s
OK   leaf/Extraction 2s
OK   leaf/Composition 2s
OK   leaf/PremiseReduction 2s
OK   leaf/Identification 2s
OK   leaf/ThCWidth 1s
### WIRE_FAILURES=0
WIREDONE
```

## Gate (`gate_predc_tie.sh`)

```
COPY_IDENTICAL=yes   BASE_RC=0   ADMITS=0   AXIOM_DECLS_IN_FILE=0
MUTATED_A=1  NEGCTL_A_RC=1   inject `lemma : false`                 -> FAILS
MUTATED_B=1  NEGCTL_B_RC=1   revert predC to abstract               -> FAILS
MUTATED_C=1  NEGCTL_C_RC=1   revert target_sum to a free const      -> FAILS
SRC_UNTOUCHED=yes    FINAL_RC=0
```

**Control C is the new one.** Putting `target_sum` back to `const target_sum :
int.` makes `targetSumReachable` unprovable — so reachability is a theorem ONLY
because the target is defined as a value the encoder attains. Without that, the
lemma would be proving something it does not depend on.

## Read the result narrowly

The accurate description is **"`target_sum` is now defined as an attained value,
which makes reachability a theorem"** — NOT "reachability was proven about the
encoder."

| | status |
|---|---|
| `predC := fun _ => false` | **KILLED.** The dangerous degeneracy: acceptance always false, LHS of the bound zero, every gate-conditioned statement vacuous. |
| `predC := fun _ => true` | **NOT killed.** A constant `encode_msgWOTS` satisfies `two_encodings` (hypothesis never met) and `enc_nonzero`. Ruling it out needs two digests with different codeword sums; neither axiom provides them — incomparable codewords may share a sum. Consequence, stated precisely rather than as "less harmful": with the gate always true it vanishes from acceptance, so S-TCR(+C) is assumed about a scheme with NO filter — a different assumption from the one the ledger names. |
| N2 (`exists c, predC (ThC ps ad m c)`) | **NOT touched.** |
| deployed target 205 reachable | **NOT established** here. |

### Why N2 is untouched — the quantifiers differ decisively

```
targetSumReachable : exists (d : dgstblock),      predC d
N2                 : exists (c : cntr), predC (ThC ps ad m c)
```

N2 ranges over `ThC`'s image **at a fixed `(ps, ad, m)`**, indexed by counters.
`tgt_witness` need not lie in that image for any particular instance, so knowing
ONE digest attains the target says nothing about whether the grind succeeds at a
GIVEN one. N2 remains a premise (`wotsc_grind_targets_predC`, `WOTS_C_Real.ec:260`)
and still carries its uncharged probability term: the firmware bounds the grind at
`0..10_000_000` and PANICS on failure (`sphincs-c10/src/wots.rs:62-74`), a
strictly smaller search than the model's never-failing `grind` (`Grind.ec:79-80`).

`Pr[G /\ COLL]` remains uncharged. `WOTS_TW_ES.ec:1353` remains ADMITTED.
**C10 is not proven at deployed parameters.**
