# RECEIPT — full chain WITH the predC tie installed, 2026-07-27/28

`predC` is no longer an abstract, axiom-free op: `cdrafts/WOTS_C_Real.ec` now
DEFINES it as `cw_sum (encode_msgWOTS d) = target_sum`. This is the receipt that
the edit did not break the chain.

Cache-invalidated (`ECO_PURGED=25`); every file an EXPLICIT target:
**4 base + 14 closure + 7 leaves = 25 files**, `CLOSURE_COMPILED == EXPECTED`
asserted, `WIRE_FAILURES=0`.

The four files that actually exercise the change — `WOTS_C_Real` (edited),
`WOTS_C_Scheme`, `WOTS_C_Reduction`, `WOTS_C_Interactive` (the main `predC`
consumer) — all compiled at their usual timings, so making `predC` transparent
did not perturb `smt()`.

> **TIMING CAVEAT:** `base/FORS_ES 57849s` (~16 h) is a machine-suspend artifact
> spanning the date change, NOT a compile time. The OK/FAIL verdicts are
> unaffected; only the elapsed-time column in this run is unreliable. Prior runs
> put `FORS_ES` at 375-384 s.

Leaves remain **GATED, NOT WIRED** — none is in `closure-c10.txt` and nothing
requires them.

```
### ECO_PURGED=25  (0 is fine on a clean tree; >0 means the cache was stale)
OK   base/WOTS_TW_ES 121s
OK   base/FL_SL_XMSS_MT_ES 584s
OK   base/FORS_ES 57849s
OK   base/SPHINCS_PLUS 176s
OK   Grind 1s
OK   STCR_C 1s
OK   WOTS_C_Real 2s
OK   WOTS_C_Scheme 2s
OK   XMSSMT_C_Scheme 3s
OK   WOTS_C_Reduction 4s
OK   WOTS_C_Interactive 28s
OK   XmssmtCC_All 750s
OK   RtopCSoundness 33s
OK   FxChain 67s
OK   FORS_C10 1s
OK   FORS_C10_Multi 1s
OK   GprocFORSC10 11s
OK   SphincsC10CapstoneWired 3s
### CLOSURE_COMPILED=14 EXPECTED=14
### LEAVES (gated, NOT wired into the chain)
OK   leaf/EncoderBridge 3s
OK   leaf/Proj129 10s
OK   leaf/Extraction 2s
OK   leaf/Composition 2s
OK   leaf/PremiseReduction 2s
OK   leaf/Identification 2s
OK   leaf/ThCWidth 1s
### WIRE_FAILURES=0
WIREDONE
```

## Tie gate (`gate_predc_tie.sh`)

A chain edit that compiles proves nothing on its own — an added comment would
also compile. The receipt is that a lemma **not statable before the tie** is
provable after it, and stops being provable when the tie is removed.

```
COPY_IDENTICAL=yes   BASE_RC=0   ADMITS=0   AXIOM_DECLS_IN_FILE=0
MUTATED_A=1  NEGCTL_A_RC=1   inject `lemma : false`              -> FAILS
MUTATED_B=1  NEGCTL_B_RC=1   revert predC to abstract            -> FAILS
SRC_UNTOUCHED=yes    FINAL_RC=0
```

**Control B verified to fail for the RIGHT reason**, not incidentally:

```
[critical] [WOTS_C_Real.ec: line 222 (7-25)] [by]: cannot close goals
```

Line 222 is `proof. by rewrite /predC. qed.` — the proof of `predC_iff_sum`.
Without the tie, `predC d <=> cw_sum (encode_msgWOTS d) = target_sum` is
unprovable, which is precisely the property that was missing.

**`ADMITS=0 AXIOM_DECLS_IN_FILE=0` is the other half of the receipt:** the tie is
a DEFINITION, so it adds nothing to the axiom census and cannot introduce
inconsistency. An `axiom predC_is_sum : ...` would have traded a vacuity hazard
for a consistency hazard.

## First gate-run was INVALID, and the baseline caught it

The initial run reported `BASE_RC=1` — the unmutated copy failed, because the
include path omitted `cdrafts` and `require STCR_C` could not resolve. Every
control would have "passed" for that reason. Recorded because it is exactly the
failure mode the `MUTATED_*` witnesses and the baseline check exist to catch.
