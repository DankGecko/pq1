# RECEIPT — leaves WIRED, 2026-07-28

Cache-invalidated, every file an EXPLICIT target: **4 base + 16 closure + 7
leaves**, `CLOSURE_COMPILED == EXPECTED`, `WIRE_FAILURES=0`.

`cdrafts/LeafWiring.ec` is closure entry 16 and is the first closure file that
`require`s a leaf. The closure loop in `wire_test.sh` now carries `-I $L` so it
can.

```
### ECO_PURGED=27  (0 is fine on a clean tree; >0 means the cache was stale)
OK   base/WOTS_TW_ES 126s
OK   base/FL_SL_XMSS_MT_ES 581s
OK   base/FORS_ES 390s
OK   base/SPHINCS_PLUS 180s
OK   Grind 1s
OK   STCR_C 0s
OK   WOTS_C_Real 3s
OK   WOTS_C_Scheme 2s
OK   XMSSMT_C_Scheme 3s
OK   WOTS_C_Reduction 4s
OK   WOTS_C_Interactive 27s
OK   XmssmtCC_All 740s
OK   RtopCSoundness 33s
OK   FxChain 69s
OK   FORS_C10 1s
OK   FORS_C10_Multi 2s
OK   GprocFORSC10 11s
OK   SphincsC10CapstoneWired 4s
OK   SphincsC10Content 4s
OK   LeafWiring 3s
### CLOSURE_COMPILED=16 EXPECTED=16
### LEAVES (gated, NOT wired into the chain)
OK   leaf/EncoderBridge 1s
OK   leaf/Proj129 2s
OK   leaf/Extraction 2s
OK   leaf/Composition 2s
OK   leaf/PremiseReduction 2s
OK   leaf/Identification 1s
OK   leaf/ThCWidth 1s
### WIRE_FAILURES=0
WIREDONE
```

## The request, answered honestly

"Wire the leaves into the closure." The obvious way — assume the chain's abstract
`encode_msgWOTS` transcribes to the leaves' digit map, then import their
conclusions — is **POISONED, not merely blocked**.

`two_encodings` (`base-c10/WOTS_TW_ES.ec:579`) is a GLOBAL AXIOM demanding that
distinct codewords be pointwise incomparable. The base-wd digit map is not:
`int2dig len 0` is the all-zero codeword and is dominated by every other. So the
transcription CONTRADICTS an axiom already in the closure, and a bridge assuming
it would prove everything ex falso — compiling cleanly, reporting 0 admits, and
certifying nothing.

**This is now a theorem, not an argument:**

```ec
lemma naive_transcription_is_poisoned : ... => NaiveTranscription toint => false.
lemma naive_transcription_proves_anything : ... => NaiveTranscription toint => P.
```

The second exists so a future author sees why such a file is *dangerous* rather
than merely useless.

## What "wired" means here, precisely

`LeafWiring` genuinely REQUIRES and CONSUMES a leaf — `EncoderBridge`'s `int2dig`
and `int2dig_inj` do real work in the proof. The leaf is now a dependency of a
chain file, not a file compiled beside one. That is wiring in the only sound
sense available.

**It is NOT** the capstone consuming a leaf conclusion. That cannot be done:
strong wiring requires `two_encodings` relativized to predC digests, which needs
the ~3450-line MM45 fork (`FL_SL_XMSS_MT_ES.ec:6342` consumes
`MEUFGCMA_WOTSTWESNPRF` via a reduction querying the WOTS-TW oracle on SUBTREE
ROOTS, which satisfy no predC, so a gated game cannot serve it).

The sound shape is recorded as `GatedTranscription` — deliberately **unproven and
unassumed** — so the remaining gap is a named object in a compiled closure file
rather than a paragraph in a comment.

## AXIOM COST — the closure census is no longer axiom-free

`require import EncoderBridge` brings **`axiom gt1_wd : 1 < wd`** into the
closure. It constrains EncoderBridge's OWN fresh abstract `wd` and is satisfiable
(`wd := 8`), so it CANNOT introduce inconsistency — but it is now in the census
and belongs in the ledger, not a footnote. `LeafWiring` itself: 0 admits, 0 axiom
declarations.

## Unchanged

`Pr[G /\ COLL]` uncharged. `WOTS_TW_ES.ec:1353` ADMITTED. N2 independent.
**C10 is not proven at deployed parameters.**
