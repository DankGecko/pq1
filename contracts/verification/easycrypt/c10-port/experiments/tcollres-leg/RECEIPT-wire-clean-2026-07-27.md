# RECEIPT — cache-invalidated full-chain rebuild, 2026-07-27 (five-leaf, FINAL)

Supersedes the four-leaf run earlier the same day, which was **stale about its own
scope**: it certified four leaves while `wire_test.sh` had grown to five, because
`PremiseReduction` was added to the leaves list after that run finished. That
matters because `PremiseReduction` is the only leaf that `require`s the heavy
chain, and its sole clean-cache evidence had been `gate_premisereduction.sh`,
which purges only its own `.eco` and reused `base-c10/*.eco` + `cdrafts/*.eco`
from the just-finished run. Those were fresh, so the result was probably right —
but "probably right because the timing worked out" is exactly the shape a receipt
exists to rule out. Found in review, not by me.

This run purges first (`ECO_PURGED=23`) and compiles **every** file as an
EXPLICIT target: 4 base + 14 closure + 5 leaves = **23 files**.

`CLOSURE_COMPILED == EXPECTED` is asserted, so a silently truncated closure
cannot read as green.

**Leaves are GATED, NOT WIRED.** None appears in `closure-c10.txt`; nothing in the
PQ1 chain `require`s them. Compiling here proves they do not rot and keeps their
negative controls meaningful. It does **not** make them chain progress.

```
### ECO_PURGED=23  (0 is fine on a clean tree; >0 means the cache was stale)
OK   base/WOTS_TW_ES 116s
OK   base/FL_SL_XMSS_MT_ES 564s
OK   base/FORS_ES 375s
OK   base/SPHINCS_PLUS 173s
OK   Grind 1s
OK   STCR_C 1s
OK   WOTS_C_Real 3s
OK   WOTS_C_Scheme 3s
OK   XMSSMT_C_Scheme 3s
OK   WOTS_C_Reduction 3s
OK   WOTS_C_Interactive 26s
OK   XmssmtCC_All 728s
OK   RtopCSoundness 33s
OK   FxChain 67s
OK   FORS_C10 1s
OK   FORS_C10_Multi 1s
OK   GprocFORSC10 10s
OK   SphincsC10CapstoneWired 3s
### CLOSURE_COMPILED=14 EXPECTED=14
### LEAVES (gated, NOT wired into the chain)
OK   leaf/EncoderBridge 4s
OK   leaf/Proj129 10s
OK   leaf/Extraction 2s
OK   leaf/Composition 2s
OK   leaf/PremiseReduction 2s
### WIRE_FAILURES=0
WIREDONE
```
