# RESULT — F1: the `log2_w` admissibility half is CHEAP; the geometry half is untouched

Companion to `PREDICTION-f1.md` (written before compiling).

## Headline

**C10's `log2_w = 3` is admissible after THREE one-line declaration changes and
ONE lemma weakening.** The entire MM45 base then recompiles:

```
WOTS_TW_ES        rc=0  128s
FL_SL_XMSS_MT_ES  rc=0  563s     (was failing at 2s before the fix)
FORS_ES           rc=0  393s
SPHINCS_PLUS      rc=0  183s
```

F1 was catalogued as a hard blocker with an 88-site cascade. **That estimate was
wrong, and this measurement corrects it.**

## What the 88 sites actually turned out to be

`val_w : w = 4 \/ w = 16 \/ w = 256` is FALSE at C10 (`w = 8`) and has 88 uses:
14 in `WOTS_TW_ES`, 28 in `FL_SL_XMSS_MT_ES`, 46 in `SPHINCS_PLUS`. But almost
all are `smt(... val_w ...)` hints that only ever wanted a LOWER BOUND.

Weakening it to **`val_w : 4 <= w`** left **60 of 88 uses passing untouched**
(all of `WOTS_TW_ES`, `FORS_ES`, `SPHINCS_PLUS`). The single genuine failure was
`FL_SL_XMSS_MT_ES:578`, `realize val_log2w by exact: val_log2w` — a CLONE
REALIZATION feeding the old trichotomy to the relaxed obligation, because
`FL_SL_XMSS_MT_ES` and `SPHINCS_PLUS` each carry their OWN copy of the
constraint. Three declarations, not 88 proofs.

## The exact diff

| change | site |
|---|---|
| `log2_w : {int \| 2 <= log2_w}` (was `= 2 \/ 4 \/ 8`) | `WOTS_TW_ES:34`, `FL_SL_XMSS_MT_ES:32`, `SPHINCS_PLUS:42` |
| `val_w : 4 <= w` (was the trichotomy) | `WOTS_TW_ES` |

`2 <= log2_w` (not `1 <=`) is chosen deliberately: it keeps `4 <= w` provable
while admitting C10's 3 and all of MM45's 2/4/8.

## Census — with the cost stated, not buried

* **Admits: 1**, and it is the INHERITED T-COLL-RES gap from unit 1, not new.
* **Axioms: +1 — `val_len1`, and it is a MEASUREMENT STUB THAT IS FALSE AT C10**
  (`len1 = 43` vs `4n = 64 / 2n = 32 / n = 16`). It is marked never-keepable
  in-file. Its 5 local uses are real repair work, NOT done.

**So this tree is a COST ESTIMATE, not a proof.** Anyone reading `rc=0` four
times must also read the stub.

## The half that is NOT measured

`len = len1 + len2` (`WOTS_TW_ES:43`) is CHECKSUM geometry, untouched here.
C10 deploys `len = 43 = len1` with no checksum term. Measured this session:
at `log2_w = 3, n = 16` the base formula gives `len1 = 43, len2 = 3, len = 46`.

So "+C" is exactly "the base with `len2` dropped" — and dropping it is a
SEPARATE change that removes the checksum from the WOTS geometry. That is the
change whose security content the Def-9 weakening (units 1-2) was built to
supply. It is not attempted here and its blast radius is unmeasured.

## Corrected estimate

| F1 component | status |
|---|---|
| `log2_w` admissibility | **cheap** — 3 declarations + 1 lemma, chain recompiles |
| `val_len1` trichotomy | 5 local uses, real but small; currently STUBBED FALSE |
| `len = len1 + len2` geometry | **unmeasured** — the actual "+C" change |

C10 is still not proven at deployed parameters. This removes one of the four
obligations named in the unit-2 correction and sizes a second; steps 1-3 of the
five-step route and `Pr[G /\ COLL]` are untouched.
