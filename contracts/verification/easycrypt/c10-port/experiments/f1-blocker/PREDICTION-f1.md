# F1 blocker — prediction, written BEFORE compiling

## Why F1 is worth doing NOW when it was a TRAP before

Earlier triage recorded F1 as "real but a trap: cheap to fix, buys zero ground",
because the ANTICHAIN obstruction (F3) blocked instantiation regardless. Units
1-2 of this week dissolved F3 (Def-9 weakening, 26 files re-verified), and the
encoder bridge emptied B2. So F1 is no longer subsumed — it is now the live
structural blocker. Same fix, different value.

## What F1 actually is — TWO changes, not one

1. `val_log2w : log2_w = 2 \/ 4 \/ 8` (`WOTS_TW_ES.ec:31`) rejects C10's
   `log2_w = 3`. 7 uses in `WOTS_TW_ES.ec`; plus `val_len1` (5 uses, all local).
2. `len = len1 + len2` (`:43`) is CHECKSUM geometry. Measured:
   C10 gives `len1 = ceil(128/3) = 43`, `len2 = 3`, so the base forces
   `len = 46` — but C10 deploys `len = 43`. **`len1` alone IS C10's len**, i.e.
   "+C" is exactly "the base with `len2` dropped".

This coheres with units 1-2: the antichain property the CHECKSUM used to supply
is what the Def-9 constant-sum weakening now supplies. The pieces are meant to
fit; this experiment tests whether they actually do.

## PREDICTION

1. Relaxing to `1 <= log2_w` breaks the **7** `val_log2w` sites (they case-split
   on the three literals) and makes `val_len1` unprovable (it asserts
   `len1 = 4n \/ 2n \/ n`, true only for `log2_w in {2,4,8}`).
2. `val_len1` is used only INSIDE `WOTS_TW_ES.ec` (0 uses in FL_SL_XMSS_MT_ES and
   SPHINCS_PLUS), so its loss is locally repairable, not a cascade.
3. Setting `len = len1` will break anything that needs `len > len1` — i.e. the
   checksum-chain reasoning. That breakage is the REAL measurement: it tells us
   how much of MM45's WOTS argument is checksum-specific rather than generic.
4. `len` is used 234 times but almost all as an opaque length; those should be
   untouched.

## Falsifiers

* If relaxing `val_log2w` alone compiles clean, I have mis-measured and should
  say so — the constraint would then be inert.
* If the `len = len1` change cascades into FL_SL_XMSS_MT_ES / SPHINCS_PLUS, F1 is
  a much larger job than "lift an axiom" and must be reported as such.
* Suspiciously fast compiles => re-check as explicit target + `lemma : false`
  negative control (trap T1 bit this project twice this week).

## Scope

This measures COST and finds the true blast radius. It is NOT expected to yield a
deployed-C10 theorem in one pass; steps 1-3 of the five-step route are untouched
and `Pr[G /\ COLL]` remains uncharged.
