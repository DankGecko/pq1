# cdrafts — the PQ1 draft chain built against `base-c10`

Working copy of `drafts/` used by `wire_test.sh` and `ec-c10.sh`. `drafts/` belongs
to a **concurrent session** and is never written by this track.

## Divergence from `drafts/` — exactly ONE file

Until 2026-07-27 every closure file here was **byte-identical** to `drafts/`, so
`base-c10` was the only variable in the receipt. That is no longer true, and the
difference is deliberate:

| file | change |
|---|---|
| `WOTS_C_Real.ec` | `predC` is **DEFINED** instead of declared abstract |

Everything else is still byte-identical — checked in the same loop `wire_test.sh`
uses, so the claim is mechanical:

```sh
for f in $(cat closure-c10.txt); do
  [ -f "drafts/$f.ec" ] && { cmp -s "cdrafts/$f.ec" "drafts/$f.ec" || echo "DIFFERS: $f"; }
done
# => DIFFERS: WOTS_C_Real     (and nothing else)
```

## Why `predC` was tied

It previously read

```ec
op predC : dgstblock -> bool.   (* "Abstract here; tied to base_w in the scheme file" *)
```

**That tie was never made.** `target_sum` appeared **zero** times in
`WOTS_C_Scheme.ec`, and `predC` carried **no axiom anywhere in the closure** —
the repo recorded this itself at `SphincsC10Content.ec:492`. So

> `predC := fun _ => false`

was a model of the entire development: every +C acceptance false, the LHS of the
bound zero, and every statement conditioned on the gate vacuously true. Any
result of the form "on the constant-sum surface, X" was unlicensed.

## Why a DEFINITION and not an axiom

```ec
const target_sum : int.
op cw_sum (em : EmsgWOTS.emsgWOTS) : int = sumz (map BaseW.val (EmsgWOTS.val em)).
op predC (d : dgstblock) : bool = cw_sum (encode_msgWOTS d) = target_sum.
```

A definition **cannot introduce inconsistency**; `axiom predC_is_sum : ...` could.
Since the whole point of the change is to remove a vacuity hazard, introducing a
consistency hazard in its place would be a bad trade. **The axiom census is
unchanged by this edit: 0 admits, 0 axiom declarations added.**

## The gate is SUM-ONLY

The old comment also claimed *"and the first z digits are zero"*. That is
**FORS+C's** `predC_fors`, not deployed WOTS, which gates on the digit sum alone —
`sphincs-c10/src/wots.rs:160` and
`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol:170`. A `predC` carrying a
leading-zeros conjunct for WOTS would be **unfaithful**, not more complete.

## UPDATE 2026-07-28 — `TargetSumReachable` is now a theorem

`target_sum` was a **free** `const int`, which admitted values no encoder
reaches — models with no deployment counterpart. It is now **defined** as an
attained value:

```ec
const tgt_witness : dgstblock.
op target_sum : int = cw_sum (encode_msgWOTS tgt_witness).
lemma targetSumReachable : TargetSumReachable.    (* witness: tgt_witness *)
```

Still **zero new axioms**. Control C in `gate_predc_tie.sh` reverts `target_sum`
to a free constant and the lemma goes **unprovable**, so the definition is doing
the work.

### Read it narrowly

The accurate description is *"`target_sum` is now defined as an attained value,
which makes reachability a theorem"* — **not** *"reachability was proven about the
encoder."*

* **KILLED:** `predC := fun _ => false` — the dangerous degeneracy (acceptance
  always false, LHS of the bound zero, every gate-conditioned statement vacuous).
* **NOT KILLED:** `predC := fun _ => true`. A *constant* `encode_msgWOTS`
  satisfies `two_encodings` (its hypothesis is never met) and `enc_nonzero`.
  Excluding it needs two digests with **different** codeword sums, and neither
  base-c10 axiom provides them — incomparable codewords may share a sum. Stated
  precisely rather than as "less harmful": with the gate always true it vanishes
  from acceptance, so S-TCR(+C) is assumed about a scheme with **no filter**,
  a different assumption from the one the ledger names.
* **NOT TOUCHED:** the honest-leg premise **N2**, `exists c, predC (ThC ps ad m c)`
  (`wotsc_grind_targets_predC`). N2 ranges over `ThC`'s image *at a fixed
  `(ps, ad, m)`*, indexed by counters; `tgt_witness` need not lie in it. Knowing
  one digest attains the target says nothing about whether the grind succeeds at
  a given instance. N2 remains a premise and still carries its uncharged
  probability term (firmware bounds the grind at `0..10_000_000` and **panics**
  on failure, `sphincs-c10/src/wots.rs:62-74`).
* **NOT ESTABLISHED:** that the deployed target `205` is reachable for the
  deployed encoder. That is `experiments/tcollres-leg/ThCWidth.ec`
  `predC_sum_inhabited` at C10 geometry, transferred here by **hand
  transcription** across the `int` / `emsgWOTS` boundary, not machine-checked.

`Pr[G /\ COLL]` remains uncharged. `WOTS_TW_ES.ec:1353` remains admitted.
**C10 is not proven at deployed parameters.**
