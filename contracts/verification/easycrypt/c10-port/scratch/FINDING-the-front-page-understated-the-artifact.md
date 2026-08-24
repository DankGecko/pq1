# FINDING — the README's front page understated the artifact, and it is the section that says "read this first"

2026-08-24. Found while looking for the next unit of EasyCrypt work. Every claim below
verified at source. Recorded because it is the FIRST claim-vs-code drift in this arc that
runs the OTHER way: it made the tree look weaker than it is.

---

## THE FALSE SENTENCE

`README.md`, in "What is actually proved, and what is not" — the section that opens
*"Read this section before quoting anything from this directory"*:

> `Q = Pr[EUF_CMA_Gproc_I(...) : res /\ !covered]` ... **Nothing in this tree bounds `Q`
> below 1, so the bound is currently compatible with 1.**

**VERIFIED FALSE.** `cdrafts-split/GprocQBound.ec:62`:

```
lemma gproc_Q_bound ... :
  Pr[EUF_CMA_Gproc_I(A).main() @ &m : res /\ ! EUF_CMA_Gproc_I.covered]
  <= Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(...)]
   + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(...)]
   + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(...)].
```

Three NAMED SM-DT hardness advantages, and `GprocQBound` is a **gated closure member**.

Two capstones consume it and carry **no `Q` at all**, both also gated:
`GprocQWired.ec::EUFCMA_SPHINCS_PLUS_C10_QWIRED` and
`GprocChargedQWired.ec::EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED`. Measured on the
statement text:

| capstone | `Q` in conclusion | ITSRC10 | SM-DT OpenPRE |
|---|---|---|---|
| `GROUNDED` (advertised headline) | **YES** | yes | no |
| `QWIRED` | no | yes | yes |
| `CHARGED_QWIRED` | no | yes | yes |

## AND THE ADVERTISED HEADLINE IS THE WEAKER THEOREM

`CHARGED_QWIRED` is **strictly stronger** than `GROUNDED`, measured by diffing the
premises (7 each):

* **dropped:** `exists (cc : cntr), predC (ThC ps0 ad0 m0 cc)` — this is **N2**, App-D
  gap #1, which the tree's own comments call "A PREMISE, not a theorem". It is replaced
  by `Pr[GAME1_INT ...]` on the RHS — a NAMED GAME probability, not a free real, so an
  instantiator cannot choose it.
* **added:** `0%r <= mkg_adv` — a non-negativity side condition.

So the front page names as "the headline theorem" a statement that carries an extra
premise AND an unreduced term, while two strictly-better gated capstones sit beside it.

## WHAT DOES *NOT* CHANGE — AND THIS IS WHY THE CORRECTION IS NARROW

The section's overall verdict, *"it is not a numerically meaningful bound"*, **survives**.
`Pr[M.F.ITSRC10 ...]` is carried by **all three** capstones and is **provably**
irreducible: `scratch/_countermodel.ec::countermodel_pr1` exhibits a LEGAL clone of the
abstract theory in which `Pr[ITSRC10(...)] = 1%r`, so no parameter-independent bound
exists.

Correcting the `Q` sentence therefore does not make the headline numeric. It moves the
honest residual off a term that IS bounded and onto the one that genuinely cannot be —
which is a better description of the same artifact, not a stronger claim about it.

**I nearly overcorrected here.** The tempting write-up was "Q is bounded, so the
compatible-with-1 caveat is gone". That would have been a fresh false claim in the
opposite direction, and the countermodel is what stops it.

## THE ERROR CLASS, WHICH IS NEW FOR THIS ARC

Every previous drift I found in this repo made a claim STRONGER than the code supported.
This one is the reverse: the artifact's own front page was **pessimistic**, and stayed
pessimistic because the correcting work (`GprocQBound`, `GprocQWired`,
`GprocChargedQWired`) was documented ~100 lines further down under "New certified
results" and the top section was never revisited.

Under-claiming is not harmless. This section is what a reader quotes, and it told them
the headline was compatible with 1 when the tree contains a gated proof that it is not.

## WHAT I DID NOT DO

I did **not** change which theorem the README advertises as the headline. Which statement
to put on the front page is a presentation decision with consequences for everything that
cites it, and it is the owner's call. The facts are now stated where the choice is made.
