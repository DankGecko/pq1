# FINDING — `c <= p_tgts` is carried by 11 certified files; its justification is un-gated and over a *different collection*

2026-08-18. Found while looking for a next unit that was a fact rather than a
number. Everything below verified at source.

> **:warning: THIS FINDING'S CENTRAL INFERENCE IS RETRACTED — see
> `FINDING-d1-is-not-the-certified-route.md`.** `D1_reduce` does **not** justify the
> premise the certified chain carries: the capstone never reaches it. The certified
> route is `interactive_D1_MA` (`WOTS_C_Interactive.ec:3193`), gated all along. The
> *measurements* below (11 files, 48 occurrences, `WOTS_C_Multi` ungated, zero
> ledger) are correct; the *dependency claim* is not. A second retraction, on a
> different claim, is recorded at the end of this file.

---

## THE SHAPE OF IT

`c <= p_tgts` is a premise threaded through **11 of the 32 closure members**
(48 occurrences):

```
WOTS_C_Interactive 7 | XmssmtCC_All 12 | SphincsC10CapstoneWired 4
SphincsC10Content 1  | C10DeployedGeometry 2 | GFailCharged 2
XmssmtCCCharged 7    | SphincsC10CapstoneCharged 2 | C10DeployedCapstone 4
GprocQWired 5        | GprocChargedQWired 2
```

The lemma that justifies its *shape* — "the reduction places one S-TCR(+C) target
per committed query" — is **`D1_reduce`** at `cdrafts-split/WOTS_C_Multi.ec:523`.

**`WOTS_C_Multi` is not in `closure-c10-split.txt`, is in none of the four
`cert-*.tsv`, and has no `.eco`: the gate has never built it.** VERIFIED.

## THE GOOD NEWS FIRST

It is **not** another stale file. Compile-tested against the current tree:
`__RC=0`, `.eco` produced. And its ledger is genuinely **zero** — no `admit`, no
`axiom`, no `declare axiom` (line-anchored grep; an earlier count of 1 was my
comment-stripper shifting line numbers onto prose).

So this is live, clean, compiling code that simply is not gated.

## THE PROBLEM

**`D1_reduce` is stated over a different collection than the certified chain
uses.** Its statement mentions only:

```
STCRC_WC.S_TCR_C, STCRC_WC.O_STCRC_Default, STCRC_WC.Col.O_THFC_Default
```

and `WOTS_C_Reduction.ec:341-344` says so explicitly:

> *"collection oracle unified to `STCRC_WC.Col` (the S-TCR collection) so the
> WOTS+C forger A and the reduction R agree — **unifying this with the repo's
> `FC`** (one `Th_lambda` over both the chain hash `f` and `Th+C`) **is the
> remaining structural reconciliation**"*

The certified chain runs over `FC`. The bridge between them is **deferred**.

## AND THE PLACEHOLDERS FOR THAT BRIDGE DO NOT EXIST

`WOTS_C_Multi.ec`'s own header (`:21-22`) says the connection is

> *"stated here as **two clearly-labelled bridge admits**, NOT smuggled into a
> module we cannot write."*

**There are no admits in the file** (verified: zero). And `:901` refers to

> *"the deferred FC<->STCRC_WC.Col unification (**`D1_bridge_WOTSTW` below**)"*

**`D1_bridge_WOTSTW` does not exist** — the name appears exactly once in the file,
in that comment. VERIFIED.

So the file's own documentation describes two artefacts that are absent. Either
they were removed and the comments went stale, or the bridge was never written.
Either way the comments assert something the file does not contain — the
`stale-comments-read-as-fact` defect class, this time attached to a premise in 11
certified files.

## WHAT THIS DOES AND DOES NOT MEAN

**It does NOT mean `c <= p_tgts` is false.** It is carried as an explicit premise
in every certified statement that needs it, and carrying a premise is honest —
`SphincsC10CapstoneWired.ec:251-252` already labels it an "HONEST RESIDUAL".
The `experiments/ptgts-pin/` work then showed it is *satisfiable* at deployed
geometry (`p_tgts = c = 262656`, least).

**It DOES mean the rationale is weaker than the surrounding prose implies.** The
premise's justification rests on a file the gate never builds, proving a statement
over a collection the certified chain does not use, with the reconciling step
explicitly deferred and its two named placeholders missing.

## THE TWO HONEST UNITS FROM HERE

1. **Cheap and correct:** add `WOTS_C_Multi` to the closure so it is gated —
   it compiles clean and is zero-admit, so this is a strict improvement — and fix
   its stale header. Note this moves `INPUTS_SHA256` and needs a
   `cert-identity.tsv` re-baseline with its log entry, so it is an owner-visible
   change, not a silent one. **Measure first** whether the cone actually grows:
   the census is cone-based, so a new root whose dependencies are already covered
   may add zero rows.
2. **The real project:** close the `FC` ↔ `STCRC_WC.Col` reconciliation, which
   `WOTS_C_Reduction.ec:344` itself calls "the remaining structural
   reconciliation". That is what would make the justification apply to the chain
   the certified statements actually use.

(1) is small and I would do it before (2). Neither is urgent: the premise is
carried, not assumed away.

---

## RETRACTION 2026-08-18 — the "`D1_bridge_WOTSTW` does not exist" claim was FALSE

I marked it **VERIFIED**. It is wrong, and the agent I briefed refused to write the
sentence I dictated because of it. Independently re-checked:

```
cdrafts-split/WOTS_C_Bridge.ec:433   lemma D1_bridge_WOTSTW
```

**Same directory.** I searched for the name *inside `WOTS_C_Multi.ec`* and reported
its absence **there** as absence from the repo. That is
`absence-from-the-wrong-scope` — the error class `cert-identity.tsv` already
records twice (`dbin`; "split/fork rows are documentary") and which I have now
committed at least three times in this arc.

Consequently **"the reconciliation is deferred and unstated" is also false**, and
had the agent obeyed my brief it would have installed a *new* false claim into a
cone file. It wrote what is measured instead. The chain does exist:
`D1_bridge_WOTSTW` (`:433`) → `D1_MEUFNACMA_WOTSC_MM45` (`:719`) →
`..._embthfc` (`WOTS_C_EmbDischarge.ec:174`) → consumed at `SPHINCS_C.ec:252`.

## THE FINDING THAT REPLACES IT — and it is worse

**`cdrafts-split/WOTS_C_Bridge.ec` does not compile**, while its own header claims
the opposite. Verified by me at r2026.02:

```
[critical] [cdrafts-split/WOTS_C_Bridge.ec: line 659 (0-38)] cannot prove goal (strict)
__RC=1        (no .eco produced)
```

and at `:379`:

> *"PROOF STATUS (2026-07-08): PROVED IN FULL — ZERO admits."*

Line 659 sits **inside `D1_bridge_WOTSTW`'s own proof** (lemma `:433`, `qed` `:707`).
None of `WOTS_C_Bridge` / `WOTS_C_EmbDischarge` / `SPHINCS_C` is in the closure, so
the gate has never built any of them.

**Not diagnosed and not claimed:** whether this is a genuine break or a
prover-budget artefact at this toolchain. Either way, the *documentation* asserts a
status the file does not currently have — and nothing gated would notice.

So the corrected picture for `c <= p_tgts` is:

* its justification chain **exists** and is more complete than I said;
* but it runs through **ungated** files, one of which **does not currently
  compile** while claiming to be fully proved.

That is a better-shaped problem than "the bridge is missing", and a worse one than
"the comments are stale".
