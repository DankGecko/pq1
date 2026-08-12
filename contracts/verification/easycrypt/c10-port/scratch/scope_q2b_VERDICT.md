# Q2b SCOPING — VERDICT, 2026-08-12

GPT-5.6 and Kimi K3, both read source. **They diverge on the central question, and
GPT wins it decisively** — on three independent grounds, one of which is my own
measurement taken before either reply landed.

---

## THE DIVERGENCE: is Q2b structurally blocked?

**Kimi: YES**, exactly as Q1 — free op, no re-interpretation, closure cannot decide.
**GPT: NO** — *"That premise is false."*

**GPT is right.** Three independent confirmations:

1. **EasyCrypt's own source** (GPT read it): `ecThCloning.ml:586` looks up theories in
   `All` mode, **not "abstract only"**; `ecTheoryReplay.ml:294` **explicitly permits
   replacing a free operator with a typed body**.
2. **This development already does it**: `FL_SL_XMSS_MT_ES.ec:547` is
   `clone import WOTS_TW_ES as WTWES with ...` — cloning the non-abstract
   `WOTS_TW_ES` is established practice *here*. Verified.
3. **My own measurement**, run before either reply: `clone WOTS_TW_ES as PINNED with
   op encode_msgWOTS <- <concrete> proof *` is accepted, yielding 12 obligations.

**The correct, narrower statement** (GPT's): Q1 is *locally right but globally
overbroad*. The existing namespace cannot be reinterpreted; a **new clone can be**.
But a standalone clone does not alter the **nested instance the capstone uses** —
so live Q2b needs either a definition at the original declaration, or a rewired
outer clone stack. That is a real constraint, and it is not the one I asked about.

## GPT'S NEW DEFECT — digit ORDER, which nobody else had

The deployed Rust treats the digest as **big-endian bytes** but extracts digits from
the integer's **LSB upward** (`sphincs-c10/src/wots.rs:11`), and **digit `i` drives
chain `i`** (`wots.rs:126`). `Proj129.ec:40` **reverses digit order** and says
outright that chain assignment is **not order-invariant**.

=> **A genuine pin must prove exact byte/bit/chain-index correspondence, not merely
equal digit sums.** This raises the true cost of any pinning route, and it means my
own `q2a` witness (order-agnostic, digit-sum only) is sufficient for *attainment*
but nowhere near sufficient for a *pin*.

## FOUR ERRORS OF MINE, ALL FOUND BY GPT, ALL VERIFIED

1. **"Only three axioms remain in `WOTS_TW_ES.ec`."** FALSE. There are also
   `declare axiom A_choose_ll` / `A_forge_ll` at `:3210`. My grep was `^axiom `,
   which cannot match an **indented `declare axiom`**. Five axiom forms, not three.
   **This is the FOURTH time today a grep of mine could not have found what I
   claimed was absent** (`dbin`; the `INPUTS_SHA256` row; `encode_msgWOTS` vs
   `c10_embg`; now this). Same class: [[feedback_absence_from_wrong_token]].
2. **Line count.** `WOTS_TW_ES.ec` is **6623**; 6591 is `FORS_ES.ec`. I attributed
   one file's size to the other and used it to cost route A.
3. **`PINNED_ENCODER` pins `emb_in`**, the node/counter serializer — **not** the WOTS
   digit encoder. I knew this and still let the brief blur it.
4. **"205 in the encoder image" does not pin the live `target_sum`.** `target_sum` is
   the sum at the separate free `tgt_witness` (`:645`). Both Kimi and GPT flagged
   this independently; it means any honest route pins **two** things, not one.

## ROUTE RANKING — GPT's, adopted

| rank | route | cost | verdict |
|---|---|---|---|
| 1 | **D — define the live encoder + target witness at their source** | **4–8 eng-days** | only proportionate route that closes *live* Q2 |
| 2 | A — abstract/clone refactor | 2–6 eng-weeks | solves a **nonexistent** language restriction; not contained |
| 3 | B — equation hypotheses (Kimi's B-plus) | 0.5–2 days | gives only `EncoderIsC10 ∧ WitnessIsC10 ⇒ target_sum = 205` — **restates the missing fact, does not close Q2b** |
| 4 | C — more surrogate work | redundant | the arithmetic already exists |

I adopt GPT's ranking over Kimi's. Kimi's B-plus is honest about being conditional,
but GPT's objection is decisive: assuming the identification *is* the open question.

## THE RECOMMENDED NEXT UNIT — and it is NOT Q2b

> **Do not do Q2b next. Build a charged, Q-wired deployed quotation surface.**

Compose the existing **N2-free charged capstone**
(`SphincsC10CapstoneCharged.ec:78`, `EUFCMA_SPHINCS_PLUS_C10_CHARGED`) with the
already-proved `gproc_Q_bound`, following the `GprocQWired.ec:67` pattern.

**Cost: 2–4 engineer-days + one container certification cycle.**

**Exact payoff:**
* **removes the current universal N2 premise**;
* replaces it with the explicit `Pr[res /\ gfail]` summand the charged chain already
  proves (`XmssmtCCCharged.ec`, `EUFNAGCMA_FLSLXMSSMTTWCESNPRF_charged` — its header
  states branch 2 is **already N2-free**);
* retains the three named Q-branch hardness terms;
* **activates neither admit**;
* expected **PHASE-2 census delta ZERO** — every file, module and reduction is
  already in the closure. Purely additive theorem composition + statement pins +
  identity refresh.

**Why it beats the alternatives:** Q2b moves no RHS term (both reviewers agree —
it is quotation-surface fidelity only). Unfolding the WOTS game now would make the
presently non-load-bearing admit at `WOTS_TW_ES.ec:1513` **load-bearing** — a
regression. A sound WOTS collision campaign is the important later project but
`tcollres-leg` shows it is 2–4 weeks of game instrumentation, not a theorem
application. The FORS admit stays off the quoted path.

**Bonus finding:** `FINDING-n2-is-independent`'s conclusion *"carry N2 as a premise,
permanently"* is now **STALE** — the charged chain replaces it with a visible
grind-failure probability. That is the third of the three `tcollres-leg` FINDINGs to
go stale; only the Def-11 unsoundness result still stands (its arithmetic is
untouched by anything since).

## WHERE EACH REVIEWER WAS RIGHT

* **Kimi** — correct that `tgt_witness` is also free; correct that route B is the
  house style at the deployed surface; correct that C is maxed; **and it caught my
  Q2a over-claim** by finding `c10_deployed_encoder_attains_target` (`:446`).
* **GPT** — correct on the central question, on digit order, on all four of my
  errors, and it produced the only recommendation that moves a term in the headline.
