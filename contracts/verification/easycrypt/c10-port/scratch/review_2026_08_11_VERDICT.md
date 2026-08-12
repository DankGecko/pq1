# ADVERSARIAL REVIEW 2026-08-11 — VERDICT AND FINDINGS

Two independent reviewers (GPT-5.6 via codex, Kimi K3 via CLI) reviewed the
"bank here" proposal. Both read source. Neither modified any file.
Plus one empirical measurement run by me in-container.

---

## THE CONVERGENCE (both reviewers, independently, same single action)

> **Do not bank on prose. Mechanize the probability-one countermodel first.**
> Build a small UNGATED clone that instantiates `ITSRC10` with a degenerate but
> LEGAL model and prove `Pr[win] = 1`. Then bank.

Rationale both gave: the entire "bank here" argument rests on the claim *"there
is a legal model in which the game is won with probability 1."* That claim is
currently **prose in three headers and nothing else**. Under the project's
founding rule — *a result nothing enforces is not a receipt* — the stopping
argument is exactly the kind of unenforced claim this repo exists to reject.
Mechanizing it converts the argument into a measurement, forecloses any future
attempt to bound the current game, and makes the stop a **theorem-terminated
branch** rather than a judgement call.

Both explicitly said: **do NOT start the ROM route, and do NOT start (B).**

Concrete model both sketched (they agree on shape):
`mkey` small / `msg` with >= 2 elements, `mco` constant, `hC` constant,
`predC_fors` all-true, `g` an explicit constant list of `k` DISTINCT tuples
(distinctness forced by `uniq_g`, which is strictly stronger than MM45's set).
Adversary: query `m0`, receive `mk`, return `(mk, m1)`. Then `predC` holds,
`cover_f = cover_q` (same digest), pair-freshness holds, and `dmkey_ll` makes it
lossless — so the win is sure.

---

## WHERE THEY CORRECTED MY DIAGNOSIS (this is the real information)

**1. My attribution of the defect was WRONG.** I said the problem is that the
adversary "grinds `mco` for free" because there is no `q_h`. GPT-5.6: the
countermodel needs **one signing query and zero hash grinding**. What it actually
exploits is the **missing output law for abstract `mco`** — plus the fact that
`q_s` is unbounded too, which I never mentioned. So "no `q_h` bound" is a
symptom, not the disease.

**2. My cost attribution was WRONG, in the direction that flattered stopping.**
I said oracleizing `mco` is expensive because it means rewriting `FORS_C10.ec`
and re-proving everything over it. **Both reviewers say the game file is
addable ALONGSIDE, cheaply, without touching `FORS_C10.ec`.** The verdict
"architectural" survives — but for two reasons I did not have:
  - **GPT-5.6:** a metered adversary is a **subset** of the current unrestricted
    class, so an inclusion lemma gives the **wrong inequality direction** to
    replace the RHS term.
  - **Kimi K3:** the deployed chain instantiates `mco` as a **concrete pure op**,
    and **a concrete hash is not a random oracle** — no coupling can bound it.
    Making a metered game mean anything requires ROM-ifying the **capstone**,
    because `q_h` only exists once the *top* game hands out a hash oracle.
  Kimi's warning is worth keeping: *"keep the cost attribution straight or the
  next reviewer will refute you on the cheap half and wrongly conclude the whole
  route is cheap."*

**3. The prob-1 claim is not my finding.** Kimi: it is already written in
`FORS_C10.ec`, `DarkSide.ec` and `DarkSideC10.ec`. Banking is already the de
facto state — the deployed headline ships the ITSRC10 term unreduced and the
paper margin is pinned. So my "decision" framing overstated what was at stake.

---

## LIVE DEFECTS — CONFIRMED BY ME AGAINST SOURCE

**D1 (HIGH, GPT-5.6) — PHASE 4's negative-control claim is FALSE.**
`self_test()` (`tools/forsc_grinding_margin.py:275`) takes an **early, separate
path**: it recomputes `ratio = p_forsc(1)/p_plain_fors(1)` and `T_LAST < T`
itself. It never executes normal guardrails 1–3 (lines 342–378). So replacing
those three guard blocks with unconditional `print(... : OK)` and no
`failures.append` would still pass (i) the happy-path 4/4 count, (ii)
`--self-test`, and (iii) all seven pinned numbers.
=> `cert-identity.tsv`'s claim that running `--self-test` distinguishes a live
guardrail from one "neutered to print OK unconditionally" is **overstated**.
**VERIFIED BY ME** at those exact line ranges. This is the **third** time I have
made a false claim about PHASE 4's controls.

**D2 (MEDIUM, GPT-5.6) — provenance is not frozen.** The vendored script is
byte-identical to PQSigner_OS *right now* (I confirmed: md5 match both ways),
but the gate pins only the **local copy**. The upstream commit/blob is not
pinned, so "BYTE-IDENTICAL" is a present-tense fact, not an invariant.

**D3 (MEDIUM, Kimi) — `DarkSide.ec:61-62` is STALE.** It says "AND NOTHING GATES
THIS FILE ... is absent from `closure-c10-split.txt`". It is closure member
**#30**. **VERIFIED BY ME.** Made stale by my own promotion commit today.

**D4 (MEDIUM, Kimi) — `FORS_C10.ec:91` is STALE.** It says the margin script
"is NOT in this checkout". I vendored it to `tools/forsc_grinding_margin.py`
today (07:52). **VERIFIED BY ME.** Also made stale by my own work today.

**D5 (LOW, GPT-5.6) — further stale rows** it flagged but I have NOT yet
verified: `GprocQBound.ec:25` ("all 16 promotion rows were module/operand rows"
vs a later clone-discharge), `GprocQBound.ec:33` ("NOT YET WIRED"),
`FORS_C10_Multi.ec:57` (says the direct route needs a concentration inequality,
but the committed raw-moment route avoids concentration).

---

## RECEIPTS THAT SURVIVED THE ATTACK

- **QWIRED IS consumed now** — GPT-5.6 traced `:382 -> :470 -> :530`. My earlier
  grep read ("not consumed outside its own file") was too literal: the consumers
  are the deployed wrappers in the same file, and they are gated by `check_lemma`
  + statement digests. The previous no-consumer defect is genuinely fixed.
- **`DarkSideC10` genuinely pins C10's `t`** — both reviewers agree; `ge1_t` from
  `ge2_t` masks nothing (it is the sound direction), and `t` is cloned as
  `SPHINCS_PLUS.t`, not a numeral.
- **`mixture_le_moment` is not vacuous** — `dinter` supplies a real finite
  nonnegative witness.
- **DarkSide's 9 lemmas ARE gated** — I suspected a hole (no `check_lemma` line);
  it dissolved: PHASE 1c pins all nine statement digests via
  `cert-statements-split.tsv`, and axiom-ification would trip PHASE 2.

## RECEIPTS THAT ARE NARROWER THAN ADVERTISED

- **`WitnessF` is SYNTACTIC anti-vacuity only** (GPT-5.6). It returns the message
  it just signed, so EUF-CMA freshness fails and its LHS success probability is
  **zero**. It proves module-restriction satisfiability, not cryptographic
  non-vacuity. The file's own lines 185–192 say this honestly.
- **`DarkSideC10`'s connection is NUMERIC, not semantic** (GPT-5.6). There is no
  lemma connecting `DS_C10.dleaf` to actual `mco`/`g` outputs, and the advertised
  "at C10's k" lemma quantifies an arbitrary `kk`.

---

## MY OWN MEASUREMENT (run in-container, r2026.02)

I had claimed the load law was "feasible — ordinary induction" WITHOUT attempting
it. I attempted it. **`head_split` is PROVEN, zero admits, clean compile**
(`scratch/_spike_load2.ec`): the recursion step

    mu (dlist (dbiased p) (n+1)) (cnt = k)
      = p * mu (dlist (dbiased p) n) (cnt = k-1)
      + (1-p) * mu (dlist (dbiased p) n) (cnt = k)

via `dlistS -> dmapE -> dprod_dlet -> dletE_bool -> dbiased1E`. This is the step
I had called the risky one.

Two things fell out:
- **A defect in my own statement**, found by dumping the goal rather than
  reasoning about it: my first version omitted `0 <= p <= 1` and left a residual
  `clamp p = p` — i.e. the lemma as first stated is FALSE outside [0,1].
- **A real remaining subtlety I had glossed:** at `k = n+1` the term
  `(1-p)^(n-k)` has a NEGATIVE exponent, which is inverse-valued in EasyCrypt and
  divides by zero at `p = 1`. "Ordinary induction" was too glib.

This CONVERGES with both reviewers: GPT-5.6 independently said the load law is
"plausibly one focused day" with the friction in **boundary arithmetic**
(negative indices, 0, n+1, p=0/1) — exactly what I hit.

**But GPT-5.6's sharper point stands:** the load law is not (B). `(B)` also needs
the **12th raw binomial moment**, and the Stirling / falling-factorial
infrastructure for it is absent from stdlib. *"Calling all of (B) one day would
be fantasy."*

---

## RECOMMENDATION

Adopt the unanimous reviewer action, with the confirmed defects folded in:

1. **Mechanize the prob-1 countermodel** (ungated clone, ~1 day). This is the
   one action both reviewers independently chose.
2. **Retract D1** in `cert-identity.tsv` + the PHASE 4 comment block — a false
   claim about a CONTROL is the worst place to be sloppy, and this is the third
   PHASE 4 miss. Either strengthen the self-test to exercise guardrails 1–3, or
   state plainly that it does not.
3. **Un-stale D3 and D4** — both were made stale by today's own commits.
4. Then **bank**, with the stop recorded as a decision (Kimi's point 4: two
   promoted headers currently disagree about whether the ROM route is an
   *obligation* or an *upgrade*).

Do NOT start the ROM route. Do NOT start (B).

Note: items 2–4 touch gated files, so they need a container gate re-run.

---

## FEASIBILITY CHECK ON THE RECOMMENDED ACTION — RUN, NOT ASSUMED

Both reviewers HEDGED on the same point (Kimi: "[T for the exact axiom
statements of `uniq_g` et al.]"; GPT-5.6: "SOURCE-DERIVED, not machine-checked"):
both sketches assume `predC_fors`, `hC` and `g` are choosable by a model. I
checked. Result — **the countermodel is constructible, and it is CHEAPER than
either reviewer assumed**, but two of their premises were wrong:

- **`predC_fors` is DEFINED, not abstract** (`FORS_C10.ec:197`):
  `predC_fors y = (nth witness (g y) (k-1)).`3 = 0`. So "predC all-true" is NOT
  a free choice — but it IS reachable, because it is defined *through* `g`,
  which is abstract (`:163`). Choose `g` so the (k-1)-th tuple has third
  component 0 and it holds.
- **`hC` is DEFINED as `g (mco mk m)`** (`:211`), so "constant `hC`" is not a
  free choice either — it is forced. But `mco` (`:152`) and `g` (`:163`) are
  both abstract, so a constant `mco` plus any `g` yields a constant `hC`. The
  conclusion survives; the reviewers' reasoning for it did not.

- **The refinements permit `k = 1`.** `FORS_C10.ec:138-140`:
  `k : { int | 1 <= k }`, `a : { int | 1 <= a }`, `t = 2^a` (defined, not
  refined). So `k = a = 1`, `t = 2` is legal — GPT-5.6's proposal survives the
  refinement check.
- **`k = 1` makes `uniq_g` VACUOUS**, which is the obstacle both reviewers
  flagged as the thing needing "an explicit construction". `uniq_g` demands
  distinct second components across the `k` tuples; at `k = 1` a one-element
  list is trivially `uniq`. Kimi's warning that `uniq_g` "means `g` can't be
  fully degenerate" is therefore true at C10's `k = 13` and **false at `k = 1`**.
- **`good_pos` discharges**: with constant `mco` and `predC_fors` true,
  `good m` is all-true, so `mu dmkey (good m) = 1 > 0` by `dmkey_ll`.

=> The spike is **cheaper than the reviewers' one-day estimate**, and the reason
is a parameter choice they did not check rather than a proof insight.

## PRE-STATED TARGET (write this BEFORE proving it, so the header cannot drift)

> There exists a **legal instantiation of the abstract theory's parameters**
> under which `Pr[ITSRC10 win] = 1`. Hence **no parameter-independent bound is
> provable for this game as axiomatized.**

It does NOT say the deployed instance is insecure, and it does NOT say "the game
is unbounded". The deployed chain fixes `mco` at a concrete op; `Pr` at *that*
instance is a fixed number about which the countermodel says nothing.

## ONE CONSTRAINT NEITHER REVIEWER SAW (advisor)

**D1's fix is constrained by D2.** Strengthening `--self-test` to exercise
guardrails 1–3 means editing `tools/forsc_grinding_margin.py`, which **breaks
the byte-identity with PQSigner_OS that the gate's own header asserts** — turning
D2 from "provenance not frozen" into "provenance actively false". So the two
consistent options are: (i) **doc-retraction only** here (cheap, honest, leaves
the gap named), or (ii) **fix upstream in PQSigner_OS first, then re-vendor and
re-pin** (correct, but a two-repo change). Pick before touching anything.


---

# EXECUTION LOG — 2026-08-11, owner decision: "doc-retraction only, then countermodel spike"

## Retractions landed (doc-only, per owner decision)

| id | file | what |
|----|------|------|
| D1 | `cert-identity.tsv`, `cert_gate_split.sh` | RETRACTED the claim that `--self-test` catches a neutered guardrail. Gap left OPEN and NAMED, with the upstream-first fix recorded as the correct one. Third PHASE 4 control error, called out as a pattern. |
| D2 | `cert-identity.tsv` | Provenance recorded as a present-tense fact, not an invariant (no upstream commit/blob pinned). |
| D3 | `cdrafts-split/DarkSide.ec:61` | "NOTHING GATES THIS FILE" marked STALE; current gating enumerated (closure #30, 9 digest pins). |
| D4 | `cdrafts-split/FORS_C10.ec:91` | "NOT in this checkout" replaced; now points at PHASE 4 + `cert-margin-split.tsv`, with the quoting caveats. |
| D5b | `cdrafts-split/GprocQBound.ec:33` | "NOT YET WIRED INTO THE CAPSTONE" marked STALE (superseded by `GprocQWired.ec`). |
| D5c | `cdrafts-split/FORS_C10_Multi.ec:57` | "needs a concentration inequality" corrected — the committed raw-moment route avoids concentration. |

**D5a NOT changed — GPT-5.6 was wrong on this one.** `GprocQBound.ec:25` says the
promotion of *the three branch files* added 16 census rows, all module/operand,
zero admit/axiom. The `clone-discharge` row GPT cited came from `DarkSideC10.ec`,
a **different, later** promotion. The sentence is correctly scoped. Verified
against `cert-baseline-split.tsv:1328-1338`.

## THE COUNTERMODEL — PROVEN

`scratch/_countermodel.ec`, **zero admits, EXIT 0 under BOTH drivers**
(`compile` and `cli`):

    lemma countermodel_pr1 &m :
      Pr[ITSRC10(Amod, O_ITSRC10_Default).main() @ &m : res] = 1%r.

over a **legal** clone of `FORSC10` — all nine obligations realized
(`ge1_k`, `ge1_a`, `dmkey_ll`, `size_g`, `eqiks_g`, `neqisvs_g`, `rng_g`,
`uniq_g`, `good_pos`) at `k = a = 1`, `mkey = unit`, `msg = bool`,
`out_t = unit`, `dmkey = dunit`, constant `mco`, `g = fun _ => [(0,0,0)]`.

So the prose in three headers is now a theorem: **no parameter-independent bound
on ITSRC10 is provable for this game as axiomatized.** The stop is
theorem-terminated, not a judgement call.

**Negative control** (`scratch/_countermodel_negctl.ec`): same model at `k = 2`
with a duplicated tuple. MUST-FAIL, and it fails at the **declared line 44**
(`realize uniq_g`) for the **declared reason** (`[by]: cannot close goals`).
This proves the axiom set is not vacuously satisfiable — without it, "there
exists a legal model" would be worthless.

## THREE THINGS THE REVIEWERS GOT WRONG, found by building it

1. **`predC_fors` is DEFINED** (`FORS_C10.ec:197`), not abstract — "predC
   all-true" is not a free choice. It is reachable only *through* abstract `g`.
2. **`hC` is DEFINED** as `g (mco mk m)` (`:211`) — "constant `hC`" is forced,
   not chosen.
3. **`uniq_g` is VACUOUS at k = 1.** Both reviewers named it as the obstacle
   requiring "an explicit construction". It bites at C10's k = 13 and not here.
   That is why the spike came in well under their one-day estimate — a parameter
   choice neither checked. The negative control above is the evidence.

Plus a real defect in *my* diagnosis, confirmed by the proof: the winning
adversary makes **one signing query and never evaluates `mco`**. The win comes
from the missing **output law** on abstract `mco`, not from free hash grinding.
A `q_h` bound alone would not fix it.

## Also measured: `head_split`

`scratch/_spike_load2.ec` — the load law's **recursion step**, proven, zero
admits. Corroborates both reviewers' "~one day" for the load law and locates the
real friction where GPT-5.6 said it was (boundary arithmetic; specifically
`(1-p)^(n-k)` at `k = n+1` is inverse-valued and divides by zero at `p = 1`).
Also caught a defect in my own statement — the missing `0 <= p <= 1` — by
dumping the goal instead of reasoning about it.

## GATE PREDICTION (stated BEFORE the run, per standing discipline)

* PHASE 1/1d/1e: OK — the six touched files were individually recompiled first.
* PHASE 1b: unchanged — no lemma name touched.
* **PHASE 1c: digests UNCHANGED** — every `.ec` edit is comment-only.
* **PHASE 2: census UNCHANGED, delta ZERO** — no new assumption of any class.
* PHASE 3: controls unchanged. PHASE 4: seven numbers unchanged (neither the
  script nor `cert-margin-split.tsv` values were touched).
* **INPUTS_SHA256 WILL MOVE** — file contents changed.
* The `split` / `fork` rows at the tail of `cert-identity.tsv` need a deliberate
  re-baseline.

## GATE RESULT — RED (1 failure), exactly as predicted

`### RESULT: RED (1 failures)` — 202 OK lines, toolchain `r2026.02`, 25 prover
configurations (in-container; the host r2026.06 would produce a plausible
all-fail receipt). The single failure was the predicted `INPUTS_SHA256` drift.

Everything else green, confirming the prediction phase by phase:
CLOSURE_COMPILED=31/31, PHASE 1d/1e/1f OK, PHASE 1b OK, **PHASE 1c digests
unchanged**, **PHASE 2 census delta ZERO**, PHASE 2b/2c canaries caught,
PHASE 3 controls at declared polarity and reason, PHASE 4 margin 7/7 with
negative controls 3/3, `inputs unchanged across the run`.

**ONE PART OF MY PREDICTION WAS WRONG**, and it is the part worth recording.
I wrote that the `split`/`fork` rows are "NOT gate-checked (no script reads
them)". **False.** `cert_gate_split.sh:94` `awk`-reads the `split` row and
compares it against the computed `INPUTS_ID`. I had grepped the scripts for the
hash *value* rather than for the *mechanism*, and concluded absence from a search
for the wrong token — **the identical error that produced the `dbin` retraction**
(grep hit dismissed, absence argued from the wrong artifact). Twice in one day,
same shape. Re-baselined to `f14321e82848ad5da03c93555e7b42e4` deliberately,
with the cause documented in `cert-identity.tsv`.
