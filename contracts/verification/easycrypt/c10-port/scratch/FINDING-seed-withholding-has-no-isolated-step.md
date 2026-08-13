# FINDING — the seed-withholding spike does not exist, and the WOTS admit is worse than "unproven"

**Date:** 2026-08-12. **Status:** verdict on a proposed unit, written before any
`.ec` was attempted, so it survives if the spike itself does not.

**This retracts my own recommendation from the end of the previous session.** I
proposed a one-day spike to "prove or refute the seed-withholding step in
isolation." **There is no isolated step.** The reasoning below is the deliverable.

---

## 1. THE RETRACTION

Previous session's closing recommendation:

> discharge inside the +C GCMA game using **seed-withholding** — `proc choose() :
> unit` takes no `ps`, and `ps` arrives only at `proc forge(ps : pseed)` ... Since
> `wots_digest` absorbs `pk_seed` first, **no encoding is computable at
> choose-time**, killing the precomputation birthday at that site.

The *cryptographic* observation is fine. The **routing** is not. Three facts kill
the one-day framing:

### CORRECTION TO LEG 1, found by me while the external reviewers were running

My first phrasing of leg 1 was **loose**, and loose in a way that invites a correct
refutation. I wrote that at the `:6542` site there is "no `ps` interposed" between the
adversary and the encoder. That is wrong as stated: the **base** game withholds the
seed exactly as the +C mirror does — `Adv_MEUFGCMA_WOTSTWESNPRF` has
`proc choose() : unit` at `WOTS_TW_ES.ec:2520` and receives `ps` only at
`proc forge(ps : pseed)` at `:2521`. Seed-withholding is **inherited from MM45**, not
a +C innovation.

**The correct statement is sharper, and it makes the verdict stronger, not weaker:**

> `encode_msgWOTS : msgWOTS -> emsgWOTS` (`:624`) **does not take `ps` at all.**
> Withholding the seed therefore buys *nothing* at the WOTS-TW layer: the adversary
> chooses both `m` (as an oracle query in `choose`) and `m'` (in `forge`), and can find
> an encoding collision **offline, before the game starts**, with no knowledge of `ps`.
> Keying appears only one layer up, where the WOTS message is the composite
> `ThC ps ad m c` and `encode ∘ ThC ps ad ·` *is* seed-dependent.

So the seed-withholding structure the previous session pointed at is **already present
at the layer that needs it and already useless there**. That is direct evidence for the
verdict rather than against it.

1. **The admit lives at the WOTS-TW layer, where the withheld seed is irrelevant.**
   `base-c10-split/WOTS_TW_ES.ec:1505` `nhchwcoll_hchwpre_msg` needs
   `m <> m' => encode_msgWOTS m <> encode_msgWOTS m'`, and its sole live caller
   is the forgery site `:6542`, inside `M_EUF_GCMA_WOTSTWESNPRF`. There, `m'` is
   an adversary-chosen `msgWOTS` and `m` is one of its own queries, and the
   encoder consumes no seed. **The collision event at that layer is protected by
   no hardness whatsoever** — the adversary picks both messages and the encoder
   is a function of the message alone, so nothing in the game stands between it
   and a colliding pair. Seed-withholding has nothing to bite on.

   *(Phrasing corrected — caught by Kimi K3, and it is a fair hit. I first wrote
   "the collision event has probability 1". That is FALSE in the abstract
   theory: `encode_msgWOTS` is free, so there are models where it is injective
   and the event is empty. Probability 1 is a claim about the **deployed**
   encoder — i.e. it presupposes exactly the identification that is still open.
   What survives abstractly is the weaker "unprotected by any hardness", and
   that is all leg 1 needs. Same error class as §4's caveat: quantitative
   language borrowed from the deployment and applied to the abstract theory.)*

2. **Seed-withholding only bites one layer up, and that layer cannot reach down.**
   At the +C layer the WOTS message is `ThC ps ad m c`
   (`cdrafts-split/WOTS_C_Real.ec:214`), which *is* `ps`-keyed, and
   `M_EUF_GCMA_WOTSC_NPRF`'s adversary type does withhold `ps` from `choose`
   (`WOTS_C_Scheme.ec:142-143`). But the +C leg reaches WOTS-TW only through the
   **unreduced summand** `Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(...))]`
   (`GprocQWired.ec:457`), and reducing that summand means applying the base
   theorem, which means consuming the admit. **Circular.**

3. **You cannot insert a game hop from outside a finished `qed`.** The case split
   the admit feeds is buried at `WOTS_TW_ES.ec:6542` inside a ~6000-line proof
   script. The parallel-and-promote pattern that built `GprocQBound` /
   `GprocQWired` / `GprocChargedQWired` works because those *compose finished
   theorems*. Charging a term **inside** an existing proof is a base-file edit,
   i.e. the 2–4 week campaign, not a spike.

**Verdict: do not schedule the seed-withholding spike as a proof patch.**

### CORRECTED BY KIMI K3 — "it has no statement" is too strong, and the better framing is sharper

My first verdict line read *"It has no statement."* That is wrong. Kimi's
objection, which I verified and accept:

> Seed-withholding **can** be routed — but only as a **theorem replacement**, not
> a proof patch. Gate the TW statement to `ThC`-image messages (or add an
> explicit TCR(+C) collision term), where withholding `ps` from `choose`
> genuinely bounds the codeword-collision event.

And the framing that follows is more quotable than mine:

> **The admit is not an unlucky gap in a finished proof. It is the exact point
> where the *generic* MM45 WOTS-TW theorem is FALSE at deployed geometry.**

That is the finding. The generic theorem quantifies over *all* `msgWOTS`; the C10
deployment only ever feeds it `ThC`-image messages, which is precisely why the
real system is safe while the generic statement is not. Legs 1 and 2 are then not
"no routing exists" but the sharper **"the hop's content is false for the generic
TW adversary"** — a statement-level fact, which is why no proof-level patch can
reach it.

### KIMI'S STRENGTHENING — the whole lemma is refuted, not just the open goal (VERIFIED)

I checked both citations at source rather than taking them:

* `is_chwcoll` (`:763-768`) and `is_chwpre` (`:807-812`) each carry
  `BaseW.val em'.[i] < BaseW.val em.[i]` as their **first conjunct**. Under a
  collision `em = em'` that is `x < x` — false at *every* index. So
  `!has_chwcoll` holds vacuously and `has_chwpre` is false. **Any collision pair,
  for any `sig`/`sig'`, refutes the entire five-hypothesis statement of
  `nhchwcoll_hchwpre_msg`**, not merely its admitted subgoal.
* The game's win condition (`:2604`) really does include `/\ P m /\ P m'`, so the
  adversary must land both messages on the constant-sum surface — and can, since
  the encoder is unkeyed and computable by it.

So §4's "inconsistent-if-completed" is, if anything, **under**-stated.

### LEG 3 IS MY WEAKEST LEG — do not lean on it

Kimi: leg 3's mechanism-fact (`qed` seals the proof term) is true, but the
conclusion "requires editing or forking the base file" **does not make the unit
hard, because this repo forks the base file routinely** —
`base-c10-fork/`, `_mut3_base/`, and especially
`experiments/wots-tw-incenc/chain/WOTS_TW_ES.ec`, which is exactly a
patched-statement copy carrying a shadow canary. A reviewer would swat leg 3 with
the incenc experiment. **The weight belongs on legs 1+2**: the hop's content is
false for the generic adversary. Leg 3 is a mechanism note, not an argument.

## 1b. THE TWO REVIEWERS DIVERGE ON LEG 1 — and the divergence kills my reason, not my conclusion

Both read source. **Kimi says leg 1 is confirmed; GPT-5.6 says leg 1 is REFUTED as
written.** Both are right about what they checked, and GPT is right about mine.

* **Kimi verified:** `encode_msgWOTS` is a function of `m` alone — the encoder is
  unkeyed. TRUE, and I had it.
* **GPT verified:** *"The encoder is unkeyed; its inputs need not be."* The game
  initialises seed-keyed oracles **before** `choose`, and `forge(ps)` receives
  `ps` (`:2519`, `:2560`), so the adversary's messages **can** be seed-adaptive.
  My phrasing — that the adversary "picks both messages" and can collide
  "offline, before the game starts" — is therefore **wrong**, and so is the
  weaker "unprotected by any hardness" I retreated to after Kimi's first hit.
  Two successive repairs of the same sentence, both still overreaching.

**What survives is simpler than either version, and both reviewers converge on it:**

> The admitted goal is a **universally quantified statement about a free op**, and
> `ps` does not occur in it. No probabilistic argument at any layer can establish
> a universal statement — and at deployed geometry this one is false.

Seed-withholding is irrelevant to it not because of anything about the adversary's
power, but because **the goal contains no probability at all**. That is the right
leg 1. GPT's exact words: *"Seed withholding may support a replacement proof, but
it cannot prove this universal admitted statement."*

**Convergent (both, independently, verified — strong evidence):** the strict digit
inequality shared by `is_chwcoll` (`:763`) and `is_chwpre` (`:808`) makes a
collision refute the whole lemma regardless of `ps`, address, or signatures; leg 2
stands; leg 3 stands; the Q2b tension is real. GPT adds that
`GFailCharged.ec:303`'s charged alternative **leaves the same base term**, so no
committed route bypasses the dependency.

**GPT's other correction, adopted:** my gate's `ledger class = 0` is **file-local**,
and the spike file `require`s `WOTS_TW_ES`, so the base admit *is* in its cone. The
gate now asserts the property that actually matters — that the file never applies
`nhchwcoll_hchwpre_msg` — instead of letting a file-local zero read as an
admit-free cone.

**GPT's remaining objection, accepted and unresolved:** the type-level collision
refutes the *universal base lemma*; it does **not** establish a reachable
`ThC`/SHA-256 collision or any deployed attack. That reachable-event gap is
exactly where seed-withholding still has value — in the replacement proof.

## 2. THE STRONGER FINDING — the admit is an INJECTIVITY demand on a domain that cannot support it

Verified at source today, all in `base-c10-split/WOTS_TW_ES.ec`:

| fact | line | value |
|---|---|---|
| `type dgst = bool list` | `:179` | — |
| `op n_m : int = 2 * n` — a **definition**, `ge1_nm` is a **lemma** | `:46`, `:48` | not axiomatised |
| `MDigestBlock` = `{x : dgst \| size x = 8 * n_m}` | `:191-193` | card = `2^(8*n_m)` = `2^(16n)` |
| `type msgWOTS = mdgstblock` — *"the ENCODER's domain: the wide digest"* | `:270` | **256 bits at n=16** |
| `op encode_msgWOTS : msgWOTS -> emsgWOTS` (free) | `:624` | codomain card = `w^len` |
| deployed `w^len = 8^43 = 2^129 <= 2^256` | `C10DeployedInstance.ec:101` | — |

So at deployed parameters the encoder maps **2^256 into 2^129**. It is
overwhelmingly many-to-one. `nhchwcoll_hchwpre_msg`'s open goal is exactly
injectivity on the `P`-gated surface. This is **not a lemma waiting for a
tactic** — it is a statement with no reason to be true, and (see §4) plausibly a
refutable one.

The admit's own comment already says the repair must be *"a game hop BEFORE the
case split — case-split-only is UNSOUND."* That comment is correct. What is new
here is **where** the hop can live: not at the WOTS-TW layer (unkeyed), and not
from outside (finished proof). Only inside a forked base file.

## 3. `RESULT-premise-reduction.md` IS STALE — demonstrated, not inferred

`experiments/tcollres-leg/RESULT-premise-reduction.md` claims:

> **Injectivity at C10 is FINE.** The digit map sends 128-bit digests into a
> 129-bit codeword space — `Proj129.c10_enc_inj_129`, exactly tight.

That was true **before the message-type split** (route D, dated 2026-08-01 in the
`WOTS_C_Real.ec` header). It is false now: the encoder's domain is the **wide**
256-bit `mdgstblock`, not a 128-bit `dgstblock`. `Proj129.c10_enc_inj_129` is a
statement about integers `x, y < 2^129` — the *codeword* space — and does not
give injectivity on a 2^256 domain.

Positive evidence of staleness (three independent citation failures — the file's
own line references no longer resolve):

| cited in RESULT-premise-reduction.md | current `base-c10-split/WOTS_TW_ES.ec` |
|---|---|
| `:563` encoder declaration | `:563` is a `ch` chain lemma; encoder is at **`:624`** |
| `:579` `two_encodings` **axiom** | `:579` is inside a chain proof; `two_encodings` is a **LEMMA** at **`:726`** |
| `:597` `enc_nonzero` | `enc_nonzero` **does not exist** — the sole textual hit at `:751` is a comment recording its deletion (2026-07-29) |

**This is the fifth `experiments/` FINDING/RESULT to go stale.** Consequence for
the ledger: `EncMsgInjOnThCImage`, which `PremiseReduction.ec` isolates as "the
only thing the chain does not already carry", is **the same demand as the admit**,
and its stated justification ("fine at C10, exactly tight") no longer holds.

## 4. THE HEADLINE — Q2b and the WOTS admit are in TENSION, not merely coupled

This is the part that reads badly if someone else finds it first.

* Q2b = pin `encode_msgWOTS` to C10's deployed base-8 digit map.
* Under that identification the encoder reads **129 bits** of a **256-bit** input
  (`sphincs-c10/src/wots.rs:26-45`; the state file records digit 42 pulling bit
  128 out of `digest[15]`). The top 127 bits are **ignored**.
* Therefore, under the identification, explicit collisions exist: any two wide
  digests agreeing on the low 129 bits and differing above collide, and both
  satisfy `P` (same codeword ⇒ same digit sum).
* Therefore **the identification REFUTES `nhchwcoll_hchwpre_msg`'s statement.**

So closing Q2b would make `base-c10-split/WOTS_TW_ES.ec` *inconsistent-if-completed*:
its admit could never be discharged by any completion, because the statement
would be provably false. **The ordering both the reviewers and I assumed is
backwards.** You cannot wire the deployed identification into the base file until
the admit is removed — and removing it means the forked-base charged campaign.

### Does the deployed lemma ALREADY pin the encoder? No — checked.

Kimi K3 raised the right worry mid-run: if `GprocQWired`'s deployed hypothesis
`hencb` pinned `encode_msgWOTS`, the artifact would *already* carry a premise
that (by the argument above) refutes its own admit — a live inconsistency, not a
future one. **It does not.** The deployed lemma's premises
(`GprocQWired.ec:418-427`) are:

| premise | what it pins |
|---|---|
| `n = c10_n`, `len = c10_len`, `k = c10_k` | scalar parameters |
| `STCRC_WC.G.CntrFT.card <= 2 ^ c10_r` | counter cardinality |
| `hemb : emb_in = c10_embg` | the **node/counter serialiser**, NOT the digit encoder |
| `hencb : forall p a x cc, encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)` | the **encode BRIDGE** — it relates the +C encoder to the base one; it says nothing about what `encode_msgWOTS` *is* |
| `forall ps0 ad0 m0, exists cc, predC (ThC ps0 ad0 m0 cc)` | grind success |

`hencb` is the bridge `PremiseReduction.ec` already identified as carried, not
the identification. **Q2b is genuinely open, and the current artifact is
consistent.** The tension in this section is a constraint on a *future* change,
not a defect in the present one.

*(Caveat, stated because the rest of this file is about my own over-claiming:
this bullet chain is a mathematical argument about the deployed digit map, not a
machine-checked EasyCrypt theorem. Turning it into one is §5's L4.)*

## 5. WHAT THE SPIKE SHOULD PRODUCE INSTEAD

New file, parallel-and-promote, base untouched:

* **L1** — the admit's statement is *equivalent* to injectivity of
  `encode_msgWOTS` on `{m | P m}`; in particular it forces `tgt_witness` to be
  the unique preimage of its own codeword. *(Cheap, abstract, certain.)*
* **L2** — hence the admit and `PremiseReduction.ec`'s `EncMsgInjOnThCImage` are
  the same demand. *(Cheap; connects two separately-tracked open items.)*
* **L3** — non-injectivity by cardinality: `w^len < 2^(8*n_m)` ⇒ no injection
  exists. `FinType`/`Finite` are available in-tree (`PRE_From_SPR_DSPR.ec:2,24`)
  but `card msgWOTS` / `card emsgWOTS` instances are **not** built. Feasibility
  **unmeasured** at time of writing.
* **L4** — the §4 refutation as a hypothesis-carrying theorem: *if* the deployed
  identification holds, *then* the admit's statement is false. Needs an explicit
  witness pair rather than a counting argument, so it may be cheaper than L3.

### THE NEXT UNIT IS CHEAPER THAN I THOUGHT — the concrete digit map is already built

Checked after Kimi recommended the clone route. `cdrafts-split/C10DeployedInstance.ec`
already has the deployed extraction as a concrete op over `bool list` — which is
exactly `dgst`, and `msgWOTS` is a subtype of it:

```
op c10_digit_at (bs : bool list) (i : int) : int =                         (:382)
  b2i (nth false bs (c10_log2_w * i)) + 2 * b2i (... + 1) + 4 * b2i (... + 2).

lemma c10_deployed_digit_map_is_wellformed (bs : bool list) (i : int) :    (:398)
  0 <= c10_digit_at bs i < c10_w.

lemma c10_window_bits : c10_len * c10_log2_w = 129.                        (:405)
```

and the header at `:378-381` states outright that since this fork **retired both
encoding axioms**, *"well-definedness is the ONLY requirement, so the deployed map
is admissible as `encode_msgWOTS`."*

So the refutation does not need new arithmetic — it needs a **witness pair**:
`tgt_witness` and a copy of it with one bit above index 128 flipped. `c10_digit_at`
reads only indices `0..128` (43 digits x 3 bits), so the two encode identically;
`P tgt_witness` holds by definition; `MDigestBlock.val` is injective so the pair is
distinct; and `admit_refuted_by_surface_collision` (already proved, above) closes it.

**Estimated cost: hours, not days** — the residual work is bounded `bool list`
manipulation (length preservation under the flip, agreement below index 129,
disagreement at the flipped index), plus either Kimi's clone with its 12
obligations or a hypothesis-carrying statement in the abstract namespace. I have
NOT attempted it; the estimate is from reading the pieces, and my estimates run high.

**The durable artifact improvement**, if L3 or L4 lands: a gate assertion that no
closure member applies the admit-tainted theorem — upgrading the disclosure from
*"currently un-applied"* to *"un-appliable, permanently."* That is the honest
permanent status of `Pr[M_EUF_GCMA_WOTSTWESNPRF ...]` as an unreduced summand,
and it retroactively justifies the current architecture as the **only sound**
choice rather than an unfinished one.

## 5a. RESULT — L1/L2/L3/L4 LANDED, GATE GREEN

`scratch/wots_admit_is_injectivity.ec`, gated by `scratch/spike_wots_admit_gate.sh`.
**Zero admits, zero axioms.** Base tree untouched.

```
DRIVER 1  easycrypt compile            rc=0
DRIVER 2  easycrypt cli -iterate       76 cmds, 0 diagnostics
LEDGER    admit/axiom outside comments 0
NC-A  appended `lemma : false`                     REJECTED
NC-B  drop P from EncInjOnP1 (=> global inj)       fails inside encinjonP_iff_encinjonP1
NC-C  drop P m from the refutation                 fails inside admit_refuted_by_surface_collision
NC-D  shortfall exponent 127 -> 126                fails inside c10_codomain_shortfall
### SPIKE RESULT: GREEN (0 failures)
```

Proved:

| lemma | content |
|---|---|
| `P_encode_congr` | `P` is a property of the CODEWORD — available only because `P` became a **definition** (2026-07-29); under the old abstract `P` this was not derivable |
| `admitgoal_iff_encinjonP` | **the admit IS injectivity** on the constant-sum surface — interderivable, not merely implied |
| `encinjonP_iff_encinjonP1` | the second surface hypothesis is redundant |
| `admit_forces_tgt_witness_unique` | the admit forces `tgt_witness` to be the **unique** preimage of its own codeword |
| `admit_refuted_by_witness` / `..._by_surface_collision` | **one** collision on the surface refutes it |
| `c10_codomain_shortfall` | `2^(8*n_m) = w^len * 2^127` at deployed C10 — the codomain is 2^127 times smaller |
| `c10_domain_exceeds_codomain` | hence `w^len < 2^(8*n_m)`, strictly |

**NC-B is the decisive control.** Deleting the surface restriction turns
`EncInjOnP1` into global injectivity, and the mutant breaks at exactly the step
that consumes `P_encode_congr`. So L1s genuinely uses the congruence and is not
silently proving something trivial.

**Gate-design note worth keeping:** the first cut of this gate predicted the
three control failure sites by line offset and reported WARN on three *correct*
controls. Grading now matches on the **containing declaration**, which is what
the control actually asserts about. A control graded by line number measures the
gate author's arithmetic, not the proof.

**What is still NOT proved, stated plainly:** `encode_msgWOTS` is free and
`n`/`w`/`len` are abstract, so `AdmitGoal` is **satisfiable** in the abstract
theory (small domain, large codeword space) and therefore **not refutable here**.
L3 supplies the refutation *shape*; the witness it consumes is exactly what Q2b
would produce. Making the refutation unconditional would additionally need
`card` instances for `MDigestBlock` and `EmsgWOTS`, which this development does
not build. **That gap is the honest boundary of this spike.**

## 5b. THE SAME INEQUALITY WAS ALREADY IN THE TREE — READ AS A PAYOFF

Found by me on a self-check, before a reviewer could:
`cdrafts-split/C10DeployedInstance.ec:101` already proves

```
lemma c10_split_removes_the_width_obstruction :
  c10_w ^ c10_len <= 2 ^ (8 * c10_n_m).
```

under the header *"THE PAYOFF: at the deployed geometry the encoder's domain now
COVERS its codomain, where before it fell short by exactly one bit."*

**That is the same inequality as my `c10_domain_exceeds_codomain`, read in the
opposite direction.** The message-type split was adopted *because* it made the
domain exceed the codomain — that is what dissolved the old 128-vs-129 width
obstruction. The finding of this spike is that **the identical fact makes the
encoder irreparably many-to-one**, and therefore makes the admit's injectivity
demand unsatisfiable at deployed geometry. One inequality; a fix on one side and
the blocker on the other.

So I claim **no novelty for the inequality**. What is new here:

* it is stated in the **abstract namespace** (`n`/`w`/`len`/`n_m` as they appear
  in `WOTS_TW_ES.ec`, where the admit actually lives) rather than at the
  `c10_*` constants of the deployed-instance record — the two are in different
  namespaces and neither implies the other without the identification;
* it is **strict**, and carries the exact multiplier `2^127`
  (`c10_codomain_shortfall`), which is the number that says how badly
  many-to-one the encoder is rather than merely that it fits;
* it is **connected to the admit** via L1/L2/L3, which is the part nothing in
  the tree did.

*(This is the same error class Kimi caught on Q2a — claiming a result the tree
already had. Checking for it first is now part of the routine.)*

## 6. WHAT DOES *NOT* CHANGE

**The deployed wallet is unaffected, and this is not an attack.** C10's WOTS layer
never encodes an adversary-chosen value — it encodes key-determined internal nodes
(`sphincs-c10/src/fors.rs:265-268`: `compute_fors_pk` takes no message argument).
The classification stands where `FINDING-def11-is-unsound-at-c10.md` put it:
**proof-technique limitation, not a vulnerability.** Nothing in the certified
GREEN artifact is invalidated — the admit was and remains non-load-bearing,
because the capstone never applies the theorem that consumes it. This finding
makes that architectural choice *permanent and principled* instead of provisional.
