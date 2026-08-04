# BLOCKING FINDING — `ThC`'s output width is unfixed, and the identification question is not well-posed until it is fixed

Found 2026-07-27 by a 9-agent adversarial workflow, re-verified at source by me
before writing this. It is the most important result of the session and it was
**not** on my radar; I was busy proving things one level down.

## The mismatch

| | width | source |
|---|---|---|
| MODEL `ThC` | `dgstblock` = `8*n` bits = **128** at `n=16` | `cdrafts/WOTS_C_Real.ec:175` |
| DEPLOYED `wots_digest` | `[u8; 32]` = **256 bits, untruncated** | `sphincs-c10/src/hash.rs:344-364` |
| bits the digit map CONSUMES | **129** of those 256 | `sphincs-c10/src/wots.rs:26-45` |

The firmware's own doc-comment is explicit: *"Returns the full 32-byte digest for
base-w digit extraction."* And digit 42 sits at `bit_offset = 126`,
`byte_idx = 16`, `bit_in_byte = 6` — `6 + 3 > 8`, so it takes the spans-two-bytes
branch and pulls **bit 128** out of `digest[15]`. 129 bits live, 127 dead.

## Why it decides the question

`PremiseReduction.EncMsgInjOnThCImage` — the premise the whole identification
route exists to discharge — is **true or false depending on which reading of
`ThC` is intended**, and nothing in the repo pins it:

| reading | digit map injective on it? | the premise |
|---|---|---|
| `trunc_129(wots_digest)` | yes, globally (`8^43 = 2^129`, exactly tight) | **TRUE** of the deployment |
| `wots_digest` (what the firmware computes) | **no — 2^127-to-1** | **FALSE**; `Composition.orphan_empty` is unsound at deployed parameters and the composition really is four-way with an uncharged branch |
| `dgstblock` at `n=16` (what the model says) | yes (128 < 129) | true in the model, but the model is then not C10 |

`Proj129.c10_low128_determines` bridges **129 → 128** on the constant-sum surface
and is correct for that. **Nothing bridges 256 → 129.**

## The direction is the wrong one

The model's 128-bit `dgstblock` makes an encoding-collision event **empty** that
the deployment genuinely **has**. That is *optimistic*, not conservative — the
usual excuse ("the model is a conservative abstraction") does not apply.

**This is not an attack.** Exploiting it requires a 129-bit *target* partial
preimage (~2^129), not a birthday collision. An earlier sketch in the review
claimed ~2^64.5 via birthday; that was wrong and its author withdrew it. Nothing
here changes the deployed security level.

But a hypothesis that is false of the real system is a faithfulness defect even
at zero quantitative cost, and it was unrecorded.

## The cost of each repair

* **Adopt `ThC = trunc_129(wots_digest)`.** Then injectivity is exact and the
  premise is true. Price: the downstream S-TCR(+C) assumption becomes target
  collision resistance of a **129-bit-output** function — strictly stronger than
  the SHA-256 statement the ledger currently names. That change must be made
  explicit in the assumption ledger, not absorbed silently.
* **Keep 256-bit and charge the collision event.** Honest, and the term is
  ~2^-129 per attempt, but it adds a summand nothing currently carries.

Either way it is a **ledger change**, not a lemma.

## Three further corrections this surfaced

1. **`predC` carries NO axiom anywhere in the closure** — the repo states this
   itself (`cdrafts/SphincsC10Content.ec:492`). So `predC := fun _ => false`
   satisfies every predC statement and zeroes the LHS of the bound. Every
   predC-relativized claim inherits that vacuity hazard until predC is tied to
   the digit sum, which `WOTS_C_Scheme.ec` does **not** do (`target_sum` appears
   zero times in it).

2. **The "first z digits are zero" half of predC is FORS+C's, not WOTS's.**
   `WOTS_C_Real.ec:178-179` describes both halves; deployed WOTS gates on the sum
   **only** — `wots.rs:66`, `wots.rs:160`, and `SPHINCsC10Asm.sol:170`. A predC
   carrying a leading-zeros conjunct for WOTS would be *unfaithful*, not more
   complete. I propagated this error into the workflow prompt; it was caught.

3. **Which leg is conditional was backwards in my write-up.** I said the honest
   leg was easy and the forgery leg was the hard one. It is the reverse:
   * forgery leg is **unconditional** (`WOTS_C_Scheme.ec:101,103` gates on
     `okC <- predC (ThC ps ad m counter)` and conjoins it to acceptance);
   * honest leg is **conditional** — `wotsc_grind_targets_predC`
     (`WOTS_C_Real.ec:208-210`) needs `exists c, predC (ThC ps ad m c)` as a
     premise (capstone premise N2), and that carries an uncharged probability
     term: the firmware bounds the grind at `0..10_000_000` and **panics** on
     failure (`wots.rs:62-74`), a strictly smaller search than the model's
     never-failing `grind` (`Grind.ec:79-80`).

## And a correction to my own committed work

`Identification.ec` proves everything about `enc_c10 : int -> codeword` with
`codeword = int list`. It **never requires `WOTS_TW_ES` or `SPHINCS_PLUS`**, and
`EncoderBridge.ec:29-30` declares its own `op wd` unconnected to base-c10's
`log2_w`. So EasyCrypt has verified nothing there about `encode_msgWOTS`; the
type correspondences are hand transcription. Commit `ec5de5c`'s message said "the
NAIVE form is PROVED IMPOSSIBLE" — that over-claims by exactly that gap. The
file's header now carries the correction.

Separately: **base-c10 does not pin C10's geometry** (`n`, `log2_w`, `len` are all
`{ int | ... }` constraints at `WOTS_TW_ES.ec:28,34,53`). Making the geometry
*expressible* is not *instantiating* it. So the 2^123.76-vs-2^128 counting
obstruction is a true statement about an instantiation that does not exist in
this development, and **base-c10 must not be described as inconsistent**.

## Status

`Pr[G /\ COLL]` remains entirely uncharged. `WOTS_TW_ES.ec:1353` remains admitted
and propagates past its section into `FL_SL_XMSS_MT_ES.ec:6342`. **C10 is not
proven at deployed parameters, and the identification route cannot be declared
well-posed until `ThC`'s width is fixed.**
