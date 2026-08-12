# WOTS/+C LEG — TRUE STATE, 2026-08-12

Written after reading `experiments/wots-tw-incenc/` and `experiments/tcollres-leg/`,
which **neither external reviewer read**. Every claim below verified at source.

## THE HEADLINE: both reviewers' recommendation is SUPERSEDED by in-repo research

GPT-5.6 and Kimi K3 both recommended charging the WOTS encoding collision and
discharging it against a T-COLL-RES-shaped assumption (GPT correctly warned not to
*name* it Def 11, but still recommended the structure).

**`experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md` (2026-07-27)
already falsified that route**, and its title is literally
*"STOP: the planned CiC Def-11 hop is UNSOUND at deployed C10"*:

* Def 11's oracle **samples `rho` uniformly from `R` on every attempt**
  (`paper-cic-2-1-13.txt:876-878`). C10 **deterministically enumerates the minimal
  counter** over a wholly public map (`sphincs-c10/src/wots.rs:59-70`,
  `for count in 0..10_000_000u32`) — no key, no sampling, publicly re-checkable.
  **Effective `|R| = 1`.**
* Restated faithfully at the deployed encoder, Def 11 is **FALSE, not merely
  unproven**: birthday-collide inside `|C_T| = 2^114.094` at ~**2^72.3** hashes,
  memoryless via van Oorschot–Wiener. That is **23 bits BELOW** the project's own
  96-bit floor.
* `eq (14)` needs `log|R| >= ~170.58`; actual is `23.25` — and 23.25 is the
  **iteration cap**, not entropy (the counter carries ~0 bits).
* Sharper addendum: Def 11 verbatim is **VACUOUS** at every reachable corner —
  non-vacuity at `q = 2^96` would need `|R| > 2^126.91`.

**THE DEPLOYED WALLET IS NOT AFFECTED.** There is no attack. C10's WOTS layer never
encodes an adversary-chosen value — it encodes key-determined internal nodes
(`fors.rs:265-268`: `compute_fors_pk` takes no message argument). The adversary
cannot inject a chosen `m` into the grinder. Classification: **proof-technique
limitation, not a vulnerability.**

So: do NOT build the ENC_COLL_WOTS → T-COLL-RES reduction the reviewers proposed.

## WHAT IS ALREADY DONE (verified, not assumed)

1. **Injectivity dependency LOCALIZED to exactly one proof step.**
   `experiments/wots-tw-incenc/` weakened `two_encodings` to Def-9 codeword
   inequality; the 6314-line MM45 WOTS-TW development then breaks at **exactly one
   site**, the forgery site — predicted before the run, confirmed
   (`RESULT.md`: one error at the predicted line; probe with the gap bridged →
   `RC=0`, whole development compiles). That one gap is today's admit
   `nhchwcoll_hchwpre_msg` (`WOTS_TW_ES.ec:1513`).

2. **The `predC` vacuity hazard is FIXED** — and the finding that reports it is now
   STALE. `FINDING-thc-width-is-unfixed.md` item 1 says "`predC` carries NO axiom
   anywhere in the closure, so `predC := fun _ => false` satisfies everything and
   zeroes the LHS". That WAS true. It is not now: `WOTS_C_Real.ec:279` defines
   `op predC (d : msgWOTS) : bool = P d` — a **definition, not an axiom**
   (deliberately: a definition cannot introduce inconsistency), and `target_sum` is
   derived from `tgt_witness` rather than being a free constant. `target_sum` still
   appears 0 times in `WOTS_C_Scheme.ec` because the tie was made in
   `WOTS_C_Real.ec` instead.

3. **The correct repair is identified and is NOT Def 11**: discharge inside the +C
   GCMA game using **seed-withholding** — `proc choose() : unit` takes no `ps`, and
   `ps` arrives only at `proc forge(ps : pseed)`
   (`cdrafts-split/WOTS_C_Scheme.ec:142-143`, `:207` `is_fresh <- m' <> m`, `:210`
   `dist_wgpidxs`). Since `wots_digest` absorbs `pk_seed` first
   (`sphincs-c10/src/hash.rs:350-365`), **no encoding is computable at
   choose-time**, killing the precomputation birthday at that site with no
   message-independence assumption. Honest caveat: `pk_seed` IS public in the
   deployed system (`params.rs:85`), so seed-withholding is a **modelling
   restriction** (R2) that makes the proof go through; the real-world safety on
   this axis rests on message-independence (R1), which is asserted, not proven.
   **Both must be recorded.**

## THE LIVE BLOCKER — and it is a LEDGER CHANGE, not a lemma

`ThC`'s output width is unfixed:

| | width | source |
|---|---|---|
| MODEL `ThC` | `dgstblock` = `8n` = **128** at n=16 | `WOTS_C_Real.ec:175` |
| DEPLOYED `wots_digest` | `[u8;32]` = **256**, untruncated | `hash.rs:344-364` |
| bits the digit map CONSUMES | **129** of those 256 | `wots.rs:26-45` |

Digit 42 sits at bit_offset 126 and pulls **bit 128** out of `digest[15]`.
**Nothing bridges 256 → 129.** And the direction is **optimistic, not
conservative**: the model makes an encoding-collision event *empty* that the
deployment genuinely *has*. Faithfulness defect at zero quantitative cost.
(Not an attack: exploiting it needs a 129-bit **target** partial preimage ~2^129,
not a birthday. An earlier ~2^64.5 birthday sketch was withdrawn by its author.)

## THE UNIT I AM STARTING — wire `Proj129` into the port

`experiments/tcollres-leg/Proj129.ec` proves

    c10_low128_determines (x y : int) :
      wd = 8 => 0 <= x < 2^129 => 0 <= y < 2^129
      => dsum (int2dig 43 x) = 205 => dsum (int2dig 43 y) = 205
      => x %% 2^128 = y %% 2^128 => x = y

i.e. **on the constant-sum surface, the low 128 bits DETERMINE the full 129-bit
value.** That is exactly the gated surface `predC` cuts out — so the model's
128-bit `dgstblock` is sufficient *where the +C gate operates*, which dissolves
the width defect on the branch that matters.

**But it is GATED, NOT WIRED** (`RESULT-proj129.md`: "standalone leaf … not
`require`d by anything in `closure-c10.txt`, so nothing in the PQ1 chain consumes
it yet. Read every claim below as a statement about *arithmetic*, not about the
port"). Worse, `FINDING-thc-width-is-unfixed.md`'s own self-correction records
that `Identification.ec` never requires `WOTS_TW_ES` or `SPHINCS_PLUS`, and
`EncoderBridge.ec:29-30` declares its own `op wd` **unconnected** to base-c10's
`log2_w` — so **EasyCrypt has verified nothing there about `encode_msgWOTS`; the
type correspondences are hand transcription.**

**The unit: turn that hand transcription into a machine-checked connection.**
Connect `Proj129`'s arithmetic to the port's real `encode_msgWOTS` / `log2_w` /
`len` / `target_sum`, so the 129→128 bridge becomes a theorem about the port
rather than about `int`. This is the parallel-and-promote pattern (new file, new
lemma, nothing mutated) that `GprocQBound`/`GprocQWired` established.

Why this unit and not the reviewers': it is the *prerequisite* for any sound
treatment of the collision event, it removes a faithfulness defect rather than
adding an assumption, and unlike the Def-11 route it is not falsified at C10.
