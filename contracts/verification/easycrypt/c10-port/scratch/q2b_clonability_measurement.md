# Q2b IS NOT STRUCTURALLY BLOCKED — measured, 2026-08-12

Residual Q1 (`SphincsC10Content.ec:66`) says EasyCrypt *"cannot re-interpret an
already-declared op **from inside** the theory"*. I assumed that also blocked
pinning `encode_msgWOTS` from OUTSIDE. **It does not.** Measured in-container
(r2026.02).

## The measurement

`clone WOTS_TW_ES as PINNED with op encode_msgWOTS <- <concrete> proof *.`
is **accepted**, and `proof *` yields exactly **12 obligations**:

    ch0  chS                          <- the WOTS hash-chain axioms
    ge1_n  ge2_len  val_log2w         <- geometry refinements
    ge1_c  ge2_adrslen
    ddgstblock_ll  dpseed_ll          <- losslessness
    HA.Adrs.inhabited                 <- inhabitation witnesses
    WAddress.inhabited
    valid_widxvals_idxvals

Notably **`two_encodings` is NOT among them** — it is a lemma now
(`WOTS_TW_ES.ec:726`) and re-proves under substitution. The encoder-pinning
fight is genuinely no longer against it.

The geometry obligations are the easy half: `C10DeployedInstance.ec:62-67`
already proves C10's numerals admissible (`c10_admissible_n`, `_log2w`, `_len`,
`c10_deployed_parameters_are_admissible`).

## THREE FALSE GREENS ON THE WAY — the methodology matters more than the number

1. **Plain `clone` (no `proof *`) discharges NOTHING.** Control:
   `clone WOTS_TW_ES as BADLEN with op len <- 1.` — `len` carries `2 <= len`
   (`ge2_len`) — **compiles, EXIT 0**. Obligations are carried into the clone as
   assumptions. So a positive result from a plain clone measures nothing.
2. **`clone ... proof *` with no `realize` ALSO returns EXIT 0** — because the
   file ENDS with the obligation open. This is precisely the silent
   open-proof-at-EOF defect `cert_gate_split.sh` PHASE 1d was written for
   (*"EasyCrypt returns rc=0 for a file that ENDS mid-proof"*). Both of my
   "successful" probes were this artifact.
3. The tell that broke it open: adding a `lemma` after the clone gave
   `cannot process [axiom] inside a proof script` — i.e. the clone had left a
   proof open. **Only then** did `easycrypt cli` list the 12 obligations.

**Lesson: an EXIT-0 clone probe is worthless without either (i) a following
declaration to prove the file did not end mid-proof, or (ii) reading the
obligation list from `cli`.** Same family as
[[feedback_absence_from_wrong_token]] — a check that could not have failed.

## HONEST LIMIT ON THIS MEASUREMENT

The probe substituted a **constant** encoder. Under a constant encoder
`two_encodings`'s hypothesis `encode m <> encode m'` is unsatisfiable, so its
re-proof may be **vacuous**. With C10's real digit map it must genuinely
re-prove. So "12 obligations" is a **lower bound** for the deployed pinning, not
the final number, and the encoder-specific risk is not yet measured.

Next measurement, if this route is taken: substitute a NON-DEGENERATE encoder
(e.g. the base-8 digit map on the low 129 bits) and re-count.

---

# CORRECTION to my Q2a claim (Kimi K3, 2026-08-12) — and the sharper picture

Kimi found `c10_deployed_encoder_attains_target` (`C10DeployedInstance.ec:446`),
which I had not. **I presented Q2a as newly closed; a related attainment lemma
already existed.** Verified at source.

But it does **not** subsume my Q2a, and the reason is the whole point:

| lemma | object | in the port's types? |
|---|---|---|
| `c10_deployed_encoder_attains_target` (`:446`) | `bigi predT (c10_digit_at c10_witness_bits) 0 c10_len = c10_target_sum` — the **deployed digit map** over `bool list` | **NO** — `c10_digit_at` (`:382`) is standalone |
| `q2a_digitsum_205` (mine) | `digitsum q2a_cw = 205` — the **port's** `digitsum : emsgWOTS -> int` | **YES** |

`C10DeployedInstance.ec` mentions `digitsum`/`encode_msgWOTS` only in COMMENTS
(`:123-130`), which say verbatim that it "does NOT say 205 is in the image of
`digitsum o encode_msgWOTS` -- that needs the ENCODER pinned".

So the honest state is **two proven ends of one bridge**:
* deployed side: the real digit map attains 205 (`:446`);
* port side: the port's own `digitsum` attains 205 on an exhibited codeword (mine);
* **missing span: the encoder identification** — exactly Q2b, exactly Q1's wall.

That is a better framing than either "Q2a was open" (mine, wrong) or "Q2a was
already done" (over-reading Kimi). Neither end touches the other, and no amount
of further work at either end closes the span — same conclusion Kimi reaches for
route C.

## Where my clonability measurement and Kimi's verdict meet

Kimi says Q2b is "unprovable by construction". I measured that
`clone WOTS_TW_ES ... with op encode_msgWOTS <- <concrete> proof *` **is
accepted**, with 12 obligations. These are not in conflict:

* the clone mechanism works and is mechanically cheap (geometry half already
  proven at `C10DeployedInstance.ec:62-67`);
* but a clone yields a **second development**. It does not make the *existing*
  closure's `encode_msgWOTS` be the digit map. To consume it you must
  re-instantiate the 31-file closure at the clone.

So my measurement refines rather than refutes: **route A's cost is not the
realization (12 obligations, cheap) — it is the re-instantiation.** Kimi reached
the same conclusion from architecture; I reached the cost split from the
obligation count. Worth recording because my earlier instinct was that the
realization would be the expensive part, and it is not.
