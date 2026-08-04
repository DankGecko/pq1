# RESULT — the 129/128 projection lemma (repairs a defect I introduced)

**Status: GATED, NOT WIRED.** `Proj129.ec` compiles as an explicit target with
**0 admits** and **1 inherited axiom** (`gt1_wd : 1 < wd`, from `EncoderBridge.ec`
— radix nondegeneracy, necessary not incidental). It is a **standalone leaf**: it
is not `require`d by anything in `closure-c10.txt`, so nothing in the PQ1 chain
consumes it yet. Read every claim below as a statement about *arithmetic*, not
about the port.

## Why this exists — a defect in my own prior unit

`EncoderBridge.c10_enc_inj` proves the digit map injective on `[0, 2^128)`, and
`RESULT-encoder-bridge.md` narrated that as *"129 ≥ 128, so there is ONE BIT to
spare"*. **The deployed encoder has no spare bit.** `sphincs-c10/src/wots.rs:35-46`
extracts `digit[i] = (digest >> 3i) & 7` for `i ∈ 0..42`, consuming bits **0..128
— 129 bits**. Digit 42 is bits 126,127,128, and bit 128 is that digit's MSB,
weight 4. A theorem about `[0, 2^128)` does not cover the deployed input range.

Found by GPT-5.6 in the 2026-07-27 adversarial review. `EncoderBridge.ec` now
carries a SUPERSEDED banner at the defect site pointing here.

## What is proven

| lemma | content |
|---|---|
| `dsum_hi` | prepending a top digit `c` adds exactly `c` to the digit sum |
| `dsum_surj` | **every** sum in `[0, l*(wd-1)]` is reached by some `n < wd^l` |
| `c10_enc_inj_129` | the repair: injective on the FULL `[0, 2^129)`, **exactly tight** (`8^43 = 2^129`) |
| `c10_step` | flipping bit 128 moves the digit sum by **exactly 4** |
| `c10_low128_determines` | on the sum-205 surface, the low 128 bits **determine** the value |
| `c10_low128_faithful` | …hence determine the codeword |
| `c10_target_sum_reachable` | the sum-205 surface is **NONEMPTY** |
| `negctl_129th_bit_is_NOT_free` | without sum=205, low-128 agreement does **not** determine the codeword |
| `negctl_witness_sums_differ_by_4` | the mechanism, concretely, at `x = 0` |

## The interesting one

The port models a digest as a **128-bit** `dgstblock`; the deployment feeds
**129 bits** to the digit map. `c10_low128_determines` says that mismatch costs
nothing **on the set the verifier actually accepts** — `pk_from_sig` returns
all-zero unless the digit sum is exactly `TARGET_SUM` (`wots.rs:155-160`), so only
the constant-sum surface is ever live. Flipping bit 128 moves the sum by 4, so it
cannot preserve `sum = 205`.

So the 129th bit is **free in general and pinned only on the constant-sum
surface**. That is a sharper statement than "spare", and it is the opposite of
what I wrote last time.

## What this does NOT establish — read before quoting

1. **It is the ARITHMETIC half only.** It does *not* prove that the model's
   abstract `ThC`-produced `dgstblock` **is** the low 128 bits of deployed
   `wots_digest`. `ThC` is abstract (`WOTS_C_Real.ec:175`). Read the result as:
   *given* that identification, the 128-bit index loses nothing. **The
   identification itself is still owed** — it was owed before this file and it is
   owed after it.
2. **Digit ORDER is not addressed.** `int2dig` is most-significant-first (index 0
   = bits 126..128); the firmware is least-significant-first (index 42 = bits
   126..128). Digit SUM and INJECTIVITY are order-invariant so both results
   transfer as stated; the **chain assignment** (which digit drives which WOTS
   chain) is *not* order-invariant and is not covered.
3. **No probability is bounded.** `Pr[G /\ COLL]` is untouched, as before.
4. **Not wired.** See the status line at the top.

## Gate receipt (`gate_proj129.sh`)

Mutations are applied to a **container-side copy**, never to the tracked source —
two controls were voided earlier this session by mutating a tracked file (once a
restore raced a concurrent compile; once a container-uid permission denial
silently skipped the mutation while the control still printed a verdict). Every
control now prints a `MUTATED_*` witness, so a mutation that fails to apply is
reported INVALID rather than passed.

```
COPY_IDENTICAL=yes   BASE_RC=0   ADMITS=0   AXIOM_DECLS_IN_FILE=0
axiom closure: EncoderBridge.ec:7:axiom gt1_wd : 1 < wd     (the only one)
MUTATED_A=1  NEGCTL_A_RC=1     inject `lemma : false`            -> FAILS
MUTATED_B=1  NEGCTL_B_RC=1     c10_pow43 exponent 43 -> 42       -> FAILS
MUTATED_C=1  NEGCTL_C_RC=1     drop sum hyps at SAME ARITY       -> FAILS
SRC_UNTOUCHED=yes    FINAL_RC=0
```

**Control C is the load-bearing one.** Arity is preserved, so the intro pattern
still matches and the failure is *semantic* — the constant-sum hypothesis is
genuinely doing the work at that exact site, not decorating it.

**Anti-vacuity is a theorem, not an assertion.** `c10_target_sum_reachable`
proves the sum-205 surface is nonempty, so `c10_low128_determines` is not a true
statement about the empty set (trap T3). It follows from `dsum_surj`, which is
proved by induction reusing `dsum_hi`.

## Tooling defect fixed alongside

`ec-c10.sh` ended in `| tail -30` with no `pipefail`, so its exit status was
*tail's* — 0 essentially always, even when EasyCrypt failed. Any caller writing
`bash ec-c10.sh f.ec && echo PASS` got a **false pass**. Now fixed and verified
empirically (a deliberately broken file returns `SCRIPT_EXIT=1`).

**The 18-file receipt was not affected by this**: `wire_test.sh` invokes
`easycrypt` directly and captures `rc` itself. The defect was confined to
interactive use.

`wire_test.sh` had two real defects, both now fixed: it did **not purge `.eco`**
before compiling (trap T2 — EasyCrypt does not invalidate a dependent's `.eco`
when a required theory changes, so a "green" run could be reporting on objects
built against a previous `base-c10`), and its `while read` dropped the last
closure entry when the file lacked a trailing newline. It now purges, reports
`ECO_PURGED`, and asserts `CLOSURE_COMPILED == EXPECTED`.
