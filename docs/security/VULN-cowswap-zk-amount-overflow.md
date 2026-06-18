# VULN — CowSwap ZK clear-signing: field-overflow amount forgery

**Severity:** Critical (breaks WYSIWYS for CoW Swap orders)
**Component:** `circuits/lib/format.circom :: FormatTrimmedAmount`
(used by `circuits/cowswap/eip712_order/circuit.circom`)
**Found:** 2026-06-10 (ZK clear-signing soundness audit)
**Status:** **RESOLVED 2026-06-10** (both cowswap AND aave fully closed — circuit bound + native guard + regenerated VKs on both paths)
**PoC:** `docs/cowswap-zk-poc/forge_amount_witness.py`
**Negative test:** `docs/cowswap-zk-poc/run_overflow_negative_test.sh`

## Resolution (2026-06-10)

Closed from **both** sides — in-circuit and in-firmware — so a field-overflow
amount forgery can no longer pass:

1. **Circuit root cause (in-circuit bound).** `FormatTrimmedAmount`
   (`circuits/lib/format.circom`) now range-checks `raw_amount` with
   `Num2Bits(190)` *before* the `raw_amount * scale_factor` multiply. With
   `raw_amount < 2¹⁹⁰` and `scale_factor ≤ 10¹⁸`, the product is
   `< 2¹⁹⁰·10¹⁸ < 2²⁴⁹·⁸ < r` over ℤ — it can never wrap the scalar field, so
   the `(int, frac, remainder)` recomposition is exact, not mod-r. 190 bits is
   lossless: a displayable amount is `≤ 10¹⁰·10¹⁸ = 10²⁸ ≈ 2⁹³·⁴ ≪ 2¹⁹⁰`. The
   identical fix is applied to `circuits/aave_v3/formatting.circom :: FormatAmount`.

2. **Firmware defense-in-depth (native bound).** `secure/src/tx/eip712/cowswap`
   gained `amount_within_field_safe_bound()` (const `RAW_AMOUNT_FIELD_SAFE_BITS =
   190`), called in `verify_and_bind_trailer` (step "1b") right after the Groth16
   verify: both `canonical[68..100]` (sellAmount) and `canonical[100..132]`
   (buyAmount) are rejected if `≥ 2¹⁹⁰`, *before* the ZK-bound `readable` is
   trusted. This closes the class on-device independent of the circuit — even a
   future circuit regression cannot produce a display/actual mismatch of this
   kind.

3. **Regenerated artifacts (cowswap).** The cowswap circuit grew past the pot14
   ceiling (17,679 constraints — note: even the *pre-fix* circuit already
   exceeded 2¹⁴, so the committed zkey was always built out-of-band with **pot16**;
   `circuits.json`'s `"ptau": "pot14…"` for this circuit is wrong). Rebuilt with
   `build/ptau/pot16_bls12_381_final.ptau` via the manual pipeline (groth16 setup
   → contribute with the pinned `contribution.seed` → verify → export). New
   `secure/data/vks/cowswap_eip712_order.vk.bin`
   (`sha256 e0de34d8…`), re-pinned `circuits/cowswap/eip712_order/circuit_final.zkey`,
   and `cargo run -p dbgen` re-pinned `VK_DB_ROOT`
   (`0086…` → `3cda5293…`) + `nonsecure/src/vk_db.bin`. `ERC20_POSEIDON_ROOT`
   unchanged (token list untouched). A fresh proof verifies end-to-end against the
   new VK (`gen_cowswap_eip712_e2e_vector.js` → snarkjs `groth16 verify` OK).

4. **Tests.**
   * Native: `secure/src/tx/eip712/cowswap/extra_tests.rs` — the exact PoC
     254-bit forged sellAmount is rejected by the bound; realistic amounts (incl.
     the 10²⁸ max-displayable) and the 2¹⁹⁰ boundary are pinned.
   * Circuit: `run_overflow_negative_test.sh` compiles an isolated
     `FormatTrimmedAmount` harness and asserts the forged witness now FAILS
     witness generation while the benign one succeeds.

### Aave path — also fully closed (5/6)

The Aave clear-sign path (`verify_and_bind_trailer_v1`, wired into
`cmd_sign_userop` + the batch path) has the identical class and is now closed
the same way as cowswap:

5. **Aave VK regenerated against the fixed circuit.** `tools/build_vks.sh
   aave_v3_pool` rebuilt the VK from the hardened `formatting.circom` (6,538
   constraints, fits pot14), re-pinned `circuits/aave_v3/circuit_final.zkey` +
   `secure/data/vks/aave_v3_pool.vk.bin` (`sha256 927bc1b7…`). The host Groth16
   test vectors were regenerated against the new key: the Aave supply witness
   was recomputed from `../zk_clear_signing/witness_supply.json` with the new
   wasm, re-proved, and `vk_data.rs` (via `vk_bin_to_rust.js`) + `test_vectors.rs`
   (via `export_zk_constants.js`) re-pinned. `cargo run -p zk-test` verifies the
   fresh proof against the new VK and the Poseidon KATs still pass. `dbgen`
   folded both new VKs → `VK_DB_ROOT` `3cda5293…` → `e2f9e2ed…`.

6. **Native bound on the v1 path.** `verify_and_bind_trailer_v1`
   (`secure/src/zk/mod.rs`) now rejects `calldata[36..68]` (the uint256 `amount`,
   ABI arg #2 for every Aave Pool action: supply/borrow/repay/withdraw) if it is
   `≥ 2¹⁹⁰`, reusing the same `amount_within_field_safe_bound` helper, before
   trusting the ZK-bound readable. Safe for the only other v1 protocol, cowswap
   `setPreSignature`, whose arg-#2 slot is the `signed` bool (≤ 1). Tests:
   `negative_v1_amount_slot_rejects_huge_aave_amount` /
   `positive_v1_amount_slot_accepts_setpresig_bool_and_real_amount` in
   `extra_tests.rs`.

(The Aave `FormatAmount` uses the identical `Num2Bits(190)` primitive proven by
the cowswap circuit-level negative test; only the recomposition differs — no
`remainder` term — which does not affect the range-check rejection.)

## TL;DR

A malicious companion can produce a **valid** Groth16 proof — over the
honest circuit and the real, pinned verification key — in which the
trusted UI displays a benign amount (e.g. `0.2000 USDC`) while the
`sellAmount` actually being signed is astronomically large (~10⁷⁰ USDC,
a 254-bit number). The order it signs drains the wallet's entire balance
of the sell token.

No verifier bug and no trusted-setup toxic waste are involved. The proof
is a genuine satisfying assignment of an **under-constrained circuit**.
This is the classic circom field-overflow soundness bug.

## Root cause

`FormatTrimmedAmount` verifies the displayed amount by recomposition
(`format.circom`):

```circom
scaled    <== raw_amount * scale_factor;                 // line 252
...
recomp_isz.in <== scaled - int_part - frac_part - remainder;   // line 261
```

with

* `raw_amount` = the order's `sellAmount`, bounded only to **< 2²⁵⁴** by
  `Uint256BytesToField` (it merely zeroes the top 2 bits — circuit.circom
  lines 79-84);
* `scale_factor = 10^(18 − decimals)`, up to **10¹⁸ ≈ 2⁶⁰** (registry LUT);
* `int_part = int_value·10¹⁸`, `frac_part = frac_value·10¹⁴`,
  `remainder ∈ [0, 10¹⁴)` (the only bounds: `rem_lt_skip.out === 1`
  line 347 + `Num2Bits(48)` line 320).

Everything is computed in the BLS12-381 scalar field `r ≈ 2²⁵⁴·⁶`. The
product `raw_amount · scale_factor` can reach `2²⁵⁴ · 2⁶⁰ = 2³¹⁴`, i.e.
**it wraps `r` about 2⁵⁹ times.** Nothing range-checks the product, so
`scaled` is the *residue* `raw_amount · scale_factor mod r`, not the true
integer product.

The code comment at lines 270-287 / 336-343 argues the design is safe
because "`remainder < pow_skip` makes the `(int, frac, remainder)`
decomposition unique given `scaled`." That is true **over ℤ**, but the
constraint is **mod r**. Uniqueness of the decomposition of `scaled` does
not help when the attacker controls `scaled` itself to be a small residue
of a huge product. The comment at lines 312-319 even acknowledges
`scaled` "easily exceeds 2⁶⁰" and deliberately omits range-checking it —
that omission is the bug.

### The hidden degree of freedom: `remainder`

The map `raw_amount ↦ raw_amount·scale mod r` is a bijection (scale is
invertible mod r). If `remainder` were forced to `0` (the pre-v3.1
behaviour described in the now-stale comment at lines 235-239), then
every displayable `scaled` would be a multiple of `scale_factor` (for
tokens with ≥ 4 decimals), forcing the unique `raw_amount` preimage to be
small and honest.

The **v3.1 relaxation that allows non-zero `remainder` in normal mode**
(lines 270-287) removes that. The attacker picks a `remainder` that is
*not* a multiple of `scale_factor`; the unique `raw_amount` preimage of
the benign `scaled` residue then becomes a huge ~254-bit value. The
`remainder` is the sub-`10⁻⁴` part that the display never shows, so the
user sees only `int.frac`.

## Exploit

Target display `0.2000 USDC` (USDC, 6 decimals → `scale = 10¹²`), hidden
`remainder = 2`:

```
scaled_repr = 0·10¹⁸ + 2000·10¹⁴ + 2          = 200000000000000002
raw_amount  = scaled_repr · (10¹²)⁻¹ mod r
            = 0x39d26d02cf7a4d98b63a920d4f6d188f2bbdde306579708fabb880fbaf375eff
              (254 bits; top byte 0x39 ⇒ top-2-bits-zero gate passes)
check: raw_amount · 10¹² mod r == scaled_repr   ✓
```

Witness (`is_sub_precision = 0`): `int_digits = [0×10]`,
`frac_digits = [2,0,0,0]`, `n_leading_zeros = 9`, `remainder = 2`. Every
constraint — `AllDigits`, recomposition (mod r), `remainder < pow_skip`,
`Num2Bits(48)`, leading-zero — is satisfied, so `snarkjs` produces a
proof that passes `verify_clear_signing_proof_v3`. The on-chain
`sellAmount` is `raw_amount` (~2.6·10⁷⁰ USDC).

Both the sell and buy amount lines use the same `FormatTrimmedAmount`
instance (circuit.circom lines 232-254), so both are forgeable; a drain
needs only the sell side oversized with an honest-small buy `limit` and
`partiallyFillable = 1`.

## Why nothing else catches it

* **Verifier** (`secure/src/zk/groth16.rs`, `bls12_381_pka`): sound —
  the forged proof is a *real* valid proof, so a correct verifier accepts
  it. Audited separately; no issue.
* **Native `canonical → orderDigest → calldata.uid` cross-check**
  (`cowswap/mod.rs :: cross_check_setpresig_calldata`): binds the huge
  `sellAmount` to the on-chain order — which is exactly what the attacker
  *wants* on-chain. It does not constrain the *display*.
* **Display** (`cowswap_display.rs :: render_cowswap_pages`): splices the
  ZK-bound `readable` (the benign `0.2000 USDC`) **verbatim, without
  re-parsing**. The huge `sellAmount` is never rendered natively, so the
  user never sees it. (`enforce_native_value_page` only covers the outer
  UserOp ETH `value`, which is 0 for `setPreSignature`.)
* **VK pinning** (`vk_bundle.rs`, `VK_DB_ROOT`): sound and irrelevant —
  the attack uses the legitimate VK.

## Caveats on impact

* A full drain requires a prior CoW VaultRelayer allowance on the sell
  token ≥ the amount pulled; infinite approvals are common, but a wallet
  that only ever approved small amounts caps the loss. The
  **cryptographic** guarantee (the device attests a false amount) is
  broken unconditionally.
* `partiallyFillable = 1` is shown on native page 4 ("Partial: Y"); a
  vigilant user *might* notice, but the headline `0.2000 USDC` is
  reassuring and most users won't connect "Partial: Y" to a drain.
* Attacker = the untrusted companion / NS world — squarely the threat
  model clear-signing exists to defend against.

## Fix

Bound the **inputs** so the product cannot wrap `r`. Range-checking
`scaled` does **not** work (the attacker's residue is small by
construction). In `FormatTrimmedAmount`, constrain `raw_amount` to a width
`W` with `2^W · max_scale_factor < r`, e.g.

```circom
component ra_bits = Num2Bits(190);   // 2^190 · 10^18 < 2^250 < r
ra_bits.in <== raw_amount;
```

`2¹⁹⁰` comfortably exceeds any displayable amount (a displayable value has
`scaled < 10²⁸ ≈ 2⁹³`, so `raw_amount < 2⁹³`), while guaranteeing
`raw_amount · scale_factor < r` over ℤ — no wrap. Tighter (≈ 2⁹⁶) is
safer still. Reinstating `remainder === 0` in normal mode is *not* a
sufficient fix on its own (low-decimal tokens can still wrap), but is a
reasonable belt-and-braces addition.

Any fix changes the circuit → new R1CS → **new trusted setup + new VK**.
Re-run `tools/build_vks.sh`, regenerate `ERC7730`/VK roots, and add a
negative test (the PoC witness must fail `snarkjs wtns check` /
`groth16 verify`). There is currently **no negative/overflow test** on
this circuit.

## Related

* Same `raw_amount * scale_factor` shape (without the `remainder` term)
  exists in `circuits/aave_v3/formatting.circom :: FormatAmount`
  (lines 315-321), imported byte-identical from upstream ZKlarity. The
  Aave clear-sign path should be checked for the same overflow class.
* Trusted-setup hygiene smell (separate, non-exploitable): the phase-2
  `contribution.seed` is committed and `circuits/ptau.lock`'s
  `_security_note` wrongly claims "ceremony hygiene is irrelevant." It is
  not exploitable today only because snarkjs `getRandomRng` mixes 64 bytes
  of fresh system randomness into the contribution (cli.cjs:309-324), so
  the committed seed does not reconstruct δ. Still: remove the seed and
  fix the note (pinning prevents VK *substitution*, not toxic-waste
  forgery).
