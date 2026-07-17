# FV pilot — CoW order-UID owner binding (P1.2) — 2026-07-17

> **Scope, first (F9).** A Kani ∀-proof over the **host-linkable, no_std**
> setPreSignature decode kernel (`tx/src/cowswap_order.rs`) that the secure world
> now calls, closing the **CoW owner-UID** slice of `signed-intent-to-display`
> (roadmap P1.2 — a review-named high-risk binding). It is a statement about the
> shape+field decode of the 164-byte calldata, not about the keccak orderDigest
> rebuild (that stays in `secure/`), not about pixels/panel/human comprehension.

## The property that matters

A CoW order is pre-signed by signing a UserOp whose inner call is
`setPreSignature(bytes orderUid, bool signed)` on GPv2Settlement. The C10
signature commits to that 164-byte calldata, and the `orderUid` it carries is
`orderDigest(32) ‖ owner(20) ‖ validTo(4)`. GPv2 requires `uid.owner ==
msg.sender` at execution, so the secure world binds the order to an **expected
owner** — the wallet `sender` for a direct pre-sign, and the **Safe** (not the
wallet) for a Safe-wrapped one (`secure/.../safe/cow_binding.rs`).

The show-one/sign-another threat here is an owner-substitution: the display/verifier
binds against an owner read from the *wrong* bytes, or accepts a non-`setPreSignature`
call whose bytes happen to line up with the offsets — so the signed calldata
authorises a pre-sign for an owner the user was not shown.

## What this pilot proves

`decode_setpresig_orderuid` (`tx/src/cowswap_order.rs`) is the host-compilable
shape + orderUid-field decode. `decode_setpresig_orderuid_canonical` (Kani,
**VERIFICATION SUCCESSFUL**, exhaustive over the fixed 164-byte layout) proves the
**canonicity / show⇒signed-bytes** direction: over ALL symbolic 164-byte calldata,

> if `decode_setpresig_orderuid(c)` accepts and returns `uid` (so the secure world
> binds the order to `uid.owner` / `uid.order_digest` / `uid.valid_to`), THEN `c`
> is the canonical `setPreSignature(orderUid, true)` encoding AND every orderUid
> field is the verbatim bytes at its canonical offset — in particular
> **`uid.owner == c[132..152]`**.

So the owner the pipeline binds against is provably the owner embedded in the
**signed** calldata, read from the right offset — no offset/aliasing bug and no
non-`setPreSignature` call can slip a different owner past the binding. Two
non-vacuity controls accompany it (`_accepts_concrete` positive, edge sentinels;
`_rejects_bad_selector` negative).

## Load-bearing (not a mirror)

The proven kernel **is** the production path. `secure/.../cowswap/mod.rs` now
delegates both `check_setpresig_calldata_shape` (the whole shape gate) and the
owner extraction in `cross_check_setpresig_calldata` to
`pqsigner_tx::cowswap_order::decode_setpresig_orderuid` — the same pattern the
CoW *order* decode already used (`decode_canonical`). Behaviour-identical: the
full secure-world cowswap host suite passes unchanged (70/70, incl.
`owner_mismatch_rejected`, `safe_owner_binding_passes_and_sender_binding_fails`,
`shape_check_rejects_bad_selector/signed_false/nonzero_tail_padding`,
`valid_to_mismatch_rejected`, `order_digest_flip_rejected`).

## Non-vacuity (standing gate)

Enrolled `cow_setpresig_selector` in `scripts/kani_mutations.json`
(`make verify-kani-mutation`): neuter the selector check (`calldata[0..4] !=
SETPRESIG_SELECTOR` → `false`) so a non-`setPreSignature` call decodes and binds
an owner — the canonicity harness turns **red** (`assert c[0..4] ==
SETPRESIG_SELECTOR`; verified `VERIFICATION:- FAILED`, then reverted). Census lock
refreshed (152 harnesses).

## Gas-lane slice — deferred (blocked by a concurrent session)

The other named P1.2 slice — **gas-lane disambiguation** — was **not** done this
pass: its kernel `secure/src/tx/display/userop_gas_lane.rs` is being actively
rewritten by a concurrent session (the ERC-7730/PQ1 display refactor touching the
whole `secure/src/tx/display/` tree). Editing it now would conflict. It is a clean
follow-up once that refactor lands: extract the gas-triple page↔signed-values
binding to a host kernel and prove the displayed gas values equal the signed
`(callGasLimit, verificationGasLimit, preVerificationGas, maxFee, maxPriority)`.

## Files

- `tx/src/cowswap_order.rs` — `decode_setpresig_orderuid` + 3 Kani harnesses.
- `secure/src/tx/eip712/cowswap/mod.rs` — rewired to the proven kernel (load-bearing).
- `scripts/kani_mutations.json` (`cow_setpresig_selector`) + `scripts/kani_census.lock.json`.
