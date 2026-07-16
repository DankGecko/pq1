# FV pilot — signed-intent → display, ERC-20 canonicity (P1.2) — 2026-07-16

> **Scope, first (F9).** A Kani ∀-proof (BOUNDED — calldata up to 104 bytes) over a
> **pure `no_std` decoder kernel** (`tx/src/erc20/calldata.rs`), the first slice of
> the `signed-intent-to-display` surface (roadmap P1.2). It forecloses show-one/sign-another **via the ERC-20
> decoder path**; it is not the whole trusted-display pipeline (Safe / CoW /
> MultiSend / ERC-7730 / pagination each need their own binding), and it is a
> statement about the decoder, not about pixels, panel delivery, or human
> comprehension.

## The property that matters

The wallet signs `call_data_digest = sha256(callData)` over the **whole**
calldata. The trusted display decodes that same calldata and renders e.g.
"transfer 0.2 USDC to 0x…". The show-one/sign-another threat is a decode/dispatch
path that **renders a benign `transfer(R,A)` for calldata that is actually
something else** — extra trailing bytes, non-zero address padding, or an
alternate encoding — so the signature commits to bytes the user was not shown.

The existing harnesses (`parse_erc20_transfer_no_misdecode`, …) prove the
**forward** direction only: a *well-formed* `transfer(R,A)` decodes to exactly
`(R,A)`. That does **not** rule out the decoder *also* accepting a non-canonical
calldata and rendering the same benign transfer.

## What this pilot proves

`parse_erc20_only_accepts_canonical` (Kani, `#[kani::unwind(105)]`, **VERIFICATION
SUCCESSFUL**, 6.5 s) quantifies over calldata of **any length up to 104 bytes and
any byte values** (BOUNDED — 104 = `transferFrom`'s 100-byte encoding + 4 slack, so
trailing bytes / non-zero padding / wrong selector are all exercised for every arm;
a calldata **longer than 104 bytes** with a pathological tail is *outside* this
proof's model) and asserts the **reverse / canonicity** direction:

> if `parse_erc20_calldata(data)` accepts and returns a call with fields `F`
> (which is exactly what the display then renders), **then `data` is the unique
> canonical ABI encoding of `F`** — `selector(4) ‖ left-zero-padded words`, exact
> length, no trailing bytes, no non-zero address padding.

Covers all three arms (`transfer` / `transferFrom` / `approve` — including the
approval-drain paths). Because the accepted bytes *are* the signed bytes, this
means: **if the ERC-20 decoder renders a transfer, the signed calldata is exactly
that transfer.** No alternate/trailing encoding can be signed while a benign
transfer is displayed.

## Non-vacuity (negative control)

The proof is only meaningful if a **weaker** decoder breaks it. Enrolled in the
standing anti-vacuity gate `scripts/kani_mutations.json`
(`erc20_canonical_padding`, `make verify-kani-mutation`): neutering the
address-word zero-padding check (`word[0..12].iter().any(|&b| b != 0)` → `false`)
makes a calldata with **non-zero address high bytes** decode to a `Transfer` whose
displayed recipient differs from the signed word — and
`parse_erc20_only_accepts_canonical` turns **red** (verified: `VERIFICATION:-
FAILED`; file restored). If that mutant ever survives, the canonicity proof is
vacuous and CI fails.

## Files

- `tx/src/erc20/calldata.rs` — `parse_erc20_only_accepts_canonical` + the
  `is_canonical` reference encoder (in the `#[cfg(kani)]` module).
- `scripts/kani_mutations.json` — the `erc20_canonical_padding` non-vacuity
  mutation; `scripts/kani_census.lock.json` refreshed (149 harnesses).

## Next slices of P1.2 (not done here)

The roadmap's named high-risk bindings remain: the **CoW order-UID `owner`
binding** and the **gas-lane disambiguation** (both flagged in the review), and
the batch/MultiSend ordering + ERC-7730 nested-field bindings. Each is its own
render⇒signed-bytes canonicity slice on its own pure kernel.
