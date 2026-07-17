# FV pilot — cross-hash separation, quantitative floor (OC2 / F9b) — 2026-07-17

> **Scope, first (F9).** A Lean-kernel-checked QUANTITATIVE refinement of the
> `keccak_sha256_cross_separation` assumption that grounds the RAW32
> UserOp-forgery-oracle defense. It adds the explicit search-game floor for the
> assumption's `BreaksHash` disjunct; it does **not** discharge the assumption
> (which stays `cited-tcb`). All new content is closed `Nat` facts (`decide`,
> no `native_decide`, no mathlib) — no new named axioms enter any closure.

## The question (OC2 / partner-B F12)

The off-chain EIP-1271 path signs `replaySafeHash(rawHash)` — a **keccak-256**
image — while the on-chain UserOp path signs `sphincsDigest(op)` — a **SHA-256**
image. `Wallet/OffchainBinding.lean` proves these are never equal (the RAW32
oracle defense: a malicious companion can't get an off-chain signature that
doubles as a Type-2 drain signature) by reducing to one cited assumption,
`keccak_sha256_cross_separation : keccak256 x ≠ sha256 y ∨ BreaksHash`.

The review's finding: the axiom's prose framed the separation as *"structurally
disjoint / structurally impossible"*, which implies a `2⁻²⁵⁶` strength. But
**both images inhabit the same 256-bit codomain** (`ByteVec 32` on both sides), so
the real floor depends on the attack shape and is **not automatically `2⁻²⁵⁶`**.
Replace the prose with an explicit game + quantitative bound, keep the
`… ∨ BreaksHash` headline, and mark OC2 partial/cited-tcb.

## The refinement

`Crypto/Quantitative.lean` § *Cross-function separation floor* — same log-domain,
kernel-decidable style the file already uses for the EUF-CMA / SM-DT-TCR
`BreaksHash` terms. The codomain width is type-guaranteed:

```
CrossOutputBits = 8 * 32 = 256      -- ByteVec 32 on both sides (crossOutputBits_eq)
```

Two regimes, because the honest floor depends on whether the target is fixed:

| regime | game | advantage | floor (bits) | Lean |
|---|---|---|---|---|
| both-messages-vary (claw / birthday) | find ANY `(x,y)`, `keccak256 x = sha256 y` | `q²·2⁻²⁵⁶` | `256 − 2·qBits` | `crossClawBits` |
| fixed-target (preimage) | hit one fixed `sphincsDigest = T` | `q·2⁻²⁵⁶` | `256 − qBits` | `crossPreimageBits` |

**The claw is the operative regime for the RAW32 defense** — and it is genuinely
available: the attacker varies BOTH the off-chain `rawHash` (full 2²⁵⁶ image via
`replaySafeHash`) AND the draining UserOp (`nonce` alone spans 256 bits, plus gas
fields), so it can search for a cross-image collision, not merely a preimage. Take
the attacker-favorable minimum:

```
crossClaw_le_preimage : crossClawBits q ≤ crossPreimageBits q   -- claw is the binding regime
```

## Result — the honest headline floor (anti-vacuity: EXACT values, not ≥0)

```
crossClaw_at_2pow64   : crossClawBits 64  = 128    -- operative floor at 2^64 offline work
crossClaw_breakpoint  : crossClawBits 128 = 0      -- exact 256-bit birthday break point
crossPreimage_at_2pow64  : crossPreimageBits 64  = 192
crossPreimage_at_2pow128 : crossPreimageBits 128 = 128
crossClaw_antitone    : q1 ≤ q2 → crossClawBits q2 ≤ crossClawBits q1
```

The floors are pinned to **exact** values (mirroring `c10_security_floor_at_slot_cap
: … = 96`), not `≥ 0` — a wrong arithmetic or a Nat-subtraction truncation past the
break would flip them, so the `decide` proofs are non-vacuous.

**The honest headline: 128 bits — C10's Cat-1 design level.** The RAW32
cross-separation holds at the *same birthday strength the whole wallet already
lives at*. The naive `2⁻²⁵⁶` was the wrong yardstick — that is the fixed-target
preimage number, valid only when the attacker cannot also vary the UserOp. This is
a **precision / honesty fix, not a downgrade**: the defense was, and remains,
comfortably infeasible (2¹²⁸ work); the refinement states the correct floor and
regime instead of an over-strong number.

## What stayed stable (closure hygiene)

- The qualitative axiom `keccak_sha256_cross_separation` is **unchanged** — same
  name, same `lean_type`. `offchain_nested_disjoint_from_userop_digest`'s
  `#print axioms` closure is byte-stable: `{propext, Quot.sound,
  keccak_sha256_cross_separation}`. `theft_free` is unaffected.
- The new quantitative theorems reference **no** named axioms (the exact-value
  ones depend on nothing; the two order lemmas only on the kernel `{propext,
  Quot.sound}`), so no closure's consumer mapping is perturbed.
- `AXIOM_STATUS.json` A6 keeps `status: cited-tcb`; only its `status_detail` gains
  the OC2 quantitative note. `make -C contracts/verification verify-ledger-consistency`
  passes (18 closures / 17 axioms, all match live Lean truth; self-test battery fires).

## Residual (stated honestly)

- OC2 remains **cited-tcb**: the quantitative layer bounds the *feasibility* of the
  `BreaksHash` disjunct; it does not replace the assumption with a probability-monad
  proof. A full EasyCrypt-style `Pr[Game(A)] ≤ ε(A)` treatment is the standing
  follow-up noted in `Crypto/Assumptions.lean`.
- `keccak256` stays modelled as an `opaque` total function (the nesting STRUCTURE,
  not keccak internals, is what the disjointness proof uses); the 256-bit RO-output
  assumption on the keccak side is the conservative choice (reduced SHA-side image
  entropy would only help the defender).

## Files

- `contracts/verification/lean/SphincsCVerify/Crypto/Quantitative.lean` — new
  § Cross-function separation floor (`CrossOutputBits`, `crossClawBits`,
  `crossPreimageBits`, exact-value + ordering theorems).
- `contracts/verification/lean/SphincsCVerify/Wallet/OffchainBinding.lean` — axiom
  docstring updated (explicit game reference + regime caveat; statement unchanged).
- `contracts/verification/docs/AXIOM_STATUS.json` — A6 `status_detail` OC2 note.
