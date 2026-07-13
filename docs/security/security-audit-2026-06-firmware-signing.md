# Firmware Security Audit — Secure-World Signing & Trusted-Display Path

> **Historical snapshot.** This report describes the 2026-06-09 tree. Its
> Groth16/BLS12-381 paths were removed on 2026-06-30; they are not current
> implementation guidance. CoW and supported Aave operations now use native
> on-device decoders. See `docs/archive/zk-clear-sign-retirement.md`.

**Date:** 2026-06-09
**Auditor:** Claude (Fable 5), max-effort pass
**Commit context:** `master` @ `5fb4c2b7` (Phase D LCD branch)

## Scope & threat model

- **In scope:** software correctness of the firmware signing path — NS→S gateway,
  the unified sign dispatch, transaction decoding, trusted-display renderers, the
  Safe EIP-712 verifier, the CowSwap Groth16 verifier, and the EIP-1271/offchain path.
- **Trusted (out of scope):** all hardware — SE chips, TrustZone SAU/GTZC enforcement,
  SHA/keccak/PKA peripherals, fault-injection resistance of silicon. This is a
  *software-logic* review.
- **Attacker:** the companion app / USB host is **fully untrusted** and supplies every
  input (chain_id, flags, header, inner tx, all hashes, all trailers, all lengths).
- **Security property under test:** **WYSIWYS** — what the user sees rendered on the
  trusted display must be *exactly* what the SPHINCS+C10 signature commits to. A
  malicious companion must not be able to display a benign action while signing a
  malicious one, hide a parameter, forge a proof, or bypass a decode.

## Method

The central `to/value/data → signature` binding was traced by hand
(`cmd_sign_userop.rs` → `reconstruct_execute_calldata` → `compute_sphincs_digest_v06`),
and four parallel adversarial deep-dives covered Safe EIP-712, CowSwap/Groth16, the
NS↔S boundary, and the known-shape decoders. Every High/Critical claim below was
re-verified against the live source, including the on-chain `PQSmartWallet.sol`
execution semantics.

## Core binding: SOUND

The central WYSIWYS binding is correct. `cmd_sign_userop.rs` snapshots NS input into
S-SRAM (TOCTOU-safe), derives `tx_for_display` and `inner_data` from that snapshot, and
feeds the **same** bytes to both the renderer (`pick_sign_pages`) and the signer
(`reconstruct_execute_calldata` → `sha256(callData)` → `compute_sphincs_digest_v06`).
`aa/src/userop.rs:150-196` encodes `target=tx.to`, `value=tx.value`, `data=inner_data`
faithfully; the digest commits to `sha256(callData)` plus all domain separators. The
problem is not the binding — it is that **one signed field (native `value`) is not
always *rendered*.**

---

## Resolution (2026-06-10)

All twelve findings are fixed. Summary of the implemented remediations:

- **C-1 / H-2 / M-8** — A single dispatcher-level invariant in
  `pick_sign_pages` (`secure/src/tx/display/mod.rs`): whenever the signed
  outer `value != 0`, a dedicated loud `! NATIVE ETH` page is spliced in
  immediately after the renderer's banner (`enforce_native_value_page` +
  `Pages::insert_blank`), regardless of which renderer wins. This closes
  C-1, H-2 and M-8 in one place — a future renderer physically cannot
  forget it. Per-`TxKind` regression tests added (`value_invariant_tests`).
- **H-3** — Field-completeness is enforced at descriptor-compile time in
  `dbgen` (`check_contract_field_completeness`), where ABI arity is known:
  every contract-call argument MUST be accounted for by a rendered field, an
  explicit `visible:"never"` field, or a `tokenPath` reference, else the
  build fails. This catches accidental omissions (the audit's example) while
  allowing the seed corpus's deliberate `never`/`tokenPath` coverage. No
  on-device false-rejects.
- **M-4** — `render_token_amount` now renders the raw integer with a
  loud `! raw, dec=?` banner when the token can't be bound, instead of an
  authoritative-looking 18-decimal scale.
- **M-5** — EIP-712 format entries now carry the full 32-byte primary-type
  hash on-wire (`dbgen` emit + IR `FormatHeader::type_hash`); the typed
  renderer selects and binds the format by the full hash, constant-time
  (`subtle::ConstantTimeEq`), not a 4-byte prefix. `ERC7730_DESCRIPTORS_ROOT`
  regenerated.
- **M-6** — `write_eth_two_rows` now uses fixed-width fractional digits
  (no trailing-zero trim), matching the ERC-20 token-amount anti-spoof
  policy.
- **M-7** — `render_enum` / `render_nft_name` now `Reject` (fall through
  to blind-sign) instead of rendering a raw integer under a semantic label.
- **L-9** — `groth16_verify*` reject identity A/B/C/vk_x/VK points before
  the Miller loop; the dead `any_identity` accumulator removed from
  `miller_loop_4` (with a comment that a blanket product mask would
  false-*accept*, so callers must reject identity inputs explicitly).
- **L-10** — Single-tx Safe `safe_v1`/`safe_exec` binds and the Groth16
  accept decision are now FI-sentinel double-evaluated (`wait_random` +
  `check_true_into_sentinel`), matching the batch dispatcher.
- **L-11** — `cross_check_eip712` dropped the tautological
  `verifying_contract` argument; the verifying contract is bound through
  the independently-checked `domain_separator`.
- **L-12** — `CLAUDE.md` corrected: Safe `multiSend` (`0x8d80ff0a`) has no
  decoder and falls to blind-sign.

Validation: host unit tests pass (incl. the new C-1 regression and the M-5
IR/dbgen round-trip against the real corpus); `pqsigner-erc7730`, `dbgen`,
and `bls12_381_pka` test suites pass; the firmware compiles clean for
`thumbv8m.main-none-eabi`. (A pre-existing `make e2e` Scenario-2 failure on
this branch reproduces identically on the unmodified commit — it stems from
the stale firmware `PROXY_INIT_CODE_HASH` after an unrelated
`PQSmartWallet.sol` change, not from these fixes.)

---

## Severity summary

| ID | Sev | Title | Primary location | Status |
|----|-----|-------|------------------|--------|
| C-1 | 🔴 Critical | `erc20_unknown` hides native ETH `value` → direct theft | `secure/src/tx/display/erc20_unknown.rs` | ✅ Fixed |
| H-2 | 🟠 High | ERC-7730 contract render omits native `value` | `secure/src/tx/display/erc7730/mod.rs` | ✅ Fixed |
| H-3 | 🟠 High | ERC-7730 has no field-completeness check (hidden params) | `secure/src/tx/display/erc7730/mod.rs` | ✅ Fixed |
| M-4 | 🟡 Medium | ERC-7730 `tokenAmount` assumes 18 decimals when unbound | `secure/src/tx/display/erc7730/formatters.rs` | ✅ Fixed |
| M-5 | 🟡 Medium | EIP-712 typed path binds `primary_type_hash` by 4-byte prefix only | `secure/src/tx/display/erc7730/mod.rs` | ✅ Fixed |
| M-6 | 🟡 Medium | ETH amount render trims trailing zeros (visual collision) | `secure/src/tx/display/primitives.rs` | ✅ Fixed |
| M-7 | 🟡 Medium | ERC-7730 `Enum`/`NftName` render raw int under semantic label | `secure/src/tx/display/erc7730/formatters.rs` | ✅ Fixed |
| M-8 | 🟡 Medium | Safe paths don't show outer UserOp `value` | `secure/src/tx/display/safe_display.rs` | ✅ Fixed |
| L-9 | 🟢 Low | `miller_loop_4` drops identity mask (false-reject only) | `bls12_381_pka/src/pairings.rs` | ✅ Fixed |
| L-10 | 🟢 Low | Groth16 verdict / single-tx Safe verify lack FI sentinel | `secure/src/zk/groth16.rs`, `cmd_sign_userop.rs` | ✅ Fixed |
| L-11 | 🟢 Low | `cross_check_eip712` contract arg is tautological | `secure/src/nsc/cmd_sign_offchain.rs` | ✅ Fixed |
| L-12 | 🟢 Low | Docs claim multiSend decoding that doesn't exist | `CLAUDE.md`, `README.md` | ✅ Fixed |

---

## C-1 🔴 CRITICAL — `erc20_unknown` hides native ETH `value` → direct theft to an attacker address

### Summary
A malicious companion makes the device **display a trivial token transfer while
signing an ETH-draining transaction** to a contract it controls. Direct, unbounded
fund loss; silent display/sign desync.

### The hole
`secure/src/tx/display/erc20_unknown.rs:16-110` (`render_erc20_unknown_pages`) renders 8
pages — `! Unknown token` / contract / recipient / amount / chain / fees / nonce — and
**never renders `tx.value`, with no `! native ETH!` warning.** Its sibling
`erc20_known.rs:42-44` *does* warn:

```rust
// erc20_known.rs — present
if !tx.value.is_zero() {
    write_line(&mut pages.buf[0][2], "! native ETH!");
}
// erc20_unknown.rs — NO equivalent anywhere in the 8 pages
```

The unknown path accepts an **arbitrary, attacker-controlled `tx.to`** (the token need
not be curated). It is selected by `pick_sign_pages` (`secure/src/tx/display/mod.rs:273-277`)
whenever calldata is `transfer`/`transferFrom`/`approve`-shaped and no ERC-20 metadata
bundle is attached:

```rust
match crate::erc20::calldata::parse_erc20_calldata(inner_data) {
    Some(call) => match erc20 {
        Some(meta) => render_erc20_known_pages(tx, &call, meta, resolver),
        None        => render_erc20_unknown_pages(tx, &call, resolver), // <-- value hidden
    },
    ...
}
```

### Verified exploit chain (every step confirmed in code)
1. Companion sends: `to_address = 0xATTACKER` (a payable contract),
   `inner_data = transfer(x, 1)` (68 bytes; parses at `tx/src/erc20/calldata.rs:50`),
   `value = victim's entire ETH balance`, no trailers, no metadata bundle.
2. Dispatcher routes to `render_erc20_unknown_pages`. User sees *"transfer 1 unit on an
   unknown token to x"* — **nothing about the attached ETH** — and confirms a
   low-stakes-looking action.
3. `reconstruct_execute_calldata` copies `tx.value` into the signed callData
   (`aa/src/userop.rs:184`: `out.buf[p..p+WORD].copy_from_slice(&tx.value.0)`).
4. `compute_sphincs_digest_v06` signs `sha256(callData)` (`aa/src/userop.rs:595-615`).
5. On-chain, `PQSmartWallet.executeWithOffchainCount` runs
   `target.call{value: value}(data)` (`contracts/smart-wallet/src/PQSmartWallet.sol:247`)
   → `0xATTACKER.call{value: victimBalance}(transfer(x,1))`. The attacker's payable
   contract pockets the ETH; the inner `transfer(x,1)` succeeds trivially or is ignored.

### Why nothing mitigates it
- **No value-guard exists** anywhere in `cmd_sign_userop.rs` or
  `cmd_sign_userop_batch.rs` (grep for value checks returns empty).
- The appended **ERC-8213 fingerprint page digests only `inner_data`**, not `value` —
  a diligent user cross-checking the calldata digest confirms `transfer(x,1)` and still
  never sees the ETH.
- Every *other* renderer that allows an arbitrary target **does** show value:
  `value_transfer.rs:34-56` ("Send ETH?"/"Value:"), `blind_sign.rs:97-104` ("! VALUE:"),
  `typed_call/mod.rs:143-146` ("! VALUE:"). `erc20_unknown` is the unique path that both
  permits an attacker-controlled target **and** hides the value — so the attacker is
  specifically motivated to shape calldata as a fake ERC-20 transfer to land on it.

### Blast radius
- Affects **single sign and batch sign** identically — batch reuses the same
  `pick_sign_pages` per inner tx (`cmd_sign_userop_batch.rs:652`), and
  `executeBatchWithOffchainCount` forwards per-element value
  (`PQSmartWallet.sol:275`: `targets[i].call{value: values[i]}(datas[i])`).

### Fix
Enforce a **dispatcher-level invariant**: whenever `tx.value != 0`, *always* render a
dedicated, loud value page regardless of which renderer wins — do not rely on each
renderer to opt in. Implement in `pick_sign_pages` (or as a post-pass on the returned
`Pages`) in `secure/src/tx/display/mod.rs`, so it cannot be forgotten by a future
renderer. Minimal stopgap: port the `erc20_known` warning **plus an actual value
amount page** into `erc20_unknown.rs`. Add a regression test that asserts a non-zero
`value` produces a value page for *every* `TxKind`. (Optionally also reject `value != 0`
on selectors that are never legitimately payable, e.g. ERC-20 `transfer`/`approve`.)

---

## H-2 🟠 HIGH — ERC-7730 contract render omits native `value`

`secure/src/tx/display/erc7730/mod.rs:102-138` (`render_erc7730_pages_inner`) emits
banner → descriptor fields → `append_envelope_pages` → confirm.
`append_envelope_pages` (`:256-284`) renders chain / fee / nonce only — **no value
page.** Native `value` is shown only if the descriptor happens to declare a field with
path `@.value`.

Same desync as C-1: a companion attaches non-zero `value` to a descriptor-matched call
and the ETH is invisible. **Bounded** relative to C-1 because the ERC-7730 binding
forces `tx.to` to equal the descriptor's pinned contract, so the ETH goes to a *curated*
contract rather than directly to the attacker — but it is still a hidden value transfer
(locked/consumed ETH; unexpected behavior on payable functions). Single + batch.

**Fix:** the same global value page from C-1 fixes this for free. Belt-and-braces: add an
unconditional value page to `append_envelope_pages` when `!tx.value.is_zero()`.

---

## H-3 🟠 HIGH — ERC-7730 renders only descriptor-declared fields; no completeness check

`render_fields` (`secure/src/tx/display/erc7730/mod.rs:233-254`) iterates only the
descriptor's declared fields; a field with `Visibility::Never` is silently skipped
(`secure/src/tx/erc7730_render/visibility.rs`). The renderer never reconstructs the real
ABI arity, so it cannot detect that an effect-bearing calldata word was omitted or
hidden — e.g. a `transfer(address,uint256)` descriptor that declares only the amount and
omits the recipient renders "Send 100 USDC" with no destination.

**Threat-model nuance:** descriptors are Merkle-pinned to `ERC7730_DESCRIPTORS_ROOT`, so a
malicious *companion* can only *select* among pinned descriptors — this becomes
companion-exploitable only through a **curation mistake**. WYSIWYS for this path
therefore rests entirely on host-side descriptor authoring correctness, which is weaker
than the in-silicon guarantees elsewhere.

**Fix:** for contract-context descriptors, independently ABI-decode the calldata against
a known arity (the curated `text_sig` for the selector is already available via the
selectors DB) and assert every static head word is covered by a rendered
(`Always`/`Optional`) field; otherwise `Reject` → blind-sign. At minimum forbid
`Visibility::Never` on contract-context descriptors.

---

## M-4 🟡 MEDIUM — ERC-7730 `tokenAmount` assumes 18 decimals / `???` when token unbound

`secure/src/tx/display/erc7730/formatters.rs:303-326`: when a `TokenAmount` field's
token address can't be matched to a contract-bound `Erc20Metadata`, the formatter falls
back to `(18, "???")` and renders a *fully-formatted decimal* with an assumed scale. For
a 6-decimal token this is 10^12× off; the number *looks* authoritative. Unlike
`erc20_unknown` (which labels "Amount (raw)" / "decimals = ?"), this misrepresents
magnitude.

**Fix:** when the token can't be bound, render the raw integer with an explicit
"raw, decimals=?" banner; never present a scaled decimal with an unverified scale.

---

## M-5 🟡 MEDIUM — EIP-712 typed path binds `primary_type_hash` by 4-byte prefix only

`secure/src/tx/display/erc7730/mod.rs:192-193`: the EIP-712 typed renderer selects the
decode format via `primary_type_hash[..4]`, but the **full 32-byte** `primary_type_hash`
is what goes into the signed struct hash
(`secure/src/nsc/cmd_sign_offchain.rs:412-420`, `keccak(primary_type_hash || encoded_data)`).
The full hash is never validated against the descriptor. Exploiting the gap requires a
4-byte keccak collision between two EIP-712 types of the *same* verifying contract (one
in the descriptor, one honored by the contract) — impractical, since the attacker can
grind neither side — but the fix is trivial.

**Fix:** store the full expected 32-byte type hash in the descriptor format and require
`primary_type_hash == format.type_hash` (constant-time compare) before rendering.

---

## M-6 🟡 MEDIUM — ETH amount render trims trailing zeros (visual collision)

`secure/src/tx/display/primitives.rs` `write_eth_two_rows` trims trailing fractional
zeros and degrades precision to fit 16 columns, so e.g. `1.0000001` and `1.0000009` ETH
can render identically. Token amounts deliberately use fixed-width no-trim
(`write_token_amount_two_rows`) "so visual-spoofing attacks can't succeed" — the ETH path
doesn't get the same treatment. Used by value_transfer / blind_sign / typed_call /
safe_display.

**Fix:** apply the fixed-width fractional-digit policy to ETH amounts as well.

---

## M-7 🟡 MEDIUM — ERC-7730 `Enum`/`NftName` render raw integer under a semantic label

`secure/src/tx/display/erc7730/formatters.rs:351-376` (`render_nft_name`), `:459-484`
(`render_enum`): Phase-4 stubs render the raw on-chain integer and discard the
enum/name resolution, so a curated swap descriptor shows `Side: 1` instead of
`Side: SELL` — opaque/misreadable while wearing the verified intent banner.

**Fix:** until the resolvers land, `Reject` these FormatOps (fall through to blind-sign),
consistent with how `Calldata`/`MustMatch` already `Reject`.

---

## M-8 🟡 MEDIUM — Safe paths don't show the outer UserOp `value`

`secure/src/tx/display/safe_display.rs:128-136` (approveHash) and `:166-176` (exec) show
the *inner* SafeTx value, never the *outer* UserOp value (`snap[296..328]`, signed as the
`value` arg of `executeWithOffchainCount`). **Bounded:** Safe `approveHash` /
`execTransaction` are non-payable, so a non-zero outer value reverts on-chain — no fund
loss, but the user confirmed an undisclosed ETH amount.

**Fix:** assert outer `value == 0` for these selectors (refuse to sign otherwise), or add
an explicit outer-value page. The global C-1 value page also covers this.

---

## L-9 🟢 LOW — `miller_loop_4` drops the identity-result mask

`bls12_381_pka/src/pairings.rs:664-726`: `miller_loop_4` computes an `any_identity`
`Choice` but never applies the `Fp12::conditional_select(.., Fp12::one(), any_identity)`
mask that the reference `pairing()` (`:635-651`) uses. If a proof point is the identity,
the loop computes a *wrong* product instead of the correct `e(identity,·)=1` factor.
**Not exploitable** — this can only cause a *false reject*, never a false accept; honest
proofs never contain identity A/B/C and VK points are pinned/non-identity.

**Fix (hygiene):** apply the mask to match `pairing()` semantics, or have
`groth16_verify*` explicitly reject identity A/B/C before the loop; remove the dead
`any_identity` otherwise.

---

## L-10 🟢 LOW — Verifier verdicts lack FI sentinel hardening

The Groth16 accept decision is a single `result == Gt::identity()` boolean
(`secure/src/zk/groth16.rs:117-127`), and the single-tx Safe `safe_v1`/exec binds are
consumed as plain `Option`s (`secure/src/nsc/cmd_sign_userop.rs:735-759`) — whereas the
batch path wraps them in `fi::check_true_into_sentinel(...)` with `wait_random()`
(`cmd_sign_userop_batch.rs:415-421`). Out of *this* (software-only) threat model, but
inconsistent with the codebase's stated FI posture.

**Fix:** mirror the batch path's sentinel double-eval for the single-tx Safe binds and
the ZK verdict.

---

## L-11 🟢 LOW — `cross_check_eip712` contract argument is tautological

`secure/src/nsc/cmd_sign_offchain.rs:382-388` passes `&v.ir.contract` as the "verifying
contract" into `cross_check_eip712`, which then compares `ir.contract` against
`ir.contract` — always true. **Not exploitable:** the real binding holds because the
companion-supplied `domain_separator` is checked against the descriptor's pinned
`ir.domain_separator` and is folded into the signed `final_eip712` (which cryptographically
commits to `verifyingContract`). But the line reads as a check it isn't.

**Fix:** remove the misleading argument, or plumb the verifying contract from an
independent source and compare it for real.

---

## L-12 🟢 LOW — Docs overstate multiSend support

`CLAUDE.md` and `README.md` state Safe "multiSend bundles … render on the OLED with full
parameters." There is **no multiSend (`0x8d80ff0a`) decoder** in the tree; such a tx
falls (loudly, WYSIWYS-safely) to blind-sign.

**Fix:** correct the docs, or implement a bounds-checked multiSend renderer.

---

## Verified sound (no break found)

- **CowSwap Groth16 forgery — not possible (within threat model).** VK is firmware-pinned
  via a SHA-256 Merkle root (`secure/src/zk/vk_bundle.rs` → `db_roots::VK_DB_ROOT`); G1/G2
  proof + VK points are full subgroup-checked (`is_torsion_free`) on deserialization; the
  pairing equation is the correct Groth16 check against the true `Fp12` identity; the
  Circom circuit `===`-binds displayed `readable` to signed `canonical`; and the firmware
  *independently* recomputes the EIP-712 order digest from `canonical` and byte-matches it
  to the `orderUid` in the signed calldata. The CoW `setPreSignature` downgrade gate is
  enforced in both single and batch handlers.
- **Safe EIP-712 — core binding sound.** Rendered fields ⟸ verified `canonical` ⟸
  `inner_data` ⟸ signed UserOp; chainId + verifyingContract pinned to the UserOp;
  DELEGATECALL rejected in both `approveHash` and `execTransaction` paths; firmware decode
  is stricter than Solidity (rejects non-canonical address/offset words); downgrade gates
  force verification when the selector says approveHash/execTransaction.
- **NS↔S boundary — robust.** No reachable OOB write, secret leak, or sign-with-wrong-key.
  Pointer validation is range + overflow + mailbox-overlap checked and HW-`TT`-confirmed on
  silicon; NS input is snapshotted to S-memory before parse (TOCTOU-safe); length fields
  read once; `overflow-checks = true` makes residual length arithmetic fail-closed;
  `SLOT_CACHE` is full-`(account, chain, slot)`-tuple keyed (no wrong-key signing). The
  prior `cmd_sign_offchain` 4016/8616 FI-OOB fix is **confirmed complete** with no sibling
  regressions.
- **Merkle trust-bundles** (ERC-20 / names / selectors / VK / ERC-7730) are
  domain-separated (`0x00` leaf / `0x01` node — second-preimage safe), depth-bounded
  (≤32), and reject trailing bytes; every companion-supplied display string is
  ASCII-charset-gated and length-bounded (no homoglyph / control-char OLED spoof).

---

## Remediation priority

1. **C-1** — ship the dispatcher-level "always render non-zero `value`" invariant. This
   single change also closes **H-2** and **M-8**. Add a per-`TxKind` regression test.
2. **H-3** — add ERC-7730 field-completeness enforcement (or restrict `Visibility::Never`).
3. **M-4, M-7** — make unbound/stubbed ERC-7730 formatters fail loud (raw + banner, or
   `Reject`) instead of presenting authoritative-looking values.
4. **M-5, M-6, L-9–L-12** — defense-in-depth and hygiene; batch into a cleanup pass.

**Bottom line:** the cryptographic and NS-boundary engineering is strong; the one
critical, directly-exploitable break is mundane and recurring — *native `value` is
signed but not always displayed* — with `erc20_unknown` the unique path that both allows
an attacker-controlled target and hides the value. A single global value-page invariant
is the highest-leverage fix.
