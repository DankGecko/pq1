# Safe-wrapped CowSwap pre-sign — companion app integration

This document specifies the contract between the PQSigner firmware and a
companion app/extension when the user pre-signs a **CowSwap order from a
Gnosis Safe**: a UserOp that drives a Safe flow whose inner call is
`GPv2Settlement.setPreSignature(orderUid, true)`. The firmware verifies
the CoW order (the existing Groth16 / AddrOnly v3 pipeline) bound to the
Safe's inner calldata and renders one combined confirmation — Safe
context **and** the full order intent — so it is unmistakable the user
is placing a specific CoW order *for a specific Safe*.

It composes two flows you should already understand:

- **[`companion-safe-tx-integration.md`](companion-safe-tx-integration.md)** —
  the `safe_v1` (`approveHash`) trailer and the Safe verifier rules.
- **[`m4-cowswap-eip712-impl.md`](m4-cowswap-eip712-impl.md)** — the CoW
  v3 (`zk_v3`) trailer: GPv2Order canonical, Groth16 proof, readable
  string, VK bundle, and the direct (`uid.owner == wallet`)
  setPreSignature flow.

What is new here is **only the binding**: the same two trailers, sent on
the same UserOp, with the orderUid's owner set to the Safe instead of
the wallet. No new command, no new wire envelope, no new crate.

> Status: landed 2026-06-11. Validated through QEMU (AddrOnly path,
> scenarios 5q/5r) and the host cross-check + binding test matrix.

## The one idea

CowSwap's settlement contract requires `uid.owner == msg.sender` for a
pre-signature. In the direct flow the wallet is the caller, so
`uid.owner == wallet`. When the order is placed **through a Safe**, the
Safe is `msg.sender` at execution, so:

```
uid.owner = the Safe address      (NOT the wallet)
```

Everything else — the order fields, the proof, the readable string, the
VK bundle — is identical to the direct CoW flow. The orderUid's owner
sits **outside** the EIP-712 digest and outside the proof, so the same
order canonical (and the same Groth16 proof, if you use one) works for
both flows; you only change the 20 owner bytes inside the orderUid.

## What the companion builds

```
1.  Build the GPv2Order (sell/buy token, amounts, validTo, appData, …).
2.  orderDigest = EIP-712 digest of the order            (32 B)
        domain  = (name "Gnosis Protocol", version "v2",
                   chainId, verifyingContract = GPv2Settlement …ab41)
3.  orderUid    = orderDigest(32) || SAFE_ADDRESS(20) || validTo(4)   (56 B)
        ▲ owner is the SAFE, not the wallet
4.  presignCalldata = setPreSignature(orderUid, true)   (164 B, see below)
5.  Build the SafeTx:
        to        = GPv2Settlement (…ab41)
        value     = 0
        operation = 0  (Call — DELEGATECALL is refused on-device)
        data      = presignCalldata
        (gasPrice / gasToken / refundReceiver normally 0)
6.  Pick the Safe flow:
        approveHash  → safe_v1 trailer + inner_data = approveHash(safeTxHash)
        execTransaction → inner_data = full execTransaction(...) calldata
7.  Build the zk_v3 trailer for the order (proof mode or AddrOnly).
8.  CMD_SIGN_USEROP (or the batch TLV) with BOTH trailers attached.
```

### `setPreSignature` calldata (164 bytes, fixed)

```
[  0..  4) selector        0xec6cb13f
[  4.. 36) bytes offset    0x40
[ 36.. 68) signed flag     1            ← must be true; revocation is unsupported
[ 68..100) bytes length    56
[100..132) orderDigest     keccak EIP-712 order digest
[132..152) owner           THE SAFE ADDRESS
[152..156) validTo         u32 BE, must equal order.validTo
[156..164) zero padding
```

The firmware re-checks every one of these fields (selector, ABI offsets,
`signed == true`, length, zero tail) and then cross-checks
`orderDigest`, `validTo` and `owner` against the v3 canonical + the
resolved Safe address. Get any byte wrong and the sign refuses.

## Wire layout

Both trailers ride the standard `CMD_SIGN_USEROP` payload, each with the
usual `[u16 BE len][payload]` framing, in the fixed trailer order:

```
[ standard 330-B sign header | inner_data (approveHash 36 B, or execTransaction ≥372 B) ]
[ erc20_len = 0 ]
[ zk_v3_len ][ zk_v3 payload ]          ← the CoW order trailer
[ safe_v1_len ][ safe_v1 payload ]      ← present for the approveHash flow; omit for execTransaction
[ selector_len = 0 ][ self_attest_len = 0 ][ erc7730_len = 0 ]
[ names count + bundles ]
```

(The v1 ZK section sits between erc20 and zk_v3 and is `len = 0` here.)

- **`zk_v3` payload** — exactly as in the direct CoW flow:
  - **Proof mode:** `proof(384) || canonical(204) || readable(128)`
    = 716 B bare; the NS layer appends the VK bundle (see below).
  - **AddrOnly mode:** the bare `canonical(204)` only — no proof, no
    readable, no VK. Use this when a token is absent from the firmware's
    on-device registry; the device renders raw token addresses + full
    hex amounts instead of formatted symbols.
- **`safe_v1` payload** — exactly as in the Safe flow:
  `canonical(281) || u16 raw_data_len || raw_data`, where `raw_data` is
  the 164-byte `presignCalldata`.

For the **`execTransaction`** flow there is no `safe_v1` trailer: the
SafeTx fields (including `data = presignCalldata`) are ABI-encoded in
`inner_data` and the firmware decodes them directly. Send only the
`zk_v3` trailer.

### Batch (`CMD_SIGN_USEROP_BATCH`)

Same two trailers, expressed as TLV records, both routed to the same
`tx_idx`: kind `3` (ZK v3) and kind `4` (Safe v1). The firmware verifies
ZK v3 records in a **second pass** after all Safe records, so the record
order within the batch trailer list does not matter.

### What the NS layer auto-injects vs. what you supply

The USB NS layer opportunistically appends the **VK bundle** for a
proof-mode `zk_v3` trailer it recognises by shape (`declared_len ==
716`), keyed on the CoW sentinel `(chainId, …ab42)`. As of this feature
the injector shifts later sections right to make room, so it works even
though the `safe_v1` trailer follows `zk_v3` in the payload — **you send
the bare 716-byte `zk_v3` and the device fills in the VK.**

You supply the VK bundle yourself only if you bypass the NS injector
(e.g. a transport that doesn't run it, or a VK not in the NS DB). AddrOnly
trailers carry no VK and are never touched by the injector.

## Firmware refusal statuses to handle

Every check fails **closed** — there is no silent downgrade. The OLED
shows a two-line banner; the gateway returns `InvalidPointer`
(`NscStatus` discriminant `4`) for all of these unless noted:

| OLED banner | Cause | Companion fix |
|---|---|---|
| `CoW sign / v3 required` | The Safe inner call is `setPreSignature` but no `zk_v3` trailer verified (missing, malformed, `signed == false`, wrong VK/proof, owner/digest/validTo mismatch). Also the direct-path message. | Attach a correct `zk_v3` trailer bound to the same order; ensure `uid.owner == safe`. |
| `Safe sign / safe_v1 required` | inner_data is `approveHash(bytes32)` but no `safe_v1` trailer verified. | Attach the `safe_v1` trailer; check chain/safe-address pinning + the data-hash / safeTxHash binds. |
| `Safe sign / exec parse fail` | inner_data looks like `execTransaction` but failed to decode, or requests `operation == 1` (DELEGATECALL). | Use `operation == 0`; encode canonical ABI. |
| (sign refused, no rich page) | `orderUid.owner != safe`, `orderDigest` mismatch, `validTo` mismatch, or amount ≥ 2^190 (field-overflow guard). | Rebuild the orderUid with the Safe as owner; recompute the digest from the exact order you display. |

**Unsupported (by design):**

- **Revocation** (`setPreSignature(uid, false)`) — refused on both the
  direct and Safe paths; the shape check requires `signed == true`.
- **multiSend batches** (`0x8d80ff0a`) — Safe's `multiSend` runs via
  DELEGATECALL, which the Safe verifier rejects wholesale, so an
  approve+presign multiSend bundle falls to loud blind-sign. Build a
  single-call SafeTx whose `data` is the presign.

## What the user sees on-device

The combined confirmation, page by page (proof mode shown; AddrOnly adds
two token/amount pages and surfaces `kind=SELL/BUY` on the context
banner):

```
1. Approve Safe TX        | Chain + name
2. Safe:                  | full Safe address
3. SafeTx Nonce / Op:Call | Inner: CoW order          ← inner-kind hint
   [ ! GAS REFUND pages — only if the SafeTx configures a refund ]
4. CowSwap order          | for this Safe: 0x5afe..0002   ← linkage banner
5. CowSwap SELL 0.20 USDC | (readable, proof-bound)
6. for at least 0.0004 WETH
7. Receiver: (= the Safe) | (zero receiver ⇒ proceeds to the owner)
8. Expires / Partial
9. Fee / balance kinds
10. appData
11. confirm (L=Cancel / R=Confirm)
   [ + ERC-8213 calldata fingerprint page ]
```

Your extension UI should mirror this so the user sees the same intent
before they reach for the device: the **Safe** the order belongs to, the
**sell/buy** legs and limit, the **expiry**, and that proceeds land in
the Safe.

## Worked example (Sepolia, AddrOnly)

```
safe        = 0x5afe000000000000000000000000000000000002
sellToken   = USDC  0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
buyToken    = WETH  0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
sellAmount  = 1_000_000_000            (1000 USDC, 6 decimals)
buyAmount   = 0x06f05b59d3b20000       (0.5 WETH)
validTo     = 0x68000000
receiver    = 0x0  (⇒ the Safe)

order canonical (204 B)  = pack(chainId, sellToken, buyToken, receiver,
                                 sellAmount, buyAmount, feeAmount=0,
                                 validTo, kind=0, partiallyFillable=0,
                                 sellTokenBalance=0, buyTokenBalance=0,
                                 appData=0)
orderDigest              = EIP-712 digest of the order
orderUid                 = orderDigest || safe || validTo          (56 B)
presignCalldata          = setPreSignature(orderUid, true)         (164 B)
SafeTx.to                = GPv2Settlement (…ab41), operation = Call
inner_data               = approveHash(safeTxHash(SafeTx))         (36 B)
zk_v3 trailer            = canonical(204)        (AddrOnly — no proof/VK)
safe_v1 trailer          = canonical(281) || u16(164) || presignCalldata
```

This is exactly QEMU e2e Scenario 5q (`nonsecure/src/e2e_test.rs`), which
signs successfully; Scenario 5r sends the same request **without** the
`zk_v3` trailer and asserts the `CoW sign / v3 required` refusal.

## Implementation pointers (firmware side)

- Binding selection: `secure/src/tx/eip712/safe/cow_binding.rs`
  (`safe_inner_is_cow_presign`, `resolve_cow_binding`).
- v3 verify (reused unchanged): `secure/src/tx/eip712/cowswap/verify.rs`
  (`verify_and_bind_trailer(bundle, calldata, chain_id, owner)`).
- Combined render:
  `secure/src/tx/display/safe_display.rs` (`InnerKind::CowswapPresign`) +
  `secure/src/tx/eip712/cowswap_display.rs` (`append_order_body_pages`).
- Gates + wiring: `secure/src/nsc/cmd_sign_userop.rs` §7c-ter/§7d and
  `secure/src/nsc/cmd_sign_userop_batch.rs` (pass-2 + render-loop gate).
- NS VK injector: `nonsecure/src/usb/commands.rs` (`inject_vk_bundle_at`).
