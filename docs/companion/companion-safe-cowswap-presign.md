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

**multiSend batches** (`0x8d80ff0a`) — the shape the Safe web UI
actually emits for CoW orders (`approve` + `setPreSignature` batched
through `MultiSendCallOnly` via DELEGATECALL) — are **SUPPORTED** with
per-record clear-signing. The single-call flow documented above remains
valid unchanged; the batched flow (allowlisted targets, hard rules, new
refusal banners) is the dedicated section
**[multiSend batches](#multisend-batches-the-shape-the-safe-ui-actually-emits)**
at the end of this document.

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

---

## multiSend batches (the shape the Safe UI actually emits)

> Status: landed 2026-06-12. Validated through the host
> decoder/resolver/compose matrices (incl. the full verify → resolve →
> record-bind → cross-check chain for both Safe flavours). QEMU e2e
> scenarios 5s/5t/5u are written but have not been executed yet — run
> `make e2e` to exercise them.

The single-call flow above assumed the SafeTx's inner call IS the
164-byte `setPreSignature`. In practice the Safe web UI never emits that
shape for a CoW order: it batches **two** actions — the ERC-20 `approve`
to the CoW vault relayer and the `setPreSignature` — through the
`MultiSendCallOnly` contract, executed as a **DELEGATECALL**:

```
SafeTx {
    to        = MultiSendCallOnly          ← NOT GPv2Settlement
    operation = 1 (DELEGATECALL)           ← refused in the single-call flow
    value     = 0
    data      = multiSend(transactions)    ← selector 0x8d80ff0a
}
```

The firmware accepts exactly this shape — and, more generally,
clear-signs any multiSend batch whose records it can decode — under the
hard rules below. Everything else still refuses loudly. There is **no
blind-sign path for a DELEGATECALL, ever**.

### What changes vs the single-call flow (TL;DR for the extension)

1. **You no longer need to build a single-call SafeTx.** Send the
   SafeTx exactly as the Safe UI/SDK builds it: `to =
   MultiSendCallOnly`, `operation = 1`, `data = multiSend(...)`.
2. **The `safe_v1` trailer is unchanged in layout** — but its
   `raw_data` is now the **full multiSend calldata** (it must keccak to
   the SafeTx's `data_hash`, as always).
3. **The `zk_v3` trailer is byte-identical to the single-call flow.**
   Same canonical / proof / AddrOnly forms, same `uid.owner = the Safe`.
   The firmware finds the `setPreSignature` **record** inside the
   multiSend payload and binds the trailer to that record's 164 bytes.
   You do not point at the record; the firmware locates it (and refuses
   if there is more than one).
4. **The `execTransaction` flavour works the same way**: encode
   `operation = 1`, `to = MultiSendCallOnly`, `data = multiSend(...)`
   in the exec calldata; attach only the `zk_v3` trailer.
5. **Optional:** attach the ERC-20 metadata trailer for the sell token
   — the firmware now matches it against multiSend **record** targets,
   so the approve record renders with symbol + decimals instead of a
   raw amount.
6. NEW refusal banners to handle (see table below).

### Accepted multiSend shape (hard rules — all enforced on-device)

DELEGATECALL runs the target's code in the Safe's storage context, so
the decode is only meaningful against a known-good MultiSend. The
firmware therefore pins everything:

| Rule | Detail |
|---|---|
| **Target allowlist** | `SafeTx.to` must be one of the canonical `MultiSendCallOnly` deployments (source: safe-global/safe-deployments): v1.3.0 canonical `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`, v1.3.0 eip155 `0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B`, v1.4.1 `0x9641d764fc13c8B624c04430C7356C1C7C8102e2`. Plain `MultiSend` (delegatecall-capable records) and zkSync variants are NOT accepted. |
| **Canonical ABI framing** | `multiSend(bytes)` selector `0x8d80ff0a`; bytes-head offset exactly `0x20`; total calldata length exactly `4 + 64 + ceil32(payload)`; zero padding. Anything Solidity wouldn't emit is refused. |
| **Record encoding** | Packed, no padding between records: `operation(1) ‖ to(20) ‖ value(32) ‖ dataLen(32) ‖ data(dataLen)`. The cursor must land exactly on the payload end. |
| **Per-record operation == 0** | Mirrors MultiSendCallOnly's on-chain revert; no nested DELEGATECALL. |
| **Record count** | 1 ..= 6 (`MULTISEND_MAX_RECORDS`). |
| **At most one `setPreSignature` record** | One `zk_v3` trailer binds one record. Two+ presign records refuse. |
| **Page budget** | The trusted display refuses (never truncates) a batch whose exact page total exceeds the 24-page budget. The standard approve+presign flow fits comfortably (≈ 16–21 pages depending on proof/AddrOnly + refund pages); if you hit `msend too long`, split the batch. |

Records the firmware can decode render rich (ERC-20 transfer /
approve / transferFrom, plain ETH, Safe-mgmt self-calls, the CoW
order). Records it cannot decode render as **loud per-record blind
pages** (selector + length + keccak) — same trust level as the existing
single-call blind inner; the user sees exactly which record is opaque.

### Wire layout (approveHash flavour)

Identical envelope to the single-call flow — only `raw_data` grew:

```
[ standard 330-B sign header | inner_data = approveHash(safeTxHash), 36 B ]
[ erc20_len ][ erc20 bundle ]            ← OPTIONAL, now record-matched (sell token)
[ zk_v1_len = 0 ]
[ zk_v3_len ][ zk_v3 payload ]           ← UNCHANGED (proof mode or AddrOnly)
[ safe_v1_len ][ canonical(281) ‖ u16 raw_data_len ‖ raw_data = multiSend calldata ]
[ selector_len = 0 ][ self_attest_len = 0 ][ erc7730_len = 0 ]
[ names count + bundles ]
```

The SafeTx canonical's fields change accordingly: `to =
MultiSendCallOnly`, `operation = 1`, `data_hash = keccak256(multiSend
calldata)`. The firmware re-derives `safeTxHash` from the canonical and
byte-compares against `inner_data[4..36]` exactly as in the single-call
flow — the multiSend bytes you display off-device are the bytes the Safe
signs.

For the **`execTransaction`** flavour there is still no `safe_v1`
trailer: encode the multiSend calldata as the `data` argument and
`operation = 1` in the exec calldata; the firmware decodes both.

The **batch** (`CMD_SIGN_USEROP_BATCH`) and **NS VK auto-injection**
behave exactly as in the single-call flow: same TLV kinds (`3` = zk_v3,
`4` = safe_v1) routed to the same `tx_idx` (ZK v3 verifies in pass 2
after Safe records), and the VK injector keys on the zk_v3 payload shape
(`declared_len == 716`), orthogonal to the multiSend change. AddrOnly
trailers are never touched.

### Building the multiSend flow (companion checklist)

```
1.  Build the GPv2Order and orderUid exactly as before
    (uid.owner = THE SAFE — unchanged).
2.  presignCalldata = setPreSignature(orderUid, true)        (164 B)
3.  approveCalldata = approve(GPv2VaultRelayer
        0xC92E8bdf79f0507f65a392b0ab4667716BFE0110, amount)  (68 B)
4.  transactions =
        pack(op=0, to=sellToken,       value=0, approveCalldata) ‖
        pack(op=0, to=GPv2Settlement,  value=0, presignCalldata)
5.  msCalldata = multiSend(transactions)   — canonical encoding
6.  SafeTx { to = MultiSendCallOnly, operation = 1, value = 0,
             data = msCalldata, (refund fields normally 0) }
7.  approveHash flavour: safe_v1 trailer carries (canonical,
        raw_data = msCalldata); inner_data = approveHash(safeTxHash).
    execTransaction flavour: inner_data = execTransaction(...,
        operation = 1, data = msCalldata, ...); no safe_v1 trailer.
8.  zk_v3 trailer: UNCHANGED from the single-call flow.
9.  Optional: ERC-20 metadata trailer for the sell token (rich
    approve render).
10. CMD_SIGN_USEROP / batch TLV as before.
```

If the allowance already exists and the Safe UI emits a **single-call**
`setPreSignature` SafeTx (`operation = 0`), the single-call flow above
applies unchanged. A multiSend wrapping ONLY the presign record also
works.

### New refusal banners (multiSend)

All fail closed with `InvalidPointer` (`NscStatus` discriminant `4`),
joining the single-call refusal table above:

| OLED banner | Cause | Companion fix |
|---|---|---|
| `Safe sign / msend malformed` | Non-canonical `multiSend` ABI (offset ≠ 0x20, bad length, nonzero padding, truncated/overrunning record, trailing bytes). | Encode exactly what Solidity emits; don't hand-roll offsets. |
| `Safe sign / msend rec op!=0` | A record's operation byte is 1 (nested DELEGATECALL) — MultiSendCallOnly would revert on-chain anyway. | Per-record `operation = 0` only. |
| `Safe sign / msend rec count` | 0 records, or more than 6. | Split the batch. |
| `Safe sign / msend 2+ presign` | Two or more `setPreSignature` records — one zk_v3 trailer can bind only one. | One CoW order per SafeTx. |
| `Safe sign / msend too long` | The decoded batch's exact page total exceeds the 24-page trusted-display budget. | Split the batch into smaller SafeTxs. |
| `Safe sign / safe_v1 required` | `operation = 1` to a target **not** on the MultiSendCallOnly allowlist (approveHash flavour — the verifier refuses the trailer). | Use a canonical MultiSendCallOnly deployment. |
| `Safe sign / exec parse fail` | Same, exec flavour. | Same. |
| `CoW sign / v3 required` | The batch contains a presign record but no zk_v3 trailer verified against it (stripped/malformed/owner mismatch). | Attach the same zk_v3 trailer as the single-call flow. |

`operation = 0` calls **to** a MultiSend contract are not treated as
batches (under CALL the Safe is not `msg.sender` for the records, so
none of the rendered semantics would hold) — they fall to the ordinary
loud blind-sign path.

### What the user sees on-device (multiSend)

For the standard approve+presign flow (AddrOnly shown):

```
1. Approve Safe TX         | Chain + name
2. Safe:                   | full Safe address
3. SafeTx Nonce            | Op: MultiSend      ← honest operation row
                           | Inner: MSend x2    ← record count
   [ ! GAS REFUND pages — only if the SafeTx configures a refund ]
4. MSend rec 1/2           | to: 0xa0b869..06eb48   ← divider page
5. Approve USDC (or "ERC-20 call (unverified)")
6. CoW VaultRelayer        | full spender address   ← pinned-address label
7. Amount (or raw hex; "unlimited" guard for max approvals)
8. Contract:               | full token address
9. MSend rec 2/2           | to: 0x9008d1..60ab41   ← divider page
10. CowSwap order          | for this Safe: 0x5afe..0002
11..16. the v3 order body (sell/buy/receiver/expiry/fee/appData)
17. confirm (L=Cancel / R=Confirm)
    [ + ERC-8213 calldata fingerprint pages ]
```

Records that forward native ETH and don't show it inline get a
dedicated `Rec sends ETH:` page after their divider. The spender page
says `CoW VaultRelayer` only when the spender byte-equals the pinned
relayer address (rodata constant, not companion data).

### Worked example (multiSend)

QEMU e2e Scenario **5s** (`nonsecure/src/e2e_test.rs`) is the canonical
wire reference: Sepolia, 1000 USDC → ≥ 0.5 WETH AddrOnly order, approve
(relayer, 1000 USDC) + presign packed through MultiSendCallOnly v1.3.0,
approveHash flavour — expected to sign. Scenario **5t** flips one
record's operation byte to 1 and asserts the `msend rec op!=0` refusal;
Scenario **5u** strips the zk_v3 trailer and asserts `v3 required`. The
same composition is exercised end-to-end (minus Groth16/QEMU) by the
host tests `multisend_wrapped_host_pipeline_composes` and
`multisend_exec_host_pipeline_composes` in
`secure/src/tx/eip712/cowswap/test_vectors.rs`.

### Implementation pointers (multiSend, firmware side)

- Strict decoder + record classifier + the shared `operation == 1`
  predicate: `secure/src/tx/eip712/safe/multi_send.rs`
  (`is_multisend_claim`, `decode_multisend`, `summarize`,
  `multisend_verdict`, `records_pages_total`).
- Operation gates (relaxed only for the allowlisted shape):
  `secure/src/tx/eip712/safe/verify.rs` step 6,
  `secure/src/tx/eip712/safe/exec_decode.rs` (`verify_and_bind_exec`).
- CoW binding through the wrapper:
  `secure/src/tx/eip712/safe/cow_binding.rs` (`resolve_safe_arm`
  multiSend arm — binds the unique presign record; fail-closed
  otherwise).
- Handler gate (verdict + page budget, single + batch):
  `secure/src/tx/display/safe_display.rs` (`multisend_sign_gate`),
  called from `secure/src/nsc/cmd_sign_userop.rs` §7d and
  `secure/src/nsc/cmd_sign_userop_batch.rs` render loop.
- Per-record render: `secure/src/tx/display/safe_display.rs`
  (`append_multisend_pages` → `append_inner_kind_pages`).
- Pinned constants (allowlist, selector, relayer, record cap):
  `proto/src/lib.rs` (`MULTISEND_CALL_ONLY_ADDRESSES`,
  `MULTI_SEND_SELECTOR`, `GPV2_VAULT_RELAYER_ADDRESS`,
  `MULTISEND_MAX_RECORDS`).
