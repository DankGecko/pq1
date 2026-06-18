# Safe multiSend clear-signing — companion app integration (delta)

This document specifies **what changes for the companion app/extension**
relative to [`companion-safe-cowswap-presign.md`](../companion/companion-safe-cowswap-presign.md)
now that the firmware clear-signs Safe **multiSend batches**. Read that
document first — everything it defines (trailers, orderUid construction,
refusal model, batch TLV) still holds; this is the delta.

> Status: landed 2026-06-12. Validated through the host
> decoder/resolver/compose matrices (incl. the full verify → resolve →
> record-bind → cross-check chain for both Safe flavours). QEMU e2e
> scenarios 5s/5t/5u are written but have not been executed yet — run
> `make e2e` to exercise them.

## Why this exists

The previous iteration assumed the SafeTx's inner call IS the 164-byte
`setPreSignature`. In practice the Safe web UI never emits that shape
for a CoW order: it batches **two** actions — the ERC-20 `approve` to
the CoW vault relayer and the `setPreSignature` — through the
`MultiSendCallOnly` contract, executed as a **DELEGATECALL**:

```
SafeTx {
    to        = MultiSendCallOnly          ← NOT GPv2Settlement
    operation = 1 (DELEGATECALL)           ← was refused before
    value     = 0
    data      = multiSend(transactions)    ← selector 0x8d80ff0a
}
```

The firmware now accepts exactly this shape — and, more generally,
clear-signs any multiSend batch whose records it can decode — under the
hard rules below. Everything else still refuses loudly. There is **no
blind-sign path for a DELEGATECALL, ever**.

## What changed vs the previous commit (TL;DR for the extension)

1. **You no longer need to build a single-call SafeTx.** Send the
   SafeTx exactly as the Safe UI/SDK builds it: `to =
   MultiSendCallOnly`, `operation = 1`, `data = multiSend(...)`.
2. **The `safe_v1` trailer is unchanged in layout** — but its
   `raw_data` is now the **full multiSend calldata** (it must keccak to
   the SafeTx's `data_hash`, as always).
3. **The `zk_v3` trailer is byte-identical to before.** Same canonical
   / proof / AddrOnly forms, same `uid.owner = the Safe`. The firmware
   finds the `setPreSignature` **record** inside the multiSend payload
   and binds the trailer to that record's 164 bytes. You do not point
   at the record; the firmware locates it (and refuses if there is more
   than one).
4. **The `execTransaction` flavour works the same way**: encode
   `operation = 1`, `to = MultiSendCallOnly`, `data = multiSend(...)`
   in the exec calldata; attach only the `zk_v3` trailer.
5. **Optional:** attach the ERC-20 metadata trailer for the sell token
   — the firmware now matches it against multiSend **record** targets,
   so the approve record renders with symbol + decimals instead of a
   raw amount.
6. NEW refusal banners to handle (see table below).

## Accepted multiSend shape (hard rules — all enforced on-device)

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

## Wire layout (approveHash flavour)

Identical envelope to the previous commit — only `raw_data` grew:

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
byte-compares against `inner_data[4..36]` exactly as before — the
multiSend bytes you display off-device are the bytes the Safe signs.

For the **`execTransaction`** flavour there is still no `safe_v1`
trailer: encode the multiSend calldata as the `data` argument and
`operation = 1` in the exec calldata; the firmware decodes both.

### Batch (`CMD_SIGN_USEROP_BATCH`)

Unchanged: same TLV kinds (`3` = zk_v3, `4` = safe_v1) routed to the
same `tx_idx`; ZK v3 still verifies in pass 2 after Safe records.

### What the NS layer auto-injects

Unchanged. The VK injector keys on the zk_v3 payload shape
(`declared_len == 716`) and is orthogonal to the multiSend change.
AddrOnly trailers are never touched.

## Building the flow (companion checklist)

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
`setPreSignature` SafeTx (`operation = 0`), the previous commit's flow
still applies unchanged. A multiSend wrapping ONLY the presign record
also works.

## New refusal banners

All fail closed with `InvalidPointer` (`NscStatus` discriminant `4`),
joining the table in the previous document:

| OLED banner | Cause | Companion fix |
|---|---|---|
| `Safe sign / msend malformed` | Non-canonical `multiSend` ABI (offset ≠ 0x20, bad length, nonzero padding, truncated/overrunning record, trailing bytes). | Encode exactly what Solidity emits; don't hand-roll offsets. |
| `Safe sign / msend rec op!=0` | A record's operation byte is 1 (nested DELEGATECALL) — MultiSendCallOnly would revert on-chain anyway. | Per-record `operation = 0` only. |
| `Safe sign / msend rec count` | 0 records, or more than 6. | Split the batch. |
| `Safe sign / msend 2+ presign` | Two or more `setPreSignature` records — one zk_v3 trailer can bind only one. | One CoW order per SafeTx. |
| `Safe sign / msend too long` | The decoded batch's exact page total exceeds the 24-page trusted-display budget. | Split the batch into smaller SafeTxs. |
| `Safe sign / safe_v1 required` (unchanged banner) | `operation = 1` to a target **not** on the MultiSendCallOnly allowlist (approveHash flavour — the verifier refuses the trailer). | Use a canonical MultiSendCallOnly deployment. |
| `Safe sign / exec parse fail` (unchanged banner) | Same, exec flavour. | Same. |
| `CoW sign / v3 required` (unchanged banner) | The batch contains a presign record but no zk_v3 trailer verified against it (stripped/malformed/owner mismatch). | Attach the same zk_v3 trailer as the single-call flow. |

`operation = 0` calls **to** a MultiSend contract are not treated as
batches (under CALL the Safe is not `msg.sender` for the records, so
none of the rendered semantics would hold) — they fall to the ordinary
loud blind-sign path, as before this change.

## What the user sees on-device

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

## Worked example

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

## Implementation pointers (firmware side)

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
