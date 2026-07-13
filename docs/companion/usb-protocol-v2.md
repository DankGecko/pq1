# PQSigner USB Protocol v2 (post-all-C10 cutover)

Companion app integration guide for the PQSigner post-quantum hardware wallet.

## Transport Layer

| Property | Value |
|----------|-------|
| USB class | Custom HID (usage page 0xFFA0) |
| VID / PID | 0x1209 / 0x7051 |
| Report size | 64 bytes (interrupt EP1 IN/OUT) |
| Framing | Ledger-compatible APDU-over-HID |
| CLA byte | **0xF0** (v2 native) |
| Max APDU reassembly | 4096 bytes (`shared::apdu_framing::MAX_APDU_RX`) |

### HID Frame Format

```
First frame (57 bytes payload):
  [0..2)  channel_id   u16 BE
  [2]     tag          0x05 = APDU
  [3..5)  sequence     u16 BE = 0x0000
  [5..7)  total_len    u16 BE (full APDU length)
  [7..64) data         up to 57 bytes

Continuation frames (59 bytes payload):
  [0..2)  channel_id   u16 BE
  [2]     tag          0x05
  [3..5)  sequence     u16 BE (1, 2, 3, ...)
  [5..64) data         up to 59 bytes
```

### APDU Format

```
Request:   CLA(1) INS(1) P1(1) P2(1) [Lc(1) Data(Lc)]
Response:  [Data] SW1(1) SW2(1)
```

### Command Chaining

For payloads exceeding 255 bytes (signing commands), the companion sends
multiple APDUs with the same INS:

- **P1 = 0x00**: last or only block
- **P1 = 0x80**: more blocks follow

The device accumulates data while P1 bit 7 is set and executes only when it
receives a block with **P1 = 0x00**. `Lc` does not terminate a chain: a short
intermediate block is legal with P1=0x80, and an exact-multiple-of-255 payload
still needs its final data block marked P1=0x00.

### Response Chaining (GET_RESPONSE)

Signing responses are up to `MAX_SIGN_RESPONSE_LEN = 12,556` bytes. The device returns the first 253
bytes with `SW = 0x61FF` (more data). The companion drains the rest by
repeatedly sending `INS 0xC0` (GET_RESPONSE) until `SW = 0x9000`.

```
Host → Device:  SIGN_USEROP (chained)
Device → Host:  [253 bytes] SW=0x61FF
Host → Device:  GET_RESPONSE
Device → Host:  [253 bytes] SW=0x61FF
...
Host → Device:  GET_RESPONSE
Device → Host:  [remaining bytes] SW=0x9000
```

## Instruction Set

> **Source of truth.** Authoritative INS values live in `proto/src/lib.rs`
> (search for `INS_V2_*`). This table is a convenience snapshot — when in
> doubt, check the constants.

After the all-C10 cutover, the v2 protocol exposes the following commands:

| INS  | Name                   | Chained? | P1         |
|------|------------------------|----------|------------|
| 0x01 | GET_DEVICE_INFO        | No       | 0          |
| 0x02 | GET_STATUS             | No       | 0          |
| 0x10 | UNLOCK                 | No       | 0          |
| 0x11 | LOCK                   | No       | 0          |
| 0x30 | SIGN_USEROP (unified)  | Yes      | 0x00/0x80  |
| 0x32 | SIGN_USEROP_BATCH      | Yes      | 0x00/0x80  |
| 0x60 | GET_WALLET_ADDRESS     | No       | 0          |
| 0x61 | GET_INIT_CODE          | No       | 0          |
| 0x62 | SIGN_OFFCHAIN          | Yes      | 0x00/0x80  |
| 0x63 | OFFCHAIN_STATUS        | No       | 0          |
| 0x70 | FW_BEGIN               | Yes      | 0x00/0x80  |
| 0x71 | FW_CHUNK               | Yes      | 0x00/0x80  |
| 0x72 | FW_COMMIT              | No       | 0          |
| 0x73 | FW_STATUS              | No       | 0          |
| 0x74 | FW_ABORT               | No       | 0          |
| 0xC0 | GET_RESPONSE           | No       | 0          |

### 0x30 SIGN_USEROP — unified sign

**This is the only single-UserOp signing command in the post-cutover wallet.**
The companion's flags request initCode or Type 1 output; firmware does not infer
registration state. Current production companions may request the slot-0
factory-deploy path or Type 2 only. They must not request/submit Type 1 until
the reviewed wire bump described below supplies its missing binding material.

**Input payload (`SIGN_USEROP_HEADER_LEN = 330` bytes of header + inner
calldata):**

```
offset  size  field
---------------------------------------------------------
  0     8    chain_id (u64 BE)
  8     4    flags (u32 BE — see shared/src/lib.rs)
 12    20    sender (MUST equal GET_WALLET_ADDRESS(account_index); mismatch is refused)
 32    20    entry_point (EntryPoint v0.6 address)
 52    32    nonce (u256 BE, base nonce for Type 1 if needed else Type 2)
 84    32    call_gas_limit (u256 BE)
116    32    verification_gas_limit (u256 BE)
148    32    pre_verification_gas (u256 BE)
180    32    max_fee_per_gas (u256 BE)
212    32    max_priority_fee_per_gas (u256 BE)
244    32    paymaster_and_data_hash (sha256, SHA256_EMPTY when empty)
276    20    to_address (inner tx recipient)
296    32    value (u256 BE)
328     2    data_len (u16 BE, 0..=4096)
330     N    data
```

Before any signature is released, every confirmation set includes a mandatory
`Signer acct #N` page followed by the full EIP-55 address independently derived
for `account_index` in secure world. The wire `sender` must match that address,
but is not trusted as the source of the displayed identity. Batch signing shows
the same identity for each member confirmation and again at the final batch
authorization gate.

**Response (post-2026-04-29 layout):**

```
[new_offchain_count   u64 BE]               (8 bytes — for Type 2 calldata)
[init_code_len        u32 BE]
[init_code            init_code_len bytes]  (4280 B when FLAG_INCLUDE_INIT_CODE, else 0)
[type1_len            u32 BE]
[type1_wrapper        type1_len bytes]      (4128 B when FLAG_REGISTER_SLOT, else 0)
[type2_len            u32 BE]
[type2_wrapper        type2_len bytes]      (always 4128 B)
```

- `type1_len == 0` means only that no Type 1 was requested/emitted. Except for
  slot 0 installed atomically by the factory path, the companion must verify
  the selected slot is already registered on-chain before requesting Type 2.
- `type1_len == 4128` means firmware signed a rotation to slot N≥1. Wire v2
  does not return the 64-byte new slot public key required to reconstruct the
  signed `addOwnerBytes(bytes)` calldata. Seedless production companions MUST
  reject this response and MUST NOT retry it until a reviewed protocol bump
  supplies the public key or complete Type-1 calldata.

**Type 1 / Type 2 wrapper (each exactly 4128 bytes):**

Both are `abi.encode(uint256 ownerIndex, bytes c10Sig)` where
`c10Sig` is a raw 4008-byte SPHINCS+C10 signature
(`C10_SIG_LEN = 4008`, `OWNER_BYTES_LEN = 64`). The wallet contract
ABI-decodes them as `SignatureWrapper(uint256 ownerIndex, bytes signatureData)`
in `validateUserOp`:

- `ownerIndex == 0` → Type 1 (bootstrap-key sig); installs the slot pubkey
  at the wrapper's destination index.
- `ownerIndex >= 1` → Type 2 (slot-key sig); executes the user's call
  via `executeWithOffchainCount(...)` which atomically updates
  `offchainSigCount[i]` to `new_offchain_count`.

The companion wraps an available wrapper in an EntryPoint v0.6 `UserOperation`
(`UserOperation06`) with the appropriate
`callData`:

- **Type 1 UserOp (rotation, currently companion-blocked):** the signed calldata
  is exactly `addOwnerBytes(newSlotPk)`. A no-op `execute(sender,0,"")` has a
  different hash and fails the contract's Type-1 selector gate. Do not submit
  it. First deployment is not Type 1: set `FLAG_INCLUDE_INIT_CODE`, use slot 0,
  and keep `FLAG_REGISTER_SLOT` clear; the factory installs slot 0.
- **Type 2 UserOp**: `callData = executeWithOffchainCount(ownerIndex,
  new_offchain_count, to, value, data)` — the wallet bumps the EIP-1271
  off-chain counter and dispatches the user's call atomically.

### 0x10 UNLOCK

No arguments. The secure world takes over the trusted UI, prompts the
user for their PIN via buttons, and (on success) unlocks both secure
elements. The PIN never crosses the gateway.

Response is a status word only (no data).

### 0x02 GET_STATUS

Returns:
```
[provisioned u8] [locked u8] [pin_remaining u8]
```

### 0x01 GET_DEVICE_INFO

Returns a versioning + capability header. Reports `ep_version = 0x0006`
(EntryPoint v0.6) and `sig_param_set = 2` (SPHINCS+C10,
`C10_SIG_LEN = 4008`).

### 0x60 GET_WALLET_ADDRESS

Input: empty for legacy `account_index = 0`, or `[account_index u32 BE]` for
accounts `0..=255`. No chain id is accepted; wallet addresses are chain-
independent by design.
Output: 20-byte CREATE2-predicted ERC-1967 proxy address.
First call after unlock takes <1 s (master keygen); cached afterwards.

### 0x61 GET_INIT_CODE

Pre-computed 4280-byte `initCode` for `(account_index, chain_id)` so the
companion can run gas estimation against the EntryPoint without
round-tripping through `0x30 SIGN_USEROP`.

### 0x62 SIGN_OFFCHAIN

EIP-1271 signature response with two layouts selected by the input `flags`
byte:

- `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 1`:
  `[new_local_offchain_count u64 BE][C10 sig (4008 B)]` (4016 bytes total).
  Wrap the raw signature as `abi.encode(uint256 ownerIndex, bytes c10Sig)` and
  call `wallet.isValidSignature(rawHash, wrappedSig)`.
- `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 0`:
  `[new_local_offchain_count u64 BE][ERC-6492 blob (8608 B)]` (8616 bytes
  total). The payload is already the complete ERC-6492 wrapper; pass it through
  unchanged to an ERC-6492-aware verifier and do not ABI-wrap it again. This
  counterfactual path is restricted to slot 0.

The deployed-wallet path refuses an unregistered slot. The undeployed
counterfactual path has one narrow exception: a never-used slot 0 is
auto-registered locally so its ERC-6492 deploy-then-verify blob can be produced.
Both paths refuse when the gap exceeds `MAX_OFFCHAIN_GAP = 100` or the combined
cap is exhausted. Bootstrap key (`ownerIndex == 0`) is **forbidden** for
EIP-1271.

The input header is 17 B (`account(1) | chain(8) | slot(4) | kind(1) |
payload_len(2) | flags(1)`). The `kind` byte selects the payload
format:

| `kind`                          | Value | Payload                                                                                       |
|---------------------------------|-------|-----------------------------------------------------------------------------------------------|
| `OFFCHAIN_KIND_RAW32`           | 0     | 32 companion-supplied opaque bytes; firmware wraps via Solady nested EIP-712 and displays `! BLIND RAW32`. Never translate a typed-data request into this kind. |
| `OFFCHAIN_KIND_PERSONAL_SIGN`   | 1     | UTF-8 message ≤ `MAX_OFFCHAIN_PERSONAL_SIGN_LEN`; firmware applies EIP-191 prefix + wraps.    |
| `OFFCHAIN_KIND_EIP712_TYPED`    | 2     | EIP-712 typed-data (see below) — Phase 4 of the ERC-7730 rollout.                              |
| `OFFCHAIN_KIND_EIP712_TYPED_V3` | 3     | EIP-712 typed-data plus nested encodeData records; see the canonical companion guide §6.5.   |

`RAW32` is a deliberately loud blind-sign tier, not evidence that the device
understands a user's intent. A hostile companion can submit the final hash of
otherwise structured typed data through this kind and suppress its semantic
pages. Production companions MUST NOT downgrade structured requests to
`RAW32`; production firmware should disable the kind unless the product owner
explicitly accepts this residual.

#### `kind = OFFCHAIN_KIND_EIP712_TYPED` (2) wire format

Payload layout (immediately after the 17-byte header):

```
[u16 BE = 1]                  // domain_sep_present (must be 1)
[u8; 32] domain_separator     // EIP-712 EIP712Domain final hash
[u8; 32] primary_type_hash    // keccak256(encodeType(primaryType, types))
[u16 BE] encoded_data_len     // ≤ MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
[u8; encoded_data_len] encoded_data
                              // canonical EIP-712 encodeData body (NOT
                              // including the type hash). Plain ABI encoding
                              // matches only flat static scalar members;
                              // dynamic/composite members use hash words.
[u16 BE] trailer_len          // ERC-7730 descriptor trailer length
[u8; trailer_len] trailer     // ERC-7730 bundle (see docs/companion/erc7730-integration.md)
```

The minimum payload length is `2 + 32 + 32 + 2 + 2 = 70` bytes (empty
`encoded_data` + zero-length trailer reaches the strict framing parser but is
rejected with `empty trailer`). The maximum payload length is
`MAX_OFFCHAIN_EIP712_TYPED_LEN`.

Secure-side processing:

1. Verify the trailer bundle against `ERC7730_DESCRIPTORS_ROOT`.
2. `cross_check_eip712(descriptor.ir, chain_id, domain_separator)` — exact,
   FI-hardened binding. The descriptor compiler forced the deployment
   `verifyingContract` into this domain separator; firmware does not receive a
   second independent contract argument on this path.
3. Constant-time select the authenticated descriptor format using the complete
   32-byte `primary_type_hash`; a four-byte prefix or catalogue hint is never
   sufficient.
4. Compute `struct_hash = keccak256(primary_type_hash || encoded_data)`.
5. Compute the EIP-712 final hash:
   `final = keccak256(0x1901 || domain_separator || struct_hash)`.
6. Render the descriptor's matching format via
   `display::erc7730::render_erc7730_eip712_pages`; render the
   ERC-8213 fingerprint with the `final` hash as the displayed value.
7. Wrap `final` through Solady's nested PersonalSign envelope (no new
   typehash, no on-chain change).
8. Sign with the slot key + bump the per-slot off-chain counter.

Output format is selected by the same deployed/counterfactual flag as kinds 0
and 1: 4016-byte count+C10 for deployed wallets, or 8616-byte
count+ERC-6492 blob for counterfactual slot 0.

### 0x63 OFFCHAIN_STATUS

Per-slot `(local_offchain_count, last_userop_count, registered)` readback.

### 0x70..0x74 FW_BEGIN/CHUNK/COMMIT/STATUS/ABORT

Streaming firmware update. PIN unlock required on every call. See
`docs/firmware/firmware-update.md`.

## Reserved / unused INS values

These INS values exist as constants in `proto/src/lib.rs` but are no
longer dispatched (or are reserved for backwards-compat probing):

- `0x20 GET_BOOTSTRAP_VK`, `0x21 GET_MAIN_VK` — superseded by
  `GET_WALLET_ADDRESS` (slot keys are derived on demand and not exposed)
- `0x31 SIGN_CLEAR_USEROP` — clear-sign is now an in-line side-effect of
  `0x30 SIGN_USEROP` when calldata is recognised (ERC-20, Safe, CowSwap…)
- `0x40 SIGN_MESSAGE`, `0x41 SIGN_EIP712` — EIP-191 / generic EIP-712 are
  served via `0x62 SIGN_OFFCHAIN` (Solady-nested EIP-712 / EIP-1271)
- `0x50 SIGN_BOOTSTRAP` — folded into `0x30 SIGN_USEROP` with
  `FLAG_REGISTER_SLOT`

## Status words

| SW     | Meaning |
|--------|---------|
| 0x9000 | OK |
| 0x6100..0x61FF | More data available; send GET_RESPONSE |
| 0x6501 | Slot exhausted (rotation path failed) |
| 0x6700 | Wrong length |
| 0x6982 | Security condition not satisfied (bad PIN, cancelled sign) |
| 0x6984 | Session expired (idle wipe) |
| 0x6985 | Device locked |
| 0x6A80 | Wrong data |
| 0x6D00 | INS not supported |
| 0x6E00 | CLA not supported |
| 0x6F00 | Internal error |
