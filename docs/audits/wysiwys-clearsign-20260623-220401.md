# audit:wysiwys — Security Audit (20260623-220401)

## Scope & threat model

WYSIWYS ("what you see is what you sign") integrity of every clear-signing
decoder/renderer in the secure world. The promise under audit: **the set of
bytes rendered to the trusted OLED equals the set of bytes covered by the
SPHINCS+C10 signature**, and no rendered value is formatted unequal to the
signed bytes.

Attacker model (per mission): the entire non-secure world and the USB companion
are attacker-controlled and send maximally hostile input. No physical access is
assumed for the CRITICAL/HIGH bar — a finding qualifies if a companion can make
the device sign something materially different from what the user confirmed on
the OLED. Physical/FI surfaces are noted where relevant but are not the focus.

**What is signed (re-derived from `cmd_sign_userop.rs`).** A Type-2 UserOp
signature is `compute_sphincs_digest_v06(params, sha256(t2_exec))` where
`t2_exec = executeWithOffchainCount(ownerIndex, newOffchainCount, to_address,
value, inner_data)` (`cmd_sign_userop.rs:1273-1285`, `:1570-1592`). The signed
preimage therefore commits, byte-for-byte, to: `to_address`, native `value`,
the inner-tx `inner_data`, plus the UserOp envelope (`chain_id`, `nonce`, the
five gas fields, `paymaster_and_data` hash). Every one of those must reach a
page. `inner_data` is decoded by the renderer ladder in `pick_sign_pages`
(`display/mod.rs:243-408`). Safe / CoW orders are additionally bound to a
verified trailer whose own field set (SafeTx struct / GPv2Order struct) is the
WYSIWYS surface.

## Methodology — what you read and how you hunted

Read end to end, tracing each signed field to a page (or to its absence):

- The dispatcher (`display/mod.rs::pick_sign_pages` + `value_page.rs`
  `enforce_native_value_page` / `enforce_gas_pages`) and the sign handler
  (`nsc/cmd_sign_userop.rs`, full 1846 lines) to fix the signed-byte set.
- Every row-formatting primitive (`display/primitives.rs`, 756 lines) — the
  place truncation/aliasing bugs hide.
- Every leaf renderer: `value_transfer`, `erc20_known`, `erc20_unknown`,
  `blind_sign`, `batch`, `slot_rotation`, `erc8213`, `safe_display` (1414 lines),
  `safe_mgmt` + `mgmt_decode`, `multi_send` (the gate↔render page-count lockstep).
- Sub-audited in parallel and then **personally re-verified the cited code** for:
  the ERC-7730 renderer (`display/erc7730/*`, `erc7730_render/*`), the typed-call
  ABI renderer (`display/typed_call/*`), the CoW order render
  (`eip712/cowswap_display.rs` + `cowswap/{mod,verify}.rs`), and EIP-1271
  off-chain (`display/eip1271.rs` + `cmd_sign_offchain.rs`).

Hunting doctrine: for every decoder I enumerated the full signed-field set, then
discharged each field to a page or flagged the gap. The dominant pattern found
is **head/tail truncation of a signed value**. I split these by data type,
because exploitability differs sharply:

- **Numeric** truncation (an *amount* or *timestamp*): hiding high-order bytes
  changes the magnitude the user reads, with **no collision required** — a clean
  display≠signed break.
- **Identifier** truncation (an *address* or opaque *bytes32*): to substitute a
  value for one the user expects, the attacker must collide the *visible* bytes
  (104 bits here) → computationally infeasible → defense-in-depth only.

## Findings   (ordered by severity, most severe first)

### [HIGH-1] Safe inner-tx unverified-ERC-20 amount is rendered as middle-truncated hex — magnitude-hiding fund drain

- **Location:** `secure/src/tx/display/safe_display.rs:1389-1413`
  (`write_raw_uint_two_rows`), reached from `append_erc20_tail_pages`
  `safe_display.rs:1104-1116` (the `meta = None` arm). Classification that forces
  this arm: `render_safe_pages_inner` `safe_display.rs:372-378` and the multiSend
  record path `append_multisend_pages` `safe_display.rs:1173-1178`.
- **Vulnerability class:** numeric truncation → signed-but-not-faithfully-shown
  amount (WYSIWYS magnitude-hiding). Unfixed Safe-path sibling of the resolved
  top-level "erc20_unknown hides value" class.
- **Attacker & required capability:** companion / NS only. No physical access,
  no FI. The single precondition (token shows as "unverified") is **attacker-
  controlled**, not user-environmental — see falsification.
- **Minimal trigger — exact bytes.** `CMD_SIGN_USEROP` (CMD 7) with:
  - header `to_address` (off 276) = the Safe contract `S`; outer `value` (off
    296) = 0; `data` (off 330) = `execTransaction(...)` calldata whose decoded
    inner SafeTx is `{ to = T (any ERC-20 the Safe holds), value = 0, operation =
    0, data = transfer(attacker, AMOUNT) }`.
  - `AMOUNT` (the 32-byte ERC-20 transfer amount word) crafted so the *magnitude*
    lives in the hidden middle bytes and the *visible* bytes look benign:
    `AMOUNT = bytes[0..7]=00…00`, `bytes[7..26] = <huge attacker magnitude>`,
    `bytes[26..32] = 00 00 00 00 00 64` (looks like "100").
  - **Omit the optional ERC-20 metadata trailer** (it is companion-supplied;
    `cmd_sign_userop.rs:691-760`). With no metadata, `verified_meta = None`.
- **Exploitation path:**
  1. `verified_meta = None` ⇒ the Safe inner classifier yields
     `InnerKind::Erc20Known(call)` then downgrades to `Erc20Unknown(call)`
     because `erc20.is_none()` (`safe_display.rs:373-376`).
  2. `append_inner_kind_pages` → `Erc20Unknown` arm → `append_erc20_tail_pages(.., meta=None, ..)`
     (`safe_display.rs:919-928`).
  3. The amount page takes the `None` branch (`safe_display.rs:1104-1116`):
     `write_raw_uint_two_rows(r1, r2, &amount)`.
  4. `write_raw_uint_two_rows` paints `row1 = "0x" + hex(amount[0..7])` and
     `row2 = "... " + hex(amount[26..32])` — bytes `[7..26]` (the middle 19) are
     **never rendered** (`safe_display.rs:1397-1412`).
  5. OLED shows: `Raw amount:` / `0x00000000000000` / `... 000000000064`. The
     user reads ≈ 100 base units and confirms.
  6. The device signs `executeWithOffchainCount(.., S, 0, execTransaction(... transfer(attacker, AMOUNT)))`.
     On chain the Safe transfers `AMOUNT` (≈ the hidden magnitude, e.g. 10^20+) of
     `T` to `attacker`. **Drain.**
- **Invariant / property broken:** WYSIWYS (#WYSIWYS, CLAUDE.md "Trusted-display
  clear-signing": "no blind-sign path for known shapes"; primitives.rs design
  rule "Never silently truncate a number. The OLED is the trusted display; a
  truncated value is as dangerous as a wrong one").
- **Evidence:**
  ```rust
  // safe_display.rs:1389  — the truncating helper
  fn write_raw_uint_two_rows(row1, row2, value) {
      row1[0]=b'0'; row1[1]=b'x';
      for i in 0..7 { row1[2+i*2]=hex[value.0[i]>>4]; ... }   // bytes 0..7
      row2[0..4] = "... ";
      for i in 0..6 { let b = value.0[26+i]; ... }            // bytes 26..32
      // bytes 7..26 (19 bytes of magnitude) are dropped, with no overflow signal
  }
  ```
  Contrast the **top-level** `erc20_unknown` renderer, which shows the full
  decimal and overflows loudly — proving this is an oversight, not policy:
  ```rust
  // erc20_unknown.rs:92-106 — full decimal, never truncated
  match amount.format_decimal(0, 0, false, &mut tmp) {
      Some(n) if n <= DISPLAY_COLS => { ... }                 // full
      Some(n) if n <= 2 * DISPLAY_COLS => { ... }             // full, two rows
      _ => write_line(&mut pages.buf[p][1], "!OVERFLOW"),     // loud
  }
  ```
- **Falsification attempt.** (1) "It needs a rare unverified token." — No: the
  ERC-20 metadata bundle is an **optional companion-supplied trailer**
  (`cmd_sign_userop.rs:333-343`, `:691`). The attacker simply withholds it, so
  the truncated path renders for *any* token (USDC included); the only visible
  cost is the token shows as "unverified" instead of by name (the contract
  address is still shown in full on a later page, but the *amount* is hidden
  regardless). (2) "The `...` elision warns the user." — It marks that *bytes*
  are omitted but conveys nothing about *magnitude*; the user reads a small
  number. This is exactly the failure mode the project rejected for amounts
  elsewhere (fixed-width decimal everywhere else). (3) "The ERC-8213 fingerprint
  binds the full calldata." — True (`cmd_sign_userop.rs:1111-1121`), but it is a
  `keccak256(uint256(len)||calldata)` the user cannot compute by hand and is
  labelled "verify off-dev"; it does not make the on-screen amount correct.
  (4) "Maybe it's unreachable for execTransaction." — Reachable for all three
  Safe flavours: approveHash (`render_safe_v1_pages`), execTransaction
  (`render_safe_exec_pages`), and every multiSend record
  (`append_multisend_pages`), since all route ERC-20 inners through the same
  `append_erc20_tail_pages`.
- **Suggested fix (describe only):** replace `write_raw_uint_two_rows` with the
  same full-decimal/overflow-loud renderer the top-level `erc20_unknown` uses
  (`format_decimal(0,0)` across ≤2 rows → `!OVERFLOW`), or render the full 32-byte
  amount across 3 rows. The invariant: an amount that does not fit must overflow
  *loudly*, never elide its middle.
- **Confidence:** confirmed (mechanism + reachability). Severity note: this meets
  the literal CRITICAL rubric ("companion-triggerable, no physical access,
  signing ≠ displayed"). Ranked HIGH conservatively because the token renders as
  "unverified" with `...`-elided hex (a savvy user *might* balk) and the
  contract/recipient addresses are shown in full. The lead may reasonably
  escalate to CRITICAL.

### [MEDIUM-2] ERC-7730 `date` / `duration` silently drop the high 24 bytes of a signed uint256 — displayed time ≠ signed time

- **Location:** `secure/src/tx/display/erc7730/formatters.rs:415` (`render_date`)
  and `:451` (`render_duration`), via `read_u64_be_tail`
  (`formatters.rs:673-680`).
- **Vulnerability class:** numeric truncation → display≠signed for a governed
  field.
- **Attacker & required capability:** companion / NS only, against a *blessed*
  (Merkle-pinned) descriptor that maps a `uint256` field to `format:"date"`. The
  shipped `secure/data/erc7730/circle-usdc-rwa.json` / `circle-usdc-twa.json`
  render `ReceiveWithAuthorization`'s `validAfter` / `validBefore` as dates.
- **Minimal trigger.** An EIP-712 `ReceiveWithAuthorization` off-chain sign (or
  the userop path carrying the descriptor) where the `validBefore` encodeData
  word = `0x0000000000000001_…_0000000000000001` (high bytes non-zero, low-8 a
  benign near-future/epoch value). `read_u64_be_tail` keeps only `bytes[24..32]`.
- **Exploitation path:**
  1. `render_date` reads `secs = read_u64_be_tail(&bytes)` — the low 64 bits only
     (`formatters.rs:415`); `read_u64_be_tail` explicitly does **not** check
     `bytes[0..24] == 0` (`formatters.rs:678-680`, its own doc: "out-of-range
     values silently truncate").
  2. OLED shows `format_iso8601_utc(secs, …)` — e.g. `1970-01-01 / 00:00:01 UTC`.
  3. The full `uint256` (astronomically large) is what is folded into the signed
     EIP-712 `structHash`. The on-chain `ReceiveWithAuthorization` compares the
     full value to `block.timestamp` → the authorization is valid far beyond the
     window the user saw.
- **Invariant / property broken:** WYSIWYS — the device signs a validity window
  different from the one confirmed on screen.
- **Evidence:**
  ```rust
  // formatters.rs:415
  let secs = read_u64_be_tail(&bytes);   // low 8 bytes only — high 24 dropped
  // formatters.rs:678
  fn read_u64_be_tail(b: &[u8;32]) -> u64 { u64::from_be_bytes(b[24..32]…) }
  ```
- **Falsification attempt.** "It's only a timestamp, not funds." — Correct that
  `value`/`to` of the authorization are shown faithfully, so this does not
  redirect funds; it extends *when* an already-authorized transfer can be
  relayed. That is a genuine WYSIWYS break (the date the user confirmed is not
  the date signed) but the fund-theft path is indirect (replay/timing of an
  already-approved transfer), hence MEDIUM and fund-impact `needs-confirmation`.
  The display≠signed mechanism itself is confirmed.
- **Suggested fix:** in `read_u64_be_tail` callers, reject (fall to blind-sign or
  paint a loud overflow banner) when `bytes[0..24] != 0`, matching the amount
  helpers' "never silently truncate" rule.
- **Confidence:** confirmed (mechanism); fund-impact needs-confirmation.

### [MEDIUM-3] typed-call `bytesN` (N ≥ 16) rendered with head-7/tail-6 elision — opaque 32-byte value middle hidden

- **Location:** `secure/src/tx/display/typed_call/mod.rs:561-580`
  (`write_bytesn_rows` else-branch), reached from `render_arg`
  `mod.rs:234-237`; returns `true` (renders & signs), unlike the array path which
  declines.
- **Vulnerability class:** identifier truncation → signed-but-not-shown middle
  bytes. Unfixed sibling of the resolved typed-call array-elision findings (the
  "decline rather than truncate" rule was applied to arrays/single-element
  address/amount but never to top-level `bytesN`).
- **Attacker & required capability:** companion / NS, with a verified selector
  trailer (curated or self-attest) for a function carrying a `bytes32`/`bytes20`
  arg whose calldata is not ERC-20/Safe/CoW shaped. Reachable per the sub-audit
  via ~237 curated selectors (e.g. `mint(uint256,bytes32)`, `setUint(bytes32,uint256)`,
  `unsealBid(bytes32,uint256,bytes32)`).
- **Minimal trigger.** `inner_data = selector || arg0(bytes32) || …` with `arg0`
  a 32-byte value whose first 7 and last 6 bytes match a value the user expects
  but whose middle 19 differ.
- **Exploitation path:** `write_bytesn_rows` paints `0x`+`word[0..7]` /
  `... `+`word[n-6..n]`, hiding `word[7..26]`, and returns `true`
  (`mod.rs:561-580`) so the arg renders and the UserOp signs. A `bytes32` that
  must be user-verified (a role hash, merkle root, commitment, orderUid fragment,
  storage key) can be substituted for one sharing the visible head/tail.
- **Invariant / property broken:** WYSIWYS for the hidden 19 bytes; also the
  project's own full-display bar (addresses were fixed to full 40-hex for exactly
  this collision class, `primitives.rs:230-263`).
- **Evidence:**
  ```rust
  // typed_call/mod.rs:561  (else branch, total_chars > 32 ⇔ n > 15)
  for i in 0..7 { row1[2+i*2]=hex_nibble(word[i]>>4); ... }    // first 7
  row2[0..4]=b"... ";
  for i in 0..6 { let b = word[n-6+i]; ... }                   // last 6
  // ... returns true — never declines to blind-sign
  ```
- **Falsification attempt.** "Brute-forceable like the old address bug?" — The
  visible 13 bytes = 104 bits; to make a malicious `bytes32` display identically
  to a user-expected one the attacker must collide those 104 bits → 2^104,
  infeasible (the fixed address bug hid only 5 bytes / 40 bits). So for the
  "substitute-for-an-expected-value" model the user *can* still detect the
  mismatch from the 13 visible bytes — this is reduced-margin defense-in-depth,
  not a clean drain — hence MEDIUM, not HIGH. It remains a real inconsistency
  with the project's stated bar and should be brought into line.
- **Suggested fix:** `write_bytesn_rows` returns `false` for `N > 15` (decline →
  loud blind-sign), or render all 32 bytes across 3 rows (fits one page).
- **Confidence:** confirmed (mechanism); drain needs-confirmation (grind-bounded).

### [MEDIUM-4] ERC-7730 `visible:"never"` permits a blessed descriptor to hide effect-bearing signed fields

- **Location:** host lint `dbgen/src/erc7730.rs` completeness check (counts a
  `visible:"never"` field as "covered" with no effect-bearing gate); shipped
  corpus `secure/data/erc7730/opensea-wyvern.json` marks `paymentToken`,
  `feeRecipient`, the four fee fields, `target`, `maker`, `taker`, `calldata`,
  `replacementPattern` all `visible:"never"`. On-device, `render_erc7730_pages`
  trusts the pinned descriptor's field list with **no completeness enforcement**.
- **Vulnerability class:** signed-but-not-shown (authored omission) — sibling of
  the resolved H-3 *tuple-member* completeness lint, which closed *accidental*
  omission but not *sanctioned* `visible:"never"` of economically-relevant fields.
- **Attacker & required capability:** companion holding a blessed descriptor that
  hides an effect-bearing field. The descriptor is Merkle-pinned
  (`ERC7730_DESCRIPTORS_ROOT`), so the attacker cannot *forge* one — they can only
  *use* a shipped descriptor whose field list already omits a signed field.
- **Exploitation path:** for an OpenSea Wyvern `Order`, `paymentToken` and the fee
  fields are committed by the EIP-712 signature but never rendered, so a hostile
  companion can present a benign "OpenSea Listing / price / expiration" while the
  signed order denominates `basePrice` in an attacker token or routes fees to an
  attacker `feeRecipient`.
- **Invariant / property broken:** WYSIWYS (a signed struct field reaches no
  page). Architectural: the on-device ERC-7730 renderer has **zero** completeness
  enforcement — the pinned corpus + host lint are part of this path's TCB.
- **Evidence:** the on-device renderer iterates only the descriptor's declared
  field list (`display/erc7730/formatters.rs` resolve/format loop); there is no
  cross-check that the list covers every effect-bearing word of `inner_data`
  (that check exists only host-side in dbgen).
- **Falsification attempt.** "The companion can't forge a descriptor." — Correct;
  this requires the omission to already exist in the shipped root, which it does
  for `opensea-wyvern.json`. The open question is whether OpenSea Wyvern is still
  a live signing surface for PQ1 (it is a legacy protocol), so end-to-end theft is
  `needs-confirmation`; the shipped descriptor is nonetheless a signed-but-not-shown
  surface and the lint sanctions the class generally.
- **Suggested fix:** in dbgen, gate `visible:"never"` behind an explicit
  effect-bearing allowlist (or downgrade OpenSea token/fee fields to `raw`); add a
  doc note that the on-device renderer trusts the field list, so corpus review is
  TCB.
- **Confidence:** needs-confirmation (corpus liveness); the lint/omission is
  confirmed via sub-audit + documented lint behaviour (not independently re-read
  in this pass).

### [LOW-5] CoW order `receiver` rendered truncated (13 of 20 bytes), inconsistent with the full-address ERC-20 recipient page

- **Location:** `secure/src/tx/eip712/cowswap_display.rs:160` (receiver page) →
  `write_addr_two_rows` `cowswap_display.rs:430-453` (shows `addr[0..7]` and
  `addr[14..20]`, hides `addr[7..14]`).
- **Vulnerability class:** identifier (address) truncation; defense-in-depth gap.
- **Attacker & required capability:** companion sets a non-zero attacker
  `receiver` in a pre-signed CoW order.
- **Exploitation path:** order proceeds route to `receiver`; the device shows only
  13 of 20 bytes with no name-DB resolution, vs the ERC-20 transfer recipient
  which uses the full 40-hex `write_addr_full_or_name`.
- **Invariant / property broken:** WYSIWYS margin for a fund-destination address;
  project full-display bar.
- **Falsification attempt.** 13 visible bytes = 104 bits → an attacker receiver
  that visually matches a user-expected address needs a 2^104 vanity grind →
  infeasible; the user can still detect a wrong receiver from the visible bytes.
  Page-layout constraint (label + footer leave only 2 rows). LOW, defense-in-depth.
- **Suggested fix:** dedicate a full 3-row address page to `receiver` and route it
  through `write_addr_full_or_name`.
- **Confidence:** confirmed (mechanism); not a practical drain.

### [LOW-6] typed-call dynamic `bytes`/`string` shows only a 5-byte SHA-256 fingerprint of the payload

- **Location:** `secure/src/tx/display/typed_call/mod.rs:622-648`
  (`write_bytes_or_string_rows`, `sha:` row = first 3 + last 2 bytes of the
  digest).
- **Vulnerability class:** opaque-payload fingerprint truncation.
- **Falsification / why LOW:** the full payload is SHA-256'd, `len` is shown
  independently, non-printable `bytes` shows `(binary)`, and an attacker must
  brute-force a 5-byte (≈2^40) SHA-256 collision *and* match `len* to alias two
  payloads — and the user is already on an unverified/blind banner. Defense-in-
  depth; consider widening to 4+4 bytes (≈2^64).
- **Confidence:** confirmed; not a practical drain.

### [INFO-7] Non-fund observations (not WYSIWYS breaks)

- **personal_sign ERC-8213 fingerprint not reproducible off-device**
  (`cmd_sign_offchain.rs:705-707`): the page shows `calldata_digest(payload) =
  keccak256(uint256(len)||payload)`, which is neither the EIP-191 personal-sign
  hash a dapp shows nor the actually-signed nested hash. The *message text* is the
  real WYSIWYS surface and is shown in full, so not a break; the fingerprint is a
  non-actionable anchor. (raw32 and EIP-712 paths fingerprint the right value.)
- **confirm-from-page-0** (`ui/confirm.rs`): a long-right long-press confirms from
  any page, so a hurried user can approve a 700-byte SIWE message without scrolling
  trailing pages. Device-wide UX property; the message is fully paginated, so not a
  display-truncation break.
- **CoW direct-flow zero `receiver`** renders as bare `0x000…000` with no
  "(= your wallet)" label (the Safe-wrapped flow labels it "(= the Safe)"). Zero
  receiver = proceeds to owner = safe; cosmetic clarity only.
- **typed-call double native-value page**: typed_call emits its own `! VALUE:`
  page *and* the dispatcher splices `! NATIVE ETH` — value shown twice (safe
  redundancy), wastes one page-budget slot.

## Enumeration ledger — the full set this surface owns

### Renderers (each signed structure → its renderer)

| Renderer | Signed structure rendered | Verdict |
|---|---|---|
| `value_transfer.rs` | plain ETH transfer (to,value,gas,nonce,chain) | discharged — all fields full, overflow-loud |
| `erc20_known.rs` | ERC-20 transfer/transferFrom/approve + verified meta | discharged — fixed-width amount, full from/recipient/contract |
| `erc20_unknown.rs` (top-level) | ERC-20 shape, no meta | discharged — **full decimal** amount, overflow-loud |
| `blind_sign.rs` | opaque calldata | discharged — full value, selector, len, SHA-256, gas, nonce |
| `typed_call/*` | ABI-decoded args | **MEDIUM-3** (bytesN≥16); LOW-6 (bytes/string); rest discharged |
| `erc7730/*` | descriptor fields / EIP-712 members | **MEDIUM-2** (date), **MEDIUM-4** (visible:never); rest discharged |
| `safe_display.rs` (approveHash/exec) | SafeTx struct + inner | **HIGH-1** (unverified amount); refund/value/op discharged |
| `multi_send.rs` + `append_multisend_pages` | per-record SafeTx batch | HIGH-1 inherited; page-count lockstep discharged |
| `safe_mgmt.rs`/`mgmt_decode.rs` | owner/module/guard/threshold ops | discharged — strict len + canonical addr/threshold, all params shown |
| `cowswap_display.rs` | GPv2Order (12 fields) | **LOW-5** (receiver); all 12 fields reach a page |
| `eip1271.rs` + `cmd_sign_offchain.rs` | personal_sign/raw32/eip712 | discharged (INFO-7 fingerprint note); full message pagination |
| `erc8213.rs` | the 32-byte fingerprint | discharged — full 32 bytes, 4 rows |
| `batch.rs` | per-tx banner wrap | discharged — fail-closed `Err` on budget |
| `slot_rotation.rs` | rotation consent (slot index) | discharged — affirmative-consent page |
| `value_page.rs` | native ETH value + gas splice | discharged — FI-hardened skip, fail-closed |

### Signed SafeTx fields (`exec_decode.rs` / `SAFE_OFF_*`) → page

| Field | Signed | Reaches a page | Note |
|---|---|---|---|
| to | yes | yes | inner-tx pages (full addr) |
| value | yes | yes | "Safe sends ETH" / PlainEth (full ETH) |
| data | yes | yes | classified inner (HIGH-1 affects unverified ERC-20 amount) |
| operation | yes | yes | "Op: Call/MultiSend/! DELEGATE" |
| safeTxGas | yes | (gas limit) | bounded; not separately drawn — minor |
| baseGas | yes | yes | refund page B `(CEILING+baseGas)*gasPrice` |
| gasPrice | yes | yes | refund page B magnitude |
| gasToken | yes | yes | refund page A (short addr; grind-bound) |
| refundReceiver | yes | yes | refund page C (full addr / "tx.origin") |
| nonce | yes | yes (approveHash) | "SafeTx Nonce" / "(execute now)" for exec |

### Signed GPv2Order fields (`cowswap/mod.rs`) → page

sellToken, buyToken, receiver(**LOW-5**), sellAmount, buyAmount, validTo,
appData(13/32 hex — info), feeAmount, kind, partiallyFillable, sellTokenBalance,
buyTokenBalance — **all 12 reach a page** (verified field table from sub-audit;
digest binds every slot; receiver truncation is the only residual).

### Row primitives audited

`write_eth_two_rows`, `write_token_amount_two_rows`, `write_cow_leg_amount`,
`format_decimal`, `format_u64` → full/overflow-loud (discharged). `write_addr_full`,
`write_addr_full_or_name` → full 40-hex (discharged). **Truncating helpers:**
`write_raw_uint_two_rows` (HIGH-1), `write_bytesn_rows` N≥16 (MEDIUM-3),
`write_addr_two_rows` (LOW-5), `write_bytes_or_string_rows` sha (LOW-6),
`read_u64_be_tail` (MEDIUM-2), `write_short_addr` (gas_token / dividers — paired
with a full-address page elsewhere or a summary row → discharged).

## Surfaces examined and judged clean (with the reason each is safe)

- **Dispatcher native-value gate** (`value_page.rs:63-89`): FI-hardened skip
  (sentinel-gated `value.is_zero`), fail-closed on full buffer; applied uniformly
  after every renderer. Closes the resolved hidden-native-value class.
- **Dispatcher gas-fee splice** (`value_page.rs:109-131`): inserts "Max fee" +
  "Worst-case" for exactly the Safe/CoW/v1 renderers that lack inline gas;
  `needs_gas` mirrors branch precedence so no double-render. Closes the
  previously-open Safe/CoW gas-fee class.
- **Safe gas-refund magnitude** (`safe_display.rs:480-557`): page B now shows
  `(GAS_USED_CEILING + baseGas) * gasPrice` at full token magnitude with `!HUGE`
  / `!AMOUNT OVERFLOW` loud fallbacks — closes the previously-OPEN baseGas-magnitude
  gap; the worst-case total has neither the floor-reads-0 nor the rate-rounds-to-0
  flaw.
- **multiSend gate ↔ render page-count lockstep** (`multi_send.rs:455-504` vs
  `safe_display.rs:1134-1205`): identical `classify_record_kind` +
  `record_content_pages` + `record_needs_value_page`; `multisend_sign_gate`
  refuses (not truncates) on budget overflow; transferFrom `From (debited)` +1 page
  mirrored both sides; host tests pin it. A record cannot be silently dropped.
- **Safe-mgmt decode** (`mgmt_decode.rs`): strict per-selector length, canonical
  address-word + ≤u16 threshold gates, every parameter (owner/module/guard/handler/
  threshold/prev-pointer) reaches a page; page_count matches the renderer.
- **typed-call ABI walker** (`typed_call/abi.rs`): two-pass canonical-packing
  enforcement (offset==tail_cursor, top-28-zero, len≤MAX, tail_cursor==body.len),
  tuples/nested/dynamic-element types decline to blind-sign; uint/int full-decimal;
  arrays count>1 decline. Offsets cannot point the rendered value at bytes the EVM
  reads differently.
- **CoW digest binding** (`cowswap/mod.rs`, `verify.rs`): all 12 struct slots in
  canonical typehash order; chain bound via domain sep; per-leg ERC-20 decimals
  Merkle-verified + address-cross-checked (no token/decimals spoof); amounts use
  full-decimal `write_cow_leg_amount` (no scale-multiply aliasing). feeAmount
  full-magnitude (resolved). Direct vs Safe-wrapped share `append_order_body_pages`.
- **EIP-1271 off-chain** (`eip1271.rs`, `cmd_sign_offchain.rs`): personal_sign
  paginates every byte (`ceil(len/48)`, 700-byte max within MAX_PAGES), non-
  printable → visible `?`, sign-length == display-length (same `payload` slice);
  raw32/eip712 nest on-device (resolved UserOp-forgery class); EIP-712 selects by
  full 32-byte primary_type_hash + exact head-length, fails closed.
- **Selector/name resolution** (`cmd_sign_userop.rs:904-937`, `:1036-1048`):
  curated bundle Merkle-verified; self-attest `keccak(text)[..4]==selector`; both
  cross-check `meta.selector == inner_data[..4]`; names Merkle-verified, mismatch →
  silent drop to safe 40-hex. A malicious call cannot render as a benign known one.
- **erc8213 fingerprint, batch wrap, slot_rotation**: full 32-byte hash; batch
  banner fail-closed `Err`; rotation is an explicit extra consent page.

## Self-review — counterexamples I went hunting for

- **HIGH-1: "the full-decimal top-level path proves the Safe path also shows it."**
  I went looking for a shared amount helper. There isn't one — `safe_display.rs`
  has its *own* `write_raw_uint_two_rows`, and the `meta=None` arm calls it. The
  inconsistency is real, not a misread.
- **HIGH-1: "metadata is mandatory so the token is always verified."** I traced the
  erc20 trailer: it is read via `read_optional_u16_prefixed` (len 0 ⇒ absent) and
  `verified_meta` becomes `None`. Withholding it is legal and forces the truncated
  path — the precondition collapses.
- **MEDIUM-2: "maybe read_u64_be_tail checks the high bytes."** It does not — the
  doc comment itself states the truncation; no caller guards it for date/duration.
- **MEDIUM-3 / LOW-5: "maybe these are clean drains, not grind-bound."** I worked
  the substitution model: for an identifier the attacker must collide the *visible*
  bytes (104 bits) to alias a user-expected value → infeasible. So I down-ranked
  both from the sub-audit's framing — the dangerous case is the *numeric* one
  (HIGH-1/MEDIUM-2) where no collision is needed.
- **multiSend: "the gate under-counts and clamps a record off-screen."** I diffed
  `records_pages_total` vs `append_multisend_pages` per kind — they share the
  classifier and counts; the `total_pages = min(.., MAX_PAGES)` clamp never fires
  for multiSend because the gate already proved `fixed+inner+reserved ≤ MAX_PAGES`.
  No silent drop.
- **Native value: "could a renderer fill MAX_PAGES and drop the value page?"** The
  gate fails closed (`Err(())` → refuse to sign), and the handler maps it to
  "Sign refused / value unshown". No silent drop.

## Open questions / items needing on-hardware confirmation

1. **HIGH-1 severity call (CRITICAL vs HIGH):** does the lead consider the
   "unverified"/`...`-elided presentation a sufficient mitigation to hold at HIGH,
   or is a companion-forced magnitude-hiding drain of any token CRITICAL? My fix
   recommendation is identical either way.
2. **MEDIUM-2 fund-impact:** confirm whether an unbounded `validBefore`/`validAfter`
   on a `ReceiveWithAuthorization` enables a meaningful replay/timing abuse beyond
   the already-authorized (value, to) — i.e. whether the timing extension is itself
   monetizable.
3. **MEDIUM-4 liveness:** is `opensea-wyvern.json` (and any other corpus descriptor
   that marks effect-bearing fields `visible:"never"`) still a signing surface PQ1
   ships/encourages? If retired, drop it from the root.
4. **MEDIUM-3 reachability:** confirm the curated selector DB actually ships entries
   with top-level `bytes32` args (sub-audit counted ~237) and that the typed-call
   path is enabled in the shipping build.
