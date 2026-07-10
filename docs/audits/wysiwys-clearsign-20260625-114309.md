# audit:wysiwys — Security Audit (20260625-114309)

Auditor: adversarial WYSIWYS pass over the trusted-display clear-signing stack.
Scope tag: `docs/audits/wysiwys-clearsign-20260625-114309.md`.

## Scope & threat model

The promise under audit: **every byte the device commits to with a SPHINCS+C10
signature was faithfully decoded and shown on the trusted OLED, and nothing
shown differs from what is signed.** Two failure directions:

* **signed-but-not-shown** — a field inside the signed digest that never reaches
  a confirmation page.
* **shown-but-not-signed** — a page whose value is formatted unequal to (or
  spoofable relative to) the signed bytes.

Threat model: the non-secure world and the USB companion are fully
attacker-controlled and send maximally hostile input. The ERC-7730 descriptor
corpus, ERC-20/names/selectors DBs, and the Merkle roots baked into the firmware
image are **vendor-controlled** (a `compile_error!`-fenced, Merkle-pinned TCB);
the companion cannot inject a new descriptor or DB entry — it can only choose
*which* pinned artifact to present and *whether* to present an optional trailer.
Findings that depend on a corpus artifact are scoped accordingly (build-time /
process gaps, not pure-companion CRITICALs).

In scope: every renderer in `secure/src/tx/display/*`, the ERC-7730 IR/walker/
formatters, the EIP-712 CoW + Safe verifiers, the typed-call ABI decoder, the
`pick_sign_pages` dispatcher + value/gas splices, and the two sign handlers
(`cmd_sign_userop`, `cmd_sign_userop_batch`) plus the off-chain handler
(`cmd_sign_offchain`) as the producers of the signed digest.

## Methodology — what you read and how you hunted

I established the **signed set** from the digest producers first
(`aa/src/userop.rs::compute_sphincs_digest_v06`, the EIP-712 `struct_hash`
builders, the off-chain final-hash builders), then traced forward to the
renderers and enumerated, field by field, whether each signed word reaches a
page. I read in full, myself: `display/mod.rs` (`pick_sign_pages` +
`pick_sign_pages_inner`), `value_page.rs`, `safe_display.rs` (1413 lines),
`safe_mgmt.rs`, `eip712/safe/{verify,mod,exec_decode,multi_send,cow_binding,
mgmt_decode}.rs`, `aa/src/userop.rs`, `cmd_sign_userop.rs` (1846 lines),
`cmd_sign_userop_batch.rs` (1496 lines), `cmd_sign_offchain.rs` (EIP-712 path),
`display/erc8213.rs`, `display/erc7730/mod.rs`, `display/erc7730/formatters.rs`
(token-amount path), and `dbgen/src/erc7730.rs` (the completeness-lint gate).

Four parallel sub-audits covered breadth (each told the resolved-findings list
to hunt **un-fixed siblings**, not rehash): typed-call ABI decoder + renderer;
ERC-7730 formatters/walker/visibility/completeness; CoW verify + display
(12-field enumeration); ERC-20 / EIP-1271 / blind / batch / primitive
formatters + Merkle-bundle binding. I independently re-derived and re-verified
every claim I rate at MEDIUM or above against the source (the line citations
below are my own reads, not the sub-agents').

Differential analysis: single-tx vs batch handler check-for-check; approveHash
vs execTransaction Safe paths; contract vs EIP-712 ERC-7730 paths; blind-sign vs
typed-call fall-through.

## Findings (ordered by severity, most severe first)

---

### [HIGH-1] ERC-7730 EIP-712 typed-data path has no field-completeness lint — a signed typed-data member can be omitted from the display

> **RESOLVED 2026-06-25.** Added `check_eip712_field_completeness` to
> `dbgen/src/erc7730.rs` and called it for the `CTX_EIP712` branch of
> `compile_one_format` (mirrors the contract-path H-3 lint): every top-level
> typed-data member must be covered by a rendered field, a `visible:"never"`
> field, or another field's `tokenPath`, else the build refuses to pin the
> descriptor. Both shipped EIP-712 descriptors (`circle-usdc-{rwa,twa}`) still
> compile (`erc7730: in sync`). Regression guards:
> `eip712_completeness_{rejects_omitted_member,accepts_full_coverage,accepts_tokenpath_coverage}`.

- **Location:**
  - dbgen gate: `dbgen/src/erc7730.rs:1004-1006` — `check_contract_field_completeness` is called **only** `if context_kind == CTX_CONTRACT`. No EIP-712 analogue exists.
  - on-device render: `secure/src/tx/display/erc7730/mod.rs:285-306` (`render_fields` iterates **only** `format.fields()`, with no "every static head word is covered by a visible field" check).
  - exact-length gate that makes the omitted words *signed*: `secure/src/tx/display/erc7730/mod.rs:248-253`.
  - off-chain EIP-712 entry: `secure/src/nsc/cmd_sign_offchain.rs:392-497` → `render_erc7730_eip712_pages`.
- **Vulnerability class:** signed-but-not-shown (completeness gap). The **un-fixed
  EIP-712 sibling** of the resolved contract-path finding
  `[[project_erc7730_tuple_member_completeness_gap]]` (H-3). The H-3 lint was
  added to the contract path only; the typed-data path was left uncovered. Memory
  flags this exact gap as OPEN; this finding supplies the concrete code + trigger.
- **Attacker & required capability:** a malicious USB companion, **given that an
  incomplete EIP-712 descriptor exists in the firmware-pinned corpus.** The
  companion cannot inject the descriptor (Merkle root is in the image), but the
  missing lint means an honest vendor developer can ship one without any tool
  catching it — exactly as a real shipped *contract* descriptor (uniswap) once
  omitted `sqrtPriceLimitX96`, which is what motivated the H-3 lint in the first
  place. No physical access; no FI.
- **Minimal trigger — the exact thing an attacker sends:** Suppose a future
  Permit2-style EIP-712 descriptor is added to the corpus with format key
  (= the EIP-712 `encodeType`):
  `PermitTransferFrom(address token,address spender,uint256 amount,uint256 nonce,uint256 deadline)`
  and a fields list that renders only `token` and `amount` (omitting `spender`,
  `nonce`, `deadline`). dbgen computes `static_head_words = 5` from the type's
  member count and accepts it (no EIP-712 completeness check). The companion then
  sends `CMD_SIGN_OFFCHAIN` with `kind = OFFCHAIN_KIND_EIP712_TYPED`,
  `domain_separator` = the real Permit2 domain, `primary_type_hash` =
  `keccak256(<the format key above>)`, and `encoded_data` = the 160-byte (5×32)
  ABI encoding `token‖spender=ATTACKER‖amount‖nonce‖deadline`, plus the pinned
  descriptor trailer.
- **Exploitation path (numbered, concrete):**
  1. `cmd_sign_offchain` verifies the descriptor against `ERC7730_DESCRIPTORS_ROOT`
     and runs `cross_check_eip712(ir, chain_id, domain_separator)` — both pass
     (the descriptor is genuinely the corpus's Permit2 descriptor for this
     domain). (`cmd_sign_offchain.rs:434-468`)
  2. The renderer locates the format by the **full 32-byte** `primary_type_hash`
     (constant-time, `mod.rs:207-216`) — passes, because the companion supplied
     the honest typehash for the 5-member type.
  3. The exact-length gate requires `encoded_data.len() == static_head_words*32 ==
     160` (`mod.rs:248-253`) — passes. **All five members are therefore folded
     into the signed `structHash = keccak256(primary_type_hash ‖ encoded_data)`.**
  4. `render_fields` walks only the two declared fields (`token`@word0,
     `amount`@word2) and paints two pages. **Words 1 (`spender = ATTACKER`), 3
     (`nonce`), 4 (`deadline`) reach no page.** (`mod.rs:294-306`)
  5. The user confirms "approve `<token>` for `<amount>`" and the firmware signs
     the EIP-712 final hash that authorises the attacker as `spender`. For a
     Permit/Permit2 flow the attacker now drains `token` up to `amount`.
- **Invariant / security property broken:** WYSIWYS — the device signs a typed
  message whose most security-relevant member (`spender`, the approval target) is
  never shown. CLAUDE.md "trusted-display clear-signing … no blind-sign path for
  known shapes."
- **Evidence (quoted):**
  ```rust
  // dbgen/src/erc7730.rs:1004
  if context_kind == CTX_CONTRACT {
      check_contract_field_completeness(sig, fmt, &parsed)?;
  }                                  // <-- EIP-712 (CTX_EIP712) gets no check
  ```
  ```rust
  // secure/src/tx/display/erc7730/mod.rs:294  (render_fields — no coverage check)
  for field_result in format.fields() {
      let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
      ... match should_render_with_mode(..) { Action::Render => dispatch(..)?, .. }
  }
  ```
  ```rust
  // mod.rs:251  (exact-length gate => omitted members ARE signed)
  if encoded_data.len() != head_len { return Err(RenderErr::Reject("7730 ed len")); }
  ```
- **Falsification attempt — what I tried to use to disprove it, and why it fails:**
  1. *"The exact-length gate (`mod.rs:251`) already closes signed-but-not-shown."*
     No. It forces `encoded_data` to be exactly `static_head_words*32`, blocking the
     *append-trailing-words* variant (the thing it was written for, 2026-06-11). It
     does **not** require every word to be covered by a *rendered field*. Omitting a
     declared member leaves `static_head_words` at the true type arity (it is
     derived from the encodeType, not the field list), so the omitted words are
     in-range, signed, and simply never walked.
  2. *"Under-declare `static_head_words` to match the 2 rendered fields."* Self-
     defeating: a 2-word `encoded_data` produces a different `structHash` than the
     real 5-member Permit, so no honest verifier would accept the resulting
     signature — the attack must use the honest arity and omit *fields*.
  3. *"The companion can't forge a descriptor."* Correct — and that is exactly why
     this is HIGH (latent, build-time) rather than CRITICAL. The two **currently
     shipped** EIP-712 descriptors (`circle-usdc-rwa.json`, `circle-usdc-twa.json`)
     are complete (all 6 members of their authorization structs are covered), so
     there is **no live exploit today**. The defect is the **absent safety net**:
     the mechanical guard that protects the contract path is missing for the
     typed-data path, which is precisely where Permit/Permit2/approval drains live.
- **Suggested fix (describe only):** add an EIP-712 analogue of
  `check_contract_field_completeness` to `compile_one_format` (drop the
  `CTX_CONTRACT` guard, or branch): for an EIP-712 format, require that every one
  of the `static_head_words` top-level members is covered by a rendered field, a
  `visible:"never"` (effect-bearing allowlist), or a tokenPath/token field — the
  same rule the contract path enforces (each EIP-712 member is one word, so the
  check is simpler than the contract tuple case). Belt-and-braces: add an
  on-device coverage assertion in `render_erc7730_eip712_pages_inner` (the set of
  field head-slots must equal `{0..static_head_words}` minus an explicit
  never-list) so a corpus mistake fails closed to the raw32 fingerprint instead of
  under-rendering.
- **Confidence:** confirmed (code paths verified directly; the only conditional is
  the corpus precondition, which is the point of the finding).

---

### [MEDIUM-1] ERC-7730 `tokenPath`-only coverage hides the token *identity* when the optional ERC-20 metadata trailer is withheld

> **RESOLVED 2026-06-25.** `render_token_amount`
> (`secure/src/tx/display/erc7730/formatters.rs`) now threads the
> `NameResolver` and, in the unbound (`bound == None`) case, emits an extra
> "Token (UNVERIFIED)" page rendering the resolved `tokenPath`/`token` address
> full-40-hex (resolver-aware) so the token identity is never omitted when the
> companion withholds the ERC-20 metadata trailer. Page-budget overflow fails
> closed to blind-sign. The bound case is unchanged (the symbol already names
> the token).

- **Location:**
  - renderer: `secure/src/tx/display/erc7730/formatters.rs:287-365` —
    `render_token_amount`. The token address is resolved (`:306
    resolve_token_address`) but used **only** to look up decimals/symbol
    (`:311-316`); the `None` arm (`:348-362`) writes the raw amount and never
    writes `token_addr` to any page.
  - lint: a `tokenPath` reference counts as covering a top-level param in
    `check_contract_field_completeness` (so a param with no field of its own still
    passes), per the sub-audit (`dbgen/src/erc7730.rs` completeness helper).
  - metadata is an **optional** trailer: `secure/src/nsc/cmd_sign_userop.rs:691`
    (`verified_meta = Some(..)` only `if erc20.len > 0`).
- **Vulnerability class:** signed-but-not-shown (token identity). Companion-
  triggerable on **shipped** descriptors (e.g. `aave-v3-pool.json
  withdraw(address asset, uint256 amount, address to)` where `asset` is covered
  only as the amount field's `tokenPath`; `uniswap-v3-router.json`
  `tokenIn`/`tokenOut`).
- **Attacker & required capability:** malicious companion; no physical access. The
  companion simply omits the ERC-20 metadata trailer for a tx whose pinned
  descriptor covers the token param only via `tokenPath`.
- **Minimal trigger:** `CMD_SIGN_USEROP` for an Aave `withdraw(asset, amount, to)`
  (or Uniswap `exactInputSingle`) UserOp, with the `aave-v3-pool` / `uniswap`
  descriptor trailer present but the ERC-20 bundle trailer **absent** (length 0 at
  the erc20 slot).
- **Exploitation path:**
  1. `verified_meta = None` (no erc20 trailer; `cmd_sign_userop.rs:691`).
  2. `render_token_amount` resolves `token_addr` from the signed calldata's
     `asset`/`tokenIn` word but, with `erc20 = None`, hits the `None` arm.
     (`formatters.rs:311-316, 348-362`)
  3. The page shows the **raw integer amount** with a loud `! raw, dec=?` footer
     and the recipient `to` on its own page — but **never the token address**.
  4. The user confirms a withdraw/swap without seeing *which* token is moved; the
     signed calldata commits to the attacker/dapp-chosen token.
- **Invariant / security property broken:** WYSIWYS — a signed operand (the token
  contract) is not represented on any page.
- **Evidence (quoted):**
  ```rust
  // formatters.rs:306    token_addr resolved...
  let token_addr = resolve_token_address(ir, body, tx, params).ok();
  // formatters.rs:311    ...but only ever used to pick decimals/symbol
  let bound = match (token_addr, erc20) {
      (Some(addr), Some(meta)) if addr == meta.contract => Some((u32::from(meta.decimals), meta.symbol)),
      _ => None };
  // formatters.rs:348    None arm: raw amount only, token address never written
  None => { let fit = write_amount_two_rows(r1, r2, &value, 0, 0, false, ""); ... }
  ```
- **Falsification attempt:**
  1. *"Metadata is mandatory, so `None` never happens."* No — it is an optional
     trailer the companion withholds at will (`cmd_sign_userop.rs:691`,
     `verified_meta = if erc20.len > 0`).
  2. *"The address shows on another page."* It does not; `render_token_amount`
     emits exactly one page (the amount) and no other unconditional address page
     exists for a tokenPath-only param.
  3. *"This enables a wrong-token / wrong-symbol display (worse)."* No — the
     `bound` match requires `addr == meta.contract` and `meta` is ERC-20-Merkle-
     verified, so a companion can only show **no** identity, never a *wrong* one.
     That bound, plus the loud `! raw, dec=?` and the shown recipient, is why this
     is MEDIUM with drain **needs-confirmation**, not HIGH: for Aave it is your own
     collateral to a shown recipient; for a Uniswap swap the hidden tokenIn/tokenOut
     is more meaningful but the swap still needs a prior approval and the
     amountOutMinimum is shown raw.
- **Suggested fix:** in `render_token_amount`'s `None` arm, render the resolved
  tokenPath address on its own page (resolver-aware); and/or strengthen the
  completeness lint so a param used *solely* as a `tokenPath` must also be covered
  by an `addressName`/`tokenTicker` field so the identity is shown even when
  metadata is absent.
- **Confidence:** confirmed (renderer path verified directly).

---

### [LOW-1] typed-call dynamic `bytes`/`string` arg shown as a 40-bit per-arg fingerprint instead of declining to blind-sign (parity gap)

> **RESOLVED 2026-06-25.** `write_bytes_or_string_rows`
> (`secure/src/tx/display/typed_call/mod.rs`) now returns `bool` and DECLINES
> (`false`) for any non-empty `bytes`/`string` payload — parity with the
> `bytesN>15` sibling — so `render_arg` bails the whole typed-call decode to
> the loud blind-sign flow (banner + ERC-8213 256-bit calldata fingerprint).
> An empty payload (`len == 0`) still renders. Test
> `positive_typed_call_renders_dynamic_string_arg` was replaced by
> `negative_typed_call_declines_non_empty_dynamic_string_arg` +
> `positive_typed_call_renders_empty_dynamic_string_arg`.

- **Location:** `secure/src/tx/display/typed_call/mod.rs:238-245`
  (`TypeRef::Bytes | TypeRef::String` renders and returns `true`, never declines)
  → `write_bytes_or_string_rows` `:581-643`, whose `sha:` row paints only
  `hash[0..3] ‖ "." ‖ hash[30..32]` = 5 bytes (40 bits) of the SHA-256 of the
  payload. Contrast its **fixed** static sibling `write_bytesn_rows` `:561-572`,
  which **declines** (→ blind-sign) for `bytesN, N>15`.
- **Vulnerability class:** signed-but-weakly-shown / defense-in-depth parity gap.
  The dynamic sibling of the resolved static-`bytesN>=16` decline-to-blind-sign
  fix and of the `[[project_typed_call_array_tail_wysiwys]]` array-tail fix.
- **Attacker & required capability:** malicious companion presenting calldata for
  a curated selector whose top-level arg is `bytes`/`string` (e.g.
  `forward(address,uint256,bytes)`, `execute(address,uint256,bytes)` — both in the
  curated set), where the `bytes` is an executable sub-call.
- **Why this is LOW and not a constructible break (correcting an over-rating):**
  the typed-call success page already carries a **loud** `! BLIND SIGN` /
  `! UNVERIFIED` banner (`mod.rs:102-105`) — the decode never claims contract
  semantics are verified — and, decisively, **every** sign confirm (blind-sign
  *and* typed-call alike) appends the ERC-8213 fingerprint page showing the
  **full 256-bit** `keccak256(uint256(len) ‖ inner_data)`
  (`cmd_sign_userop.rs:1111-1121`; `erc8213.rs:91-114`, all 32 bytes across 4
  rows). That digest covers the entire `bytes` payload, so the cross-checking
  user's collision margin is 256 bits on **both** paths — the per-arg 40-bit
  `sha:` row is redundant defense behind it, **not** the user's only anchor. There
  is therefore no constructible signed≠shown oracle here: it is a *less-rich
  presentation of an already-blind situation*, which is why I rate it LOW /
  defense-in-depth rather than MEDIUM.
- **Invariant / security property:** WYSIWYS completeness consistency (the project's
  own "decline rather than truncate" bar that addresses + static `bytesN` already
  meet).
- **Falsification attempt:** *"Decoding removes the whole-calldata hash anchor and
  drops the margin to 40 bits."* False — the ERC-8213 256-bit page is appended by
  the handler regardless of which renderer ran, so the anchor is present and
  256-bit on the typed-call path too.
- **Suggested fix:** for parity with the static `bytesN` sibling, make
  `write_bytes_or_string_rows` return `false` (decline → loud blind-sign) for any
  non-empty `bytes`/`string` payload; or widen the `sha:` row to 16 bytes.
- **Confidence:** confirmed (the gap exists); **needs-confirmation** that it is
  worth changing given the ERC-8213 backstop.

---

### Informational completeness gaps (signed-but-not-shown, no constructible exploit)

These are signed digest fields with no page. I could not construct an exploit for
any; each is recorded with the reason it does not rise to MEDIUM. They are listed
here (not as numbered findings) to keep the enumeration honest.

* **`SafeTx.safeTxGas`** — signed (EIP-712 struct member #5; decoded into
  `SafeTx.safe_tx_gas` `eip712/safe/mod.rs:101,139-140` and `DecodedExec.safe_tx_gas`
  `exec_decode.rs:48`) but **not threaded into `SafeRenderInput`**
  (`safe_display.rs:144-182, 220-233`) and never rendered. It is a gas limit on the
  *already-displayed* inner call; it cannot redirect funds or change amounts. With
  a refund configured (`gasPrice>0`) the worst-case refund magnitude is already
  bounded by `GAS_USED_CEILING` on refund page B, so a low `safeTxGas` (the classic
  "fail the inner call but still refund" grief) cannot exceed the shown refund.
* **`paymasterAndData`** (companion-supplied `paymaster_and_data_hash`, signed at
  `cmd_sign_userop.rs:1590` / batch `:1289`, never displayed). A paymaster only
  *sponsors* gas, or — for a token paymaster — charges a token the wallet has
  *already approved*, bounded by the worst-case gas cost that the gas pages already
  show in ETH terms. No new drain primitive; not displayable meaningfully.
* **UserOp `nonce` high 192 bits — resolved 2026-07-10.** The low 64-bit v0.6
  sequence remains on the ordinary `Nonce:` row. A non-zero 192-bit nonce key
  now adds one exact `Nonce lane key:` page containing all 48 hex characters on
  every single/batch authorization surface, with an independent FI
  completion/skip proof. Lane zero omits the page. This closes the later-found
  safe-retry/double-execution ambiguity that this snapshot had classified as
  informational.
* **`sender` / `entryPoint`** — signed domain-separator fields, not displayed. A
  wrong value self-invalidates: the real EntryPoint recomputes the hash with its own
  address, and a slot sig is only valid against the wallet that lists that slot key
  as an owner, so a spoofed value yields a signature that validates nowhere.

## Enumeration ledger — the full signed set, each row exploitable or discharged

### UserOp `sphincsDigest` fields (`aa/src/userop.rs:687-707`)

| # | Signed field | Reaches a page? | Verdict |
|---|---|---|---|
| 1 | `sender` | no | discharged — domain sep, self-invalidating (informational) |
| 2 | `nonce` (low 64) | yes — `write_nonce_row` | clean |
| 2b| `nonce` (high 192 key) | conditional exact 48-hex page | fixed 2026-07-10 — non-zero parallel lanes cannot hide behind identical sequence screens |
| 3 | `init_code_digest` | firmware-computed (`cmd_sign_userop.rs:1501`), not raw-shown | clean — CREATE2-constrained to `sender`; deploy path |
| 4 | `call_data_digest` = `executeWithOffchainCount(ownerIndex,count,to,value,data)` | `to`,`value`,`data` shown; `data` also via ERC-8213 256-bit fp | clean |
| 5 | `call_gas_limit` | yes (summed into worst-case) | clean |
| 6 | `verification_gas_limit` | yes (summed) | clean — `cmd_sign_userop.rs:656-659` sums all three |
| 7 | `pre_verification_gas` | yes (summed) | clean |
| 8 | `max_fee_per_gas` | yes (gas pages) | clean |
| 9 | `max_priority_fee_per_gas` | yes (tip row) | clean |
| 10| `paymaster_and_data_digest` | no | discharged — sponsor-only / pre-approved, gas-bounded (info) |
| 11| `entry_point` | no | discharged — domain sep, self-invalidating (info) |
| 12| `chain_id` | yes (chain page) | clean |

`to` and `value` (inner) are not in the ERC-8213 fingerprint (which covers
`inner_data` only) but are shown on dedicated pages (`pick_sign_pages` +
`enforce_native_value_page`, FI-hardened, fail-closed). ✓

### SafeTx EIP-712 struct + domain (`eip712/safe/mod.rs::struct_hash`)

| Field | Shown | Verdict |
|---|---|---|
| `to` | yes (Inner to / Contract) | clean |
| `value` | yes (inner-ETH / PlainEth, FI value splice) | clean |
| `data` (→ `data_hash`) | yes (decoded inner ladder + selector/len/hash) | clean |
| `operation` | yes ("Op:" row, loud `! Op: DELEGATE`) | clean |
| `safeTxGas` | **no** | discharged — gas limit, no fund redirect (info) |
| `baseGas` | yes (folded into refund worst-case page B) | clean |
| `gasPrice` | yes (refund page B magnitude) | clean |
| `gasToken` | yes (refund page A) | clean |
| `refundReceiver` | yes (refund page C) | clean |
| `nonce` | yes (approveHash) / "(execute now)" (exec) | clean |
| domain `chainId` | yes | clean |
| domain `verifyingContract` (Safe addr) | yes (page 1, full) | clean |

multiSend records: per-record `to`/`value`/`data` each reach a page (divider +
value page + classified pages); strict canonical framing (`multi_send.rs`) makes
on-device == on-chain decode; page-budget gate refuses rather than truncates. ✓

### GPv2Order (CoW) — all 12 fields hashed into `struct_hash` AND shown
(`cowswap/mod.rs` ↔ `cowswap_display.rs`; verified field-by-field). `receiver`
full-hex, `sellAmount`/`buyAmount`/`feeAmount` full magnitude overflow-safe,
`partiallyFillable`/`sellTokenBalance`/`buyTokenBalance`/`validTo`/`kind` shown.
`appData` shown as len + head/tail of its 32-byte hash (grind-bounded
identifier, fully hashed) — needs-confirmation, not exploitable. ✓

### ERC-7730 (contract path) / typed-call / ERC-20 / blind / eip1271
See findings HIGH-1 (EIP-712 completeness), MEDIUM-1 (tokenPath identity), LOW-1
(dynamic bytes). All other paths discharged (see "clean" section).

## Surfaces examined and judged clean (with the reason each is safe)

* **Dispatcher value/gas splices** (`value_page.rs`) — `enforce_native_value_page`
  is FI-sentinel-gated on the skip-zero decision and fails **closed** on a full
  buffer; `enforce_gas_pages` splices the two fee pages for the gas-less surfaces
  (Safe/CoW/v1) atomically and fails closed. Both propagate `Err(())` →
  refuse-to-sign in both handlers (`cmd_sign_userop.rs:1098`, batch `:832`).
* **Gas worst-case faithfulness** — `display_gas_limit` sums **all three** signed
  gas fields (`cmd_sign_userop.rs:656-659`, batch `:673-676`); the worst-case page
  is `maxFee × Σgas`, a correct upper bound on the EntryPoint prefund. My initial
  "only callGasLimit shown" hypothesis was wrong.
* **Safe `execTransaction` / `approveHash` / multiSend decoders** — strict
  canonical ABI (address-word zero-pad checks, exact length per selector, offset
  ≥ head, exact padding, per-record `op==0`, record cap) so on-device decode
  cannot differ from on-chain; the multiSend *claim* predicate fires even for a
  malformed blob → **loud refuse**, never a silent blind-sign dressed as benign
  (`multi_send.rs:69-75`, `verify.rs:138-142`).
* **Safe-mgmt renderer** — every owner/threshold/module/guard/handler operand
  shown full; only linked-list `prev` pointers truncated (cannot change the
  on-chain effect, which is fixed by the full-shown operand). `! MULTISIG OFF` /
  `! THRSHLD = 0` / `! ENABLE MODULE` / `! CHANGE GUARD` loud banners.
* **CoW Safe-wrapped binding** (`cow_binding.rs`) — `owner == Safe` enforced; the
  v3 trailer binds to the exact 164-byte presign record (a strict subslice);
  ambiguous/malformed multiSend binds provably-unverifiable bytes with
  `via_safe=true` → "v3 required" refuse. No drift between single & batch.
* **typed-call ABI geometry** — offsets/lengths top-bits-zero-gated, `len > 2^20`
  rejected, non-canonical packing / residual bytes / dropped tail args all
  rejected (whole render bails to blind-sign); arrays decline for `count>1` or any
  non-full element; static `bytesN>15` declines; `uintN` shows the full word with
  loud `!OVERFLOW`.
* **ERC-20 / primitive formatters** — `format_decimal` extracts all 78 digits and
  fails closed to `!AMOUNT OVERFLOW` (never silent high-byte drop); `transferFrom`
  `from` gets its own "From (debited)" page; recipient/spender/contract full
  40-hex; `is_unlimited_amount` only ever *over*-warns.
* **Merkle-bundle binding** — ERC-20/names/selectors leaves bind
  `(chain_id, contract, …)` to the firmware-pinned root and the call site
  cross-checks `meta.chain_id == chain_id && meta.contract == tx.to` (or safe-inner
  / multiSend-record equivalents); `NameResolver` keys on tx-derived
  `(chain_id, address)`. No metadata-for-wrong-contract spoof.
* **Batch handler** — per-inner-tx fresh `tx_for_display`, full `pick_sign_pages`
  (so value/gas splices apply per member), per-tx banner + per-tx ERC-8213
  fingerprint + batch-final keccak fingerprint, all fail-closed; same downgrade
  (CoW v3 / Safe v1) + multiSend gates as single-tx, check-for-check.
* **ERC-7730 contract path** — `head_bounded_body` clamps reads to the static head
  (walker slot-confusion fix intact); nested-calldata stub `Reject`s → loud
  blind-sign; `Date`/`Duration`/`NftName`/`Enum`/`Calldata` reject `>u64` /
  unsupported → loud; `COMPACT_MODE=false` and only affects `Optional`. The
  completeness lint **is** enforced here (`CTX_CONTRACT`).
* **Off-chain EIP-1271** — personal-sign message hard-capped at 700 and **rejected**
  if longer (nothing signed-but-unshown), fully paginated, same bytes hashed;
  raw32 loud `! Raw 32-byte` + full 32 bytes + fingerprint; on-device
  `replaySafeHash` nesting keeps off-chain values disjoint from `sphincsDigest`.

## Self-review — counterexamples I went hunting for and why they failed

* **"The worst-case gas page understates the prefund (only callGasLimit)."** Went
  to `cmd_sign_userop.rs:656-659`: it sums all three signed gas fields. Failed to
  materialise.
* **"The execTransaction decoder lets trailing bytes carry a second meaning."**
  Trailing bytes after the ABI args are signed (in the callData digest) but inert
  on-chain (Solidity ignores them) and do not change the decoded `to/value/data`
  the renderer shows. No divergence.
* **"A malicious paymaster hash hides an unbounded drain."** The charge is bounded
  by the worst-case gas the page already shows and requires a pre-existing token
  approval; a paymaster cannot pull funds the wallet did not already authorise.
* **"typed-call decoding strips the user's 104-bit whole-calldata anchor down to
  40 bits."** The ERC-8213 256-bit fingerprint page is appended by the *handler*
  for every renderer (blind-sign and typed-call alike), so the anchor is present
  and stronger than 104 bits on both. The dynamic-bytes gap is therefore LOW, not
  MEDIUM.
* **"The EIP-712 exact-length gate already closes the typed-data completeness
  gap."** It blocks appended trailing words, not omitted *declared* members; the
  omitted members stay in-range and signed. The gap (HIGH-1) survived.
* **"The tokenPath-only gap lets a wrong symbol render (worse than hidden)."** The
  `addr == meta.contract` + Merkle-verified `meta` bound means only *no* identity,
  never a wrong one — capping it at MEDIUM.

## Open questions / items needing on-hardware confirmation

1. **HIGH-1 process control:** confirm that the descriptor-build CI has no
   *other* EIP-712 completeness check outside `dbgen` (e.g. a JSON-schema linter in
   the host pipeline). I found only the `CTX_CONTRACT`-gated `dbgen` lint; if a
   second guard exists it would downgrade HIGH-1. Recommend treating the fix as a
   ship-blocker for the first non-USDC EIP-712 descriptor regardless.
2. **MEDIUM-1 corpus survey:** enumerate every shipped contract descriptor whose
   token param is covered *only* via `tokenPath` (Aave, Uniswap confirmed by the
   sub-audit) to size the live exposure; decide between the renderer fix (show the
   address) and the lint fix (require a token-identity field).
3. **LOW-1:** product decision on whether to decline-to-blind-sign for dynamic
   `bytes`/`string` (parity) given the ERC-8213 backstop already present.
