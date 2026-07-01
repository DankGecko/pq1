# VULN — ERC-7730 EIP-712 nested-struct fund-routing address escapes the WYSIWYS build gate

**Severity:** HIGH (WYSIWYS / clear-sign supply-chain), was **latent** (no clean live witness — see §Reachability).
**Class:** display ≠ signed (build-gate incompleteness).
**Status:** **FIXED 2026-07-01** (see §Fix applied). Was the direct EIP-712 sibling of the FIXED
`VULN-erc7730-visible-never-noparam-clearsign` (which closed only the **contract-context** branch).
**Attacker:** correctly-provisioned, locked device + a future auto-vendored / hostile ERC-7730 descriptor
(same supply-chain model as the documented sibling — the corpus is auto-vendored from the upstream Ledger registry).

## Summary

`dbgen::erc7730::check_field_visibility` is the *sole* build-time defense that a Merkle-pinned ERC-7730
descriptor cannot clear-sign a known shape while hiding a fund-routing `address` behind a trusted banner
(rule 2, "No hidden fund-routing address"). It has an **EIP-712-shaped hole**: it never examines an
`address` that lives **inside an EIP-712 struct member** (a nested struct like a UniswapX `witness`, a
Rarible `Asset`, a Permit `PermitDetails`, or any `Order(Meta info, …)Meta(address spender, …)` shape).

Two independent gate branches both operate only at **top-level member granularity**:

1. **Rule 2** (`dbgen/src/erc7730.rs:2028-2089`) descends into tuple members **only when
   `context_kind == CTX_CONTRACT`** (line 2034). For EIP-712 it takes the `None` branch and calls
   `type_contains_address(top_ty)` (line 2072). A nested struct member's type is a **struct NAME**
   (`"ExclusiveDutchOrder"`, `"Asset"`, `"Meta"`), and `type_contains_address` (line 1907) is a
   literal-`address`-token scan — a struct name contains no `address` token → returns `false` → the
   member and every address nested inside it is **not required to be shown**.
2. **Completeness lint** (`check_eip712_field_completeness`, line 1802) only requires each **top-level**
   member to be declared/hidden/tokenPath'd — it never descends into nested members either.

On the device side (`cmd_sign_offchain.rs:485` / `render_erc7730_eip712_pages_inner`), the signed value is
`keccak(0x1901 ‖ domainSep ‖ keccak(primary_type_hash ‖ encoded_data))`. `encoded_data` is the
companion-supplied canonical EIP-712 top-level `encodeData`, in which a nested struct member is a single
opaque `hashStruct` word. The firmware **signs that word without expanding or verifying it** and cannot
render anything inside it. So a nested fund-routing address is simultaneously:

* **committed** to the signature (via the `hashStruct` word folded into `struct_hash`), and
* **un-gated** at build time (neither check looks inside the struct), and
* **un-showable** on device (nested contents are never in `encoded_data`).

### Canonical exploit shape

Descriptor (vendored into the pinned root):

```
Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)
fields: { amount: visible (tokenAmount/raw),  info: visible:"never" }
```

`parse_format_key` keeps only the first paren group (`split_arg_list` → `find_matching_paren`), so
`top_types = ["Meta","uint256"]` and the trailing `Meta(address spender,…)` definition is dropped;
`inner_names["info"]` is empty. Rule 2 sees `type_contains_address("Meta") == false` → passes. Completeness
sees both top members accounted for → passes. Rule 1 passes (`amount` is a shown effect-bearing field).
The all-hidden on-device belt (`mod.rs:309`) does **not** fire because `amount` produces a page.

At sign time a hostile companion sends `OFFCHAIN_KIND_EIP712_TYPED` with
`primary_type_hash = keccak(sig)`, `encoded_data = hashStruct(Meta{spender=ATTACKER,…}) ‖ amount`
(2 words, matches `static_head_words`). The device renders the intent banner + the benign `amount`, skips
`info`, and signs a `struct_hash` that fully commits to `hashStruct(Meta{spender=attacker})`. The user
authorizes a nested approval/route to the attacker having seen only a benign amount.

## Reachability (why it is latent today, and why it is still HIGH)

A locked-device companion can only present descriptors that Merkle-verify against the pinned
`ERC7730_DESCRIPTORS_ROOT`, so exploitation needs a triggering descriptor **in the corpus**. Scanning all
124 shipped EIP-712 descriptors: the ones that *do* carry a nested fund-routing address (UniswapX
`witness.outputs[].recipient` across Exclusive/Dutch/Limit/V2 orders, Permit2, Rarible `makeAsset`) are all
**non-exploitable for a *clean* benign render**, but only by accident:

* Their nested "shown" fields include array paths (`witness.outputs.[]`) that `compile_path` **refuses for
  EIP-712** (`erc7730.rs:2574`) → the whole format is dropped in tolerant mode → blind-sign.
* Other nested "shown" fields (`permitted.amount`, `witness.inputStartAmount`) **mis-resolve**: EIP-712
  paths compile to summed logical ordinals (`compile_path` 2b), and `resolve_structured` reads the wrong
  top-level word (e.g. `permitted.amount` = `FieldIdx(0)+FieldIdx(1)` → word 1 = `spender`), or an
  out-of-range slot → the field declines → the format declines. (Separate correctness bug, see below.)

So the gate hole is **masked by a broken nested-EIP-712 renderer**, not by the gate. This is fragile:

1. It is the **exact defense** the documented `visible:"never"` HIGH established ("stop the *next* corpus
   resync from silently shipping a recipient-hiding descriptor"). That guarantee has a hole for EIP-712
   nested-struct addresses — a future resync of the upstream registry can ship one and the gate blesses it.
2. It becomes a **directly live HIGH** the moment the planned **Phase 5 "deep-types" nested-EIP-712
   rendering** lands (referenced in `calldata_nested.rs` and the EIP-712 renderer comments): once the
   device can render nested top-level-scalar siblings, a descriptor with a shown top-level scalar + a hidden
   nested struct clear-signs benignly while committing to the attacker's nested address — with no broken
   renderer to save it.

Two adversarial verifiers rated it HIGH; one (reachability lens) rated MEDIUM on "no live witness today".
The severity here follows the project's own precedent for the documented sibling (HIGH, arch/supply-chain).

## Fix (recommended)

Make rule 2 + the completeness lint **descend into EIP-712 named-struct members** and require every nested
`address` to be shown (or reviewed-allowlisted), symmetric with the CTX_CONTRACT tuple descent. This needs
`parse_format_key` to also parse the trailing `Struct(...)` definitions of an EIP-712 `encodeType` (today
`split_arg_list` drops them), so the gate can walk `permitted.token` / `witness.…recipient` / `Meta.spender`.
Fail-safe: a refused format drops to blind-sign (tolerant) or hard-errors a hand-authored descriptor.

Belt: an on-device structural check — if an EIP-712 format declares a top-level member whose EIP-712 type is
a struct that is not fully rendered, decline to blind-sign (mirrors the contract-context all-hidden belt but
for the partial-nested case). Do **not** rely on the broken nested renderer as the safety net.

## Fix applied (2026-07-01)

Both the build-gate descent and the on-device belt landed; the primary-type HIGH is closed.

**1. Parse the EIP-712 `encodeType` tail (`dbgen/src/erc7730.rs`).** `ParsedFormatKey` gains a
`struct_defs: BTreeMap<name, [(member, type)]>`. `parse_format_key` now parses everything after the
primary type's argument list (`&rest[args_str.len()..]`) via the new `parse_struct_defs` — so the gate
sees `Meta(address spender,…)` / `PermitDetails(address token,…)` / the forward-referenced UniswapX
structs instead of dropping them. A malformed tail is an error (fail-closed → tolerant-corpus drop /
strict hard-error).

**2. Rule 2 descends (load-bearing).** `check_field_visibility`, for `CTX_EIP712`, routes any top-level
member whose (array-stripped) type is a struct into the new recursive `check_eip712_member_addresses`:
every nested `address` (via `path_matches_member` on a field `path` **or** shown-amount `tokenPath`) must
be shown or reviewed-allowlisted, else the format is refused. Array-of-struct members (elements not
device-addressable) are refused if they transitively reach an address (`struct_reaches_address`).
Bounded by `MAX_STRUCT_DEPTH = 8` + a visited-set; too-deep / cyclic types fail closed. The canonical
`Order(Meta info,…)Meta(address spender,…)` with `info` hidden now errors naming `info.spender`.

**3. On-device belt (`PARAM_NESTED_STRUCT = 0x41`).** `compile_one_format` computes `has_nested_struct`
and parks the marker on the format's first field. `pqsigner-erc7730`'s param parser sets
`ParamSet.nested_struct`; the secure `render_fields` declines the WHOLE format to blind-sign on seeing it
(checked **before** the visibility decision, so a `visible:"never"` nested struct still trips it). This
survives a gate regression and is the hook point for the future Phase-5 faithful nested renderer — the
device never relies on the (broken) nested renderer as the safety net.

**Corpus / root.** Regenerated via `cargo run -p dbgen`: the only catalog change is a `+4`-byte marker on
the already-pinned nested-struct descriptors (Uniswap **Permit2** `PermitSingle`/`PermitTransferFrom`,
**Rarible** exchange-v2 + wrapper — they surface their addresses via `tokenPath`/top-level, so rule 2
refuses none of them). **Zero leaves dropped/added.** New `ERC7730_DESCRIPTORS_ROOT`
`0x52c170dc…2243b9a9` (e2e root unchanged). Those descriptors now honestly blind-sign on device instead
of mis-resolving nested members.

**Tests.** dbgen: struct-def parse (2-level + Permit2 + forward-ref UniswapX), hidden-nested-address
refused (canonical + Permit2 `details.token`), shown / allowlisted / address-free accepted,
array-of-struct refused, marker-on-field[0], `path_matches_member`. Device: marker parse + malformed-
payload reject. Integration: `belt_rejects_eip712_nested_struct_permit2` drives the REAL Permit2 leaf
through `render_erc7730_eip712_pages` and asserts the belt `Reject`. All suites green (dbgen 116,
pqsigner-erc7730 88, secure host 2033, erc7730 roundtrip 10) + drift-check in sync + `thumbv8m`
firmware builds.

**Residual (unchanged).** The related MEDIUM below (dynamic `tokenPath` `FollowOffset` omission in the
device `resolve_path_bytes`) is a separate fail-loud correctness gap and is **not** addressed here.

## Related findings (same audit, 2026-07-01)

* **MEDIUM — dynamic `tokenPath` token-identity omission.** `dbgen` compiles a *dynamic* `tokenPath`
  (`FieldIdx…FollowOffset…`, e.g. 1inch AggregationRouterV4 `swap(…, (…,bytes permit) desc, …)` with
  `tokenPath:"desc.srcToken"` where `desc` is a dynamic tuple), and rule 2 credits it as "showing" the
  token. But the device's `resolve_path_bytes` (`formatters.rs:1567`) is **FieldIdx-only and rejects
  `FollowOffset`** → `token_addr = None` → the sold token's identity is omitted (amount renders raw
  `! raw, dec=?`). Shipped, but fails loud → MEDIUM.
* **LOW/correctness — nested EIP-712 paths mis-resolve.** As above; Permit2/UniswapX clear-signing is
  broken (declines or renders garbage), which is what currently masks the HIGH.
