# ERC-7730 tokenPath byte-slice / array-index resolver — WYSIWYS safety model (Tier B, 2026-07-01)

> **2026-07-10 tightening:** this document records the original Tier-B
> rationale. Current production accepts a tokenPath extraction only inside the
> single exact canonical C1 whole tail proven by the format-wide calldata
> preflight; C2/multi-tail layouts are excluded. Resolution/framing failure for
> a verified or registry-declared known call hard-refuses signing — it does not
> degrade to raw amount or blind-sign. The compiler still forbids extraction
> ops in rendered value paths.

## The asymmetry that makes this safe (read this first)

A `tokenAmount` renders `value × 10^-decimals  symbol`, where `decimals`/`symbol`
come from resolving the field's **`tokenPath`** to a 20-byte token address and
looking it up in the firmware-pinned `ERC20_DB_ROOT`.

Some DEX descriptors put the token address **packed inside a dynamic leg** rather
than in a plain `address` argument:

| Path | Function | Where the token lives |
|---|---|---|
| `params.path.[0:20]` | Uniswap V3 `exactInput` | first 20 bytes of the packed `bytes path` (input token) |
| `params.path.[-20:]` | Uniswap V3 `exactInput`/`exactOutput` | last 20 bytes of the packed path (output token) |
| `path.[0]` | Uniswap V2 `swapExactTokensForTokens` | first element of `address[] path` |
| `path.[-1]` | Uniswap V2 `swapTokensForExactTokens` | last element of `address[] path` |

Tier B teaches the resolver to follow those four extraction shapes. **The load-
bearing safety property is that these ops are accepted ONLY as a `tokenPath` —
never as a rendered value.** The reason is an asymmetry in the blast radius of a
wrong extraction:

- **tokenPath failure ⇒ mis-*identify* an amount.** The recipient, the selector,
  and "a swap is happening" are all still correct (they are separate, statically-
  resolved fields). A failed extraction returns `Err` → the amount degrades to the
  **raw integer + `! raw, dec=?`** footer (audit M-4), *never* a scaled magnitude
  with an assumed decimals, and the extracted address (when shown at all) appears
  only on a loud **`Token (UNVERIFIED)`** page (MEDIUM-1) — an advisory, explicitly-
  unverified identity, never a value the user is asked to trust. A tokenPath cannot
  move funds; it only labels an amount.
- **rendered-value-slice failure ⇒ wrong displayed *address*.** paraswap's
  `pools.[-1]` (a shown pool address) or `beneficiaryAndApproveFlag.[-20:]` (a shown
  beneficiary) rendered from a slice would show a wrong *recipient* = direct theft.

So slices are split down the middle: the identification half (tokenPath) is safe
and enabled; the value half (rendered `path`) stays declined-to-loud-blind-sign.

## The invariant and where it is enforced (both sides)

> A byte-slice (`[a:b]` / `[-N:]`) or array-index (`[i]` / `[-1]`) extraction op may
> appear **only** as the terminal op of a `tokenPath`. It is refused in any rendered
> value `path`.

- **Compile side (`dbgen::erc7730`).** `compile_path` (value paths) → `compile_path_inner(is_token_path=false)`;
  `compile_token_path` (only the `tokenAmount` `tokenPath` call site) → `is_token_path=true`.
  Only the `true` branch of `compile_structured_contract_path` reaches
  `compile_token_path_extraction`, which emits the extraction op. A value path with a
  slice hits the names-loop `_ => reject` and fails to compile → the whole format
  drops to loud blind-sign. Unit tests: `token_path_slice_ops_are_tokenpath_only`,
  `token_path_slice_width_and_type_guards`, `token_path_slice_emits_terminal_extraction_op`.
- **Device side (`pqsigner-erc7730::render::resolve`).** The value-path resolver
  `resolve_structured` rejects `ArrayIdx`/`ArraySlice`/`ArrayLast` (`_ => Reject`).
  Only `resolve_token_address` (reached solely from the `tokenPath` branch of
  `formatters::resolve_token_address`) accepts them, splitting the nav prefix (run
  through the same hardened `resolve_structured`) from the single terminal op.

## Runtime fail-safety (the calldata is adversarial, the program is not)

The path program is Merkle-pinned in the attested IR — it is trusted. The **calldata
body** (offset/length/count words + data) is companion-controlled. Every extraction
read is bounds-checked against the **actual body buffer** (`read_dynamic`,
`read_length_word`, `.get()`, `checked_*`), so a crafted length/count word can only
shrink coverage or force the raw fallback — never read out of bounds or panic:

- byte slice requires **exactly 20 bytes** (an address); `[-20:]` needs `len ≥ 20`;
- array element requires `idx < count` AND the element's 32 bytes inside the body;
- any failure returns `Err`, which `render_token_amount` degrades to the raw-integer
  `! raw, dec=?` page (M-4). No mis-scale, no wrong address.

**Kani** proves panic-/OOB-/overflow-freedom over a fully-symbolic 128-byte body for
each of the three real program shapes (`tok_bytes_slice_panic_free`,
`tok_array_index_panic_free`, `tok_array_last_panic_free`, all VERIFICATION:
SUCCESSFUL). **Host render tests** drive real ABI-encoded multi-hop calldata and
assert each leg's token symbol *and* magnitude against ground truth, with a decoy-
token non-vacuity check (`uniswap_exact_input_binds_{input,output}_token_*`,
`uniswap_v2_swap_binds_first_and_last_array_element`,
`uniswap_slice_binding_is_non_vacuous_decoy_token`).

## Body routing

A `tokenAmount` whose `tokenPath` descends a `FollowOffset` (dynamic tuple / `bytes` /
`address[]`) resolves in the calldata tail, so the field is rendered against the FULL
body even when its own amount path is static-head (e.g. `swapExactTokensForTokens`:
static `amountIn`, dynamic `path.[0]`). `formatters::token_path_needs_full_body`
parses the tokenPath ops (not a raw byte scan — a `FieldIdx` slot byte can equal the
`FollowOffset` opcode) and the `mod.rs` field dispatch ORs it into the full-body
decision.

## What stays declined (correct)

paraswap AugustusSwapper `pools.[-1]` / `beneficiaryAndApproveFlag.[-20:]` (rendered
address values), paraswap `#.data.[292:324]` (32-byte word slice, not a 20-byte
address), and 1inch `goodUntil.[-4:]` (a rendered 4-byte timestamp) all stay
declined — the value-path reject and the 20-byte-address width guard both refuse them.

## Coverage impact

Corpus root `5c9a64db → 8d65b027` (leaf count unchanged at 784 — the swap functions
are new *formats* on already-present contract leaves). Uniswap V3 Router IR
`446 → 811` bytes (multi-hop `exactInput`/`exactOutput` + V2 `swap*ForTokens` now
clear-sign the token identities), QuickSwap `450 → 1088`. 1inch/flyingtulip stay
partially blocked by orthogonal gates (rendered `goodUntil` slice / dynamic-tuple
formats). See `docs/erc7730-coverage-blocker-analysis-2026-07.md` for the full
re-grounding (the earlier "DEX bucket has no clean capability / Uniswap is niche"
call was wrong).

## Curation caveat

Tier A (the sibling change that unlocked the single-hop `exactInputSingle`/
`exactOutputSingle` by hiding the redundant `sqrtPriceLimitX96` price bound) edits the
**vendored** `secure/data/erc7730-registry/.../calldata-UniswapV3Router02.json`. A
future `xtask vendor-registry` re-copy drops that edit — re-apply the two
`{ "path": "params.sqrtPriceLimitX96", … "visible": "never" }` fields.
