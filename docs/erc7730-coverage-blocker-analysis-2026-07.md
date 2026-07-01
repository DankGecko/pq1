# ERC-7730 coverage: honest blocker analysis + build recommendation (2026-07)

**Question:** is the on-device ERC-7730 renderer a subpar architecture, and what should we
build to "support as many protocols as possible per the Ethereum clear-signing registry"?

**Method:** classified every function in all **94** strictly-skipped registry descriptors
(377 functions) by its *full* ABI-decoder blocker set — the load-bearing rule being that a
function is only "unlocked" when **every** visible field resolves, so mixed-blocker swaps
don't inflate the estimate. (Workflow: `erc7730-coverage-blocker-histogram`, 9 agents reading
the real JSON.)

## The honest diagnosis (I was right to be suspicious, wrong about the cause)

The current renderer resolves a field by summing path indices into the **static head** of the
calldata, plus one bolt-on sole-dynamic-array walker. That is a real ceiling: `send(string text)`,
`mint(bytes)`, `approveAndCall(…, bytes extraData)` are declined **solely** because the value
lives in the calldata tail, not because they're unreviewable. The architecture is the limit, not
the shapes' complexity. My earlier "each shape is a bespoke walker / not human-reviewable / 100%
isn't the goal" was partly a rationalization of a limited resolver.

**But my earlier table was wrong about what walls off the swaps.** It said "29 multi-arg swaps —
tuples + multiple dynamic args." The data says the DEX hot path is walled off by **byte/index
SLICES** (`dex.[-20:]`, `path.[0:20]`, `goodUntil.[-4:]`), a capability I hadn't even named.

## The histogram (net-new functions a general resolver unlocks)

Capability tiers on top of today's resolver (C0):

| Tier | What it adds | Net-new fns | Difficulty | Unlocks |
|---|---|---|---|---|
| **C0 (today)** | static-head scalars + sole-dynamic-array | — (165 of these skipped fns already render) | — | Aave lending, Safe owner-mgmt, QuickSwap liquidity, Lombard ERC-20, most celo |
| **C1** | one dynamic `bytes`/`string`, follow one offset to the tail | **+26** | low (array-walker-level) | celo register/setName, sei delegate/withdraw, threshold receiveTbtc/approveAndCall, p2p send |
| **C2** | descend one **tuple** level (inline-static or dynamic-offset) | **+41** | medium | **Morpho Blue (6), 1inch `swap` (4), Uniswap single-hop, paraswap simpleSwap family (13), threshold BTC-bridge (8)** |
| **C3** | 2+ dynamic args (whole-head decode) | **+18** | medium-high | kiln batch-deposit, lido claimWithdrawals, sei validator ops, consensus DepositContract |

Cumulative renderable calldata: C1→191, C1+C2→232, C1+C2+C3→250 (of 341 classifiable). **Cite the
net-new (+26 / +67 / +85), not 250** — 165 already render at C0, so 250 is a ~3× inflation.

**C2 (tuple-nav) is the single highest-leverage capability** — +41 functions and where the
real-intent DeFi lives (Morpho, 1inch `swap`, Uniswap, threshold).

## What stays declined even after a full C1+C2+C3 resolver (127 fns)

| Bucket | Count | Note |
|---|---|---|
| **HARD-slice** | **53** | Byte-range / negative-index. **The DEX aggregator hot path** — 1inch unoswap/clipper/fill (V4/5/6), Uniswap V3 packed-path, QuickSwap/paraswap `path.[-1]`. A separate, higher-risk slicing engine. **This is where swap *volume* is.** |
| HARD-nested-calldata | 25 | Recursive inner-CALL. **Safe `execTransaction`/`setup` (12) already render via the native S-world Safe verifier** → a generic decoder mostly duplicates. Net-new generic-only ≈ 13 (SafeProxyFactory, multicall/reenter, BatchExecutor). |
| HARD-array-of-tuple | 12 (+1) | Per-element offset table. paraswap megaSwap/multiSwap, flare RewardManager+propose, kiln/figment batch `bytes[]`. |
| EIP-712 typed-data | 28 | **Separate render path**, not the calldata decoder. **Safe SafeTx (6) + CoW already native.** Genuinely-uncovered ≈ 24 (UniswapX ×4, Permit2 ×3, Lens, rarible, opensea). |
| PARSER | 1 | p2p `updateStateAndDeposit` — near-free fix (skip an all-hidden dynamic-tuple arg). |
| OTHER | 8 | 6 file-not-found snapshot artifacts + 1 duplicate (`V6-zksync`) + 1 `string[]`. Drop from denominators. |

Flagship reality check: 1inch **`swap` = C2 (reachable)**; paraswap **`simpleBuy` = C2**;
paraswap **`megaSwap` = HARD** (nested array-of-tuple + negative index); 1inch **`clipperSwap` is
version-split** — V4-eth already works (C0), V5/V6 are HARD-slice. `unoswap` likewise: V3 works,
V4/5/6 are HARD-slice.

## Recommendation

1. **Don't rewrite — grow the resolver incrementally.** The C0 baseline is a secure foundation
   (48% of even the *skipped* descriptors render today, plus the 776 already compiled). Each new
   capability is its own adversarial-review + Kani-bounded landing, everything unhandled keeps
   declining-to-blind. This is the array-walker discipline, repeated — **net-new security-critical
   code each time, not a cheap "reuse `walk`"** (the codebase's `walk` explicitly declines tuples).

2. **Priority order (by leverage ÷ risk):**
   - **C1 (dyn bytes/string, +26)** — cheapest, de-risks the general approach. Do first.
   - **C2 (tuple-nav, +41)** — the main event: Morpho, 1inch `swap`, Uniswap single-hop, threshold.
   - **Array-walker relaxation** (read the first of N arrays) — cheap sub-win (lido claimWithdrawals).
   - **Slices (53)** — a *separate, deliberate* decision. Highest real-world swap volume, but a
     distinct higher-risk byte-extraction engine. Evaluate on its own merits, not bundled with C1/C2.
   - **C3 (multi-dynamic, +18)** — lowest-value increment (batch/governance plumbing).

3. **Deliberately DON'T build (mostly duplicative):** generic nested-calldata + generic EIP-712 —
   the native Safe/CoW S-world verifiers already cover the high-value cases.

4. **Attestation is the orthogonal, arguably bigger, security lever:** we render in dev-mode
   (`allow_unattested`), trusting registry *content* without cryptographically enforcing ERC-8176
   attestations. Flipping that gate is "trusted-and-attested," independent of render coverage.
   **Status (2026-07):** the flip is blocked on the attestation *ecosystem* (near-zero real EAS
   attestations), not on our code — our ERC-8176 `descriptorHash` binding + an EAS-coverage tripwire
   (`make erc8176-coverage`) are landed and cross-validated. See
   [`erc8176-attestation-status.md`](./erc8176-attestation-status.md).

**Caveats:** these tiers are a static path-shape read; a C0 function can still be blocked at render
by ERC20_DB_ROOT (tokenAmount) / ENS (addressName) / MAX_FORMATS / page-budget — orthogonal gaps.

## Landed since this analysis (2026-07-01)

- **C1** (dynamic `bytes`/`string`, FollowOffset resolver), **C2** (flat dynamic-tuple members), **C3**
  (multi-dynamic args + relaxed multi-array). Corpus 776→806, then mhaas's `visible:"never"` WYSIWYS
  gate trimmed hidden-address descriptors (→706).
- **Nested field-GROUP flattening** (`feat(erc7730): flatten nested field-GROUPS`, 7325e9f0). Morpho
  Blue's `marketParams` nested-group descriptor now clear-signs — the C2 "tuple-nav" leverage the table
  above scored for Morpho. Pure dbgen parser feature; the combined member paths ride the existing
  width-aware compiler + gates. Corpus 706→708 (+2, Morpho mainnet+Base only). The other 9 nested-group
  registry descriptors (paraswap/uniswap/flare) correctly stay declined (dynamic tuples / arrays-of-
  tuples / EIP-712 — the gates reject them). Morpho's **static** `marketParams` was the only one whose
  members live at fixed head slots; the dynamic-tuple / array-of-tuple nested groups remain in HARD-*.

## Decision: the HARD-slice engine (the 53-function DEX hot path) — DEFER, with a specified safe subset

**Decision (2026-07-01): do NOT build a general byte-slice engine now.** It is the highest-risk
capability in the whole coverage frontier and its high-value cases are structurally the *most*
dangerous. The 53 functions stay declined-to-loud-blind-sign (the honest raw target/selector ladder),
which is a safe, non-misleading UX — not a silent gap.

**What the registry actually slices** (every slice path in the vendored corpus, by shape):

| Shape | Registry witnesses | Source length | Risk |
|---|---|---|---|
| Negative index `[-1]` | `pools.[-1]` (16) | **runtime** (dynamic array) | last-element depends on an attacker-influenceable count word |
| Negative-open `[-n:]` | `to.[-20:]`, `dex/dex2/dex3.[-20:]` (12+), `goodUntil.[-4:]`, `mintRecipient/destinationCaller.[-20:]` | **runtime** (dynamic `bytes`) | "last n bytes" is relative to a length word the descriptor cannot bound |
| Fixed positive `[a:b]` into **dynamic** bytes | `hookData.[32:52]`, `hookData.[52:53]`, `takerTraits.[:1]`, `#.data.[:1]` | **runtime** | reads protocol-internal offsets inside an un-ABI-framed blob; no framing to bound-check |
| Fixed/neg slice of a **fixed-length** source (`bytesN`, static-tuple member) | *(rare; e.g. a `bytes32`-packed flag+addr)* | **compile-time** | normalizable to an absolute positive range at build time |

**Why the high-value cases are the risky ones.** The DEX swap volume lives in the packed-path slices —
`dex.[-20:]` (extract the pool/token address packed into the low bytes of a **dynamic** `bytes` leg) and
`hookData.[32:52]` (a field at a protocol-chosen offset inside an un-delimited blob). Both read a
**runtime-length** source: the extraction position (`len - 20`) or the validity of a fixed offset
(`52 ≤ len`) depends on the ABI length word, which the companion controls. Worse, showing one slice
**hides the rest of the source** — the same array-tail-hiding / slot-confusion WYSIWYS hazard the
walker fix (`docs/security/VULN-erc7730-walker-slot-confusion.md`) closed for whole words. A slice
engine without a *byte-coverage completeness* proof (every byte of the sliced source shown or provably
inert) would reintroduce exactly that class: "show `[32:52]`, blind-sign `[0:32]` and `[53:]`."

**The one bounded-safe subset** (a specification for whenever this is picked up, NOT a green light):

> A slice `[a:b]` (or a negative slice normalized to positive at build time) is admissible **only** when
> its source has a **compile-time-fixed length** — a static head word `bytesN` (N ≤ 32) or a
> fixed-width static-tuple member — so the build can (1) resolve the slice to an **absolute** byte range
> `[a', b')` with `0 ≤ a' < b' ≤ N` checked at compile time, and (2) enforce a **byte-coverage
> completeness lint**: every byte `[0, N)` of the source is either surfaced by some visible slice or
> explicitly declared inert (mirroring the tuple-member completeness lint). The device then reads a
> deterministic, in-bounds byte range of a head word it already bounds — no length word in the trust
> path, no hidden tail. It ships as its own increment with its own adversarial-review + Kani-bounded
> landing (the array-walker discipline), and **excludes every runtime-length source** — dynamic
> `bytes` / `T[]`, negative index `[-1]`, and the DEX packed-path — from the near-term build.

**Honest leverage of that subset:** LOW. Almost every registry slice is on a *dynamic* source
(packed `bytes` paths, `pools.[-1]` on a dynamic array), so the fixed-length-source subset unlocks few
of the 53 while the DEX volume stays out. That asymmetry — low-value-safe vs high-value-dangerous — is
precisely why the general engine is deferred rather than incrementally grown: unlike C1/C2, there is no
cheap, safe first slice that de-risks the dangerous ones. Revisit only with a dedicated
adversarial-review + Kani campaign scoped to the runtime-length packed-path threat model.
