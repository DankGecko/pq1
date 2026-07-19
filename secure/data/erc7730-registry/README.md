# Vendored ERC-7730 registry security corpus

**Upstream baseline:** vendored from
[`ethereum/clear-signing-erc7730-registry`](https://github.com/ethereum/clear-signing-erc7730-registry).
The exact commit/tree and curation-manifest identity are machine-owned by the
managed receipt below; they are not duplicated in hand-maintained prose. The
checked-in corpus is **not byte-identical to that upstream revision**: the
firmware-pinned `ERC7730_DESCRIPTORS_ROOT` is derived from the upstream baseline
plus the 17 reviewed full-file replacements listed below, under
`secure/data/erc7730/policy.toml`. The strict manifest at
`secure/data/erc7730/curations/manifest.json` binds the upstream repository,
commit, tree, v2 schema, pristine/excluded/curated corpus receipts, policy,
selected tool inputs, and every replacement's exact before/after bytes and
SHA-256.

This tree is the complete security-relevant JSON corpus (`registry/**/*.json`
plus `ercs/**/*.json`, excluding validated upstream test fixtures), not merely the
descriptors that compile into render leaves. Rejected, broken, and
nonstandard-named descriptors are retained because their parsable
`(chain_id, contract, selector)` declarations feed the firmware-pinned
known-call omission filter. Dropping such a dead-only project can leave the
Merkle root unchanged while incorrectly restoring blind signing.

Refresh the upstream baseline with:

```bash
cargo run --locked -p pqsigner-xtask -- vendor-registry \
  --registry-root /path/to/clear-signing-erc7730-registry
```

The command refuses any origin/HEAD/tree/schema/corpus mismatch or relevant
dirty upstream input, copies the pristine baseline to staging, applies only the
manifest's full-file replacements, and installs only after the curated corpus
receipt and unchanged known-call tuple set/Bloom are proven. There is no manual
"reapply the patch" step. `gen-erc7730-descriptors --check` independently
rejects local manifest, replacement, policy, selected tool-input, or checked-in
curated-corpus drift. The complete ceremony and review requirements live in
[`docs/erc7730-root-rotation-and-update-policy.md`](../../../docs/erc7730-root-rotation-and-update-policy.md).
The final curated build must reproduce the compiled blob, Merkle root, leaf
count, provenance, stable review/skip receipt, known-call count, canonical
tuple-set SHA-256, and Bloom bytes. Merkle-root or Bloom equality alone is not
accepted as a faithfulness proof.

<!-- BEGIN XTASK-VERIFIED ERC7730 REGISTRY RECEIPT -->
Checked-in curated receipt, verified against a fresh build by `--check`: **430 leaves**, **354,095-byte**
compiled companion catalogue, root
`6b4f243d3f60f15fb64555d91861f702f852bdb400087a716627ece9dd4e1978`,
**4,542** canonical known-call tuples, tuple-set SHA-256
`96ea46d23d2f321a81030b77a61a243a003c1ceb6d0dca8df32ba838bcc0c88b`.
Curation manifest SHA-256
`eb49d548e57e49640b1a3caf7330964f4c7ccb8ba09418e504cb4165dc8c9a73` binds upstream commit
`784c87c925e8438e7b4736b2af85a501f8d2a265` and tree
`8da8dba78c3e581bbd06c15cc681d07e570dcfb1`.
The Bloom contains 28,235 / 131,072 set bits, below the generator's 25% cap.
<!-- END XTASK-VERIFIED ERC7730 REGISTRY RECEIPT -->

The `.pqsigner-erc7730-vendor` file is an exact machine-owned directory
sentinel only. It deliberately carries no upstream SHA or generated receipt;
the machine-checked source/overlay identities live in the curation manifest,
while the generated catalogue authority remains in the artifacts and managed
receipt above.

Current reviewed full-file replacements (17):

- `registry/aave/calldata-WrappedTokenGatewayV3.json`
- `registry/aave/calldata-lpv2.json`
- `registry/aave/calldata-lpv3.json`
- `registry/flyingtulip/eip712-PftMarketplace-BuyOffer.json`
- `registry/lido/calldata-stETH.json`
- `registry/lido/calldata-wstETH-referral-staker.json`
- `registry/p2p/calldata-P2pOrgUnlimitedEthDepositor.json`
- `registry/p2p/calldata-P2pSsvProxyFactory.json`
- `registry/threshold/calldata-L1BitcoinDepositor-address.json`
- `registry/threshold/calldata-L1BitcoinDepositor-bytes32.json`
- `registry/threshold/calldata-L2BitcoinDepositor.json`
- `registry/uniswap/calldata-UniswapV3Router02.json`
- `registry/uniswap/eip712-UniswapX-DutchOrder.json`
- `registry/uniswap/eip712-UniswapX-ExclusiveDutchOrder.json`
- `registry/uniswap/eip712-UniswapX-LimitOrder.json`
- `registry/uniswap/eip712-uniswap-V2DutchOrder.json`
- `registry/uniswap/eip712-uniswap-permit2.json`

Do not make ad-hoc edits outside that reviewed curation set. Adding, removing,
or changing a curation requires the same review and root-rotation ceremony.

Layout mirrors the registry (`registry/<project>/…` + `ercs/…`) so the
descriptors' `includes` (`../../ercs/…` and bare sibling `common-*.json`)
resolve unchanged.

Notes:
- `*.tests.json` and `tests/` fixture dirs are excluded from trusted rendering
  and the copied corpus only after the vendor command parses every fixture,
  rejects `includes`, any deployment declaration, or a fully-specified
  domain-only EIP-712 `(chainId, verifyingContract)` binding, and emits a
  deterministic excluded-inventory receipt. For upstream commit
  `784c87c9…a265`, that receipt
  is **272 files / 687,949 bytes / SHA-256
  `689a0904b10841fbd5d9ead4a6b8e049f04a5146eac88b6d8f2faa565abd685f`**
  under domain `pqsigner/erc7730-excluded-fixture-corpus-v1`. Fixture naming is
  never permission to hide a live binding.
- This corpus is currently `dev-unattested`. There is no implemented ERC-8176
  host verifier; production fails closed until one emits reviewed
  `erc8176-verified` provenance.
- A registry-declared contract call that the renderer cannot decode is kept in
  the known-call filter and hard-refuses without a safe compiled proof. Only a
  genuinely absent tuple may reach the generic display ladder (subject to safe
  Bloom false positives).
