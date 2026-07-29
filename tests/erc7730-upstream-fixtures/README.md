# ERC-7730 upstream positive fixtures (test only)

This directory is a byte-for-byte test-only import of the `*.tests.json`
files from `ethereum/clear-signing-erc7730-registry` commit
`784c87c925e8438e7b4736b2af85a501f8d2a265`.

- Corpus: 272 files / 687,949 bytes / 510 positive cases.
- Format inventory: 502 unique fixture-targeted source/format pairs against
  871 accepted PQ1 source/format pairs; 306 intersect, 565 accepted formats
  currently lack an upstream fixture, and 196 fixture targets remain outside
  the accepted catalogue.
- Receipt domain: `pqsigner/erc7730-excluded-fixture-corpus-v1`.
- Receipt SHA-256:
  `689a0904b10841fbd5d9ead4a6b8e049f04a5146eac88b6d8f2faa565abd685f`.
- Source layout is preserved as `registry/<project>/tests/*.tests.json`.

These bytes are deliberately outside `secure/data/erc7730-registry` and are
never compiled into the descriptor catalogue, Merkle root, known-call Bloom,
or firmware. The dbgen integration test independently pins that isolation and
the exact corpus receipt.

`expectedTexts` are Ledger presentation snapshots, not portable PQ1 golden
pages. The test lane preserves every raw string and inventories the known
projection hazards (Ledger-owned envelope fields, line-wrapped addresses and
numbers, unresolved `???` tickers, `... More` truncation, empty expectations,
and non-paired sequences). A positive fixture proves only that a cited example
can be decoded and projected; it is not evidence that malformed inputs cannot
downgrade or that untested descriptor formats are safe.

The semantic lane currently exercises seven Merkle-verified PQ1 transcripts:
an unsigned Type-2 Lido claim, a signed Type-2 Threshold stake, an unsigned
EIP-155 legacy Lido transfer, a flat-static Tally/UNI EIP-712 delegation, a
SmartCredit loan request (`address`, `uint256`, `bytes32`, and `uint64`), a
PoolTogether ballot (`uint256` and `bool`), and a Tally Bravo ballot
(`uint256` and `uint8`). Corpus-derived mutations additionally pin proof and
deployment binding, static and sole-dynamic offset/tail framing, exact EIP-712
member counts, zero/maximum-word rendering, and refusal of every unsupported
EIP-2718 type byte before selector projection while preserving Type-2, legacy
RLP, and the one enrolled bare-calldata fixture. Every presentation waiver is
exact, case-owned, and consumed while walking the expected tokens in order;
address waivers are also class-pinned and matched at their field position. The
long P2P string and the WETH `deposit()` fixture with trailing calldata remain
explicit PQ1 refusals.

## Bounded v2 validation subset

The separate `registry-v2/` tree is a byte-for-byte, test-only import of seven
`testsv2` files from `ethereum/clear-signing-erc7730-registry` commit
`3ddfbc02502cbea327ee852bc581fb769f8cf373` (tree
`014579d1f7917a42fcd683ce1b922d728f35b1a7`).

- Subset: 7 files / 22,579 bytes / 21 cases.
- Receipt domain:
  `pqsigner/erc7730-upstream-v2-validation-subset-v1`.
- Receipt SHA-256:
  `9fe717b33e3b40c1c5175ac10107a645acde2dbb6b2e7923ff4e9402f549a750`.
- The receipt uses the existing excluded-fixture convention: hash the domain,
  the big-endian `u64` file count, then each lexicographically sorted path
  relative to this directory as big-endian `u32` path length + path bytes +
  big-endian `u64` file length + the file SHA-256.
- Exact imported paths and file SHA-256s:
  - `registry-v2/flyingtulip/testsv2/eip712-SessionManager-FT.tests.json`:
    `d85ea2ce1135dc7dfe7b3389bac3e298a35515ca21b8defe59676d0915cf5fba`
  - `registry-v2/flyingtulip/testsv2/eip712-SessionManager-ftUSD.tests.json`:
    `5e8bddc530f0617a4b5c3343ab74ef0c3b03ab3c9c05f14359c3f667df63b116`
  - `registry-v2/lido/testsv2/calldata-WithdrawalQueueERC721.tests.json`:
    `44894c0063f797a5b8ad3dcf410cad3191e35ff0ff1141d47fcba3f4ee8ff231`
  - `registry-v2/lido/testsv2/calldata-stETH.tests.json`:
    `0f477ecd8b5eace96b264887eee02c79071d0ea4874e6c75f9ec27c8565890b2`
  - `registry-v2/lido/testsv2/calldata-wstETH.tests.json`:
    `85712d33446db0f6ac1b16c1215ec2731dd575934aba83d9fbfe6577dfae29f9`
  - `registry-v2/lombard/testsv2/eip712-network-fee-authorization-mainnet.tests.json`:
    `43f8267b1804af15dd114772fe0a2d294324188c8281c3199ef8a40623220f03`
  - `registry-v2/lombard/testsv2/eip712-network-fee-authorization-sepolia.tests.json`:
    `1ffa565c0d694bbe09fdbacafa115131f2946d8bfce06b0d6707e0d6532c2dfc`

The signed `rawTx` and EIP-712 `data` values are untrusted validation vectors,
not catalogue, deployment, metadata, or signing authority. `dataProvider`
entries are offline test inputs only. Upstream structured `expected`
presentation is a comparison reference, not a PQ1 display oracle: the
authenticated PQ1 descriptor, curation, and fail-closed renderer remain
authoritative, including where PQ1 deliberately presents stricter semantics.
An imported positive for a tuple PQ1 does not admit remains a refusal vector.

This bounded subset does not replace or modify the legacy 272-file corpus
above. Its commit, byte count, receipt domain, and
`689a0904b10841fbd5d9ead4a6b8e049f04a5146eac88b6d8f2faa565abd685f`
receipt remain unchanged.

Refreshes of the legacy corpus must update its upstream SHA and receipt in the
same review as the vendored descriptor baseline. The bounded v2 subset may
advance independently as test-only validation input, but its commit/tree,
paths, hashes, receipt, and executable semantic expectations must move
together. Do not hand-edit imported fixture JSON.
