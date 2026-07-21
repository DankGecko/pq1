# ERC-7730 upstream positive fixtures (test only)

This directory is a byte-for-byte test-only import of the `*.tests.json`
files from `ethereum/clear-signing-erc7730-registry` commit
`784c87c925e8438e7b4736b2af85a501f8d2a265`.

- Corpus: 272 files / 687,949 bytes / 510 positive cases.
- Format inventory: 502 unique fixture-targeted source/format pairs against
  870 accepted PQ1 source/format pairs; 305 intersect, 565 accepted formats
  currently lack an upstream fixture, and 197 fixture targets remain outside
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

Refreshes must update the upstream SHA and fixture receipt in the same review
as the vendored descriptor baseline. Do not hand-edit imported fixture JSON.
