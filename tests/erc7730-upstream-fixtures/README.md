# ERC-7730 upstream positive fixtures (test only)

This directory is a byte-for-byte test-only import of the `*.tests.json`
files from `ethereum/clear-signing-erc7730-registry` commit
`784c87c925e8438e7b4736b2af85a501f8d2a265`.

- Corpus: 272 files / 687,949 bytes / 510 positive cases.
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

Refreshes must update the upstream SHA and fixture receipt in the same review
as the vendored descriptor baseline. Do not hand-edit imported fixture JSON.
