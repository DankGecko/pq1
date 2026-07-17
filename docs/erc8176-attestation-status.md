# ERC-8176 attestation — status, mechanism, and flip-readiness (2026-07)

**Question this answers:** can we flip the ERC-7730 descriptor corpus from
"trusted content" (dev mode) to "trusted **and attested**" — `allow_unattested_dev_descriptors = false`?

**Short answer: not yet — blocked on both our missing production verifier and
the attestation ecosystem.** The ERC-8176 standard is live but adoption is ~zero
(3 total attestations on the canonical EAS schema, all from a single test
address; **0** of our descriptors attested). We have the hash binding and an
advisory coverage tripwire, but no authenticated offline EAS snapshot verifier
or production ingestion path. Neither code nor ecosystem gate is complete.

## What ERC-8176 actually is (verified against the spec, 2026-07)

Part of the Ethereum Foundation's May-2026 Clear Signing standard (ERC-7730
descriptors + neutral registry + **ERC-8176 auditor attestations** + ERC-8213
fingerprints). Mechanism — from the draft ([ethereum/ERCs PR #1576](https://github.com/ethereum/ERCs/pull/1576)):

- Attestations live on the **Ethereum Attestation Service (EAS)** — mainnet
  schema UID **`0xe023eef113c1670774801c34b377fdf612dd8a4d2fa92fe382e15bd91fafb5c2`**
  ([easscan #377](https://easscan.org/schema/view/0xe023eef113c1670774801c34b377fdf612dd8a4d2fa92fe382e15bd91fafb5c2)),
  a single field `bytes32 descriptorHash`. On-chain (`attest()`) or offchain
  (EIP-712 signed EAS v2 blobs).
- **`descriptorHash = keccak256(RFC-8785 JCS(fully-resolved descriptor))`** —
  includes merged first, then JCS-canonicalized, then keccak (the EVM variant).
- Attestations are a **separate document type**; descriptors are unchanged (there
  is *no* `integrity` field embedded in the descriptor — a secondary source got
  that wrong; the spec is explicit).
- Auditors self-register permissionlessly (`auditors/eip155-1-0xAddr/profile.json`);
  wallets pick which attesters to trust (ENS-resolved). Verify = standard EAS
  validation + `descriptorHash` equality + not-revoked + not-expired.

Contrast with our internal `descriptor_hash`: that is **SHA-256**(JCS(descriptor)),
the on-device IR/leaf identifier baked into the firmware-pinned Merkle tree
(SHA-256 per the PQ-stack convention). The ERC-8176 hash is **keccak-256** of the
*same* JCS bytes — EVM-mandated, host-only, never computed on the device.

## What we built (pre-production foundations)

- **`erc8176_hash` in `dbgen`** = `keccak256(jcs_canonicalize(resolved descriptor))`,
  reusing the existing RFC-8785 canonicalizer. Emitted into every row of
  `secure/data/erc7730.review.txt` (`erc8176_hash=0x…`) so an auditor can look
  each descriptor up on EAS. **Cross-validated byte-exact** against an independent
  implementation (foundry `cast keccak` over a python RFC-8785 canonicalization):
  `ledgerquest/eip712-ledgerquest` → `0x16a312e2…acad…` from both. Golden-vector
  unit test `erc8176_hash_golden_vectors`. The firmware-pinned root is **unchanged**
  — `erc8176_hash` is review-only metadata, not in the leaf.
- **Coverage checker** `tools/erc8176_eas_coverage.py` (`make erc8176-coverage`):
  reads the review-file hashes, queries EAS schema #377, reports how many of our
  descriptors meet the policy's distinct-attester threshold against an advisory
  `--trusted <auditor addrs>` list. It reports per-descriptor shortfalls and can
  never authorize a production flip: the command-line trust set and live query
  are not the required authenticated, reproducible offline policy input. curl +
  stdlib only; read-only. The deterministic offline regression target is
  `make erc8176-coverage-test` and is enrolled in CI.
- The legacy `enforce_policy` gate (embedded-`attestations`-array, identity-only)
  is documented as an **outdated model** that predates the finalized EAS-based
  spec; it stays behind `allow_unattested_dev_descriptors`. It is not the real
  enforcement path — the checker + a future EAS snapshot are.

## Current coverage (420-leaf catalogue snapshot, measured 2026-07)

`make erc8176-coverage` (the live result distinguishes all returned records
from the eligible, unrevoked, unexpired subset used for threshold arithmetic):

```
our descriptors (unique descriptorHashes): 224   (→ 420 firmware leaves)
total attestations returned by EAS:        3
eligible (unrevoked and unexpired):        2
OUR descriptors with ANY attestation:      0
```

The 3 EAS attestations are all from one address (`0xBf01daF4…77253`, not a known
auditor); two carry ASCII test junk as the "hash", one a real-looking hash that
matches **none** of our descriptors. The upstream registry `auditors/` directory
holds only a README — **zero** registered auditors, **zero** `sigs/` files. The
ecosystem has not populated (~2 months post-launch).

## Flip-readiness: the precise unblock condition

Flip `allow_unattested_dev_descriptors = false` only after both the missing code
and external evidence exist. To assess a candidate advisory trust set, run
`python3 tools/erc8176_eas_coverage.py --trusted <0xADDR> [<0xADDR> ...]`;
that live report is an ecosystem tripwire, not authorization.
Concretely, the external half requires:

1. Auditors we trust (Ledger / Fireblocks / Sourcify / Cyfrin) actually publish
   EAS attestations under schema #377 for the descriptors we ship.
2. Their real attester addresses populate `policy.toml`'s `trusted_attesters`
   (currently placeholders).

The code half must authenticate and snapshot those trusted attestations so the
build stays reproducible/offline, require `≥ min_attesters` distinct trusted
attestations per shipped descriptorHash, and bind the resulting policy and
provenance into the release artifact. Below-threshold descriptors are excluded;
corresponding filter-positive calls retain the current hard refusal rather than
silently falling to ordinary blind signing.

**Until then:** run `make erc8176-coverage` periodically (it's the tripwire); stay
in dev mode. Flipping now would remove clear-sign coverage for the entire
420-leaf corpus, while filter-positive calls would hard-refuse, for zero
security gain because there is nothing to verify against.

## Why this is the honest posture

For a *shape* attacker (a descriptor that hides fields), the structural WYSIWYS
gates (rule 1/2, dup-name, EIP-712 nested-struct) are the defense. For a *content*
attacker (a descriptor that lies about what a function does), attestation by a
party who checked the descriptor against the real contract is the defense — and
that is exactly ERC-8176. We cannot manufacture that trust unilaterally; a
self-signed curation key in the repo would be a no-op (an attacker who owns CI
owns the key). So we make our binding provably-correct, instrument coverage, and
implement the authenticated verifier before any future flip when the ecosystem
provides real attestations to enforce.
