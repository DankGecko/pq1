# ERC-8176 attestation — status, mechanism, and flip-readiness (2026-07)

**Question this answers:** can we flip the ERC-7730 descriptor corpus from
"trusted content" (dev mode) to "trusted **and attested**" — `allow_unattested_dev_descriptors = false`?

**Short answer: not yet — blocked on the attestation *ecosystem*, not on our code.**
The ERC-8176 standard is live but adoption is ~zero (3 total attestations on the
canonical EAS schema, all from a single test address; **0** of our descriptors
attested). We have made our side correct-and-ready and instrumented so we know
the day it unblocks. This is the same evidence-driven posture as the HARD-slice
and non-address-hidden-value decisions.

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
  validation + `descriptorHash` equality + not-revoked.

Contrast with our internal `descriptor_hash`: that is **SHA-256**(JCS(descriptor)),
the on-device IR/leaf identifier baked into the firmware-pinned Merkle tree
(SHA-256 per the PQ-stack convention). The ERC-8176 hash is **keccak-256** of the
*same* JCS bytes — EVM-mandated, host-only, never computed on the device.

## What we built (correct-and-ready)

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
  descriptors are attested and by whom, and gives a flip-readiness verdict against
  a `--trusted <auditor addrs>` list. curl + stdlib only; read-only.
- The legacy `enforce_policy` gate (embedded-`attestations`-array, identity-only)
  is documented as an **outdated model** that predates the finalized EAS-based
  spec; it stays behind `allow_unattested_dev_descriptors`. It is not the real
  enforcement path — the checker + a future EAS snapshot are.

## Current coverage (420-leaf catalogue snapshot, measured 2026-07)

`make erc8176-coverage`:

```
our descriptors (unique descriptorHashes): 224   (→ 420 firmware leaves)
total attestations under the EAS schema:   3
OUR descriptors with ANY attestation:      0
```

The 3 EAS attestations are all from one address (`0xBf01daF4…77253`, not a known
auditor); two carry ASCII test junk as the "hash", one a real-looking hash that
matches **none** of our descriptors. The upstream registry `auditors/` directory
holds only a README — **zero** registered auditors, **zero** `sigs/` files. The
ecosystem has not populated (~2 months post-launch).

## Flip-readiness: the precise unblock condition

Flip `allow_unattested_dev_descriptors = false` (and rewrite `enforce_policy` to
the real EAS-snapshot model) **when** `make erc8176-coverage --trusted <Ledger/
Fireblocks/Sourcify/… addrs>` reports acceptable trusted coverage of the corpus.
Concretely, that requires, externally:

1. Auditors we trust (Ledger / Fireblocks / Sourcify / Cyfrin) actually publish
   EAS attestations under schema #377 for the descriptors we ship.
2. Their real attester addresses populate `policy.toml`'s `trusted_attesters`
   (currently placeholders).

Then the production build snapshots the trusted attestations (so the build stays
reproducible/offline), the gate requires `≥ min_attesters` trusted attestations
per shipped descriptorHash, and un-attested descriptors drop to loud blind-sign
(fail-safe) rather than shipping unattested.

**Until then:** run `make erc8176-coverage` periodically (it's the tripwire); stay
in dev mode. Flipping now would drop the entire 420-leaf corpus to blind-sign for
zero security gain, because there is nothing to verify against.

## Why this is the honest posture

For a *shape* attacker (a descriptor that hides fields), the structural WYSIWYS
gates (rule 1/2, dup-name, EIP-712 nested-struct) are the defense. For a *content*
attacker (a descriptor that lies about what a function does), attestation by a
party who checked the descriptor against the real contract is the defense — and
that is exactly ERC-8176. We cannot manufacture that trust unilaterally; a
self-signed curation key in the repo would be a no-op (an attacker who owns CI
owns the key). So we make our binding provably-correct, instrument coverage, and
flip when the ecosystem gives us real attestations to enforce.
