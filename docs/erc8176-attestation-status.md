# ERC-8176 attestation — status, mechanism, and flip-readiness (2026-08-05)

**Question this answers:** can we flip the ERC-7730 descriptor corpus from
"trusted content" (dev mode) to "trusted **and attested**" — `allow_unattested_dev_descriptors = false`?

**Short answer: not yet — the host verifier code half now exists, but the
attestation ecosystem and production release inputs do not.** ERC-8176 is still
an **open draft** at
[`ethereum/ERCs#1576`](https://github.com/ethereum/ERCs/pull/1576), not a final
standard. The implementation work below pins draft revision
`502c96345b630b66e1dc7d8c790831c7cc2478eb`; that pin is plumbing authority,
not permission to claim final-standard or production provenance. Adoption is ~zero
(3 total attestations on the canonical EAS schema, all from a single test
address; **0** of our descriptors attested). We have the hash binding, advisory
coverage tripwire, and a bounded authenticated offline verifier, but no real
trusted-auditor evidence or approved production snapshot. The canonical
catalogue therefore remains `dev-unattested`.

## What ERC-8176 actually is (verified against the spec, 2026-07)

Proposed as part of the Ethereum clear-signing suite (ERC-7730 descriptors +
neutral registry + **ERC-8176 auditor attestations** + ERC-8213 fingerprints).
Mechanism — from the pinned open draft above:

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

**Forced-blind authority boundary.** ERC-8176 evidence may support admitting a
descriptor into the firmware's accepted clear set `C`; it does not authorize a
runtime signing path or give raw forced-blind pages semantic trust. Forced blind
is not clear signing. Under the default-off candidate, only cleanly absent
metadata for an exact member of the separately authenticated refused-known set
`F = K \ C`, in the enumerated single steady-state Type-2 case, may enter the
separate on-device ceremony. Omission for a tuple in `C` and every present
descriptor validation, binding, or render failure remain fatal. Feature-off and
rollback behavior remain hard refusal, and ERC-8176 production admission plus
the independent configuration, UI/FI, resource, provenance, rollback, and
release gates remain unchanged.

## What we built (host code half; still pre-production)

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
- **Offline verifier** `dbgen::erc8176`: accepts only the bounded, versioned
  `pqsigner-erc8176-eas-snapshot-v1` format and performs no network access. A
  production policy independently pins the exact snapshot SHA-256, Ethereum
  block hash/number/timestamp, reproducible evaluation time, freshness and
  remaining-validity bounds, and canonical mainnet CAIP-10 trust set. Against
  that anchor it verifies the Pectra block header, EAS account/runtime-code
  identity, EIP-1186 account/storage proofs, canonical EAS-v2 UID and EIP-712
  signature, low-s EOA signer, schema, descriptor hash, time, expiry, and zero
  offchain-revocation state. Parsers and proof material are explicitly bounded
  and reject duplicate/unknown fields and unused witnesses.
- **Classical-crypto boundary:** EAS requires secp256k1 recovery, but that is
  external-signature verification rather than wallet signing authority.
  `make classical-crypto-boundary` pins the exact `dbgen -> k256 -> ecdsa`
  packages/features/edges, rejects them from every other normal/build graph,
  and rejects signing or secret-key APIs from the verifier's production
  regions. Cargo-deny retains its global bans for all other classical
  implementations; firmware, FW-update, and wallet contracts remain C10-only.
- **Catalogue admission:** `dbgen` counts distinct trusted signers for the exact
  include-resolved RFC-8785 JCS descriptor hash and retains all deployments only
  when the configured threshold is met. This runs after the complete known-call
  inventory, so a below-threshold descriptor is omitted from the Merkle
  catalogue while its calls remain filter-positive hard refusals. Verified
  review receipts bind the draft revision, policy/snapshot hashes, checkpoint,
  evaluation policy, and admitted counts.
- **Release compatibility is separate from attestation:** the generated `P73S`
  receipt binds the selected root, blob/Bloom identities, provenance class,
  policy and curation inputs, and compiler version into the signed secure-image
  hash. Companion preflight can therefore prove that its catalogue matches one
  authenticated firmware release. Its report is explicitly compatibility-only:
  it cannot set `erc8176_attestation=true`, authorize a production root, or
  compensate for missing auditor evidence. Production-oriented callers may
  pass `--require-erc8176-verified`; `fwsign` then rejects an authenticated
  `dev-unattested` P73S before writing sidecars, and the companion helper
  forwards and independently checks that requirement. This is a provenance
  class gate over signed build output, not a second attestation verifier or a
  production/rollback/shipment grant.
- **Deliberate limitations:** snapshot v1 supports offchain EAS-v2 attestations
  by EOAs only. It rejects contract/code-bearing signers (including ERC-1271 and
  EIP-7702), does not fetch data, decide consensus finality, select real
  auditors, or rotate a production root. Descriptor-embedded `attestations`
  never count as evidence. The checked-in dev policy's older explanatory
  comments are curation-manifest-bound bytes; update that file only atomically
  with an approved production policy, manifest, artifacts, and root ceremony.

## Current coverage (365-leaf catalogue snapshot, measured 2026-08-05)

The current PQ1 catalogue has 365 leaves and 214 unique resolved ERC-8176
descriptor hashes. A fresh `python3 tools/erc8176_eas_coverage.py --json` query
returned three schema records: two eligible, one expired, none revoked or
malformed, and **zero PQ1 descriptor matches**. No descriptor has any trusted
attestation, and zero meet the required two-distinct-attester threshold.

Upstream's
[`#2764`](https://github.com/ethereum/clear-signing-erc7730-registry/pull/2764)
merged on 2026-07-31, so registry master now contains one auditor profile for
Patrick Collins / Cyfrin, signer
`0x3846c3A30E62075Fa916216b35EF04B8F53931f6`. Registration proves control of an
identity; it is not by itself a PQ1 trust decision or an attestation over a
descriptor.

The companion
[`#2765`](https://github.com/ethereum/clear-signing-erc7730-registry/pull/2765)
with 181 offchain EAS-v2 signature files remains open, review-required, and
failing the registry's descriptor/schema validation. A prior read-only
rehearsal recovered the same Cyfrin signer from all 181 signatures, but only
three resolved hashes matched the exact descriptor bytes shipped by PQ1. One
candidate signer cannot satisfy PQ1's two-distinct-attester policy, so even
that unmerged batch would make **zero PQ1 descriptors production-admissible**.

Registry master therefore has one registered auditor profile but zero merged
signature files. PQ1 has not approved that candidate, selected a second
independent auditor, pinned a production checkpoint/snapshot, or authorized a
production root. The canonical policy and release status remain
`dev-unattested`.

## Flip-readiness: the precise unblock condition

Flip `allow_unattested_dev_descriptors = false` only after the external evidence
and release-owned inputs exist. To assess a candidate advisory trust set, run
`python3 tools/erc8176_eas_coverage.py --trusted <0xADDR> [<0xADDR> ...]`;
that live report is an ecosystem tripwire, not authorization.
Concretely, the remaining half requires:

1. Auditors we trust (Ledger / Fireblocks / Sourcify / Cyfrin) actually publish
   EAS attestations under schema #377 for the descriptors we ship.
2. Their real attester addresses populate `policy.toml`'s `trusted_attesters`
   (currently placeholders), and an owner independently approves a finalized
   checkpoint, snapshot hash, evaluation epoch and freshness policy.
3. The resulting production policy/snapshot passes the verifier and threshold,
   then goes through the separately reviewed root/release ceremony. The
   companion-to-firmware code path now authenticates the pairing through the
   signed-image `P73S` receipt ([#379](https://github.com/EthereumPhone/PQ1/issues/379)),
   but that compatibility mechanism does not rotate or authorize a root and
   does not close the independent release/rollback quarantine.

**Until then:** run `make erc8176-coverage` periodically (it's the tripwire); stay
in dev mode. Flipping now would remove clear-sign coverage for the entire
365-leaf corpus, while filter-positive calls would hard-refuse, for zero
security gain because there is nothing to verify against.

## Why this is the honest posture

For a *shape* attacker (a descriptor that hides fields), the structural WYSIWYS
gates (rule 1/2, dup-name, EIP-712 nested-struct) are the defense. For a *content*
attacker (a descriptor that lies about what a function does), attestation by a
party who checked the descriptor against the real contract is the defense — and
that is exactly ERC-8176. We cannot manufacture that trust unilaterally; a
self-signed curation key in the repo would be a no-op (an attacker who owns CI
owns the key). So the verifier and binding can land fail-closed now, while the
canonical production flip waits for independent evidence it can actually
enforce. The live owner item is
[#377](https://github.com/EthereumPhone/PQ1/issues/377).
