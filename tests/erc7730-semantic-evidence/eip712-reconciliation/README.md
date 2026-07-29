# ERC-7730 EIP-712 reconciliation

This package is the compact future-review index for GitHub issue
[`#498`](https://github.com/EthereumPhone/PQ1/issues/498). It records the exact
27-source / 39-leaf queue that was previously accepted without source-level
semantic classification.

`manifest.json` separates:

- exact deployments promoted only after source/runtime/domain/type evidence;
- descriptors quarantined from the clear-signing set pending the stated
  evidence or presentation repair.

Quarantine is fail-closed. The manifest-bound curation marker is enforced at
build time and emits no clear-signing leaf; the typed-data handler requires a
valid descriptor proof and therefore refuses the request. EIP-712 is not part
of the contract-call `P73K` forced-blind set and remains ineligible for that
fallback. A future owner should reconsider only the named source after
satisfying its `reason_code` requirement; family names, fixtures, or parser
capability alone are not deployment authority.

This is merge-stage E1 evidence. It grants no live-code monitoring, execution
success, ERC-8176 production provenance, hardware, shipment, or forced-blind
authority.
