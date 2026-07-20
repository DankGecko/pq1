# Aave V3 permit compatibility evidence

This package records why PQ1 deliberately refuses three otherwise
operand-complete Aave V3 calls:

- `withdrawETHWithPermit(address,uint256,address,uint256,uint8,bytes32,bytes32)`
- `repayWithPermit(address,uint256,uint256,address,uint256,uint8,bytes32,bytes32)`
- `supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)`

The source witnesses are excerpts from the official `aave-v3-origin`
repository at the commit and full-file hashes in `manifest.json`. Both Pool
routes pass `_msgSender()` as the permit owner. The gateway passes `msg.sender`
for aWETH, and the Aave aToken implementation accepts that permit only when
`owner == ECDSA.recover(digest, v, r, s)`.

When PQSmartWallet executes one of these calls, PQSmartWallet itself is
`msg.sender`. Its ERC-1271 verifier accepts only the exact 4,128-byte
`abi.encode(ownerIndex, C10 signature)` wrapper; the Aave calls expose only the
fixed `uint8 v, bytes32 r, bytes32 s` transport. They therefore cannot carry a
PQ1 authorization for the required owner.

Current Aave Pool revisions 10 and 11 and the current gateway wrap the permit
attempt in `try/catch`, so an invalid permit does not necessarily revert the
whole call. With a sufficient pre-existing allowance, execution continues with
the same supply, repay, or withdrawal logic as the corresponding ordinary
route. Those ordinary routes are already admitted by PQ1. The permit variants
therefore add no PQ1 capability: without prior allowance they fail later, and
with prior allowance they duplicate a non-permit route after silently ignoring
the unusable permit attempt. Rendering V/R/S as a useful authorization would
be misleading even though every calldata operand could be shown.

The production descriptors retain each selector in the independently derived
known-call inventory while omitting it from authenticated IR. A known request
therefore hard-refuses instead of falling through to a generic or blind-sign
path.

## Evidence boundary

The archived files are exact relevant-function excerpts, not complete source
trees or deployed-bytecode proofs. Their full upstream file hashes and commit
identities make the retrieval reproducible; the executable test binds the
excerpts to the local PQSmartWallet signature contract and to the fail-closed
catalogue result. The revision-10 source commit recorded in the manifest has
the same catch-and-continue permit structure; the archived excerpt is revision
11. Because this remediation removes signing eligibility, it does not depend
on proving that every pinned Aave deployment has identical bytecode. It grants
no fallback, blind-signing, deployment, or shipment authority.
