# Safe core calldata semantic evidence

This offline bundle binds the three accepted Safe core calldata descriptor
families to official Safe source tags, official Safe deployment manifests, and
historical Ethereum runtime code at one canonical fixed block.

The admitted subset is deliberately small:

- `addOwnerWithThreshold(address,uint256)` shows the new owner and threshold;
- `changeThreshold(uint256)` shows the complete new threshold; and
- `approveHash(bytes32)` says that a Safe hash is being approved and shows the
  complete hash.

The authenticated per-deployment allowlists keep `setup`, `execTransaction`,
`removeOwner`, and `swapOwner` out of the clear set. Their upstream display
definitions omit an effect-bearing delegatecall target, execution target, or
linked-list predecessor. No module, guard, fallback-handler, or module-execution
route is added by this slice.

## Honest boundary

This is historical source, deployment-manifest, ABI, and runtime-identity
evidence for the deployments already named by the three descriptors. It does
not prove live transaction success, owner state, threshold state, approved-hash
meaning, future deployments, future code monitoring, proxy instances, SafeL2,
migrations, production provenance, hardware behavior, fallback authority, or
blind signing.

Primary upstream records:

- https://github.com/safe-fndn/safe-smart-account
- https://github.com/safe-global/safe-deployments
- https://eth.drpc.org
- https://rpc.mevblocker.io
