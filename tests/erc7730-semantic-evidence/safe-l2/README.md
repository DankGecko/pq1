# SafeL2 calldata semantic evidence

This offline bundle binds the three accepted SafeL2 calldata descriptor
families to official Safe source tags, official Safe deployment manifests, and
historical Ethereum runtime code at one canonical fixed block.

SafeL2 inherits the relevant owner and hash-approval mutations from the
corresponding Safe release. Its L2-specific code adds execution events; it does
not change the three admitted call effects:

- `addOwnerWithThreshold(address,uint256)` shows the new owner and threshold;
- `changeThreshold(uint256)` shows the complete new threshold; and
- `approveHash(bytes32)` says that a Safe hash is being approved and shows the
  complete hash.

The authenticated per-deployment allowlists keep `setup`, `execTransaction`,
`removeOwner`, and `swapOwner` out of the clear set. Their shared upstream
display definitions omit an effect-bearing delegatecall target, execution
target, or linked-list predecessor. No module, guard, fallback-handler,
module-execution, or event-derived route is admitted.

The descriptor addresses are SafeL2 singleton implementations, not Safe proxy
instances. The package proves that every descriptor deployment is named by the
corresponding official deployment manifest. Fixed-block Ethereum evidence
then byte-compares the two 1.3.0 variants and the 1.4.1 and 1.5.0 singletons
against their official code hashes.

## Honest boundary

This is historical source, deployment-manifest, ABI, and runtime-identity
evidence for the singleton deployments already named by the three descriptors.
It does not prove live transaction success, owner state, threshold state,
approved-hash meaning, per-chain runtime monitoring outside the recorded
Ethereum observations, future code, proxy instances, migrations, production
provenance, hardware behavior, fallback authority, or blind signing.

Primary upstream records:

- https://github.com/safe-fndn/safe-smart-account
- https://github.com/safe-global/safe-deployments
- https://eth.drpc.org
- https://rpc.mevblocker.io
