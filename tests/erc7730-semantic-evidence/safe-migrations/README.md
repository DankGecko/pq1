# Safe migration and L2-setup calldata semantic evidence

This offline bundle binds the four accepted Safe migration/setup descriptor
families to official Safe source tags, official Safe deployment manifests,
historical Ethereum runtime code, and immutable migration targets at one fixed
canonical block.

The admitted subset is deliberately narrow:

- `migrateSingleton()` changes a Safe proxy to the versioned canonical Safe
  singleton encoded by the exact migration deployment;
- `migrateL2Singleton()` changes a Safe proxy to the versioned canonical
  SafeL2 singleton encoded by that deployment; and
- `setupToL2(address)` validates the complete signed singleton operand and,
  outside Ethereum chain ID 1, installs it in a nonce-zero Safe.

`migrateWithFallbackHandler()` and `migrateL2WithFallbackHandler()` remain
structural refusal-only routes. They also install an immutable fallback handler
whose exact identity is absent from the upstream display, so future admission
requires explicit removal of the marker and new display evidence.

## Honest boundary

This is historical source, deployment-manifest, ABI, runtime-identity, and
immutable-getter evidence for the deployments already named by the four
descriptors. It does not prove a Safe proxy instance, its current nonce or
singleton, a delegatecall wrapper, transaction success, live code at a
user-supplied L2 singleton, future deployments, future code monitoring,
production provenance, hardware behavior, fallback authority, or blind
signing.

Primary upstream records:

- https://github.com/safe-fndn/safe-smart-account
- https://github.com/safe-global/safe-deployments
- https://eth.drpc.org
- https://rpc.mevblocker.io
