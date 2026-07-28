# Account and factory-control ERC-7730 evidence

This offline bundle closes the bounded account/factory-control slice of PQ1
issue 497:

- Celo `Accounts` on mainnet, limited to operand-complete account, signer,
  metadata, storage-root-removal, and payment-delegation routes;
- Kiln `Factory` on Ethereum and Hoodi, limited to `createOperator`,
  `createSplitter`, and `transferOwnership`;
- WalletConnect `StakeWeight` on Optimism, limited to the six descriptor
  routes for creating, funding, extending, updating, and withdrawing a WCT
  lock.

The Celo deployment/source authority is reused, without duplicating bytes, from
the already receipted `celo-validators-first-member` bundle. That bundle binds
the Registry-selected Accounts proxy and implementation at a fixed Celo block,
three independent RPC views, fully verified Blockscout source, and the exact
official Celo source commit. The focused account/factory test additionally
binds the admitted Accounts signatures to those source bodies and to the
curated display.

For both Kiln deployments, two RPC providers agree on canonical fixed-block
headers and direct runtime bytecode. Sourcify exact-match records bind each
runtime to `Factory.sol`, its ABI, and the implementation dependencies. The
verified source establishes that operator fees and recipient percentages are
basis points, that `createSplitter` binds the operator and salt, and that
`createSplitterAndCall` can execute arbitrary nested calldata and therefore
remains an exact known-call refusal.

For WalletConnect, two Optimism RPC providers agree on the proxy runtime,
EIP-1967 implementation, implementation runtime, configuration proxy, and
configuration-selected L2 WCT token at one canonical block. The archived token
calls bind symbol `WCT` and 18 decimals. Sourcify records bind the proxy and
implementation runtimes to the verified ABI/source used to establish the six
route meanings.

## Honest boundary

These are historical fixed-block receipts. They do not monitor future proxy,
configuration, or token upgrades; prove present execution success, balances,
allowances, lock state, operator validity, or metadata freshness; or authorize
hardware, shipment, fallback, or blind signing. Celo Alfajores is not admitted.
Celo signature-bearing routes and opaque storage-root addition, and Kiln
`createSplitterAndCall`, remain structurally refused.

Primary records:

- https://github.com/celo-org/celo-monorepo
- https://sourcify.dev/server/api-docs/swagger.json
- https://ethereum.org/en/developers/docs/apis/json-rpc/
