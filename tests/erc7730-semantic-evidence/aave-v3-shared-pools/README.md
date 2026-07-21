# Aave V3 shared-address Pool deployment evidence

This offline bundle extends the existing Ethereum Pool evidence to the four
Aave V3 deployments that share proxy address
`0x794a61358D6845594F94dc1DB02A252b5b4814aD`: Optimism (10), Polygon (137),
Arbitrum (42161), and Avalanche (43114). It adds deployment and semantic
evidence for the same ten already-admitted formats. It does not add a format,
selector, fallback, or blind-signing authority.

## Fixed deployment identities

For each chain, two provider fronts independently return the same canonical
fixed-block header, EIP-1967 implementation slot, proxy/provider identity,
revision 11, linked BorrowLogic and SupplyLogic addresses, provider `getPool()`
result, admin-only proxy views, and proxy/implementation/provider/linked-logic
runtime code. Every state request uses EIP-1898 `blockHash` with
`requireCanonical: true`; the exact requests and raw responses are archived
under `rpc/raw/` and checked offline.

The Aave address book at commit
`7e444a1e73b538fd0b9e093e5156401d6fccca7d` names each proxy, provider, and
implementation. Aave V3 Origin commit
`fd1fbd9150426ca8ace9cee45b4acf912ae84f5b` supplies the regular and L2 Pool
instances, their inherited Pool entry points, and the linked Borrow/Supply
logic. Sourcify runtime matches bind the Optimism, Polygon, and Arbitrum
implementations to their compiler metadata and ABI; the Avalanche verification
is archived from Routescan. Optimism and Arbitrum use `L2PoolInstance`, while
Polygon and Avalanche use `PoolInstance`; all four inherit the ten admitted
canonical entry points from `Pool` and return the same linked logic addresses.

## Honest boundary

These are historical fixed-block receipts for four upgradeable proxies. They
do not monitor upgrades, establish the remaining ten unique deployments in the
descriptor, prove reserve/token metadata, transaction success, hardware,
production, shipment, fallback, or blind signing. The compressed L2-only
`bytes32` overloads are not admitted by this evidence. Future implementation
changes require fresh evidence.

Primary upstream records:

- https://github.com/aave-dao/aave-address-book
- https://github.com/aave-dao/aave-v3-origin
- https://sourcify.dev/server/api-docs/swagger.json
- https://api.routescan.io
