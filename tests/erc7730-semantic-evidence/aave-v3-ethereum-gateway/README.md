# Aave V3 Ethereum WrappedTokenGatewayV3 semantic evidence

This offline bundle binds the mainnet gateway at
`0xd01607c3C5eCABa394D8be377a08590149325722` to its deployed code, immutable
WETH/Pool targets, verified source, ABI, and the four PQ-compatible routes
already present in the ERC-7730 descriptor.

The source establishes that the first ABI `address` operand is intentionally
unnamed and ignored by `depositETH`, `repayETH`, `borrowETH`, and `withdrawETH`;
the contract always uses immutable `POOL`. PQ1 therefore labels and renders
that signed operand as ignored rather than calling it “Pool”. The remaining
pages bind native value/amount, referral code, recipient/debt-holder, and
caller-derived roles. Source tests also pin repayment capping and refund,
withdraw-all handling, immutable Pool forwarding, and caller-directed borrow
delivery. The V/R/S permit route remains absent and hard-refused.

## Honest boundary

This package proves a historical mainnet deployment and exact source semantics.
It does not claim that the ignored operand selects a pool, predict transaction
success or reserve state, authorize permit signing, monitor future deployments,
or establish hardware, production, shipment, fallback, or blind signing.

Primary upstream records:

- https://github.com/aave-dao/aave-address-book
- https://github.com/aave-dao/aave-v3-origin
- https://eth.blockscout.com/address/0xd01607c3C5eCABa394D8be377a08590149325722
- https://sourcify.dev/server/api-docs/swagger.json
