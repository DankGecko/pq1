# WETH9 deposit semantic evidence

This directory is the offline evidence input for the two WETH9 `deposit()`
routes admitted by PQ1:

- Ethereum mainnet `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- Ethereum Sepolia `0xfff9976782d46cc05630d1f6ebab18b2324d6b14`

The payable `deposit()` function has no calldata operands. On success it
credits `balanceOf[msg.sender]` by exactly `msg.value` and emits
`Deposit(msg.sender, msg.value)`. The ERC-7730 descriptor displays
`@.value`, so its displayed amount is the exact signed transaction value
consumed by the deployed function.

The fixed-block receipt uses two independent RPC operators on each chain:

- mainnet block 25,569,139: dRPC and MEV Blocker;
- Sepolia block 11,308,073: dRPC and Tenderly.

For each chain both endpoints agree on the block hash/state root, complete
runtime, standard EIP-1967 implementation/admin/beacon slots, and encoded
`name`, `symbol`, and `decimals` results. Both deployments are direct
contracts: their verified WETH9 executable stream contains no proxy dispatch
opcode, and all three standard EIP-1967 slots are zero.

The two 3,124-byte runtimes are intentionally stored separately. Bytes
0..3080—the complete executable instruction stream—are identical. Only the
32-byte Solidity swarm metadata content hash differs.

Source and ABI provenance:

- official DappHub source:
  `dapphub/ds-weth@abb410d7a927f5c9b42e3bca83fa5701ed9a36b4`;
- official canonical-weth mainnet deployment record:
  `gnosis/canonical-weth@0dd1ea3e295eef916d0c6223ec63141137d22d67`;
- mainnet Blockscout verified source: partial verification, solc 0.4.19,
  optimizer disabled;
- Sepolia Blockscout verified source: full verification, the same compiler and
  ABI.

The official DappHub file names the source contract `WETH9_`; deployed
verified sources name it `WETH9`, and Sepolia's source includes an Etherscan
submission header. The function bodies and executable semantics otherwise
match. This difference is recorded explicitly in `manifest.json`.

Primary records:

- https://github.com/dapphub/ds-weth/tree/abb410d7a927f5c9b42e3bca83fa5701ed9a36b4
- https://github.com/gnosis/canonical-weth/tree/0dd1ea3e295eef916d0c6223ec63141137d22d67
- https://eth.blockscout.com/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
- https://eth-sepolia.blockscout.com/address/0xfff9976782d46cc05630d1f6ebab18b2324d6b14

This is historical fixed-block evidence, not live monitoring. It establishes
neither future code/state nor production, shipment, fallback, or blind-signing
authority.
