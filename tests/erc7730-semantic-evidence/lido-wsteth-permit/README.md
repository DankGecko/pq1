# Lido wstETH calldata permit semantic evidence

This directory is the offline, fixed-block evidence input for the single
Ethereum wstETH deployment whose calldata `permit` route PQ1 admits.

It pins the direct runtime, ERC-1967 implementation-slot result, deployment
receipt, verified permit ABI and source, official Lido source anchor, and the
fixed-block `name`, `symbol`, `decimals`, `stETH`, and `DOMAIN_SEPARATOR`
results. dRPC and MEV Blocker returned identical results for every archived
block, code, slot, transaction, receipt, and call value.

The offline dbgen integration test binds those receipts to the exact curated
descriptor deployment, all seven calldata operands, the production ERC-20
metadata row, and the on-device contract-binding check. It also checks the
deployed permit semantics: deadline, owner nonce, EIP-712 hash, recovery,
owner match, nonce increment, and approval.

Primary sources:

- Lido deployment list: https://docs.lido.fi/deployed-contracts/
- Official Lido source: https://github.com/lidofinance/lido-dao/tree/2b46615a11dee77d4d22066f942f6c6afab9b87a
- Verified deployed source: https://eth.blockscout.com/address/0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0
- Evidence block: https://eth.blockscout.com/block/25566776
- Deployment transaction: https://eth.blockscout.com/tx/0xaf2c1a501d2b290ef1e84ddcfc7beb3406f8ece2c46dee14e212e8233654ff05
- OpenZeppelin ERC20Permit v3.4.0: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/drafts/ERC20Permit.sol

The explorer source used CRLF line endings. The archived flattened file is
explicitly normalized to LF with a final newline; both source hashes are
recorded. Ordinary tests are fully offline. The nonce is authenticated
contract state but is not calldata, so this evidence does not claim that PQ1
displays it.
