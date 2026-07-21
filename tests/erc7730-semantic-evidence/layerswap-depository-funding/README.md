# Layerswap Depository funding semantic evidence

This offline bundle covers exactly the two user funding routes on Ethereum
mainnet LayerswapDepository
`0xE226E4825CB215aBaFAd98fdd400583eAb6a594f`:

- `depositNative(bytes32,address)` (`0x80a6de92`); and
- `depositERC20(bytes32,address,address,uint256)` (`0xf4371f63`).

It does not authorize any administrative route, another deployment, a future
upgrade, fallback, or blind signing.

## Address correction

The enrollment brief transcribed the address as
`0xE2260D5eF5d71467f0C1AacC3B6e5Ab6f6B8594f`. At the fixed block below,
three independent RPCs return empty code for that address and the same
3,876-byte runtime for the registry-declared `0xE226E482...a594f` address.
The latter is also the fully verified explorer deployment. This bundle records
the typo as a negative identity control instead of silently changing it.

## Fixed deployment and source identity

At Ethereum block 25,582,700 (`0x1865c6c`, hash
`0xdb61c00e...edf38631`), MEV Blocker, Tenderly, and Flashbots independently
agree on the block header and complete runtime. Every code query uses the
EIP-1898 block hash with `requireCanonical:true`.

Blockscout reports the contract as fully verified, unchanged bytecode, built
with Solidity `0.8.29+commit.ab55807c`, Prague EVM, and optimizer 200. Its
3,876-byte deployed bytecode is byte-identical to the fixed-block RPC runtime.
The archived standard-JSON input and exact compiler rebuild that runtime.

The deployed primary source is byte-identical to
`layerswap/layerswap-depository` commit
`a7a4ccd89f0fb5046f8d0053283da6e36c6b638c` (tree
`23e6d14d7a81950582f49dcf93a528abac9223d0`), the source revision immediately
before deployment. The official README and source are retained alongside all
verified compiler inputs.

## Semantic conclusion

Neither accepted method performs a swap or signs a destination chain, output
asset, output amount, beneficiary on another chain, deadline, fee, quote, or
fulfillment condition. Both only validate the signed receiver against mutable
whitelist state and forward funds to that receiver. The `bytes32 id` merely
correlates the deposit with an off-chain order. The official README says a
backend observes the event and fulfills the destination order later.

`depositNative` forwards the complete signed transaction value or reverts.
`depositERC20` passes the signed amount to `safeTransferFrom(msg.sender,
receiver, amount)`, then measures the receiver's balance delta for
fee-on-transfer tokens. Consequently the trusted display describes a funding
or forwarding action, labels the ERC-20 word as the requested amount, and does
not promise an on-chain swap or exact eventual output.

## Honest boundary

Whitelist membership, pause state, token behavior, allowance, balances,
backend recognition, destination fulfillment, price, fee, timing, output, and
transaction success remain live or off-chain. The fixed-block receipt does not
monitor later code changes (this deployment is direct, not a proxy), mutable
state, or solver behavior. This is merge evidence only, not hardware,
production, shipment, fallback, or blind-signing authority.

Primary records:

- https://github.com/layerswap/layerswap-depository/tree/a7a4ccd89f0fb5046f8d0053283da6e36c6b638c
- https://eth.blockscout.com/address/0xE226E4825CB215aBaFAd98fdd400583eAb6a594f
- https://eth.blockscout.com/block/25582700
