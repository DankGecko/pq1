# Aave V3 Ethereum Pool deployed-semantics evidence

This offline bundle binds PQ1's ten clear-signable Aave V3 Pool routes on
Ethereum mainnet to one finalized deployment snapshot. It adds reproducible
evidence; it does not add a descriptor, selector, fallback, or blind-signing
authority.

## Fixed deployment identity

At Ethereum block 25,574,144 (`0x1863b00`, hash
`0xc764a332…ba4bfd`), raw responses from dRPC, MEV Blocker, and Tenderly agree
on all of the following:

- the Aave PoolAddressesProvider returns proxy
  `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2`;
- that proxy's EIP-1967 implementation slot and admin-only
  `implementation()` view return
  `0x728a138A4823392C2EFA55e028d434F526fE03CF`;
- the proxy's admin and delegated `ADDRESSES_PROVIDER()` view return
  `0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e`;
- delegated `POOL_REVISION()` returns revision 11; and
- proxy, implementation, provider, BorrowLogic, and SupplyLogic runtime bytes
  are identical across the three provider fronts.

The checked-in request batches and raw responses are under `rpc/raw/`. Every
state or call request uses EIP-1898 `blockHash` with
`requireCanonical: true`. Offline tests validate those requests and derive
every relationship above from the raw results rather than trusting a summary
agreement flag.

## Source, ABI, and signed-field meaning

The official Aave address book at commit
`7e444a1e73b538fd0b9e093e5156401d6fccca7d` independently names the same
proxy, implementation, provider, and linked logic addresses. The archived
`PoolInstance.sol`, `Pool.sol`, `BorrowLogic.sol`, and `SupplyLogic.sol` from
`aave-dao/aave-v3-origin` commit
`fd1fbd9150426ca8ace9cee45b4acf912ae84f5b` are byte-identical to the
corresponding Blockscout verified source fields.

The implementation ABI and source establish the ten admitted routes:

- repay and repay-with-aTokens bind asset, amount, rate mode, and the explicit
  or signer-derived debt holder;
- collateral changes bind the asset, enable/disable choice, and the signer or
  explicitly named debtor;
- withdraw binds the asset, amount, and recipient;
- borrow binds the asset, amount, rate mode, referral code, and debt holder;
- deposit and supply bind the asset, amount, position recipient, and referral
  code; and
- manager approval and renunciation bind the manager/user addresses and the
  approval boolean, with the signer supplying the source-side role.

The generated PQ1 IR exposes all 27 effect-bearing fields. Its amount fields
also bind the token-address argument; repay/repay-with-aTokens render the
all-ones amount as `All`, and withdraw renders it as `Max`. The V/R/S permit
variants and dynamic multicall remain absent from the format table while their
exact chain/address/selectors remain in the independent known-call inventory
and Bloom, so they continue to hard-refuse instead of falling through.

## Honest boundary

This package proves one historical state of an upgradeable Ethereum proxy. It
does not monitor future upgrades or establish the other fourteen unique Pool
deployments in the descriptor. It does not prove transaction success, reserve
or token metadata honesty, hardware behavior, production or shipment
readiness, or any blind-signing authority. A future implementation change
requires new evidence before the same proxy/selector trust can be treated as
current.

Primary upstream records:

- https://github.com/aave-dao/aave-address-book
- https://github.com/aave-dao/aave-v3-origin
- https://eth.blockscout.com/address/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2
- https://eth.blockscout.com/address/0x728a138A4823392C2EFA55e028d434F526fE03CF
