# Midas mTBILL DepositVault semantic evidence

This deterministic offline bundle supports one bounded PQ1 ERC-7730 route:
Ethereum mainnet Midas mTBILL `DepositVault.depositInstant(address,uint256,
uint256,bytes32)` at proxy `0x99361435420711723aF805F08187c9E6bF796683`
(selector `0xc02dd27a`). It supplies no authority for the custom-recipient overload,
either asynchronous deposit-request overload, another Midas deployment, or a
redemption vault.

## Fixed deployment identity

At Ethereum block 25,579,745 (`0x18650e1`, hash
`0x747c9dfc...ceb7fb`), dRPC, Tenderly, and MEV Blocker independently agree
that:

- the admitted proxy's EIP-1967 implementation is
  `0xC8AF8477f3CaA89F60Fe9d1f48EeE5433C55982B`;
- its `mToken()` getter returns Ethereum mTBILL proxy
  `0xdd629e5241cbc5919847783e6c96b2de4754e438`;
- that mTBILL proxy's EIP-1967 implementation is
  `0xD4998Cc1ba435298C521f250b81856B1F25C8455`;
- all three providers return byte-identical vault and token proxy and
  implementation runtimes; and
- the token metadata is `Midas US Treasury Bill Token`, `mTBILL`, 18 decimals.

Every historical state read and call uses EIP-1898 `blockHash` with
`requireCanonical:true`. The requests and complete provider responses live
under `rpc/raw/`; the collector changes only JSON object and batch ordering to
make recapture deterministic, not any response value. The Rust evidence test
derives provider agreement and identities from those files instead of trusting
this README or `manifest.json`.

## Deployment and source provenance

The official `midas-apps/contracts` repository is pinned at commit
`237c56a85e51560a977d9473ce3f939d877f2a4f` (tree
`1cff2a6fe8ad0f97e312a28624e9b32166f0d942`). The archived official address
map names exactly this mTBILL token and DepositVault; the archived mainnet
configuration records its issuance policy inputs. The five load-bearing
official Solidity files match the Blockscout-verified deployed sources
byte-for-byte.

The Blockscout implementation record is fully verified with Solidity
`0.8.9+commit.e5eed63a`, optimizer enabled for 200 runs, literal source
metadata, and no linked libraries. All 36 verified source files are archived
under `source/verified/`, and the exact explorer compiler settings are archived
separately. A standard-JSON input derived from that complete closure narrows
only `outputSelection`; `solc` 0.8.9 reconstructs the complete 17,677-byte
deployed implementation runtime byte-for-byte. Raw proxy, implementation,
mTBILL proxy, and mTBILL implementation Blockscout records are retained as
independent explorer evidence.

## Signed-operand semantics

The exact one-entry ABI projection establishes four signed operands:

- `tokenIn`: the payment-token address;
- `amountToken`: a base-18 normalized payment amount, regardless of the
  payment token's native decimals;
- `minReceiveAmount`: the minimum base-18 mTBILL amount accepted by the call;
- `referrerId`: an application-supplied full 32-byte referral identifier.

The deployed source validates caller access, calculates the deposit from the
signed payment token and normalized amount, requires the calculated mint amount
to meet `minReceiveAmount`, transfers the payment and any fee, and mints mTBILL
to `msg.sender`. The decimal-correction path rejects a normalized amount that
cannot be represented exactly in the payment token's native precision. The
event retains the signed `referrerId`; it is not semantically absent merely
because the upstream descriptor hid it.

## Honest residual and authority boundary

Payment-token enrollment and token configuration, user access lists,
greenlist/blacklist/sanctions state, rates, fees, daily limit, supply cap,
minimums, pause state, and proxy implementations are mutable live state. This
bundle neither monitors future upgrades nor proves that any particular call
will succeed. It does not identify a friendly payment-token name, promise a
mint quantity beyond the signed minimum, or claim that the referral identifier
has a user-comprehensible interpretation.

The standard four-argument route always mints to the caller, but the evidence
does not authorize hiding that beneficiary in the trusted display. It does not
authorize the custom-recipient route, whose recipient is separately signed, or
the request routes, which transfer payment before later administrator approval
and minting. Nothing here enables fallback or blind signing, changes parser or
state authority, or grants hardware, production, shipment, or transaction-
success authority.

Primary records:

- https://github.com/midas-apps/contracts/tree/237c56a85e51560a977d9473ce3f939d877f2a4f
- https://docs.midas.app/resources/smart-contracts-addresses
- https://eth.blockscout.com/address/0x99361435420711723aF805F08187c9E6bF796683
- https://eth.blockscout.com/address/0xC8AF8477f3CaA89F60Fe9d1f48EeE5433C55982B
- https://eth.blockscout.com/block/25579745
