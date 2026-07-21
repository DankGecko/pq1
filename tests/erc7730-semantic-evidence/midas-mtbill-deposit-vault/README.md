# Midas mTBILL DepositVault semantic evidence

This deterministic offline bundle supports the four flat-static deposit routes
of the Ethereum mainnet Midas mTBILL `DepositVault` at proxy
`0x99361435420711723aF805F08187c9E6bF796683`:

- `depositInstant(address,uint256,uint256,bytes32)` (`0xc02dd27a`);
- `depositInstant(address,uint256,uint256,bytes32,address)` (`0x42e8866b`);
- `depositRequest(address,uint256,bytes32)` (`0x6e26b9f8`); and
- `depositRequest(address,uint256,bytes32,address)` (`0xe50e3dbb`).

It supplies no authority for another Midas deployment or a redemption vault.

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

## Signed-operand and payer semantics

The exact four-entry ABI projection establishes these signed operands:

- `tokenIn`: the payment-token address;
- `amountToken`: a base-18 normalized payment amount, regardless of the
  payment token's native decimals;
- `minReceiveAmount`, on the two instant routes only: the minimum base-18
  mTBILL amount accepted by the call;
- `referrerId`: an application-supplied full 32-byte referral identifier; and
- `recipient`, on the two custom-recipient routes: the mTBILL beneficiary.

The deployed source validates caller access, calculates the deposit from the
signed payment token and normalized amount, and always pulls the payment and
any fee from `msg.sender`. The decimal-correction path rejects a normalized
amount that cannot be represented exactly in the payment token's native
precision. Every route's event retains the signed `referrerId`; it is not
semantically absent merely because the upstream descriptor hid it.

The two instant routes require the calculated mint amount to meet the signed
`minReceiveAmount` and mint mTBILL immediately. The standard route passes
`msg.sender` as its implicit beneficiary; the custom route mints to the signed
`recipient`. A trusted display therefore binds the implicit caller as
beneficiary on the standard route, and shows both the signed beneficiary and
the authenticated payer on the custom route.

The two request routes transfer payment immediately and create a pending
request. The standard route records `msg.sender` as its implicit beneficiary;
the custom route records the signed `recipient`, while `msg.sender` remains the
payer. A vault administrator may later approve with a later `newOutRate` and
mint the resulting amount, or reject the request. No minimum, final mTBILL
amount, approval time, or successful approval is signed by either request.
PQ1's trusted intent must therefore remain the explicit warning
`Pay now; request mTBILL`, and must not display a predicted or guaranteed
output.

## Honest residual and authority boundary

Payment-token enrollment and token configuration, user access lists,
greenlist/blacklist/sanctions state, rates, fees, daily limit, supply cap,
minimums, pause state, and proxy implementations are mutable live state. This
bundle neither monitors future upgrades nor proves that any particular call
will succeed. It does not identify a friendly payment-token name, promise an
instant mint quantity beyond the signed minimum, promise any request-route
output or timing, or claim that the referral identifier has a
user-comprehensible interpretation. The archived `rejectRequest` path marks a
request canceled but supplies no automatic refund guarantee; no refund claim
belongs on the trusted display.

Nothing here authorizes hiding the full referral ID, beneficiary, or payer
role; enables fallback or blind signing; changes parser or state authority; or
grants another deployment, hardware, production, shipment, or transaction-
success authority.

Primary records:

- https://github.com/midas-apps/contracts/tree/237c56a85e51560a977d9473ce3f939d877f2a4f
- https://docs.midas.app/resources/smart-contracts-addresses
- https://eth.blockscout.com/address/0x99361435420711723aF805F08187c9E6bF796683
- https://eth.blockscout.com/address/0xC8AF8477f3CaA89F60Fe9d1f48EeE5433C55982B
- https://eth.blockscout.com/block/25579745
