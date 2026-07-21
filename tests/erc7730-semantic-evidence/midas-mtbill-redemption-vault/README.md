# Midas mTBILL RedemptionVault semantic evidence

This deterministic offline bundle supports exactly four flat-static token-out
routes of the Ethereum mainnet Midas mTBILL RedemptionVault at proxy
0xF6e51d24F4793Ac5e71e0502213a9BBE3A6d4517:

- redeemInstant(address,uint256,uint256) (0x8b53f75e);
- redeemInstant(address,uint256,uint256,address) (0x85ab2c13);
- redeemRequest(address,uint256) (0xbfc2d46a); and
- redeemRequest(address,uint256,address) (0x15571a04).

The ABI archive also retains redeemFiatRequest(uint256) (0xd5f73f5c) as a
negative authority control. This bundle does not authorize that route, another
Midas deployment, fallback, or blind signing.

## Fixed deployment identity

At Ethereum block 25,579,745 (0x18650e1, hash 0x747c9dfc...ceb7fb),
dRPC, Tenderly, and MEV Blocker independently agree that:

- the admitted proxy's EIP-1967 implementation is
  0x2F1372244CEDCAf8eE1759D2F02435628f14975f;
- its mToken() getter returns Ethereum mTBILL proxy
  0xdd629e5241cbc5919847783e6c96b2de4754e438;
- that token proxy's implementation is
  0xD4998Cc1ba435298C521f250b81856B1F25C8455;
- all three providers return byte-identical vault and token proxy and
  implementation runtimes; and
- the token metadata is Midas US Treasury Bill Token, mTBILL, 18 decimals.

Every historical state read and call uses EIP-1898 blockHash with
requireCanonical:true. The Rust evidence test derives agreement and identities
from the archived requests and complete provider responses.

## Deployment and source provenance

The official midas-apps/contracts repository is pinned at commit
237c56a85e51560a977d9473ce3f939d877f2a4f (tree
1cff2a6fe8ad0f97e312a28624e9b32166f0d942). Its mainnet address map names the
exact proxy as the mTBILL RedemptionVault. The five load-bearing official
Solidity files match the Blockscout-verified deployed sources byte-for-byte.

The implementation record is fully verified with Solidity
0.8.9+commit.e5eed63a, optimizer enabled for 200 runs, literal source metadata,
and no linked libraries. All 36 verified source files are archived. The
standard-JSON reconstruction narrows only outputSelection; solc 0.8.9 rebuilds
the complete 17,811-byte implementation runtime exactly.

## Signed operands and route semantics

All four admitted calls debit exactly the signed base-18 amountMTokenIn from
msg.sender: the fee is sent separately and the remainder is either burned
immediately or moved into the pending-request vault. The trusted display must
identify that input as mTBILL, not as the arbitrary output token.

Both instant routes sign tokenOut, amountMTokenIn, and a base-18 normalized
minReceiveAmount. The source converts and truncates the actual output to the
output token's native precision, enforces that normalized actual amount against
the signed minimum, and transfers the result immediately. The standard
overload uses authenticated msg.sender as beneficiary; the custom overload
uses the signed recipient and still debits msg.sender.

Both request routes sign tokenOut and amountMTokenIn, but no output minimum.
They transfer mTBILL immediately, store a pending request, and leave later
completion to a vault administrator using a later supplied mToken rate. The
standard overload stores msg.sender as beneficiary; the custom overload stores
the signed recipient. The trusted intent must say that mTBILL leaves now and no
output minimum is signed. The archived rejectRequest path only marks a request
canceled and supplies no automatic refund guarantee.

## Fiat refusal and honest residual

redeemFiatRequest(uint256) signs only an mTBILL amount. Currency, payout
amount, bank destination, timing, and fulfillment terms are absent. On-chain
approval recognizes a zero-address manual-fulfillment sentinel and performs no
fiat transfer. It therefore remains an exact-known hard refusal.

Output-token enrollment, access policy, rates, fees, allowance, liquidity,
daily limit, pause state, token balances, request disposition, and proxy
implementations are mutable live state. The bundle neither monitors future
upgrades nor promises transaction success, a request output, timing, or refund.
It supplies source/merge evidence only, not hardware, production, shipment, or
irreversible-action authority.

Primary records:

- https://github.com/midas-apps/contracts/tree/237c56a85e51560a977d9473ce3f939d877f2a4f
- https://eth.blockscout.com/address/0xF6e51d24F4793Ac5e71e0502213a9BBE3A6d4517
- https://eth.blockscout.com/address/0x2F1372244CEDCAf8eE1759D2F02435628f14975f
- https://eth.blockscout.com/block/25579745
