# Ondo manager semantic evidence

This deterministic offline package covers exactly the four accepted
ERC-7730 deployment leaves emitted by:

- `ondo-finance/calldata-GMTokenLimitOrder.json` for the direct Ethereum and
  BNB Smart Chain deployments;
- `ondo-finance/calldata-OUSGInstantManager.json` for the direct Ethereum
  deployment; and
- `ondo-finance/calldata-USDYInstantManager.json` for the direct Ethereum
  deployment.

It does not add a descriptor, selector, fallback, or blind-signing path.

## Deployment and source binding

At Ethereum block 25,624,832 (`0x1870100`, hash
`0xd4f3efc6...729d9944`) dRPC and Tenderly agree on the complete manager and
token runtimes, token implementation slots, manager token bindings, and token
metadata. At BNB Smart Chain block 112,456,960 (`0x6b3f500`, hash
`0x298e6b16...c58816cd`) NodeReal and MeowRPC agree on the complete GM Token
Limit Order runtime. Every state query is bound to the retained block hash
with EIP-1898 `requireCanonical:true`.

The four manager runtimes byte-match the `runtimeBytecode.onchainBytecode`
returned by Sourcify's current v2 contract-lookup API. Sourcify classifies all
four as direct (`isProxy:false`) verified `match` records and supplies the
complete source closure and ABI. The Ethereum and BSC GM records have
byte-identical source closures and ABIs; their runtimes differ only as the
separately bound deployments.

The OUSG, USDY, and rUSDY constants are token proxies, not immutable token
implementations. The package binds each fixed-block EIP-1967 implementation
slot to Sourcify's proxy resolution and archives a verified direct
implementation record. At the fixed block their metadata is:

| Token | Address | Name | Symbol | Decimals |
|---|---|---|---|---:|
| OUSG | `0x1b19...ee92` | Ondo Short-Term U.S. Government Bond Fund | OUSG | 18 |
| USDY | `0x96f6...985c` | Ondo U.S. Dollar Yield | USDY | 18 |
| rUSDY | `0xaf37...b879` | Ondo U.S. Dollar Yield (Rebasing) | rUSDY | 18 |

OUSG and USDY match the existing production ERC-20 metadata corpus. rUSDY was
not enrolled in that corpus at this evidence freeze, so this package does not
claim that a friendly rUSDY ticker is available at runtime; the renderer's
authenticated raw-amount/address behavior remains the safe boundary.

## Accepted signed meaning

The five GM Token Limit Order routes preserve all five signed words. Source
binds them to four combinations of `BUY`/`SELL` and exact-GM/exact-quote
orders. The device shows both token identities, the exact GM or quote amount,
the 18-decimal maximum/minimum USD price, and the expiry. `cancelOrder`
changes only an active order made by `msg.sender` and the exact order ID is
shown.

OUSG `subscribe` transfers the signed deposit-token amount and mints at least
the signed OUSG minimum to the caller. OUSG `redeem` burns the signed OUSG
amount and transfers at least the signed receiving-token minimum to the
caller.

USDY `subscribe` and `redeem` have the same input/minimum-output meaning for
USDY. The rebasing variants additionally wrap USDY into rUSDY or unwrap rUSDY
into USDY, and enforce the signed rUSDY or receiving-token minimum. Every
dynamic token address is bound through the displayed `tokenAmount` identity
path; no address operand is silently discarded.

## Honest boundary

This is historical fixed-block evidence, not live monitoring. It does not
prove transaction success, compliance eligibility, accepted-token state,
allowance, balance, fee, oracle price, rate-limit state, pause state, order
existence, execution price, or future token-proxy implementations/metadata.
It authorizes no manager route beyond the sixteen deployment-format instances
named in `manifest.json`, no future deployment, fallback, forced blind flow,
hardware claim, production release, or shipment.

Primary records are the checked-in Sourcify v2 responses and the retained
EIP-1898 requests/provider responses. `collect.sh` reproduces the collection;
`manifest.json` SHA-256-receipts every non-manifest byte.
