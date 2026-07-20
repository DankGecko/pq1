# QuickSwap V2 Router02 constrained-route evidence

This offline bundle binds PQ1's constrained ERC-7730 admission of eight routes
on Polygon's canonical QuickSwap V2 Router02 deployment:

- three all-static, non-permit remove-liquidity routes; and
- two token-to-token multi-hop swaps; and
- exactly three standard native-asset swaps:
  `swapExactETHForTokens(uint256,address[],address,uint256)`,
  `swapExactTokensForETH(uint256,uint256,address[],address,uint256)`, and
  `swapTokensForExactETH(uint256,uint256,address[],address,uint256)`.

The token-to-token swaps are the classic deadline-bearing five-argument
Router02 functions, selectors `0x38ed1739` and `0x8803dbee`. They are distinct
from Uniswap SwapRouter02's four-argument functions, selectors `0x472b43f3`
and `0x42712a67`. The three native-asset selectors are `0x7ff36ab5`,
`0x18cbafe5`, and `0x4a25d94a`, respectively. The archived ABI subset preserves
the pinned official source's input names, types, order, payable/nonpayable
mutability, and return values.

Two additional source-defined routes are intentionally descriptor-declared
only to enter the exact and Bloom known-call refusal sets:
`swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)`
(`0x791ac947`) and
`swapETHForExactTokens(uint256,address[],address,uint256)` (`0xfb3bdb41`).
They remain absent from trusted IR and gain no clear-sign authority.

The runtime was captured by EIP-1898 block hash from independent public RPC
fronts. The archived official QuickSwap source snapshot and build files match
the verified flattened deployment source under the normalization described in
`manifest.json`.

## Source-derived swap semantics

The pinned router and library source establish all of the following:

- `ensure(deadline)` requires the signed deadline to be at least the executing
  block's timestamp;
- both swap libraries require `path.length >= 2` for successful execution;
- every `path` element selects a token, adjacent pair, hop direction,
  intermediate receiver, or final output token;
- exact-input fixes `amounts[0] = amountIn`, derives every later amount from
  live pair reserves, requires the last derived amount to meet `amountOutMin`,
  transfers the signed input token from `msg.sender`, and sends the final hop
  to the exact signed `to` address;
- exact-output fixes the last amount to `amountOut`, derives required inputs
  backwards through every hop, caps the first amount by `amountInMax`,
  transfers that live-state-derived input from `msg.sender`, and sends the
  final hop to the exact signed `to` address; and
- `swapExactETHForTokens` is payable, requires `path[0] == WETH`, uses the exact
  signed outer `msg.value` as its input, wraps it, enforces the signed token
  `amountOutMin`, and sends the final token hop to the literal `to` address;
- `swapExactTokensForETH` is nonpayable, requires the last path element to be
  `WETH`, transfers the signed token `amountIn`, enforces the signed native
  `amountOutMin`, unwraps the final WETH amount, and sends native currency to
  the literal `to` address;
- `swapTokensForExactETH` is nonpayable, requires the last path element to be
  `WETH`, fixes the signed native `amountOut`, caps the live-state-derived token
  input by `amountInMax`, unwraps the exact output, and sends native currency
  to the literal `to` address; and
- unlike SwapRouter02, the classic router has no special `address(1)` or
  `address(2)` recipient sentinels: `to` is always literal.

PQ1 therefore renders every signed `path` address as `Route`, in order, and
uses the first and last signed elements as the input/output token identities.
Paths above the device's eight-address review cap refuse instead of hiding
hops. Empty paths fail endpoint resolution. The generic array renderer has no
per-format minimum-count predicate, so a canonical one-address path can render
exactly even though the official router then reverts on its `path.length >= 2`
check. Clear signing describes the signed request; it does not promise that
live execution will succeed. The same boundary applies to native routes: the
full signed route is shown, but the generic format has no authenticated
per-format equality predicate for the pinned Polygon wrapped-native endpoint
`0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270`. A wrong first or last endpoint
therefore renders exactly and then reverts on the router's explicit WETH check.

## Honest live-state residuals

The display binds the signed route, amounts/caps, beneficiary, deadline, and,
for `swapExactETHForTokens`, the exact signed outer native value.
It cannot bind live reserves, pair/token code and behavior, balances,
allowances, transfer taxes, miner/validator timestamp choice, or intervening
state changes. In particular, `amountOutMin` and exact `amountOut` are gross
pair transfer amounts: a fee-on-transfer or otherwise non-standard output token
can deliver less net value to the beneficiary. Exact-output's actual input is
derived from live pair reserves and is only bounded by the displayed
`amountInMax`. Malicious or non-standard tokens can also violate ordinary
ERC-20 transfer assumptions. These residuals are not signed calldata and are
not presented as guarantees.

For remove-liquidity, `liquidity` is the exact LP-token base-unit quantity
transferred to the derived pair and burned, but the pair identity and LP-token
decimals are not signed. PQ1 therefore shows all 32 signed bytes as raw
hexadecimal rather than inventing a ticker or decimal scale.

The fee-on-transfer removal variant also checks gross pair token output rather
than the beneficiary's net post-tax receipt and transfers the router's entire
selected-token balance, which can include dust, to the signed beneficiary.

Permit-bearing removal routes, fee-on-transfer swap routes, the refundable
exact-output native-input route, and every other descriptor-declared swap route
remain known calls that hard-refuse clear signing. The two refusal-only
declarations above are catalogue inputs for that refusal behavior, not trusted
display formats. This bundle grants no authority to those routes, other
deployments, fallback/blind signing, live-state success, hardware readiness, or
shipment.
