# QuickSwap V2 Router02 constrained-route evidence

This offline bundle binds PQ1's constrained ERC-7730 admission of fourteen routes
on Polygon's canonical QuickSwap V2 Router02 deployment:

- two non-permit add-liquidity routes,
  `addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)`
  and `addLiquidityETH(address,uint256,uint256,uint256,address,uint256)`; and
- three all-static, non-permit remove-liquidity routes; and
- two token-to-token multi-hop swaps; and
- exactly four selected native-asset swaps:
  `swapExactETHForTokens(uint256,address[],address,uint256)`,
  `swapETHForExactTokens(uint256,address[],address,uint256)`,
  `swapExactTokensForETH(uint256,uint256,address[],address,uint256)`, and
  `swapTokensForExactETH(uint256,uint256,address[],address,uint256)`; and
- all three fee-on-transfer swaps:
  `swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)`,
  `swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)`,
  and
  `swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)`.

The two add-liquidity selectors are `0xe8e33700` and `0xf305d719`, respectively.
The token-to-token swaps are the classic deadline-bearing five-argument
Router02 functions, selectors `0x38ed1739` and `0x8803dbee`. They are distinct
from Uniswap SwapRouter02's four-argument functions, selectors `0x472b43f3`
and `0x42712a67`. The four native-asset selectors are `0x7ff36ab5`,
`0xfb3bdb41`, `0x18cbafe5`, and `0x4a25d94a`, respectively. The archived ABI
subset preserves the pinned official source's input names, types, order,
payable/nonpayable mutability, and return values.

The three fee-on-transfer selectors are `0x5c11d795`, `0xb6f9de95`, and
`0x791ac947`, respectively. Their source-backed displays deliberately preserve
the distinction between a signed request and live execution: token-input
`amountIn` is labelled `Requested Input`, not an exact debit or pair receipt.

The runtime was captured by EIP-1898 block hash from independent public RPC
fronts. The archived official QuickSwap source snapshot and build files match
the verified flattened deployment source under the normalization described in
`manifest.json`.

## Source-derived add-liquidity semantics

The pinned router and library source establish all of the following:

- `_addLiquidity` creates a missing pair, reads its live reserves, and uses the
  reserve ratio to choose the actual token deposits;
- for an empty pair, both actual deposits equal their signed desired amounts
  and neither signed minimum is checked;
- for a non-empty pair, one actual deposit equals its signed desired amount and
  the other is the reserve-ratio optimum. Only that adjusted side's signed
  minimum is checked; the full-desired side's minimum is not checked in that
  branch;
- the signed desired token amounts are therefore inclusive maxima for the
  actual deposits, not promises that the router will transfer both amounts;
- `addLiquidity` transfers the two live-reserve-derived actual amounts from
  `msg.sender` to the derived pair and asks that pair to mint a live-state-
  derived LP-token amount to the literal signed `to` address;
- `addLiquidityETH` supplies the exact signed outer `msg.value` to
  `_addLiquidity` as the desired native side, so the outer value is an inclusive
  maximum. It wraps and deposits only the live-reserve-derived actual native
  amount, then refunds any excess outer value to `msg.sender`;
- `addLiquidityETH` likewise transfers only its live-reserve-derived actual
  token amount, and the literal signed `to` address is the LP recipient; and
- neither route signs the pair address or LP-token output amount; pair creation,
  existing reserves, token behavior, pair behavior, actual deposits, and minted
  LP output remain live-state-derived.

PQ1 therefore labels both desired token amounts and the payable outer native
value `Maximum to Add`. It labels each minimum `Conditional Min`, because the
source checks only the adjusted side in a non-empty pair and checks neither side
in an empty pair. The exact signed `to` address is labelled `LP Recipient`; PQ1
does not invent or display an exact LP-token identity or output amount.

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
- `swapETHForExactTokens` is payable, requires `path[0] == WETH`, fixes the
  signed `amountOut` as the gross final pair transfer, derives the required
  native input backwards from live reserves, requires that input to be at most
  the signed outer `msg.value`, wraps only the required input, and refunds any
  excess outer value to `msg.sender` before returning;
- `swapExactTokensForETH` is nonpayable, requires the last path element to be
  `WETH`, transfers the signed token `amountIn`, enforces the signed native
  `amountOutMin`, unwraps the final WETH amount, and sends native currency to
  the literal `to` address;
- `swapTokensForExactETH` is nonpayable, requires the last path element to be
  `WETH`, fixes the signed native `amountOut`, caps the live-state-derived token
  input by `amountInMax`, unwraps the exact output, and sends native currency
  to the literal `to` address; and
- `_swapSupportingFeeOnTransferTokens` recomputes each hop's actual input from
  the pair's live token-balance increase instead of treating signed `amountIn`
  as the quantity received by the pair;
- `swapExactTokensForTokensSupportingFeeOnTransferTokens` requests the signed
  nominal `amountIn` transfer, measures the literal beneficiary's output-token
  balance before and after the swap, and requires that balance delta to meet
  the signed `amountOutMin`;
- `swapExactETHForTokensSupportingFeeOnTransferTokens` is payable, wraps the
  exact outer `msg.value`, measures the literal beneficiary's output-token
  balance delta, and requires that delta to meet `amountOutMin`;
- `swapExactTokensForETHSupportingFeeOnTransferTokens` requests the signed
  nominal token input, requires the last route element to be WETH, then reads
  the router's whole WETH balance after the swap, checks that whole balance
  against `amountOutMin`, unwraps it, and transfers all of it to the literal
  beneficiary. Because there is no before/after delta, pre-existing router WETH
  dust can increase the native output; and
- unlike SwapRouter02, the classic router has no special `address(1)` or
  `address(2)` recipient sentinels: `to` is always literal.

PQ1 therefore renders every signed `path` address as `Route`, in order, and
uses the first and last signed elements as the input/output token identities.
For `swapETHForExactTokens`, it labels the signed outer value `Maximum to Send`
and the signed token amount `Gross Output`; it does not call that gross pair
transfer the beneficiary's guaranteed net receipt. For the two token-input
supporting-fee routes, signed `amountIn` is labelled `Requested Input`; for the
two supporting-fee token-output routes, `Minimum to Receive` is backed by the
source's beneficiary balance-delta check rather than a gross pair amount.
Paths above the device's eight-address review cap refuse instead of hiding
hops. Empty paths fail endpoint resolution. The generic array renderer has no
per-format minimum-count predicate, so a canonical one-address path can render
exactly even though the official router then reverts: standard routes use an
explicit `path.length >= 2` check, while supporting-fee routes fail on their
indexed path access. Clear signing describes the signed request; it does not
promise that live execution will succeed. The same boundary applies to native
routes: the full signed route is shown, but the generic format has no authenticated
per-format equality predicate for the pinned Polygon wrapped-native endpoint
`0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270`. A wrong first or last endpoint
therefore renders exactly and then reverts on the router's explicit WETH check.

## Honest live-state residuals

For add-liquidity, the display binds the signed token identities, desired
maxima, conditional minima, LP recipient, deadline, and the signed outer native
maximum where applicable. It does not bind the live pair address, pair
existence or code, reserves, actual deposited amounts, LP-token identity or
decimals, or minted LP output. The actual deposits depend on the live reserve
ratio. Transfer-tax or otherwise non-standard tokens can make the pair receive
less than the router's computed transfer amount, and pair donations or
non-standard pair behavior can change the minted output. For `addLiquidityETH`,
the actual native deposit and refund depend on live reserves; excess outer value
is refunded to `msg.sender`, not the signed LP recipient.

For swaps, the display binds the signed route, requested amounts/caps, beneficiary,
deadline, the exact signed outer native inputs for `swapExactETHForTokens` and
`swapExactETHForTokensSupportingFeeOnTransferTokens`, and the signed outer
native maximum for `swapETHForExactTokens`.
It cannot bind live reserves, pair/token code and behavior, balances,
allowances, transfer taxes, miner/validator timestamp choice, or intervening
state changes. For standard routes, `amountOutMin` and exact `amountOut` are
gross pair transfer amounts: a fee-on-transfer or otherwise non-standard
output token can deliver less net value to the beneficiary. Exact-output's
actual input is derived from live pair reserves and is only bounded by the displayed
`amountInMax` or, for `swapETHForExactTokens`, `Maximum to Send`. Malicious or
non-standard tokens can also violate ordinary ERC-20 transfer assumptions. For
the refundable exact-output route, the actual native input and refund depend on
those live reserves; only their signed upper bound and the exact gross output
request are claimed. These residuals are not signed calldata and are not
presented as guarantees.

For supporting-fee token inputs, signed `amountIn` is only the nominal
`transferFrom` request; transfer tax can make the first pair receive less, and
arbitrary token behavior can make the sender's economic debit differ. For the
two token-output supporting-fee routes, the minimum is the beneficiary's
observed balance increase, though rebasing and non-standard balance behavior
remain live-state assumptions. For the token-to-native supporting-fee route,
the minimum applies to the router's whole post-swap WETH balance, not a swap
delta, and all of that balance—including pre-existing dust—is unwrapped and
sent to the signed beneficiary.

For remove-liquidity, `liquidity` is the exact LP-token base-unit quantity
transferred to the derived pair and burned, but the pair identity and LP-token
decimals are not signed. PQ1 therefore shows all 32 signed bytes as raw
hexadecimal rather than inventing a ticker or decimal scale.

The fee-on-transfer removal variant also checks gross pair token output rather
than the beneficiary's net post-tax receipt and transfers the router's entire
selected-token balance, which can include dust, to the signed beneficiary.

Permit-bearing removal routes remain known calls that hard-refuse clear
signing. This bundle grants no authority to other routes, other deployments,
fallback/blind signing, live-state success, hardware readiness, or shipment.
