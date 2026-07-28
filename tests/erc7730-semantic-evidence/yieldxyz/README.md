# Yield.xyz POL validator and USDe vault evidence

This package pins the two residual Yield.xyz calldata descriptor families used
by PQ1 to Ethereum block `25,630,720` (`0x1871800`). dRPC and MEV Blocker
independently returned the same block hash, state root, runtime bytes, proxy
bindings, token/configuration calls, and metadata recorded in `rpc/`.

## POL validator shares

All seventeen descriptor destinations have the same
`ValidatorShareProxy` runtime and returned implementation
`0xBe63B977ABBAA99fC0243e208340c530Dd4ee9E8` from `implementation()`.
The fully verified `ValidatorShare` source and its exact fixed-block runtime
bind four admitted routes:

- `buyVoucherPOL` spends no more than the signed POL amount because whole-share
  rounding can clamp the deposit down; it enforces the signed minimum shares
  and also claims the caller's accrued POL rewards;
- `sellVoucher_newPOL` queues the signed requested POL amount, enforces the
  signed maximum shares burned, and also claims accrued POL rewards; the later
  claim payout uses the live withdrawal exchange rate;
- `unstakeClaimTokens_newPOL` consumes the signed caller-bound unbond nonce and
  pays the caller an amount derived from queued state and the live withdrawal
  rate;
- `withdrawRewardsPOL` pays the caller a live state-derived reward amount.

Every calldata operand is visible. The descriptor explicitly names the
rounding and live-state residuals instead of presenting them as exact outputs.

## USDe allocator vault

The descriptor destination is an EIP-1967 transparent proxy whose fixed-block
implementation slot resolves to
`0xA7249e2902B956e7127dF56BF45D58Cff610d832`. The captured proxy calls bind:

- underlying USDe at `0x4c9EDD5852cd905f086C759E8383e09bff1E68B3`;
- strategy/asset sUSDe at `0x9d39A5de30e57443bff2a8307a4256c8797a3497`;
- 18-decimal `stk-USDe` vault shares; and
- `hasCooldown = true` in the fixed-block vault configuration.

Only `deposit(uint256,address)` is admitted. It authenticates the exact USDe
spend and receiver, while the minted stk-USDe amount depends on live rates and
fees and has no signed minimum. Three sibling selectors remain structural
exact-known refusals:

- `mint` computes the USDe spend from live state without a signed maximum;
- cooldown-enabled `withdraw` and `redeem` transfer state-derived sUSDe
  strategy shares rather than the descriptor's advertised exact USDe output,
  and also derive a burned-share or output amount from state.

`collect.sh` deterministically re-captures the fixed-block RPC and Blockscout
records and fails if an RPC response remains incomplete after bounded retries.
`manifest.json` receipts every offline artifact by byte count and SHA-256.

This is historical source/runtime and signed-input meaning evidence. It is not
live monitoring and grants no authority for future proxy upgrades,
configuration or rate changes, transaction success, fallback, blind signing,
production, shipment, or irreversible action.
