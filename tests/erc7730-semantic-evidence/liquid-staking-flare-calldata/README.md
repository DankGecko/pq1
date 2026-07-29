# Liquid-staking and Flare calldata evidence

This package pins seven residual ERC-7730 source families to exact historical
deployments, runtime bytes, verified source/ABI records, immutable or
fixed-block configuration, and token meaning. It covers:

- BENQI sAVAX on Avalanche;
- Ethena sUSDe and Swell rswETH on Ethereum;
- DistributionToDelegators, PollingFoundation, and ValidatorRewardManager on
  Flare; and
- PollingFoundation on Songbird.

The four chain snapshots were captured within eight seconds of one another on
2026-07-28. `fixed-block-receipt.json` records their exact block hashes, state
roots, deployments, proxy bindings, and configuration observations.
`collect.sh` deterministically replays every fixed-block request and downloads
the corresponding verified explorer records. `manifest.json` receipts every
offline artifact by byte count and SHA-256.

## Admitted liquid-staking meaning

The sAVAX proxy resolves to the verified `StakedAvax` implementation.
`submit()` authenticates the exact native AVAX paid, but minted sAVAX depends on
the live exchange rate and has no signed minimum. `requestUnlock` authenticates
the exact shares entering caller-bound custody; AVAX returned later is
state-derived. The four redemption forms consume caller-bound unlock state or
overdue shares and return live-rate AVAX or sAVAX. Those residuals are explicit
warnings, not presented as exact outputs.

Ethena's deployed `StakedUSDeV2` is direct code, not an EIP-1967 proxy.
`cooldownShares` burns the exact signed sUSDe shares and derives queued USDe;
`cooldownAssets` queues the exact signed USDe amount and derives burned shares.
`unstake` chooses the exact receiver but withdraws the caller's full cooldown
state, so its amount is deliberately described as state-derived.

The rswETH proxy resolves to the verified `RswETH` implementation. Standard
ERC-20 and whitelist routes display every calldata operand. Deposits display
the signed native amount or `msg.value`, recipient/referral, and signed minimum
where one exists. Repricing displays all three signed accounting inputs and
warns that configured live recipients receive the derived rewards.
`withdrawERC20` moves the contract's full live token balance to an authenticated
admin signer; it does not pretend the amount is signed.

## Admitted Flare and Songbird meaning

Distribution claims show reward owner, recipient, month, and native/wrapped
payout choice while warning that the amount is calculated from live state.
Opt-out confirmation shows the complete signed address list.
`autoClaim(address[],uint256)` remains an exact-known refusal because mutable
ClaimSetupManager state expands the signed reward-owner list into additional
claim/delegation accounts and applies a live executor fee that the descriptor
cannot authenticate.

Both PollingFoundation deployments admit vote casting and the non-executable
proposal overload. Vote support is rendered as the source enum, and all six
non-executable proposal settings are visible. The executable overload remains
an exact-known refusal because it carries arbitrary `bytes[]` calls and a
target/value/calldata topology that PQ1 cannot safely authenticate.

ValidatorRewardManager claims show the exact requested amount, owner, recipient,
and payout choice. The executor and recipient setters show their complete
replacement lists and warn that an empty list clears the corresponding
authorization set.

This is historical source/runtime and signed-input meaning evidence. It is not
live monitoring and grants no authority for future upgrades or configuration,
rates, balances, proposal execution, transaction success, fallback, blind
signing, production, shipment, or irreversible action.
