# PQ Smart Wallet — Base Sepolia deployed integration test + red-team

**Date:** 2026-05-27 · **Chain:** Base Sepolia (84532) · **EntryPoint:** v0.6 `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`

End-to-end on-chain validation of the post-quantum ERC-4337 wallet contracts
(`PQSmartWallet`, `PQSmartWalletFactory`, `SPHINCsC10Asm`) against the **real**
on-chain SPHINCS+C10 Yul verifier, followed by an adversarial suite. The
contracts both **do what they should** (deploy → account creation → UserOp →
key rotation) and **resist what they shouldn't** (18/18 attacks blocked).

> **Source intentionally NOT published.** The contracts are deployed as raw
> bytecode only — no Basescan/Sourcify verification. The deployed bytecode is
> inherently public on-chain but carries only the metadata-hash trailer, not
> source.

## Deployed contracts (unverified)

| Contract | Address |
|----------|---------|
| `SPHINCsC10Asm` (verifier) | `0x472294ddaba57c98a47f5f0a5483f7ef7e8a78fe` |
| `PQSmartWallet` (impl) | `0x4c3d793c1aa7296fef68da5730515fca6458e219` |
| `PQSmartWalletFactory` | `0xb903d72c61be8c67c3311ce53e0a2db6626ef133` |
| Test wallet (proxy) | `0x31D58586a6f4B6DaCb4D0f9918a1F59661c61f3e` |

The deployed verifier's runtime codehash equals the audited pin
`0x919cf8ef…89c0` (it has no immutables), i.e. the on-chain verifier is
byte-identical to the reviewed bytecode. The impl/factory codehashes differ
from their pins by construction (they bake in chain-specific immutables);
their immutables were instead checked directly (below).

## Methodology

- **Signatures.** A local host signer (`tools/pqtest_signer`, see below) built
  on the workspace `sphincs-c10` crate produces genuine 4008-byte C10
  signatures over the exact digests the contracts compute. The host `sha2`
  path is byte-identical to the on-chain SHA-256-precompile verifier (proven by
  `PQSmartWalletRealSig.t.sol`), so a host-signed sig that the Rust verifier
  accepts also verifies on-chain. **Three distinct C10 signature types were
  exercised on-chain:** the factory squat-defence `factorySig`, a slot-key
  UserOp signature, and a bootstrap-key rotation signature.
- **Keys.** Derived deterministically from test *labels* (`test-bootstrap-v1`,
  `test-slot0-v1`, `test-slot1-v1`, …) — never a real mnemonic. Testnet ETH only.
- **Bundling.** UserOps were submitted directly to `EntryPoint.handleOps` with
  the `mhaas` EOA acting as bundler + beneficiary (no external bundler). Every
  signing/UserOp tx was dry-run via `eth_call` before broadcast.
- **Account.** All transactions signed by the password-protected `cast` keystore
  account `mhaas` (`0x3a4e6eD8B0F02BFBfaA3C6506Af2DB939eA5798c`).

## Functional validation — all green

| Step | Tx | Result |
|------|----|--------|
| Deploy (verifier, impl, factory) | 3 CREATE2 txs | deterministic addresses; verifier codehash == audited pin |
| Config read-back | — | `impl.entryPoint`==EntryPoint v0.6, `impl.c10Verifier`==`factory.c10Verifier`==verifier, `factory.implementation`==impl, `impl.nextOwnerIndex`==1 (impl locked) |
| `createAccount` | `0xee2a0c1a…f63ca7` | **factorySig verified on-chain** → wallet deployed; owners {0: master, 1: slot0}; `bootstrapUses`/`slotUses`==0 |
| Mock UserOp (slot key) | `0xd876100e…fd44dc` | `validateUserOp` C10-verifies the slot sig → `executeWithOffchainCount` transfers 12345 wei; `slotUses(1)` 0→1; `UserOperationEvent success=true` |
| Type-1 rotation (bootstrap) | `0x0ea1e16a…02e770` | `addOwnerBytes` installs slot1 at index 2; `bootstrapUses` 0→1; `AddOwner`+`BootstrapUsed` emitted |

The rotation is the path repaired by the EntryPoint-guard fix
(`addOwnerBytes`/`removeOwnerAtIndex` gated on the EntryPoint, not
`address(this)`); before the fix it reverted `NotFromSelf`. Its success here is
**on-chain proof the fix works**, complementing the unit suite + merged PR.

## Adversarial round — 18/18 attacks blocked

Read-only attack simulations (`eth_call`/view, impersonating arbitrary
`msg.sender` via `--from`; no txs, no state changed). Each row is an attack
that must be rejected; the decoded revert reasons confirm the *specific*
defense fired.

| # | Attack | Defense |
|---|--------|---------|
| A1 | Create a wallet with a forged `factorySig` | `InvalidFactorySignature` |
| A2 | Replay a `factorySig` from another chain | digest chain-bound → rejected |
| A3 | Wrong `chainId` parameter | `WrongChainId` |
| A4 | Reuse a `factorySig` with a swapped slot0 | digest slot0-bound → rejected |
| B1 | EOA calls `validateUserOp` directly | `NotFromEntryPoint` |
| B2 | EOA drains the wallet via `executeWithOffchainCount` | `NotFromEntryPoint` |
| B3 | EOA mints an owner via `addOwnerBytes` | `NotFromEntryPoint` |
| B4 | Self-call into `addOwnerBytes` (H-2 mint path) | `NotFromEntryPoint` (the guard added by the fix) |
| B5 | `executeWithOffchainCount` with no validated UserOp | reverts (H-3 transient-token guard) |
| B6 | Install a non-N-masked owner | `InvalidNMaskLayout` |
| C1 | Slot key signs `addOwnerBytes` (mint) | role-split → `AA24 signature error` |
| C2 | Bootstrap key signs `executeWithOffchainCount` (spend) | role-split → `AA24` |
| C3 | Garbage C10 signature | on-chain verifier → `AA24` |
| C4 | Valid sig by a non-registered key | verify vs slot0 pubkey → `AA24` |
| C5 | Tamper the signature-wrapper tail-pad (L-1) | tail-pad check → `AA24` |
| C6 | Replay a consumed nonce | `AA25 invalid account nonce` |
| D1 | EIP-1271 with the bootstrap key | rejected (no `0x1626ba7e` accept magic) |
| D2 | EIP-1271 with a garbage slot signature | rejected (no accept magic) |

The self-call owner-mint (audit H-2) is blocked two ways on-chain:
`SelfCallForbidden` in the execute path **and** the EntryPoint guard on
`addOwnerBytes` (B4). EIP-1271 forgeries revert during Solady's nested-EIP-712
unwrap rather than returning `0xffffffff`; either way no accept magic is
returned, and the happy path (`0x1626ba7e` for a properly-nested slot sig) is
covered by `test_isValidSignature_happyPath`.

## Conclusions

- The deployed contracts behave correctly under legitimate use and resist the
  adversarial cases above. Squat-defence, EntryPoint-only authorization, the
  bootstrap/slot role-split, the on-chain C10 verifier, signature-wrapper
  malleability hardening (L-1), N-mask enforcement (I-2), and replay protection
  all hold on-chain.
- The EntryPoint-guard fix (owner add/remove) is validated live, not just in
  unit tests.

## Caveats & open items

- **Source confidentiality:** contracts are unverified on Basescan by design.
- **Test scope:** test keys + testnet ETH only; not a production deployment.
- **Known Medium (not exercised here):** the H-3/M-1 transient tokens assume
  validate→execute adjacency that ERC-4337 v0.6 does not guarantee across a
  *multi-op same-sender bundle*. Not exploitable for theft (worst case the
  bundled ops revert); the single-op tests above don't trigger it.
- **Formal verification:** the Halmos A3 bridge discharge is `pending-rerun`
  against the post-fix bytecode (see `AXIOM_STATUS.json`); independent of this
  on-chain campaign.

## Reproducing (local tooling — NOT in this repo)

The scripts and host signer used for this campaign are kept **local and
git-excluded** (not published, per the source-confidentiality constraint):

- `deploytest/01_preflight.sh` … `06_challenge_assumptions.sh` — the staged
  scripts (deploy, config, createAccount, UserOp, rotation, red-team), each
  self-logging to `deploytest/logs/`. Read-only checks run directly; every
  state-changing tx is signed by the `mhaas` keystore.
- `tools/pqtest_signer/` — standalone host C10 signer (subcommands `keypair`,
  `factory-sig`, `userop-sig`, `verify`) over the `sphincs-c10` crate.

Both are listed in `.git/info/exclude`; only this report is committed.
