# Security Policy

PQSigner OS is a post-quantum hardware wallet: STM32U585 firmware (TrustZone
secure/non-secure worlds + FSBL), OPTIGA Trust M and SE050 secure elements,
SPHINCS+/C10 signing, clear-signing decoders, and the on-chain
`PQSmartWallet` contracts. Security reports are taken seriously — people's
funds are the point of the design.

## Supported versions

The project is **pre-production**: no devices have shipped and there are no
released versions. Only the current `master` HEAD of this repository is
supported. Findings against dated snapshots, archived docs, or superseded
candidates will usually be answered with a pointer to current master.

## Before you report

Known issues are tracked **openly** on the
[issue tracker](https://github.com/EthereumPhone/PQ1/issues) — please check
first whether your finding is already filed:

- [`label:ship-blocker`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Aship-blocker) — must close before any unit ships
- [`label:finding`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Afinding) — adversarial-review findings
- [`milestone:"Production ship gate"`](https://github.com/EthereumPhone/PQ1/milestones) — the live ship-readiness view

Explicitly **accepted residuals** are documented, not bugs: see
`docs/security/threat-model.md` §9 (live caveats) and the findings catalogue
in `docs/security/adversarial-review/findings/`.

## Reporting a vulnerability

- **Preferred:** open a private security advisory from this repository's
  **Security** tab ("Report a vulnerability"), if enabled for your account.
- **Otherwise:** open a *minimal* public issue that says only that you have a
  security report to share, and ask for a private contact channel. Do **not**
  include the vulnerability details, PoC, or affected code paths in the
  public issue.

Please include: affected component and `file:line` where possible, the
attacker model (hostile host/companion, physical/bench, supply chain,
remote), a falsifiable PoC or concrete reasoning trace, and whether you
believe the issue is already covered by an existing tracker item.

We aim to acknowledge new reports within **7 days**. There is currently
**no bug bounty program**.

## Scope

In scope: secure-world firmware (`secure/`, `fsbl/`), the TrustZone gateway
and NSC veneers, secure-element drivers and provisioning (OPTIGA, SE050),
PIN/wipe/lifecycle flows, entropy and key derivation, the signing and
clear-signing paths (ERC-7730/EIP-712/EIP-1271/6492), firmware update and
secure boot, trusted UI/confirm path, the Solidity contracts and factory,
and the build/release/provenance chain.

Out of scope: issues already tracked openly (above); dev-only, mock, and
QEMU-only paths that cannot ship; denial of service requiring physical
destruction of the device; attacks that require conditions the threat model
documents as accepted residuals; and reports against hardware we do not
control (upstream MCU/SE silicon errata — still welcome as information).

## Coordinated disclosure

This is a pre-ship product. Please give us reasonable time to triage, fix,
and (where relevant) complete irreversible-factory-step adjustments before
any public disclosure. We will credit reporters in the fix write-up unless
you ask otherwise. Confirmed-and-fixed vulnerabilities are documented under
`docs/security/vulns/` and cross-linked from the fixing commit and issue.
