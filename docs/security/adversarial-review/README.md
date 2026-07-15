# Adversarial-review playbooks — system security surfaces

This directory holds **adversarial review playbooks**, one per major non-FV attack surface of PQSigner_OS. Each is a reusable recipe + a copy-paste **master prompt** for tasking an agent (or an N-way swarm) to *break* a surface's asserted security property rather than confirm it — the same discipline as the [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md), transposed off the Lean tree onto firmware, hardware integration, lifecycle, configuration, and release operations.

## What these are (and are not)

- **They ARE** review guides for **claim-vs-code/config/process drift and fail-open / vacuity**: walking each subsystem and its evidence against the invariant it claims to uphold, hunting a decoder that renders but doesn't bind, a veneer that derefs before validating, a counter the reconcile logic doesn't check, a gate a single fault skips, or a release receipt that names different bytes. Each catalog row is anchored to a **real gate or near-miss in this tree**, exactly as the FV playbook anchors its V1–V11 catalog to real EF findings.
- **They are NOT** the silicon bench plan. [`docs/security/red-teaming.md`](../red-teaming.md) already enumerates the *bench pass-fail bars* (glitch rigs, logic-analyzer bus captures, desolder attacks, TVLA on real traces, `make gtzc-enforcement-hw`). These playbooks are the **source/configuration/process-review counterpart**; hardware-facing playbooks cross-link red-teaming.md as their bench sibling and do **not** re-list its checks. Where a property can only be settled on silicon, the playbook says so and points to red-teaming.md.

## The playbooks

| Playbook | Surface | Invariant defended | Cardinal failure |
|---|---|---|---|
| [clear-signing](./clear-signing-adversarial-review.md) | ERC-7730 + EIP-712 decoders, display renderers, Merkle bundles | Trusted display (Claim 9) | Page renders X, signature commits to Y (WYSIWYS break) |
| [trustzone-gateway](./trustzone-gateway-adversarial-review.md) | NSC veneers, NS-pointer validation, SAU/GTZC | #4 secrets only in S-world | Malicious NS crosses the boundary / extracts a secret / TOCTOU |
| [secure-element](./secure-element-adversarial-review.md) | OPTIGA + SE050 drivers, provisioning, PIN lockstep | #1 XOR split, #2 PIN lockstep, #3 SE tunnels | Plaintext secret on I2C / PIN-counter desync / advertised≠actual |
| [sca-fi](./sca-fi-adversarial-review.md) | FI-hardened sign chain, FI primitives, CT compares, zeroize | Single-fault safety + trace secrecy | One glitch forges a sig / one trace leaks a key bit |
| [firmware-update + secure-boot](./firmware-update-secure-boot-adversarial-review.md) | `fw_update/`, `fw-manifest/`, `fwsign/`, `fsbl/`, measured-boot | Claim 8 + boot integrity | Unsigned/downgraded image runs / brick / fingerprint spoof |
| [usb + compromised-companion](./usb-companion-adversarial-review.md) | NS-side USB stack + the hostile-companion threat model | Hostile-host containment | A companion attack with no on-device defense / gateway-crossing frame |
| [off-chain signing](./offchain-signing-adversarial-review.md) | EIP-1271/6492 + the page-123 counter state machine | #9 anti-forgery binding | Companion nests a hash → UserOp forgery oracle / counter rollback |
| [on-chain contracts](./onchain-contracts-adversarial-review.md) | `PQSmartWallet`/`Factory`/`PQMultiOwnable`/Yul verifier (Solidity, beyond `theft_free`) | Solidity-level safety | Reentrancy / cross-slot auth / storage collision the Lean proof doesn't reach |
| [trusted-UI / confirm-path](./trusted-ui-adversarial-review.md) | confirm dialog, PIN entry, seed wizard, buttons, timer | Physical-consent gating | Sign without a genuine confirm / NS spoofs consent / timer bypass |
| [silicon-lockdown hardening-depth](./silicon-lockdown-adversarial-review.md) | STM32U5 option bytes (RDP/WRP/HDP/OTP/debug), OPTIGA LcsO ratchet, SE050 lockdown, secure-boot immutability | Hardening depth (no single-point collapse) | A reversible/un-fenced/mis-ordered lockdown layer sinks the stack |
| [lifecycle + persistent state](./lifecycle-persistent-state-adversarial-review.md) | factory/transit/first boot, provisioning, flash + SE state, wipe/restore, recovery, RMA/decommission | Cross-store atomicity, truthful recovery, and lifecycle authority | Power loss or a discarded backend error leaves split-brain state, a false READY/WIPED receipt, or a durable brick |
| [entropy + key lifecycle](./entropy-key-lifecycle-adversarial-review.md) | STM32/OPTIGA/SE050 RNGs, wallet entropy, KDF roots/domains/nonces, OptRand/shuffles, zeroization | Exact-fill fail-closed entropy and domain-separated key lifecycle | A source is silently dropped/short, a weak root is selected, a nonce/key repeats, or two roles derive the same key |
| [secure runtime + resources](./secure-runtime-resource-adversarial-review.md) | unsafe/MMIO, `static mut`, exceptions/IRQs, stack/RAM, watchdog, reset cleanup, init order | Sound bounded execution under every permitted schedule | ISR alias/stack collision/false watchdog progress/fault residue compromises or wedges S-world |
| [production configuration + prodtest](./production-configuration-prodtest-adversarial-review.md) | Cargo cfg/features, paired S/NS/FSBL artifacts, compile/CI gates, PIN-less factory diagnostics and fixture | The reviewed/tested configuration is the exact candidate binary | Dev/prodtest code ships, worlds mismatch, a stub counts as PASS, or evidence exercised another cfg |
| [build, release, provenance + key custody](./build-release-provenance-adversarial-review.md) | source/toolchain/codegen, reproducibility, `fwmeasure`/`fwsign`, HSM/quorum, SBOM/provenance, package/distribution | Authorized source-to-published-artifact identity | Wrong/unreviewed bytes are signed or published, the legitimate key is abused/lost, or provenance names another artifact |

The [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md) covers the FV surface family — the Lean on-chain proofs + the firmware Kani vacuity — and carries the shared "green ≠ sound" thesis all of these inherit.

Several playbooks are **cross-cutting lenses** rather than single subsystems.
They are additive: apply every lens intersecting the change rather than choosing
one as a substitute for the subsystem owner.

- **[usb + compromised-companion](./usb-companion-adversarial-review.md) — the outer-attacker anchor**: what a fully-hostile host can attempt across *every* flow, each attack mapped to the on-device defense in the playbook that owns it. Start here for the end-to-end remote-attacker view.
- **[silicon-lockdown hardening-depth](./silicon-lockdown-adversarial-review.md) — the lockdown-depth lens**: whether the irreversible production hardening stack (RDP/WRP/OTP/debug + OPTIGA LcsO + SE050 lockdown + secure-boot) is deep, *enforced* (compile-fence + blocking `prod-check-ship`), correctly *ordered*, and un-bypassable — using an (a) enforced / (b) deferred-by-design / (c) unenforced taxonomy where only (c) is a review target. Start here to judge whether "hardened" is enforced or merely intended.
- **[lifecycle + persistent state](./lifecycle-persistent-state-adversarial-review.md) — the state-composition lens**: whether factory, first boot, update, wipe/restore, recovery, and RMA agree across MCU + both SEs at every power-cut boundary.
- **[entropy + key lifecycle](./entropy-key-lifecycle-adversarial-review.md) — the byte-origin lens**: which sources, roots, context bytes, freshness epochs, and wipe boundaries actually determine every key/nonce/random output.
- **[secure runtime + resources](./secure-runtime-resource-adversarial-review.md) — the execution-composition lens**: whether unsafe preconditions, exception schedules, stack/RAM bounds, watchdog progress, and reset cleanup hold on the exact target.
- **[production configuration + prodtest](./production-configuration-prodtest-adversarial-review.md) — the selected-program lens**: whether resolved cfg/features, paired worlds, factory tests, gates, and exact ELF contents match the evidence being cited.
- **[build, release, provenance + key custody](./build-release-provenance-adversarial-review.md) — the off-device authority lens**: whether reviewed source/config becomes the measured, authorized, signed, attested, and atomically published bytes under a recoverable custody policy.

## Shared shape (every playbook)

- **Part A — failure catalog.** A surface-specific, stable-ID table (for example `CS*`, `TZ*`, `LC*`, `EK*`, `RT*`, `PC*`, `BR*`) of the ways the surface can look correct yet not be, each with a `Status` column that honestly separates **defended-by-construction** (with the test/gate that proves it), **claim-vs-code tension**, **by-design-leaky/limited** (a documented posture, not a bug), and **found-this-surface / reasoned-latent**.
- **Part B — existing defenses (Layer 1).** The mechanical backbone already in the tree (render harness, Kani kernels, fuzz differentials, `compile_error!` fences, HW e2e, rainbow sweeps, cargo-checkct, zeroize-audit) — so the catalog claims are anchored, not generic.
- **Part C — the master prompt.** A copy-paste brief that tasks a fresh agent to walk every catalog mode against a scoped surface, demands a **falsifiable PoC per finding** (no PoC ⇒ "suspicion, unverified"), and requires a **mandatory honest residual** (what survived, what wasn't looked at, and whether the pass *executed* the checkers or only read source).
- **Part D — cadence + honest boundary.** When to run each layer, the one-line gut check, and an explicit statement of what the playbook *cannot* tell you (the boundary — stated on purpose, because an unstated boundary is itself a coverage gap).

## Where findings go — [`findings/`](./findings/README.md)

Discovery passes return external candidate packets and never write canonical
repository state. The coordinator freezes the raw packets, preserves every
variant, and sends their union to the exact Partner-A/Partner-B pair required by
the planning workflow. **After symmetric cross-adjudication**, an authorized
maintainer records the result as a dated report in
[`findings/`](./findings/README.md) (from
[`findings/TEMPLATE.md`](./findings/TEMPLATE.md)). The four frozen partner
reports are first reconciled, without voting, in
[`findings/CROSS_ADJUDICATION_TEMPLATE.md`](./findings/CROSS_ADJUDICATION_TEMPLATE.md).
Each canonical report has
frontmatter `status:` and, because it is created only after the cross matrix
freezes, starts at `status: in-review`; every canonical finding starts at
`Status: 🔬 REVIEWED`. Later resolution moves an item to `✅ FIXED` /
`☑️ ACCEPTED` / `🚫 INVALID` / `⏸ DEFERRED`. `🔲 OPEN` is reserved for
pre-cross/imported records. `☑️ ACCEPTED` is owner-only; a discovery reviewer
may recommend acceptance but cannot set it.
The catalogue remains the review record and `docs/work-todo.md` the action
list.

## Running a pass

The framework-agnostic kit at
[`contracts/verification/adversarial-review/`](../../../contracts/verification/adversarial-review/README.md)
drives discovery fan-out backend-agnostically (`run_review.py --backend
{claude,codex,generic}`, `--reviewers N --quorum M`, `--run-id <stable-id>
--out <external-dir>`). Executing runs require an explicit output base outside
the repository and create no-clobber backend/run-ID namespaces. It was built for the FV
surface; add a per-surface angle to its `protocol.json` mirroring the existing
`kani-decoder-vacuity` angle — the persona (`PROMPT.md`) and discovery grouping
are shared; only the catalog + target files change per surface. Quorum only
corroborates/prioritizes candidates. It never sets a finding disposition, and
sub-quorum candidates are retained rather than discarded. Send every candidate,
variant/origin ID, and honest residual to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only that pair's symmetric cross-adjudication may assign
`CONFIRMED`/`REFUTED`/`NARROWED`/`UNRESOLVED`.

For two tool-produced receipts, use `run_review.py --union-raw
<partner-a-raw.json> <partner-b-raw.json> --out <external-dir>`. The
content-addressed envelope retains both complete raw payloads and diagnostics;
it performs no cross-run grouping, re-voting, disposition, or authority grant.

For a quick one-off, paste a playbook's Part-C prompt into any agent chat and
fill the `{{…}}` scope slot. For model diversity, run twice across two backends
and union all candidates, retained variants, and honest-residual blocks before
the required exact-pair adjudication.

## Cadence summary

- **Per-PR touching a surface:** its Layer-1 gates + a scoped Part-C pass on the changed code.
- **Per-milestone:** full-scope Part-C swarm per surface, paired with the matching red-teaming.md bench section.
- **Pre-ship:** the deferred lifecycle/silicon/factory/release work (first-boot transition, OPTIGA lockdown, bench FI/SCA, key rotation, exact production artifacts, HSM custody and publication ceremony) — tracked by the applicable owner documents + `docs/STATUS.md`, not authorized by these playbooks.

> **The one-sentence boundary shared by all listed playbooks.** *An executing pass may report that it reproduced no break within its recorded scope, configuration, and evidence level; it cannot establish that every covered or uncovered path is sound, that silicon matches source assumptions, or that a source-only pass executed the claimed behavior.* That sentence — not a green checkmark — is what to hand an auditor.
