# Adversarial-review playbooks — firmware / hardware surfaces

This directory holds **adversarial code-review playbooks**, one per major non-FV attack surface of PQSigner_OS. Each is a reusable recipe + a copy-paste **master prompt** for tasking an agent (or an N-way swarm) to *break* a surface's asserted security property rather than confirm it — the same discipline as the [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md), transposed off the Lean tree onto the firmware/hardware code.

## What these are (and are not)

- **They ARE** code-review guides for **claim-vs-code drift and fail-open / vacuity**: walking the source of each subsystem against the invariant it claims to uphold, hunting a decoder that renders but doesn't bind, a veneer that derefs before validating, a counter the reconcile logic doesn't check, a gate a single fault skips. Each catalog row is anchored to a **real gate or near-miss in this tree**, exactly as the FV playbook anchors its V1–V11 catalog to real EF findings.
- **They are NOT** the silicon bench plan. [`docs/security/red-teaming.md`](../red-teaming.md) already enumerates the *bench pass-fail bars* (glitch rigs, logic-analyzer bus captures, desolder attacks, TVLA on real traces, `make gtzc-enforcement-hw`). These playbooks are the **code-review counterpart**; each cross-links red-teaming.md as its bench sibling and an input, and does **not** re-list its checks. Where a property can only be settled on silicon, the playbook says so and points to red-teaming.md.

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

The [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md) covers the FV surface family — the Lean on-chain proofs + the firmware Kani vacuity — and carries the shared "green ≠ sound" thesis all of these inherit.

Two playbooks are **cross-cutting lenses** rather than single subsystems, and both work by mapping across the others:
- **[usb + compromised-companion](./usb-companion-adversarial-review.md) — the outer-attacker anchor**: what a fully-hostile host can attempt across *every* flow, each attack mapped to the on-device defense in the playbook that owns it. Start here for the end-to-end remote-attacker view.
- **[silicon-lockdown hardening-depth](./silicon-lockdown-adversarial-review.md) — the lockdown-depth lens**: whether the irreversible production hardening stack (RDP/WRP/OTP/debug + OPTIGA LcsO + SE050 lockdown + secure-boot) is deep, *enforced* (compile-fence + blocking `prod-check-ship`), correctly *ordered*, and un-bypassable — using an (a) enforced / (b) deferred-by-design / (c) unenforced taxonomy where only (c) is a review target. Start here to judge whether "hardened" is enforced or merely intended.

## Shared shape (every playbook)

- **Part A — failure catalog.** A surface-specific table (`CS1–CS10`, `TZ1–TZ8`, `SE1–SE9`, `FI1–FI10`) of the ways the surface can look correct yet not be, each with a `Status` column that honestly separates **defended-by-construction** (with the test/gate that proves it), **claim-vs-code tension**, **by-design-leaky/limited** (a documented posture, not a bug), and **found-this-surface / reasoned-latent**.
- **Part B — existing defenses (Layer 1).** The mechanical backbone already in the tree (render harness, Kani kernels, fuzz differentials, `compile_error!` fences, HW e2e, rainbow sweeps, cargo-checkct, zeroize-audit) — so the catalog claims are anchored, not generic.
- **Part C — the master prompt.** A copy-paste brief that tasks a fresh agent to walk every catalog mode against a scoped surface, demands a **falsifiable PoC per finding** (no PoC ⇒ "suspicion, unverified"), and requires a **mandatory honest residual** (what survived, what wasn't looked at, and whether the pass *executed* the checkers or only read source).
- **Part D — cadence + honest boundary.** When to run each layer, the one-line gut check, and an explicit statement of what the playbook *cannot* tell you (the boundary — stated on purpose, because an unstated boundary is itself a coverage gap).

## Where findings go — [`findings/`](./findings/README.md)

**Every pass files its findings as a dated report in [`findings/`](./findings/README.md)** (from [`findings/TEMPLATE.md`](./findings/TEMPLATE.md)), so they are all in one catalogued place. Each report has a frontmatter `status:` and **each finding carries its own `Status:`** (`🔲 OPEN` → `✅ FIXED` / `☑️ ACCEPTED` / `🚫 INVALID` / `⏸ DEFERRED`), so working through a list is unmistakable at a glance — `grep -rn 'Status: 🔲 OPEN' findings/` lists everything still open. The [`findings/README.md`](./findings/README.md) holds the catalogue table + the status lifecycle; `docs/work-todo.md` stays the *action list*, `findings/` is the *review record* — cross-link them. Every playbook's Part-C master prompt instructs the agent to write here.

## Running a pass

The framework-agnostic kit at [`contracts/verification/adversarial-review/`](../../../contracts/verification/adversarial-review/README.md) drives the swarm fan-out backend-agnostically (`run_review.py --backend {claude,codex,generic}`, `--reviewers N --quorum M`). It was built for the FV surface; add a per-surface angle to its `protocol.json` mirroring the existing `kani-decoder-vacuity` angle — the persona (`PROMPT.md`) and cross-vote machinery are shared; only the catalog + target files change per surface.

For a quick one-off, paste a playbook's Part-C prompt into any agent chat and fill the `{{…}}` scope slot. For model diversity, run twice across two backends and union the honest-residual blocks into the next round's targets.

## Cadence summary

- **Per-PR touching a surface:** its Layer-1 gates + a scoped Part-C pass on the changed code.
- **Per-milestone:** full-scope Part-C swarm per surface, paired with the matching red-teaming.md bench section.
- **Pre-ship:** the deferred once-only silicon/factory work (OPTIGA lockdown, bench FI/SCA, PUT-KEY ceremony) — tracked in `docs/production-todo.md` + `docs/STATUS.md`, not here.

> **The one-sentence boundary shared by all nine.** *A playbook can tell you that no covered surface lets its invariant drift as of the last executing pass — it cannot tell you the uncovered paths are sound, the silicon behaves as the source assumes, or that a non-executing (source-only) pass proved anything.* That sentence — not a green checkmark — is what to hand an auditor.
