# docs/archive — quarantined historical docs

These files were moved out of `docs/` in the **2026-06-18 doc reorg**. They are
kept (not deleted) for provenance. **None is current guidance** — each row below
names where the live truth lives. Cross-references elsewhere in the repo were
repointed to `docs/archive/…` at move time.

> If you landed here from a link: read the "Where the live truth is" column, not
> the archived file. Several of these describe a **superseded signing primitive**
> (SLH-DSA / SPHINCS+ SHA2-128f / ML-DSA / XMSS / "c7" / 17 KB sigs) — the project
> is all-**SPHINCS+C10** (4008-byte sig). `CLAUDE.md` is authoritative.

## Merged into a live doc (content folded forward)

| Archived file | Folded into | Notes |
|---|---|---|
| `companion-erc7730-integration.md` | `docs/companion/companion-erc7730-implementation-guide.md` | Earlier narrower draft. Its 2 unique pitfalls are now §9 rows of the guide; its `E73D` catalog schema was **superseded** by the guide's `P730` (§3) — do not use it. |
| `optiga-shielded-connection.md` | `docs/secure-elements/OPTIGATRUSTM/ifx-i2c-protocol.md` §3a | The Shielded Connection IS the IFX I2C presentation layer that the protocol reference stubbed out; folded in full (handshake, TLS-PRF KDF, AES-128-CCM, pairing, session save/restore). |

## Absorbed research inputs (the output is a live reference)

| Archived file | Output / live doc | Notes |
|---|---|---|
| `provisioning-research-brief.md` | `docs/provisioning/provisioning-reference.md` | The deep-research *prompt brief*; the reference is the maintained deliverable. |
| `provisioning-crosscheck-new-findings.txt` | `docs/provisioning/provisioning-reference.md` + `docs/production-todo.md` | Scratch cross-check; every finding was folded into the reference (and the SWAP_BANK ship-blocker into production-todo). |

## Bannered-stale / superseded design snapshots (provenance only)

| Archived file | Why archived | Where the live truth is |
|---|---|---|
| `ai-research-briefing.md` | States the **wrong signing primitive** (SLH-DSA 17 KB + ML-DSA bootstrap) — a paste hazard. | `CLAUDE.md` (current architecture); its §5 corrected-facts table is historical. |
| `pq-aa-wallet-design.md` | Original two-tier design (ML-DSA-44 / XMSS / dual verifier) superseded by all-C10. | `CLAUDE.md` §Recovery, `contracts/smart-wallet/`. |
| `sphincs-c7-firmware-integration.md` | Self-bannered OBSOLETE; describes the deleted C7 (keccak256, 3704-B) signer. | `CLAUDE.md` invariant #5 (all-C10). |

## Completed point-in-time handoffs (work shipped; residuals tracked elsewhere)

| Archived file | What it handed off | Live residuals (if any) |
|---|---|---|
| `handoff-erc7730-phase2.md` | Host IR compiler + Merkle DB + xtask (Phase 2). | Wire formats live in `docs/companion/erc7730-integration.md`. |
| `handoff-erc7730-phase3.md` | Sign-input trailer wiring + walker + EIP-712 typed offchain (Phase 3). | As above. |
| `handoff-erc7730-phase5.md` | Final audit-polish (Phase 5). | Remaining clear-sign gaps: `docs/companion/companion-erc7730-implementation-guide.md` §12; misc residuals in `docs/work-todo.md` "Archived-handoff residuals". |
| `handoff-modularity-refactor.md` | Workspace-crate extraction phase plan. | Unfinished phases captured in `docs/work-todo.md` "Archived-handoff residuals". |
| `handoff-unsafe-reduction.md` | Per-peripheral MMIO → `hw::mmio` migration. | §3 migration queue captured in `docs/work-todo.md` "Archived-handoff residuals"; CLAUDE.md unsafe taxonomy is the live reference. |
| `handoff-verity-c10-verifier.md` | Multi-quarter plan to port the Yul verifier into the Verity Lean EDSL. | **Approach superseded** by the live Aeneas→Lean track (`docs/verification/verification-targets-2026-06.md`, `contracts/verification/`). |
| `verity-v0.1.0-primitive-map.md` | Companion recon of Verity v0.1.0's API + gap table (Phase-0 of the above). | As above — superseded by Aeneas. |
| `calldata-decoding-handoff.md` | Phase-2 calldata typed-args decode design + a Phase-3 sketch. | Phase-2 decode shipped (`secure/src/tx/typed_call/`). Its Phase-3 "Migration to ERC-7730 per-contract attestation" sketch **became the shipped ERC-7730 descriptor system** (`secure/data/erc7730/policy.toml`, `secure/src/tx/erc7730.rs`); reachable via `docs/companion/companion-selector-decoding.md §13`. No open residual. |
