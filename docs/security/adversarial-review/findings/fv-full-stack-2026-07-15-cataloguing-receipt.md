---
surface: fv
run_date: 2026-07-15
reviewer_role: supplemental
reviewer_identity: "Codex coordinator — post-freeze cataloguing only"
effort: "identity/digest validation and documentation catalogue mutation"
backend: "local SHA-256, git identity, and Markdown validation"
scope: "Catalogue the immutable dual-review reports, coordinator synthesis, roadmap, surface map, provenance, and open work after target freeze"
stage: multi-stage
frozen_identity: "sha256:ad0de135a1f043d31bf7f9d73648ad813f9a45ed42192a5bb0b59fc20b9be3d0"
status: resolved
---

# FV full-stack review — post-freeze cataloguing receipt — 2026-07-15

## Purpose and authority

This receipt records the documentation-only mutation performed **after** the
review target, both first passes, and both cross-adjudications were frozen. It
does not alter the reviewed identity, close any finding, authorize
implementation, approve a merge, or authorize shipment. It deliberately has no
self-digest field: changing this file to record its own digest would make the
value false.

## Frozen target identity

| Field | Value |
|---|---|
| Repository / branch | `PQSigner_OS` / `fix/sweep-2026-07-14-findings` |
| HEAD | `ddc7cefc35cb54e324dac94330c6ee86f9383c90` |
| Frozen tracked-diff SHA-256 | `6d9a66f6832ce47fa20762480433349ff0b2b9831e9adb2991199ff3278422a4` |
| Frozen status SHA-256 | `d1b72a5c68dc2488479f847e1c20eab770b1b545fba81e23eaeaaa169a9589cd` |
| Packet-supplied aggregate content identity | `ad0de135a1f043d31bf7f9d73648ad813f9a45ed42192a5bb0b59fc20b9be3d0` |
| Neutral packet | `74f9716f744dbab0d376096a05fc75db28e008d389ff2ddb749df8e1c54ead82` |
| Cross packet | `cf2bdc6c1e911019155c007f9a34c8f275fc109f4c7ea7a31aa20cbbfef49972` |
| Drift through reviewer completion | none in the read-only frozen trees |

The worktree was intentionally dirty before this review. Existing modified and
untracked files belong to concurrent/user work. The review used isolated copies
and did not rewrite them. Immediately before this receipt, after the authorised
documentation catalogue updates but excluding this receipt itself, the live
tracked-diff SHA-256 was
`a5e2dce48561040191521be38f2b2088a73c835adffc8d15efc57e479f558612`
and the live status SHA-256 was
`a1595e6b5b34cf8107afedbce0c226f0ffadf9f6f9d61184fb9f90143af6f8d1`.
Those are catalogue-state receipts, not new reviewed-target identities.

## Required reviewer artifacts

| Artifact | Identity / effort | Bytes / lines | SHA-256 |
|---|---|---:|---|
| [`partner-a-first-pass`](./fv-full-stack-2026-07-15-partner-a-first-pass.md) | Claude Code Opus 4.8, `max`; mutually withheld | 41,535 / 227 | `5afe1f48de1847281bdbb3e10e5ce2f9e18e4faff95c34599a1c755be19722f8` |
| [`partner-b-first-pass`](./fv-full-stack-2026-07-15-partner-b-first-pass.md) | GPT-5.6 SOL, `ultra`, Codex CLI 0.144.4; mutually withheld | 49,814 / 462 | `9b8a4264ee8430075466ab43e60904496408df67e0563d16a48906b2eb8e9cef` |
| [`partner-a-cross`](./fv-full-stack-2026-07-15-partner-a-cross.md) | Claude Code Opus 4.8, `max`; symmetric cross | 29,242 / 174 | `339c2d98bad1b5198e7fcdeef42961c94b23f4fb1024868571fcdfeb472a89e1` |
| [`partner-b-cross`](./fv-full-stack-2026-07-15-partner-b-cross.md) | GPT-5.6 SOL, `ultra`; symmetric cross | 28,918 / 275 | `ac2ed51b2c386f80237819e8ebed2d83b615b5ef289b21d4a35c21e45763fb27` |
| [`coordinator synthesis`](./fv-full-stack-2026-07-15-coordinator.md) | executing/sourced, preserves severity disagreements | 27,958 / 462 | `7d88a0372c4739442af4222d8b64da6705f6fa0d520a9eca7afc73b41449f1d7` |

The four partner Markdown files were copied without normalization. Their
repository SHA-256 values exactly match the frozen scratch artifacts, including
their original lack of a terminal newline. They were not wrapped, reformatted,
or given new frontmatter.

## Prompt, envelope, and retry provenance

| Item | SHA-256 / result |
|---|---|
| Partner A first-pass prompt | `f3a96a48fffb4f72ed785c8af74b3c238d72db7a0b8c4fdd26f87bcfd8c7eae1` |
| Partner A first-pass JSON envelope | `a4d5a49d29697b503922abf74ffb6658170f6fa81198f6ec98e9fa979e9b73e4`; success |
| Partner A original cross prompt | `64ad09a8f0f674b9039b3a36bb854ba05bbf3234c78cecbec4702f5df0868011` |
| Partner A invalid cross envelope | `86d662c02d8d4f9455872da3654942a4146a91b63e219570a886b52c620a457d`; `API Error: Connection closed mid-response`; excluded from evidence |
| Partner A unchanged-packet retry prompt | `529e7d78d0313c77f915a36a8e51c30e841decaab05ba971e11989d7f68e18a5` |
| Partner A successful cross JSON envelope | `5734102d94bca593bd37e8e5f546b5eb6a1c5ebb2b640a84072b504b5f469daf`; `subtype=success`, `is_error=false`, 32 turns; model usage records `claude-opus-4-8` |
| Partner B cross prompt | `9aa86ee0c41e16d008da85881e4b6e6bbedf4ea748f84e04a9edf799a7ab6a93` |

Both cross reports contain a disposition for every A-F1 through A-F7 and B-F1
through B-F14. The invalid Opus attempt supplied no conclusion and was not
merged with the retry.

## EasyCrypt/sibling correction and durable execution receipts

| Item | Value |
|---|---|
| `c10-eufcma-port` | HEAD `70974e90723153a0af151626b5921dd33a025773`, clean |
| MM45 SPHINCS+ | HEAD `a28e4c53897a4bb57b575a177225862d48f824b7`; tracked diff `7b019433601404906510abf06771c837c88c6aa6bd9d85282429021231f3bdf3` |
| MM45 XMSS | HEAD `fa90ebc250be32262bf88f9bcf7b9375dc04dc11`, clean |
| Tx-Merkle regeneration log | `d0abb9ad7695b361bc0ef64abb7b4318d2769271ac1fa1617f6a193380947ff9` |
| extracted arbitrary-axiom canary log | `3ea1e0d4330317294a46d1f38a38f39223a25ea339d5eedfd8dcc70a2c979362` |
| corrected frozen-root EasyCrypt run | `367ff8c538e898386ee7fef749d9cf6b60808d5449d6d2a151a41581cfed9056`; 10/21 compiled, 11 skipped, exit 0 |

The earlier MM45 diff value ending `…b876…` and the original inert
`MM45_ROOT` environment prefix were coordinator receipt defects. The corrected
diff was independently reproduced; the EasyCrypt command was rerun with the
actual `EC_FV_ROOT` input. This narrows provenance but confirms the substantive
skip-as-success result.

## Authored documentation artifacts

| Artifact | SHA-256 before this receipt |
|---|---|
| [`coordinator findings`](./fv-full-stack-2026-07-15-coordinator.md) | `7d88a0372c4739442af4222d8b64da6705f6fa0d520a9eca7afc73b41449f1d7` |
| [`research/expansion roadmap`](../../../verification/formal-verification-assurance-expansion-2026-07-15.md) | `306a0b305cedc822de1106a9eb82b10bb3c61e5593bd9b15d9f65daa327d775d` |
| [`nine-surface map`](../../../../contracts/verification/docs/FV_SURFACE_MAP.md) | `c1e9d11b05d01f4accdd5a40c07a5e50a63912c21ef70dabce32108bbda33985` |
| [`review provenance`](../../../../contracts/verification/docs/REVIEW_PROVENANCE.md) | `54d22c8ad69205caf8485cf6b7e9bb5cd455c016a7bff9ebe1922b465caf61b1` |

The same documentation-only change set added dated status corrections to the
current claim/assurance/proof-map/status/README documents, expanded the FV
playbook with EasyCrypt and the exact dual-review protocol, and added eleven
open implementation/research items plus the roadmap decision to
`docs/work-todo.md`. It did not change proof source, product source, contracts,
models, Makefiles, workflows, tool implementations, or release state.

## Validation and residual

- `git diff --check`: PASS before this receipt.
- All four raw report SHA-256 values match their frozen sources exactly.
- Both cross reports contain all 21 required finding IDs.
- Markdown link validation was run on authored/modified current documents; raw
  immutable reports retain their original scratch-path anchors by design.
- No proof/build aggregate was rerun after documentation cataloguing because no
  proof, source, model, gate, or build input was changed.

Open findings remain open in the coordinator report and `docs/work-todo.md`.
This receipt resolves only the cataloguing operation.
