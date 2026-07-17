BEGIN PARTNER B BOUNDED RESPONSE V1

Identity recheck:
- Partner A cross SHA-256: `d11bf34e8b6ece6eac442ef26674ea7604c816bbc8dd50804539327f32186e70`.
- Partner B cross SHA-256: `8f2310602fbd36f09994ed1de794c332f0bf1ea85dbd98f6dc1a0f00c6a2e193`.
- Target HEAD: `9647b79374d5e2e10445254492308101b8be708b`.
- Target binary-diff SHA-256: `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25`.
- Tracked delta remains exactly `docs/erc7730-implementation-review-2026-07.md` and `docs/work-todo.md`; untracked and ignored-file inventories remain empty.

Raw ID and origin: `XB-1`, origin Partner A

Disposition: CONFIRMED

Exact reproduced evidence:
- Eight unique cited path literals do not exist in the frozen target:
  - `secure/src/tx/erc7730/render/mod.rs`
  - `secure/src/handlers.rs`
  - `secure/src/tx/known_calls.rs`
  - `secure/src/confirm.rs`
  - `secure/src/tx/erc7730/formatter.rs`
  - `secure/src/tx/erc8213.rs`
  - `secure/tests/wysiwys_dispatch_differential_tests.rs`
  - `secure/src/tx/erc7730/ir.rs`
- Repetition of those paths, plus PB-AR-008’s non-path document shorthand, makes 9 of the 11 technical location blocks non-reproducible as written.
- Corrected citation map:
  - PB-AR-001: `docs/erc7730-implementation-review-2026-07.md:450`; `secure/src/tx/display/dispatch.rs:211-240`; `pqsigner-erc7730/src/render/mod.rs:30-44`; secure re-export at `secure/src/tx/erc7730_render/mod.rs:17`; metadata handling at `secure/src/nsc/cmd_sign_userop.rs:551-677`.
  - PB-AR-002: `pqsigner-erc7730/src/known_calls.rs:47-57`; `secure/data/erc7730-known-calls.bloom`; `docs/erc7730-implementation-review-2026-07.md:450-457`.
  - PB-AR-003: `secure/src/ui/confirm.rs:47-157`; `secure/src/fi.rs:296-335`; `secure/src/hw/buttons.rs:243-307`.
  - PB-AR-004: `secure/src/tx/display/blind_sign.rs:97-175`; `tx-core/src/eip1559.rs:71,134`; `pqsigner-erc7730/src/display/primitives.rs:591-717`; `secure/src/tx/display/erc8213.rs:85-113`.
  - PB-AR-005: `secure/src/tx/display/dispatch.rs`; `secure/src/nsc/cmd_sign_userop.rs:1027-1151`, especially `1105-1110`; `secure/src/nsc/cmd_sign_userop_batch.rs:891-918`; `proto/src/lib.rs:1460`.
  - PB-AR-006: `secure/src/tx/display/userop_gas_lane.rs:35-109`; `pqsigner-erc7730/src/display/render/mod.rs:907-951`; `secure/src/tx/display/erc7730/mod.rs:16-18`; `secure/src/nsc/cmd_sign_userop.rs:1345-1368`; batch insertions at `secure/src/nsc/cmd_sign_userop_batch.rs:1071-1095,1206-1230`.
  - PB-AR-007: `docs/erc7730-implementation-review-2026-07.md:531-536`; `pqsigner-erc7730/src/display/mod.rs:60-82`.
  - PB-AR-008: `CLAUDE.md:14-16`; `docs/companion/companion-erc7730-implementation-guide.md:66-106,849-860`; `docs/erc7730-root-rotation-and-update-policy.md:42-52`; `docs/companion/erc7730-integration.md:24-43`; `docs/erc8176-attestation-status.md:73-88`; `docs/security/adversarial-review/clear-signing-adversarial-review.md:20`.
  - PB-AS-009: `secure/src/display_under_test/wysiwys_dispatch_differential_tests.rs:16-23,278,294-336`; handler gas pages at `secure/src/nsc/cmd_sign_userop.rs:1345-1368`.
  - PB-BR-010: `tools/erc8176_eas_coverage.py:102-104,132-142`; add the policy anchors reproduced under XB-2.
  - PB-DOC-011: `docs/companion/companion-erc7730-implementation-guide.md:1051`; `pqsigner-erc7730/src/ir.rs:224-249`; `pqsigner-erc7730/src/display/render/formatters.rs:218,580-618`; `secure/src/tx/display/erc8213.rs:85-90`; `docs/erc7730-implementation-review-2026-07.md:216`; `docs/work-todo.md:2161`.
- The relocated PB-AR-004 sources establish behavior of existing/reused formatting primitives, not that every hypothetical future forced renderer must round. The precise residual is therefore a risk requiring a frozen forced-path schema and tests, not proof of inevitable rounding.
- PB-AR-007’s lexical-drop observation is not target stack-usage proof; target high-water evidence remains an implementation/production-stage requirement.

Required correction or precise residual:
- Replace the stale and shorthand citations with the map above in any canonical/coordinator record.
- Treat the raw Partner B first pass as non-reproducible without this corrigendum.
- This response confirms a citation-quality defect, not fabrication, and does not reopen the underlying first-pass merits.

Stage impact and whether an owner decision remains:
- Impacts architecture-review traceability and the evidence gate before findings are consumed for implementation or canonical merge.
- It is not independently a product vulnerability or forced-blind architecture blocker.
- No owner decision remains; an editorial/evidence-record correction is required.

Evidence class and honest residual:
- Source-only filesystem-existence checks and symbol-resolution searches against the frozen target.
- No build, test, hardware, or production execution evidence.
- Residual: this bounded inspection corrected technical location blocks but did not re-adjudicate every substantive first-pass claim or inspect Partner A’s other cross conclusions.

Raw ID and origin: `XB-2`, origin Partner A

Disposition: REFUTED

Exact reproduced/refuting evidence:
- `secure/data/erc7730/policy.toml:15-17` states that future production support must verify at least `min_attesters` distinct EAS records from `trusted_attesters`, bind each to the exact `erc8176_hash`, and only then emit verified provenance.
- `secure/data/erc7730/policy.toml:35` sets `min_attesters = 2`.
- `docs/erc8176-attestation-status.md:73-88`, specifically `85-87`, says the production gate requires at least `min_attesters` trusted attestations per shipped descriptor hash.
- `tools/erc8176_eas_coverage.py:102-104` treats a descriptor as covered whenever the intersection between its attesters and the trusted-attester set is merely nonempty.
- `tools/erc8176_eas_coverage.py:132-142` consequently permits a “safe to flip” conclusion using that one-or-more predicate.
- Concrete counterexample: with trusted attesters `{A, B}` and a descriptor attested only by `{A}`, the checker accepts because the intersection is nonempty, while the frozen policy rejects because the distinct-attester count is `1 < 2`.

Required correction or precise residual:
- PB-BR-010’s substantive premise stands; it must not be withdrawn or narrowed.
- Its citation block should add `secure/data/erc7730/policy.toml:15-17,35` and `docs/erc8176-attestation-status.md:73-88`.
- The checker must enforce `len(trusted_attesters ∩ descriptor_attesters) >= min_attesters` for every shipped descriptor and bind the result to an authenticated, reproducible production snapshot.
- The precise residual is that the current checker implements existence of one trusted attester, not the frozen two-distinct-attester policy.

Stage impact and whether an owner decision remains:
- This remains an implementation and production-provenance gate for the coverage checker; it is not a forced-blind architecture blocker.
- No policy-owner decision remains for the frozen packet: the threshold is explicitly `2`.
- Changing that threshold later would require a separate owner-authorized policy change; it is not an ambiguity in this review.

Evidence class and honest residual:
- Source-only policy/code comparison plus a pure counterexample.
- No live EAS query, authenticated production snapshot, checker execution, or hardware evidence.
- Residual: production readiness remains unproven until the corrected threshold logic and reproducible attestation snapshot are implemented and exercised.

END PARTNER B BOUNDED RESPONSE V1