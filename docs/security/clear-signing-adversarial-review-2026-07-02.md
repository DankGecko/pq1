# Clear-signing adversarial review - ERC-7730 CS5 pass (2026-07-02)

## Scope

Selected playbook: `docs/security/adversarial-review/clear-signing-adversarial-review.md`, focused on CS5 (`visibility:"never"` / partial-hide) with spot checks against CS1, CS2, CS6, and CS9 because those are the adjacent ways a descriptor can render a page that is not bound to the signed bytes.

Target files read:

- `dbgen/src/erc7730.rs`
- `pqsigner-erc7730/src/render/{visibility,params,nested,resolve}.rs`
- `secure/src/tx/display/erc7730/{mod,formatters,calldata_nested,nested}.rs`
- `secure/src/display_under_test/erc7730_render_pure_tests.rs`
- `secure/data/erc7730/policy.toml`
- Prior postmortems: `docs/VULN-erc7730-visible-never-noparam-clearsign.md`, `docs/VULN-erc7730-rule1-inert-field-nonaddr-action-hide.md`, `docs/VULN-erc7730-eip712-nested-struct-address-hide.md`, and `docs/erc7730-implementation-review-2026-07.md`.

## Confirmed findings

No new confirmed WYSIWYS vulnerability survived this pass.

The pass deliberately did not re-file already-fixed CS5 findings:

- All-hidden descriptor formats are now refused at build time by `check_field_visibility` and rejected again on device by the `format.field_count > 0` / no-field-pages belt in both calldata and typed-data render paths.
- Hidden address arguments are rejected for top-level calldata, static tuple members, top-level EIP-712 members, nested EIP-712 struct members, and v2 array-of-struct members unless a policy allowlist entry matches the exact `(signature, path)` and has a non-empty rationale.
- The rule-1 inert-field bypass is covered: a format that only shows self/replay roles such as `from`, `owner`, `nonce`, or `deadline` while hiding the actual action is rejected.
- Field-level `$ref` resolution, display-definition body unknown keys, duplicate tuple/top-level names, nested calldata, and nested EIP-712 descent all fail closed or are covered by regression tests.

## Attempts that failed

### CS5 all-hidden / partial-hidden formats

Attempted break: compile a known-shape format that hides every parameter or hides the routing address while showing a benign amount or inert field.

Observed defenses:

- `dbgen/src/erc7730.rs::compile_one_format` unconditionally calls `check_field_visibility` after completeness checks.
- Rule 1 requires at least one non-inert visible argument or `@.value`.
- Rule 2 rejects hidden address arguments, including nested EIP-712 addresses.
- On-device belts in `secure/src/tx/display/erc7730/mod.rs` reject formats that declare fields but append zero field pages.

Strongest failed PoC attempt: the historic witnesses `setAllowedTarget(address target,bool allowed)`, hidden-recipient `transfer(address to,uint256 amount)`, Rarible `MetaTransaction(uint256 nonce,address from,bytes functionSignature)`, Permit `spender`, and nested `Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)` are all present as regression tests and pass.

### CS6 nested EIP-712 binding

Attempted break: make the rendered nested pages survive while flipping either the committed top-level hashStruct word or a nested element word.

Observed defenses:

- The renderer recomputes and constant-time compares the nested `hashStruct` or array hash before rendering sub-fields.
- The top-level reconciliation requires `records_consumed == nested_descent_count` and `cursor == nested_blob.len()`.
- The host render tests include flip-to-decline checks for Permit2 single, PermitTransferFrom, PermitBatch array, and UniswapX deep nested orders.

No display-not-bound witness survived.

### CS2 nested calldata fail-open

Attempted break: keep outer ERC-7730 pages clear-signed while an inner `format:"calldata"` field is unsupported.

Observed defense: `secure/src/tx/display/erc7730/calldata_nested.rs` always returns `RenderErr::Reject("7730 nested calldata p5")`; the dispatcher discards the partial page buffer and falls to the loud blind-sign path. The existing implementation deliberately declines rather than rendering an opaque inner-call hash under a clear-sign banner.

## Residuals and watch items

1. Non-address hidden values remain an accepted residual, not a newly confirmed bug. The current policy intentionally does not structurally reject every hidden `uint256`, `bytes`, or array because prior corpus measurements found only false positives. This still relies on descriptor content governance / ERC-8176 attestation for a future descriptor that shows a target but hides an effect-bearing payload.

2. `Visibility::Optional` is safe in the current shipping configuration because `COMPACT_MODE` is `false`; optional fields render like always-visible fields. If compact mode is ever enabled at runtime, `check_field_visibility` must be revisited because it currently treats optional fields as shown while `should_render_with_mode(..., compact=true)` skips them. No current WYSIWYS break exists because the toggle is hardcoded off.

3. This was not a full CS1-CS10 sweep. The pass read CoW/Safe binding claims only indirectly through the playbook and existing tests; it did not re-drive the Safe/CoW EIP-712 cross-check PoCs.

## Provenance

Executed checks:

```text
cargo test -p dbgen erc7730
cargo test -p pqsigner-erc7730
cargo test -p sphincs-tz-secure erc7730_render --tests
```

Results: all passed. The secure crate test emitted pre-existing warnings, including warnings in locally modified files, but the targeted ERC-7730 render tests passed.

Not executed:

- Kani harnesses.
- Fuzz targets.
- Full `make check-erc7730-descriptors` / `xtask gen-erc7730-descriptors --check`, because the working tree already contains generated ERC-7730 DB/root changes unrelated to this review.

Boundary: this pass can say the reviewed CS5 clear-signing bypasses are covered by source checks plus the executed host tests above. It cannot claim the full clear-signing surface is sound, that future compact-mode semantics are safe, or that descriptor content is production-trustworthy without the attestation flip.
