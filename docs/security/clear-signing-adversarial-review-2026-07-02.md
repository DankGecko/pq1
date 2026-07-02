# Clear-signing adversarial review - ERC-7730 and render ladder (2026-07-02)

## Scope

Selected playbook: `docs/security/adversarial-review/clear-signing-adversarial-review.md`.

Review stance: try to break WYSIWYS for ERC-7730 contract calldata, ERC-7730 EIP-712 typed data, and the dispatch ladder that decides whether a transaction is clear-signed, raw-signed, or refused. The target failure is a page that looks clear-signed while omitting, misbinding, or mis-scaling bytes that the C10 signature commits to. A secondary failure is a decoder that fails open to a trusted banner instead of a loud blind/raw/refuse path.

Files read in this second pass:

- `docs/security/adversarial-review/clear-signing-adversarial-review.md`
- `docs/erc7730-implementation-review-2026-07.md`
- `docs/security/vulns/VULN-erc7730-visible-never-noparam-clearsign.md`
- `docs/security/vulns/VULN-erc7730-rule1-inert-field-nonaddr-action-hide.md`
- `docs/security/vulns/VULN-erc7730-eip712-nested-struct-address-hide.md`
- `dbgen/src/erc7730.rs`
- `dbgen/tests/erc7730_roundtrip.rs`
- `dbgen/tests/erc7730_phase5_policy_and_includes.rs`
- `pqsigner-erc7730/src/render/{params,visibility,nested,resolve}.rs`
- `secure/src/tx/display/{mod,blind_sign,eip1271}.rs`
- `secure/src/tx/display/erc7730/{mod,formatters,calldata_nested,nested}.rs`
- `secure/src/nsc/cmd_sign_offchain.rs`
- `secure/src/display_under_test/erc7730_render_pure_tests.rs`
- `tx/src/selectors/bundle.rs`
- `secure/data/erc7730/policy.toml`
- Live registry descriptors with optional or conditional visibility.

## Bottom line

No new current "display != signed bytes" exploit survived this pass: the current render path rejected, downgraded to explicit blind/raw signing, or rendered the signed operand for the attack cases I checked.

That is not the same as "nothing to fix." I found four open or latent problems worth tracking:

1. **OPEN / Medium: top-level `fields[].params` subkeys still silently drop.**
2. **OPEN / Medium production blocker: the shipping ERC-7730 registry path is still dev-policy / unattested.**
3. **LATENT / Medium: enabling ERC-7730 compact mode would hide currently signed optional fields without a matching dbgen proof.**
4. **LOW hardening: contract-context ERC-7730 `PageBudget` downgrades silently to raw/blind signing. It does not truncate pages, but it also does not tell the user why clear-signing disappeared.**

## Findings

### AR-CS-01: top-level `params` subkeys are still silently ignored

Severity: Medium. Status: Open residual.

`dbgen` now rejects unmodeled top-level format and field keys before compiling a format, and nested EIP-712 subfield params are conservative: unknown nested params return `Ok(None)` and belt-decline the format. Runtime TLV parsing also rejects unknown TLV tags.

The remaining hole is top-level `fields[].params`. `compile_params` reads raw `serde_json::Value` and looks up only known keys for each formatter. Unknown keys and wrong-typed known keys are often ignored:

- `tokenAmount` accepts `tokenPath`, `token`, `nativeCurrencyAddress`, `threshold`, and `message`, but does not reject any extra key.
- `addressName` accepts `types` and `sources`, but ignores extra params.
- `unit` accepts `decimals`, `base`, `prefix`, and `suffix`, but ignores extra params.
- `raw`, `amount`, `nftName`, `chainId`, and `tokenTicker` explicitly ignore all params for forward compatibility.

Why this matters: descriptor authors can believe a security-relevant display constraint is active when it is not. A typo such as `tokenpath`, `decimls`, or an object-form future key compiles to a different clear-sign surface instead of skipping loudly in tolerant mode. For `tokenAmount`, the renderer often falls back loudly to raw integer plus `Token (UNVERIFIED)`, so I did not get a clean current WYSIWYS exploit. The issue is still a trust-boundary bug: the pipeline has already learned that silently dropped descriptor keys are dangerous, but the params sub-key layer has not been given the same treatment.

Fix: add per-formatter param allowlists and strict type checks in `compile_params`; in tolerant registry builds, skip the one format with a reason instead of emitting degraded IR. Add JSON-schema CI against the pinned ERC-7730 schema so dbgen and schema validation fail together.

### AR-CS-02: production descriptor trust is not yet ERC-8176-enforced

Severity: Medium / production blocker. Status: Open residual.

`secure/data/erc7730/policy.toml` still has:

```toml
allow_unattested_dev_descriptors = true
```

`dbgen` has a production override path, and tests assert that production mode rejects unattested seed descriptors. However, the shipping registry path in `dbgen/src/main.rs` currently refuses `--policy production` for the registry catalogue rather than building it under enforced attestations. That is preferable to pretending, but it means the current descriptor root is curated by source review and dbgen gates, not by the intended ERC-8176 attestation policy.

Why this matters: CS5 is still load-bearing at build time for hidden non-address material. The on-device belts catch all-hidden formats and hidden nested addresses, but they do not prove every hidden scalar or bytes field is harmless. Until attestation is enforced, descriptor content governance remains manual.

Fix: wire production attestation enforcement for the registry build, replace placeholder trusted attesters, flip `allow_unattested_dev_descriptors=false` for production, and keep `--policy production` as a CI gate that must build the same shipping registry root.

### AR-CS-03: compact mode would currently reopen optional-field hiding

Severity: Medium if enabled. Status: Latent; current build has `COMPACT_MODE=false`.

Runtime visibility semantics skip optional fields when compact mode is true:

```rust
Visibility::Optional => {
    if compact { Action::Skip } else { Action::Render }
}
```

But `dbgen::check_field_visibility` treats `visible:"optional"` as shown for the build-time WYSIWYS proof. That is safe today because `secure/src/tx/display/erc7730/mod.rs` hardcodes `COMPACT_MODE: bool = false`.

The live registry already contains material optional fields. Examples include Threshold tBTC descriptors with optional Bitcoin funding vectors / locktime / UTXO details and SwissBorg's optional relaying fee `@.value`. If compact mode were enabled as a runtime/user setting without changing dbgen, those signed fields would disappear from a clear-sign page while the descriptor still passed the "has visible fields" proof.

Fix: do not enable compact mode until dbgen proves the compact surface separately. Conservative options: treat `optional` as hidden for rule-1/rule-2 when compact is possible, compile separate display profiles with separate roots, or make compact retry opt-in only after a format-level proof that skipped optional fields are non-material.

### AR-CS-04: contract-context page-budget downgrade is silent

Severity: Low. Status: Hardening finding, not a WYSIWYS exploit.

ERC-7730 contract-context rendering returns `RenderErr::PageBudget` when dynamic pages exceed `MAX_PAGES`. `pick_sign_pages_inner` discards the partial page buffer and falls to lower ladder rungs. That means no trusted clear-sign page is truncated and then signed, which is the important WYSIWYS property.

The weakness is disclosure: `Reject(_)` shows `Can't clear-sign` / `review raw sign`, while `NoFormat` and `PageBudget` fall through silently. A descriptor that is known and verified but too large becomes raw/typed/blind signing without telling the user why the richer clear-sign path disappeared.

Fix: show the same downgrade status for `PageBudget` as for `Reject`, or retry compact mode only after AR-CS-03 is fixed. Off-chain EIP-712 is already stricter: `cmd_sign_offchain.rs` refuses on ERC-7730 render failure rather than falling back to raw32.

### AR-CS-05: self-attested selector names remain lower trust by design

Severity: Informational / UX trust boundary. Status: Accepted residual.

`parse_self_attest_bundle` proves only `keccak256(text_sig)[..4] == selector` plus ASCII / length checks. A companion that can find a 4-byte selector collision can choose a misleading same-selector name.

The display path is currently honest about that lower trust: the blind-sign banner remains `! BLIND SIGN`, curated selector metadata is labelled `FUNCTION:`, and self-attested metadata is labelled `GUESS:`. I did not find a path where a self-attested selector becomes a curated clear-sign function name. The residual is human-factor risk: `GUESS:` has to remain visually loud and must never be promoted to a trusted label without a stronger provenance check.

## CS1-CS10 attack matrix

| Row | Attack tried | Result |
|---|---|---|
| CS1 display != signed bytes | Flip EIP-712 typed data, nested struct records, and calldata body assumptions while preserving a rendered page. | No surviving witness found. EIP-712 matches full 32-byte primary type hash and exact `encoded_data` length; nested records are hash-bound before sub-fields render; calldata scalar paths read only the static head. |
| CS2 fail-open clear banner | Force nested calldata, unsupported encrypted fields, malformed TLVs, and no-visible-field formats. | Defended. Nested calldata and encrypted fields reject; all-hidden formats reject on-device; contract context downgrades to raw/blind pages and off-chain typed data refuses. |
| CS3 unpinned descriptor or metadata | Look for attacker-controlled roots or trailing bytes in descriptor/selector metadata. | Descriptor and selector bundles verify against pinned roots and reject trailing bytes. Production attestation remains open as AR-CS-02. |
| CS4 magnitude / precision hiding | Check raw, array raw, nftName, date/blockheight, tokenAmount unknown-token paths, and amount overflow handling. | Current code renders full raw words or loud overflow/raw markers. I did not find a current truncation path in the reviewed renderers. |
| CS5 partial hide | Revisit all-hidden, hidden address, inert-only visible field, nested address, and non-address hidden cases. | Historic all-hidden/address/inert cases are fixed. Non-address hidden material remains policy/dbgen-dependent; compact optional hiding is latent AR-CS-03. |
| CS6 nested binding incomplete | Try to render nested pages with flipped committed hash words, extra nested blob records, or empty arrays. | Defended by hash binding, `records_consumed` / cursor reconciliation, empty-array reject, max-array cap, and existing flip-to-decline tests. |
| CS7 canonical target / Safe operation bypass | Spot-checked Safe/CoW comments and prior gates; not the primary selected scope. | No new break found in this pass. Existing code claims operation gates and Safe/CoW binding before ERC-7730 routing; this should get its own pass if the scope is Safe/multiSend. |
| CS8 page-budget truncation | Push dynamic ERC-7730 renderers toward `MAX_PAGES`. | No truncation found: `push_blank` returns `PageBudget` and partial pages are discarded. Disclosure gap is AR-CS-04. |
| CS9 legacy/dual walker desync | Check whether legacy `pqsigner-erc7730::walker` reaches secure rendering. | No secure render path found using the legacy walker; live rendering uses the display resolver path. Future re-export remains a footgun. |
| CS10 trust-label collision | Inspect curated vs self-attested selector display labels. | No curated-label bypass found. Self-attested selectors stay under `! BLIND SIGN` and `GUESS:`; residual is AR-CS-05. |

## Existing defenses that mattered

- `dbgen::erc7730::compile_one_format` runs completeness and visibility checks before emitting IR.
- Duplicate tuple/top-level names are rejected before name-keyed completeness or visibility checks can be fooled.
- Field-level `$ref`s and display-definition unknown keys are resolved/gated before compile.
- Hidden address arguments are rejected for top-level calldata, EIP-712 members, nested EIP-712 structs, and v2 array-of-struct members unless an exact reviewed policy allowlist entry has a rationale.
- The on-device ERC-7730 renderer rejects known-shape formats that declare fields but append no field pages.
- EIP-712 typed data matches the full type hash and exact encoded-data length; V3 nested records reconcile count and cursor.
- Unknown runtime TLV tags reject, and `format:"encrypted"` is rejected at dbgen plus runtime.
- Blind-sign is explicit: `! BLIND SIGN`, target/value/selector/data length, calldata SHA-256, chain, fee, gas, and nonce.
- Self-attested selector labels remain `GUESS:`, not `FUNCTION:`.

## Verification

Executed during this review series:

```text
cargo test -p dbgen erc7730
cargo test -p dbgen --test erc7730_roundtrip
cargo test -p dbgen --test erc7730_phase5_policy_and_includes
cargo test -p pqsigner-erc7730
cargo test -p sphincs-tz-secure erc7730_render --tests
```

Results:

- `dbgen --test erc7730_roundtrip`: 15 passed.
- `dbgen --test erc7730_phase5_policy_and_includes`: 12 passed.
- `pqsigner-erc7730`: 106 passed.
- `sphincs-tz-secure erc7730_render --tests`: 58 passed, 1 ignored, 2030 filtered. The secure crate emitted pre-existing warnings, including warnings in locally modified files outside this report.

Not executed:

- Kani harnesses.
- Fuzz targets.
- Full generated-descriptor sync check, because the working tree already contains unrelated generated ERC-7730 DB/root changes.

## Recommended next fixes

1. Close AR-CS-01 first: per-format params allowlists and strict type checks remove the most obvious descriptor-authoring blind spot.
2. Keep compact mode disabled until AR-CS-03 has a build-time proof and render tests over live optional-field descriptors.
3. Wire production attestation enforcement for the registry path before making production trust claims about ERC-7730.
4. Add a small source or render test that asserts `PageBudget` downgrade is loud, or intentionally documented as silent if that UX choice is accepted.
