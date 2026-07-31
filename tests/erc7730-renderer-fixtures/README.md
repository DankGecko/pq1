# ERC-7730 renderer fixtures

Synthetic descriptors that exist **only** to host renderer tests. They are not
shipped, not attested, and sit at addresses (`0xfe00…fe01`, `0xfe00…fe02`) no
deployment uses.

## Why they exist

Renderer tests used to be hosted on the production catalogue. On 2026-07-28 the
#498 EIP-712 reconciliation quarantined 24 descriptor sources — a correct and
deliberate policy decision, recorded per-source with a `reason_code` in
`tests/erc7730-semantic-evidence/eip712-reconciliation/manifest.json`. Five of
them happened to be the fixtures those tests used, so nine renderer tests began
panicking with `no leaf for … on chain …`.

The renderer had not changed. Its **test data** had been withdrawn from the
catalogue by an unrelated decision. That is the wrong dependency: renderer
coverage should not be a hostage of catalogue membership. Two CI jobs stayed red
for 84 commits because the failure looked like a renderer bug.

These fixtures remove the coupling. Curation policy cannot take them away.

## How they are used

`build_fixture_registry()` in
`secure/src/display_under_test/erc7730_render_pure_tests.rs` compiles this
directory through the **same** `dbgen` path as the production catalogue, so the
tests exercise real compiled IR rather than hand-assembled bytes.

## Constraints worth knowing before adding one

* **Filename must match `calldata-*` or `eip712-*`.** The scanner refuses
  anything else with `UNSCANNED: filename does not match …` — deliberately, so
  an upstream rename cannot silently drop a trusted descriptor.
* **EIP-712 fields must be static scalars.** A bare `string` in an EIP-712 type
  is refused at compile time: `encodeData` carries an opaque hash word, not the
  display value. Rendering an EIP-712 string requires an entry in
  `EIP712_STRING_PREIMAGE_ENROLLMENTS` (`dbgen/src/erc7730.rs`), which is
  compiled-in and **intentionally empty** in production.
* **Calldata strings are capped** at `DYN_TEXT_MAX` = 2 × `DISPLAY_COLS` = 32
  bytes on a single page, printable ASCII only, and refuse rather than truncate.

## What is deliberately NOT here

The multi-page EIP-712 string-preimage coverage (exact empty/trailing-space
preimages, two-string stream ordering/omission/mutation refusal, multi-page
content URIs, mixed string-plus-nested-array page budget). Reaching that painter
needs string-preimage authority that production is designed never to grant, and
faking it here would mean building a mechanism to grant it. The coverage is not
worth the mechanism.

That path is dormant, and two tests keep it honest:
`production_eip712_string_preimage_authority_is_empty` (secure side) and
`production_catalogue_has_no_eip712_string_preimage_authority` (dbgen side). The
first fails with an explicit list of the coverage to restore if the dormancy
ever ends.
