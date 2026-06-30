# Groth16 ZK clear-signing — retired (2026-06-30)

## Summary

The on-device **Groth16 (BLS12-381) ZK clear-signing verifier** has been removed
from the firmware and from the host-side tooling. The only clear-signing path it
still served — **Aave v3 Pool** `borrow`/`repay` — was ported to the native
on-device **ERC-7730** decoder, so there is **no clear-signing regression**.

## Why

The ZK verifier (ZKlarity-style "prove the human-readable string is a faithful ABI
decode of this calldata") was originally justified as a *generic* verifier so the
wallet wouldn't need a per-protocol on-device decoder for every contract. That
premise no longer held:

- The firmware had since grown full native on-device decoders for everything else —
  ERC-20, Safe (`SafeTx` / `execTransaction` / `multiSend`), CoW Swap, the typed-call
  ABI parser, and a native ERC-7730 IR walker.
- The **CoW Swap** ZK circuit was already retired to a native EIP-712 verifier
  (commit `05f9758a`).

After that, the **only** live consumer of Groth16 in the firmware was Aave v3
`borrow`/`repay`. (`supply`/`withdraw` were already covered by *both* the ZK path and
the native `aave-v3-pool.json` descriptor; the ZK path only won on renderer-ladder
priority.) Keeping a BLS12-381 pairing verifier + Poseidon hash + a trusted-setup VK +
an off-device prover for that narrow slice was a poor trade — especially given the
class of bugs this path had produced (range-check / byte-pack non-binding forgery,
amount-overflow field wrap, the trusted-setup `_security_note` hazard).

Net effect: **lower firmware attack surface** (no pairing crypto, no Poseidon, no
trusted-setup VK, no off-device prover, no PKA hardware accelerator) with no loss of
clear-signing coverage.

## What was removed

**Firmware (`secure/`):**
- `secure/src/zk/` (the entire Groth16 verifier: `groth16.rs`, `poseidon.rs`,
  `vk_bundle.rs`, `vk_data.rs`, generated Poseidon constants) and the
  `secure/src/zk_under_test/` test scaffold.
- The `zk_v1` clear-sign trailer path in `cmd_sign_userop.rs` /
  `cmd_sign_userop_batch.rs`, and the `v1` arm of `pick_sign_pages`.
- The `bls12_381` dependency, the `pka-accel` / `accel-pka` features, and the PKA
  hardware accelerator driver `secure/src/hw/pka.rs` (BLS12-381 field arithmetic was
  its only consumer). The PKA peripheral is still marked SECURE in GTZC defensively.
- `VK_DB_ROOT` from `secure/src/db_roots.rs`; `secure/data/vks.json`, `secure/data/vks/`.

**Host tooling:**
- Crates `bls12_381_pka/`, `zk-test/`, `tools/sca/groth16_target/`, and the Circom
  sources `circuits/`.
- `dbgen`'s VK / Poseidon generation (`vks.rs`, `poseidon.rs`, `erc20_poseidon.rs`).
- `nonsecure/src/vk_db.rs` and the companion-stub `vk` bundle builder.
- Scripts `tools/build_vks.sh`, `tools/export_zk_constants.js`,
  `tools/export_poseidon_constants.js`; the NPM/`circuits` check in
  `tools/verify_pins.sh`.

## Wire-format compatibility

The 2-byte `zk_bundle` length field is **kept reserved** in the sign-input wire format
so the downstream trailer offsets (`zk_v3` CoW, `safe_v1`, selector, ERC-7730, names)
stay byte-stable. The firmware now requires that field to be **zero** and fails closed
on any non-zero length — no proof bytes are ever parsed. In the batch wire format the
`TRAILER_KIND_ZK_V1` per-kind cap is set to `0` (a non-empty record of that legacy kind
is rejected at parse time; an empty one is ignored).

## Aave coverage after retirement

`secure/data/erc7730/aave-v3-pool.json` now carries native descriptors for
`supply` / `supplyWithPermit` / `withdraw` / **`borrow`** / **`repay`** (the
`interestRateMode` enum is hidden — on-device enum rendering is unsupported — and
`referralCode` stays hidden, matching the existing field style). `ERC7730_DESCRIPTORS_ROOT`
was regenerated. Coverage is exercised by `cargo test -p pqsigner-erc7730` and the
dbgen round-trip tests.

## See also

- CoW Swap ZK retirement: commit `05f9758a`.
- Native ERC-7730 path: `pqsigner-erc7730/`, `secure/src/tx/display/erc7730/`.
