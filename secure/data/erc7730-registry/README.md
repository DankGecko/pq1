# Vendored ERC-7730 registry (compilable subset)

This tree is the **vendored compilable subset** of the upstream
[`ethereum/clear-signing-erc7730-registry`](https://github.com/ethereum/clear-signing-erc7730-registry).
It is the SOURCE of the firmware-pinned `ERC7730_DESCRIPTORS_ROOT` once the
corpus switch lands — committed in-repo so the root is reproducible and CI can
rebuild-and-verify it without fetching an external repo.

**Do not hand-edit.** Regenerate with:

```bash
cargo run -p pqsigner-xtask -- vendor-registry \
  --registry-root /path/to/clear-signing-erc7730-registry
```

The tool tolerantly builds the catalog (`build_db_tolerant` — per-descriptor +
per-format tolerance), copies every descriptor that contributes ≥ 1 leaf plus
its project-dir sibling include templates (`common-*.json`,
`<proj>-common-*.json`, …) and all `ercs/*.json`, preserving the registry-
relative tree so `includes` still resolve, and then **verifies the vendored
tree rebuilds the identical Merkle root** (the faithfulness proof — it fails if
any include template is missing).

Layout mirrors the registry (`registry/<project>/…` + `ercs/…`) so the
descriptors' `includes` (`../../ercs/…` and bare sibling `common-*.json`)
resolve unchanged.

Notes:
- `*.tests.json` and `tests/` fixture dirs are intentionally excluded.
- This is **render** coverage (what the on-device renderer can clear-sign),
  not attestation — the ERC-8176 attestation gate is a separate production step
  (`policy.toml`).
- A function the renderer can't decode (a dynamic swap, a nested tuple) is
  per-format-skipped: that function blind-signs while the descriptor's other
  functions clear-sign.
