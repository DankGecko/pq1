# These workflows do not run. Nothing in this directory has ever executed.

GitHub Actions only reads workflows from the **repository root** `.github/workflows/`.
`EthereumPhone/PQ1` is a monorepo, so everything in
`contracts/smart-wallet/.github/workflows/` is inert — a leftover of the
Coinbase-Smart-Wallet port that came with its own repo layout.

Confirmed empirically on 2026-07-31: `gh run list` over this repo's entire history returns
exactly six distinct workflow names — `CI`, `Nightly (heavy gates)`, `ClusterFuzzLite (batch)`,
`Lean FV (SphincsCVerify)`, `Lean FV (extracted §33 Aeneas)`, `A3.1 transcription lint`. Neither
`test.yml` nor `certora.yml` appears, and neither ever has.

This file exists because that inertness is **actively misleading**. An external security reviewer
reading this repo in July 2026 credited PQ1 with "a Certora CI workflow" and "a 109-test Foundry
suite in CI" on the strength of these two files. Both conclusions were wrong in different ways.

## What is actually true

**`test.yml` — superseded, and the real thing is better.** Contract tests *do* run in CI: the
`Contracts (forge test)` job in the root `.github/workflows/ci.yml`. That job additionally does
the lib-exact restore (each Foundry dependency checked out at the exact rev in
`contracts/smart-wallet/foundry.lock`) that the codehash-freeze tests depend on — see
[the Foundry codehash lib-sensitivity note]. This file is strictly worse than what already runs.

**`certora.yml` — dead three times over, and the tool was superseded anyway.** Even if this
directory were live, this workflow could not work:

1. it triggers on `pull_request: branches: [main]`, and this repository's default branch is
   `master`;
2. its job declares `outputs.matrix: ${{ steps.set-matrix.outputs.matrix }}`, and there is no step
   with id `set-matrix` — the output is always empty;
3. its matrix names `.conf` files that are not present in `certora/confs/`.

More importantly, `contracts/verification/docs/AXIOM_STATUS.json` (A3.4) records that the Certora
artifact was **consciously replaced** by the Halmos + Kontrol + Lean pipeline. So the four
`.spec` files under `contracts/smart-wallet/certora/` are unexecuted by design, not by neglect —
but nothing in the tree said so until now.

## Consequences for anyone editing here

* **Do not add a gate here.** It will not run. Put it in the root `.github/workflows/`.
* These files are linted **report-only** by the root `workflow-security.yml` job
  `zizmor (report-only — inert contracts subtree)`. They currently carry 9 high-severity
  `unpinned-uses` findings, including `coverallsapp/github-action@master` — a mutable third-party
  ref. That is hygiene debt on a template someone might copy, not a live exposure.
* If you are tempted to fix the pins here instead of deleting the files, ask first whether the
  files should exist at all. Deleting them is the owner's call; documenting them was not.
