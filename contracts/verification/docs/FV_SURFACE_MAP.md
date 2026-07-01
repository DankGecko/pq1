# FV surface map — what the formal-verification stack covers, and what the adversarial review actually reaches

**Snapshot: 2026-07-01.** This doc answers one question the per-theorem ledgers cannot:
**is the adversarial review (`docs/verification/fv-adversarial-review-playbook.md`)
run across the *entire* FV surface, or only certain subsystems?** It is the concrete
artifact for catalog class **G3 (coverage-completeness)** — the class no per-theorem
gate can see, because a subsystem with *no* review has no red row to notice.

**The honest headline: two 2026-07-01 adversarial rounds covered ~3 of the 8 FV
surfaces below — the Lean on-chain tree (round 1) and the firmware Kani surface
(round 2, source-read; `ADVERSARIAL_REVIEW_KANI_2026-07-01.md`, verdict: 13 low + 7 info,
0 medium+, no hollow load-bearing proof, no live vuln).** The rest of the stack (Miri, the protocol
models, CT/SCA, the Aeneas §33 extraction, the differential/fuzz corpus) has **never been
adversarially reviewed.** Each is *gated* (green when run), but "green" is not
"adversarially attacked for vacuity" — the V1–V11 catalog was never pointed at it.
So each "no headline soundness hole" verdict is scoped to the surface it ran on, not
the whole thing.

## The surface

| # | FV surface | What it proves | Gate(s) | CI enforcement | Adversarially reviewed? |
|---|---|---|---|---|---|
| 1 | **Lean on-chain — `theft_free`** | no unauthorized fund movement given a correct signed digest (the headline theorem + safety closure) | `verify-{build,fv-lints,audit,ledger-consistency,proof-mutation,storage-mutators}`; `verify-lean4checker` (local backstop) | per-PR (`lean-fv.yml`) + nightly (`proof-mutation`) | ✅ **2026-07-01 (source-read-only)** — the playbook's *only* target |
| 2 | **Lean on-chain — bytecode bridge / A3.1** | deployed `SPHINCsC10Asm.verify = execC10Asm` (∀ carried by KAT + executable differential + ~250-mutant screen; symbolic ∀ in progress) | `verify-{bytecode,transcription,interp,bulk,cavp}`; `kontrol`/`halmos` | per-PR (`bytecode`/`transcription` in `ci.yml`); `kontrol`/`halmos` **local** | ◑ partial (a31 angle, 2026-07-01) — **user's active front** |
| 3 | **Aeneas §33 extracted** | firmware pure-logic (KDF byte-layout / invariant #5·#8 functional) = the Rust, ∀ | `verify-{extracted,extract-differential,spec-vendored-fidelity}` | `lean-extracted.yml` (nightly) | ❌ **never** |
| 4 | **Firmware Kani** (93 harnesses / 17 files) | decoder/gate DECISIONS panic/OOB-free + canonical-acceptance (multiSend / CoW / typed-call / SafeTx / ERC-7730 / Safe-mgmt / NS-ptr / fw-manifest / AA-calldata) | `make kani` + `verify-kani-mutation` (**curated: 6 mutations / 4 files — the other 57 harnesses have no vacuity screen**) | nightly (`nightly.yml`) | ✅ **2026-07-01 (source-read)** — `kani-decoder-vacuity` angle, 13 low + 7 info, 0 medium+; `ADVERSARIAL_REVIEW_KANI_2026-07-01.md` |
| 5 | **Firmware Miri** | 0-UB on the host-reachable `unsafe` (FI volatile helpers, NS-ptr deref, tree-borrows) | `make miri` | per-PR (`ci.yml`) | ❌ **never** |
| 6 | **Protocol models** (5 ProVerif + 3 Tamarin + 1 CryptoVerif) | dual-SE seed-split secrecy · 3-way PIN-lockstep reconcile · SCP03 + OPTIGA-shield tunnels · FW-update authenticity (symbolic + computational) | `proverif`/`tamarin`/`cryptoverif` + `verify-protocol-models` | nightly (`nightly.yml`: `proverif` + `verify-protocol-models`); `tamarin`/`cryptoverif` **local** | ❌ **never** |
| 7 | **CT / SCA** | 4 crypto drivers (kdf/fors/th/saes) constant-time on `thumbv8m` (binsec relational) | `make checkct` | **local only** — the `checkct` job is `workflow_dispatch`-only + `continue-on-error` (WIP; a G1) | ❌ **never** |
| 8 | **Differential / fuzz** | decoder ↔ deployed-`MultiSendCallOnly` bytecode agreement (revm) · panic-freedom over unbounded input (11 libFuzzer targets) | `fuzz-all` + the revm differential (dev-only) | ClusterFuzzLite (`cflite-*`); `fuzz-all` **local** | ❌ **never** |

*(Enforcement per row is asserted mechanically by `make verify-gate-enforcement` — the G1 lint — against `scripts/gate_enforcement.json`.)*

## What this means for the review

- **The V1–V11 catalog transfers to every surface, but was only *run* on #1–#2.** A Kani
  harness can be vacuous (asserts nothing / bounded so tightly it's trivial — V1/V3); a
  protocol query can be a tautology over its own model (V2); a differential can *sample*
  where it needs `∀` (V8); a fuzz target can have zero coverage (V1). None of these were
  attacked this round. The `verify-kani-mutation` / `verify-protocol-models` gates catch
  the *re-discovery* of a known vacuity per surface, but no adversary has done the *first*
  pass on #3–#8.
- **Next rounds must extend the master-prompt `TARGET` + add per-surface angles** (Kani /
  Miri / protocol / CT / Aeneas / differential), each with its own claims inventory. Until
  then, the honest scope of any "no hole found" is: **the Lean on-chain tree only.**
- **G3 is the un-mechanizable residual** — a threat with no covering *claim* (not just no
  review) still has no red row. That needs a threat-model → claim map + the periodic
  external red-team (playbook Layer 3), not a gate.

See `ADVERSARIAL_REVIEW_2026-07-01.md` (the run this scopes) and
`../../docs/verification/fv-adversarial-review-playbook.md` (the method + the G1–G5 catalog).
