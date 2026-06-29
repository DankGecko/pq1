# What the formal-verification stack has actually bought us (empirical calibration)

**Snapshot date: 2026-06-29.** Counts below are a claim about the *surveyed git
history up to this date*, not a timeless statement about FV's capability. A
future defect or soundness catch should update this file, not silently falsify a
sentence in it.

**This file is NOT a source of truth for what is *claimable*.** That is
[`THE_CLAIM.md`](./THE_CLAIM.md) (the SSOT for the claimable / not-claimable
boundary) and [`TRUST_ASSUMPTIONS.md`](./TRUST_ASSUMPTIONS.md) (the TCB
inventory). This file answers a *different*, softer question that those two
deliberately do not: **has the FV work paid for itself, and where?** Read it as
the honest value-calibration companion to the assurance case, not as an
assertion about what is proven. Where the two could drift, defer to
`THE_CLAIM.md`.

---

## TL;DR

The FV stack's demonstrated payoff to date is **soundness self-policing** and
**spec-transcription regression-fencing**, *not* discovery of exploitable
on-chain/firmware bugs. That is not a weakness — it is what these tools are *for*
within their declared scope. **Every HIGH-severity exploitable finding in the
surveyed history occurred in a subsystem FV had explicitly declared
out-of-scope** (the trusted-display / clear-sign path —
[`FAITHFULNESS_AUDIT_2026-06-14.md`](./FAITHFULNESS_AUDIT_2026-06-14.md) lists
trusted-display + four device invariants as NOT COVERED). So the box-score read
"manual audits found the real bugs, FV found none" is the *wrong* frame: it
reads as a detection failure when the accurate statement is a **scope-coverage
gap**. No exploitable contract/firmware defect in the surveyed history is
*attributable to a blind spot inside FV's covered scope.*

The mark this earns and the reasoning is in the assessment thread; this file is
the evidence behind it.

---

## What FV demonstrably caught (with commit evidence)

Three distinct *kinds* of catch. Only the third is "a bug in the product"; the
first two are the higher-value, harder-to-get-any-other-way wins.

### 1. Soundness self-catches — FV policing its own trust base

These are defects in *our own proofs/axioms* that would have made the assurance
case **vacuous or inconsistent** — i.e. a green `make verify` that proved
nothing. Nothing but a mechanized kernel + adversarial axiom audit finds these;
a human reviewer reading the same Lean would very plausibly have nodded past
all four.

| What | Defect | Evidence |
|------|--------|----------|
| **EUF-CMA axiom was inconsistent** | Shape `∀ vk t m s, isForgery → False` derives `False` from a genuine valid KAT signature at the empty transcript → `theft_free` was **vacuously true** (proved nothing). | Honest downgrade `dd4c2110`; fix (reduction + key-bound transcript) `4ba5be10`; irreducibility of the residual conjunct `3da1409b`. Write-up: [`EUF_CMA_INCONSISTENCY.md`](./EUF_CMA_INCONSISTENCY.md), `Crypto/EUFCMA.lean`. |
| **`sha256_injective` was false-but-latent** | A literally-false lemma that would detonate the instant mathlib was added; restated as collision-resistance, and 3 vacuous hardness shapes upgraded to opaque. | `83776287`. |
| **`entrypoint_no_replay` was a phantom axiom** | Referenced by **zero** theorems AND latent-false against its own model (`handleOp` never reads `op.nonce`). Removed rather than left as latent-false debt. | `Bridge/EntryPoint.lean` (REMOVED 2026-06-14 note). |
| **Anti-vacuity gates institutionalized** | Proof-mutation + ledger-consistency gates so a *future* vacuous/false/inconsistent axiom is caught mechanically, not by luck. | `d0a40f82`; `make verify-proof-mutation` + `make verify-ledger-consistency`. |

**Why this is the headline value:** an unsound proof is *worse* than no proof —
it is a false sense of security with a green checkmark. The fact that the stack
caught **its own** EUF-CMA inconsistency, a false injectivity lemma, and a
phantom axiom is the strongest evidence that the verification discipline is
real and adversarial rather than ceremonial.

### 2. Spec-transcription catches — the differential corpus as a standing fence

The Rust ↔ Solidity ↔ Lean differential / KAT corpus is **not** a one-time
curiosity; it is a **hard check** (`requireFullVerify=true`, non-zero exit on
drift — `make verify-bytecode` + `lake exe verify-test-vectors`). It caught two
*real* Lean-spec transcription bugs that made the executable spec disagree with
the deployed verifier on concrete vectors:

| Bug | Effect | Evidence |
|-----|--------|----------|
| **`chainHash` wrote ADRS `chain_index` instead of `chain_pos`** (bytes [20,24) vs [24,28)), clobbering the caller-set field. | Every WOTS chain endpoint wrong → corrupted layer-0 `wotsPk` + subtree root; surfaced one layer late at the layer-1 digit-sum gate. | `5055d66d`. |
| **`loadWord32` returned all-zero on a partial tail read** instead of `calldataload`-style zero-padding. | Silently zeroed the final 16-byte auth-path entry (sig offset 3992). | `5055d66d`. |

Localized by a layer-by-layer differential against the Rust signer
(`sim_internals`) and the deployed Yul. The corpus now stands as a **regression
fence**: any future drift between the three legs fails CI. These are genuine
"the spec was wrong" catches, not product bugs — but they directly protect the
A3.1 faithfulness claim that the whole bytecode-proof rests on.

### 3. Product bugs caught by FV: none on record (within covered scope)

No exploitable contract or firmware defect in the surveyed history is
attributable to the FV stack. This is expected and *not* a failure — see the
scope discussion below.

---

## Where the real exploitable bugs came from (and why that's not an FV miss)

The HIGH-severity exploitable findings in the surveyed history were all caught
by **manual / LLM-assisted clear-sign (WYSIWYS) audits**, not by the FV stack:

| Finding | Severity | Source | Evidence |
|---------|----------|--------|----------|
| `approveHash` clear-sign length-bypass | HIGH | manual WYSIWYS audit | `0a26a134` (2026-06-28) |
| ERC-20 metadata mis-attribution via `v1_ms` disjunct | HIGH | manual WYSIWYS audit | `01981a14` (2026-06-28) |
| On-chain `decimals` wrong for 22 tokens (+ RPC verifier) | HIGH | manual WYSIWYS audit | `ea47a114` |

**All three live in the trusted-display / clear-sign path**, which
`FAITHFULNESS_AUDIT_2026-06-14.md` explicitly enumerates as **NOT COVERED** by
the Lean theft-freedom proof (alongside device invariants #1 XOR seed split,
#2 PIN lockstep, #3 SE tunnels, #4 TrustZone isolation). So they are not FV
"whiffs" — they occurred squarely in **FV's declared blind spot**. The honest
read is: *the proof covers "no unauthorized fund movement given a correct
signed digest"; it says nothing about whether the digest the user approved
matches the bytes on the OLED.* Closing that is the **scope-coverage gap**, the
subject of the tracked follow-up below — not a detection failure of the proofs
that exist.

A secondary, honest caveat about the firmware-FV tools (Kani/Miri/cargo-checkct,
adopted 2026-06-17): they found **0 bugs partly as a coverage artifact** — they
run on the *host* toolchain over host-reachable logic, and the highest-risk
`unsafe` (CMSE veneers, raw MMIO, on-target NS-pointer ABI) is
`thumbv8m`-`cfg`'d and compiled out of the host build. "0 caught" there is as
much about *where they can look* as about the code being clean. That, too, is
the coverage gap, not a clean bill of health.

---

## The two genuinely-uncaptured gaps (status)

Everything else FV-related is tracked in `docs/work-todo.md` §33/§34 with
what/why/closes-it/cost discipline (the Kani/Miri/cargo-checkct/cargo-fuzz/
Tamarin/ProVerif adoptions are *done and logged*; the A3.1 ∀-signature ceiling,
the protocol-track residuals, and the firmware functional ranks are *open and
reasoned*). Two things were, until this writing, NOT captured as actionable
work:

1. **The model→Rust span for device invariants #1–#4 (a cited-TCB
   transfer-by-assumption, not a buildable mechanization).** The *design* layer
   for these invariants is already proven *as far as it can soundly go* — #1
   (seed-split secrecy) by the info-theoretic `Crypto/SplitSecrecy.lean`
   (kernel-clean one-time-pad combinatorial core; the SOUND replacement for the
   symbolic `tamarin/seed_split_xor.spthy`, which carries an Unruh-2010
   XOR-unsoundness caveat) + `cryptoverif/seed_split_secrecy.cv`; #2/#3/#4
   (PIN-lockstep reachability / tunnel authenticity / isolation) by the protocol
   models (5 ProVerif + 3 Tamarin). The genuine gap is that **there is no
   spanning theorem from those abstractions down to the secure-crate Rust** that
   implements them (`dual_se.rs`, `offchain_state.rs` flash RMW, SE drivers) — a
   documented multi-tool composition gap, an honest cited-TCB interface (like A2
   / A4), *not* an Aeneas job (these are secrecy/reachability properties, not
   functional correctness — Aeneas proves "this Rust computes this spec," the
   invariant-#5/#8 shape). **Filed** in `docs/work-todo.md` §34 (Firmware FV) as a
   cited-TCB residual, paired with the actionable highest-ROI move (extend the
   Rust↔Lean differential + Kani to the clear-signing decoders + counter
   arithmetic — the surfaces where the real HIGHs lived).

   > **Scope correction (2026-06-29):** an earlier draft of this entry wrongly
   > framed the closure as "Aeneas-extract the dual-SE/flash subsystem" and
   > characterized the §33 Aeneas track as blocked. Both were wrong. Aeneas
   > extraction is for invariant #5/#8 *functional* correctness and is
   > **substantially delivered** — `contracts/verification/extracted/` is ~79
   > files / ~9.6k lines, ~12 ranks proven; `aeneas-probe/UPSTREAM_ISSUES.md` is
   > a *scoped* gate on the heaviest SHA-256 crypto kernels, not a wholesale
   > wall. It is simply not the bridge for #1–#4.

2. **This empirical-value calibration itself.** Closed by this file.

---

## How to keep this honest

- Re-survey on each new HIGH finding or soundness catch and update the tables +
  the snapshot date. Do not let a count go stale.
- If a future bug *is* caught by the FV stack inside its covered scope, that is a
  material change to the value story — record it prominently.
- Never let this file's softer empirical claims be cited *as* a proof claim.
  Proof claims live in `THE_CLAIM.md`; this file defers to it.
