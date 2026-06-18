# AI-Aided Lean Verification — Deep Research Report (2026-06-10)

Deliverable of a deep-research run (106 agents, 24 primary sources, 25 claims adversarially
verified 3-vote each: 20 confirmed, 5 refuted). Question: state of the art of AI-aided Lean 4
verification of Rust software, and the best harness for PQSigner's pure-logic crates
(`sphincs-c10`, `aa`, `domain`, parsers) against the existing `SphincsCVerify` spec codebase.

## TL;DR recommendation

- **Extraction: Aeneas (Charon → LLBC → Lean)**, not hax. Aeneas has industrial adoption in
  exactly our domain (Microsoft's SymCrypt Rust verification, incl. preview-branch ML-KEM);
  hax's Lean backend is ~1 year old, experimental by its own manual, and the subject of the
  April 2026 "Verification Facade" critique. Same call Signal Shot made (Aeneas + SymM + grind).
- **Prover orchestration: Lean Squad** (Don Syme / GitHub Next) — a public, 2-command-install
  GitHub agentic workflow that runs an LLM agent (Claude by default) on a schedule against a
  Lean repo. Proved 1,220 theorems across raft-rs/quiche/PX4 for ~$7/run (~$240/project) with
  near-zero human labor, and found 3 real bugs. We adapt it: extraction supplies definitions
  (their weak "Path B" — AI-written models — is the part we don't need), AI only closes sorries.
- **Plus Aristotle (Harmonic) API/MCP** for sorry-holes Claude can't close. Aleph is the
  strongest on paper but its benchmark numbers were refuted in verification and availability is
  unconfirmed — do not plan around it.
- **Adversarial spec layer** (the part nobody ships yet, and we can): `plausible`
  (QuickCheck-style counterexample tactic) on every spec before proof effort; multi-agent
  spec-gaming review using the Verification Facade gap taxonomy as the checklist; host-side
  differential fuzzing of Lean-spec-as-oracle vs the real crate (verified-ledger pattern).
- **Realistic close-rates on real software obligations: ~30% per agentic pass**, not the 99%
  olympiad numbers (SorryDB benchmark: Gemini Flash 3 agentic 30.3%, Claude Opus 4.5
  self-correcting 27.1%, deterministic tactics 8.4%). Iterative error-feedback beats parallel
  sampling. Plan for loops, not one-shot.
- **Funding: EF Verified-zkEVM applications are open through ~end-2026** (grants program,
  verified-zkevm@ethereum.org). Our track — plausibly the **first implementation-linked
  SPHINCS+ verification anywhere** (the Barbosa et al. EasyCrypt artifact is security-proof
  only, no implementation connection) — is a credible application.
- **Not a ship gate.** Frozen params/wire-formats mean proofs landing after October still apply
  to shipped firmware.

## 1. Landscape map

### Verified-zkEVM (Ethereum Foundation) — the ecosystem the RV paper lives in
- Grants-and-bounties program "likely running until the end of 2026," targeting formally
  verified zk(E)VMs by 2027. Applications open (KYC required). [verified-zkevm.org]
- Cryptography track = ArkLib (Lean 4 SNARK/IOR framework on mathlib + VCV-io) + CompPoly.
  Explicit goal: executable specs tied to security proofs, Rust verified against them.
- The arXiv 2605.30106 paper was the deliverable of a **3-month Q4-2025 grant** ("Rust
  Verification Through Lean 4 Tooling", Runtime Verification) — a feasibility study, not a
  product. Expect prototype-quality reusable artifacts (monadic helper lemmas, lakefile
  shapes, CI patterns) — still genuinely reusable.
- The hax **Lean backend** is itself an EF grant to Cryspen (Q2 + Q4 2025); first merged Lean
  proofs ~Aug 2025.

### Aleph's real deployment record (verified)
- Q3-2025 EF grant "an experiment in using Logical Intelligence's AI tools for proofs in
  ArkLib". ~10 `aleph-prover[bot]` PRs against ArkLib (Feb–Mar 2026); proofs harvested into a
  maintainer-merged PR (#421). Pattern: **propose-then-human-harvest**, not autonomous merge.
- REFUTED in verification (0-3): the press-release claim "Aleph 94% on VeriSoftBench vs
  Aristotle 69%". No verified close-rate or availability/pricing data exists. Treat Aleph as
  unavailable until proven otherwise.

### Signal Shot (Beneficial AI Foundation + Lean FRO + Signal)
- Verifying the Signal protocol + its Rust implementation. Stack: **Aeneas** as the
  Rust-to-Lean translator, **SymM** (new monadic framework, Dec 2025), **grind** for automated
  discharge, Mathlib + CSLib as foundations. Platform details not yet public; Cryspen and the
  Aeneas team are contributing. Validates our pipeline shape at the highest-profile level.

### Lean Squad (Don Syme, GitHub Next, Apr 2026) — the AI harness that actually exists
- Public GitHub Agentic Workflow: `gh extension install github/gh-aw` +
  `gh aw add-wizard githubnext/agentics/lean-squad`. Runs every 8 h; agent draws weighted
  tasks (research / spec / proof / critique / CI / report); opens PRs.
- Results: raft-rs 443 theorems (~$240, 3 human nudges in 3 weeks); quiche 518 theorems,
  found an `Ord` antisymmetry bug; PX4 259 theorems, found 2 real bugs. ~$7 per long run.
- Honest caveats from the author: AI-written Lean definitions ("Path B") have no
  correspondence guarantee; risk of "pseudo-completion" via axiomatized preconditions; many
  theorems are "glorified testing". **Our setup neutralizes the main weakness** — extraction
  (Aeneas) + hand-written reviewed specs replace AI-written definitions; we keep only the
  orchestration loop and add an adversarial critique layer.

### Verified SPHINCS+ — state of the art
- FV-SPHINCSPLUS-EC (Barbosa et al., EasyCrypt 2026.02): machine-checked **security proof**
  (tight EUF-CMA) — already cited as our A5 TCB discharge. **No connection to any
  implementation** (C/Rust/Jasmin). Our SphincsCVerify + extraction track would be, as far as
  this research found, the first implementation-linked SPHINCS+ verification.

## 2. Head-to-head: extraction tools

| | Aeneas (+Charon) | hax (Lean backend) | rocq-of-rust |
|---|---|---|---|
| Output | Pure functional Lean, `Result` monad, borrow semantics resolved | Lean via `RustM` monad, annotation-driven | Rocq, not Lean |
| Maturity | Lean one of its 2 most mature backends; industrial use (MS SymCrypt/ML-KEM, preview branch) | ~10–15 months old; "experimental" per Cryspen's own manual; bare `loop` unsupported Dec 2025 (while-loop support added Jan 2026 — moving fast) | Out of scope (wrong prover) |
| Known critique | None published at this level | "Verification Facade" (ePrint 2026/670): 3 semantic-gap classes, 5 PoC exploits passing extraction; TCB = 35 OCaml phases, 113 `assume val` ops (~19% of integer model), `assume!` macros. Targets the F* backend; taxonomy explicitly portable to any extraction pipeline incl. Aeneas | — |
| External crates | Hand-written Lean models (`FunsExternal_Template.lean` stubs emitted) | Hand-written axiomatized models (e.g. `Core_models.Num.fsti`) | — |
| Source mods | **Not** zero-modification (claim refuted in verification); expect minor refactors | "Can only translate a fragment of Rust" (authors' words); refactors likely | — |
| Semantics guarantee | Functional-translation paper (ICFP'22), no end-to-end formal guarantee | Authors explicit: **no formal guarantee**, assurance via testing generated models | — |

Verdict: **Aeneas**, with the Facade taxonomy used as our adversarial audit checklist rather
than a reason to avoid extraction. Both tools require hand-axiomatized externals — for us
that's SHA-256, deliberately, via the same `Spec.sha256` symbol as bridge axiom A1, KAT-tested.

Refuted sub-claims — do NOT cite: hax "proof-inert while-loop bodies" detail (0-3); hax
debug/release `+!` ML-KEM break (1-2); Aeneas "zero modifications + gcd termination" (0-3).

## 3. Head-to-head: AI provers / automation (usable-today lens)

| Tool | Availability (Jun 2026) | Evidence on software obligations | Use |
|---|---|---|---|
| Claude agentic loop (Lean Squad / Claude Code) | Now; ~$7/run observed | SorryDB: Opus 4.5 self-correcting 27.1%; quiche/PX4/raft results above | **Primary workhorse** |
| Gemini agentic (16-iteration) | Now | SorryDB best: 30.3% | Alternative/second opinion |
| Aristotle (Harmonic) | API (aristotle.harmonic.fun) + MCP server (`septract/lean-aristotle-mcp`); pricing unverified | Closed 2 RV-paper theorems classes: structural/monadic lemmas, linear arith | Secondary closer for stubborn holes |
| Aleph (Logical Intelligence) | Unconfirmed; vendor numbers refuted | Real ArkLib bot-PRs (harvest pattern) | Watch; request pilot; don't plan on it |
| Goedel-Prover V2 / Kimina | Open models | SorryDB: 2.7% / 1.0% pass@1 — mathlib-tuned provers transfer poorly (VeriSoftBench finding) | Skip |
| grind / omega / simp / aesop (deterministic) | In-toolchain | SorryDB: 8.4% alone | Always-on first pass (free) |

Design findings that shape the harness: (1) **iterative error-feedback beats parallel
sampling** (SorryDB); (2) **curated dependency-closure context beats full-repo dumps**
(VeriSoftBench); (3) repo-centric obligations are much harder than benchmark math — plan
multi-round loops on a frozen target, which is exactly our shape.

## 4. Adversarial spec-validation layer (the user-proposed "adversarial thing" — state of the art says: assemble it, nobody ships it)

1. **`plausible`** (leanprover-community): QuickCheck-style counterexample tactic. Run on the
   negation/instances of every new spec and theorem statement BEFORE proof effort — catches
   wrong specs in seconds. Needs `Repr`/`Shrinkable`/`SampleableExt` for custom types.
2. **Facade-taxonomy audit** as a recurring multi-agent review: (a) translation infidelity —
   diff extracted Lean against Rust semantics on adversarial cases; (b) trust-boundary audit —
   enumerate every axiom/external model, zero `assume`-style escapes, KAT-test each
   axiomatized primitive (we already do: NIST CAVS for SHA-256); (c) spec-gaming — agents try
   to write an implementation that satisfies the spec while violating intent. Our existing
   `lint_axioms.sh` / `AXIOM_STATUS.json` discipline is genuinely ahead of field practice here.
3. **Differential oracle** (welltyped-systems/verified-ledger pattern): compile the executable
   Lean spec to a host-side oracle, fuzz the real Rust crate against it in cargo tests. Catches
   spec↔implementation divergence empirically before/alongside proofs.
4. Lean kernel re-checks everything; AI output can never compromise soundness (trust boundary
   per RV paper §3 stage 4).

## 5. Recommended harness architecture for this repo

```
contracts/verification/
  lean/SphincsCVerify/          # existing specs + proofs (unchanged)
  extracted/                    # NEW: separate lake project, pinned to Aeneas's toolchain
    SphincsC10/{Types,Funs}.lean        # Aeneas output (generated, committed)
    SphincsC10/FunsExternal.lean        # hand model: SHA-256 = Spec.sha256 (same symbol as A1)
    Equiv/{Adrs,Wots,Fors,Merkle}.lean  # equivalence theorems, sorry-first
  scripts/                      # extend: no-sorry + axiom-lint cover extracted/
.github/workflows/lean-squad.yml  # adapted Lean Squad: scheduled agent closes sorries,
                                  # iterative error-feedback, dependency-closure context,
                                  # Aristotle MCP fallback, plausible gate, critique task
tools/spec-oracle/               # Lean→C compiled spec oracle + cargo differential-fuzz tests
```

- Toolchain: pin extracted/ to whatever Aeneas requires; bridge to SphincsCVerify when
  versions align (RV paper achieved alignment at Lean 4.26/4.28 after upstream coordination).
- CI gates stay ours: no-sorry on protected branches, axiom whitelist, AXIOM_STATUS schema.
- Maintenance burden: low — wire formats and C10 params are frozen; drift risk concentrated
  in Lean/Mathlib/Aeneas version bumps (budget a few days per quarter).

## 6. Phased plan (background track; does NOT gate October)

- **Phase 0 — extraction spike (1–2 weeks, now).** Run Charon/Aeneas on `sphincs-c10`.
  Expect some source refactoring. Hand-write `FunsExternal` SHA-256 model. Drive ONE theorem
  (`address.rs` vs `Spec/Adrs.lean`) to QED with Claude + plausible. Go/no-go on extraction
  fidelity. Fallback if Aeneas chokes: extract-a-model (RV workaround #2) + differential
  tests binding model to crate.
- **Phase 1 — harness online (July–Aug).** Install/adapt Lean Squad workflow; wire Aristotle
  MCP; plausible gate; panic-freedom theorems across parsers (`proto`/`shared`/`aa` input
  paths); start `aa` userOpHash equivalence (links firmware to the existing
  `Wallet/ValidateUserOp.lean` model — the firmware↔chain composite theorem).
- **Phase 2 — C10 building blocks (Aug–Oct).** WOTS chain / FORS / merkle per-function
  equivalence vs Spec modules. Expect ~30%/round AI close-rate; loop invariants are the
  human-ish residue (Claude-assisted, user reviews 10-line statements only).
- **Post-October.** Hypertree composition, sign∘verify end-to-end, Tier B (Merkle bundles,
  fw-manifest, EIP-712), Tier C state-machine conformance. EF grant application
  (verified-zkevm@ethereum.org) framed as: first implementation-linked SPHINCS+ verification +
  reusable Aeneas/AI-CI tooling — submit before program wind-down (end-2026).
- **Budget order-of-magnitude:** Lean Squad data point $7/run, $240/project-scale; ours is
  heavier (equivalence vs greenfield) — assume low thousands of $ in tokens through October.

## 7. Risks (explicit)

1. **Extraction fidelity** — the Facade gap classes apply to any pipeline incl. ours.
   Mitigation: taxonomy-as-checklist audits, KAT-tested axioms, differential oracle, axiom CI.
2. **Close-rate reality** — ~30%/pass on real obligations; WOTS/FORS loop invariants may
   stall. Mitigation: iterative loops on a frozen target; accept post-October completion;
   Aristotle for structural residue.
3. **Aeneas may not swallow sphincs-c10 idioms** (zero-mod claim refuted). Mitigation:
   Phase-0 spike decides cheaply; model-extraction fallback documented.
4. **Tool/vendor volatility** — Aleph unavailable, Aristotle pricing unknown, hax improving
   monthly. Mitigation: Claude-agentic is the verified-cheap baseline; revisit quarterly.
5. **Toolchain drift** — independent Lean release tracks. Mitigation: separate pinned lake
   project; bridge opportunistically; quarterly alignment budget.

## Refuted claims (do not cite)

- Aleph 94% / Aristotle 69% on VeriSoftBench (vendor PR; 0-3).
- Aleph availability status as stated in the press release (1-2).
- hax proof-inert while-loop bodies detail (0-3); hax debug/release `+!` ML-KEM break (1-2).
- Aeneas zero-source-modification + gcd termination example (0-3).

## Sources

Verified-zkEVM: https://github.com/Verified-zkEVM/Overview · https://verified-zkevm.org/ ·
https://github.com/Verified-zkEVM/ArkLib · https://verified-zkevm.org/data/grants.json
RV paper: https://arxiv.org/abs/2605.30106
Extraction: https://eprint.iacr.org/2025/142.pdf (hax paper) ·
https://hax.cryspen.com/blog/2025/12/08/verifying-a-real-world-rust-crate/ ·
https://hax.cryspen.com/blog/2026/01/19/verifying-a-real-world-rust-crate/ ·
https://eprint.iacr.org/2026/670.pdf (Verification Facade) ·
https://symbolic.software/blog/2026-04-07-cryspen-hax/ ·
https://lean-lang.org/use-cases/aeneas/ · https://github.com/AeneasVerif/aeneas ·
https://www.microsoft.com/en-us/research/blog/rewriting-symcrypt-in-rust-to-modernize-microsofts-cryptographic-library/
AI provers/harnesses: https://dsyme.net/2026/04/20/lean-squad-automated-software-verification-with-near-zero-human-labour/ ·
https://arxiv.org/abs/2602.18307 (VeriSoftBench) · https://arxiv.org/html/2603.02668v1 (SorryDB) ·
https://github.com/septract/lean-aristotle-mcp
Adversarial/spec: https://github.com/leanprover-community/plausible ·
https://github.com/welltyped-systems/verified-ledger ·
https://welltyped.systems/blog/verified-conformance-testing-for-dummies
Signal Shot: https://leodemoura.github.io/blog/2026-4-20-signal-shot-the-platform-is-ready/ ·
https://www.beneficialaifoundation.org/blog/signal-shot ·
https://cryspen.com/post/software-verification-in-lean-2026/
SPHINCS+: https://github.com/MM45/FV-SPHINCSPLUS-EC · https://eprint.iacr.org/2024/910
