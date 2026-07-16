# `/docs/verification/` — verification program, strategy & research

**These docs are the *program* layer of the verification effort** — tooling
surveys, the soundness roadmap, research notes, and extraction handoffs. They
answer "where is FV going and why," not "what is proven right now."

> **Naming note (read this if you landed here by mistake).** There are **two**
> "verification" doc homes, with a clean split:
> - **`/docs/verification/` (here)** — *program / strategy / research* docs.
> - **[`/contracts/verification/docs/`](../../contracts/verification/docs/)** —
>   *proof-artifact* docs: what is **claimable** (the SSOT,
>   [`THE_CLAIM.md`](../../contracts/verification/docs/THE_CLAIM.md)), the
>   axiom/TCB inventory, per-proof audits, open obligations. Those live next to
>   the Lean/Halmos/Kontrol/protocol artifacts they describe and are referenced
>   by docstrings + the `Makefile` by relative path.
>
> Rule of thumb: a claim about **what is proven** → `contracts/verification/docs/`;
> a note about **what to build next / which tool** → here.

## Map

- **Tooling & adoption:** [`security-tooling-sota-2026-06.md`](./security-tooling-sota-2026-06.md)
  (the 2026-06 SOTA sweep + adopt-now shortlist),
  [`fv-soundness-roadmap-2026-06.md`](./fv-soundness-roadmap-2026-06.md) (T0/T1/T2
  roadmap), [`fv-adversarial-review-playbook.md`](./fv-adversarial-review-playbook.md).
- **Can the hardware surfaces be formally verified? (the survey + verdict):**
  [`hardware-formalization-survey-2026-07-17.md`](./hardware-formalization-survey-2026-07-17.md)
  — ~45 external tool/paper claims adjudicated against primary sources: what applies per
  surface (with URLs), the negative results (no public ARMv8-M model, no T=1′ formal model,
  no embedded flash/OTP litmus suite, no errata-vs-usage checker), a refuted-claims table,
  ranked build proposals, and the delta vs the 47-surface inventory. Includes the STM32U5
  **SESIP silicon certificate** (TN1545/UM3387) — the vendor's own assumption ledger, which
  this repo was not citing.
- **The honest boundary (read before writing any claim about the device):**
  [`hardware-assumption-boundary-2026-07-17.md`](./hardware-assumption-boundary-2026-07-17.md)
  — what is achievable vs. permanently-assumed for each of the six hardware
  surfaces (OTP, flash atomicity, ARMv8-M/CMSE/SAU-GTZC, I2C/T=1' framing,
  SE black box, STM32 peripherals); the falsifiability criterion that separates
  a hardware model from proof theatre; entitled-vs-overclaim claim language;
  per-invariant silicon dependency; and the RDP-2 / dual-SE-split trace.
- **Research notes:** [`lean-verification-research-2026-06.md`](./lean-verification-research-2026-06.md),
  [`spec-assurance-research-2026-06.md`](./spec-assurance-research-2026-06.md),
  [`how_to_math_proof_secureness.md`](./how_to_math_proof_secureness.md),
  [`verification-targets-2026-06.md`](./verification-targets-2026-06.md).
- **Spec conformance:** [`sphincs-c10-spec-conformance-checklist.md`](./sphincs-c10-spec-conformance-checklist.md),
  [`c10-fips205-delta-audit.md`](./c10-fips205-delta-audit.md).
- **Extraction handoff:** [`handoff-pinstate-extraction.md`](./handoff-pinstate-extraction.md)
  (recipe for the §33 Aeneas ranks).

For the empirical "has the FV work paid for itself, and where" calibration, see
[`FV_VALUE_AND_GAPS.md`](../../contracts/verification/docs/FV_VALUE_AND_GAPS.md)
in the proof-artifact home.
