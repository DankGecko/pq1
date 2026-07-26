# Rollback architecture freeze receipt — 2026-07-26

**Scope:** composite freeze identity for the Draft 1.1 + Draft 1.2 rollback
and lock architecture gate. A file cannot embed its own digest, so the pair
is recorded here.

## Frozen pair

| document | path | SHA-256 |
|---|---|---|
| Draft 1.1 (post-errata-3) | `docs/security/a-b-firmware-rollback-architecture.md` | `57b7e359ca1f8f0367e83ba355f61de35a8b6f25c6050435870227e4a5488293` |
| Draft 1.2 (post-errata-5) | `docs/security/fw-rollback-draft12-candidate-2026-07-21.md` | `eb856dd4220bc906f5b12e257a0a9cb6d74c76f228111e2d7ec04345728a700b` |

## Gate history (all GPT-5.6 SOL `ultra`, exact-digest)

- **Run 1 (2026-07-26):** NO-GO — 10 findings (A14/A16/A18/A28/A35
  availability-constructor staleness, A38/B4 factory-genesis contradiction,
  B3 burn-window matrix gap, C1 digest drift, C2 heal ambiguity, C3
  invariant overscope). Coordinator reproduced the two load-bearing claims;
  the C1 "drift" was the `589fb771` reviewer-lineup change only.
- **Owner decision (2026-07-26):** `RecoverySameEpoch` and
  `FloorBoundAccepted` DECLINED (availability, not safety; service/RMA
  accepted). Executed as bounded in-text errata.
- **Run 2 (2026-07-26):** NO-GO — all 10 remediated; 2 remaining blockers
  (B3 carried; A38-new mutation-owner gap). Remediated: §11 burn-window
  rows + R2.6 carve-out; `FirstBootLockWriter` owner entry.
- **Run 3 (2026-07-26):** NO-GO — both blockers remediated; §18 at 28
  RESOLVED / 12 GAP (all OPEN-register production gates). Sole finding D1:
  superseded digests named as the base. Remediated by this receipt.
- **Run 4 (2026-07-26):** NO-GO — D1 remediated; sole finding R4-1:
  Draft 1.2 §3 rows 1–2 + OPEN-LOCK-1 still carried heal semantics,
  contradicting the adopted verify-never-heal. Remediated (rows now
  hard-fail; OPEN-LOCK-1 re-scoped to burn-path one-shotness +
  Phase-B crash-consistency).
- **Run 5 (2026-07-26):** NO-GO — R4-1 edits remediated; findings R5-1
  ("factory-escape corrector" / "heal-then-lock" wording) and R5-2
  (burn-window re-enter vs tz-1 hard-fail contradiction). Remediated:
  wording fixes + phase-appropriate profiles on both sides (re-attempt
  only on exactly the pre-ceremony staged profile; else halt/RMA).
- **Run 6 (2026-07-26):** NO-GO — R5-1/R5-2 remediated; sole finding R6-1:
  Draft 1.2's Base pin still named the pre-R5 Draft-1.1 digest
  (`ee982785…`) while this receipt bound `57b7e359…`. Remediated: Base
  re-pinned; Draft 1.1 digest unchanged since. (Run 6 also recorded a
  pre-freeze evidence GAP: BENCH-4/A3/A4 completion evidence is owed
  before the Option-B/A freeze review — tracked as #398/#387/#388, not a
  blocker for this architecture freeze.)
- **Run 7 (2026-07-26):** **APPROVE** — no stage-blocking defect found.
  §18: 28 RESOLVED / 12 GAP (the 12 are Draft 1.1's declared later-stage
  production/silicon gates — OPEN-JRN-HW-1, JRN-DUR-1, ECC-1, FLASH-HW-1,
  RAM-1, OTP-1..3, REL-1, C10-1, §12.3 capacity/EOL, VBAT retention,
  ES0499 envelope). BENCH-4/A3/A4 completion (#398/#387/#388) recorded
  as a pre-FSBL-freeze evidence gap, non-blocking for this architecture
  freeze. Model-identity honesty: runs 1–4 invoked and self-attested
  `gpt-5.6-sol` at `ultra`; runs 5–7 invoked identically but the runtime
  exposed only "Codex, GPT-5 family" — recorded as GAP, not hidden.

The 12 run-3 GAPs are Draft 1.1's own declared production gates
(OPEN-JRN-HW-1, OPEN-JRN-DUR-1, OPEN-ECC-1, OPEN-FLASH-HW-1, OPEN-RAM-1,
OPEN-OTP-1..3, OPEN-REL-1, OPEN-C10-1, §12.3 capacity/EOL, VBAT retention,
master-list completeness, ES0499 envelope) — they gate implementation and
silicon, not this architecture freeze, per Draft 1.1 §14's own milestone
structure.

## Review-policy note

Reviewer lineup per on-master policy commit `589fb771`: Claude Opus 5
(`opus`) at `xhigh` effort and GPT-5.6 SOL at `ultra` effort, each over the
same frozen digest, neither seeing the other's report first. The Opus-5 leg
is outstanding as of this receipt.
