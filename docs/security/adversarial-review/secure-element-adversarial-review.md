# Secure-element (OPTIGA + SE050) adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for running an adversarial code-review pass over PQSigner's dual secure-element stack — the OPTIGA Trust M V3 + SE050 drivers, provisioning, and PIN-attempt enforcement. Three invariants converge here:

> **#1 Dual-chip seed split** — BIP-39 entropy is XOR-split (`half_O` on OPTIGA, `half_E` on SE050); neither chip alone reveals a bit. **#2 Hardware PIN gating** — every ordinary PIN attempt is consumed by MCU page 124, OPTIGA F1D0/E120, and the SE050 UserID; boot can perform only the directional readable-counter check `E120_used > page124_used`, while SE050 independently enforces max-10 lockout and reports blocked auth to the wipe path. **#3 E2E encrypted SE tunnels** — OPTIGA Shielded Connection (TLS-PRF + AES-128-CCM-8), SE050 SCP03 (level 0x33); no plaintext secret on I2C.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) §5.1–5.6 (SCP03/Shielded/lockstep/lockdown, all silicon) and §4.2 (XOR split) enumerate the *bench pass-fail bars* — logic-analyzer bus captures, desolder rigs, PUT-KEY ceremonies. **This playbook is the code-review counterpart**: it walks the *driver source* against invariants #1/#2/#3, hunting a plaintext-on-wire feature downgrade, a PIN-counter desync the reconcile logic misses, an advertised-vs-actual gap, or a secret OID readable without auth. Same discipline as the [FV playbook](../../verification/fv-adversarial-review-playbook.md); cross-link red-teaming.md as the bench counterpart, do not re-run its checks.

> **Corrected facts (carry these, not folklore).** The research prompts that seeded this playbook carried errors the source corrected — the playbook uses the corrections: **(a)** the master secret is OID **`0xF1D2`** (`OID_MASTER_SECRET`); `0xF1D4` is the **bootstrap VK**, not the master. **(b)** The OPTIGA PBS is **DHUK-derived at boot** (`hw::secret_keys::derive_into("pqsigner/optiga-pbs-v1")`) and has no flash page. Bank-1 page 126 (`0x0C0F_C000`) is exclusively the wrapped **SE050 BHK** when `bhk` is enabled; the earlier persistent firmware-update failure counter was removed. **(c)** The reconcile tamper condition is `se_count > mcu` (**not** `!=`) — MCU-leads is benign (power-cut window). **(d)** PIN attempts are three-way, but boot reconciliation is not: the SE050 attempt-attribute read returns `SW=0x6986`, so boot uses the directional MCU-page124/OPTIGA-E120 pair and SE050 retains its independent lockout/status path.

> **Honesty note + ship-blocker framing.** Known S-1/S-2/S-3 items need not be
> duplicate-filed as new discoveries, but their absence remains a ship blocker.
> Reviewers must report any false closure/authority claim or bypass of the
> current quarantine, and cross-link the owning STATUS/production TODO.

---

## Part A — The secure-element failure catalog (SE1–SE9)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| SE1 | **Plaintext secret on I2C** | a feature downgrade routes a secret/challenge through the plaintext branch | **DEFENDED (by fence).** `optiga-no-shield` (half_O + PIN HMAC challenge in clear) and factory-key SCP03 (`half_E` decryptable from on-wire challenges via published AN12436 keys) are real plaintext paths, closed only by `compile_error!` fences (`nsc/mod.rs`: HIGH-1 SE-tunnel `:470-491`, MEDIUM-1 `optiga-no-shield` `:501-517`). `GetRandom` must traverse the shield or fail closed (`optiga/mod.rs:239-254`, no silent downgrade) | **Verify the fence trigger covers every shipping config** (see SE8); `scp03_logic.rs` anti-factory-key guard; bus-capture is red-teaming.md §5.1 (silicon) | ✅ fence + host guard / silicon bench |
| SE2 | **Full-entropy concentration** | the full seed sits in one place long enough to scrape | **DEFENDED (transient, zeroized).** Neither chip ever holds both halves; the full seed is reconstructed **only in MCU secure SRAM** at `unlock` (`dual_se.rs:430` `xor_32`), immediately zeroized with `fi::zeroize_barrier()` between steps (`:447-461`). **Residual (disclosed)**: this is the one window invariant #1's split collapses — a RAM-scrape / cold-boot / FI-during-unlock target (HARDENING.md §13 calls the SRAM window the biggest remaining surface) | FI sweep of the unlock window; see [SCA/FI playbook](./sca-fi-adversarial-review.md) for the zeroize-audit + `zeroize_barrier` review | ⚠ partial (zeroize-audit) |
| SE3 | **PIN-counter desync undetected** | an attacker rolls back a readable counter without tripping tamper | **DEFENDED in source within the documented direction; reboot-silicon receipt OPEN.** `reconcile_pin_attempts` fires on `E120_used > page124_used`; MCU-leads is the conservatively charged cut/transport state. The SE050 leg returns `None` under the production policy (`0x6986`), so it contributes independent attempt enforcement/lockout but no boot comparison. | `make pin-gate-hw-counter-e2e` proves three-way attempt consumption and in-run desync recovery; `pin-gate-wipe-e2e` proves 10-wrong → wipe. Neither invokes reboot reconciliation. Add a reboot-based silicon test for E120-leading wipe and benign MCU-leading retention. | ✅ attempt/wipe HW e2e / ⚠ boot edge open |
| SE4 | **Advertised ≠ actual lockstep** | a future doc reintroduces three-way boot-reconciliation language | **OWNER CLAIM CORRECTED; KEEP AS REGRESSION LENS.** `CLAUDE.md` now distinguishes three-way per-attempt consumption from the directional page124/E120 boot check. The SE050 attempt-attribute read remains policy-denied; making it readable would require a separately reviewed policy/backend and silicon decision. | Diff active owner docs against `reconcile_pin_attempts` and `pin_attribute_read_refused_on_user_userid`; any future three-way boot claim reopens SE4 | ✅ documentation correction / regression review |
| SE5 | **Shielded / SCP03 downgrade & replay** | a forced re-handshake drops to plaintext, or a captured transcript replays | **DEFENDED.** OPTIGA: seq-replay refused (`shield.rs:300-307`), nonce-wrap renegotiate at `enc_seq>=0xFFFF_FFF0` (`:220`), record-type in AAD rejects alert/handshake frames (`:288-294`). SCP03: monotonic 16-byte counter (`scp03.rs:299`), level 0x33 mandatory unwrap (`apdu.rs:230-240`). **Attack surface**: a MITM wedging PRL state forces fresh handshakes (self-heal `mod.rs:249-254`) — confirm no plaintext fallback fires on the second failure; confirm `zeroize_session` (`scp03.rs:138`) is invoked on lock/idle so a transcript can't replay a live session | Rainbow `fault_sweep_scp03.py`; audit the re-handshake / self-heal path for a plaintext fallback | ⚠ partial (FI sweep + review) |
| SE6 | **OID read without auth** | a secret OID readable with `require_shielded=false` | **DEFENDED.** Secret OIDs F1D1/F1D2/F1D3/F1D4 have Read = `Auto(0xF1D0) AND Conf(0xE140)` (`apdu.rs:909,923`) — reading half_O/master requires **both** PIN auth and the shielded connection. E120 and the F1E1 provisioning/reset sentinel are `Read = Always` and non-secret; only E120 is lockout authority in production. | Grep for any read of F1D1/F1D2 with `require_shielded=false`; confirm the AND (not OR) on the Read AC builder | ✅ host AC-builder tests / grep |
| SE7 | **Brick / extraction on fw-update** | a fw-update writes the page holding a re-derivation root and bricks the wallet or exposes a secret | **DEFENDED (redirected).** OPTIGA PBS is DHUK-derived and has no flash page. **The real class lives on the SE050 axis**: the wrapped BHK is on bank-1 page 126 (`hw/bhk.rs:72`), and `hw/bhk.rs:40` mandates "the firmware-update path MUST NOT touch page 126" | Audit the fw-update staging/erase range against the single-owner BHK page and keep persistent failure-state writes absent; the historical collision report is `docs/security/vulns/VULN-page126-bhk-fwfail-collision-brick.md` | ⚠ partial (range audit) |
| SE8 | **Ship-blocker fence gap** | a shipping config that ships a blocker open | The irreversible SE closures remain OPEN. During the rollback quarantine, all production/factory STM32 shapes are rejected; bench builds require the explicit production-forbidden `legacy-fw-rollback-unsafe` feature. Production already requires `optiga-hw-counter`; E120 is lockout authority. F1E1 remains a provisioning/reset sentinel whose final lifecycle or replacement is separately tracked, not a missing one-line production fence. | Negative production/factory compilation tests plus the future reviewed SE ceremony | 🚫 shipping blocked |
| SE9 | **A half crosses chips** | a provisioning/debug path ships one chip's half to the other | **NOT OBSERVED.** Each half is read/decrypted independently (`dual_se.rs:388-425`) and only XORed locally in MCU SRAM | Confirm no debug/prov path (`factory_provisioning.rs`, the `dual-se-*-e2e` harnesses) transmits a half to the opposite chip | ❌ adversary (grep + review) |

**Read this catalog as a review map, not a shipping verdict.** SE8 and the
factory half remain open blockers even when already tracked.

---

## Part B — The existing defenses (Layer 1)

1. **Compile-time ship-blocker fences.** The `compile_error!` wall in `nsc/mod.rs` (S-1/S-2/S-3 OPTIGA, HIGH-1/MEDIUM-1 SE tunnels, Tier-1 KDF REQUIRE, tamp/tamp-wipe/tzic-wipe, consumption-mask, the leaky-feature denylist `:114-133`). These *prevent shipping unhardened* but do not close the bench/factory half (SE8).
2. **HW PIN-attempt e2e (silicon).** `make pin-gate-hw-counter-e2e` proves three-way attempt consumption, in-run desynchronization recovery, and simulated cache resynchronization; it does not reboot or exercise the directional boot check. `pin-gate-wipe-e2e` proves 10-wrong → factory-reset both SEs + page-124 erase. `optiga-hw-counter-e2e` provisions E120 LUC and drives cycles (PASSED 2026-04-22). A separate cold-reboot silicon receipt for E120-leading wipe and MCU-leading retention remains OPEN.
3. **SE050 stress catalog (silicon).** `make se050-stress` / `-destructive` — the S-5/S-6 verifiers and the source of the silicon findings (`docs/secure-elements/se050-silicon-findings.md`); `se050-admin-extract-attempt-e2e` (S-6), `dual-se-admin-wipe-e2e`, `dual-se-bhk-e2e`.
4. **Host logic tests.** `scp03_logic.rs` (SCP03 KDF + GP PUT-KEY vectors + anti-factory-key guard), `optiga_under_test/pure_tests.rs`, `se050_under_test/pure_tests.rs`, `nsc_core_under_test/pure_tests.rs` (verifies the `compile_error!` fences exist). AC-builder tests for the Read = `Auto AND Conf` gate (SE6).
5. **FI + protocol backstops.** Rainbow `fault_sweep_{scp03,optiga_lock,pin}.py`; the ProVerif model `contracts/verification/proverif/optiga_shield_handshake.pv`. See the [SCA/FI playbook](./sca-fi-adversarial-review.md) for the unlock-window FI review.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's dual secure-element stack. Your
job is to BREAK invariants #1 (XOR seed split), #2 (three-way per-attempt PIN
enforcement plus the directional page124/E120 boot check),
and #3 (no plaintext secret on I2C), NOT to confirm them. Default to "a secret leaks or
a counter desyncs until I prove it can't." A passing HW e2e and a confident invariant in
CLAUDE.md are CONSISTENCY signals — attack whether all three attempt paths run,
whether the boot predicate exceeds its documented direction, and whether the
plaintext-downgrade fences cover every shipping config.

CORRECTED FACTS (use these, not the folklore): master OID = 0xF1D2 (F1D4 = bootstrap VK);
OPTIGA PBS is DHUK-DERIVED and has no flash page (page 126 = wrapped SE050 BHK only —
the brick concern is the BHK, not the PBS); reconcile fires on E120_used > page124_used
(NOT !=); SE050's 0x6986 attempt-attribute denial excludes it from boot reconciliation,
not from per-attempt consumption or its independent max-10 lockout.

TARGET (read first, in this order):
  - docs/security/adversarial-review/secure-element-adversarial-review.md §A — SE1–SE9.
  - secure/src/dual_se.rs — XOR split, unlock/reconstruction window, reconcile inputs.
  - secure/src/nsc/mod.rs:1053-1108 (reconcile predicate) + :281-517 (ship-blocker fences).
  - secure/src/optiga/{mod,shield,apdu}.rs — Shielded Connection, AC metadata builders, OIDs.
  - secure/src/se050/{mod,scp03,apdu}.rs — SCP03 level, UserID PIN, admin path.
  - Cross-check: docs/STATUS.md §A (ship-gate + evidence) + docs/security/threat-model.md
    §5 (the falsifiable claims). Cross-link known S-1/S-2/S-3 ownership rather
    than duplicate-filing, but report any false closure, authority, or bypass.
SCOPE THIS RUN: {{e.g. "the reconcile predicate + the None-leg divergence path" | "every
  plaintext-downgrade fence vs the shipping feature matrix" | "the unlock reconstruction
  window" | "the shielded/SCP03 re-handshake fallback"}}.

ATTACK PROTOCOL — walk EVERY SE1–SE9 mode against each surface in scope:
  SE1 plaintext-on-I2C · SE2 full-entropy concentration · SE3 PIN-counter desync ·
  SE4 advertised≠actual lockstep · SE5 shielded/SCP03 downgrade+replay · SE6 OID read
  without auth · SE7 brick/extraction on fw-update · SE8 ship-blocker fence gap ·
  SE9 a half crosses chips.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a shipping feature-combo that trips a plaintext path without hitting a compile_error!;
  - a counter-desync sequence the reconcile predicate classifies benign (e.g. force one
    leg to None, then drift the other);
  - a code path reading F1D1/F1D2 with require_shielded=false;
  - a fw-update erase range that touches the BHK page (bank-1 0x0C0F_C000);
  - a diff between an invariant's TEXT and what the driver actually enforces (SE4-shaped).
  No PoC ⇒ list under "suspicions, unverified".

RULES:
  - Verify against the CURRENT tree; distinguish a silicon-validated claim from a host-only
    one (bus-capture / desolder are red-teaming.md bench items — cite, don't re-run).
  - Known S-1/S-2/S-3 blockers remain blockers. Avoid duplicate catalogue
    entries, but report false closure/authority and every new bypass.
  - For each candidate: SE-mode, file:line, PoC, provisional severity, stable
    candidate ID, and proposed fix (flag
    if it would break a fence, regress an e2e, or weaken an AC).
    Do not assign a finding disposition.

OUTPUT — return an external candidate packet to the coordinator. Do not modify
the repository, write a canonical findings report, or update catalogue/status
fields. Include every candidate and the honest residual. The coordinator freezes
the raw packet and gives the complete union to the exact Partner-A/Partner-B
pair; only their symmetric cross-adjudication may assign dispositions. An
authorized maintainer records the adjudicated result afterward.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per surface.
  2. "What I did NOT look at" — drivers/paths not walked, SE-modes not exhausted, whether
     you reasoned about silicon behavior you did not run.
  3. "PROVENANCE — did this pass RUN any e2e / stress / FI sweep, or read source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** Use ≥3 independent discovery reviewers per scope
across two model backends. Quorum only corroborates/prioritizes discovery; it
does not set a disposition, and sub-quorum variants remain in the packet. Give
every candidate and origin variant to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only their symmetric cross-adjudication may disposition it, with disagreement
preserved.

---

## Part D — Cadence + honest boundary

- **Per-PR touching `optiga/`, `se050/`, `dual_se.rs`, or the reconcile/fence code:** the Layer-1 host logic tests + a scoped Part-C pass; a change to the reconcile predicate or a fence re-runs `pin-gate-hw-counter-e2e` on silicon.
- **Per-invariant-text edit (CLAUDE.md #1/#2/#3):** re-check the SE4 claim-vs-code map — does the driver still enforce what the text now says?
- **Pre-ship (design-lock):** the deferred S-1/S-2/S-3 factory ceremony + the bench red-team (red-teaming.md §5) — the once-only irreversible work.
- **The one-line gut check:** *if one chip is fully compromised, the bus is tapped, or a readable counter is rolled back — does every attempt still consume the documented gates, and does boot enforce exactly the documented directional check?* Any return of "three-way boot reconciliation" language is claim drift.

**The boundary, stated on purpose.** This playbook can tell you whether the *driver source* enforces invariants #1/#2/#3 as written, and whether the claim drifts again (SE4) or rests on a fence (SE1/SE8). It **cannot** tell you the shield actually carries no plaintext on a logic-analyzer (red-teaming.md §5.1), that the LcsO ratchet was burned on a sacrificial part (the deferred S-1 factory work), or that a chip-firmware rev won't change the SE050 counter behavior. Those are the bench's + the factory ceremony's job.
