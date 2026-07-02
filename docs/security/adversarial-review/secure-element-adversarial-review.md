# Secure-element (OPTIGA + SE050) adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for running an adversarial code-review pass over PQSigner's dual secure-element stack — the OPTIGA Trust M V3 + SE050 drivers, provisioning, and the PIN-gating lockstep. Three invariants converge here:

> **#1 Dual-chip seed split** — BIP-39 entropy is XOR-split (`half_O` on OPTIGA, `half_E` on SE050); neither chip alone reveals a bit. **#2 Hardware PIN gating, three-way lockstep** — PIN compare in SE silicon (never MCU); SE050 UserID (max 10), OPTIGA F1D0 AuthRef bound to E120 LUC, MCU page-124 counter; boot reconciles to strictest, disagreement = tamper, 10 wrong → `factory_reset_admin`. **#3 E2E encrypted SE tunnels** — OPTIGA Shielded Connection (TLS-PRF + AES-128-CCM-8), SE050 SCP03 (level 0x33); no plaintext secret on I2C.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) §5.1–5.6 (SCP03/Shielded/lockstep/lockdown, all silicon) and §4.2 (XOR split) enumerate the *bench pass-fail bars* — logic-analyzer bus captures, desolder rigs, PUT-KEY ceremonies. **This playbook is the code-review counterpart**: it walks the *driver source* against invariants #1/#2/#3, hunting a plaintext-on-wire feature downgrade, a PIN-counter desync the reconcile logic misses, an advertised-vs-actual gap, or a secret OID readable without auth. Same discipline as the [FV playbook](../../verification/fv-adversarial-review-playbook.md); cross-link red-teaming.md as the bench counterpart, do not re-run its checks.

> **Corrected facts (carry these, not folklore).** The research prompts that seeded this playbook carried three errors the source corrected — the playbook uses the corrections: **(a)** the master secret is OID **`0xF1D2`** (`OID_MASTER_SECRET`); `0xF1D4` is the **bootstrap VK**, not the master. **(b)** The OPTIGA PBS is **DHUK-derived at boot** (`hw::secret_keys::derive_into("pqsigner/optiga-pbs-v1")`), **not** flash-page-126-sealed — so a fw-update wiping page 126 does *not* brick OPTIGA and flash extraction does *not* yield the PBS. Page 126 was repurposed as the fw-update verify-failure counter, and bank-1 page 126 (`0x0C0F_C000`) now holds the wrapped **SE050 BHK** — *that* is where the brick/extraction concern actually lives (SE7). **(c)** The reconcile tamper condition is `se_count > mcu` (**not** `!=`) — MCU-leads is benign (power-cut window). **(d)** The "three-way lockstep" is **two-way (MCU ↔ OPTIGA-E120) in production**: SE050's counter reads `SW=0x6986` on a user-PIN-gated UserID, so its leg is silently skipped (already tracked, work-todo).

> **Honesty note + ship-blocker framing.** The `Status` column separates **defended**, **claim-vs-code tension** (advertised ≠ actual), and **deferred-by-design**. The OPTIGA lockdown ship-blockers **S-1/S-2/S-3** are *known, planned, and deferred deliberately* — real chips cost money and the LcsO=Op ratchet is irreversible, so the reversible code/FV hardening is done first and the factory ceremony runs once at design-lock. **Do not frame S-1/S-2/S-3 as gotchas** — cite them as tracked (STATUS.md §A, production-todo.md). The live code-review targets are the claim-vs-code tensions (SE3/SE4) and the plaintext-downgrade fences (SE1/SE8).

---

## Part A — The secure-element failure catalog (SE1–SE9)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| SE1 | **Plaintext secret on I2C** | a feature downgrade routes a secret/challenge through the plaintext branch | **DEFENDED (by fence).** `optiga-no-shield` (half_O + PIN HMAC challenge in clear) and factory-key SCP03 (`half_E` decryptable from on-wire challenges via published AN12436 keys) are real plaintext paths, closed only by `compile_error!` fences (`nsc/mod.rs`: HIGH-1 SE-tunnel `:470-491`, MEDIUM-1 `optiga-no-shield` `:501-517`). `GetRandom` must traverse the shield or fail closed (`optiga/mod.rs:239-254`, no silent downgrade) | **Verify the fence trigger covers every shipping config** (see SE8); `scp03_logic.rs` anti-factory-key guard; bus-capture is red-teaming.md §5.1 (silicon) | ✅ fence + host guard / silicon bench |
| SE2 | **Full-entropy concentration** | the full seed sits in one place long enough to scrape | **DEFENDED (transient, zeroized).** Neither chip ever holds both halves; the full seed is reconstructed **only in MCU secure SRAM** at `unlock` (`dual_se.rs:430` `xor_32`), immediately zeroized with `fi::zeroize_barrier()` between steps (`:447-461`). **Residual (disclosed)**: this is the one window invariant #1's split collapses — a RAM-scrape / cold-boot / FI-during-unlock target (HARDENING.md §13 calls the SRAM window the biggest remaining surface) | FI sweep of the unlock window; see [SCA/FI playbook](./sca-fi-adversarial-review.md) for the zeroize-audit + `zeroize_barrier` review | ⚠ partial (zeroize-audit) |
| SE3 | **PIN-counter desync undetected** | an attacker drifts a counter without tripping tamper | **DEFENDED (with disclosed bound).** `reconcile_pin_attempts` (`nsc/mod.rs:1053-1108`) fires on `se_count > mcu` (correct — MCU-leads is benign); intra-SE divergence via `pin_attempt_counts_divergent` (`dual_se.rs:530-542`). **Disclosed bounds** (tracked, work-todo 549): the SE050 leg reads `None` in production (0x6986) so cross-check is MCU↔OPTIGA-E120; a `None` leg suppresses the divergence check; an attacker resetting **all three** counters escapes detection (limitation `nsc/mod.rs:1016-1021`) | `make pin-gate-hw-counter-e2e` (three-way sync, silicon), `pin-gate-wipe-e2e` (10-wrong → wipe); attack the `None`-leg-suppresses-divergence path | ✅ HW e2e / ❌ adversary (edge) |
| SE4 | **Advertised ≠ actual lockstep** | docs say "three-way" but production is two-way | **⚠ CLAIM-VS-CODE (tracked).** CLAUDE.md invariant #2 + STATUS S-3 say "three-way"; the code cross-checks **MCU ↔ OPTIGA-E120** only because SE050's `pin_attempt_count` returns `None` (`nsc/mod.rs:1033-1046`, retraction `se050/mod.rs:485-510`). Load-bearing pair still holds (SE-silicon compare gives no way to drift the SE050 counter undetected); regression test `pin_attribute_read_refused_on_user_userid` re-enables the leg if a future chip honours the read | Read the reconcile correction note vs the invariant text; this is a V5/V11-shaped advertised-vs-actual gap, not a bug | ❌ adversary (doc-vs-code) |
| SE5 | **Shielded / SCP03 downgrade & replay** | a forced re-handshake drops to plaintext, or a captured transcript replays | **DEFENDED.** OPTIGA: seq-replay refused (`shield.rs:300-307`), nonce-wrap renegotiate at `enc_seq>=0xFFFF_FFF0` (`:220`), record-type in AAD rejects alert/handshake frames (`:288-294`). SCP03: monotonic 16-byte counter (`scp03.rs:299`), level 0x33 mandatory unwrap (`apdu.rs:230-240`). **Attack surface**: a MITM wedging PRL state forces fresh handshakes (self-heal `mod.rs:249-254`) — confirm no plaintext fallback fires on the second failure; confirm `zeroize_session` (`scp03.rs:138`) is invoked on lock/idle so a transcript can't replay a live session | Rainbow `fault_sweep_scp03.py`; audit the re-handshake / self-heal path for a plaintext fallback | ⚠ partial (FI sweep + review) |
| SE6 | **OID read without auth** | a secret OID readable with `require_shielded=false` | **DEFENDED.** Secret OIDs F1D1/F1D2/F1D3/F1D4 have Read = `Auto(0xF1D0) AND Conf(0xE140)` (`apdu.rs:909,923`) — reading half_O/master requires **both** PIN auth and the shielded connection. Counter OIDs E120/F1D5 are `Read = Always` (non-secret, but the attacker's *oracle* for the reconcile counters) | Grep for any read of F1D1/F1D2 with `require_shielded=false`; confirm the AND (not OR) on the Read AC builder | ✅ host AC-builder tests / grep |
| SE7 | **Brick / extraction on fw-update** | a fw-update writes the page holding a re-derivation root and bricks the wallet or exposes a secret | **DEFENDED (redirected).** OPTIGA PBS is DHUK-derived, **not** page-126-sealed (see corrected facts) — fw-update wiping page 126 does not brick OPTIGA. **The real class lives on the SE050 axis**: the wrapped BHK is on bank-1 page 126 (`hw/bhk.rs:72`), and `hw/bhk.rs:40` mandates "the firmware-update path MUST NOT touch page 126" | Audit the fw-update staging/erase range against the BHK page + the fw-fail-counter page (`hw/flash.rs:154-248`); the postmortem is `docs/secure-elements/optiga-brick-postmortem.md` | ⚠ partial (range audit) |
| SE8 | **Ship-blocker fence gap** | a shipping config that ships a blocker open | **DEFERRED-BY-DESIGN (do not flag as a gotcha).** The compile-time half is landed: S-1 `optiga-lock-operational` required (`nsc/mod.rs:368-382`), S-2 `optiga-reset-oids` forbidden (`:329-343`), S-3 `optiga-hw-counter` required (`:305-322`). **Disclosed residual (G1-shaped)**: the S-1 fence keys on `mode-production` **alone** — a release `stm32u585` image omitting the profile ships S-1-open (convention, not enforced, `:353-363`); the claimed `build_metadata_counter` production gate does **not** exist yet (S-3 code-doable residual, STATUS.md:98) | The irreversible LcsO ratchet + sacrificial-part validation + PQ1-factory-HSM cert are factory work (production-todo.md); the `build_metadata_counter` fence is the one code-doable open | ⚠ known/tracked (not a finding) |
| SE9 | **A half crosses chips** | a provisioning/debug path ships one chip's half to the other | **NOT OBSERVED.** Each half is read/decrypted independently (`dual_se.rs:388-425`) and only XORed locally in MCU SRAM | Confirm no debug/prov path (`factory_provisioning.rs`, the `dual-se-*-e2e` harnesses) transmits a half to the opposite chip | ❌ adversary (grep + review) |

**Read this catalog as the answer to "does a single-chip compromise, a bus tap, or a PIN-brute stay bounded?"** SE1/SE5/SE6 defend invariant #3 by construction; SE2/SE9 defend invariant #1; SE3 defends invariant #2 with a *disclosed* bound. **SE4 is the sharpest code-review target** — the "three-way" claim is really two-way in production, tracked but worth re-attacking whenever the invariant text is quoted. **SE7 and SE8 are the deferred/redirected classes**: SE7's brick concern moved from OPTIGA-PBS to the SE050 BHK page, and SE8's blockers are deferred-by-design factory work, not review findings.

---

## Part B — The existing defenses (Layer 1)

1. **Compile-time ship-blocker fences.** The `compile_error!` wall in `nsc/mod.rs` (S-1/S-2/S-3 OPTIGA, HIGH-1/MEDIUM-1 SE tunnels, Tier-1 KDF REQUIRE, tamp/tamp-wipe/tzic-wipe, consumption-mask, the leaky-feature denylist `:114-133`). These *prevent shipping unhardened* but do not close the bench/factory half (SE8).
2. **HW PIN-lockstep e2e (silicon).** `make pin-gate-hw-counter-e2e` (three-way sync — the flagship SE3/SE4 test), `pin-gate-wipe-e2e` (10-wrong → factory-reset both SEs + page-124 erase), `optiga-hw-counter-e2e` (E120 LUC provision + drive cycles, PASSED 2026-04-22).
3. **SE050 stress catalog (silicon).** `make se050-stress` / `-destructive` — the S-5/S-6 verifiers and the source of the silicon findings (`docs/secure-elements/se050-silicon-findings.md`); `se050-admin-extract-attempt-e2e` (S-6), `dual-se-admin-wipe-e2e`, `dual-se-bhk-e2e`.
4. **Host logic tests.** `scp03_logic.rs` (SCP03 KDF + GP PUT-KEY vectors + anti-factory-key guard), `optiga_under_test/pure_tests.rs`, `se050_under_test/pure_tests.rs`, `nsc_core_under_test/pure_tests.rs` (verifies the `compile_error!` fences exist). AC-builder tests for the Read = `Auto AND Conf` gate (SE6).
5. **FI + protocol backstops.** Rainbow `fault_sweep_{scp03,optiga_lock,pin}.py`; the ProVerif model `contracts/verification/proverif/optiga_shield_handshake.pv`. See the [SCA/FI playbook](./sca-fi-adversarial-review.md) for the unlock-window FI review.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's dual secure-element stack. Your
job is to BREAK invariants #1 (XOR seed split), #2 (three-way hardware PIN lockstep),
and #3 (no plaintext secret on I2C), NOT to confirm them. Default to "a secret leaks or
a counter desyncs until I prove it can't." A passing HW e2e and a confident invariant in
CLAUDE.md are CONSISTENCY signals — attack the CLAIM-VS-CODE gaps (is "three-way" really
three-way?) and the plaintext-downgrade fences (do they cover every shipping config?).

CORRECTED FACTS (use these, not the folklore): master OID = 0xF1D2 (F1D4 = bootstrap VK);
OPTIGA PBS is DHUK-DERIVED not page-126-sealed (page 126 = fw-fail counter + SE050 BHK —
the brick concern is the BHK, not the PBS); reconcile fires on se_count > mcu (NOT !=);
"three-way" lockstep is TWO-WAY in production (SE050 counter reads 0x6986 → leg skipped).

TARGET (read first, in this order):
  - docs/security/adversarial-review/secure-element-adversarial-review.md §A — SE1–SE9.
  - secure/src/dual_se.rs — XOR split, unlock/reconstruction window, reconcile inputs.
  - secure/src/nsc/mod.rs:1053-1108 (reconcile predicate) + :281-517 (ship-blocker fences).
  - secure/src/optiga/{mod,shield,apdu}.rs — Shielded Connection, AC metadata builders, OIDs.
  - secure/src/se050/{mod,scp03,apdu}.rs — SCP03 level, UserID PIN, admin path.
  - Cross-check: docs/STATUS.md §A (ship-gate + evidence) + docs/security/threat-model.md
    §5 (the falsifiable claims). Ship-blockers S-1/S-2/S-3 are DEFERRED-BY-DESIGN — cite as
    tracked, do NOT report as findings.
SCOPE THIS RUN: {{e.g. "the reconcile predicate + the None-leg divergence path" | "every
  plaintext-downgrade fence vs the shipping feature matrix" | "the unlock reconstruction
  window" | "the shielded/SCP03 re-handshake fallback"}}.

ATTACK PROTOCOL — walk EVERY SE1–SE9 mode against each surface in scope:
  SE1 plaintext-on-I2C · SE2 full-entropy concentration · SE3 PIN-counter desync ·
  SE4 advertised≠actual lockstep · SE5 shielded/SCP03 downgrade+replay · SE6 OID read
  without auth · SE7 brick/extraction on fw-update · SE8 ship-blocker fence gap (tracked,
  not a finding) · SE9 a half crosses chips.

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
  - S-1/S-2/S-3 are deferred-by-design factory work — report only NEW code-doable gaps
    (e.g. the missing build_metadata_counter fence), not the known blockers.
  - For each finding: SE-mode, file:line, PoC, disposition, severity, proposed fix (flag
    if it would break a fence, regress an e2e, or weaken an AC).

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per surface.
  2. "What I did NOT look at" — drivers/paths not walked, SE-modes not exhausted, whether
     you reasoned about silicon behavior you did not run.
  3. "PROVENANCE — did this pass RUN any e2e / stress / FI sweep, or read source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** ≥3 reviewers per scope, cross-vote, two model backends.

---

## Part D — Cadence + honest boundary

- **Per-PR touching `optiga/`, `se050/`, `dual_se.rs`, or the reconcile/fence code:** the Layer-1 host logic tests + a scoped Part-C pass; a change to the reconcile predicate or a fence re-runs `pin-gate-hw-counter-e2e` on silicon.
- **Per-invariant-text edit (CLAUDE.md #1/#2/#3):** re-check the SE4 claim-vs-code map — does the driver still enforce what the text now says?
- **Pre-ship (design-lock):** the deferred S-1/S-2/S-3 factory ceremony + the bench red-team (red-teaming.md §5) — the once-only irreversible work.
- **The one-line gut check:** *if one chip is fully compromised, or the bus is tapped, or three counters are reset — does the invariant still hold, and does the code enforce what the invariant TEXT claims?* If the text says "three-way" and the code does two, you are not safe on that claim — you have drift.

**The boundary, stated on purpose.** This playbook can tell you whether the *driver source* enforces invariants #1/#2/#3 as written, and where the code drifts from the invariant text (SE4) or rests on a fence (SE1/SE8). It **cannot** tell you the shield actually carries no plaintext on a logic-analyzer (red-teaming.md §5.1), that the LcsO ratchet was burned on a sacrificial part (the deferred S-1 factory work), or that a chip-firmware rev won't change the SE050 counter behavior. Those are the bench's + the factory ceremony's job.
