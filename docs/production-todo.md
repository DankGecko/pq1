# Production-only TODO

Everything in this file represents a **one-way action** — provisioning
steps, silicon-level commits, or chip-state transitions that cannot be
undone on the target unit. These must NOT be executed during normal
development iteration. They belong on a dedicated factory / end-to-end
validation flow against sacrificial parts, then on the production line.

Compare with `docs/work-todo.md`, which is strictly the
reversible-iteration backlog.

## Ground rules

1. **Dev builds never flip any of these gates.** The default feature
   set keeps every one-way transition behind an opt-in Cargo feature.
   If a normal `make flash-hw-*` target commits silicon, that is a
   bug — file it, fix the default.
2. **Sacrificial parts first.** Every one-way flow below is validated
   against a chip we have explicitly designated as "about to be
   committed and never rolled back." If that chip fails a step, we
   learn and retry on the next sacrificial part, never on a customer
   device.
3. **No feature combinations on dev machines.** The
   `optiga-lock-operational`, future `stm32-burn-device-key`, RDP=2,
   and WRP1A flows are enabled exactly once per physical part, at
   production time. They never appear in a `make flash-*` target
   that developers run day-to-day.
4. **Every gate has an explicit "why this is safe now" checklist.**
   Before flipping a one-way switch, the operator records what was
   validated on the sacrificial parts that justified the commit.

## Irreversible gates, by subsystem

### OPTIGA Trust M V3 — LcsO transitions

Per SRM §"Life Cycle Status" the LcsO state machine only moves forward:
`Creation (0x01) → Initialization (0x03) → Operational (0x07) →
Termination (0x0F)`. No reverse command exists, no authorisation
reverses it, no factory-reset path is exposed. Once you commit,
you are committed.

The `optiga-lock-operational` Cargo feature gates every LcsO=op bump
we emit today. Default OFF. Production builds flip it only at final
provisioning, after every item in the pre-commit checklist below has
passed against sacrificial parts.

#### Production items (each is one-way per chip)

- [ ] **E140 LcsO=Operational.** PBS metadata frozen, chip accepts
      Change only via `Conf(E140)` (shielded connection with matching
      PBS). NOTE: PRL does NOT need this — Shielded Connection works
      with E140 at LcsO=Creation per the Infineon pairing example +
      SRM "Pairing Use Case Pre-conditions" (requires `LcsO <
      operational`). This transition is purely a *post-pairing
      hardening* step that locks the PBS against plaintext rewrite.
      Production chips land here once the PBS derivation is fully
      validated and we're ready to seal the chip's pairing against
      tampering.
- [ ] **F1D0 (AUTH_REF) — TIGHTEN `Change` AC BEFORE LcsO=Operational. SHIP BLOCKER S-1. DO NOT REGRESS.**
      The bring-up metadata
      `{Change=ALW, Read=NEV, Exec=ALW | LUC(E120), DataType=AUTHREF}`
      written by `apdu::build_metadata_auth_ref` / `build_metadata_auth_ref_luc`
      (`secure/src/optiga/apdu.rs:930`, `:1059`) MUST be replaced with
      a tightened variant **before** the LcsO ratchet to Operational.
      Required final state on a shipping chip:
      `{Change=Auto(F1D0), Read=NEV, Exec=LUC(E120), DataType=AUTHREF}`
      then ratchet to LcsO=Operational so the metadata becomes
      immutable. Acceptable fallbacks if sacrificial-part testing
      reveals `Auto(F1D0)` doesn't behave as expected on our firmware
      revision: `Change = NEV` (immutable; PIN change requires
      factory reset) or `Change = LcsO<Op` (same effect after
      ratchet). **`Change = Conf(E140)` is NOT acceptable** — a
      PBS-extraction attacker satisfies it and rewrites F1D0 the
      same way as `ALW`.

      **Why this is a ship blocker (desoldered-OPTIGA brute-force).**
      With `Change=ALW`, an attacker who desolders the OPTIGA and
      attaches it to their own I²C bench can: (1) overwrite F1D0 with
      a chosen 32-byte HMAC key (plaintext write, no credential
      required); (2) HMAC-verify against F1D0 with their chosen key —
      verify succeeds → `Auto(F1D0)` latched; (3) reset E120 to
      `(0, limit)` because E120's `Change` AC is `Auto(F1D0)` and they
      just satisfied it; (4) burn the silicon lockout indefinitely,
      yielding unbounded PIN brute-force on the desoldered chip.
      `secure/src/optiga/mod.rs:1238 reset_e120_via_transient_auth`
      documents the exact attack as the *legitimate* admin-wipe path —
      the bench attacker has the same capability minus the firmware
      politeness. Even though `half_O` at F1D1 still requires
      `Conf(E140)` to read (so the seed half isn't directly leaked
      without also extracting PBS from the MCU), this regression
      destroys the LUC defense layer that the threat model
      (`docs/security/threat-model.md:125`) advertises as the primary online
      brute-force bound on the OPTIGA half.

      **Why `Change=Conf(E140)` is NOT sufficient.** A
      PBS-extraction attacker (e.g. via STM32U585 RDP regression /
      fault injection — there is published research against RDP1 and
      side-channel work against RDP2) satisfies `Conf(E140)`, rewrites
      F1D0 to their own HMAC key, and re-runs the same attack.
      `LcsO<Op` (combined with actually ratcheting LcsO to
      Operational) forecloses this branch entirely because the chip's
      silicon LcsO state machine refuses the metadata write regardless
      of PBS possession. **The ship config MUST use `LcsO<Op` (or
      `NEV`), not `Conf(E140)`.**

      **What this costs.** With `Change = Auto(F1D0)` (the primary
      choice) — nothing. User-driven PIN change is preserved: the
      user enters the current PIN, F1D0 auth succeeds, Auto(F1D0)
      session state is granted, and `SetDataObject(F1D0, new_hmac)`
      succeeds. With the `NEV` / `LcsO<Op` fallbacks — F1D0 becomes
      immutable, so user-driven PIN change requires factory-reset +
      reprovision (wipes both SEs, user re-enters mnemonic, picks new
      PIN). Same posture as Trezor's OPTIGA integration. Decide
      between primary and fallback during the sacrificial-part
      verification step (item 3 below) and document the decision
      before the ratchet.

      **Implementation checklist before this gate flips:**
      1. Add `apdu::build_metadata_auth_ref_ship()` returning
         `{Change=Auto(F1D0), Read=NEV, Exec=LUC(E120),
         DataType=AUTHREF}`. Verify the AC byte encoding by reading
         back the metadata after `set_metadata` and comparing against
         the SRM §"Access Conditions" table. (The encoding constants
         in `apdu.rs:200-260` have been independently audited as
         correct — ALW=0x00, NEV=0xFF, qualifiers `==/>/<` =
         0xFA/0xFB/0xFC, `&&/||` = 0xFD/0xFE, LcsO ref = 0xE1,
         LcsO set = 0xC0, Change/Read/Execute tags = 0xD0/0xD1/0xD3,
         DataType tag = 0xE8, TrustAnchor type = 0x11. Auto(OID) uses
         the auto-reference tag — confirm against SRM before the
         `_ship()` builder lands.)
      2. Register `build_metadata_auth_ref` and
         `build_metadata_auth_ref_luc` (the bring-up `Change=ALW`
         variants) in the `compile_error!` fence under
         `mode-production` in `secure/src/nsc/mod.rs:98-116`.
      3. Verify on a sacrificial part: provision F1D0 with the
         tightened metadata at LcsO=Creation, ratchet F1D0 to
         LcsO=Operational, then attempt a plaintext `SetDataObject`
         on F1D0 — MUST fail with `OPTIGA_ERR_ACCESS_DENIED`.
         Attempt the same write inside an opened Shielded Connection
         — MUST also fail (proving Conf(E140) does not satisfy
         `LcsO<Op` after the ratchet). Attempt
         `reset_e120_via_transient_auth` — MUST fail at the F1D0
         overwrite step. If any of these succeed, the AC encoding is
         wrong and shipping with this metadata is equivalent to
         shipping `Change=ALW` permanently.
      4. Confirm the LUC increment-on-failed-auth property holds with
         a tearing/glitch test: power-yank between the wrong-PIN APDU
         response and the E120 readback, repeat ≥1000×, assert E120
         never lags the attempt count. Required because the LUC's
         failure-side increment semantics are not explicitly
         documented by Infineon; the happy-path increment is
         empirically validated by `optiga-hw-counter-e2e`
         (`secure/src/main.rs:1844-1854`) on TRUSTMV3SHIELDTOBO1 but
         the tearing/glitch case is not.
      5. Add the boundary case to `optiga-hw-counter-e2e`:
         `current = limit - 1` + correct PIN → must still authorize
         and reset E120 to 0. Today the test only resets from low
         `current`.
      6. `make ship-checklist` (see `docs/security/security-review-2026-05.md`
         §F) asserts that a release binary's provisioning path
         calls `build_metadata_auth_ref_ship()` and never the
         bring-up variants. Static grep + compile-time fence both.

      **Cross-references.** `docs/security/security-review-2026-05.md` §C-N
      (this issue); `docs/security/threat-model.md` §"S3 — auth-equivalent"
      (advertises the 10-attempt bound that this regression breaks);
      `secure/src/optiga/mod.rs:1216-1236` (admits `Change=ALW`
      enables the transient-auth bypass); `secure/src/optiga/apdu.rs:920-924,
      1052-1054` (doc comments flag the dev-only status of the
      current variants).
- [ ] **F1D1 / F1D2 / F1D3 / F1D4 LcsO=Operational.** Entropy / master
      secret / VK / bootstrap VK. Metadata frozen at `{Change=Auto(F1D0)
      OR Conf(E140), Read=Auto(F1D0) OR Conf(E140)}`. Data remains
      writeable via PIN-HMAC auth or shielded connection — exactly
      the wallet's read/write envelope.
- [ ] **F1E1 (COUNTER) LcsO=Operational — OR remove entirely (SHIP BLOCKER S-3).**
      Production builds MUST enable `optiga-hw-counter`. In that build
      F1E1 is unused — the counter is the silicon LUC at E120. F1E1
      MUST therefore either be (a) ratcheted to LcsO=Op with junk
      content so it cannot be re-armed as a counter on a desoldered
      chip, or (b) removed from the provisioning sequence entirely.
      The currently-documented `{Change=Conf(E140), Read=ALW}` shape
      is the soft-counter path that S-3 deprecates: `Conf(E140)` is
      bypassable by a PBS-extraction attacker, and on a chip without
      hw-counter the F1D0 Execute=ALW lets a desoldered-chip attacker
      burn unbounded HMAC verifies without ever touching F1E1. The
      mitigation is: enforce `optiga-hw-counter` at compile time (see
      S-3 in `docs/work-todo.md`), then make `build_metadata_counter`
      a `compile_error!` under `mode-production`, then write F1E1
      either as a frozen-junk slot or skip it entirely.

      Also reconcile the F1D5 / F1E1 / "soft-counter" naming drift
      across `apdu.rs:151`, `apdu.rs:956 build_metadata_counter`
      docstring, and the duress-comment in `mod.rs`. All three name
      the same mechanism. Pick one (delete the mechanism) and remove
      the other two stories.
- [ ] **Global chip LcsO (0xE0C0) = Operational** if we ever transition
      it. Currently we leave this alone; if we ever write it, it goes
      in this doc first.

#### SHIP BLOCKER S-2 — Trust-anchor cleanup — OID TARGET UNDER REVISION (2026-05-29)

> **⚠️ CORRECTION (2026-05-29) — this section is mis-targeted; revise the OID before acting.**
> Our own 2026-04-22 on-silicon metadata dump (memory `project_optiga_reset_oids`)
> shows **`0xE0E3` is a device-certificate slot (`DataType=0x12`), already full
> with Infineon's device cert — NOT a Trust Anchor (`0x11`)**. The chip will not
> retype it, so `reset.rs`'s "provision trust anchor at 0xE0E3" is a **silent
> no-op** (also why `flash-hw-optiga-reset` no-ops on the TRUSTMV3SHIELDTOBO1, and
> why the "16/16 OK" escape-hatch claim below is stale — the 2026-04-22 run got
> uniform `Status(0xFF)`). Cross-confirmed by the deep-research output
> (`docs/provisioning/provisioning-reference.md`, Matrix 2 + top correction box).
>
> **Reframed threat:** the real Protected-Update trust-anchor pool is the
> `DataType=0x11` slots (research: `0xE0E8/0xE0E9/0xE0EF`), which ship **empty at
> LcsO=creation** — a physical attacker can install *their own* anchor there and
> sign a manifest. **Our code touches none of them.** So the exposure is "open
> type-0x11 anchor slots," not "Infineon sample cert at 0xE0E3." Also open:
> whether the SetObjectProtected path is even live on our chip rev (our dump
> showed every manifest failing for want of a usable TA) — so the dump settles
> *severity* too.
>
> **Do NOT act on the OID targets below until the "⏳ BENCH-PENDING" dump at the
> end of this section confirms the real anchor slot.** The fix *shape* (HSM-
> controlled anchor, or fill-and-lock every type-0x11 slot + ratchet LcsO=Op) is
> unchanged; only the OID targets move.

The single biggest hole in the OPTIGA shipping posture, and the one
that defeats EVERY other hardening including S-1's metadata tightening
and every LcsO=Operational ratchet above. **Cannot ship while this is
open. There is no `optiga-lock-operational` flag value that closes it
on its own — this requires a separate factory-controlled cert
substitution.**

The bring-up flow under `optiga-reset-oids`
(`secure/src/optiga/reset.rs`) provisions `0xE0E3` with the Infineon
**sample** EC P-256 cert from `samples/integrity/sample_ec_256_priv.pem`.
The matching private key is in Infineon's public example bundle.
Anyone holding it can sign a SetObjectProtected manifest the chip
accepts, and a valid manifest **bypasses the target OID's Change AC
entirely**, including `Change = NEV` and `Change = Auto(F1D0)` on
ratcheted objects.

Required for ship (each item is one-way per chip):

- [ ] **Lock the real type-0x11 trust-anchor pool `{0xE0E8, 0xE0E9, 0xE0EF}`**
      (SRM Table 68 — triple-sourced, see correction block; `0xE0EF` =
      platform-integrity, the SRM metadata-update example → primary target).
      Each MUST be either a PQ1-factory-HSM-controlled cert (private key never
      exported; the HSM signs production manifests) + LcsO=Op, OR junk + LcsO=Op
      (cost: no field-recoverable OID reset post-ship). **NOT `0xE0E3`** — that's
      a device-identity slot (type 0x12); our `reset.rs` install there silently
      no-ops. **NOT `0xE0E4..0xE0E7`** — no objects exist there (GetDataObject errors).
- [ ] **Ratchet the device-cert slots `{0xE0E1, 0xE0E2, 0xE0E3}` (type 0x12,
      `Change=LcsO<op`) to LcsO=Op** so an attacker cannot RETYPE a device-cert
      slot to `DataType=0x11` at creation and install their own anchor (the real
      E0E1-E0E3 attack vector). `0xE0E0` is already `Change=NEV` — leave it (it's
      the chip-unique device-identity cert; see the anti-counterfeit note in the
      datasheet-cross-reference subsection).
- [ ] **Lock `0xF1D7`** (currently "left spare" per `apdu.rs:159`).
      Either fill with junk + ratchet to LcsO=Op so its metadata
      becomes immutable, or — if any other F1Dx slots remain spare —
      apply the same treatment to all of them. Any object whose
      metadata is mutable AND whose data_type can be set to `0x11`
      is a usable trust anchor surface.
- [ ] **`compile_error!` fence** `optiga-reset-oids` and
      `reset::provision_trust_anchor` in `secure/src/nsc/mod.rs`'s
      production-build fence. Currently the feature flag is dev-only
      by convention; make it a compile-time guarantee that no
      production binary can write the sample TA cert.
- [ ] **Document the factory HSM key custody** (which device, which
      key slot, who has authorization to sign manifests, what
      authorization workflow gates a signing operation). Pin this in
      §"Supply-chain attestation" below.
- [ ] **Sacrificial-part verification:** with the production trust
      anchor in place at `0xE0E3` and all other TA-pool OIDs +
      `0xF1D7` ratcheted:
      - Manifest signed by a non-PQ1 / Infineon-sample key targeting
        `kid ∈ {0xE0E8, 0xE0E9, 0xE0EF}` → MUST fail.
      - Same manifest targeting `kid ∈ {0xE0E1, 0xE0E2, 0xE0E3, 0xF1D7,
        random OIDs}` → MUST fail.
      - Manifest signed by the factory HSM key → MUST succeed.
      - Manifest attempting to rewrite F1D0 after S-1's ratchet,
        signed by the public Infineon sample key → MUST fail.
      - Manifest attempting to promote any spare OID to
        `DataType = 0x11`, signed by the Infineon sample key → MUST
        fail (chip should reject the metadata change post-ratchet
        regardless).
- [ ] **Verify on silicon** that the chip enforces "`kid` must point
      at an OID with `DataType = 0x11`" — i.e. the chip refuses a
      manifest whose `kid` points at a regular data object even if
      that object's content happens to be a valid X.509 cert.
      Trezor's integration relies on this; verify on our chip
      revision before depending on it.

#### Pre-commit checklist (sacrificial part, each run fresh)

Before flipping `optiga-lock-operational=on` on a "real" unit:

1. Run `make flash-hw-optiga-bringup-write-only` (Phase A) with the
   feature OFF. All 6 user OIDs provision; chip stays at
   LcsO=Creation; nothing committed.
2. Reflash with a different commit hash or a comment-only code edit.
   Confirm PBS fingerprint `8ca52e4bc284d822` reproduces identically.
   This is the rebuild-stability proof for the hardcoded-master path.
3. Repeat step 2 twice more. Any drift in the fingerprint aborts the
   flow — root-cause before proceeding.
4. On a second fresh part: flip `otp-hardcoded-master-key` OFF so the
   OTP burn path runs. Validate first-boot TRNG→OTP→readback cycle
   completes cleanly (`[S][otp] device master burned, X bytes`
   appears; second boot shows `device master already burned`).
5. On a third fresh part: full Phase-B with `optiga-lock-operational`
   enabled + `e2e-skip-unlock` off. MasterHello / SlaveHello / record-
   layer exchange all succeed against the committed PBS. Read back
   entropy / master / vk via the shielded channel and confirm bit-
   for-bit match of what was written.
6. Only then: flip `optiga-lock-operational=on` on the production
   build for the unit being provisioned. Single flip, single chip.

#### Escape hatch

`make flash-hw-optiga-reset` uses SetObjectProtected + an Infineon
sample Trust Anchor to reset the F1D0..F1DF user-OID range. Validated
16/16 on the original bench chip. Can recover a user-OID range that
was accidentally LcsO=op'd in dev. Cannot reset E140 once LcsO=op
with a lost PBS (that's the hard brick from the first chip), so the
escape hatch exists for user OIDs only.

#### ⏳ BENCH-PENDING (no dev board on hand 2026-05-29) — do first when back at the board

All need the physical TRUSTMV3SHIELDTOBO1; they gate the corrected S-1/S-2 fixes.

- [ ] **OPTIGA E0Ex metadata dump (settles S-2).** `trustm_metadata -r` on
      `0xE0E0 0xE0E1 0xE0E2 0xE0E3 0xE0E8 0xE0E9 0xE0EF` — record type / LcsO /
      Read+Change AC / populated. Then the discriminating read: the **`Int(...)`
      (Integrity) AC on the objects we actually Protected-Update** — that names
      the exact trust-anchor OID the manifest path consults, i.e. the slot S-2
      must lock. Settles where the sample cert is, what E0E3 holds, whether our
      write no-ops, which anchor matters, and whether the attack path is live.
- [ ] **S-1 code fix (`apdu.rs:934`).** Our provisioning **actively writes
      `Change=ALW`** on F1D0 (worse than the chip default). Change the production
      path to write `Change=Conf(0xE140)&&Auto(0xF1D0)`, `Read=NEV`, then ratchet
      LcsO=Op. Keep the dev `Change=ALW` variant gated OFF in production.
- [ ] **S-2 code fix (`reset.rs`).** Slot identity is now DOC-SETTLED (SRM Table 68,
      triple-sourced): re-target anchor provisioning from the no-op `0xE0E3` (device
      cert, type 0x12) to the real type-0x11 pool `{0xE0E8, 0xE0E9, 0xE0EF}`, ratchet
      the device-cert slots E0E1/E0E2/E0E3 (block DEVCERT→TA retype), and fix the
      `reset.rs:24-26` comment + `TRUST_ANCHOR_OID`. Requires the AC-builder code gap
      (work-todo) first. Bench still needed ONLY for: (a) does the chip accept a
      type-0x12 `kid` (mixed evidence — `ecdsa_verify` accepts 0x11|0x12); (b) the
      exact `Int`-AC the manifest path consults.
- [ ] **Retire/relabel the stale escape-hatch "16/16 OK" claim** and consider
      removing `optiga-reset-oids` + `reset.rs` (memory `project_optiga_reset_oids`).
- [x] **OPTIGA monotonic-counter endurance — RESOLVED (2026-05-29 cross-reference).**
      ~600k updates per counter / ~2M total CONFIRMED against the SRM + datasheet.
      Size PIN/usage thresholds well under it (our E120 limit is 32 — ample margin).

### OPTIGA Trust M V3 — datasheet cross-reference (SRM v3.70, 2026-05-29)

From the SRM / ConfigGuide / Keys&Certificates cross-reference. The S-1/S-2/S-3 ship
blockers above stand; these refine accuracy + add residuals.

- **S-2 severity — LABEL down, LOCKDOWN unchanged.** SetObjectProtected is NOT
  unconditional: the SRM (§2.2.5 / lines 3929-3931) gates it on the *target* object's
  metadata carrying an `Int(trust-anchor)` Change/`0xD8` AC **and** a reset-type (`0xF0`);
  an object with no `0xF0` cannot be metadata-updated via SetObjectProtected at all. So it
  updates only objects that reference an anchor — not "every Change AC including NEV/Auto."
  **This lower severity is CONDITIONAL on a verified invariant — no PQ1 object carries
  `Int(TA)`/`0xF0`** (currently true: our AC builder can't even emit them — see work-todo
  code-gap item). That invariant must be (a) checked across every provisioned object and
  (b) **GUARDED** — a future change adding `Int(anchor)` to enable legitimate protected-update
  reopens the bypass. The anchor-pool lockdown {E0E8/E0E9/E0EF} + device-cert-retype block
  {E0E1-E0E3} **remain ship-blocker work** (the severity refinement does NOT unblock ship).
- **E0E0 is NOT "a public sample anyone can reproduce" (threat-framing correction).** On
  PRODUCTION parts `0xE0E0` is a chip-unique Infineon device cert (`Change=NEV`, leaf key
  sealed at `0xE0F0 Read=NEV`) — an anti-counterfeit primitive to USE, not neutralize. The
  reproducible artifact is the engineering-sample *Test* cert — and our bench evidence came
  from the TRUSTMV3SHIELDTOBO1 **eval shield**, which may carry that test cert. So: don't
  replace E0E0; treat E0E0 + the coprocessor UID (E0C2) as a device-identity opportunity on
  production parts; confirm whether our eval shield holds the test cert vs a production cert.
- **New residuals (verify/decide):** (1) Security Monitor config `0xE0C9` — `tmax=0` can
  disable the throttle; verify it's non-zero + not writable. (2) `E120` linked-counter uses
  `Change=Auto(F1D0)`; SRM recommends `Change=NEV` (DoS-hardening) — evaluate. (3) Any object
  we want SetObjectProtected-protected needs Change AC = `Int(anchor)` (+ if confidential,
  `Conf(secret)` with the secret OID *different* from the target).
- **Decisions to record (unused):** Hibernate/`CloseApplication`-persist (we use auto-sleep +
  per-boot OpenApplication; SEC>0 blocks hibernate); SecStaG/SecStaA boot-phase ACs (we gate
  on Conf/Auto/Luc).
- **Confirms that resolve:** anchor pool {E0E8/E0E9/E0EF} type 0x11, device certs E0E0-E0E3
  type 0x12, no E0E4-E0E7 (SRM Table 68) ✓; PBS 64 B / type 0x22, shielded = TLS-PRF-SHA256 +
  AES-128-CCM-8 ✓; CC EAL6+ / BSI-DSZ-CC-0961 ✓; counter endurance 600k/2M ✓ (resolves the
  TO-VERIFY). ⚠️ the PSA cert **number/HW-ver/date** in O-12 are NOT in the Infineon docs —
  verify against products.psacertified.org before citing as fact.

### STM32U585 — OTP + option-bytes commits

#### Production items

- [ ] **STM32 OTP master-key burn.** 32 TRNG bytes into
      `0x0BFA_0080..0x0BFA_00A0` on first secure-world boot of a blank
      MCU. Gated today by the absence of the `otp-hardcoded-master-key`
      feature; `ensure_device_master` burns on demand once, locks the
      region, reads back thereafter. Per-MCU, one-way, not rewriteable.
      **Once work-todo #7 Tier 1 (DHUK) lands**, the master-key region
      demotes to salt duty and may be repurposed — at which point burning
      it stops being required for SE-pairing, and the irreversibility
      concern narrows to "whatever salt consumers we later add." Until
      then, this burn stays mandatory.

      **Pre-production validation — verify OTP actually programs on the
      target chip before shipping.** Not every STM32U585 with clean
      option bytes accepts user-OTP writes. On one B-U585I-IOT02A
      (`Rev W`) dev board we hit `SECSR=0x90` (`WRPERR|PGSERR`) on every
      quad-word in `0x0BFA_0080..0x0BFA_00A0`, with:
      - `RDP = 0xAA` (Level 0)
      - `OTPBLR_CUR = OTPBLR_PRG = 0`
      - No WRP coverage of OTP
      - `HDP1EN = HDP2EN = 0`
      - `TZEN = 1`

      Option bytes looked identical to a known-good board. Suspected
      root cause is a non-display-able RSS / debug-authentication /
      OBK-seal state left by some prior programming session, or a
      silicon quirk on that specific revision (see ST errata ES0499).
      `STM32_Programmer_CLI -psrss` returns "not supported for this
      device" on U5, so there's no host-side command to introspect or
      regress the state once it's latched.

      Production gate: for each chip, **flash a minimal test image that
      calls `otp::ensure_device_master` and confirms the burn + readback
      succeeds** before committing the unit to fulfillment. A chip that
      can't program user OTP cannot run the shipping firmware
      (no real PBS → no Shielded Connection → no dual-SE pairing) and
      must be rejected, not patched with `otp-hardcoded-master-key`.
      The dev-only `optiga-factory-reset-hw` /
      `optiga-preprovision-hw` /
      `flash-hw-optiga-oled-standalone-testkey` targets sidestep this
      check by using a compile-time shared-across-dev-boards PBS
      constant — never enter production with that feature set. The
      `make prod-check` CI gate is what catches this;
      `otp-hardcoded-master-key` in a non-`e2e-test` release build is
      already a `compile_error!` in `secure/src/nsc/mod.rs`.
- [ ] **OTP rollback-counter tally** (`ROLLBACK_WORDS = 32`, 1024
      commits). Each accepted firmware-update CHUNK+COMMIT clears one
      bit; never reset. Exhausted parts are update-dead — treat that as
      the device's end-of-life.
- [ ] **BHK page first-write** (work-todo #7 Tier 2 Phase 2B). 32 TRNG
      bytes DHUK-ECB-wrapped and written to the dedicated BHK secret-
      flash page on first-boot provisioning. The wrapped bytes
      themselves are not a silicon commit (flash can be re-erased), BUT
      once any SE is paired with a `secret_keys::*_v1` derivation that
      consumed this BHK, re-generating BHK invalidates that pairing —
      same class of brick as a lost PBS. Treat the first BHK write as
      a per-device one-way event even though the underlying storage is
      erasable. Firmware-update paths MUST NOT touch the BHK page; the
      linker script carves it out of the bank-2 update region and
      `fw_update` rejects writes that overlap it. Factory-reset and
      PIN-lockout-wipe also leave page 126 untouched — unlike Trezor,
      we deliberately do **not** regenerate the BHK on wipe (Trezor's
      `secret_bhk_regenerate()` is a crypto-erase of its encrypted flash
      store; we have no plaintext secret in MCU flash, and regenerating
      our BHK would brick the SE050's existing pairing — see
      `docs/architecture/trezor-comparison.md` §5 and §6.5 for the full rationale).
      **Staged rollout:**
      Phase 2A landed the cryptographic primitive (`cmac_bhk` +
      `derive_into_bhk` + `bhk-hardcoded-master-key` dev fallback) with
      no chip writes; Phase 2B (this checkbox) lands the silicon path;
      Phase 2C migrates SE050 SCP03 + admin PIN + TROPIC01 pairing
      callers from DHUK to BHK with a coordinated re-pair step.
- [ ] **DHUK availability probe** (work-todo #7 Tier 1). Before any
      DHUK-based derivation, verify SAES returns stable output for a
      known test vector (`SAES-CMAC(DHUK, b"dhuk-probe-v1") == X_for_this_die`).
      The output is per-die — we cannot pre-compute it at the factory
      across a fleet, but we CAN record each production chip's probe
      output alongside its UID at provisioning time, and compare against
      the same probe on every subsequent boot. A mismatch means chip
      transplant / DHUK regression / SAES peripheral glitch — device
      refuses to unlock. Probe output is non-secret (only proves DHUK
      is reachable, same as a UID read), safe to store in the binding
      manifest from #22.
- [ ] **RDP = Level 2.** Once the factory burns RDP=2, debug access is
      permanently disabled. No JTAG, no SWD, no read-out of flash.
      Required before shipping to prevent flash extraction. Note:
      RDP2 → RDP0 regression on STM32U5 does a mass erase but survives
      for OTP (confirmed behaviour; OTP is the anchor of trust). Also
      confirmed: **DHUK survives RDP2→RDP0 regression** — it is derived
      inside SAES from an OTP-based RHUK (the ST-factory root HUK; OTP is
      absent from the RDP1→0 mass-erase list), not silicon-fused-and-stored
      — so Tier 1 derivations still reproduce after a mass erase. **BHK does NOT survive** — its DHUK-wrapped bytes
      live in flash, which is mass-erased. A regressed + re-provisioned
      device generates a fresh BHK → Tier 2 pairings re-key, which means
      SE050 + TROPIC01 (if on BHK per the work-todo #7 split) must be
      re-paired via the normal first-boot provisioning path. Document
      this in the refurbishment / RMA flow.
- [ ] **WRP1A on FSBL pages (0..3).** Writes to the first-stage
      bootloader flash region are rejected post-commit. Makes the FSBL
      immutable in the field.
- [ ] **WRP on BHK page** (work-todo #7 Tier 2). Write-protect the BHK
      page via WRP1B or a second WRP group so no rogue firmware can
      overwrite DHUK-wrapped BHK bytes and force a pairing mismatch.
      Erase-allowed only during factory provisioning.
- [ ] **SECBOOTADD0 set to the FSBL base.** Secure boot points to the
      signed entry.
- [ ] **BOOT_LOCK = 1.** Force the boot entry to `SECBOOTADD0` (the FSBL) — no
      alternate boot via RAM or the system bootloader. (Research-derived: ST
      UM3387 §3.2.3 SESIP-certified lockdown set; we set SECBOOTADD0 but not
      BOOT_LOCK today.)
- [ ] **HDP1 (HDP1EN + HDP1_PEND covering the FSBL; HDP1_ACCDIS engaged at
      boot-exit).** Hides FSBL code+secrets from later boot stages at runtime —
      distinct from WRP, which only write-protects. FSBL self-reads a
      verification value after engaging HDP and halts on mismatch. (Research-
      derived; UM3387 §3.2.3/§4.2.1. We observed `HDP1EN=0` in the OTP-burn note
      above — i.e. NOT set today. Gap.)
- [ ] **OEM2 / Debug-Authentication keys (OBKeys).** Provision a secret OEM2 DA
      key so that post-RDP2 a regulated, cert-gated SWD reopen exists for external
      security auditors and RMA — the only post-lockdown access path. The default
      DA password is a hole; a default-password challenge MUST fail. (Research-
      derived; ST AN6008. Not present today.)
- [ ] **Ordering: commit WRP1A *before* RDP2.** WRP is removable only while
      RDP≠2 (AN5156), so the WRP1A `UNLOCK=0` burn MUST precede the RDP2 burn or
      the FSBL never becomes immutable. Pin into the ceremony order: WRP →
      DA-finalize → **RDP2 last of all**.

#### BHK survivability matrix (which events spare vs destroy the BHK)

Consolidates the BHK wipe/regression behavior (the recurring "does a wipe brick
the device?" question). The BHK lives DHUK-wrapped in **bank-1 flash page 126
(`0x0C0F_C000`)** and is reloaded into TAMP backup registers every boot; the DS
§3.43.2 confirms a tamper erases backup registers + SRAM2 + caches but **NOT main
flash**.

| Event | BHK flash page 126 | BHK backup-reg copy | SE050 SCP03 channel | Device reusable? |
|---|---|---|---|---|
| Tamper (HW or SW mode) | survives | cleared | survives (reloaded next boot) | ✅ after reboot |
| User factory-reset (PIN known) | survives (spared) | — | survives | ✅ re-provision a fresh seed |
| PIN-lockout wipe (10 wrong PINs) | survives (spared) | — | survives | ⚠️ yes — but the SE050 UserID is silicon-locked, so re-provision needs the OID-range bump (S-6), a firmware step |
| Firmware update | survives (page carved out of the bank-2 update region) | — | survives | ✅ |
| RDP regression (RDP1→0 mass-erase) | **WIPED** | cleared | **broken once SCP03 is BHK-rooted** (Phase 2C) | ⚠️ re-pair — see the Phase-2C SHIP-GATE in work-todo §7 |

**Why sparing the BHK is correct (not a weakness):** the BHK alone reveals nothing
— the seed is XOR-split (half_O/OPTIGA + half_E/SE050) and PIN-gated in SE silicon;
the BHK only roots the SCP03 *bus-encryption* channel. The security guarantee is
"wipe the **secrets**" (half_E/half_O/master), which every wipe path does. Wiping
the BHK additionally would brick the SE pairing without crypto-erasing anything
(unlike Trezor, we don't store the secret in MCU flash under the BHK —
`docs/architecture/trezor-comparison.md §6.5`). The hard-brick "lost immutable root" risk is the
**OPTIGA PBS** (on the DHUK, which survives mass-erase — that's *why* PBS is on
DHUK), NOT the BHK.

**Keep it spared (production):** WRP-lock page 126 (erase only at factory
provisioning); when implementing hardware-mode tamper erase, scope it to backup
regs / SRAM2 / caches — do NOT add a software step that erases page 126; and do
NOT try to make the BHK survive RDP regression by OTP-storing or DHUK-deriving it
(OTP-store burns scarce OTP; DHUK-derive collapses the Tier-2 isolation).

#### Pre-commit checklist

1. All firmware built with matching `SOURCE_DATE_EPOCH` and
   `--build-id=none`; `make verify-repro` green.
2. `fwsign verify-release` passes against the vendor public key that
   will be baked into the FSBL.
3. OTP master burn validated on at least two sacrificial MCUs —
   first-boot burn + subsequent-boot read back both produce the
   expected derivation outputs.
4. **DHUK probe recorded per part** (work-todo #7 Tier 1). At first
   boot of the sacrificial MCU, compute `SAES-CMAC(DHUK, b"dhuk-probe-v1")`
   and log the 16-byte output. Reboot and confirm it reproduces. This
   per-die value becomes the authenticated anchor stored in the #22
   binding manifest.
5. **BHK first-write + DHUK-wrap readback** (work-todo #7 Tier 2). On
   the same sacrificial MCU: TRNG 32 bytes → SAES-ECB-encrypt under
   DHUK → write to BHK page. Reboot. DHUK-ECB-decrypt the page → compare
   to pre-wrap bytes. Apply a firmware-update cycle (simulated `.pqfw`
   install) and confirm the BHK page is preserved byte-for-byte and
   the re-wrap still yields the same bytes — this is the "BHK survives
   legitimate updates" regression gate. Then rehearse an RDP2→RDP0
   regression on a SECOND sacrificial MCU and confirm the BHK page
   is erased (expected) while DHUK is still reachable.
6. RDP=0 → RDP=1 transition rehearsed on a sacrificial part. Device
   still boots, firmware updates still accepted, debug access denied.
7. RDP=1 → RDP=2 rehearsed on a second sacrificial part. Confirm:
   firmware updates still accepted; no debug interface; OTP survives
   an RDP2→RDP0 regression (mass erase clears main flash, OTP
   persists); DHUK probe still reproduces post-regression; BHK page
   is confirmed gone post-regression (and re-provisionable).
8. Only then: production line flips each part through OTP-burn →
   DHUK-probe-record → BHK-first-write → OPTIGA-provision →
   SE050-provision → option-byte lock in sequence, with per-part
   logs recording every step's observable (fingerprints, return
   codes, readback matches, DHUK probe output).

### STM32U585 — datasheet cross-reference (DS13086, 2026-05-29)

Cross-referenced Matrix-1 / this section against the STM32U585 datasheet (full
text + a focused lifecycle/SWAP_BANK sub-audit). Full 92-finding set in the run
output; the actionable residue is below. Most alarming "absent" items turned out
already-enforced in code (see "Already enforced") — the genuine new work is the
SWAP_BANK ship-blocker + four hardening residuals.

#### ⚠️ SHIP-BLOCKER — SWAP_BANK cross-bank boot redirect — RM0456-RESOLVED (2026-05-29)

Mechanic confirmed (RM0456 §7.5.8 + Fig 24 + FLASH_OPTR bit 20): **SWAP_BANK remaps
which PHYSICAL bank serves the boot logical address 0x0C00_0000.** WRP/SECWM/HDP are
**physical-bank-bound** (§7.6.1 — they travel with the bank), so bank-1-only
protection leaves physical bank 2's boot pages exposed. And SWAP_BANK programming is
**NS-reachable** (staged in nonsecure FLASH_OPTR, triggered via OPTSTRT in nonsecure
FLASH_NSCR — no OPTSTRT in FLASH_SECCR; §7.9.9/§7.9.13) — so the NS world itself can
flip it. Our layout (bank 1 = secure FSBL+S-world, **bank 2 = NS runtime, boot pages
NS-writable today**) is the staging area: write a malicious image into bank-2 boot
pages → flip SWAP_BANK → it serves 0x0C00_0000.

**KEY (corrects the earlier draft, which wrongly said "BOOT_LOCK does NOT defend"):
`BOOT_LOCK=1` + `TZEN=1` makes SWAP_BANK IMMUTABLE** — any write fails `OPTWERR`
(RM0456 §7.4.1 L20405 / §7.4.2 L20746). So the NS-flip is **closed at the source by
BOOT_LOCK** (which we set anyway). Keep BOTH layers (belt + braces):

- [ ] **PRIMARY (source-level): commit `BOOT_LOCK=1` + `TZEN=1`** → SWAP_BANK can't
      be written at all (`OPTWERR`). This was missing from the earlier draft and is
      the single most important fix; set it in the lifecycle lockdown.

- [ ] **WRP1A *and WRP2A*, `UNLOCK=0`, over pages 0..3 of BOTH physical banks**,
      committed before RDP2. (Two WRP areas per bank @ 8 KB granularity — DS
      §3.4.1; FSBL = 32 KB = one 8-KB-granular area per bank.)
- [ ] **Stage the same known-good FSBL in both banks' pages 0..3** so a SWAP_BANK
      flip is a harmless no-op, not a brick. (Erased+WRP-locked bank-2 boot pages
      are the weaker fallback: swap → DoS instead of RCE.)
- [ ] **Mirror HDP2 + SECWM2** over the bank-2 boot pages (DS §3.4.2: one HDP area
      *per bank*; we only spec HDP1/SECWM1 today). The hide must cover both banks.
- [ ] `SWAP_BANK=0` — set it; it becomes durable once BOOT_LOCK=1 locks it
      (`OPTWERR`). (Pre-BOOT_LOCK it's NS-mutable — so order BOOT_LOCK into the burn
      sequence and don't rely on the bare bit before then.)

  **3 discriminators — RESOLVED (RM0456):** (a) YES, SWAP_BANK remaps the physical
  bank at 0x0C00_0000 (§7.5.8/Fig 24); (b) WRP/SECWM/HDP are physical-bank-bound
  (§7.6.1) → WRP1A-only insufficient, WRP2A+SECWM2+HDP2 required; (c) SWAP_BANK
  programming is NS-reachable (nonsecure NSCR/OPTR) — **but `BOOT_LOCK=1` closes it
  at the source** (above). Remaining bench task: a sacrificial dry-run confirming
  the BOOT_LOCK→OPTWERR lock + the both-banks WRP/identical-FSBL no-op behavior.

#### RM0456 register-exact resolutions (2026-05-29) — closes the STM32 decision tail

26/28 Stage-1 STM32 gaps resolved against RM0456 (verify pass re-checked every cited
line). Register-exact values to pin in Matrix-1 / the read-back verifier:

- **RDP** `FLASH_OPTR.RDP[7:0]`: 0xAA=L0, 0x55=L0.5 (TZEN=1 only), 0xCC=L2, **any other value=L1** (catch-all, not a single code).
- **WRP**: 4 areas, 2/bank (WRP1A/1B bank-1, WRP2A/2B bank-2), 8 KB page granularity; per-register `UNLOCK`=bit 31 (0=locked/immutable). WRP2AR governs physical bank 2.
- **HDP**: enable+extent are option bytes in the SECWM registers — `HDP1EN`=`FLASH_SECWM1R2[31]`, `HDP1_PEND`=`SECWM1R2[23:16]` (off 0x54); HDP2 in `FLASH_SECWM2R2`. (Runtime hide-engage `HDP_ACCDIS` is in `FLASH_SECHDPCR`.)
- **BOOT_LOCK + SECBOOTADD0**: both in `FLASH_SECBOOTADD0R`@0x4C (SECURE reg, NS RAZ/WI). `SECBOOTADD0[24:0]`=bits 31:7 (128 B granular; word value 0x0C00_007C → boot address 0x0C00_0000 = FSBL base — note the register *word* ≠ the boot *address*).
- **OEM keys (RDP-regression / debug-auth)**: `OEM1KEY`=`FLASH_OEM1KEYR1`@0x70 + `R2`@0x74; `OEM2KEY`=`OEM2KEYR1`@0x78 + `R2`@0x7C. Write-only (read 0).
- **nBOOT0/nSWBOOT0**: `FLASH_OPTR` bit 27 / bit 26. `NSWBOOT0=0` → BOOT0 taken from the nBOOT0 option bit (pin ignored, deterministic — preferred).
- **BOR**: `FLASH_OPTR.BOR_LEV[10:8]` — 000≈1.7 V (default/floor), 001≈2.0, 010≈2.2, 011≈2.5, **100≈2.8 V**. Raise above 000 to narrow the glitch dwell window.
- **SRAM ECC**: ECC-capable banks = SRAM2 (full 64 KB), SRAM3 (first 256 KB), BKPSRAM; SRAM1/SRAM4 NOT. Enabled via FLASH_OPTR option bits, **inverted polarity (0=enabled)**: SRAM2_ECC=bit 24, SRAM3_ECC=bit 23. **DECISION: put secret buffers (master_secret / slot-cache / entropy) in SRAM2** — uniquely ECC-capable AND hardware-erased on tamper; set bit 24=0.
- **MPCBB** (invariant-#4 SRAM-secure enforcement): 512 B block granularity, one `SEC` bit/block in `GTZC1_MPCBBz_SECCFGRx`; resets to all-secure under TZEN=1. **MPCWM4** governs BKPSRAM (32 B watermark) if used.
- **TAMP backup-register secure zones** (`TAMP_SECCFGR`@0x20): `BKPRWSEC[7:0]`=end of zone-1 (RW-secure, BKP0R..), `BKPWSEC[23:16]`=end of zone-2. BHK in BKP0R..7R needs `BKPRWSEC>=8`. `BHKLOCK`=bit 30 (set-only → SAES-only). **`TAMPSEC`=bit 31** + `TAMP_PRIVCFGR.TAMPPRIV`=bit 31 → tamper config secure+privileged (NS can't disable tamper).
- **Hardware-mode tamper erase** = per-tamper `NOER=0`: `TAMPxNOER` in `TAMP_CR2`@0x04 (8 external), `ITAMPxNOER` in `TAMP_CR3`@0x08 (internal). NOER=0 = immediate silicon backup-register erase (the "confirmed" mode) — set it for the BHK-protecting tamper(s).
- **SAES KEYSEL** = `SAES_CR[30:28]`: 001=DHUK, 010=BHK, 100=DHUK^BHK (confirms M-11). **DHUK** = SAES-computed from a non-volatile per-die software-secret RHUK (confirms M-12). **BHK** write-once → BHKLOCK → SAES-only, cleared on tamper/RDP-regression (confirms M-11).
- **RCC CSS**: `RCC_CR.CSSON`=bit 19 (HSE clock-security; on HSE fail → NMI + auto-fallback to MSIS/HSI16). LSE CSS separate.

Still-open (need silicon/registry, NOT RM0456): the OPTIGA bench OID reads + the SE050 production-BOM variant + the OPTIGA/MCU PSA-SESIP cert-registry to-verifies.

#### Hardening residuals (new, beyond SWAP_BANK)

- [ ] **Hardware-mode tamper erase for the BHK-protecting tamper(s).** DS §3.43.2:
      tampers support HW mode = immediate silicon erase of backup registers (incl.
      BHK), no CPU in the loop. Use HW-mode as the **belt** (an attacker who
      halts/glitches the core can't stop it) + the planned software
      `trigger_lockout_wipe()` as **braces** (the coordinated dual-SE zeroize
      HW-mode can't do). `tamp.rs` is log-only today; production needs both.
      **BUG (found 2026-05-29, RM0456 §64.7 + mem-map L7293/L7306):** `tamp.rs`
      uses `TAMP = 0x5600_4400`, which the memory map assigns to **LPTIM1**, not
      TAMP. The TAMP register map is **0x5600_7C00** (matches `bhk.rs` `TAMP_S`).
      So `tamp.rs`'s `CR3=0` write (and every CR1/IER/etc. write) lands on LPTIM1,
      not TAMP — the "all internal tampers in confirmed mode" config is NOT live.
      Fix the base to `0x5600_7C00` before relying on HW-mode erase; confirmed
      mode (CR3 ITAMPxNOER=0) is what erases BKP0R..BKP7R via the `tamp_confirmed`
      signal (Table 644 L183834-183836, unconditional — no TAMP_ERCFGR bit needed;
      ERCFG0 @0x54 gates only Backup SRAM, L183849-183852).
- [ ] **Place secret SRAM in an ECC-on bank + treat double-error as tamper.** DS:
      SRAM2 (64 KB) and 256 KB of SRAM3 support ECC (786 KB ECC-off / 722 KB
      ECC-on). Put `master_secret` / slot-cache / reconstructed entropy in an
      ECC-enabled region; an FI-induced bit-flip then faults (ECC double-error)
      instead of silently corrupting a security decision — complements M-15.
- [ ] **PVD + raised BOR** (M-15 bucket, cheap). Arm PVD (undervoltage interrupt)
      → route the ISR to the zeroize/lockout path; raise BOR above the 1.71 V
      default to shrink the voltage window a glitch can dwell in.
- [ ] **TAMP backup-register secure-zone + privilege.** BHKLOCK is set (`bhk.rs`),
      but configure the 3-zone backup-register SECCFGR boundary + mark the TAMP
      *config itself* SECURE+privileged (`TAMP_PRIVCFGR`) so NS code cannot disable
      tamper or the BHK-erase — the backup-domain analogue of the GTZC allowlist.
- [ ] **Doc — RDP Level 0.5** is missing from our 0/1/2 progression. It exists
      (TZEN-only: secure-debug closed, NS-debug + NS-flash R/W open) — the
      manufacturer/auditor NS-debug-while-secure-locked state, NOT a field
      substitute for L1/L2 (Flash Write=Yes at 0.5). Add to the ceremony narrative.
- [ ] **Doc — enumerate the 11 internal tampers in M-14** (JTAG-if-RDP>0,
      crypto-fault on RNG/SAES/AES/PKA, backup-voltage, temperature, LSE) — already
      enabled in `tamp.rs`; M-14 just says "internal tamper on." Audit-facing.

#### Already enforced in code — name them in Matrix-1 (NOT new holes)

The automated pass grepped only docs; a code-check found these already implemented
— the gap is only that the matrix doesn't name the controller:
- **MPCBB** block-based secure SRAM — `sau.rs` configures MPCBB1/MPCBB2.
- **TAMP BHKLOCK** — `bhk.rs` sets `TAMP_SECCFGR.BHKLOCK` (bit 30).
- **RCC TrustZone** — auto-propagates from our TZSC peripheral-secure marking (DS
  §3.8: RCC shares the securable-peripheral status), so SAES/HASH/RNG/PKA clock
  controls are already secure.
- **GPDMA exfil** — a non-secure DMA master is blocked from secure SRAM by MPCBB
  (master-aware), which we configure. (Verify on silicon alongside the GTZC test.)
- **GPIO** — all GPIOs secure after reset (fail-closed); we de-secure only USB
  pins. Verify trusted-path GPIOs (OLED SPI, buttons, SE I2C) stay secure.

#### Decisions to record (most resolve to "unused — document it")

MPU (likely unused — no RTOS) · secure-world privilege axis (likely single-
privilege) · OTFDEC (N/A — internal-flash boot; confirm no external encrypted
region) · MPCWM (N/A — external mem unused) · DCACHE (external-memory-only →
unused; still set the cache TZ-security attribute in FSBL) · IWDG/WWDG option-byte
freeze-in-Debug config · flash NVM ECC (SED/DED — wire as an integrity signal for
FSBL/counter pages) · DPA-resistant PKA (not load-bearing — SPHINCS+ is the only
signer, BLS verify is over public data) · add the MCU's own cert line to Matrix-1.

#### Confirms — resolved / corroborated against the DS

- **OTP = 512 bytes**, one-way, survives mass-erase. Budget: 32 B master +
  ~128 B rollback ≈ 160/512 — state the ceiling, tally future consumers.
- **UID (96-bit) @0x0BFA_0590 is the read-only system-memory area**, SEPARATE from
  the writable user-OTP at 0x0BFA_0080 — different sub-blocks, NOT an overlap.
  (Both addresses are RM0456, not the DS.)
- **RNG = NIST SP800-90B** (no AIS-31 claim — do not assert AIS-31).
- **SAES is the ONLY DPA-side-channel-hardened AES** on the part — routing
  DHUK/BHK through SAES is correct; never route a secret through the plain AES.
- **Tamper budget for our exact part** (STM32U585AII6Q, UFBGA169 + SMPS):
  **8 external tamper pins, 7 active meshes**; 32 backup registers (we use 8 → 24 spare).
- **DHUK rooted in an OTP-based RHUK; BHK cleared on tamper/RDP-regression** ✓.
- ⚠️ **SESIP3 + PSA Level 3** — DS says "(Target)" = assurance *target*. Verify
  against the PSA/SESIP registry before citing as achieved (same caution as the
  OPTIGA cert number). **DEV_ID 0x482 is RM0456** (not the DS) — cite it in Phase 1.1.

### SE050 — SCP03 + ADMIN provisioning

The SE050 half of the dual-SE also has irreversible steps (per
`docs/secure-elements/se050-factory-reset.md` + work-todo #20). Summarising here:

- [ ] **SCP03 keys rotated per device** (work-todo #11). Derivation
      root and chip-state changes:
      - Today: hardcoded AN12436 Rev 2.4 defaults for OEF `0xA921`
        at `secure/src/se050/scp03.rs:21-30`. `KEY_VERSION = 0x0B`.
        Every device of the same firmware build shares identical
        keys (the keys are *published* — SCP03 confidentiality vs. a
        datasheet-armed bus sniffer is currently theatre).
      - Post-#11 Stage A (derivation plumbing, **reversible**): firmware
        pulls the root from `secret_keys::se050_scp03_{enc,mac,dek}_key()`
        under the `se050-derived-scp03` Cargo feature, and `establish()`
        gains a probe-on-boot fallback (try derived keys at `KVN=0x0B`
        first; on MAC mismatch / `0x6A88` retry with the hardcoded
        constants), so one firmware works against both rotated and
        factory-default chips. No chip writes at this stage.
      - **Root = BHK** (not DHUK, not DHUK⊕BHK). `se050_scp03_*_key`
        route through `derive_into_bhk` ⇒ `SAES-CMAC(BHK,
        "se050-scp03-{enc,mac,dek}-v1")` in a `bhk`-on build (which is
        the production build); falls through to `derive_into` (DHUK /
        OTP per build) when `bhk` is off. Same axis as the SE050 admin
        PIN. Rationale for BHK here (vs. the OPTIGA PBS, which stays on
        DHUK): the SE050's SCP03 keyset `0x0B` is *replaceable* (you can
        PUT KEY it again) and on an RDP2 production unit the BHK can
        never be lost (no regression path) ⇒ the "BHK gone → unrecoverable"
        brick mode is structurally impossible, so the Tier-2 isolation
        (a silicon-DHUK extraction doesn't reach `half_E`) comes for
        free. The OPTIGA PBS is the opposite case — its E140 is bumped
        to `LcsO=Operational` (immutable), so its root must be the
        maximally-stable thing = the silicon DHUK. See
        `docs/architecture/trezor-comparison.md §6.5` for the full reasoning.

      **The irreversible part — GP PUT KEY ceremony (stage B)** — run
      ONCE per chip, at production-provisioning time only (see ordering
      constraint below):

      1. Establish SCP03 against keyset `KVN=0x0B` with the hardcoded
         AN12436 constants (the factory state of a fresh chip).
      2. Compute the per-device keys via `secret_keys::se050_scp03_*_key()`
         (BHK-rooted — so this MUST run on a unit whose BHK is already
         provisioned at its final per-die-DHUK RDP level, see below).
      3. Compute the Key Check Value per key (`KCV` = AES-ECB-Enc over a
         fixed filler block, truncated to 3 bytes — exact filler per GP
         2.3 §11.8 / AN12436 §5.2; pin against the `plug-and-trust`
         reference when implementing).
      4. Wrap each new key under the *current* DEK:
         `wrapped = AES-ECB-Enc(current_DEK, new_key)`. The OEF-`0xA921`
         factory DEK is `67 02 DA C3 09 42 B2 C8 5E 7F 47 B4 2C ED 4E 7F`
         (`plug-and-trust/sss/ex/inc/ex_sss_tp_scp03_keys.h:223`).
      5. Send GP `PUT KEY` to **replace keyset `0x0B` in place** — i.e.
         the data-field KVN is `0x0B`, not a new `0x11`. (Adding a new
         `0x11` would leave the published `0x0B` keys live and still
         authenticatable → the rotation buys nothing; and there is no
         command to *delete* a keyset, so replace-in-place is the only
         real option. Exact `P1`/`P2` framing per GP 2.3 §11.8 — `P1` =
         KVN-to-replace = `0x0B`, `P2` = first-key-id with the
         multiple-keys bit; pin against the reference impl.) Body =
         `[0x0B] ([key_type=0x88 AES][len=0x10][wrapped][kcv_len=0x03][kcv]) × 3`
         for ENC / MAC / DEK — SCP03 always installs all three even
         though we never *use* the DEK after rotation (AN12436 §5.2.3).
      6. Verify `SW=0x9000`.
      7. From here on every boot establishes against `KVN=0x0B` with the
         BHK-derived keys; the probe-on-boot fallback (Stage A) lets the
         same firmware still cope with a not-yet-rotated chip.
      8. Optional stage C (#11): mix the SE050 UID into the derivation
         label for clone defense. One extra `ReadObject(0xA000_F00E)` on
         every subsequent boot.

      **Provisioning-order constraint (because the root is BHK):** the
      BHK is 32 random bytes generated at first boot and stored in flash
      page 126 *DHUK-ECB-wrapped*. The DHUK changes once, at RDP0→RDP1
      (ST-substituted constant → real per-die). So the BHK first-write
      AND this PUT KEY ceremony MUST happen *after* the unit has been
      stepped to its final per-die-DHUK RDP level (RDP ≥ 1) — provision
      the BHK at RDP0 and then step to RDP1 and page 126 no longer
      decrypts to the same bytes ⇒ every BHK-derived secret (admin PIN
      *and* the SCP03 keyset) is silently wrong ⇒ dead SE050. Factory
      sequence: **step RDP → 1 → provision (BHK first-write here) →
      OPTIGA provision → SE050 provision → SCP03 PUT KEY → … → burn
      RDP2.** (This ordering constraint already applies to the
      Phase-2C admin PIN; the SCP03 rotation just inherits it.)

      **Failure modes after commit:**
      - Lose the BHK → cannot re-establish SCP03 → hard brick, same
        class as OPTIGA PBS loss. On a production unit this is
        structurally impossible: RDP2 has no regression path, so the
        flash mass-erase that would clear page 126 cannot happen; WRP on
        page 126 (separate item below) blocks a buggy firmware from
        erasing it. On a *dev* board it is very possible (the
        RDP1↔RDP0 dance mass-erases) — which is exactly why the PUT KEY
        ceremony build (`se050-rotate-scp03`) is production-provisioning-
        only and is NEVER flashed to a board that still moves RDP around.
      - Partial `PUT KEY` (brown-out mid-rotation): potentially leaves
        the chip with one-of-three keys updated, breaking SCP03. The
        pre-commit checklist rehearsal on sacrificial parts MUST verify
        that `PUT KEY` is atomic at the chip level (NXP spec says it
        is; confirm empirically) — and the firmware-side probe-on-boot
        fallback gives a partial-rotation chip a fighting chance (it'll
        still try `0x0B` with the hardcoded keys, which won't work if
        any key changed — so really: rely on atomicity, confirm it).
- [ ] **Admin UserID at 0x7B10_00A0** (range v6, bumped 2026-04-22 from
      v5 `0x7B0E_00A0` / v4 `0x7B0C_00A0` / v3 `0x7B06_00A0` across
      bench-chip cross-contamination events) with two-entry
      TAG_POLICY provisioned. Admin PIN derivation status:
      - **Today:** derived on demand via `hw::secret_keys::se050_admin_pin()`
        → `derive_into_bhk("pqsigner/se050-admin-pin-v1")`. Per the
        build: `SAES-CMAC(BHK, …)` in a `bhk` build (the shipping
        target — the Phase-2C call-site flip landed in `aa23f05` and was
        hardware-validated via `dual-se-bhk-e2e` 2026-05-12); falls
        through to `SAES-CMAC(DHUK, …)` with `saes-dhuk` alone;
        `HKDF(OTP-master/const, …)` on the legacy / `otp-hardcoded-
        master-key` path. Both `Se050::store_objects` (provisioning)
        and `Se050::factory_reset_admin` (wipe) use the derivation;
        nothing is persisted — page 125's PIN slot is gone entirely
        (`hw::flash::write_admin_pin` / `read_admin_pin` /
        `ADMIN_PIN_OFFSET` deleted, commits `482969d` + `da18f29`); the
        page still holds the wipe-in-progress flag at offset 16.
      - **Provisioning-order constraint** (because the production root is
        the BHK): the admin UserID must be created at the unit's final
        per-die-DHUK RDP level (RDP ≥ 1) — the BHK's flash wrapping
        (page 126) is DHUK-keyed and the DHUK changes at RDP0→RDP1, so
        a chip provisioned at RDP0 then stepped to RDP1 has a silently-
        wrong admin PIN. Same constraint the SCP03 rotation inherits
        (see the SCP03 item above): step RDP→1 → provision BHK →
        provision SE050 (admin UserID here) → … → burn RDP2.
      Wipe flow validated via `make dual-se-admin-wipe-e2e` (full
      8-step roundtrip) + `make dual-se-multi-unlock-e2e` (15 unlocks
      across 3 cold reboots), and — with the BHK-rooted admin PIN —
      via `make dual-se-bhk-e2e` (8/8, `factory_reset_admin → Ok`,
      `store_objects OK`, `Admin factory reset complete`), all PASS on
      real silicon.
- [ ] **User UserID PIN storage.** Change the UserID's policy to
      whatever we ultimately ship (currently in `docs/se050-userid-
      pin-auth.md`); post-provision, policy is frozen.

#### SE050 SCP03 rotation pre-commit checklist (sacrificial parts)

Before flipping `se050-rotate-scp03=on` on any real unit:

1. On sacrificial SE050 #1: build + flash with `se050-derived-scp03`
   only (no rotate feature). Confirm the build talks to a factory-
   default chip → SCP03 establishment FAILS with key mismatch. This
   is the expected behaviour: post-plumbing-only builds CANNOT talk
   to un-rotated chips. Log the error, no chip state committed.
2. On sacrificial SE050 #2: build + flash with `se050-rotate-scp03`.
   First boot: firmware sees default keyset, runs PUT KEY ceremony,
   rotates to `KVN=0x11` with derived keys. Second boot on the same
   chip: firmware uses `KVN=0x11` + derived keys → SCP03 establishes.
   Third boot: reflash with a comment-only code edit, confirm SCP03
   still establishes (derivation stable across firmware rebuilds).
4. On sacrificial SE050 #3: same as #2 but induce a brown-out
   mid-`PUT KEY` by cutting VCC between the ENC and MAC key writes.
   Verify on restore: either all three keys rotated (atomic), or
   chip reports specific error the code can detect and retry. If
   partial rotation survives the brown-out → halt the rollout and
   re-design.
5. On sacrificial SE050 #4 (only if stage C is shipping): repeat #2
   with UID binding enabled. Confirm derivation depends on UID:
   swap the rotated SE050 to a different STM32 board with
   `se050-rotate-scp03` built for that STM32's OTP → SCP03 establish
   fails (different OTP → different derived keys → key mismatch).
   Swap back → works. This is the clone-resistance proof.
6. Only then: production line runs per-unit `PUT KEY` → provision →
   admin UserID + user UserID install → option-byte lock. Per-part
   logs record: SE050 UID, KVN 0x11 KCV (3 bytes per key), post-
   rotation SCP03 establishment success, first-boot admin PIN
   derivation fingerprint.

#### SE050 SCP03 rotation — escape hatch

**None.** Unlike OPTIGA's SetObjectProtected + Trust Anchor recovery
(which can reset user OIDs at `LcsO=Op`), SE050 has no reset-to-
factory-keys path for SCP03. The `0x0B` default keyset still exists
on the chip (GP `PUT KEY` installs new keysets, doesn't replace the
default), but once the firmware commits to `KVN=0x11` there's no
build-time path back to `0x0B` without an explicit rollback feature
— and rolling back exposes every device to the same factory default
that made rotation necessary in the first place. Treat a lost
derivation root as a total loss of that chip.

### SE050 — datasheet cross-reference (AN12413/AN12436, 2026-05-29)

Variant pinned **SE050E2 / OEF 0xA921** (see Matrix-3 preamble). Matrix-3 rows carry
the per-row corrections; the residuals + decisions below come from the AN12413/AN12436
cross-reference (full 56-finding set in the run output).

- **half_E `ALLOW_WRITE` (write-once) — SHIP ITEM (work-todo).** Code grants READ|WRITE|
  DELETE (REQUIRE_SM-gated); READ+DELETE are design-mandatory, WRITE is droppable and MUST
  be dropped at the FIRST provisioning run (policy immutable post-create). [S-C]
- **S-7 closed (doc side):** AN12413 §3.2.4.4 — a TYPE_USERID object's auth-attempts attribute
  is spec'd to "remain 0," so the SE050 boot-reconcile leg is dead-by-spec (stronger than the
  0x6986 reason already cited). Code behavior already correct (returns `None` → leg skipped);
  the `mod.rs:527/533` comment mislabels the field → fix the comment (queued code change).
- **Variant/`GetVersion` assertion (work-todo)** — expected OEF `0xA921`, fail-closed (anti-substitution).
- **Pre-provisioned NXP credential objects** (`0xF000_0xxx` cloud keys + `0x7FFF_xxxx`) survive
  DeleteAll and are undeletable — code already skips them (`apdu.rs:1022`). Add a provisioning-
  acceptance row: `ReadIDList`, confirm the only non-NXP objects are PQ1's; document the NXP
  objects are off our trust path.
- **Applet LockState / transport lock** — assert the applet is **Active** at boot (GetVersion/
  CreateSession probe) and fail loudly if transport-locked, rather than letting SCP03 fail
  opaquely. Optionally evaluate `PERSISTENT_LOCK` + `RESERVED_ID_TRANSPORT` (held in PQ1's HSM)
  as a provisioning tamper-seal.
- **Platform-SCP-not-forced (decide):** SE050E defaults `SCP_NOT_REQUIRED`; we rely on per-object
  `REQUIRE_SM` (sufficient for half_E). Decide whether to also `SetPlatformSCPRequest` to force
  the whole channel as defense-in-depth.
- **Smaller attack-surface items (verify/decide):** I²C-master feature (`RESERVED_ID_I2CM_ACCESS`
  / `CONFIG_I2CM`) — confirm not exploitable; strong-attack/tamper-fault counter
  (`RESERVED_ID_ATTACK_COUNTER`) — could be read as a tamper signal; secure-import
  (`ImportExternalObject` + RFC3394 wrapped-key) — confirm no unexpected injection path.
- **Decisions to record (unused):** PCR / `REQUIRE_PCR_VALUE` (we do measured-boot MCU-side) ·
  ECKey session (unused — platform SCP03/AESKey only; `RESERVED_ID_ECKEY_SESSION` is
  NXP-provisioned device-unique, not a secret to rely on) · Crypto Object lifecycle (N/A —
  invariant #5, no crypto) · `POLICY_OBJ_FORBID_ALL` for spare/provisioning objects.
- **Confirms that resolve:** default Platform SCP03 keys for our variant + P1=0x33 ✓; PUT KEY
  keyset 0x0B ✓; **per-object `REQUIRE_SM` forces a secure channel for half_E even with platform
  SCP not forced** ✓ (our confidentiality basis); `RESERVED_ID_FACTORY_RESET` (0x7FFF0205)
  NXP-reserved/unavailable ✓ (corroborates S-6 + the BHK Phase-2C ship-gate); UserID immutable
  post-create + max_attempts 0..255 / 0=unlimited / prod=10 ✓; CC EAL6+ ✓; object attributes
  immutable after creation = the spec root-cause of S-6/S-7 ✓.

### Supply-chain attestation (work-todo #22)

- [ ] **SLH-DSA-128s factory manifest signed with HSM key.** Once the
      HSM key is created, the corresponding trust anchor is baked into
      the FSBL. Rotating the HSM key requires a firmware update on all
      already-shipped devices. Treat the initial HSM-key ceremony as
      a one-way event.
- [ ] **Transparency log append for each device.** Appending is
      trivially reversible (just don't append), but by the time a
      device is shipped, its manifest hash must already be in the log
      for the verification ceremony to succeed. Missing a device →
      that device fails its own box-opening ceremony.

### Firmware-update signing

- [ ] **Vendor signing key(s) established.** SPHINCS+C10 keypair,
      private key kept in Argon2id + XChaCha20-Poly1305 encrypted
      blob (see `fwsign keygen`). Losing the private key means no
      future updates for the installed base. The public key is baked
      into the FSBL at factory provisioning — changing it requires
      an FSBL update, which requires WRP1A unlock, which requires
      RDP regression (mass erase). So: lose the key, lose the fleet.

### Hardening regressions — restore before production

These are pre-production regressions the bring-up branch knowingly
ships with, flagged in `CLAUDE.md` §"Development Posture" and
surfaced by the three-way PIN-sync validation runs (2026-04-22).
None of them affect the PIN-sync / wipe-dispatch paths that were
validated on silicon — the three-way lockstep, boot-time cache
re-sync, and MCU-MAX wipe dispatch all work today. They DO affect
the broader secure-world isolation that production will need.

- [ ] **GTZC1_TZSC_SECCFGR{1,2,3} allowlist restored to invariant #4.**
      Currently `secure/src/sau.rs` clears these to 0 (everything NS)
      because the first attempt at the "CRIT-4 all-secure baseline"
      mis-identified which controller governs USB OTG FS on STM32U585
      — USB OTG FS is AHB2, governed by a separate **GTZC2_TZSC** block
      whose base address we have not yet confirmed (`0x5203_4400`
      bus-faulted on first guess). This makes peripherals like I2C1,
      AES, HASH, PKA, SAES, RNG reachable from the non-secure world —
      a regression of CLAUDE.md invariant #4 ("all secrets live ONLY
      in TrustZone secure world"). Fix: locate the GTZC2 base
      empirically on the STM32U585 silicon (or via RM0456 rev C2+ if
      it lists the address), reinstate a conservative allowlist that
      lets USB OTG FS reach NS while keeping I2C1 / HASH / PKA / SAES
      / RNG strictly secure.

- [ ] **Debug instrumentation stripped from release builds.** The
      bring-up branch shipped with `debug-log` allowed on hardware
      release (the `compile_error!` gate in `secure/src/nsc/mod.rs`
      was removed), `hw::hash::init_clock`'s semihosting prints are
      `DHCSR.C_DEBUGEN`-gated rather than deleted, `secure_log!`
      calls litter the first-boot wizard, and the NS `main()` emits
      pre-USB register dumps. Production CI must gate shipped
      firmware on `debug-log`, `e2e-test`, and `mock-se` being OFF —
      the existing `make prod-check` target is the right hook, but
      needs to actually fail the build rather than warn when these
      features are present.

- [ ] **Destructive / dev-only test feature fence.** The following
      targets exist for silicon validation or bring-up diagnostics
      and must not reach production firmware: `pin-gate-wipe-e2e`,
      `pin-gate-hw-counter-e2e`, `dual-se-admin-wipe-e2e`,
      `dual-se-multi-unlock-e2e`, `optiga-admin-wipe-e2e`,
      `se050-admin-wipe-e2e`, `wipe-for-wizard`, `pin-diag-boot`,
      `dev-testkey`, `otp-hardcoded-master-key`. Most transitively
      require `e2e-test`, which is already in the `compile_error!`
      gate in `secure/src/nsc/mod.rs`, but `make prod-check` must
      fail the build when ANY of these features is enabled — the
      current gate only covers `e2e-test` + `debug-log` + `mock-se`.
      Adding a new destructive / dev-only e2e feature must land
      with a matching `prod-check` entry in the same commit.

- [ ] **`optiga-lock-operational=ON` production commit.** Every
      validated test run to date has kept every OID at
      `LcsO=Creation`. The production bump to `LcsO=Operational` is
      covered by this document's OPTIGA section (and is the defining
      commit ceremony of the OPTIGA subsystem), but also needs
      explicit cross-validation against the PIN-sync paths before
      flipping: confirm that `reset_hw_pin_counter`,
      `factory_reset`, and the three-way lockstep all still work on
      an OID set with `LcsO=Op` metadata. See work-todo.md #25 Gap 5
      for the reversible dry-run on a sacrificial chip that must
      precede any production LcsO=Op flip.

- [ ] **`make test-key-speed` as release smoke gate.** The NS bench
      is the primary "did anything regress signing perf?" detector.
      Confirmed working 2026-05-06 (see work-todo #27 for the
      stale-NS-veneer false alarm and resolution). **Pre-release CI
      gate (must hold before any production firmware tag):**
      `make test-key-speed` exits 0 on real STM32U585 silicon AND
      the reported A / B-avg / C timings are within ±15% of a recorded
      baseline. Recorded reference timings on B-U585I-IOT02A as of
      2026-05-06 (TAMP IRQ-mode, mock-se + e2e-test, fresh secure +
      NS link):

        A) chain=1 first-sign (Type1 + slot-keygen + Type2)  ~9,200 ms
        B-avg) chain=1 type2-only (slot cached)              ~4,000 ms
        C) chain=2 first-sign (slot keygen-cached)          ~10,300 ms

      Commit a JSON record of the baseline alongside
      `tests/ui_fixtures.json` once the CI gate is wired. Drift
      outside the band is a release-blocker until investigated.

- [ ] **TAMP escalation: log-only → `trigger_lockout_wipe()`.** Today
      the polled handler in `secure/src/hw/tamp.rs` (`tamp::poll()`
      from SysTick) logs the reason via `secure_log!` and write-1-to-
      clears the SR flag — by design, so a false ITAMP9 during a
      probe-rs debug session can't wipe a bench chip. Production must
      flip three things in lockstep:
        1. Replace `secure_log!(...)` + clear in `tamp::poll()` /
           `tamp::on_tamp_irq()` with `trigger_lockout_wipe()` (which
           zeroizes seed material, erases page 124, and reboots).
        2. Move from polled to IRQ — see work-todo.md TAMP IRQ-flip
           item for the `DefaultHandler` dispatch path. IRQ latency
           (~hundreds of cycles) beats SysTick polling (~1 ms) by an
           order of magnitude, which matters when the wipe is racing
           an attacker reading residual-power side channels off the
           backup SRAM.
        3. Audit `TAMP_IER` / NVIC enable bits across all peripherals
           in the same commit — once `DefaultHandler` is dispatching,
           any unmasked IRQ on any peripheral lands there too. Without
           a firmware-wide audit of "which IERs are set right now,"
           this is a footgun. The audit + wipe-flip + IRQ-mode flip
           must all land in one diff so review can verify the trigger
           surface end-to-end.
      Reference: `docs/architecture/trezor-comparison.md §2.5`,
      `core/embed/sec/tamper/stm32u5/tamper.c:100-207`. The Trezor
      production handler is the model — `reboot_with_rsod()` after
      backup-SRAM auto-erase via `TAMP_CR3=0`. PQSigner is one
      `secure_log!` line away from that today.

## Where items come from

When an item is moved out of `docs/work-todo.md` into here, the diff
looks like a removal from work-todo.md and an addition here, with
the context preserved. The intent is that work-todo.md stays
strictly reversible so dev iteration is always safe, while
production-todo.md is the "commit ceremony" checklist.

When a dev flow discovers a new one-way action (say, a new SE
provisioning step), the item lands HERE by default. Only after it
becomes clear that a reversible variant can be written — e.g., gated
behind a feature that keeps the chip at LcsO=Creation — does a
reversible sibling appear in work-todo.md.

## Current validation state

As of 2026-04-23:

- **Phase A (reversible) validated** on TRUSTMV3SHIELDTOBO1 —
  `docs/work-todo.md` #24 P2. Shielded Connection + PIN unlock +
  factory_reset roundtrip all PASS on real silicon.
- **Dual-SE entropy reconstruction validated across reboots.**
  `make dual-se-multi-unlock-e2e` does 5 unlocks per boot across
  3 cold boots (15 unlocks total). Boots 2 + 3 detect
  already-provisioned state and skip re-provision → pure NVM
  read + XOR reconstruction, master_secret reproduces byte-identical
  every time. Closes the colleague-reported "works once, fails on
  reboot" class caused by OPTIGA RST jumper on D5 cross-coupling
  into SE050 ENA via the OM-SE050ARD shield. RST wire physically
  moved to D6 (= STM32 PE0 empirically on this board; `header_sweep`
  retained as pre-flight validator for any future board rev).
- **Dual-SE admin-wipe validated end-to-end.** `make dual-se-admin-
  wipe-e2e` PASSES all 8 steps including step 7 (both chips
  unprovisioned post-wipe). Admin PIN derivation now OTP-rooted
  in both provisioning and wipe paths; 6-canary selftest proves
  the 6-delete-under-one-session shape that production
  `admin_factory_reset` depends on is stable on the chip.
- **Phase B (irreversible, E140 LcsO=op)** not yet attempted. No
  sacrificial part burned yet. When it happens, it goes against a
  fresh TRUSTMV3 shield with the pre-commit checklist above fully
  passed.
- **OTP master burn path** still under the hardcoded-master-key
  feature on every dev build. First-burn validation on a
  sacrificial MCU is still owed. The admin-PIN derivation now
  depends on this — migrating off `otp-hardcoded-master-key` is
  a prerequisite for any chip ever leaving the bench.
- **DHUK + BHK tiers** (work-todo #7) not implemented yet. All SE
  pairings today derive from the readable OTP master; Tier 1
  migration has not started. The DHUK probe → per-part record flow
  and BHK first-write are all factory-only actions that land
  concurrently with #7.
- **RDP + WRP1A + SECBOOTADD0** never exercised. `make stm32-harden-
  opts` in the Makefile sets BOR/SRAM2_RST only.

Nothing from this list has been committed on any dev unit. When
anything does get committed, this file gets a dated entry recording
which part, which commit hash, and which checklist run justified the
flip.
