# audit:pin-unlock — Security Audit (20260625-114309)

## Scope & threat model

Target: the PIN / unlock path and the three-way attempt-counter lockstep
(MCU page-124 ↔ OPTIGA E120 LUC / F1E1 soft ↔ SE050 USERID `auth_attempts`),
per CLAUDE.md **invariant #2** ("Hardware PIN gating, three-way lockstep … PIN
compare in SE silicon, never in MCU … Boot reconciles to strictest;
disagreement = tamper. `MAX_ATTEMPTS = 10`") and **invariant #3** (E2E-encrypted
SE tunnels). Plus the explicitly-named known-open OPTIGA shipping-state
ship-blockers S-1/S-2/S-3 and the SE050 S-5 residual.

This is the third pass on this surface (prior: `pin-unlock-lockstep-20260611-141459.md`,
`-20260623-220401.md`). Everything below was **re-derived from current code**,
not copied; line numbers are current as of this commit. Where a finding is
carried forward it is marked CARRIED-FORWARD and re-confirmed against the tree.

Code read this pass:
`secure/src/nsc/mod.rs` (`gated_unlock`, `reconcile_pin_attempts`, the full
`compile_error!` ship-blocker fence set, dispatcher + every CMSE veneer),
`secure/src/nsc/cmd_request_unlock.rs`, `secure/src/nsc/state.rs`,
`secure/src/hw/flash.rs` (page-123/124/125/126 + duress-wipe-mode QW),
`secure/src/dual_se.rs` (unlock / unlock_duress / duress_pad /
factory_reset_admin / pin_attempt_count / XOR split),
`secure/src/optiga/mod.rs` (`authenticate_and_read`, `read_hw_pin_counter`,
`reset_hw_pin_counter`, `reset_e120_via_transient_auth`, `read_counter_raw`,
`unlock`, `pin_attempt_count`, `factory_reset`, LcsO ratchet `lock_oid` /
`verify_and_lock` / E140 bump), `secure/src/optiga/apdu.rs` (F1D0 metadata),
`secure/src/optiga/reset.rs` (trust anchor), `secure/src/se050/mod.rs`
(`authenticate_and_read`, `verify_session` dispatch, `pin_attempt_count_raw`,
`unlock`, `factory_reset_admin`, `classify_se050_unlock_error`),
`secure/src/secure_element.rs` (trait defaults + `UnlockError`),
`secure/src/main.rs` (boot order: load_pbs → reconcile → wipe-resume →
sync_remaining → wizard/unlock), `Makefile` (`RELEASE_FEATURES`, `prod-check`,
`PROD_FORBIDDEN`, `release`), `secure/Cargo.toml` (feature graph).

Two attacker profiles, both maximally hostile:
* **A-NS** — fully attacker-controlled non-secure world + USB companion, **no
  physical access**. Any gateway CMD with arbitrary arguments.
* **A-PHYS** — patient physical attacker: device in hand, logic analyzer,
  desolder/replace an SE, inject a clock/EM fault (single-fault model unless
  noted). Lost/stolen device, evil maid.

In-scope impact: PIN/unlock bypass, brute-force past the cap, attempt-counter
rollback/desync, seed/half extraction, software PIN compare. **Production
feature target** (every claim is derived against this set, not QEMU/bring-up):
`dual-se` (= `optiga-trust-m` + `se050`) + `optiga-hw-counter` +
`se050-derived-scp03` + `saes-dhuk` + the tamp/tzic/consumption-mask fences.

## Methodology — what you read and how you hunted

1. Traced the unlock control flow end-to-end:
   `nsc_request_unlock` veneer → `cmd_request_unlock::run` → `enter_pin`
   (trusted UI) → `verify_pin_with_chip` → `gated_unlock` →
   `DualSecureElement::unlock` → OPTIGA `authenticate_and_read` + SE050
   `authenticate_and_read`. Read the *body* of every "we check X."
2. Enumerated every site that **reads, bumps, resets, or gates on** each of the
   three counters in the *production* feature set, and asked for each whether a
   single fault / reset / APDU-ordering trick desyncs them or rolls one back.
3. Re-derived the boot reconcile against the *actual* values each SE returns in
   production (`optiga.pin_attempt_count()` reads F1E1; `se050` returns `None`),
   not the docstring's claims.
4. Differential pass: diffed the OPTIGA vs SE050 unlock legs check-for-check;
   diffed the page-124 bump gate vs its two sibling sentinel gates; diffed the
   wipe-flag crash-safety against the unconditional page-124 reset.
5. Treated the ship-blocker `compile_error!` fences as code to break: enumerated
   each fence's `cfg` predicate, walked the `Cargo.toml` feature graph for what
   pulls each hardening feature, and resolved what `make release` / `make
   prod-check` actually compile and accept.
6. Hunted the new(er) surfaces the earlier passes only skimmed: the `duress-pin`
   dispatch inside `gated_unlock`, the `factory_reset_admin` failure paths +
   page-124 refund, and the `reset_e120_via_transient_auth` wipe helper.
7. Grepped for any software PIN comparison and any NS-reachable counter-reset
   path.

**Bottom line up front.** I found **no new NS-triggerable or single-glitch PIN
bypass / brute-force / extraction.** The three counters DO advance in lockstep
on a wrong PIN (proven below). The two real defects on this surface are both
carried forward and re-confirmed against current code: the boot reconcile is a
**dead detector** in production (invariant #2's "disagreement = tamper" cannot
fire — MEDIUM-1 here), and the page-124 bump-failure gate is **FAIL-OUT**
(single-glitch uncharged attempt, SE-silicon-bounded — MEDIUM-2 here). The
OPTIGA ship-blocker enforcement gap (S-1 fence keyed on `mode-production` alone)
remains open and is the highest-impact item (HIGH-1).

## Findings (ordered by severity, most severe first)

---

### [HIGH-1] CARRIED-FORWARD (still open): the S-1/S-2 closure feature `optiga-lock-operational` is enforced ONLY by a `mode-production`-keyed fence — the canonical `make release` path ships F1D0 `Change=ALW` + mutable metadata → desolder-bench seed extraction via the shared PIN

- **Location:**
  - S-1 fence: `secure/src/nsc/mod.rs:337-351` — `cfg(all(mode-production,
    optiga-trust-m, not(optiga-lock-operational)))`. Every *sibling* hardening
    fence keys on the broader `any(mode-production, all(stm32u585,
    not(debug_assertions)))`: S-3 `:274-291`, S-2 `:298-312`, consumption-mask
    `:365-380`, tamp/tamp-wipe/tzic-wipe `:400-420`, se050-derived-scp03
    `:439-460`, optiga-no-shield `:470-486`. S-1 is the **lone** require-fence
    pinned to `mode-production` only.
  - F1D0 metadata selector: `secure/src/optiga/apdu.rs:1080`
    (`build_metadata_auth_ref_luc_oid(OID_PIN_CTR, cfg!(feature =
    "optiga-lock-operational"))`) → `:1089,1104-1107`
    (`change_is_auto == false` ⇒ `push_ac_simple(.., META_CHANGE, AC_ALW)`).
  - Trust anchor at `0xE0E3` is Infineon's PUBLIC sample cert (S-2):
    `secure/src/optiga/reset.rs:16` (sample EC P-256 key), `:26`
    (`TRUST_ANCHOR_OID = 0xE0E3`), `:33-38` (cert from the Infineon
    protected-update sample tool — matching private key is public).
  - LcsO ratchet code, gated solely on the feature: E140 bump
    `secure/src/optiga/mod.rs:622-647` (with an `is_device_master_burned()`
    runtime guard at `:626`), `lock_oid` `:754-775`, `verify_and_lock`
    `:799-838`. **Correction to the 2026-06-11 audit:** the ratchet is NOT
    additionally gated on `factory-production-irreversible-im-sure` — that flag
    (`Cargo.toml:499`) is unused in the ratchet path. Satisfying the S-1 fence
    (= enabling `optiga-lock-operational`) does run the real ratchet; the gap is
    purely that the fence does not fire on the canonical build path.
  - Feature graph: `secure/Cargo.toml:553` (`optiga-lock-operational = []`,
    **zero reverse-dependencies**), `:307` (`optiga-hw-counter =
    ["optiga-trust-m"]` — does NOT pull lock-operational).
  - Build path: `Makefile:1979` (`RELEASE_FEATURES ?=
    stm32u585,se050,optiga-trust-m,dual-se,ui-lcd,saes-dhuk,se050-derived-scp03`
    — omits `mode-production`, `optiga-hw-counter`, `optiga-lock-operational`,
    `consumption-mask`, `tamp*`, `tzic-wipe`), `:1989` (`PROD_FORBIDDEN`),
    `:1994-2009` (`prod-check` — a **denylist** that greps for forbidden
    features, never asserts a required feature is present), `:2012` (`release:
    prod-check`).
- **Vulnerability class:** broken hardware-lifecycle access control; missing
  build-time enforcement of a security invariant; shared-PIN cascade.
- **Attacker & required capability:** A-PHYS. Desolder the OPTIGA (or sit on its
  I²C bus). The exploit needs only an OPTIGA at LcsO=Creation with F1D0
  `Change=ALW` — exactly what a release build omitting `optiga-lock-operational`
  provisions.
- **Minimal trigger (the build side — what produces the vulnerable image):**
  Default `make release` does NOT compile (S-3 / consumption-mask / tamp fences
  fire because those features are absent). The operator is forced to add
  features — but the compile errors name only `optiga-hw-counter`,
  `consumption-mask`, `tamp`, `tamp-wipe`, `tzic-wipe`. Building with exactly
  those (every named fence satisfied):
  ```
  make release RELEASE_FEATURES="stm32u585,se050,optiga-trust-m,dual-se,\
    ui-lcd,saes-dhuk,se050-derived-scp03,optiga-hw-counter,consumption-mask,\
    tamp,tamp-wipe,tzic-wipe"
  ```
  compiles **clean** (the S-1 fence is keyed on `mode-production`, which is
  absent, so it never fires) and `make prod-check` **passes** (none of the added
  features are in `PROD_FORBIDDEN`; a denylist cannot express "lock-operational
  is missing"). The image provisions F1D0 `Change=ALW` (apdu.rs:1104-1107) and
  never ratchets LcsO=Operational.
- **Exploitation path (numbered, concrete):**
  1. A release image as above ships with F1D0 `Change=ALW`, every OID at
     LcsO=Creation (metadata fully mutable).
  2. A-PHYS desolders / MITMs the OPTIGA. Because F1D0 `Change=ALW`, the attacker
     `SetDataObject`-overwrites F1D0 with a *chosen* HMAC key — no PIN, no
     Shielded-Connection secret at Creation. (This is the *same* primitive the
     firmware itself uses legitimately during wipe — `reset_e120_via_transient_
     auth`, `optiga/mod.rs:1368-1373`, which depends on "F1D0's Change AC is ALW
     (always writeable)"; an attacker has identical access.)
  3. Self-authenticate F1D0 with that chosen key, satisfying E120's `Change =
     Auto(F1D0)` (apdu.rs:1036), and reset the E120 LUC counter to `(0, limit)`.
     The S-3 silicon lockout is neutralised: **unbounded** F1D0 HMAC-verify
     queries.
  4. (S-2 arm, same missing feature) At LcsO=Creation install your own X.509
     Trust Anchor at `0xE0E3` (the pool is never junk-locked without
     `lockdown_ta_pool`) and send a `SetObjectProtected` manifest signed by the
     matching key to bypass **every** OID's `Change` AC — defeating even an
     isolated S-1 fix. S-1 and S-2 close together, via the *same* feature.
  5. Brute-force the user PIN against the now-uncapped OPTIGA. `half_O` /
     `master` read AC is `Auto(F1D0)`, so a correct PIN yields `half_O`.
  6. **Shared-PIN cascade** (`project_se_removal_invariant`): the user PIN is
     identical on both chips. Enter the recovered PIN on SE050 — its 10-try
     silicon lock never trips because the *first* try is correct → read
     `half_E` (`se050/mod.rs:2705`, `authenticate_and_read` `:2445`).
  7. `entropy = half_O XOR half_E` (`dual_se.rs:26-32,394`) → full BIP-39 seed →
     drain every wallet on every chain.
- **Invariant / security property broken:** invariant #1 (dual-chip split — the
  cascade defeats it), invariant #2 (three-way lockstep), and the
  "remove-an-SE-to-a-bench can't extract the seed" property that
  `project_se_removal_invariant` says holds **only after S-1+S-2+S-3 all land**.
- **Evidence:**
  ```rust
  // nsc/mod.rs:337  — S-1 fence keyed on mode-production ALONE
  #[cfg(all(feature = "mode-production", feature = "optiga-trust-m",
            not(feature = "optiga-lock-operational")))]
  compile_error!("Production OPTIGA builds require `optiga-lock-operational` ...");
  ```
  ```rust
  // optiga/apdu.rs:1104  — without lock-operational, F1D0 Change = ALW
  if change_is_auto { push_ac_auto(&mut inner, &mut c, META_CHANGE, OID_AUTH_REF); }
  else              { push_ac_simple(&mut inner, &mut c, META_CHANGE, AC_ALW); }
  ```
  ```make
  # Makefile:1989 — prod-check is a DENYLIST; it never requires lock-operational
  PROD_FORBIDDEN = e2e-test dev-testkey mock-se debug-log otp-hardcoded-master-key ...
  ```
  `grep -nE optiga-lock-operational secure/Cargo.toml` → `:553` defines it `[]`
  with no feature listing it as a dependency.
- **Falsification attempt — why "shipping == `mode-production` convention" does
  NOT save it:** The S-1 fence comment (nsc/mod.rs:322-336) is correct that the
  fence cannot broaden to `all(stm32u585, not(debug_assertions))` without
  bricking dev hardware (`make e2e-hw` / `play-hw-display` are `--release` HW
  builds, and the LcsO ratchet is irreversible). It names `make prod-check` as
  the belt-and-braces. I tried to use that as the disproof and it fails:
  `prod-check` (Makefile:1994-2009) only scans for **forbidden** features — it
  has no "required-present" clause, so the *absence* of `optiga-lock-operational`
  is invisible to it. The trap is structural: the very `RELEASE_FEATURES`
  default omits `mode-production`, and the compiler actively errors on five
  *other* required hardening features while staying silent on this one — a
  "follow the compiler" operator lands on a vulnerable image.
- **Suggested fix (describe only):** Make `prod-check` an allowlist as well as a
  denylist: after resolving the feature set for an `stm32u585` shipping image,
  FAIL unless `mode-production` (or directly `optiga-lock-operational` +
  `optiga-hw-counter` + `consumption-mask` + `tamp,tamp-wipe,tzic-wipe`) is
  present. Equivalently add a `compile_error!` on `all(stm32u585,
  not(debug_assertions), optiga-trust-m, not(e2e-test), not(dev-testkey),
  not(optiga-lock-operational), not(<new explicit dev-hardware opt-out flag>))`
  so a release HW build must *consciously* opt out of the lock. The remaining
  S-1/S-2 closure (irreversible LcsO ratchet + sacrificial-part validation +
  replacing the public sample Trust Anchor with the PQ1-factory-HSM cert) stays
  bench/factory work.
- **Confidence:** confirmed for the enforcement gap (fence `cfg` predicates +
  feature graph + prod-check denylist + default `RELEASE_FEATURES` all read
  directly, all unchanged since 2026-06-23). The runtime desolder exploit is the
  documented, accepted S-1/S-2 bring-up risk; the code-confirmed part is that the
  post-2026-06-11 fence still does not close it on the canonical build path.

---

### [MEDIUM-1] CARRIED-FORWARD: boot attempt-counter reconcile is a dead detector in production — both SE legs are decoupled from the live lockout, so invariant #2's "Boot reconciles to strictest; disagreement = tamper" can never fire (and may instead self-wipe on a benign wrong-PIN-then-reboot)

> Re-confirmed against the current tree (same defect as the prior passes'
> MEDIUM-2). Re-derived here because it is the load-bearing half of invariant #2,
> and because the `reconcile_pin_attempts` docstring + `main.rs` comment **still
> assert a working three-way cross-check that the code contradicts** ("assume the
> doc lies" — and here it does).

- **Location:** `secure/src/nsc/mod.rs:1006-1031` (`reconcile_pin_attempts`),
  called once at boot from `secure/src/main.rs:1266-1269` (right after
  `load_pbs` at `:1254`, **before** any shield handshake);
  `secure/src/dual_se.rs:467-492` (`pin_attempt_count` = `max` of the two legs)
  / `:494-506` (`pin_attempt_counts_divergent`);
  OPTIGA leg `secure/src/optiga/mod.rs:2943-2948` (`pin_attempt_count` →
  `read_counter_raw` `:2120-2129`, reads `OID_COUNTER = 0xF1E1`), F1E1 never
  bumped/reset under `optiga-hw-counter` (the bump/reset live in the
  `#[cfg(not(feature = "optiga-hw-counter"))]` arm `:2194-2239` / `:2394-2398`;
  the live path uses E120 at `:2164-2192` and `reset_hw_pin_counter` `:2389`);
  SE050 leg `secure/src/se050/mod.rs:571-599` (`pin_attempt_count_raw`) returns
  `None` on the production `USERID_OBJ` policy denial SW=0x6986 — **documented
  outright at `:539-563`**, which explicitly *retracts* the earlier
  "policy-gate-independent" claim that the `nsc/mod.rs:993-1000` docstring still
  repeats.
- **Vulnerability class:** dead tamper-detector / security decision compared
  against a frozen constant; (secondary) availability / spurious wallet wipe.
- **Attacker & required capability:** the *security* loss needs A-PHYS (reset
  MCU page-124 out-of-band and go undetected at boot); the *availability* hazard
  (regime a) needs nobody — a user mistypes the PIN once then power-cycles.
- **Failure analysis (numbered, concrete):**
  1. Production forces `optiga-hw-counter` (S-3 fence, nsc/mod.rs:274-291). Under
     it OPTIGA's lockout is the silicon LUC E120 (`authenticate_and_read`
     `:2164-2192`); F1E1 is no longer bumped/reset — it is frozen at its
     provisioned `0` for the life of the wallet (it doubles as the
     `is_provisioned` liveness sentinel).
  2. The reconcile's OPTIGA leg is `optiga.pin_attempt_count()` →
     `read_counter_raw()` → reads **F1E1**, never E120. The SE050 leg returns
     `None` (policy denial). So `DualSecureElement::pin_attempt_count()` =
     `max(Some(0), None) = Some(0)` (dual_se.rs:486-491), a constant, and
     `pin_attempt_counts_divergent()` = `false` always.
  3. `reconcile_pin_attempts` computes
     `mcu_vs_se = matches!(Some(0), s if s != mcu)` and
     `tamper = mcu_vs_se || se_split` (nsc/mod.rs:1015-1016). Two regimes:
     * **(a) False-positive wipe.** If the plaintext F1E1 read *succeeds* at boot
       and returns `Some(0)`, then whenever page-124 `mcu ∈ [1,9]` (user
       fat-fingered the PIN once then powered off / idle-timed-out before a
       successful unlock), `0 != mcu` → `tamper` → `factory_reset_admin()` +
       `pin_attempts_reset()` (`:1022-1031`). **The wallet self-wipes on a benign
       wrong-PIN-then-reboot** — recoverable only from the 24-word backup. An
       attacker with brief physical access can grief-wipe with one wrong PIN +
       reboot (availability, not theft).
     * **(b) Dead detector.** If the F1E1 read *fails* before the shielded link
       is up (the reconcile runs at main.rs:1268, right after `load_pbs`, which
       does NOT handshake; `read_counter_raw` does not `ensure_shield`), it
       returns `None` → `se_used = None` → `mcu_vs_se = false` → **no tamper ever
       fires**, and an A-PHYS who resets page-124 is not boot-detected.
  4. Either way invariant #2's "Boot reconciles to strictest; disagreement =
     tamper" and the `main.rs:1257-1265` comment are false in production. The
     primary lockouts (MCU page-124 in `gated_unlock`, SE050 silicon, E120) still
     function, so this is **not by itself a PIN bypass** — it removes the layer
     designed to catch a single-counter reset, and (regime a) adds a benign-wipe
     hazard.
- **Why this stays MEDIUM (not HIGH), and the security bound:** the reconcile
  detects "one counter reset out-of-band." For every single-counter reset the
  *other* counters still bound brute force — most importantly the **SE050 silicon
  UserID lock at `max_attempts = 10`** (`se050/mod.rs:2723-2728`,
  `AuthMethodBlocked → PinLocked → wipe`), which a page-124 erase does NOT reset.
  So the dead reconcile removes a tamper *signal* but not the *backstop*; it does
  not enable extraction. Resetting the SE silicon counters themselves requires
  admin auth (S-6 closed: admin can only DELETE) or the S-1 desolder path
  (HIGH-1), not the reconcile gap.
- **Invariant / security property broken:** invariant #2 (three-way lockstep /
  "disagreement = tamper"), defence-in-depth tier; the docstring/comment are an
  active doc-vs-code lie.
- **Evidence:**
  ```rust
  // optiga/mod.rs:2943 — reconcile's OPTIGA leg reads F1E1, never E120
  fn pin_attempt_count(&mut self) -> Option<u8> { unsafe { self.read_counter_raw() } }
  ```
  ```rust
  // se050/mod.rs:554 (doc) — the SE050 leg is documented DEAD in production
  // "On production `USERID_OBJ` ... this method returns `None` at boot, so the
  //  SE050 leg of the boot-time ... reconcile is silently skipped."
  ```
  ```rust
  // nsc/mod.rs:1015 — the only live cross-check value is the frozen Some(0)
  let mcu_vs_se = matches!(se_used, Some(s) if s != mcu);
  let tamper = mcu_vs_se || se_split;
  if !tamper { return; }
  ```
- **Falsification attempt:** I re-checked whether the SE050 leg might be live on
  the current tree (the `nsc/mod.rs` docstring asserts it is). It is not:
  `pin_attempt_count_raw` (se050/mod.rs:571) does `read_object_attributes` on
  `USERID_OBJ`, which the production two-entry policy denies with SW=0x6986
  (documented + silicon-confirmed `:539-563`) → `None`. I also checked whether
  F1E1 tracks E120 under hw-counter — it does not; the bump/reset are
  `#[cfg(not(optiga-hw-counter))]`. Both legs are dead; MEDIUM-1 stands.
- **Suggested fix (describe only):** under `optiga-hw-counter` have
  `OptigaTrustM::pin_attempt_count()` return the **E120** silicon value
  (`read_hw_pin_counter()` → `used = limit - remaining`, normalised to the
  `MAX_ATTEMPTS` scale) instead of F1E1; make `reconcile_pin_attempts`
  FI-sentinel its `tamper` decision and treat a `None` SE leg as "skip + loudly
  log unavailable," never "silently agree." Decouple the F1E1 liveness sentinel
  from anything the reconcile reads as a count. Delete the stale "relies on that
  path" docstring.
- **Confidence:** the design defect (reconcile's live value decoupled from the
  real lockout) is **confirmed** from code. Which runtime regime (a false-wipe vs
  b dead-detector) occurs is **needs-confirmation** on silicon — it depends on
  whether the plaintext F1E1 read succeeds before the shield handshake at boot.

---

### [MEDIUM-2] CARRIED-FORWARD: `gated_unlock` MCU pre-commit bump-failure gate is FAIL-OUT (not sentinel-hardened), unlike its two immediate siblings — a single glitch can grant a PIN attempt without charging page-124

> Re-confirmed; unchanged at the cited lines. The lone FAIL-OUT link in an
> otherwise FAIL-IN gate chain.

- **Location:** `secure/src/nsc/mod.rs:857-861`. `pin_attempts_bump` is
  `secure/src/hw/flash.rs:769-798` and is **not** `#[inline(never)]` (only its
  `scan_forward`/`scan_reverse` helpers are, flash.rs:696/723).
- **Vulnerability class:** missing FI hardening on a security decision (FAIL-OUT:
  the secure action is the explicit `return`; the attacker-bypass-target is the
  fall-through into `se.unlock`).
- **Attacker & required capability:** A-PHYS, single fault (skip the `bl
  pin_attempts_bump`, or skip the `return`), once per attempt.
- **Exploitation path (numbered, concrete):**
  1. `gated_unlock` pre-commits the page-124 bump before the SE verify. The gate:
     ```rust
     if crate::hw::flash::pin_attempts_bump().is_err() {
         return Err(UnlockError::InternalError);   // secure action = explicit branch
     }
     // fall-through: proceed to se.unlock(pin)     // insecure continue = fall-through
     ```
  2. A glitch that skips the `bl pin_attempts_bump` leaving a stale `r0` that
     `.is_err()` reads as `Ok`, OR a glitch that skips the `return` after a
     genuinely-failing bump, reaches `se.unlock` **without charging page-124**.
  3. The proceed-gate above (`pre_count < MAX_ATTEMPTS`, sentinel-hardened
     `:850-855`) reads the *unbumped* count next time, so repeating the glitch
     every attempt means the MCU lockout never trips.
- **Bounding (why MEDIUM, not a brute-force bypass):** the SE silicon counters
  are independent NVM gates and still apply on the real verify — SE050
  `max_attempts=10` (`se050/mod.rs:2723-2728`; `AuthMethodBlocked → remaining=0 →
  PinLocked`), E120 limit 32 (`optiga/mod.rs:2164-2192`). A wrong PIN makes OPTIGA
  return `PinIncorrect` (`optiga/mod.rs:2345-2350` maps `PinIncorrect | Status(_)
  | PinLocked → PinIncorrect`), which makes `DualSecureElement::unlock` call SE050
  (`dual_se.rs:330-335`), so both SE counters advance whenever the verify
  executes — even a perfectly reliable bump-skip yields ≤10 PIN guesses before
  SE050 locks. `pin_attempts_bump` is itself internally hardened (post-write
  readback + sentinel re-check, flash.rs:786-796) so a write-only glitch is
  already caught. This is a regression of the "MCU counter is authoritative"
  claim, not an unbounded brute force.
- **Invariant / security property broken:** the project's own FI doctrine
  (FAIL-IN + Hamming-distant sentinel on every security gate). The sibling gate
  directly above (`allowed != OK_SENTINEL`, `:850-855`) and the PIN-incorrect
  wipe gate (`cmd_request_unlock.rs:113-118`) are both sentinel-hardened FAIL-IN;
  this bump gate is the lone FAIL-OUT.
- **Evidence:** `nsc/mod.rs:857-861` (quoted) vs the sentinel'd `allowed` gate at
  `:850-855` and the FAIL-IN comment block at `cmd_request_unlock.rs:100-118`.
- **Falsification attempt:** I checked whether the downstream verify-result FI
  guard (`is_ok_1 && is_ok_2` → sentinel, `:929-935`) compensates — it does not;
  it guards the success/Err discriminant, not whether the bump was charged. The
  SE-side bump compensates only to the silicon cap (≤10), which is the bound
  above, not a refutation.
- **Suggested fix (describe only):** route the bump result through
  `check_true_into_sentinel(|| bump_ok)` and FAIL-IN (default = refuse); mark
  `pin_attempts_bump` `#[inline(never)]` so a skipped call is observable at the
  caller; optionally re-read page-124 after the SE call and abort if it did not
  advance by exactly one on a non-success.
- **Confidence:** needs-confirmation. The FAIL-OUT shape and missing sentinel are
  confirmed by inspection; single-fault feasibility depends on whether
  `pin_attempts_bump` is emitted as a real `bl` in the release build
  (disassembly required), and the impact is silicon-bounded as noted.

---

## PROVE-OR-BREAK — the three-counter lockstep

The mission asked for either a sequence that desyncs/refunds a counter, or a
proof that the three advance in lockstep and "reconcile to strictest" cannot
fail open. Result: **the per-attempt advance IS lockstep; the boot reconcile
"disagreement = tamper" claim is BROKEN (MEDIUM-1).**

**Proven lockstep on a wrong PIN** (every wrong attempt advances all three):
1. `gated_unlock` (nsc/mod.rs:839-861) reads page-124 (double fwd/rev scan,
   fail-closed), sentinel-gates `pre_count < MAX_ATTEMPTS`, then
   **pre-commits** `pin_attempts_bump()` → page-124 += 1, *before* any SE verify.
2. `DualSecureElement::unlock` (dual_se.rs:314-335) calls `optiga.unlock`; a wrong
   PIN drives `authenticate_and_read`'s `hmac_verify_auto_state`, whose
   trezor-shape `DecryptSym` fires the silicon **LUC on E120** (E120 += 1;
   the failed-verify increment is covered by `optiga-hw-counter-e2e`,
   mod.rs:2183-2185). OPTIGA returns `PinIncorrect`.
3. Because OPTIGA returned `Ok | PinIncorrect`, dual_se calls `se050.unlock` →
   `authenticate_and_read` → `verify_session`, whose VERIFY APDU decrements the
   **SE050 silicon UserID `auth_attempts`** (and the software `self.remaining`
   mirror, se050/mod.rs:2718-2722).

So one wrong PIN = page-124 +1, E120 +1, SE050 UserID -1. The MCU counter is
pre-commit (charged even if the verify never runs), the two SE counters are
charged by the silicon when the verify runs. **No path verifies the PIN before
charging page-124** (no compare-before-bump). The cap binds at the strictest of
{MCU 10, SE050 10, E120 32} = **10**.

**Broken: "reconcile to strictest; disagreement = tamper."** See MEDIUM-1 — in
production the reconcile's only live value is a frozen constant, so the boot
cross-check cannot fire. The lockstep above is what actually holds the line; the
reconcile does not contribute.

**Single-fault notes:** the only single-glitch desync is MEDIUM-2 (skip the
page-124 bump), bounded to ≤10 by the SE silicon. Forcing OPTIGA to return a
non-`PinIncorrect` error (the `_ => InternalError` arm at optiga/mod.rs:2895)
makes dual_se *skip* SE050 (dual_se.rs:334) — but that attempt advances neither
E120 (verify didn't complete) nor SE050, while page-124 is already pre-committed,
so it grants no free attempts and leaks no PIN information.

## Known-open ship-blockers — verification & precise scope

Acknowledged in CLAUDE.md / `project_se_removal_invariant`; this pass confirms
each against the current code.

- **S-1 (F1D0 `Change=ALW`) — REAL, partially fenced.** Without
  `optiga-lock-operational`, `build_metadata_auth_ref_luc_oid` writes F1D0
  `Change=ALW` (`apdu.rs:1080,1089,1104-1107`; the non-LUC `build_metadata_auth_
  ref` is also `Change=ALW` at `:945,949`). A desoldered/bus attacker rewrites the
  PIN-HMAC key, self-auths, resets E120, brute-forces the PIN unbounded. The
  firmware's own `reset_e120_via_transient_auth` (`optiga/mod.rs:1368-1450`)
  documents and *relies on* this exact `Change=ALW` capability — confirming it is
  live. A `compile_error!` fence exists (`nsc/mod.rs:337-351`) but fires only
  under `mode-production` — see **HIGH-1** for the coverage gap. The actual fix
  (irreversible LcsO=Operational ratchet via `lock_oid`/`verify_and_lock` +
  sacrificial-part validation) is bench/factory work and is **not** done. The
  *code-doable* residual flagged in CLAUDE.md (a `build_metadata_counter`
  production gate) was not located in this pass.
- **S-2 (Trust Anchor at 0xE0E3 = Infineon PUBLIC sample cert) — REAL.** The cert
  + EC P-256 signing key are Infineon's public sample set (`reset.rs:16,26,33-38`),
  so anyone can sign a `SetObjectProtected` manifest bypassing every OID's
  `Change` AC. Sharpening: (1) the sample cert is only *provisioned* by the
  `optiga-reset-oids` recovery path, which the S-2 fence forbids in production
  (`nsc/mod.rs:298-312`) — a clean production chip does not carry it; (2) but at
  LcsO=Creation the attacker installs their *own* Trust Anchor regardless, so S-2
  is only truly closed by the same LcsO=Operational metadata freeze that closes
  S-1. **S-1 and S-2 are closed by the SAME feature** (`optiga-lock-operational`)
  — the one HIGH-1 shows the canonical release path fails to force.
- **S-3 (`optiga-hw-counter` mandatory) — REAL, fence is SOUND.** The S-3 fence
  (`nsc/mod.rs:274-291`) fires on `any(mode-production, all(stm32u585,
  not(debug_assertions)))` — any release-hardware OPTIGA build — and forces
  `optiga-hw-counter`. Under it the lockout is the silicon E120 LUC, gated at
  `authenticate_and_read` `:2164-2192` and reset only on success `:2389`. No
  `mode-production`-only gap. The firmware-side `curr >= limit` compare
  (`:2188`) is a bare conditional but is belt-and-braces — the silicon LUC
  (`COUNTER_EXCEEDED`) is the real enforcement, so a glitch on that `if` does not
  bypass the silicon lock.
- **S-5 (SE050 SCP03 R-ENC fix) — landed in code, needs silicon confirmation.**
  The `se050-derived-scp03` require-fence (`nsc/mod.rs:439-460`) forces per-device
  derived SCP03 keys in production, and `se050-scp03-allow-factory-fallback` is on
  the prod-check denylist (`Makefile:1989`). What remains is a logic-analyzer
  capture on a real B-U585I confirming the unlock *response* phase is ciphertext +
  8-byte R-MAC with no `half_E` plaintext on I²C (invariant #3). A plaintext
  `half_E` on the bus would collapse the SE050 leg of invariant #1 independently
  of the PIN path. Not re-scored.

## Enumeration ledger — the full set this surface owns

### The three attempt counters
| Counter | Read | Bump | Reset | In-prod state | Verdict |
|---|---|---|---|---|---|
| MCU page-124 | `flash::pin_attempts_read` (dual fwd/rev scan, fail-closed→32) | `pin_attempts_bump` (pre-commit, readback+sentinel) | `pin_attempts_reset` (success / wipe only) | live, authoritative MCU gate | bump-gate FAIL-OUT → **MEDIUM-2** |
| OPTIGA E120 (silicon LUC) | `read_hw_pin_counter` | atomic in `hmac_verify_auto_state` (silicon) | `reset_hw_pin_counter` on success | live lockout (limit 32) | sound; resettable only by S-1 desolder → **HIGH-1** |
| OPTIGA F1E1 (soft) | `read_counter_raw` | only under `not(hw-counter)` | only under `not(hw-counter)` | **frozen at 0** in prod | feeds dead reconcile → **MEDIUM-1** |
| SE050 USERID `auth_attempts` | `pin_attempt_count_raw` (returns `None` in prod, SW=0x6986) | silicon on VERIFY | silicon on success | live lockout (max 10) — strictest cap | sound for lockout; reconcile leg dead → **MEDIUM-1** |

### NS-reachable gateway handlers vs the PIN gate
| CMD | Handler | PIN-gated? | Verdict |
|---|---|---|---|
| 1 GET_REMAINING | `cmd_get_remaining` | no (status only; returns `min` of SE caches) | discharged — no secret, no state change |
| 2 REQUEST_UNLOCK | `cmd_request_unlock` | drives trusted-UI PIN entry; PIN never crosses NS | discharged — see clean #1 |
| 7 SIGN_USEROP | `cmd_sign_userop` | `pin_verified.check_sentinel()` | discharged |
| 11 IS_UNLOCKED | `cmd_is_unlocked` | `is_true_fi()` readback | discharged — status only |
| 12 LOCK | `cmd_lock` | zeroizes | discharged |
| 14 GET_WALLET_ADDRESS | `cmd_get_wallet_address` | `check_sentinel` | discharged |
| 15 GET_INIT_CODE | `cmd_get_init_code` | `check_sentinel` | discharged |
| 16 SIGN_OFFCHAIN | `cmd_sign_offchain` | `check_sentinel` | discharged |
| 17 OFFCHAIN_STATUS | `cmd_offchain_status` | `check_sentinel` | discharged |
| — OFFCHAIN_SYNC | `cmd_offchain_sync` | `check_sentinel` | discharged |
| 30 SIGN_USEROP_BATCH | `cmd_sign_userop_batch` | `check_sentinel` | discharged |
| 20-24 FW_* | `cmd_fw_{begin,chunk,commit,status,abort}` | `check_sentinel` | discharged |
| 200 TEST_PIN_LOCKOUT | `cmd_test_pin_lockout` | `#[cfg(e2e-test)]` only | discharged — fenced out of prod |
| 100-109 PRODTEST_* | `prodtest::*` | `#[cfg(prodtest)]` only | discharged — fenced out of prod |

No NS-reachable path calls `mark_unlocked` / `unlock_with_master` /
`set_e2e_unlocked` (only `cmd_request_unlock`, the S-world wizard, and `e2e-test`
helpers), and no NS command writes page-124/125 directly.

### `pin_attempts_reset` (page-124 refund) call sites
| Site | Trigger | Verdict |
|---|---|---|
| `nsc/mod.rs:940` | `gated_unlock` success (correct PIN) | legit |
| `cmd_request_unlock.rs:169` | `trigger_lockout_wipe` (wipe) | legit |
| `nsc/mod.rs:1029` | `reconcile_pin_attempts` tamper (wipe) | legit |
| `main.rs:1418` | boot wipe-resume (wipe) | legit |
| `dual_se.rs:965`, `main.rs:24xx`, `cmd_test_pin_lockout.rs` | `#[cfg]` e2e/test only | fenced out of prod |

No NS-reachable or spurious reset.

### SE050 unlock error → counter/lockout mapping (`classify_se050_unlock_error`, se050/mod.rs:2547)
| `Se050Error` | `self.remaining` side-effect | `UnlockError` | Verdict |
|---|---|---|---|
| `PinIncorrect` | `-=1` | `PinIncorrect` | correct |
| `AuthMethodBlocked` | `=0` | `PinLocked` → wipe | correct (silicon already locked) |
| other | none | `InternalError` | discharged — no SE attempt consumed |

### OPTIGA unlock error mapping (`optiga/mod.rs:2886`)
| `OptigaError` | `UnlockError` | dual_se calls SE050? |
|---|---|---|
| `Ok` | (master) | yes |
| `PinIncorrect` | `PinIncorrect` | yes |
| `PinLocked` | `PinLocked` | no (dual_se `Err(_)` arm) — but page-124 pre-committed, no free attempt |
| other (`Transport`/`NotProvisioned`/…) | `InternalError` | no — verify didn't run, E120 not advanced, no leak |

### Software PIN-compare sites (invariant #2)
| Site | Backend | In dual-se prod? |
|---|---|---|
| `secure_element.rs:363` (`crate::pin::verify_pin`) | `MockSecureElement` | no (`mock-se` fenced out) |
| `secure_element.rs:581` | host test | no |
| `tropic01_se.rs:437,615` (`batch_verify_pin`) | Tropic01 | no (not in `dual-se`) |
| OPTIGA `hmac_verify_auto_state` | chip compares | yes — silicon |
| SE050 `verify_session` (UserID) | chip compares | yes — silicon |

No software PIN comparison is reachable in a `dual-se` shipping build. Invariant
#2 upheld.

## Surfaces examined and judged clean (with the reason each is safe)

1. **NS/companion PIN brute-force via the gateway (A-NS).** `CMD_REQUEST_UNLOCK`
   drives the trusted-UI `enter_pin` in S-world (`cmd_request_unlock.rs:25-37`);
   the PIN never crosses from NS. NS can only *trigger* a prompt needing physical
   buttons and burning an MCU attempt. **Safe.**
2. **`gated_unlock` success-path fail-open (Err→Ok under one glitch).** The
   returned `master` is AES-GCM-MAC-bound: `DualSecureElement::unlock`
   cross-checks `kdf(entropy)==master_o` with double `ct_eq` + sentinel
   (`dual_se.rs:406-417`) and the downstream entropy-blob decrypt MACs again. The
   reset+`Ok` arm is sentinel-gated (`nsc/mod.rs:937-948`). A glitched
   discriminant yields a garbage master that fails decrypt. **Safe vs single
   fault.**
3. **Compare-before-bump / TOCTOU.** Page-124 bump is strictly pre-commit, with
   verified readback + sentinel re-check (`flash.rs:769-798`); E120 bump is atomic
   with the silicon verify; SE050 bumps in silicon on VERIFY. No path verifies the
   PIN before charging a counter. **Safe** (except the FAIL-OUT *shape* in
   MEDIUM-2, which is the bump-failure branch, not ordering).
4. **10-wrong-PIN → wipe completeness, and the page-124 refund hazard.**
   `verify_pin_with_chip` uses FAIL-IN sentinel + double-read of the post-bump
   count (`cmd_request_unlock.rs:80-124`). `trigger_lockout_wipe`
   (`:155-176`) calls `factory_reset_admin()` (result ignored), then
   `pin_attempts_reset()`, then zeroizes. I chased the worst case: a wipe that
   *fails* but still refunds page-124. The crash-safety holds — SE050
   `factory_reset_admin` **arms the page-125 wipe flag before destructive work**
   (`se050/mod.rs:2873`) and **erases page 125 only when `!admin_exists()`**
   confirms the wipe completed (`:2886-2887`); boot resumes on the armed flag
   (`main.rs:1401-1420`) *before* accepting any PIN. So a failed admin-pin-present
   wipe leaves the flag armed → boot re-wipes. The one path that does NOT arm the
   flag — `se050_admin_pin()` derivation failure (`:2856-2869`, unauth sweep then
   `Ok(())`) — still has OPTIGA's `factory_reset` destroy `half_O`, so the old
   wallet is unreconstructable (`half_E` alone is useless) and the device drops to
   the wizard. **Crucially, a failed wipe never resets the SE050 silicon UserID
   counter**, so even a refunded page-124 hits SE050's `AuthMethodBlocked` at 10
   on the next attempt → wipe. The refund is SE-silicon-bounded, not a brute force.
   **Safe** (documented in self-review).
5. **SE050 admin-substitution (S-6).** User `USERID_OBJ` is written with
   `admin_ref=None`; the admin credential (max_attempts=0, unlimited) can only
   DELETE user objects, never read them. A cracked admin PIN yields DoS, not
   `half_E`. **Closed** — keeps the SE050 leg of the shared-PIN cascade gated
   behind the *user* PIN.
6. **`pin_verified` storage + bypass of `mark_unlocked`.** `pin_verified` is a
   `FihBool` complement-pair (`state.rs:44`), read via `check_sentinel`;
   `mark_unlocked` uses the FihBool API and wipes the prior master first
   (`state.rs:286-303`). No NS-reachable writer. **Safe.**
7. **State zeroize on lock/idle/panic + ISR race.** `zeroize_sensitive` wipes
   `master_secret` + slot entropy with barriers and drops `pin_verified`
   (`state.rs:153-199`); `HandlerGuard` (AtomicU32 depth) blocks SysTick idle-wipe
   from racing an in-flight unlock (`nsc/mod.rs:717-754`). **Safe.**
8. **`duress-pin` path (NOT shipped by default — `Cargo.toml:334`, absent from
   `RELEASE_FEATURES`).** When enabled, `gated_unlock` tries `unlock_duress` first
   (`nsc/mod.rs:882-911`); a wrong PIN returns `PinIncorrect` and the real
   `se.unlock(pin)` still runs (`dual_se.rs:251-298,286-297`). The duress verify
   hits only E121 + the duress UserID, granting no free *real* attempts; a
   duress-correct unlock resets page-124 by design (deniability) but requires
   knowing the duress PIN. The decoy master is MAC-bound (`dual_se.rs:265-276`).
   **Safe** for its purpose; see Open Questions for the reconcile interaction.
9. **`reset_e120_via_transient_auth` as an attacker oracle.** It is `unsafe fn`
   private to the optiga module, reachable only from `factory_reset`, and requires
   the active Shielded Connection (PBS). An on-bus attacker without PBS can't drive
   it; an attacker with PBS already owns the chip. **No new capability**
   (`optiga/mod.rs:1384-1388`).

## Self-review — counterexamples I went hunting for, and why they failed

- **"A failed admin-wipe + the unconditional `pin_attempts_reset` in
  `trigger_lockout_wipe` refunds attempts and the old wallet survives → unbounded
  brute force."** This is the sharpest new angle I built. It fails for two
  independent reasons: (1) the page-125 wipe flag is armed before destructive
  work and only erased on confirmed completion, so a failed wipe re-fires at boot
  *before* any PIN is accepted (`se050/mod.rs:2873,2886-2887`, `main.rs:1401`);
  (2) even if both the wipe AND the flag-arm are glitched (flag arm's Err is
  ignored, `:2873`), the SE050 silicon UserID counter is NOT reset by a failed
  wipe — it sits at 10 → the next attempt returns `AuthMethodBlocked → PinLocked
  → wipe`. The refund is bounded by the SE silicon lock, not unbounded. To make
  it unbounded the attacker must ALSO reset the SE silicon counters, which is the
  S-1 desolder path (HIGH-1), not a new bug.
- **"The SE050 reconcile leg is live on the current tree (the `nsc/mod.rs`
  docstring says so) → MEDIUM-1 is wrong."** It is not: `pin_attempt_count_raw`
  returns `None` on the production policy (SW=0x6986, se050/mod.rs:539-563,
  silicon-confirmed). The docstring is stale. MEDIUM-1 stands.
- **"Forcing OPTIGA to a non-`PinIncorrect` error skips SE050 (dual_se.rs:334) →
  free attempts on one chip."** The skipped-SE050 attempt advances neither E120
  (verify never completed) nor SE050, while page-124 is already pre-committed; it
  grants no free attempts and leaks no PIN info. The strictest cap (page-124 = 10,
  pre-commit) still binds.
- **"Some required feature transitively pulls `optiga-lock-operational`."**
  `Cargo.toml:553` defines it `[]`; `optiga-hw-counter` (the feature S-3 forces) is
  `["optiga-trust-m"]` — it does not pull lock-operational. Nothing required forces
  it; HIGH-1 stands.
- **"`prod-check` catches the missing `mode-production`/`optiga-lock-operational`
  build."** It only scans `PROD_FORBIDDEN`; it has no required-present clause. A
  clean build missing only `optiga-lock-operational` slips through. HIGH-1 stands.
- **"The LcsO ratchet needs `factory-production-irreversible-im-sure` too, so even
  enabling `optiga-lock-operational` gives false closure."** I read the ratchet
  (`optiga/mod.rs:622-647,754-838`) — it is gated *solely* on
  `optiga-lock-operational` (plus an `is_device_master_burned()` runtime guard).
  The second flag is unused there. So satisfying the S-1 fence *would* run the
  ratchet; the gap is purely the fence not firing. (Corrects the 2026-06-11 audit.)
- **"A single glitch flips Err→Ok in `gated_unlock` for a free unlock."** The
  master is MAC-bound and the verdict is sentinel-gated; a forced Ok yields garbage
  that fails the entropy-blob MAC. Failed to materialise.

## Open questions / items needing on-hardware confirmation

1. **MEDIUM-1 regime.** On a real `dual-se + optiga-hw-counter` board: provision,
   enter **one** wrong PIN, power-cycle, observe whether the device wipes (regime
   a, false-positive availability bug) or boots normally (regime b, dead detector).
   Determines immediate priority. Either outcome confirms the defect. The trigger
   is whether the plaintext F1E1 read succeeds before the shield handshake at
   `main.rs:1268`.
2. **MEDIUM-2 feasibility.** Disassemble the release `gated_unlock` to confirm
   `pin_attempts_bump` is emitted as a real `bl` (skippable) vs inlined, and bench
   whether a single glitch at `nsc/mod.rs:857` reaches `se.unlock` without
   advancing page-124.
3. **HIGH-1 build provenance.** Capture the exact feature string CI/`make release`
   uses for a shipping image and confirm `mode-production` (hence
   `optiga-lock-operational`) is present. Until prod-check gains a required-feature
   assertion, this is operator discipline, not enforcement.
4. **S-1 silicon ceremony.** Irreversible LcsO=Operational ratchet +
   sacrificial-part validation + replacing the Infineon public sample Trust Anchor
   with the PQ1-factory-HSM cert remain bench/factory work even after HIGH-1's
   enforcement fix. Confirm whether the claimed `build_metadata_counter`
   production gate exists (not found this pass).
5. **S-1 × multi-wipe interaction (post-fix regression risk).** Once F1D0 becomes
   `Change=Auto(F1D0)` (S-1 closed), `reset_e120_via_transient_auth`
   (`optiga/mod.rs:1389`) can no longer rewrite F1D0 — the wipe-path E120 reset it
   depends on (`:1361-1366`) breaks, risking E120 saturation / soft-brick after
   repeated wipes. Verify the post-S-1 wipe path resets E120 by another route
   (availability, not theft).
6. **S-5 (invariant #3).** Logic-analyzer capture on a real B-U585I that the unlock
   response phase is ciphertext + 8-byte R-MAC with no `half_E` plaintext on I²C.
7. **Duress × reconcile interaction (if `duress-pin` ever ships).** A
   duress-correct unlock resets page-124 while leaving E120/SE050-main untouched;
   benign today (reconcile dead), but a *fixed* reconcile must not read a
   post-duress page-124=0 against a non-zero E120 as tamper.
