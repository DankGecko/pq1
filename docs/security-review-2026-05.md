# Security Review — 2026-05-12

Audit scope: firmware (`secure/`, `nonsecure/`, `proto/`, `domain/`, `aa/`,
`tx-core/`, `tx/`, `hal/`, `shared/`, `fw-manifest/`, `fsbl/`, `bip39/`,
`sphincs-c10/` API surface only). The on-chain Solidity verifier, the
ZK Groth16 verifier internals, the SE050/OPTIGA driver internals, and
the trusted-UI rendering pipeline are out of scope and warrant their
own passes.

## Fixed in this change

| ID  | Sev  | Files touched | Summary |
|-----|------|---------------|---------|
| C-1 | Crit | `secure/build.rs`, `secure/Cargo.toml`, `secure/src/fw_update/{mod,vendor_pubkey}.rs` | Embed vendor SPHINCS+C10 pubkey via `FSBL_VENDOR_PUBKEY` env var (same path FSBL uses), verify manifest signature at `verify_manifest` BEFORE the destructive ops in `cmd_fw_commit` (slot erase, OTP rollback-floor bump, boot-state write). The "fingerprint-must-match-active-slot" gate that protected nothing — attacker can replicate it trivially — is gone. |
| C-2 | Crit | `secure/src/nsc/cmd_fw_chunk.rs` | Added `HandlerGuard::enter()` at handler entry. Prevents the use-after-drop on `FwUpdateCtx` when SysTick's idle-wipe races with a chunk write. |
| H-2 | High | `cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs`, `cmd_sign_offchain.rs` | Open-coded inline `if ok_sentinel != OK_SENTINEL` blocks replaced with `fi::check_true(\|\| v1 && v2)`. The sentinel now lives in a `*mut u32` (Trezor pattern) so LLVM can't fold the third check into a register-only compare. |
| H-3 | High | `cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs` | Added a symmetric `fi::check_true` outer verify-before-release for the Type 1 (bootstrap) `factorySig` and `addOwnerBytes` signatures. Previously only the Type 2 sig had the outer FI guard. |
| H-4 | High | `secure/src/nsc/mod.rs` | `gated_unlock` now reads `result.is_ok()` twice, separated by `wait_random()`, and routes the verdict through `fi::check_true`. A glitch that turns `Err` into the `Ok` arm (and resets the MCU page-124 attempt counter) must now defeat the sentinel-gated check too. The SE silicon counter is still the primary rate-limit. |
| L-2 | Low  | `cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs`, `cmd_sign_offchain.rs` | `SNAP_BUF` now wiped on the **happy path** exit as well as entry. Error paths still leave data resident until the next sign — see "Not fixed" below. |
| L-6 | Low  | `secure/src/hw/otp.rs` | OTP rollback-floor post-bump readback now double-evaluated through `fi::check_true`. |
| M-1 | Med  | `secure/src/nsc/mod.rs` | `HANDLER_DEPTH` migrated from `static mut u32` (read-modify-write race) to `AtomicU32` (`fetch_add(1, SeqCst)` / `compare_exchange_weak` saturating decrement). Closes the tiny window where SysTick could observe `depth == 0` between a handler's read and write of the increment. |

### Build verification

- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "stm32u585 ui-noop dual-se"` → clean
- `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se"` → clean
- `cargo test -p sphincs-tz-secure --tests` → 105/105 passing
- `cargo build -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se" --release` → clean

### One-line behavior changes

1. **All builds for `--features stm32u585` without `FSBL_VENDOR_PUBKEY` set emit a cargo:warning** and produce a binary that REJECTS every manifest (the embedded pubkey is all-zero). Production CI must set the env var; dev recipes should run `make dev-pubkey-fixture` (a recipe that needs to be added; see "Production checklist" §F-1).
2. **`cmd_fw_chunk` now blocks SysTick idle-wipe** for the (short) duration of one chunk write. Stalls in flash-page-erase still leave the inactive slot in a half-written state, but the SRAM `FwUpdateCtx` is safe.

## Not fixed (cannot be done from firmware alone)

### C-4. OPTIGA F1D0 `Change = ALW` — desoldered-chip PIN brute-force (SHIP BLOCKER S-1)

`secure/src/optiga/apdu.rs:930` (`build_metadata_auth_ref`) and `:1059`
(`build_metadata_auth_ref_luc`) emit `Change = AC_ALW` on F1D0. An
attacker who desolders the OPTIGA and attaches it to a bench rig can
overwrite F1D0's HMAC secret with a chosen key (no credential
required), self-auth, then reset E120 to drain the LUC lockout —
unbounded PIN brute-force per chip. The legitimate
`reset_e120_via_transient_auth` admin-wipe path
(`secure/src/optiga/mod.rs:1238`) documents the exact attack and
admits it depends on `Change=ALW`.

Direct seed leakage from F1D1 still requires `Conf(E140)` (the
Shielded Connection PBS), which lives only on the paired MCU and is
re-derived from DHUK each boot — so this regression does not
*directly* expose `half_O`. But it eliminates the LUC layer the threat
model bills as the primary online brute-force bound on the OPTIGA
half, and the dual-SE XOR split becomes the only remaining gate.

Fix is metadata + LcsO ratchet, not a firmware patch in isolation —
documented fully in `docs/production-todo.md` "OPTIGA Trust M V3 —
LcsO transitions" (F1D0 item, expanded 2026-05-28) and tracked as
ship blocker `S-1` at the top of `docs/work-todo.md`.

**Primary fix:** `Change = Auto(F1D0)` (PIN change requires current
PIN) + ratchet to LcsO=Op. **Fallbacks** (if `Auto(F1D0)` doesn't
work on our firmware revision): `NEV` or `LcsO<Op`. **NOT acceptable:**
`Conf(E140)` — bypassable by a PBS-extraction attacker.

**Closure is necessary but not sufficient** — see C-5 (Trust Anchor)
which can bypass any F1D0 hardening. Both must close together.

CI / `make ship-checklist` MUST hard-fail until: (a) a
`build_metadata_auth_ref_ship()` exists with `Change=Auto(F1D0)` (or
`NEV`/`LcsO<Op` fallback), (b) the bring-up `_alw` variants are in the
`mode-production` `compile_error!` fence, (c) sacrificial-part
verification of post-ratchet F1D0 immutability passes, (d) the
tearing/glitch test on the LUC failed-auth increment passes.

### C-5. OPTIGA trust-anchor at `0xE0E3` is the Infineon public sample cert (SHIP BLOCKER S-2)

`secure/src/optiga/reset.rs:26-49` provisions `TRUST_ANCHOR_OID =
0xE0E3` with the DER X.509 cert from Infineon's
`samples/integrity/sample_ec_256_priv.pem`. **The matching EC P-256
private key is in Infineon's public example bundle.** Anyone with the
sample key can sign a `SetObjectProtected` manifest the chip will
accept, and a valid manifest **bypasses the target OID's Change AC
entirely** — including any of S-1's proposed F1D0 fixes
(`Auto(F1D0)`, `NEV`, `LcsO<Op`).

This makes S-1 alone insufficient: an attacker on the bus rewrites
F1D0 via Protected Update, then proceeds with the brute-force attack
unimpeded. Every other OPTIGA Change-AC hardening on the chip is
subordinate to the trust-anchor surface.

Affects: every locked OID, every F1Dx secret, the LUC counter E120,
F1E1, every spare OID (F1D7 is explicitly "left spare" per
`apdu.rs:159` and can be promoted to `DataType=0x11` via Protected
Update with the sample key).

**Required fix (see production-todo.md "SHIP BLOCKER S-2"):**
1. Replace `0xE0E3` cert with a PQ1-factory-HSM-controlled cert
   whose private key never leaves the HSM (or remove the trust
   anchor entirely + lose field-recoverable OID reset).
2. Enumerate and lock `0xE0E4..0xE0E8` (the rest of the trust-anchor
   pool).
3. Fill/lock `0xF1D7` and any other spare OIDs.
4. `compile_error!` gate `optiga-reset-oids` and
   `reset::provision_trust_anchor` in the production-build fence.
5. Sacrificial-part verification that manifests signed by the public
   Infineon sample key are rejected for every plausible `kid`.

### C-6. OPTIGA soft-counter path defeats desoldered-chip lockout (SHIP BLOCKER S-3)

The default build (without `optiga-hw-counter`) emits
`build_metadata_auth_ref` (`Execute = ALW`, no LUC) +
`build_metadata_counter` (soft counter at F1E1, `Change = Conf(E140)`).
The "10-attempt cap" is enforced **entirely in MCU firmware** by
`gated_unlock` and the F1E1 soft counter. On a desoldered chip this
collapses: F1D0.Execute=ALW allows unbounded HMAC verifies against the
chip, and a PBS-extraction attacker rewrites the F1E1 soft counter
through `Conf(E140)`.

**Required fix:**
1. `optiga-hw-counter` becomes mandatory for production
   (`compile_error!` in the `mode-production` fence when off).
2. `build_metadata_counter` becomes a `compile_error!` in production
   builds (`#[cfg(not(any(feature="optiga-hw-counter", test)))]
   compile_error!`).
3. Remove `OID_COUNTER = 0xF1E1` from production provisioning, OR
   ratchet F1E1 to LcsO=Op with junk content.
4. Reconcile F1D5 / F1E1 / "soft-counter" naming drift across
   `apdu.rs:151`, `apdu.rs:956 build_metadata_counter` docstring, and
   the duress-comment.

### C-7. SE050 SCP03 at P1=0x03 — response unprotected; `half_E` leaks on I²C bus (SHIP BLOCKER S-5)

`secure/src/se050/scp03.rs:213` sends `P1=0x03` in EXTERNAL_AUTHENTICATE
(C-MAC + C-DEC only, no R-MAC/R-ENC). `s_rmac` is derived at `:194` and
never read anywhere in the codebase. `secure/src/se050/apdu.rs:262-282
send_apdu` reads `sw` off `raw_resp[n-2..]` and `tlv_parse`s the rest
directly — no `unwrap_response` call (compare OPTIGA's
`shield.unwrap_response` for the correct shape).

The fact that `read_authed` works in production confirms the SE050 is
emitting responses cleartext-on-the-wire at the negotiated security
level. **Every successful `read_authed` puts the secret on the bus in
plaintext.** A passive probe on the SE050 I²C lines (no SCP03 key
knowledge required) captures `half_E` during every legitimate unlock.

Worse than C-4/C-5 in attacker-cost terms: no desoldering, no PBS
extraction — a malicious in-case implant or a supply-chain PCBA swap
captures the seed half from any user who unlocks the device.

**Required fix:** Switch to `P1=0x33`, implement
`scp03::unwrap_response`, wire it into `send_apdu`. Sacrificial-part
verification via logic-analyzer capture of a read_authed cycle — bytes
during the response phase MUST be ciphertext + R-MAC.

Full spec: `docs/work-todo.md` S-5 + `docs/production-todo.md` §"SE050
SCP03 response protection" (to be added in the SE050 hardening pass).

### C-8. SE050 admin-delete on USERID_OBJ enables seed theft from admin compromise (SHIP BLOCKER S-6)

`secure/src/se050/mod.rs:1598-1604` (production `store_objects`) passes
`admin_ref = Some(ADMIN_WIPE_OBJ)` for the UserID's `admin_auth_obj_id`,
producing policy `[USERID_OBJ → WRITE|DELETE|SM, ADMIN_WIPE_OBJ →
DELETE|SM]` on the UserID auth object itself. SE050 policies are
immutable post-`WriteUserID`, so this is locked in for every
already-provisioned chip until reset.

An attacker with admin auth (e.g. via flaws in the BHK-derived admin
PIN, or pre-RDP2 device theft):
1. `delete_object_authed(USERID_OBJ)` → succeeds via admin entry.
2. `write_userid(USERID_OBJ, attacker_pin, 5, None)` → succeeds, slot
   was just emptied.
3. Auth against USERID_OBJ with attacker_pin → succeeds.
4. `read_authed(ENTROPY_OBJ)` → returns `half_E`. ENTROPY_OBJ's policy
   gates on "session against ID USERID_OBJ"; the attacker's new
   UserID at the same ID satisfies that.

Admin path was supposed to be DoS-only ("admin can wipe but not
steal"); this policy shape breaks that promise.

**Required fix:** `mod.rs:1600` passes `None` for the UserID's
`admin_auth_obj_id`. Keep `admin_ref` on the data objects (ENTROPY_OBJ
et al) so admin can still DoS-wipe the secret. Replace the
10-wrong-PIN-lockout cleanup path (which previously relied on the
admin-delete-of-UserID entry) with SE050 full-chip `factory_reset`.

Sacrificial-part verification: after the fix,
`delete_object_authed(USERID_OBJ)` from an admin session MUST fail
with `0x6986`; `delete_object_authed(ENTROPY_OBJ)` MUST still succeed.

Full spec: `docs/work-todo.md` S-6.

### C-9. SE050 lower-severity follow-ups (tracked under S-7)

Not ship blockers individually but should land in the same hardening
pass as C-7/C-8:
- `write_userid(.., max_attempts=0, ..)` silently provisions
  unlimited-attempts UserID (`apdu.rs:421-423`); reject with
  `InvalidParam`.
- `delete_object` maps `SW=0x6986 → Ok(())` (`apdu.rs:620`); return
  distinct error.
- Status-code mappings unverified on silicon (already
  self-documented in `apdu.rs:30-48`); capture actual SW for
  lockout via the planned iterative_wipe probe.
- Extended-Lc + Le emits 1 Le byte instead of 2 (`apdu.rs:200-203`);
  latent, doesn't fire on ≤256B reads.
- `iterative_delete_all` requires the PIN to fire pass 2
  (`apdu.rs:739`) — so on 10-wrong-PIN the secret is *orphaned*,
  not erased; document explicitly in threat-model Claim 5.

### C-3. Pre-production TZSC/SAU regression
`secure/src/sau.rs:173-181, 232`. `TZSC_SECCFGR{1,2,3} = 0` (everything NS) and SAU region 3 maps the entire peripheral window NS. Cannot be tightened until the GTZC2_TZSC base address is confirmed against RM0456 — the first guess (`0x5203_4400`) bus-faults on touch. This is a hardware/bring-up problem, not a software fix. CI must hard-fail any release build whose `sau::init()` leaves the SECCFGRx registers cleared.

### H-1. AES-GCM nonce derived from master_secret
`domain/src/lib.rs:121-126`. Today's construction is safe because distinct entropy → distinct master → distinct nonce. The fix (random 96-bit nonce stored in the blob) requires touching the entropy-blob wire format on both SEs, which would be a flag-day data migration for every provisioned device. Defer until the next planned format-bump. The brittleness is documented in the function docstring as a regression test target.

### H-5. `CMD_GET_INIT_CODE` produces deploy signatures without user confirm
`secure/src/nsc/cmd_get_init_code.rs`. Adding a confirm is straightforward but changes companion-app flows (every cold "what's my address on chain X" lookup would prompt). Needs a product decision on UX trade-off vs. the harvesting risk (a hostile companion enumerating slot-0 deploy signatures for every chain).

### H-6. `paymaster_and_data` is signed but never displayed
The user has no way to see what paymaster the UserOp is authorizing. Fixing this requires a new optional trailer carrying the decoded paymaster address + fee fields, a new trusted-UI page, and a companion-app schema bump. Tracked separately as a UX-and-protocol change.

### M-2. 64-bit `slot_key` truncation
`offchain_state.rs:23`, `hw/flash.rs:943`. Wide enough for documented usage (≤ 256 active slots/device); tightening to 128 bits is a format change to the per-slot flash journal. Defer until the next compaction cycle of page 123 lands a wire-format bump anyway.

### M-3. `last_userop_count_set` silently tolerates regressions
`hw/flash.rs:1377-1392`. The trade-off is documented (avoid bricking the slot vs. detect bugs). I added a `secure_log!` recommendation to the review but did not change the runtime semantics — it's a deliberate product choice.

### M-4. `cmd_get_wallet_address` keygen without `HandlerGuard`
Low risk (entropy lives on stack as `Zeroizing`, BSS master_secret is only re-read at the start). Added to the production checklist below for symmetry.

### M-5. Slot-rotation confirm needs more context
Pure UI improvement; needs a product decision on what to show.

### L-2 (partial). `SNAP_BUF` not wiped on error paths
Fixed on happy path only. A scope-guard pattern that fires on every `return` would close this completely; current code has too many early `return NscStatus::*` to refactor blindly. Tracked.

### L-3. `verify_pin_with_chip` is not double-checked
The SE driver's authenticated-channel response is itself the gate; the MCU-side Rust match is the only post-SE conditional. Hardening it further requires either calling `se.unlock(pin)` twice (burns 2× SE counter) or surfacing a glitch-tolerant discriminant from the SE driver. Out of scope for this pass.

### L-7. QEMU mailbox dispatcher has no length validation on `CMD`
Match is exhaustive on `u32`; safe by construction. No change.

## Production checklist

These items MUST be resolved before any device leaves the bench.

### A. Mandatory build-time gates
- [ ] **CI hard-fails** on `stm32u585` builds where `FSBL_VENDOR_PUBKEY` is unset. The cargo:warning is not enough — turn it into a hard error in the production Makefile recipe (mirror `make fsbl-release`).
- [ ] **CI runs `make verify-pins`** (already exists) and verifies the `compile_error!` fences in `secure/src/nsc/mod.rs:98-116` still gate the dev features.
- [ ] **Add a test** that a release build's `verify_manifest` rejects a manifest signed by a different key. Easy way: re-sign the dev fixture with a different seed, point `FSBL_VENDOR_PUBKEY` at the prod fixture, exercise BEGIN, assert `WrongVendor`.

### B. TZSC/SAU lockdown (C-3)
- [ ] Confirm GTZC2_TZSC base address against RM0456 §§54 and on real silicon (bus-fault canary).
- [ ] In `sau::stm32::configure_gtzc()`: set every SECCFGRx to a default-secure baseline, allowlist only the peripherals NS actually needs (USB OTG FS, GPIO subset, the UCPD1 register reserved for boot-time only).
- [ ] Tighten SAU region 3 to cover only the NS-allowed peripheral window, not all 256 MB.
- [ ] Add a post-init self-check that reads back every SECCFGRx and halts on mismatch.

### C. FI hardening rollout
- [ ] Audit every other gateway handler for symmetry with the H-3 fix (single-tx, batch, offchain sign all now have outer FI guards on every sig release; verify no path was missed).
- [ ] Replace remaining open-coded sentinel patterns in the codebase with `fi::check_true` (grep `OK_SENTINEL`/`FAIL_SENTINEL` for unattended sites).
- [ ] Move `tamp::on_tamp_irq` from log-only to `trigger_lockout_wipe()` per the docstring at `hw/tamp.rs:13`.

### D. FW-update finishing
- [ ] **Wire up the real confirm UI** in `fw_update::confirm_commit` (currently stubbed to return `false` in non-e2e builds, which is what saved C-1 from being live).
- [ ] Add the unit test that `verify_manifest` rejects:
  - Wrong-vendor signature (BadSignature)
  - Tampered images post-streaming (SecureMismatch/NonsecureMismatch)
  - Below-floor versions (BelowRollback)
- [ ] Reconsider whether OTP bump should still live inside `cmd_fw_commit` or move to a post-boot "I survived" handler. Today the signature check protects the OTP bump from forged manifests but the user's confirm still gates a *legitimate-but-malicious-version-bump* DoS (someone tricks the user into installing a vendor-signed v(MAX-1) release, then no v50 downgrade is possible). The full fix is to require an additional cool-off / multi-version bump constraint.

### E. UX gaps
- [ ] **H-5**: gate `CMD_GET_INIT_CODE` behind a single OLED confirm or per-session quota.
- [ ] **H-6**: add `paymaster_and_data` decode + display.
- [ ] **M-5**: show `slot N-1 used X/65536` on the rotation confirm.
- [ ] Show paymaster address + fee summary in the basic sign render.

### F. Dev infrastructure
- [ ] Add `make dev-pubkey-fixture` recipe that writes `fsbl/fixtures/dev_pubkey.bin`, set `FSBL_VENDOR_PUBKEY` to it for all dev Makefile recipes, document in `docs/dev-board-setup.md`.
- [ ] Add `make ship-checklist` recipe that asserts:
  - `FSBL_VENDOR_PUBKEY` is set AND not the dev fixture
  - `TZSC_SECCFGR*` are non-zero (read back from a hardware probe)
  - The runtime self-test confirms `vendor_pubkey::VENDOR_PK_FPR` matches the fwsign-published fingerprint
  - All compile-time fences in `secure/src/nsc/mod.rs:98-116` are honored

### G. Carry-overs from this review (low-priority but tracked)
- [ ] M-2: 128-bit `slot_key`
- [ ] M-3: `secure_log!` on `last_userop_count_set` regression
- [ ] M-4: `HandlerGuard` for `cmd_get_wallet_address`
- [ ] L-1: comment/code drift on the pkSeed/pkRoot layout
- [ ] L-2 (full): scope-guard `SNAP_BUF` wipe on every return path
- [ ] L-3: FI on the unlock-result match
- [ ] L-5: surface the FI-detected "reconstructed entropy doesn't match master" via a persistent flag readable from the wizard
- [ ] L-8: bootstrap_cache eviction hygiene

## How to verify the fixes

```bash
# Build matrix
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "stm32u585 ui-noop dual-se"
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se"
cargo test  -p sphincs-tz-secure --tests
cargo build -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features "ui-noop mock-se" --release

# Run a sign smoke
make e2e

# (Once the vendor-pubkey fixture is wired) FW-update e2e
FSBL_VENDOR_PUBKEY=fsbl/fixtures/dev_pubkey.bin make fw-update-e2e
```

The signature-verify path is exercised in unit tests at `fw-manifest/src/lib.rs`; the integration on the secure firmware side currently has no direct test (the `confirm_commit` stub returns `false` so the COMMIT path never fires in production). Adding one is on the production checklist (D).
