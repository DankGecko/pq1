# VULN — Half-written provisioning soft-bricks the device at first-boot setup

- **Severity:** HIGH (reliability) — a transient SE fault at the most fragile moment (unbox / seed-restore) leaves the device looking dead with no user-discoverable recovery.
- **Class:** availability / soft-brick, first-boot / seed-restore path (not a transaction; not companion-controlled).
- **Found:** 2026-07-02 reliability hunt. Finder rated LOW; deeper trace shows it is HIGH.
- **Status:** rollback fix landed (`secure/src/crypto.rs`) + regression test. Root-cause SE050 ordering (below) flagged for silicon review.

## Mechanism

`crypto::provision_from_mnemonic` (the "new wallet" / "restore from seed" wizard entry) called:

```rust
store.provision(...).expect("provisioning failed");   // pre-fix
```

`DualSecureElement::provision` (`dual_se.rs:144`) is **non-atomic**: OPTIGA fully first (line 180), then SE050 (line 185). Within `se050::store_objects`, `USERID_OBJ` is written **first** (mod.rs:1704), then the data objects `ENTROPY_OBJ / VK_OBJ / BOOTSTRAP_VK_OBJ` (1716-1766). And `se050::check_provisioned` keys **only** on `USERID_OBJ` existence (mod.rs:1470-1475); `DualSecureElement::is_provisioned` is an AND across both SEs (dual_se.rs:141).

So a transient SE050 I²C fault (a class already observed on this hardware — see the fixed t1oi2c / TRNG-SECS issues) **after** the `USERID_OBJ` write but **before** the entropy write:

1. `.expect()` panics → `panic_handler` (main.rs:3887) zeroizes + `loop { wfi() }` forever → device freezes mid-setup, user power-cycles.
2. On reboot: `is_provisioned()` = `optiga(true) && se050(USERID_OBJ exists → true)` = **true** → the wizard is **skipped**.
3. User enters their (correct) PIN → SE050 UserID verify succeeds (resets the SE counter) → entropy reconstruction reads the **missing** `ENTROPY_OBJ` → `unlock()` returns `UnlockError::InternalError` (dual_se.rs:390-424).
4. `cmd_request_unlock` (line 132-138) returns `InternalError` **without bumping the MCU counter and without wiping**. So the user's correct PIN yields an opaque error *forever*, they never reach the 10-wrong-PIN wipe by entering the right PIN, and the wizard never re-runs.

Net: a device that looks dead at first-boot setup, from a transient glitch, with no obvious recovery. The developers already guard the **decoy** wallet against exactly this (crypto.rs:283-287 wipes both wallets on decoy-provision failure) but not the **real** wallet.

Note the S-6 hardening (mod.rs:1960-1970) makes `USERID_OBJ` **non-admin-deletable**, so `factory_reset_admin` cannot clear it — but it *does* wipe the OPTIGA leg, which flips `is_provisioned()` false (the AND), and `user_factory_reset` (PIN-authed, mod.rs:626) *can* self-delete USERID with the correct PIN the user still holds. So recovery is possible in principle, just not surfaced automatically.

## Fix applied

`crypto::provision_from_mnemonic` now rolls back on failure before halting, mirroring the decoy path:

```rust
if store.provision(...).is_err() {
    entropy.zeroize(); master_secret.zeroize();
    let _ = store.factory_reset_admin();   // wipes OPTIGA leg → is_provisioned()=false → wizard re-runs
    panic!("provisioning failed — rolled back for wizard restart");
}
```

`factory_reset_admin` arms the crash-safe wipe flag first, so a fault mid-rollback is resumed on the next boot. On the next cold boot `is_provisioned()` reads false (OPTIGA blank) and the wizard re-runs cleanly.

Regression test: `secure/src/secure_element.rs::failed_provision_rolls_back_before_halting` (new `MockSecureElement::force_provision_err` + `factory_reset_admin` override that clears slots). Host suite 2065/0; thumbv8m dual-SE image compiles.

## Residual (silicon review recommended)

The rollback fixes the *observable* soft-brick for the common case (user re-enters the same PIN on the wizard re-run). Two SE050-ordering hazards remain, both silicon-dependent and out of scope for a blind code change:

1. `check_provisioned` keys on the **first**-written object (`USERID_OBJ`) rather than the last, so `is_provisioned()` can transiently read true mid-write. Consider keying it on the last-written object — but note the write-once + fail-loud-if-exists (0x6986) re-provision semantics and the S-6 non-admin-deletable USERID interact here.
2. If the user picks a **different** PIN on the wizard re-run, the surviving (admin-undeletable) `USERID_OBJ` keeps the old PIN while OPTIGA F1D0 gets the new one → three-way lockstep mismatch. Same limitation the existing decoy rollback has.

Recommended bench check: drive a fault between the USERID write and the entropy write and confirm the rollback + re-provision path recovers on real silicon (does `factory_reset_admin` reliably flip `is_provisioned()` false, and does re-provision with a fresh PIN reconcile).
