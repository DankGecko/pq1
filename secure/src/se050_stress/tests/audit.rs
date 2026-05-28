//! Silicon verification of recently-landed ship-blocker fixes.
//!
//! S-5 (2026-05-28): SCP03 elevated to `P1=0x33`; `unwrap_response`
//! wired into `send_apdu`. Logic-analyzer verification on a real
//! B-U585I-IOT02A still pending per CLAUDE.md — these tests prove the
//! Rust side works end-to-end, leaving the bus capture as the only
//! remaining closure step.
//!
//! S-6 (2026-05-28): user UserID's admin-delete policy entry removed.
//! Admin can DoS-wipe data objects but can no longer substitute the
//! user PIN by deleting + recreating the UserID at the same OID.
//!
//! Each test in this file directly probes one of those guarantees.
//! A FAIL here is a hard signal that the fix doesn't hold on this
//! silicon — investigate before shipping.

use crate::stress_test;
use crate::se050::apdu::Se050Error;
use crate::se050_stress::{StressCtx, StressError, StressResult, Tier};
use crate::se050_stress::ctx::AdminPolicy;

// ---------------------------------------------------------------------------
// 3. scp03_response_encryption_verify (S-5 closure)
// ---------------------------------------------------------------------------

/// Writes a 32-byte sentinel pattern, reads it back through the
/// authenticated session, and asserts byte-for-byte round-trip equality.
///
/// At SCP03 `P1=0x33` (the new post-S-5 level) the response is encrypted
/// + R-MAC-authenticated; `unwrap_response` is responsible for
/// decrypting and verifying. If `unwrap_response` is broken — wrong
/// IV, wrong key derivation, off-by-one R-MAC length — the read either
/// returns garbage (`assert_eq` fails) or `Se050Error::Scp03`.
///
/// Sentinel pattern is `[0xDE; 32]`: maximally distinguishable from
/// natural TLV / SW bytes in a wire capture, so a logic analyzer can
/// confirm the on-bus response is NOT a 32-byte run of 0xDE (which
/// would imply ciphertext bypass).
fn scp03_response_encryption_verify(ctx: &mut StressCtx) -> StressResult {
    const SENTINEL: [u8; 32] = [0xDE; 32];
    let target = ctx.oid(0x01);

    // Clean slate.
    ctx.delete_scratch(target)?;

    ctx.write_scratch(target, &SENTINEL)?;

    let mut got = [0u8; 64];
    let n = ctx.read_scratch(target, &mut got)?;
    if n != SENTINEL.len() {
        secure_log!(
            "[S][stress][audit-s5] read returned {} bytes (want {})",
            n, SENTINEL.len(),
        );
        return Err(StressError::Assertion {
            what: "S-5 round-trip length mismatch",
            iter: 0,
        });
    }
    ctx.assert_eq("S-5 SCP03 payload round-trip", &got[..n], &SENTINEL)?;

    secure_log!(
        "[S][stress][audit-s5] 32-B 0xDE round-trip OK at P1=0x33 — unwrap_response verified",
    );
    Ok(())
}
stress_test!(SCP03_RESPONSE_ENCRYPTION_VERIFY, "scp03_response_encryption_verify", Tier::Safe, scp03_response_encryption_verify);

// ---------------------------------------------------------------------------
// 7. userid_no_admin_delete (S-6 closure)
// ---------------------------------------------------------------------------

/// Provision a UserID with `AdminPolicy::WithoutAdminEntry`, then
/// attempt to delete it under stress-admin auth. The expectation is
/// that the SE050 refuses (`Se050Error::Status(non-9000)`).
///
/// Why this matters: pre-S-6, every UserID carried a two-entry policy
/// including admin DELETE. That made the substitution attack possible:
/// admin → delete UserID → recreate at same OID with attacker PIN →
/// the gated data objects' policy is now satisfied by the new PIN,
/// letting the attacker exfiltrate `half_E`. Post-S-6, omitting the
/// admin entry makes the UserID immutable from admin's perspective —
/// only the user PIN itself can self-delete it.
///
/// This test FALSIFIES (or VERIFIES) that on silicon. PASS = admin
/// delete refused, AND user self-delete still succeeds (so the
/// invariant is "admin can't substitute" not "no one can delete").
fn userid_no_admin_delete(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let user_pin: [u8; 8] = *b"audit_s6";

    // Pre-clean (best-effort — admin can delete a USER-self-policy-only
    // UserID only via this test's own self-delete path, so the prior
    // run's residue requires admin-aware sweep).
    ctx.delete_scratch(target)?;

    // Step 1: provision UserID WITHOUT the admin entry. This is the
    // critical S-6 configuration.
    ctx.provision_test_userid(
        target,
        &user_pin,
        5,
        AdminPolicy::WithoutAdminEntry,
    )?;

    // Step 2: admin attempt to delete must FAIL. Use the raw admin
    // session because `delete_scratch` swallows the error to stay
    // idempotent — for the audit we want the error visible.
    let sid = ctx.open_admin_session()?;
    let delete_result = ctx.delete_authed(&sid, target);
    ctx.close_session(&sid);

    match delete_result {
        Ok(()) => {
            // Bad — admin deleted a UserID it shouldn't be able to.
            // S-6 is NOT enforced on this silicon.
            secure_log!(
                "[S][stress][audit-s6] FAIL: admin deleted UserID with no admin policy entry",
            );
            return Err(StressError::Assertion {
                what: "S-6 broken: admin deleted no-admin-policy UserID",
                iter: 0,
            });
        }
        Err(Se050Error::Status(sw)) => {
            secure_log!(
                "[S][stress][audit-s6] admin delete refused with SW=0x{:04x} (expected non-9000)",
                sw,
            );
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-s6] admin delete refused with driver error: {:?}",
                e,
            );
        }
    }

    // Step 3: confirm the UserID is still on-chip.
    let still_there = ctx.check_exists(target).unwrap_or(false);
    ctx.assert_true(
        "UserID must survive admin delete attempt",
        still_there,
    )?;

    // Step 4: user self-delete still works (proves the UserID isn't
    // structurally immortal — only admin is locked out).
    let sid = ctx.open_user_session(target, &user_pin)?;
    let self_delete = ctx.delete_authed(&sid, target);
    ctx.close_session(&sid);

    if let Err(e) = self_delete {
        secure_log!(
            "[S][stress][audit-s6] user self-delete FAILED: {:?} (S-6 fix may have over-restricted)",
            e,
        );
        return Err(e.into());
    }

    secure_log!(
        "[S][stress][audit-s6] S-6 confirmed: admin REFUSED, user self-delete OK",
    );
    Ok(())
}
stress_test!(USERID_NO_ADMIN_DELETE, "userid_no_admin_delete", Tier::Destructive, userid_no_admin_delete);
