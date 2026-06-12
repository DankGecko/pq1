//! CoW-binding resolution for Safe-wrapped `setPreSignature` orders.
//!
//! A CowSwap order can be pre-signed two ways:
//!
//!   * **Direct** — the wallet's UserOp inner calldata IS the 164-byte
//!     `setPreSignature(orderUid, true)` call on GPv2Settlement, and
//!     the orderUid's owner is the wallet (`sender`) itself.
//!   * **Safe-wrapped** — the UserOp drives a Gnosis Safe flow
//!     (`approveHash` with a `safe_v1` trailer, or `execTransaction`
//!     decoded from calldata) and the *SafeTx inner call* is the
//!     setPreSignature. The orderUid's owner is then the SAFE: on
//!     execution the Safe is `msg.sender` at the settlement contract,
//!     and GPv2 requires `uid.owner == msg.sender`.
//!
//! Both shapes verify through the same
//! [`crate::tx::eip712::cowswap`] pipeline — the only inputs that
//! differ are *which calldata* the v3 trailer must bind to and *which
//! address* the orderUid's owner must equal. This module owns that
//! selection so the two gateway handlers (single + batch) and the
//! downgrade gate share one predicate instead of three copies that can
//! drift.
//!
//! ## Fail-closed by construction
//!
//! A wrong selection (logic bug, glitched branch) yields a
//! `(owner, calldata)` pair that the v3 pipeline's own cross-checks
//! reject: the calldata length/shape gate refuses anything that is not
//! a well-formed 164-byte setPreSignature, and the owner byte-compare
//! refuses a mismatched uid. There is no input for which a mis-routed
//! binding verifies, so no FI sentinel is needed around the selection
//! itself (the verify *result* is sentinel-hardened at the call sites).

use sphincs_tz_shared::{
    GPV2_SETTLEMENT_ADDRESS, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO, SET_PRE_SIGNATURE_SELECTOR,
};

use super::{VerifiedSafeExec, VerifiedSafeV1};

/// Does this Safe inner call claim to be a CoW `setPreSignature`?
///
/// Mirrors the direct-path downgrade-gate predicate in
/// `cmd_sign_userop` (`cow_selector && cow_target`): target must be
/// the GPv2Settlement singleton (same CREATE2 address on every chain
/// CoW supports) and the selector must match. Deliberately does NOT
/// check the full 164-byte shape — the gate must also fire for a
/// malformed or `signed == false` calldata so those refuse loudly
/// instead of falling through to a blind-sign page the user might
/// habituate to confirming.
#[must_use]
pub fn safe_inner_is_cow_presign(inner_to: &[u8; 20], raw_data: &[u8]) -> bool {
    *inner_to == GPV2_SETTLEMENT_ADDRESS
        && raw_data.len() >= 4
        && raw_data[..4] == SET_PRE_SIGNATURE_SELECTOR
}

/// Resolved CoW-binding target: which calldata the v3 trailer must
/// shape-check + digest-bind against, and whose address the orderUid's
/// owner must equal.
pub struct CowBinding<'s> {
    /// Expected `orderUid.owner` — the Safe address for a wrapped
    /// order, the wallet (`sender`) for a direct one. **Owned**: in
    /// the batch handler the Safe context lives inside `routed[tx_idx]`,
    /// which is mutably re-borrowed right after resolution to store the
    /// verify result — a `&[u8; 20]` into the canonical would hold that
    /// borrow open.
    pub owner: [u8; 20],
    /// The setPreSignature calldata candidate. Keeps the snapshot
    /// lifetime `'s` (both `raw_data` and `decoded.data` are reborrows
    /// of the TOCTOU snapshot, not of the `Verified*` structs).
    pub calldata: &'s [u8],
    /// `true` iff a verified Safe context supplied the binding. This is
    /// the downgrade-gate predicate: a safe-wrapped presign with no
    /// verified v3 trailer must refuse to sign, exactly like the
    /// direct path's `cow_selector && cow_target` gate.
    pub via_safe: bool,
}

/// Resolve which `(owner, calldata)` pair a CoW v3 trailer must bind to.
///
/// Precedence: a verified `safe_v1` (approveHash) context wins, then a
/// verified `execTransaction` context, then the direct path. The two
/// Safe flavours are mutually exclusive in practice (disjoint selectors
/// on the same `inner_data`), so the ordering only pins down behaviour
/// for impossible inputs.
#[must_use]
pub fn resolve_cow_binding<'s>(
    inner_data: &'s [u8],
    direct_owner: &[u8; 20],
    safe_v1: Option<&VerifiedSafeV1<'s>>,
    safe_exec: Option<&VerifiedSafeExec<'s>>,
) -> CowBinding<'s> {
    if let Some(safe) = safe_v1 {
        let mut inner_to = [0u8; 20];
        inner_to.copy_from_slice(&safe.canonical[SAFE_OFF_TO..SAFE_OFF_TO + 20]);
        if safe_inner_is_cow_presign(&inner_to, safe.raw_data) {
            let mut owner = [0u8; 20];
            owner.copy_from_slice(
                &safe.canonical[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20],
            );
            return CowBinding {
                owner,
                calldata: safe.raw_data,
                via_safe: true,
            };
        }
    }
    if let Some(exec) = safe_exec {
        if safe_inner_is_cow_presign(&exec.decoded.to, exec.decoded.data) {
            return CowBinding {
                owner: exec.safe_address,
                calldata: exec.decoded.data,
                via_safe: true,
            };
        }
    }
    CowBinding {
        owner: *direct_owner,
        calldata: inner_data,
        via_safe: false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::eip712::safe::DecodedExec;
    use sphincs_tz_shared::SAFE_V1_CANONICAL_LEN;

    const SAFE_ADDR: [u8; 20] = [0x5a; 20];
    const SENDER: [u8; 20] = [0x11; 20];

    /// 164-byte well-formed-enough presign calldata (selector only —
    /// the resolver doesn't shape-check, the v3 pipeline does).
    fn presign_calldata() -> [u8; 164] {
        let mut cd = [0u8; 164];
        cd[..4].copy_from_slice(&SET_PRE_SIGNATURE_SELECTOR);
        cd
    }

    fn canonical_with(inner_to: &[u8; 20]) -> [u8; SAFE_V1_CANONICAL_LEN] {
        let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
        c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&SAFE_ADDR);
        c[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(inner_to);
        c
    }

    fn exec_with<'a>(inner_to: [u8; 20], data: &'a [u8]) -> VerifiedSafeExec<'a> {
        VerifiedSafeExec {
            chain_id: 1,
            safe_address: SAFE_ADDR,
            decoded: DecodedExec {
                to: inner_to,
                value: [0u8; 32],
                operation: 0,
                safe_tx_gas: [0u8; 32],
                base_gas: [0u8; 32],
                gas_price: [0u8; 32],
                gas_token: [0u8; 20],
                refund_receiver: [0u8; 20],
                data,
                signatures: &[],
            },
        }
    }

    // ── predicate matrix ───────────────────────────────────────────

    #[test]
    fn predicate_true_on_settlement_plus_selector() {
        let cd = presign_calldata();
        assert!(safe_inner_is_cow_presign(&GPV2_SETTLEMENT_ADDRESS, &cd));
    }

    #[test]
    fn predicate_true_even_for_malformed_tail() {
        // Gate must fire for selector-matching calldata of ANY length
        // ≥ 4 (incl. a signed==false body) so the refusal is loud
        // instead of a blind-sign fallback.
        let cd = [0xec, 0x6c, 0xb1, 0x3f, 0xff];
        assert!(safe_inner_is_cow_presign(&GPV2_SETTLEMENT_ADDRESS, &cd));
    }

    #[test]
    fn predicate_false_on_wrong_target() {
        let cd = presign_calldata();
        assert!(!safe_inner_is_cow_presign(&[0xaa; 20], &cd));
    }

    #[test]
    fn predicate_false_on_wrong_selector() {
        let mut cd = presign_calldata();
        cd[0] ^= 1;
        assert!(!safe_inner_is_cow_presign(&GPV2_SETTLEMENT_ADDRESS, &cd));
    }

    #[test]
    fn predicate_false_on_short_data() {
        assert!(!safe_inner_is_cow_presign(&GPV2_SETTLEMENT_ADDRESS, &[]));
        assert!(!safe_inner_is_cow_presign(
            &GPV2_SETTLEMENT_ADDRESS,
            &[0xec, 0x6c, 0xb1]
        ));
    }

    // ── resolver matrix ────────────────────────────────────────────

    #[test]
    fn no_safe_context_resolves_direct() {
        let inner = presign_calldata();
        let b = resolve_cow_binding(&inner, &SENDER, None, None);
        assert_eq!(b.owner, SENDER);
        assert_eq!(b.calldata.as_ptr(), inner.as_ptr());
        assert!(!b.via_safe);
    }

    #[test]
    fn approvehash_wrapped_resolves_safe() {
        let raw = presign_calldata();
        let safe = VerifiedSafeV1 {
            canonical: canonical_with(&GPV2_SETTLEMENT_ADDRESS),
            raw_data: &raw,
        };
        // inner_data is the 36-byte approveHash calldata in this shape.
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert_eq!(b.owner, SAFE_ADDR);
        assert_eq!(b.calldata.as_ptr(), raw.as_ptr());
        assert_eq!(b.calldata.len(), 164);
        assert!(b.via_safe);
    }

    #[test]
    fn exec_wrapped_resolves_safe() {
        let raw = presign_calldata();
        let exec = exec_with(GPV2_SETTLEMENT_ADDRESS, &raw);
        let inner = [0u8; 372];
        let b = resolve_cow_binding(&inner, &SENDER, None, Some(&exec));
        assert_eq!(b.owner, SAFE_ADDR);
        assert_eq!(b.calldata.as_ptr(), raw.as_ptr());
        assert!(b.via_safe);
    }

    #[test]
    fn safe_with_non_cow_inner_resolves_direct() {
        // ERC-20 transfer selector inside the Safe — the CoW binding
        // must stay on the direct path (where it will simply not
        // verify, since inner_data is approveHash).
        let mut raw = presign_calldata();
        raw[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        let safe = VerifiedSafeV1 {
            canonical: canonical_with(&GPV2_SETTLEMENT_ADDRESS),
            raw_data: &raw,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert_eq!(b.owner, SENDER);
        assert_eq!(b.calldata.as_ptr(), inner.as_ptr());
        assert!(!b.via_safe);
    }

    #[test]
    fn safe_with_presign_to_wrong_target_resolves_direct() {
        // Selector matches but the SafeTx inner target is not the
        // settlement singleton — e.g. a phishing contract reusing the
        // selector. No CoW binding; renders through the normal Safe
        // inner ladder (blind-sign).
        let raw = presign_calldata();
        let safe = VerifiedSafeV1 {
            canonical: canonical_with(&[0xaa; 20]),
            raw_data: &raw,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert_eq!(b.owner, SENDER);
        assert_eq!(b.calldata.as_ptr(), inner.as_ptr());
        assert!(!b.via_safe);
    }

    #[test]
    fn safe_v1_takes_precedence_over_exec() {
        // Impossible wire shape (disjoint selectors) — pinned anyway so
        // the precedence is deterministic if an upstream invariant ever
        // breaks.
        let raw_a = presign_calldata();
        let raw_b = presign_calldata();
        let safe = VerifiedSafeV1 {
            canonical: canonical_with(&GPV2_SETTLEMENT_ADDRESS),
            raw_data: &raw_a,
        };
        let exec = exec_with(GPV2_SETTLEMENT_ADDRESS, &raw_b);
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), Some(&exec));
        assert_eq!(b.owner, SAFE_ADDR);
        assert_eq!(b.calldata.as_ptr(), raw_a.as_ptr());
        assert!(b.via_safe);
    }
}
