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
//! ## MultiSend-wrapped orders
//!
//! The Safe web UI does not emit a single-call SafeTx for CoW flows —
//! it batches `[ERC-20 approve(GPv2VaultRelayer), setPreSignature]`
//! through `MultiSendCallOnly` via DELEGATECALL. When a verified Safe
//! context's inner call is an allowlisted multiSend (see
//! [`super::multi_send`]) carrying **exactly one** presign-claiming
//! record, the v3 trailer binds to that record's 164 bytes — the rest
//! of the pipeline (owner = the Safe, digest/validTo cross-check) is
//! unchanged. Zero presign records means a generic batch: no CoW
//! binding and no v3 requirement (the renderer shows every record).
//!
//! ## Fail-closed by construction
//!
//! A wrong selection (logic bug, glitched branch) yields a
//! `(owner, calldata)` pair that the v3 pipeline's own cross-checks
//! reject: the calldata length/shape gate refuses anything that is not
//! a well-formed 164-byte setPreSignature, and the owner byte-compare
//! refuses a mismatched uid. The multiSend arm preserves the property:
//! a malformed or ambiguous (≥2 presign claims) payload binds the FULL
//! multiSend calldata — which starts with `0x8d80ff0a` and so can never
//! pass the pipeline's selector/length pins — keeping `via_safe = true`
//! so the handlers' "v3 required" gate refuses even if the dedicated
//! msend verdict gate were glitched past. There is no input for which a
//! mis-routed binding verifies, so no FI sentinel is needed around the
//! selection itself (the verify *result* is sentinel-hardened at the
//! call sites).

use sphincs_tz_shared::{
    GPV2_SETTLEMENT_ADDRESS, SAFE_OFF_OPERATION, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO,
    SET_PRE_SIGNATURE_SELECTOR,
};

use super::{multi_send, VerifiedSafeExec, VerifiedSafeV1};

// `safe_inner_is_cow_presign` (the pure CoW-presign predicate: target ==
// GPv2Settlement singleton + `setPreSignature` selector, no full-shape
// check) was extracted, verbatim, into `pqsigner_tx::multisend` so the
// page-budget classification that consumes it is host-compilable and
// Kani-bounded. Re-exported here so `resolve_safe_arm`, `safe_display`,
// the `safe` mod re-export, and the tests keep using it unchanged.
pub use pqsigner_tx::multisend::safe_inner_is_cow_presign;

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

/// Evaluate one verified Safe context (either flavour, reduced to its
/// `(operation, inner_to, raw_data, safe_address)` facts) against both
/// CoW claims.
///
/// Returns `None` when the inner call makes no CoW claim at all — a
/// direct (non-multiSend) non-presign call, or a well-formed multiSend
/// whose records contain zero presign claims (a generic batch needs no
/// v3 trailer; the renderer shows every record).
fn resolve_safe_arm<'s>(
    operation: u8,
    inner_to: &[u8; 20],
    raw_data: &'s [u8],
    owner: [u8; 20],
) -> Option<CowBinding<'s>> {
    if safe_inner_is_cow_presign(inner_to, raw_data) {
        return Some(CowBinding {
            owner,
            calldata: raw_data,
            via_safe: true,
        });
    }
    if multi_send::is_multisend_claim(operation, inner_to, raw_data) {
        return match multi_send::summarize(raw_data) {
            // Generic batch — no CoW record, no v3 requirement.
            Ok(s) if s.presign_claims == 0 => None,
            // The CoW flow: bind the unique presign record's bytes.
            Ok(s) if s.presign_claims == 1 => Some(CowBinding {
                owner,
                // `presign_record_data` re-derives from the same bytes
                // the summary just decoded; `unwrap_or(raw_data)` is
                // unreachable but keeps the arm fail-closed (the full
                // multiSend calldata can never pass the v3 pipeline).
                calldata: multi_send::presign_record_data(raw_data).unwrap_or(raw_data),
                via_safe: true,
            }),
            // Malformed payload or ambiguous (≥2 presign claims): bind
            // provably-unverifiable bytes with `via_safe = true` so the
            // "v3 required" gate refuses — belt-and-braces under the
            // dedicated msend verdict gate, which refuses these earlier
            // with a specific banner.
            _ => Some(CowBinding {
                owner,
                calldata: raw_data,
                via_safe: true,
            }),
        };
    }
    None
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
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&safe.canonical[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20]);
        let operation = safe.canonical[SAFE_OFF_OPERATION];
        if let Some(binding) = resolve_safe_arm(operation, &inner_to, safe.raw_data, owner) {
            return binding;
        }
    }
    if let Some(exec) = safe_exec {
        if let Some(binding) = resolve_safe_arm(
            exec.decoded.operation,
            &exec.decoded.to,
            exec.decoded.data,
            exec.safe_address,
        ) {
            return binding;
        }
    }
    CowBinding {
        owner: *direct_owner,
        calldata: inner_data,
        via_safe: false,
    }
}

/// WYSIWYS gate for a verified *direct* (non-Safe-wrapped) CoW v3 order
/// (audit 2026-06-26 — direct-path target unshown).
///
/// `render_cowswap_pages` shows the decoded order but NOT the UserOp's
/// inner-tx call target (`to_address`); the signed
/// `executeWithOffchainCount(...)` forwards `to_address.call{value}(data)`
/// to an arbitrary target. Unless that target IS the GPv2 settlement
/// singleton, the trust-inspiring "CowSwap order" screen would accompany a
/// call to an attacker-chosen, never-displayed target — a native-ETH drain
/// (the value page shows the amount but not the destination) dressed as a
/// gas-free CoW presign. The Safe-wrapped path already pins the *inner*
/// target via [`safe_inner_is_cow_presign`]; this is the direct-arm twin.
///
/// Returns `true` when the target is acceptable (refuse on `false`). Only
/// constrains the case the renderer can't show — a verified direct order;
/// the Safe-wrapped path (`via_safe`) and the non-CoW paths are unaffected.
/// A legitimate direct presign always targets GPv2, so this never refuses a
/// well-formed CoW UserOp.
#[must_use]
pub fn direct_cow_target_ok(zk_v3_present: bool, via_safe: bool, to_address: &[u8; 20]) -> bool {
    if zk_v3_present && !via_safe {
        *to_address == GPV2_SETTLEMENT_ADDRESS
    } else {
        true
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

    // ── multiSend resolver matrix ──────────────────────────────────

    use super::super::multi_send::test_util::{
        cow_flow_calldata, encode_multisend, pack_record, presign_calldata_stub, ZERO_VALUE,
    };
    use sphincs_tz_shared::{MULTISEND_CALL_ONLY_ADDRESSES, SET_PRE_SIGNATURE_SELECTOR as PRESIG};

    const MS_CALL_ONLY: [u8; 20] = MULTISEND_CALL_ONLY_ADDRESSES[0];

    fn canonical_with_op(
        inner_to: &[u8; 20],
        operation: u8,
    ) -> [u8; SAFE_V1_CANONICAL_LEN] {
        let mut c = canonical_with(inner_to);
        c[SAFE_OFF_OPERATION] = operation;
        c
    }

    fn exec_with_op<'a>(
        inner_to: [u8; 20],
        data: &'a [u8],
        operation: u8,
    ) -> VerifiedSafeExec<'a> {
        let mut e = exec_with(inner_to, data);
        e.decoded.operation = operation;
        e
    }

    /// The binding the v3 pipeline receives must be the presign
    /// *record's* bytes — a strict subslice of the multiSend calldata.
    #[test]
    fn multisend_approvehash_binds_presign_record() {
        let ms = cow_flow_calldata();
        let safe = VerifiedSafeV1 {
            canonical: canonical_with_op(&MS_CALL_ONLY, 1),
            raw_data: &ms,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert!(b.via_safe);
        assert_eq!(b.owner, SAFE_ADDR);
        assert_eq!(b.calldata.len(), 164);
        assert_eq!(&b.calldata[..4], &PRESIG);
        let ms_range = ms.as_ptr() as usize..ms.as_ptr() as usize + ms.len();
        assert!(ms_range.contains(&(b.calldata.as_ptr() as usize)));
    }

    #[test]
    fn multisend_exec_binds_presign_record() {
        let ms = cow_flow_calldata();
        let exec = exec_with_op(MS_CALL_ONLY, &ms, 1);
        let inner = [0u8; 372];
        let b = resolve_cow_binding(&inner, &SENDER, None, Some(&exec));
        assert!(b.via_safe);
        assert_eq!(b.owner, SAFE_ADDR);
        assert_eq!(b.calldata.len(), 164);
        assert_eq!(&b.calldata[..4], &PRESIG);
    }

    /// Zero presign records = generic batch: no CoW binding, no v3
    /// requirement — the renderer shows every record instead.
    #[test]
    fn multisend_without_presign_resolves_direct() {
        let packed = pack_record(0, &[0x11; 20], &ZERO_VALUE, &[]);
        let ms = encode_multisend(&packed);
        let safe = VerifiedSafeV1 {
            canonical: canonical_with_op(&MS_CALL_ONLY, 1),
            raw_data: &ms,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert!(!b.via_safe);
        assert_eq!(b.owner, SENDER);
        assert_eq!(b.calldata.as_ptr(), inner.as_ptr());
    }

    /// Two presign records is ambiguous (one trailer, one binding):
    /// fail closed — via_safe with bytes the CoW pipeline rejects.
    #[test]
    fn multisend_two_presigns_fails_closed() {
        let mut packed = pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata_stub(),
        );
        packed.extend_from_slice(&pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata_stub(),
        ));
        let ms = encode_multisend(&packed);
        let safe = VerifiedSafeV1 {
            canonical: canonical_with_op(&MS_CALL_ONLY, 1),
            raw_data: &ms,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert!(b.via_safe, "ambiguous multiSend must keep the v3 requirement");
        // Non-verifiable by construction: multiSend selector, not 164 B.
        assert_ne!(&b.calldata[..4], &PRESIG);
        assert_ne!(b.calldata.len(), 164);
    }

    /// Malformed multiSend (claim fires, decode fails): fail closed.
    #[test]
    fn multisend_malformed_fails_closed() {
        let ms = [0x8d, 0x80, 0xff, 0x0a, 0xde, 0xad, 0xbe, 0xef];
        let safe = VerifiedSafeV1 {
            canonical: canonical_with_op(&MS_CALL_ONLY, 1),
            raw_data: &ms,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert!(b.via_safe);
        assert_ne!(b.calldata.len(), 164);
    }

    /// op==0 to a MultiSend address is NOT a multiSend claim (under
    /// CALL the Safe is not msg.sender for the records) — stays on the
    /// direct path, where it renders as loud blind-sign.
    #[test]
    fn multisend_op0_resolves_direct() {
        let ms = cow_flow_calldata();
        let safe = VerifiedSafeV1 {
            canonical: canonical_with_op(&MS_CALL_ONLY, 0),
            raw_data: &ms,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert!(!b.via_safe);
        assert_eq!(b.owner, SENDER);
    }

    /// op==1 to a non-allowlisted target never produces a binding here
    /// — but more importantly it never produces a `Verified*` at all
    /// (the verifier op-gates are pinned in `verify.rs` /
    /// `exec_decode.rs` tests). This pins the resolver half: even if a
    /// Verified* existed, no multiSend claim fires.
    #[test]
    fn multisend_non_allowlisted_target_no_claim() {
        let ms = cow_flow_calldata();
        let safe = VerifiedSafeV1 {
            canonical: canonical_with_op(&[0xaa; 20], 1),
            raw_data: &ms,
        };
        let inner = [0u8; 36];
        let b = resolve_cow_binding(&inner, &SENDER, Some(&safe), None);
        assert!(!b.via_safe);
    }

    // ── direct-path target gate (audit 2026-06-26) ─────────────────

    /// A verified direct v3 order MUST target the GPv2 settlement
    /// singleton — anything else is a call to an unshown target behind a
    /// CoW screen, so the handler must refuse.
    #[test]
    fn direct_v3_to_attacker_refused() {
        assert!(
            !direct_cow_target_ok(true, false, &[0xaa; 20]),
            "direct v3 order to a non-settlement target must be refused"
        );
    }

    /// A verified direct v3 order to the real settlement is fine.
    #[test]
    fn direct_v3_to_settlement_ok() {
        assert!(direct_cow_target_ok(true, false, &GPV2_SETTLEMENT_ADDRESS));
    }

    /// The Safe-wrapped path pins the inner target itself, so the outer
    /// `to_address` (the Safe) is not constrained by this gate.
    #[test]
    fn safe_wrapped_target_unconstrained() {
        assert!(direct_cow_target_ok(true, true, &[0xaa; 20]));
    }

    /// No verified v3 ⇒ not a CoW render ⇒ gate is inert (other renderers
    /// show the target themselves).
    #[test]
    fn no_v3_is_inert() {
        assert!(direct_cow_target_ok(false, false, &[0xaa; 20]));
        assert!(direct_cow_target_ok(false, true, &[0xaa; 20]));
    }
}
