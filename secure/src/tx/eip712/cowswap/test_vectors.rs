//! CoW GPv2Order cross-check test vectors.
//!
//! Fixtures + regression tests for the v3 security gate. Kept in a
//! `#[cfg(test)]` sibling so the 1000 USDC → WETH byte-array doesn't
//! dilute the production-logic audit surface in `mod.rs`.
//!
//! Coverage (9 tests total):
//!   * happy path — valid canonical + calldata + owner passes all
//!     invariants.
//!   * 5 per-field flips on the failure side: chain_id, validTo,
//!     orderDigest, appData (caught via digest), owner.
//!   * 3 shape-check violations: bad selector, signed=false, nonzero
//!     tail pad.

use super::*;

/// 1000 USDC → ≥ 0.5 WETH fixture — matches companion e2e_vector.
fn fixture_canonical() -> [u8; 204] {
    let mut c = [0u8; 204];
    c[0..8].copy_from_slice(&1u64.to_be_bytes()); // chain_id
    c[8..28].copy_from_slice(&[
        0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
        0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
    ]); // USDC
    c[28..48].copy_from_slice(&[
        0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
        0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
    ]); // WETH
    c[48..68].copy_from_slice(&[
        0x74, 0x2d, 0x35, 0xcc, 0x66, 0x34, 0xc0, 0x53, 0x29, 0x25, 0xa3, 0xb8, 0x44, 0xbc,
        0x45, 0x4e, 0x44, 0x38, 0xf4, 0x4e,
    ]); // receiver
        // sell_amount = 1_000_000_000 at [68..100]
    c[96..100].copy_from_slice(&1_000_000_000u32.to_be_bytes());
    // buy_amount = 0x06F05B59D3B20000 at [100..132]
    c[124..132].copy_from_slice(&0x06F05B59D3B20000u64.to_be_bytes());
    // fee_amount = 0 at [132..164]
    // valid_to = 0x68000000 at [164..168]
    c[164..168].copy_from_slice(&0x68000000u32.to_be_bytes());
    c[168] = 0; // kind = Sell
    c[169] = 0;
    c[170] = 0;
    c[171] = 0;
    c[172..204].copy_from_slice(&[
        0x83, 0xb9, 0xdc, 0xb2, 0x31, 0x6e, 0x54, 0xfc, 0x04, 0xc1, 0x0f, 0x74, 0xc9, 0xa3,
        0xd5, 0xdd, 0x66, 0xa9, 0xe4, 0xc4, 0x3c, 0x04, 0xcc, 0xef, 0xb9, 0xc0, 0xc0, 0x3e,
        0x61, 0xe5, 0xfb, 0x28,
    ]);
    c
}

fn fixture_owner() -> [u8; 20] {
    [0xfb, 0x3c, 0x7e, 0xb9, 0x36, 0xcA, 0xA1, 0x2B, 0x5A, 0x88, 0x4d, 0x61, 0x23, 0x93, 0x96, 0x9A, 0x55, 0x7d, 0x43, 0x07]
}

/// Hand-build a setPreSignature calldata for an arbitrary uid owner.
/// The owner sits OUTSIDE the EIP-712 digest, so the same canonical +
/// digest serve both the direct flow (owner = wallet sender) and the
/// Safe-wrapped flow (owner = the Safe). Reuses `compute_digest` for
/// the orderDigest slice.
fn fixture_calldata_for_owner(owner: &[u8; 20]) -> [u8; 164] {
    let canonical = fixture_canonical();
    let digest = compute_digest(&canonical, 1).unwrap();
    let mut cd = [0u8; 164];
    cd[0..4].copy_from_slice(&[0xec, 0x6c, 0xb1, 0x3f]);
    cd[35] = 0x40;
    cd[67] = 1;
    cd[99] = 56;
    cd[100..132].copy_from_slice(&digest);
    cd[132..152].copy_from_slice(owner);
    cd[152..156].copy_from_slice(&canonical[164..168]);
    cd
}

fn fixture_calldata() -> [u8; 164] {
    fixture_calldata_for_owner(&fixture_owner())
}

#[test]
fn happy_path_passes() {
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    assert!(cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner).is_ok());
    assert!(check_setpresig_calldata_shape(&calldata).is_ok());
}

#[test]
fn chain_id_mismatch_rejected() {
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 137, &owner),
        Err(OrderUidMismatch::ChainIdMismatch)
    );
}

#[test]
fn valid_to_mismatch_rejected() {
    let canonical = fixture_canonical();
    let mut calldata = fixture_calldata();
    calldata[152] = calldata[152].wrapping_add(1);
    let owner = fixture_owner();
    // The valid_to check runs before the digest check, so this
    // bubbles out as ValidToMismatch (digest would also fail).
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::ValidToMismatch)
    );
}

#[test]
fn order_digest_flip_rejected() {
    let canonical = fixture_canonical();
    let mut calldata = fixture_calldata();
    calldata[100] ^= 0x01;
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::OrderDigestMismatch)
    );
}

#[test]
fn canonical_field_flip_rejected_via_digest() {
    // Flip any single byte of canonical that isn't chain_id or
    // valid_to and the orderDigest will diverge — catching the
    // attack "swap the appData silently behind a verified proof".
    let mut canonical = fixture_canonical();
    canonical[172] ^= 0xFF; // appData MSB
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::OrderDigestMismatch)
    );
}

#[test]
fn owner_mismatch_rejected() {
    let canonical = fixture_canonical();
    let mut calldata = fixture_calldata();
    calldata[132] ^= 0x01;
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::OwnerMismatch)
    );
}

#[test]
fn shape_check_rejects_bad_selector() {
    let mut cd = fixture_calldata();
    cd[0] ^= 0xFF;
    assert_eq!(
        check_setpresig_calldata_shape(&cd),
        Err(OrderUidMismatch::CanonicalDecode)
    );
}

#[test]
fn shape_check_rejects_signed_false() {
    let mut cd = fixture_calldata();
    cd[67] = 0;
    assert_eq!(
        check_setpresig_calldata_shape(&cd),
        Err(OrderUidMismatch::CanonicalDecode)
    );
}

#[test]
fn shape_check_rejects_nonzero_tail_padding() {
    let mut cd = fixture_calldata();
    cd[163] = 1;
    assert_eq!(
        check_setpresig_calldata_shape(&cd),
        Err(OrderUidMismatch::CanonicalDecode)
    );
}

// ---------------------------------------------------------------------------
// Safe-wrapped presign (uid owner = a Gnosis Safe, not the wallet)
// ---------------------------------------------------------------------------

fn fixture_safe_address() -> [u8; 20] {
    [0x5a; 20]
}

#[test]
fn safe_owner_binding_passes_and_sender_binding_fails() {
    // The same order pre-signed THROUGH a Safe: uid.owner is the Safe.
    // Cross-check must pass when the expected owner is the Safe and
    // refuse when it's the wallet sender — this asymmetry is exactly
    // what `safe::cow_binding::resolve_cow_binding` selects on.
    let canonical = fixture_canonical();
    let safe = fixture_safe_address();
    let calldata = fixture_calldata_for_owner(&safe);
    assert!(check_setpresig_calldata_shape(&calldata).is_ok());
    assert!(cross_check_setpresig_calldata(&canonical, &calldata, 1, &safe).is_ok());
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &fixture_owner()),
        Err(OrderUidMismatch::OwnerMismatch)
    );
}

#[test]
fn safe_wrapped_host_pipeline_composes() {
    // Everything the firmware chains for a Safe-wrapped presign except
    // the Groth16 step (cfg(not(test))-gated): build a SafeTx whose
    // inner call is the presign with uid.owner = the Safe, verify the
    // safe_v1 trailer against the approveHash calldata, resolve the
    // CoW binding off the verified Safe, and run the v3 cross-check
    // against the resolved (owner, calldata) pair.
    use crate::tx::eip712::safe::{
        compute_safe_tx_hash, resolve_cow_binding, verify_and_bind_trailer,
    };
    use sphincs_tz_shared::{
        APPROVE_HASH_SELECTOR, GPV2_SETTLEMENT_ADDRESS, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH,
        SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO, SAFE_V1_CANONICAL_LEN,
    };

    let safe_addr = fixture_safe_address();
    let presign_cd = fixture_calldata_for_owner(&safe_addr);

    // SafeTx canonical: Safe `safe_addr` calls the settlement with the
    // presign bytes (operation Call, no value, no refund, nonce 0).
    let mut sc = [0u8; SAFE_V1_CANONICAL_LEN];
    sc[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&1u64.to_be_bytes());
    sc[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&safe_addr);
    sc[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(&GPV2_SETTLEMENT_ADDRESS);
    sc[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&keccak(&presign_cd));

    // safe_v1 trailer bundle: canonical || u16 raw_data_len || raw_data.
    let mut bundle = [0u8; SAFE_V1_CANONICAL_LEN + 2 + 164];
    bundle[..SAFE_V1_CANONICAL_LEN].copy_from_slice(&sc);
    bundle[SAFE_V1_CANONICAL_LEN..SAFE_V1_CANONICAL_LEN + 2]
        .copy_from_slice(&(164u16).to_be_bytes());
    bundle[SAFE_V1_CANONICAL_LEN + 2..].copy_from_slice(&presign_cd);

    // UserOp inner calldata: approveHash(safeTxHash).
    let safe_tx_hash = compute_safe_tx_hash(&sc).unwrap();
    let mut inner = [0u8; 36];
    inner[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    inner[4..36].copy_from_slice(&safe_tx_hash);

    let verified = verify_and_bind_trailer(&bundle, &inner, 1, &safe_addr)
        .expect("safe_v1 trailer must verify");

    let wallet_sender = fixture_owner();
    let bind = resolve_cow_binding(&inner, &wallet_sender, Some(&verified), None);
    assert!(bind.via_safe);
    assert_eq!(bind.owner, safe_addr);
    assert_eq!(bind.calldata, presign_cd.as_slice());

    let calldata_array: &[u8; 164] = bind.calldata.try_into().unwrap();
    assert!(check_setpresig_calldata_shape(calldata_array).is_ok());
    assert!(cross_check_setpresig_calldata(
        &fixture_canonical(),
        calldata_array,
        1,
        &bind.owner
    )
    .is_ok());
}

#[test]
fn multisend_wrapped_host_pipeline_composes() {
    // The Safe-UI shape end-to-end minus Groth16: the SafeTx
    // DELEGATECALLs MultiSendCallOnly with `multiSend([approve(vault
    // relayer) on sellToken, setPreSignature])`; the safe_v1 trailer
    // verifies (operation gate opens for the allowlisted target), the
    // resolver binds the v3 target to the presign RECORD's bytes, and
    // the cross-check passes against the order canonical with
    // uid.owner = the Safe.
    extern crate alloc;
    use crate::tx::eip712::safe::multi_send::test_util::cow_flow_calldata_with;
    use crate::tx::eip712::safe::{
        compute_safe_tx_hash, resolve_cow_binding, verify_and_bind_trailer,
    };
    use sphincs_tz_shared::{
        APPROVE_HASH_SELECTOR, MULTISEND_CALL_ONLY_ADDRESSES, SAFE_OFF_CHAIN_ID,
        SAFE_OFF_DATA_HASH, SAFE_OFF_OPERATION, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO,
        SAFE_V1_CANONICAL_LEN,
    };

    let safe_addr = fixture_safe_address();
    let presign_cd = fixture_calldata_for_owner(&safe_addr);
    // approve on the order's sellToken (canonical[8..28] = USDC).
    let sell_token: [u8; 20] = fixture_canonical()[8..28].try_into().unwrap();
    let ms = cow_flow_calldata_with(&sell_token, &presign_cd);

    // SafeTx canonical: DELEGATECALL into MultiSendCallOnly v1.3.0.
    let mut sc = [0u8; SAFE_V1_CANONICAL_LEN];
    sc[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&1u64.to_be_bytes());
    sc[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&safe_addr);
    sc[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(&MULTISEND_CALL_ONLY_ADDRESSES[0]);
    sc[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&keccak(&ms));
    sc[SAFE_OFF_OPERATION] = 1;

    let mut bundle = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + ms.len());
    bundle.extend_from_slice(&sc);
    bundle.extend_from_slice(&(ms.len() as u16).to_be_bytes());
    bundle.extend_from_slice(&ms);

    let safe_tx_hash = compute_safe_tx_hash(&sc).unwrap();
    let mut inner = [0u8; 36];
    inner[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    inner[4..36].copy_from_slice(&safe_tx_hash);

    let verified = verify_and_bind_trailer(&bundle, &inner, 1, &safe_addr)
        .expect("multiSend safe_v1 trailer must verify (allowlisted DELEGATECALL)");

    let wallet_sender = fixture_owner();
    let bind = resolve_cow_binding(&inner, &wallet_sender, Some(&verified), None);
    assert!(bind.via_safe);
    assert_eq!(bind.owner, safe_addr);
    assert_eq!(
        bind.calldata,
        presign_cd.as_slice(),
        "the binding must be the presign RECORD's bytes, not the multiSend wrapper"
    );

    let calldata_array: &[u8; 164] = bind.calldata.try_into().unwrap();
    assert!(check_setpresig_calldata_shape(calldata_array).is_ok());
    assert!(cross_check_setpresig_calldata(
        &fixture_canonical(),
        calldata_array,
        1,
        &bind.owner
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// On-device decode trailer (`verify_and_bind_trailer`) — parse, binding,
// and the AddrHex fallback. The `Decoded` positive path (a leg whose
// ERC-20 bundle Merkle-verifies against the firmware-pinned ERC20_DB_ROOT
// and whose token/chain match the canonical leg) is exercised end-to-end
// by the QEMU CoW scenarios — building a real Merkle proof against the
// committed tree isn't tractable in a host unit test. These tests pin the
// security-critical behaviours: the keccak binding still gates, and a
// missing/garbage/mismatched bundle DEGRADES a leg to AddrHex rather than
// rejecting or trusting host-supplied metadata.

#[test]
fn decode_canonical_only_trailer_both_legs_addrhex() {
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    let v = verify_and_bind_trailer(&canonical, &calldata, 1, &owner)
        .expect("canonical-only trailer with valid calldata must verify");
    assert!(matches!(v.sell, CowLeg::AddrHex));
    assert!(matches!(v.buy, CowLeg::AddrHex));
    assert_eq!(v.canonical, canonical);
}

#[test]
fn decode_trailer_rejected_on_order_digest_flip() {
    let canonical = fixture_canonical();
    let mut calldata = fixture_calldata();
    calldata[100] ^= 0x01; // corrupt the bound orderDigest
    let owner = fixture_owner();
    assert!(verify_and_bind_trailer(&canonical, &calldata, 1, &owner).is_none());
}

#[test]
fn decode_trailer_rejected_on_wrong_owner() {
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    assert!(verify_and_bind_trailer(&canonical, &calldata, 1, &[0u8; 20]).is_none());
}

#[test]
fn decode_trailer_rejected_when_canonical_too_short() {
    let calldata = fixture_calldata();
    assert!(verify_and_bind_trailer(&[0u8; 100], &calldata, 1, &fixture_owner()).is_none());
}

#[test]
fn decode_trailer_rejected_on_bad_calldata_len() {
    let canonical = fixture_canonical();
    assert!(verify_and_bind_trailer(&canonical, &[0u8; 36], 1, &fixture_owner()).is_none());
}

#[test]
fn decode_garbage_leg_bundles_degrade_to_addrhex() {
    // canonical(204) + sell_len||garbage + buy_len||garbage. The garbage
    // can't Merkle-verify, so both legs fall back to AddrHex — but the
    // order still verifies because the keccak binding is intact.
    extern crate alloc;
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    let g = [0xABu8; 48];
    let mut t = alloc::vec::Vec::new();
    t.extend_from_slice(&canonical);
    t.extend_from_slice(&(g.len() as u16).to_be_bytes());
    t.extend_from_slice(&g);
    t.extend_from_slice(&(g.len() as u16).to_be_bytes());
    t.extend_from_slice(&g);
    let v = verify_and_bind_trailer(&t, &calldata, 1, &owner)
        .expect("binding intact, garbage legs must degrade not reject");
    assert!(matches!(v.sell, CowLeg::AddrHex));
    assert!(matches!(v.buy, CowLeg::AddrHex));
}

#[test]
fn decode_zero_len_legs_are_addrhex() {
    extern crate alloc;
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    let mut t = alloc::vec::Vec::new();
    t.extend_from_slice(&canonical);
    t.extend_from_slice(&0u16.to_be_bytes()); // sell_len = 0 → no bundle
    t.extend_from_slice(&0u16.to_be_bytes()); // buy_len  = 0 → no bundle
    let v = verify_and_bind_trailer(&t, &calldata, 1, &owner).expect("Some");
    assert!(matches!(v.sell, CowLeg::AddrHex));
    assert!(matches!(v.buy, CowLeg::AddrHex));
}

#[test]
fn decode_malformed_len_prefix_does_not_panic() {
    // A len prefix larger than the remaining bytes must not panic and
    // must not reject — the leg simply degrades to AddrHex.
    extern crate alloc;
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    let mut t = alloc::vec::Vec::new();
    t.extend_from_slice(&canonical);
    t.extend_from_slice(&0xFFFFu16.to_be_bytes()); // claims 65535 bytes, none follow
    let v = verify_and_bind_trailer(&t, &calldata, 1, &owner)
        .expect("malformed len must degrade, binding intact");
    assert!(matches!(v.sell, CowLeg::AddrHex));
    assert!(matches!(v.buy, CowLeg::AddrHex));
}

#[test]
fn multisend_exec_host_pipeline_composes() {
    // Same composition through the `execTransaction` flavour: the
    // wallet's inner calldata IS the execTransaction whose `data` is
    // the multiSend blob and `operation` is 1.
    extern crate alloc;
    use crate::tx::eip712::safe::multi_send::test_util::cow_flow_calldata_with;
    use crate::tx::eip712::safe::{resolve_cow_binding, verify_and_bind_exec};
    use sphincs_tz_shared::{EXEC_TRANSACTION_SELECTOR, MULTISEND_CALL_ONLY_ADDRESSES};

    let safe_addr = fixture_safe_address();
    let presign_cd = fixture_calldata_for_owner(&safe_addr);
    let sell_token: [u8; 20] = fixture_canonical()[8..28].try_into().unwrap();
    let ms = cow_flow_calldata_with(&sell_token, &presign_cd);

    // ABI-encode execTransaction(to=MultiSendCallOnly, value=0,
    // data=ms, operation=1, gas/refund zeroed, signatures empty).
    let head_len = 10 * 32;
    let ms_padded = (ms.len() + 31) / 32 * 32;
    let data_off = head_len;
    let sigs_off = head_len + 32 + ms_padded;
    let total = 4 + head_len + 32 + ms_padded + 32;
    let mut cd = alloc::vec![0u8; total];
    cd[..4].copy_from_slice(&EXEC_TRANSACTION_SELECTOR);
    let head = &mut cd[4..];
    head[12..32].copy_from_slice(&MULTISEND_CALL_ONLY_ADDRESSES[0]); // to
    head[2 * 32 + 28..2 * 32 + 32].copy_from_slice(&(data_off as u32).to_be_bytes());
    head[3 * 32 + 31] = 1; // operation = DelegateCall
    head[9 * 32 + 28..9 * 32 + 32].copy_from_slice(&(sigs_off as u32).to_be_bytes());
    let data_pos = 4 + head_len;
    cd[data_pos + 28..data_pos + 32].copy_from_slice(&(ms.len() as u32).to_be_bytes());
    cd[data_pos + 32..data_pos + 32 + ms.len()].copy_from_slice(&ms);
    // signatures tail: zero length at sigs_off (already zeroed).

    let verified = verify_and_bind_exec(&cd, 1, &safe_addr)
        .expect("multiSend execTransaction must verify (allowlisted DELEGATECALL)");
    assert_eq!(verified.decoded.operation, 1);

    let wallet_sender = fixture_owner();
    let bind = resolve_cow_binding(&cd, &wallet_sender, None, Some(&verified));
    assert!(bind.via_safe);
    assert_eq!(bind.owner, safe_addr);
    assert_eq!(bind.calldata, presign_cd.as_slice());

    let calldata_array: &[u8; 164] = bind.calldata.try_into().unwrap();
    assert!(check_setpresig_calldata_shape(calldata_array).is_ok());
    assert!(cross_check_setpresig_calldata(
        &fixture_canonical(),
        calldata_array,
        1,
        &bind.owner
    )
    .is_ok());
}
