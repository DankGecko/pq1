//! Strict decoder + classifier for Safe `MultiSendCallOnly` batches.
//!
//! The Safe web UI wraps any flow needing more than one action in
//! `SafeTx{to = MultiSendCallOnly, operation = 1 (DELEGATECALL),
//! data = multiSend(transactions)}` — e.g. a CoW order placement is
//! `[ERC-20 approve(GPv2VaultRelayer, amount), setPreSignature(uid,
//! true)]`. DELEGATECALL runs the target's code in the Safe's own
//! storage context, so the packed payload is only worth decoding when
//! the target is a known-good MultiSend implementation:
//!
//!   * **Address allowlist** — only the three canonical
//!     `MultiSendCallOnly` deployments (v1.3.0 canonical / v1.3.0
//!     eip155 / v1.4.1) are accepted as a DELEGATECALL target. Any
//!     other target keeps today's hard refusal at the Safe verifiers'
//!     operation gates.
//!   * **Per-record `operation == 0`** — mirrors MultiSendCallOnly's
//!     on-chain revert, so no nested DELEGATECALL can ride a record
//!     even if the allowlist were somehow wrong.
//!   * **Strict ABI framing** — canonical `multiSend(bytes)` encoding
//!     only: head offset exactly 0x20, exact total length, zero
//!     padding. Anything Solidity wouldn't emit is refused, so the
//!     on-device render can never disagree with on-chain decoding.
//!
//! ## One predicate, four call sites
//!
//! [`is_multisend_claim`] is THE acceptance predicate for
//! `operation == 1`, shared verbatim by (a) the `safe_v1` verifier's
//! operation gate, (b) the `execTransaction` verifier's operation
//! gate, (c) the CoW-binding resolver's multiSend arm, and (d) the
//! renderer's defensive re-check + `Op:` row. A divergence between
//! any two of those would let a DELEGATECALL SafeTx verify but fall
//! through to a render path that mislabels it — keeping them one
//! function makes that drift impossible.

use sphincs_tz_shared::{
    MULTISEND_CALL_ONLY_ADDRESSES, MULTISEND_MAX_RECORDS, MULTI_SEND_SELECTOR,
};

use super::cow_binding::safe_inner_is_cow_presign;
use super::mgmt_decode::{classify_safe_mgmt, page_count as mgmt_page_count, SafeMgmtOp};
use crate::erc20::calldata::{parse_erc20_calldata, Erc20Call};

// The strict outer-framing decoder, its 32-byte word reader, and the
// refusal taxonomy were extracted, verbatim and behaviour-identical,
// into the host-compilable `pqsigner-tx` crate so they can be
// Kani-bounded-verified (canonical-acceptance / soundness — see
// `pqsigner_tx::multisend::verification`). Re-exported here so every
// caller below (`is_multisend_claim`, `MsRecordIter`, `summarize`,
// `multisend_verdict`, the test suite, …) and the four external call
// sites keep working unchanged.
pub use pqsigner_tx::multisend::{decode_multisend, read_u32_word, MsError};

/// Fixed per-record header: `operation(1) || to(20) || value(32) ||
/// dataLen(32)`, followed by `data(dataLen)`. Packed encoding — no
/// padding between records.
const MS_RECORD_HEADER_LEN: usize = 1 + 20 + 32 + 32;

/// Is `to` one of the canonical `MultiSendCallOnly` deployments?
#[must_use]
pub fn is_allowlisted_multisend(to: &[u8; 20]) -> bool {
    MULTISEND_CALL_ONLY_ADDRESSES.iter().any(|a| a == to)
}

/// Does this SafeTx inner call claim to be an allowlisted multiSend
/// batch?
///
/// `operation == 1` is part of the predicate on purpose: under
/// `operation == 0` (CALL) the MultiSend contract — not the Safe — is
/// `msg.sender` for every record, so none of the record semantics the
/// trusted UI would render (CoW `uid.owner == the Safe` above all)
/// hold. An op-0 call to a MultiSend address therefore stays on
/// today's path (opaque calldata → loud blind-sign, honest
/// `Op: Call`).
///
/// Like [`safe_inner_is_cow_presign`], this deliberately does NOT
/// shape-check the payload — the claim must also fire for a malformed
/// blob so it refuses loudly instead of falling through to a
/// blind-sign page the user might habituate to confirming.
#[must_use]
pub fn is_multisend_claim(operation: u8, to: &[u8; 20], data: &[u8]) -> bool {
    operation == 1
        && is_allowlisted_multisend(to)
        && data.len() >= 4
        && data[..4] == MULTI_SEND_SELECTOR
}

// ---------------------------------------------------------------------------
// Strict decode — `decode_multisend`, `read_u32_word`, and `MsError`
// now live in `pqsigner_tx::multisend` (re-exported above) so they can
// be Kani-bounded. The record iterator below still consumes them.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Record iterator
// ---------------------------------------------------------------------------

/// One packed multiSend record. `data` borrows from the same snapshot
/// the multiSend calldata lives in.
#[derive(Copy, Clone, Debug)]
pub struct MsRecord<'a> {
    /// Raw operation byte. [`summarize`] (and therefore every accepted
    /// payload) requires this to be 0; the iterator itself reports it
    /// verbatim so tests can probe the rejection.
    pub operation: u8,
    pub to: [u8; 20],
    /// Native value forwarded with the record's call, uint256 BE.
    pub value: [u8; 32],
    pub data: &'a [u8],
}

impl MsRecord<'_> {
    #[must_use]
    pub fn value_is_zero(&self) -> bool {
        self.value.iter().all(|&b| b == 0)
    }
}

/// Iterator over the packed records slice returned by
/// [`decode_multisend`]. Yields `Err` once on the first malformed
/// record, then `None`. The cursor must land exactly on the slice end
/// — a partial trailing record is [`MsError::TruncatedRecord`].
pub struct MsRecordIter<'a> {
    packed: &'a [u8],
    cursor: usize,
    failed: bool,
}

impl<'a> MsRecordIter<'a> {
    #[must_use]
    pub fn new(packed: &'a [u8]) -> Self {
        Self {
            packed,
            cursor: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for MsRecordIter<'a> {
    type Item = Result<MsRecord<'a>, MsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.cursor == self.packed.len() {
            return None;
        }
        let rest = &self.packed[self.cursor..];
        if rest.len() < MS_RECORD_HEADER_LEN {
            self.failed = true;
            return Some(Err(MsError::TruncatedRecord));
        }
        let operation = rest[0];
        let mut to = [0u8; 20];
        to.copy_from_slice(&rest[1..21]);
        let mut value = [0u8; 32];
        value.copy_from_slice(&rest[21..53]);
        let data_len = match read_u32_word(&rest[53..85]) {
            Ok(l) => l,
            Err(_) => {
                self.failed = true;
                return Some(Err(MsError::BadRecordDataLen));
            }
        };
        let data_end = match MS_RECORD_HEADER_LEN.checked_add(data_len) {
            Some(e) if e <= rest.len() => e,
            _ => {
                self.failed = true;
                return Some(Err(MsError::TruncatedRecord));
            }
        };
        let data = &rest[MS_RECORD_HEADER_LEN..data_end];
        self.cursor += data_end;
        Some(Ok(MsRecord {
            operation,
            to,
            value,
            data,
        }))
    }
}

// ---------------------------------------------------------------------------
// Summary + acceptance verdict
// ---------------------------------------------------------------------------

/// Shape facts about a fully-decoded multiSend payload.
#[derive(Copy, Clone, Debug)]
pub struct MsSummary {
    pub record_count: usize,
    /// Number of records claiming to be a CoW `setPreSignature`
    /// (target == GPv2Settlement, selector match). Exactly one zk_v3
    /// trailer rides a sign request, so only `0` (generic batch) and
    /// `1` (CoW flow) are signable; `>= 2` is refused upstream.
    pub presign_claims: usize,
    /// Record index of the (last) presign claim. Meaningful only when
    /// `presign_claims == 1`.
    pub presign_idx: usize,
}

/// Decode + validate the payload's hard rules: strict framing, 1..=
/// [`MULTISEND_MAX_RECORDS`] records, every record `operation == 0`.
/// Counts presign claims (selector-level only — the full 164-byte
/// shape stays in the CoW pipeline so a malformed or `signed == false`
/// presign refuses loudly there instead of blind-rendering).
pub fn summarize(data: &[u8]) -> Result<MsSummary, MsError> {
    let packed = decode_multisend(data)?;
    let mut record_count = 0usize;
    let mut presign_claims = 0usize;
    let mut presign_idx = 0usize;
    for rec in MsRecordIter::new(packed) {
        let rec = rec?;
        if rec.operation != 0 {
            return Err(MsError::RecordOpNotCall);
        }
        if record_count == MULTISEND_MAX_RECORDS {
            return Err(MsError::BadRecordCount);
        }
        if safe_inner_is_cow_presign(&rec.to, rec.data) {
            presign_claims += 1;
            presign_idx = record_count;
        }
        record_count += 1;
    }
    if record_count == 0 {
        return Err(MsError::BadRecordCount);
    }
    Ok(MsSummary {
        record_count,
        presign_claims,
        presign_idx,
    })
}

/// The data slice of the unique presign-claiming record, when there is
/// exactly one. The CoW-binding resolver binds the zk_v3 trailer to
/// these bytes.
#[must_use]
pub fn presign_record_data(data: &[u8]) -> Option<&[u8]> {
    let packed = decode_multisend(data).ok()?;
    let mut found: Option<&[u8]> = None;
    for rec in MsRecordIter::new(packed) {
        let rec = rec.ok()?;
        if safe_inner_is_cow_presign(&rec.to, rec.data) {
            if found.is_some() {
                return None; // ambiguous — refused upstream anyway
            }
            found = Some(rec.data);
        }
    }
    found
}

/// Does any record target `contract`? Used by the handlers' ERC-20
/// metadata acceptance gate: an outer ERC-20 trailer attributed to a
/// token one of the records calls is allowed through to the renderer
/// (which re-checks the address per record before applying it).
#[must_use]
pub fn any_record_to_matches(data: &[u8], contract: &[u8; 20]) -> bool {
    let Ok(packed) = decode_multisend(data) else {
        return false;
    };
    for rec in MsRecordIter::new(packed) {
        match rec {
            Ok(r) if &r.to == contract => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// Handler-level acceptance verdict for a verified Safe context's
/// inner call. One shared mapping so the single and batch handlers
/// cannot drift.
pub enum MsVerdict {
    /// Inner call is not a (claimed) allowlisted multiSend — not this
    /// module's business.
    NotMultiSend,
    /// Decodes cleanly under every hard rule; carry the shape facts.
    Accept(MsSummary),
    /// Claimed multiSend that violates a hard rule. The handler must
    /// refuse to sign — a DELEGATECALL payload has no degraded render.
    Reject(&'static str),
}

#[must_use]
pub fn multisend_verdict(operation: u8, to: &[u8; 20], raw: &[u8]) -> MsVerdict {
    if !is_multisend_claim(operation, to, raw) {
        return MsVerdict::NotMultiSend;
    }
    match summarize(raw) {
        Ok(s) if s.presign_claims >= 2 => MsVerdict::Reject("msend 2+ presign"),
        Ok(s) => MsVerdict::Accept(s),
        Err(e) => MsVerdict::Reject(e.as_status_str()),
    }
}

// ---------------------------------------------------------------------------
// Per-record display classification + page accounting
// ---------------------------------------------------------------------------

/// Display classification of one record — the per-record analogue of
/// the Safe renderer's `InnerKind` ladder, factored here (host-
/// testable) so the page-budget gate and the renderer derive page
/// counts from the SAME classification and physically cannot disagree.
#[derive(Copy, Clone, Debug)]
pub enum MsRecordKind {
    /// Empty calldata, zero value.
    EmptyCall,
    /// Empty calldata, non-zero value — plain ETH transfer.
    PlainEth,
    /// Strict ERC-20 transfer / transferFrom / approve shape. Renders
    /// "known" (symbol + decimals) only if verified metadata address-
    /// matches; page count is identical either way.
    Erc20(Erc20Call),
    /// Record targets the Safe itself with a recognised singleton op.
    SafeMgmt(SafeMgmtOp),
    /// Record targets the Safe itself with an unrecognised selector.
    UnknownSafeSelf,
    /// Claims `setPreSignature` on GPv2Settlement. Renders as the full
    /// CoW order (banner + shared body) for the unique bound record;
    /// the gates guarantee a verified zk_v3 exists by render time.
    CowPresignClaim,
    /// Anything else — loud per-record blind-sign (selector + length +
    /// data hash), same trust level as today's single blind inner.
    Blind,
}

/// Classify one record for display. Mirrors the single-call ladder in
/// `display::safe_display`: CoW claim first (disjoint target), then
/// Safe self-calls, then empty/ERC-20/blind.
#[must_use]
pub fn classify_record_kind(
    to: &[u8; 20],
    value_is_zero: bool,
    data: &[u8],
    safe_address: &[u8; 20],
) -> MsRecordKind {
    if safe_inner_is_cow_presign(to, data) {
        return MsRecordKind::CowPresignClaim;
    }
    if to == safe_address && !data.is_empty() {
        return match classify_safe_mgmt(data) {
            Some(op) => MsRecordKind::SafeMgmt(op),
            None => MsRecordKind::UnknownSafeSelf,
        };
    }
    if data.is_empty() {
        return if value_is_zero {
            MsRecordKind::EmptyCall
        } else {
            MsRecordKind::PlainEth
        };
    }
    match parse_erc20_calldata(data) {
        Some(call) => MsRecordKind::Erc20(call),
        None => MsRecordKind::Blind,
    }
}

/// Content pages for one classified record (excluding its divider page
/// and any spliced value page). `cow_body_pages` = 1 banner + the
/// shared order body (6 proof-mode / 8 AddrOnly).
#[must_use]
pub fn record_content_pages(kind: &MsRecordKind, cow_body_pages: usize) -> usize {
    match kind {
        MsRecordKind::EmptyCall => 1,
        MsRecordKind::PlainEth => 2,
        // header + recipient + amount + contract; +1 for the transferFrom
        // `From (debited)` page (lockstep with
        // `safe_display::{append_erc20_tail_pages, inner_kind_page_count}`).
        MsRecordKind::Erc20(call) => 4 + usize::from(matches!(call, Erc20Call::TransferFrom { .. })),
        MsRecordKind::SafeMgmt(op) => mgmt_page_count(op),
        MsRecordKind::UnknownSafeSelf | MsRecordKind::Blind => 3,
        MsRecordKind::CowPresignClaim => cow_body_pages,
    }
}

/// Does this record need a dedicated "record sends ETH" page? PlainEth
/// shows its value inline; EmptyCall is zero-value by definition; every
/// other kind would otherwise sign a hidden per-record `value`.
#[must_use]
pub fn record_needs_value_page(kind: &MsRecordKind, value_is_zero: bool) -> bool {
    !value_is_zero && !matches!(kind, MsRecordKind::PlainEth | MsRecordKind::EmptyCall)
}

/// Total inner pages a decoded multiSend payload renders: per record,
/// 1 divider page + optional value page + content pages. `None` when
/// the payload doesn't decode (callers gate on [`multisend_verdict`]
/// first, so `None` here is defensive).
///
/// This is exact, not an upper bound: the renderer classifies through
/// the same [`classify_record_kind`] and counts through the same
/// [`record_content_pages`], so gate and render agree by construction.
#[must_use]
pub fn records_pages_total(
    data: &[u8],
    safe_address: &[u8; 20],
    cow_body_pages: usize,
) -> Option<usize> {
    let packed = decode_multisend(data).ok()?;
    let mut total = 0usize;
    for rec in MsRecordIter::new(packed) {
        let rec = rec.ok()?;
        let value_is_zero = rec.value_is_zero();
        let kind = classify_record_kind(&rec.to, value_is_zero, rec.data, safe_address);
        total += 1; // divider
        if record_needs_value_page(&kind, value_is_zero) {
            total += 1;
        }
        total += record_content_pages(&kind, cow_body_pages);
    }
    Some(total)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Host-test builders for canonical multiSend calldata, shared with the
/// `cow_binding` / `verify` / `extra_tests` suites so every test
/// constructs the wire shape through one encoder.
#[cfg(test)]
pub mod test_util {
    use sphincs_tz_shared::{
        GPV2_SETTLEMENT_ADDRESS, GPV2_VAULT_RELAYER_ADDRESS, MULTI_SEND_SELECTOR,
        SET_PRE_SIGNATURE_SELECTOR,
    };
    extern crate alloc;
    use alloc::vec::Vec;

    pub const ZERO_VALUE: [u8; 32] = [0u8; 32];

    /// Pack one record: `op || to || value || dataLen || data`.
    pub fn pack_record(op: u8, to: &[u8; 20], value: &[u8; 32], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(op);
        out.extend_from_slice(to);
        out.extend_from_slice(value);
        let mut len_word = [0u8; 32];
        len_word[28..32].copy_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&len_word);
        out.extend_from_slice(data);
        out
    }

    /// Canonical `multiSend(bytes)` calldata around a packed payload.
    pub fn encode_multisend(packed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MULTI_SEND_SELECTOR);
        let mut offset_word = [0u8; 32];
        offset_word[31] = 0x20;
        out.extend_from_slice(&offset_word);
        let mut len_word = [0u8; 32];
        len_word[28..32].copy_from_slice(&(packed.len() as u32).to_be_bytes());
        out.extend_from_slice(&len_word);
        out.extend_from_slice(packed);
        // Zero-pad to a 32-byte boundary, like Solidity.
        let pad = (32 - packed.len() % 32) % 32;
        out.extend_from_slice(&alloc::vec![0u8; pad]);
        out
    }

    /// Selector-correct 164-byte presign calldata (zero body — the
    /// resolver and decoder don't shape-check; the CoW pipeline does).
    pub fn presign_calldata_stub() -> [u8; 164] {
        let mut cd = [0u8; 164];
        cd[..4].copy_from_slice(&SET_PRE_SIGNATURE_SELECTOR);
        cd
    }

    /// Strict 68-byte `approve(spender, amount)` calldata.
    pub fn approve_calldata(spender: &[u8; 20], amount_low: u8) -> [u8; 68] {
        let mut cd = [0u8; 68];
        cd[..4].copy_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
        cd[16..36].copy_from_slice(spender);
        cd[67] = amount_low;
        cd
    }

    /// Strict 100-byte `transferFrom(from, to, amount)` calldata. The
    /// `from` is the debited account the renderer surfaces on its own page.
    pub fn transfer_from_calldata(from: &[u8; 20], to: &[u8; 20], amount_low: u8) -> [u8; 100] {
        let mut cd = [0u8; 100];
        cd[..4].copy_from_slice(&[0x23, 0xb8, 0x72, 0xdd]);
        cd[16..36].copy_from_slice(from);
        cd[48..68].copy_from_slice(to);
        cd[99] = amount_low;
        cd
    }

    /// The Safe-UI CoW flow: `[approve(vault relayer) on TOKEN,
    /// setPreSignature]`, both records op 0 / value 0, wrapped in
    /// canonical multiSend calldata. `presign` defaults to the stub.
    pub fn cow_flow_calldata_with(token: &[u8; 20], presign: &[u8]) -> Vec<u8> {
        let mut packed = pack_record(
            0,
            token,
            &ZERO_VALUE,
            &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
        );
        packed.extend_from_slice(&pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            presign,
        ));
        encode_multisend(&packed)
    }

    pub fn cow_flow_calldata() -> Vec<u8> {
        cow_flow_calldata_with(&[0x70u8; 20], &presign_calldata_stub())
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::{
        approve_calldata, cow_flow_calldata, encode_multisend, pack_record, transfer_from_calldata,
        ZERO_VALUE,
    };
    use super::*;
    use sphincs_tz_shared::{GPV2_SETTLEMENT_ADDRESS, GPV2_VAULT_RELAYER_ADDRESS, SET_PRE_SIGNATURE_SELECTOR};
    extern crate alloc;
    use alloc::vec::Vec;

    const MS_CALL_ONLY_130: [u8; 20] = MULTISEND_CALL_ONLY_ADDRESSES[0];
    const SAFE_ADDR: [u8; 20] = [0x5a; 20];

    fn presign_calldata() -> [u8; 164] {
        super::test_util::presign_calldata_stub()
    }

    // ── claim predicate ────────────────────────────────────────────

    #[test]
    fn claim_true_for_allowlisted_op1_multisend() {
        let cd = cow_flow_calldata();
        for a in &MULTISEND_CALL_ONLY_ADDRESSES {
            assert!(is_multisend_claim(1, a, &cd));
        }
    }

    #[test]
    fn claim_false_for_op0() {
        // CALL to a MultiSend contract: the Safe is not msg.sender for
        // the records, so the claim must NOT fire (stays blind-sign).
        let cd = cow_flow_calldata();
        assert!(!is_multisend_claim(0, &MS_CALL_ONLY_130, &cd));
    }

    #[test]
    fn claim_false_for_non_allowlisted_target() {
        let cd = cow_flow_calldata();
        assert!(!is_multisend_claim(1, &[0xaa; 20], &cd));
        // Plain MultiSend v1.3.0 — deliberately NOT allowlisted.
        let plain: [u8; 20] = [
            0xa2, 0x38, 0xcb, 0xeb, 0x14, 0x2c, 0x10, 0xef, 0x7a, 0xd8, 0x44, 0x2c, 0x6d, 0x1f,
            0x9e, 0x89, 0xe0, 0x7e, 0x77, 0x61,
        ];
        assert!(!is_multisend_claim(1, &plain, &cd));
    }

    #[test]
    fn claim_false_for_wrong_selector_or_short_data() {
        let mut cd = cow_flow_calldata();
        cd[0] ^= 1;
        assert!(!is_multisend_claim(1, &MS_CALL_ONLY_130, &cd));
        assert!(!is_multisend_claim(1, &MS_CALL_ONLY_130, &[0x8d, 0x80, 0xff]));
    }

    #[test]
    fn claim_fires_even_for_malformed_tail() {
        // Selector + allowlist match with a garbage body: the claim
        // must fire so the refusal is loud, not a blind-sign fallback.
        let cd = [0x8d, 0x80, 0xff, 0x0a, 0xde, 0xad];
        assert!(is_multisend_claim(1, &MS_CALL_ONLY_130, &cd));
        assert!(matches!(
            multisend_verdict(1, &MS_CALL_ONLY_130, &cd),
            MsVerdict::Reject(_)
        ));
    }

    // ── strict decode ──────────────────────────────────────────────

    #[test]
    fn decode_happy_two_records() {
        let cd = cow_flow_calldata();
        let packed = decode_multisend(&cd).expect("decode");
        let recs: Vec<_> = MsRecordIter::new(packed)
            .collect::<Result<Vec<_>, _>>()
            .expect("records");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].to, [0x70u8; 20]);
        assert_eq!(recs[0].data.len(), 68);
        assert_eq!(recs[1].to, GPV2_SETTLEMENT_ADDRESS);
        assert_eq!(recs[1].data.len(), 164);
        assert!(recs.iter().all(|r| r.operation == 0 && r.value_is_zero()));
    }

    #[test]
    fn decode_rejects_wrong_selector() {
        let mut cd = cow_flow_calldata();
        cd[3] ^= 1;
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::WrongSelector);
    }

    #[test]
    fn decode_rejects_short_input() {
        assert_eq!(
            decode_multisend(&MULTI_SEND_SELECTOR).unwrap_err(),
            MsError::ShortInput
        );
    }

    #[test]
    fn decode_rejects_nonstandard_offset() {
        let mut cd = cow_flow_calldata();
        cd[4 + 31] = 0x40; // offset word low byte: 0x20 → 0x40
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadOffset);
        let mut cd2 = cow_flow_calldata();
        cd2[4] = 0x01; // offset word high bits set
        assert_eq!(decode_multisend(&cd2).unwrap_err(), MsError::BadOffset);
    }

    #[test]
    fn decode_rejects_length_overrun() {
        let mut cd = cow_flow_calldata();
        // Inflate the declared bytes length past the calldata end.
        let len_off = 4 + 32 + 28;
        let huge = (u32::MAX / 2).to_be_bytes();
        cd[len_off..len_off + 4].copy_from_slice(&huge);
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadLength);
    }

    #[test]
    fn decode_rejects_length_high_bits() {
        let mut cd = cow_flow_calldata();
        cd[4 + 32] = 0x01; // length word byte above the u32 range
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadLength);
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let mut cd = cow_flow_calldata();
        cd.extend_from_slice(&[0u8; 32]); // extra all-zero word after the padded tail
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadPadding);
    }

    #[test]
    fn decode_rejects_nonzero_padding() {
        let token = [0x70u8; 20];
        // 68-byte approve record → packed len 85+68 = 153 → 7 pad bytes.
        let packed = pack_record(
            0,
            &token,
            &ZERO_VALUE,
            &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
        );
        let mut cd = encode_multisend(&packed);
        assert_eq!(packed.len() % 32 != 0, true, "test needs a padded tail");
        let last = cd.len() - 1;
        cd[last] = 0xff;
        assert_eq!(decode_multisend(&cd).unwrap_err(), MsError::BadPadding);
    }

    #[test]
    fn iter_rejects_truncated_record_header() {
        let packed = [0u8; 50]; // < 85-byte header
        let err = MsRecordIter::new(&packed).next().unwrap().unwrap_err();
        assert_eq!(err, MsError::TruncatedRecord);
    }

    #[test]
    fn iter_rejects_record_data_overrun() {
        let mut packed = pack_record(0, &[0x11; 20], &ZERO_VALUE, &[0xaa; 4]);
        // Inflate the record's dataLen beyond the slice end.
        packed[53 + 28..53 + 32].copy_from_slice(&100u32.to_be_bytes());
        let err = MsRecordIter::new(&packed).next().unwrap().unwrap_err();
        assert_eq!(err, MsError::TruncatedRecord);
    }

    #[test]
    fn iter_rejects_record_datalen_high_bits() {
        let mut packed = pack_record(0, &[0x11; 20], &ZERO_VALUE, &[]);
        packed[53] = 0x01;
        let err = MsRecordIter::new(&packed).next().unwrap().unwrap_err();
        assert_eq!(err, MsError::BadRecordDataLen);
    }

    // ── summarize ──────────────────────────────────────────────────

    #[test]
    fn summarize_cow_flow() {
        let cd = cow_flow_calldata();
        let s = summarize(&cd).expect("summary");
        assert_eq!(s.record_count, 2);
        assert_eq!(s.presign_claims, 1);
        assert_eq!(s.presign_idx, 1);
    }

    #[test]
    fn summarize_presign_only() {
        let packed = pack_record(0, &GPV2_SETTLEMENT_ADDRESS, &ZERO_VALUE, &presign_calldata());
        let s = summarize(&encode_multisend(&packed)).expect("summary");
        assert_eq!(s.record_count, 1);
        assert_eq!(s.presign_claims, 1);
        assert_eq!(s.presign_idx, 0);
    }

    #[test]
    fn summarize_rejects_record_op1() {
        let token = [0x70u8; 20];
        let mut packed = pack_record(
            1, // nested DELEGATECALL record
            &token,
            &ZERO_VALUE,
            &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
        );
        packed.extend_from_slice(&pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata(),
        ));
        assert_eq!(
            summarize(&encode_multisend(&packed)).unwrap_err(),
            MsError::RecordOpNotCall
        );
    }

    #[test]
    fn summarize_rejects_zero_records() {
        assert_eq!(
            summarize(&encode_multisend(&[])).unwrap_err(),
            MsError::BadRecordCount
        );
    }

    #[test]
    fn summarize_rejects_too_many_records() {
        let mut packed = Vec::new();
        for i in 0..=MULTISEND_MAX_RECORDS {
            packed.extend_from_slice(&pack_record(0, &[i as u8; 20], &ZERO_VALUE, &[]));
        }
        assert_eq!(
            summarize(&encode_multisend(&packed)).unwrap_err(),
            MsError::BadRecordCount
        );
    }

    #[test]
    fn summarize_counts_two_presign_claims() {
        let mut packed = pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata(),
        );
        packed.extend_from_slice(&pack_record(
            0,
            &GPV2_SETTLEMENT_ADDRESS,
            &ZERO_VALUE,
            &presign_calldata(),
        ));
        let cd = encode_multisend(&packed);
        let s = summarize(&cd).expect("summary");
        assert_eq!(s.presign_claims, 2);
        // …and the verdict refuses the ambiguity.
        assert!(matches!(
            multisend_verdict(1, &MS_CALL_ONLY_130, &cd),
            MsVerdict::Reject("msend 2+ presign")
        ));
        // …and the binding extractor declines to pick one.
        assert!(presign_record_data(&cd).is_none());
    }

    // ── presign extraction + record-target scan ───────────────────

    #[test]
    fn presign_record_data_returns_the_record_slice() {
        let cd = cow_flow_calldata();
        let data = presign_record_data(&cd).expect("presign record");
        assert_eq!(data.len(), 164);
        assert_eq!(&data[..4], &SET_PRE_SIGNATURE_SELECTOR);
        // The slice borrows from inside `cd` (no copy).
        let cd_range = cd.as_ptr() as usize..cd.as_ptr() as usize + cd.len();
        assert!(cd_range.contains(&(data.as_ptr() as usize)));
    }

    #[test]
    fn any_record_to_matches_finds_token_and_settlement() {
        let cd = cow_flow_calldata();
        assert!(any_record_to_matches(&cd, &[0x70u8; 20]));
        assert!(any_record_to_matches(&cd, &GPV2_SETTLEMENT_ADDRESS));
        assert!(!any_record_to_matches(&cd, &[0xaa; 20]));
    }

    // ── verdict ────────────────────────────────────────────────────

    #[test]
    fn verdict_not_multisend_for_direct_presign() {
        let cd = presign_calldata();
        assert!(matches!(
            multisend_verdict(0, &GPV2_SETTLEMENT_ADDRESS, &cd),
            MsVerdict::NotMultiSend
        ));
    }

    #[test]
    fn verdict_accepts_cow_flow() {
        let cd = cow_flow_calldata();
        match multisend_verdict(1, &MS_CALL_ONLY_130, &cd) {
            MsVerdict::Accept(s) => {
                assert_eq!(s.record_count, 2);
                assert_eq!(s.presign_claims, 1);
            }
            _ => panic!("expected Accept"),
        }
    }

    // ── classification + page accounting ──────────────────────────

    #[test]
    fn classify_matrix() {
        // CoW claim
        assert!(matches!(
            classify_record_kind(&GPV2_SETTLEMENT_ADDRESS, true, &presign_calldata(), &SAFE_ADDR),
            MsRecordKind::CowPresignClaim
        ));
        // ERC-20 approve
        assert!(matches!(
            classify_record_kind(
                &[0x70; 20],
                true,
                &approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1),
                &SAFE_ADDR
            ),
            MsRecordKind::Erc20(Erc20Call::Approve { .. })
        ));
        // Safe self-call, recognised mgmt op (changeThreshold(2))
        let mut mgmt = [0u8; 36];
        mgmt[..4].copy_from_slice(&[0x69, 0x4e, 0x80, 0xc3]);
        mgmt[35] = 2;
        assert!(matches!(
            classify_record_kind(&SAFE_ADDR, true, &mgmt, &SAFE_ADDR),
            MsRecordKind::SafeMgmt(_)
        ));
        // Safe self-call, unknown selector
        assert!(matches!(
            classify_record_kind(&SAFE_ADDR, true, &[0xde, 0xad, 0xbe, 0xef], &SAFE_ADDR),
            MsRecordKind::UnknownSafeSelf
        ));
        // Empty / plain ETH
        assert!(matches!(
            classify_record_kind(&[0x11; 20], true, &[], &SAFE_ADDR),
            MsRecordKind::EmptyCall
        ));
        assert!(matches!(
            classify_record_kind(&[0x11; 20], false, &[], &SAFE_ADDR),
            MsRecordKind::PlainEth
        ));
        // Opaque
        assert!(matches!(
            classify_record_kind(&[0x11; 20], true, &[0xd0, 0xe3, 0x0d, 0xb0], &SAFE_ADDR),
            MsRecordKind::Blind
        ));
    }

    #[test]
    fn value_page_rules() {
        let blind = MsRecordKind::Blind;
        assert!(record_needs_value_page(&blind, false));
        assert!(!record_needs_value_page(&blind, true));
        assert!(!record_needs_value_page(&MsRecordKind::PlainEth, false));
        assert!(!record_needs_value_page(&MsRecordKind::EmptyCall, true));
    }

    #[test]
    fn pages_total_cow_flow() {
        let cd = cow_flow_calldata();
        // approve: 1 divider + 4 content; presign (AddrOnly, body 1+8=9):
        // 1 divider + 9 content → 15.
        assert_eq!(records_pages_total(&cd, &SAFE_ADDR, 9), Some(15));
        // proof mode (body 1+6=7) → 13.
        assert_eq!(records_pages_total(&cd, &SAFE_ADDR, 7), Some(13));
    }

    #[test]
    fn pages_total_counts_value_pages() {
        // One blind record carrying ETH: divider + value page + 3 blind.
        let mut value = [0u8; 32];
        value[31] = 1;
        let packed = pack_record(0, &[0x11; 20], &value, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            records_pages_total(&encode_multisend(&packed), &SAFE_ADDR, 9),
            Some(5)
        );
    }

    /// WYSIWYS lockstep (audit 2026-06-18 — transferFrom `from` page). A
    /// transferFrom record debits a third-party `from`, so it renders one
    /// extra "From (debited)" page: divider(1) + header+From+recipient+
    /// amount+contract(5) = 6. This pins `record_content_pages` against the
    /// `safe_display` renderer (which is `#[cfg(not(test))]` and so has no
    /// host coverage of its own) — if the two ever drift, the multiSend
    /// page-budget gate would mis-size and silently drop or blank a page.
    #[test]
    fn pages_total_transfer_from_adds_from_page() {
        let xfer_from = encode_multisend(&pack_record(
            0,
            &[0x70; 20], // token (not the Safe → classifies as Erc20)
            &ZERO_VALUE,
            &transfer_from_calldata(&[0xaa; 20], &[0xbb; 20], 7),
        ));
        assert_eq!(records_pages_total(&xfer_from, &SAFE_ADDR, 9), Some(6));

        // A plain `approve` (no `from`) stays at divider(1) + 4 = 5.
        let approve = encode_multisend(&pack_record(
            0,
            &[0x70; 20],
            &ZERO_VALUE,
            &approve_calldata(&[0xbb; 20], 7),
        ));
        assert_eq!(records_pages_total(&approve, &SAFE_ADDR, 9), Some(5));
    }
}
