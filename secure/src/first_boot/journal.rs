//! First-boot provisioning journal — pure page-127 codec (host-testable).
//!
//! Work-todo #36: the first field boot self-locks RDP-2 and rotates the SE
//! pairing secrets off the factory transport keysets. The ceremony records
//! each completed step so ordinary power loss between completed quad-word
//! programs can resume safely. Recovery is bounded by the finite page: repeated
//! interruptions or a flash fault can exhaust it and force fail-closed RMA.
//! Completion is recorded **commit-LAST** in a durable log on flash page 127
//! (KEY_PAGE — owned outright by this journal).
//!
//! The codec is log-structured and append-only, mirroring the page-123
//! off-chain-counter idiom (`hw::flash` / `offchain_state`): 16-byte
//! quad-word records, the log ends at the first all-`0xFF` QW, and any QW
//! that doesn't parse as a framed record is **skipped, not treated as the
//! end** (a torn write leaves a non-blank-but-invalid QW mid-log). Because
//! we only ever *append* (never rewrite a QW in place), complete QWs preceding
//! a reset are orphaned and the next boot re-appends. Host tests model reset
//! boundaries between completed QW programs; silicon partial-program behavior
//! remains a production validation gate.
//!
//! Everything here is pure arithmetic over `&[u8]` + a `write_qw` closure,
//! with no hardware dependency, so it is unit-tested on the host. The
//! hardware glue (actually reading/writing page 127, ICACHE invalidation)
//! lives in `first_boot::mod` behind the `stm32u585` + `rdp2-self-lock`
//! gates.

// This module is only *consumed* under `rdp2-self-lock` (+ by the host
// tests); in a dev/QEMU build without the feature the encoders are unused.
#![allow(dead_code)]

use fw_manifest::crc32_ieee;

/// Bytes per flash quad-word (128-bit program granularity on STM32U5).
pub const QW: usize = 16;
/// Quad-words in the 8 KB page 127.
pub const PAGE_QWS: usize = 512;
/// Quad-words in one salt record: two data words followed by its commit header.
pub const SALT_RECORD_QWS: usize = 3;
/// Salt plus the OPTIGA-complete and whole-ceremony-complete step markers.
pub const SALT_COMPLETION_RESERVE_QWS: usize = SALT_RECORD_QWS + 2;

/// Record magic — "PF" (Pqsigner First-boot). Distinguishes a framed
/// journal record from raw salt bytes / erased flash.
const MAGIC: [u8; 2] = [0x50, 0x46];

/// Record type: a step-completion marker (self-contained).
const TYPE_STEP: u8 = 0x01;
/// Record type: the TRNG-salt commit header (validates the 2 preceding QWs).
const TYPE_SALT_HDR: u8 = 0x02;

// ---------------------------------------------------------------------------
// Step identifiers + the completion bitmask exposed in `JournalState`.
// ---------------------------------------------------------------------------

/// BHK first-write completed (page-126 wrapped BHK is final).
pub const STEP_BHK: u8 = 1;
/// SE050 SCP03 keyset rotated transport → final (BHK-rooted).
pub const STEP_SE050_KEYS: u8 = 2;
/// SE050 admin credential re-keyed transport → final.
pub const STEP_SE050_ADMIN: u8 = 3;
/// OPTIGA PBS rotated transport → final (DHUK + persisted salt).
pub const STEP_OPTIGA_PBS: u8 = 4;
/// Whole ceremony complete — normal boot may proceed to the seed wizard.
pub const STEP_ALL_DONE: u8 = 5;

/// Highest valid step id (bounds the bitmask + rejects garbage ids).
const STEP_MAX: u8 = STEP_ALL_DONE;

#[must_use]
const fn step_bit(step_id: u8) -> u32 {
    // step ids are 1-indexed; bit (id-1).
    1u32 << (step_id - 1)
}

/// Convenience masks for the `done` bitmask.
pub const DONE_BHK: u32 = step_bit(STEP_BHK);
pub const DONE_SE050_KEYS: u32 = step_bit(STEP_SE050_KEYS);
pub const DONE_SE050_ADMIN: u32 = step_bit(STEP_SE050_ADMIN);
pub const DONE_OPTIGA_PBS: u32 = step_bit(STEP_OPTIGA_PBS);
pub const DONE_ALL: u32 = step_bit(STEP_ALL_DONE);

/// Result of scanning the journal page.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct JournalState {
    /// Bitmask of completed steps (`DONE_*`).
    pub done: u32,
    /// The persisted TRNG salt, if a valid `SALT_HDR` record was found.
    pub salt: Option<[u8; 32]>,
    /// Index of the next appendable (all-`0xFF`) QW, or `PAGE_QWS` if full.
    pub next_free: usize,
}

impl JournalState {
    /// Is a given step recorded complete?
    #[must_use]
    pub fn has(&self, done_mask: u32) -> bool {
        self.done & done_mask == done_mask
    }

    /// Has the whole ceremony completed?
    #[must_use]
    pub fn all_done(&self) -> bool {
        self.has(DONE_ALL)
    }

    /// Is the page completely fresh (blank — never provisioned)?
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.next_free == 0 && self.done == 0 && self.salt.is_none()
    }

    /// Does the append frontier have room for `qws` complete records?
    #[must_use]
    pub fn can_append(&self, qws: usize) -> bool {
        self.next_free
            .checked_add(qws)
            .is_some_and(|end| end <= PAGE_QWS)
    }
}

// ---------------------------------------------------------------------------
// Encoders — produce the exact 16-byte QWs the hardware glue programs.
// ---------------------------------------------------------------------------

/// Encode a step-completion record. `crc32` covers the first 12 bytes so a
/// torn write (partial QW) fails validation and is skipped on the next scan.
#[must_use]
pub fn encode_step(step_id: u8) -> [u8; QW] {
    let mut rec = [0u8; QW];
    rec[0..2].copy_from_slice(&MAGIC);
    rec[2] = TYPE_STEP;
    rec[3] = step_id;
    // rec[4..12] reserved (zero).
    let crc = crc32_ieee(&rec[0..12]);
    rec[12..16].copy_from_slice(&crc.to_le_bytes());
    rec
}

/// Encode the 3 QWs of a salt record: `[salt_lo, salt_hi, header]`. The
/// caller MUST program them **in order** and treat the header (`[2]`) as the
/// commit point — it carries `crc32(salt)` so a crash before the header
/// leaves the two data QWs orphaned and the salt is regenerated next boot.
#[must_use]
pub fn encode_salt(salt: &[u8; 32]) -> [[u8; QW]; SALT_RECORD_QWS] {
    let mut lo = [0u8; QW];
    let mut hi = [0u8; QW];
    lo.copy_from_slice(&salt[0..16]);
    hi.copy_from_slice(&salt[16..32]);

    let mut hdr = [0u8; QW];
    hdr[0..2].copy_from_slice(&MAGIC);
    hdr[2] = TYPE_SALT_HDR;
    hdr[3] = 0;
    hdr[4..8].copy_from_slice(&crc32_ieee(salt).to_le_bytes());
    // hdr[8..12] reserved (zero).
    let self_crc = crc32_ieee(&hdr[0..12]);
    hdr[12..16].copy_from_slice(&self_crc.to_le_bytes());

    [lo, hi, hdr]
}

// ---------------------------------------------------------------------------
// Scanner.
// ---------------------------------------------------------------------------

#[must_use]
fn qw_is_blank(qw: &[u8]) -> bool {
    qw.iter().all(|&b| b == 0xFF)
}

/// Does `rec` self-validate as a framed record of `expected_type`?
/// (MAGIC + type match + `crc32(first 12) == last 4`.)
#[must_use]
fn framed_as(rec: &[u8], expected_type: u8) -> bool {
    if rec.len() < QW {
        return false;
    }
    if rec[0..2] != MAGIC || rec[2] != expected_type {
        return false;
    }
    let stored = u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]);
    crc32_ieee(&rec[0..12]) == stored
}

/// Scan the journal page. `page` must be at least `PAGE_QWS * QW` bytes
/// (the caller passes the 8 KB page-127 image); extra bytes are ignored and
/// a short slice scans only the QWs it contains.
///
/// Rules (page-123 idiom):
/// - The log ends at the first all-`0xFF` QW → that index is `next_free`.
/// - A QW that self-validates as a `STEP` record with an in-range id ORs
///   that step into `done`.
/// - A `SALT_HDR` record validates the salt from the two immediately
///   preceding QWs (`crc32(salt)` must match); the **latest** valid salt
///   wins.
/// - Any other non-blank QW (raw salt bytes, torn/partial writes) is
///   skipped — never treated as the end and never misread (a raw QW would
///   have to collide on MAGIC + type + a 32-bit CRC to be misframed, and
///   even then its secondary check — in-range step id or salt CRC — rejects
///   it).
#[must_use]
pub fn scan(page: &[u8]) -> JournalState {
    let qw_count = core::cmp::min(page.len() / QW, PAGE_QWS);
    let mut st = JournalState {
        done: 0,
        salt: None,
        next_free: qw_count, // default: full/none-blank → past the end
    };

    let mut i = 0usize;
    while i < qw_count {
        let rec = &page[i * QW..i * QW + QW];

        if qw_is_blank(rec) {
            st.next_free = i;
            break;
        }

        if framed_as(rec, TYPE_STEP) {
            let step_id = rec[3];
            if step_id >= 1 && step_id <= STEP_MAX {
                st.done |= step_bit(step_id);
            }
            // else: garbage id → skip (defensive; encoder never emits it).
        } else if framed_as(rec, TYPE_SALT_HDR) && i >= 2 {
            // Salt data is the two immediately-preceding QWs.
            let mut salt = [0u8; 32];
            salt[0..16].copy_from_slice(&page[(i - 2) * QW..(i - 1) * QW]);
            salt[16..32].copy_from_slice(&page[(i - 1) * QW..i * QW]);
            let want = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
            if crc32_ieee(&salt) == want {
                st.salt = Some(salt); // latest valid salt wins
            }
        }
        // else: raw / torn QW → skip and keep scanning.

        i += 1;
    }

    st
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an all-blank (erased) page image.
    fn blank_page() -> [u8; PAGE_QWS * QW] {
        [0xFF; PAGE_QWS * QW]
    }

    fn write_qw(page: &mut [u8], idx: usize, rec: &[u8; QW]) {
        page[idx * QW..idx * QW + QW].copy_from_slice(rec);
    }

    #[test]
    fn blank_page_is_blank() {
        let page = blank_page();
        let st = scan(&page);
        assert!(st.is_blank());
        assert_eq!(st.next_free, 0);
        assert_eq!(st.done, 0);
        assert_eq!(st.salt, None);
    }

    #[test]
    fn append_capacity_is_checked_and_overflow_safe() {
        let at = |next_free| JournalState {
            done: 0,
            salt: None,
            next_free,
        };
        assert!(at(PAGE_QWS - SALT_RECORD_QWS).can_append(SALT_RECORD_QWS));
        assert!(!at(PAGE_QWS - SALT_RECORD_QWS + 1).can_append(SALT_RECORD_QWS));
        assert!(!at(PAGE_QWS).can_append(1));
        assert!(!at(PAGE_QWS).can_append(usize::MAX));
    }

    #[test]
    fn steps_accumulate_and_report_all_done() {
        let mut page = blank_page();
        write_qw(&mut page, 0, &encode_step(STEP_BHK));
        write_qw(&mut page, 1, &encode_step(STEP_SE050_KEYS));
        write_qw(&mut page, 2, &encode_step(STEP_SE050_ADMIN));
        let st = scan(&page);
        assert!(st.has(DONE_BHK));
        assert!(st.has(DONE_SE050_KEYS));
        assert!(st.has(DONE_SE050_ADMIN));
        assert!(!st.has(DONE_OPTIGA_PBS));
        assert!(!st.all_done());
        assert_eq!(st.next_free, 3);

        write_qw(&mut page, 3, &encode_step(STEP_OPTIGA_PBS));
        write_qw(&mut page, 4, &encode_step(STEP_ALL_DONE));
        let st = scan(&page);
        assert!(st.all_done());
        assert_eq!(st.next_free, 5);
    }

    #[test]
    fn salt_roundtrips_via_header_lookback() {
        let mut page = blank_page();
        let salt = [0xABu8; 32];
        // Steps first, then salt (matches the real write order — salt is
        // generated in the OPTIGA step, after the SE050 steps).
        write_qw(&mut page, 0, &encode_step(STEP_BHK));
        let recs = encode_salt(&salt);
        write_qw(&mut page, 1, &recs[0]);
        write_qw(&mut page, 2, &recs[1]);
        write_qw(&mut page, 3, &recs[2]); // header = commit
        let st = scan(&page);
        assert_eq!(st.salt, Some(salt));
        assert!(st.has(DONE_BHK));
        assert_eq!(st.next_free, 4);
    }

    #[test]
    fn torn_salt_before_header_is_absent_and_regenerable() {
        let mut page = blank_page();
        let salt = [0x11u8; 32];
        let recs = encode_salt(&salt);
        // Data QWs written, header (commit) NOT written — power cut.
        write_qw(&mut page, 0, &recs[0]);
        write_qw(&mut page, 1, &recs[1]);
        let st = scan(&page);
        assert_eq!(st.salt, None, "no header → salt absent");
        // next_free points past the two orphan data QWs (they are non-blank).
        assert_eq!(st.next_free, 2);

        // Resume: regenerate a fresh salt appended after the orphans.
        let salt2 = [0x22u8; 32];
        let recs2 = encode_salt(&salt2);
        write_qw(&mut page, 2, &recs2[0]);
        write_qw(&mut page, 3, &recs2[1]);
        write_qw(&mut page, 4, &recs2[2]);
        let st = scan(&page);
        assert_eq!(st.salt, Some(salt2), "regenerated salt is found");
    }

    #[test]
    fn torn_partial_step_qw_is_skipped_not_end() {
        let mut page = blank_page();
        write_qw(&mut page, 0, &encode_step(STEP_BHK));
        // A garbage / partially-written QW mid-log (not blank, not framed).
        let mut junk = [0x00u8; QW];
        junk[0] = 0x50; // partial magic, but CRC won't validate
        write_qw(&mut page, 1, &junk);
        write_qw(&mut page, 2, &encode_step(STEP_SE050_KEYS));
        let st = scan(&page);
        assert!(st.has(DONE_BHK));
        assert!(st.has(DONE_SE050_KEYS), "scan continued past the junk QW");
        assert_eq!(st.next_free, 3);
    }

    #[test]
    fn corrupt_step_crc_is_ignored() {
        let mut page = blank_page();
        let mut rec = encode_step(STEP_BHK);
        rec[15] ^= 0xFF; // corrupt the CRC
        write_qw(&mut page, 0, &rec);
        let st = scan(&page);
        assert!(!st.has(DONE_BHK), "bad CRC → step not counted");
    }

    #[test]
    fn corrupt_salt_data_fails_header_crc() {
        let mut page = blank_page();
        let salt = [0x33u8; 32];
        let recs = encode_salt(&salt);
        write_qw(&mut page, 0, &recs[0]);
        let mut bad_hi = recs[1];
        bad_hi[0] ^= 0xFF; // corrupt one salt byte
        write_qw(&mut page, 1, &bad_hi);
        write_qw(&mut page, 2, &recs[2]); // header carries crc of the ORIGINAL salt
        let st = scan(&page);
        assert_eq!(st.salt, None, "salt data ≠ header CRC → rejected");
    }

    #[test]
    fn latest_salt_wins() {
        let mut page = blank_page();
        let s1 = [0x44u8; 32];
        let s2 = [0x55u8; 32];
        let r1 = encode_salt(&s1);
        let r2 = encode_salt(&s2);
        for (k, r) in r1.iter().enumerate() {
            write_qw(&mut page, k, r);
        }
        for (k, r) in r2.iter().enumerate() {
            write_qw(&mut page, 3 + k, r);
        }
        let st = scan(&page);
        assert_eq!(st.salt, Some(s2), "later salt record wins");
    }

    #[test]
    fn short_slice_scans_only_present_qws() {
        // A caller that passes fewer than 512 QWs must not panic.
        let mut page = [0xFFu8; 4 * QW];
        write_qw(&mut page, 0, &encode_step(STEP_BHK));
        let st = scan(&page);
        assert!(st.has(DONE_BHK));
        assert_eq!(st.next_free, 1);
    }

    #[test]
    fn out_of_range_step_id_ignored() {
        let mut page = blank_page();
        // Forge a well-framed record with an out-of-range step id.
        let mut rec = [0u8; QW];
        rec[0..2].copy_from_slice(&MAGIC);
        rec[2] = TYPE_STEP;
        rec[3] = 200;
        let crc = crc32_ieee(&rec[0..12]);
        rec[12..16].copy_from_slice(&crc.to_le_bytes());
        write_qw(&mut page, 0, &rec);
        let st = scan(&page);
        assert_eq!(st.done, 0, "unknown step id contributes nothing");
    }
}
