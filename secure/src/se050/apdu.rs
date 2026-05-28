//! SE050 APDU encoding and command wrappers.
//!
//! Implements the minimal set of SE05x commands needed for UserID-based
//! PIN authentication and binary object storage:
//!
//!   SELECT, CheckExists, WriteUserID, WriteBinaryGated,
//!   CreateSession, VerifySession, ReadAuthed, CloseSession.
//!
//! APDU format: ISO 7816-4 (CLA | INS | P1 | P2 | [Lc | Data] | [Le]).
//! SE05x payload fields are TLV-encoded.

use super::scp03::Scp03Session;
use super::t1oi2c::{T1Error, T1State};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// SE050 operation errors.
#[derive(Debug)]
pub enum Se050Error {
    /// T1oI2C framing, CRC, or timeout error.
    Transport,
    /// SCP03 handshake or cryptogram mismatch.
    Scp03,
    /// SE050 returned a non-0x9000 status word.
    Status(u16),
    /// PIN verification failed (SE050 decremented attempt counter).
    PinIncorrect,
    /// UserID authentication object is silicon-locked — the chip-side
    /// `auth_attempts == max_attempts` and the policy now denies any
    /// further use of the credential. Mapped from `SW_COMMAND_NOT_
    /// ALLOWED = 0x6986` per `plug-and-trust/hostlib/hostLib/inc/
    /// se05x_enums.h:84` (`kSE05x_SW12_COMMAND_NOT_ALLOWED`, "Command
    /// not allowed — access denied based on object policy"), AN12413
    /// §4.3.1 Table 15.
    ///
    /// **Where the lock surfaces (silicon, 2026-05-28).** On
    /// B-U585I-IOT02A the lockout is enforced at `create_session`
    /// (SW=0x6986) — the chip refuses to even open a session against a
    /// locked UserID, BEFORE any VERIFY runs. `create_session` and
    /// `verify_session` both translate 0x6986 to this variant so either
    /// manifestation maps cleanly. Cleanly observed in the 2026-05-28
    /// destructive run (tests 14 `pin_counter_persists_across_reinit`
    /// + 17 `userid_silicon_lockout`) once the driver `reinit()`s after
    /// every failed verify — see the corrected analysis in
    /// `docs/se050-silicon-findings.md` §4a.
    ///
    /// **NOT 0x6982.** An earlier draft mapped SW=0x6982 here too,
    /// believing it was the lockout code. It is not — 0x6982 is the
    /// Finding-A3 session-pending TRANSIENT (any non-session APDU
    /// after a failed verify/close cycle returns it until `reinit()`),
    /// which is RECOVERABLE and must never trigger a wipe. Mapping it
    /// to `AuthMethodBlocked → PinLocked → trigger_lockout_wipe` would
    /// be a false-positive device wipe. 0x6982 therefore stays a raw
    /// `Status(0x6982)` → `InternalError` (transient, no wipe).
    ///
    /// Distinct from `PinIncorrect` because the chip won't accept any
    /// more attempts — the only recovery is `factory_reset_admin` + a
    /// fresh `UserID` re-provision (which after S-6 requires bumping
    /// the OID range; see USERID_OBJ comment in mod.rs).
    AuthMethodBlocked,
    /// Device not provisioned (UserID object missing).
    NotProvisioned,
    /// Response data exceeds caller buffer.
    BufferOverflow,
    /// Caller supplied an out-of-range argument (e.g. `GetRandom`
    /// length outside the SE050's accepted [1, 256] range).
    InvalidParam,
}

impl From<T1Error> for Se050Error {
    fn from(_: T1Error) -> Self {
        Se050Error::Transport
    }
}

// ---------------------------------------------------------------------------
// SE050 constants
// ---------------------------------------------------------------------------

/// SE050 applet AID (from NXP documentation).
const SE050_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
];

// Instruction codes
const INS_WRITE: u8 = 0x01;
const INS_READ: u8 = 0x02;
const INS_MGMT: u8 = 0x04;
const INS_PROCESS: u8 = 0x05;
/// OR'd into INS_WRITE for authentication object creation (UserID, keys).
const INS_AUTH_OBJECT: u8 = 0x40;

// P1 values
const P1_DEFAULT: u8 = 0x00;
const P1_BINARY: u8 = 0x06;
const P1_USERID: u8 = 0x07;

// P2 values
const P2_DEFAULT: u8 = 0x00;
const P2_CREATE_SESSION: u8 = 0x1B;
const P2_EXIST: u8 = 0x27;
const P2_VERIFY_SESSION_USERID: u8 = 0x2C;
/// NXP AN12413 §5.13.1 — `Se05x_API_GetRandom`. Header is
/// `(CLA=0x80, INS=INS_MGMT, P1=P1_DEFAULT, P2=P2_RANDOM)`; body is
/// `TLV(TAG_1, length:u16)`; response is `TLV(TAG_1, random_bytes)`.
const P2_RANDOM: u8 = 0x49;

// TLV tags
const TAG_SESSION_ID: u8 = 0x10;
const TAG_POLICY: u8 = 0x11;
const TAG_MAX_ATTEMPTS: u8 = 0x12;
const TAG_1: u8 = 0x41;
const TAG_2: u8 = 0x42;
const TAG_3: u8 = 0x43;
const TAG_4: u8 = 0x44;

const SW_OK: u16 = 0x9000;

// ---------------------------------------------------------------------------
// TLV encoding helpers — re-exported from the always-on `iso7816`
// module so a single source of truth (and a single proptest harness)
// covers both the production path here and any future SE driver.
// ---------------------------------------------------------------------------
use crate::iso7816::{tlv_parse, tlv_put, tlv_put_u32};

// ---------------------------------------------------------------------------
// APDU buffer builder
// ---------------------------------------------------------------------------

/// Maximum APDU buffer size.
const MAX_APDU: usize = 1024;

/// Builds an ISO 7816-4 APDU incrementally.
///
/// Usage: `ApduBuf::new(cla, ins, p1, p2)`, then `.tlv(...)` calls to
/// append payload TLVs, then `.finish()` to encode Lc and return the
/// complete APDU bytes.
struct ApduBuf {
    buf: [u8; MAX_APDU],
    /// Write cursor — starts at 7 to reserve space for the header and
    /// a 3-byte extended Lc. `finish()` fixes up the actual Lc encoding.
    cursor: usize,
}

impl ApduBuf {
    /// Start a new APDU with the given header bytes.
    fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        let mut buf = [0u8; MAX_APDU];
        buf[0] = cla;
        buf[1] = ins;
        buf[2] = p1;
        buf[3] = p2;
        // Cursor starts at offset 7 (past header + 3-byte extended Lc slot).
        // finish() will compact to short Lc if the payload is small.
        Self { buf, cursor: 7 }
    }

    /// Append a TLV to the payload.
    fn tlv(&mut self, tag: u8, value: &[u8]) -> &mut Self {
        self.cursor = tlv_put(&mut self.buf, self.cursor, tag, value);
        self
    }

    /// Append a TLV with a 4-byte big-endian value.
    fn tlv_u32(&mut self, tag: u8, val: u32) -> &mut Self {
        self.cursor = tlv_put_u32(&mut self.buf, self.cursor, tag, val);
        self
    }

    /// Finalize the APDU: encode Lc and return the complete byte slice.
    /// If `with_le` is true, appends Le=0x00 for commands expecting response data.
    fn finish(&mut self, with_le: bool) -> &[u8] {
        let payload_len = self.cursor - 7;

        if payload_len == 0 && !with_le {
            // Case 1: no payload, no Le — just the 4-byte header
            return &self.buf[..4];
        }

        if payload_len == 0 && with_le {
            // Case 2: no payload, Le only
            self.buf[4] = 0x00;
            return &self.buf[..5];
        }

        // Payload present: encode Lc
        let start;
        if payload_len < 256 {
            // Short Lc: shift payload from offset 7 to offset 5
            self.buf[4] = payload_len as u8;
            // Copy payload left by 2 bytes
            for i in 0..payload_len {
                self.buf[5 + i] = self.buf[7 + i];
            }
            start = 0;
            let mut end = 5 + payload_len;
            if with_le {
                self.buf[end] = 0x00;
                end += 1;
            }
            return &self.buf[start..end];
        }

        // Extended Lc: 0x00 || hi || lo
        self.buf[4] = 0x00;
        self.buf[5] = (payload_len >> 8) as u8;
        self.buf[6] = (payload_len & 0xFF) as u8;
        // Payload is already at offset 7
        let mut end = 7 + payload_len;
        if with_le {
            self.buf[end] = 0x00;
            end += 1;
        }
        &self.buf[..end]
    }
}

// ---------------------------------------------------------------------------
// APDU transceive
// ---------------------------------------------------------------------------

/// Send an APDU and return the response data (without SW).
///
/// If an SCP03 session is active, the APDU is MAC'd and encrypted before
/// sending (`scp03::wrap_apdu`), the wire response is MAC-verified and
/// decrypted (`scp03::unwrap_response`), and the SW is parsed from the
/// resulting plaintext. The Le byte is stripped before MAC computation
/// and re-appended afterward (ISO 7816-4 Case 4).
///
/// S-5 fix: previously the response was read straight off the wire (SW
/// + TLV from the ciphertext / un-MAC'd body), which silently broke if
/// the SE happened to respond in cleartext (level 0x03 — what the
/// driver used to negotiate). At level 0x33 every response is wrapped
/// and the `unwrap_response` call below is mandatory.
pub unsafe fn send_apdu(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    apdu: &[u8],
    resp_buf: &mut [u8],
) -> Result<usize, Se050Error> {
    let (tx_buf, tx_len) = if scp03.active {
        // Detect Lc and Le for proper SCP03 wrapping
        let (hdr_len, lc_val) = if apdu.len() >= 7 && apdu[4] == 0x00 {
            (7usize, ((apdu[5] as usize) << 8) | (apdu[6] as usize))
        } else if apdu.len() >= 5 {
            (5usize, apdu[4] as usize)
        } else {
            (apdu.len(), 0)
        };

        let has_le = apdu.len() > hdr_len + lc_val;
        let apdu_no_le = if has_le { &apdu[..apdu.len() - 1] } else { apdu };

        let mut wrapped = [0u8; MAX_APDU];
        let mut wlen = super::scp03::wrap_apdu(scp03, apdu_no_le, &mut wrapped);

        // S-7c fix — extended-Lc commands take a 2-byte Le per ISO 7816-4
        // (and per NXP plug-and-trust `se05x_tlv.c:1055-1059`). At SCP03
        // level 0x33 wrap_apdu always produces extended-Lc output because
        // it appends an 8-byte C-MAC, pushing the body well past the
        // 255-byte short-Lc cap on every command with a payload.
        if has_le {
            let wrapped_extended =
                wlen >= 7 && wrapped[4] == 0x00;
            if wrapped_extended {
                wrapped[wlen] = 0x00;
                wrapped[wlen + 1] = 0x00;
                wlen += 2;
            } else {
                wrapped[wlen] = 0x00;
                wlen += 1;
            }
        }
        (wrapped, wlen)
    } else {
        let mut buf = [0u8; MAX_APDU];
        buf[..apdu.len()].copy_from_slice(apdu);
        (buf, apdu.len())
    };

    #[cfg(feature = "debug-log")]
    {
        if tx_len >= 5 {
            // Log the raw (post-SCP03) APDU header + first few bytes
            secure_log!(
                "[SE050] TX CLA={:02x} INS={:02x} P1={:02x} P2={:02x} Lc={:02x} len={}",
                tx_buf[0], tx_buf[1], tx_buf[2], tx_buf[3], tx_buf[4], tx_len
            );
        }
    }

    let mut raw_resp = [0u8; MAX_APDU];
    let n = t1.transceive(&tx_buf[..tx_len], &mut raw_resp)
        .map_err(|_| Se050Error::Transport)?;

    if n < 2 {
        return Err(Se050Error::Transport);
    }

    // S-5 fix — unwrap (R-MAC verify + R-ENC decrypt) when SCP03 is up.
    // The unwrapped buffer is `plaintext_body || SW1 SW2`; reading SW
    // off `raw_resp[n-2..]` (the old code) would have used SW from the
    // ciphertext at level 0x33, which is identically the on-wire SW
    // because GP Amd D leaves SW outside the R-ENC envelope — but the
    // body bytes are encrypted, so the old code's TLV parse upstream
    // was reading ciphertext as if it were plaintext.  At level 0x03
    // (pre-S-5) the body was cleartext but unauthenticated.  Either
    // way, unwrap_response is now the only correct path.
    let mut unwrapped = [0u8; MAX_APDU];
    let (resp_slice, resp_len) = if scp03.active {
        let m = super::scp03::unwrap_response(scp03, &raw_resp[..n], &mut unwrapped)?;
        (&unwrapped[..m], m)
    } else {
        (&raw_resp[..n], n)
    };

    let sw = ((resp_slice[resp_len - 2] as u16) << 8) | (resp_slice[resp_len - 1] as u16);

    #[cfg(feature = "debug-log")]
    secure_log!("[SE050] RX SW=0x{:04x} len={}", sw, resp_len);

    if sw != SW_OK {
        return Err(Se050Error::Status(sw));
    }

    let data_len = resp_len - 2;
    if data_len > resp_buf.len() {
        return Err(Se050Error::BufferOverflow);
    }
    resp_buf[..data_len].copy_from_slice(&resp_slice[..data_len]);
    Ok(data_len)
}

// ---------------------------------------------------------------------------
// SE050 commands
// ---------------------------------------------------------------------------

/// GP SELECT — activate the SE050 applet.
///
/// Sent WITHOUT SCP03 wrapping (the session isn't established yet).
/// Uses raw data (not TLV) per ISO 7816-4 SELECT BY NAME.
pub unsafe fn select_applet(t1: &mut T1State) -> Result<(), Se050Error> {
    let mut apdu = [0u8; 64];
    apdu[0] = 0x00; // CLA
    apdu[1] = 0xA4; // INS = SELECT
    apdu[2] = 0x04; // P1 = select by name
    apdu[3] = 0x00; // P2
    apdu[4] = SE050_AID.len() as u8; // Lc
    apdu[5..5 + SE050_AID.len()].copy_from_slice(SE050_AID);
    let total = 5 + SE050_AID.len();

    let mut resp = [0u8; 256];
    let n = t1.transceive(&apdu[..total], &mut resp).map_err(|_| Se050Error::Transport)?;
    if n < 2 {
        return Err(Se050Error::Transport);
    }
    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    if sw != SW_OK {
        return Err(Se050Error::Status(sw));
    }
    Ok(())
}

/// Check if an object exists on the SE050.
pub unsafe fn check_exists(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
) -> Result<bool, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_EXIST);
    let cmd = apdu.tlv_u32(TAG_1, obj_id).finish(true);

    let mut resp = [0u8; 64];
    match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(n) => {
            #[cfg(feature = "debug-log")]
            {
                if n >= 3 {
                    secure_log!(
                        "[SE050] check_exists resp: {:02x} {:02x} {:02x} (n={})",
                        resp[0], resp[1], resp[2], n
                    );
                }
            }
            if let Some((_, val, _)) = tlv_parse(&resp[..n]) {
                Ok(!val.is_empty() && val[0] == 0x01)
            } else {
                Ok(false) // can't parse → assume not found
            }
        }
        Err(Se050Error::Status(0x6985)) => Ok(false),
        Err(e) => Err(e),
    }
}

// Policy ar_header bit values (per se05x_const.h, POLICY_OBJ_ALLOW_*).
const AR_ALLOW_READ: u32 = 0x0020_0000;
const AR_ALLOW_WRITE: u32 = 0x0010_0000;
const AR_ALLOW_DELETE: u32 = 0x0004_0000;
const AR_REQUIRE_SM: u32 = 0x0002_0000;

/// Build a TAG_POLICY value with one or two entries.
///
/// Layout per entry (9 bytes):
///   `[entry_len=0x08] [auth_obj_id:4 BE] [ar_header:4 BE]`
///
/// SE05x policy semantics: entries are OR'd — if ANY entry's auth_obj_id
/// is satisfied by the current session AND that entry's ar_header allows
/// the requested operation, the operation succeeds. This lets us grant
/// "normal use under UserID" + "admin delete under a secondary auth
/// object" on the same secure object.
fn build_policy(
    primary_auth: u32,
    primary_ar: u32,
    admin_auth: Option<u32>,
) -> ([u8; 18], usize) {
    let mut out = [0u8; 18];
    let mut len = 0;

    let a = primary_auth.to_be_bytes();
    let ar = primary_ar.to_be_bytes();
    out[0] = 0x08;
    out[1..5].copy_from_slice(&a);
    out[5..9].copy_from_slice(&ar);
    len += 9;

    if let Some(admin) = admin_auth {
        let a2 = admin.to_be_bytes();
        // Admin entry: ALLOW_DELETE only (never ALLOW_READ) + REQUIRE_SM.
        let ar2 = (AR_ALLOW_DELETE | AR_REQUIRE_SM).to_be_bytes();
        out[9] = 0x08;
        out[10..14].copy_from_slice(&a2);
        out[14..18].copy_from_slice(&ar2);
        len += 9;
    }

    (out, len)
}

/// Create a UserID authentication object with a PIN and a policy allowing
/// self-delete plus optional admin-delete.
///
/// The SE050 verifies PINs internally and enforces an attempt counter.
/// After `max_attempts` failures the UserID locks permanently.
///
/// `max_attempts` must be in `1..=255`. Per AN12413 §4.7.1.5 Table 98 the
/// SE050 treats `max_attempts = 0` as "UNLIMITED" — a silent footgun
/// (caller may intend "lock immediately") that this function rejects with
/// `Se050Error::InvalidParam`.  Callers that genuinely want unlimited
/// attempts (admin / duress UserIDs whose lockout is enforced on the MCU
/// side) MUST use [`write_userid_unlimited`] explicitly.  The same table
/// also caps PINs at 255 attempts; values >= 256 are rejected.  (S-7a
/// fix — docs/security-review-2026-05.md §C-9.)
///
/// Policy entries:
///   1. `auth_obj_id = <self>`, `ar = ALLOW_WRITE | ALLOW_DELETE | REQUIRE_SM`
///      (session verified against this PIN can rotate PIN and self-delete)
///   2. If `admin_auth_obj_id` is provided:
///      `auth_obj_id = <admin>`, `ar = ALLOW_DELETE | REQUIRE_SM`
///      (a session authenticated against the admin UserID can delete THIS
///       UserID without knowing its PIN). **S-6 caveat:** passing
///       `Some(admin)` for a *user* UserID opens the substitution attack
///       (admin deletes UserID, recreates with attacker PIN, satisfies
///       any data object's `[UserID → ALLOW_READ]` policy).  Production
///       code passes `None` for the user UserID and `Some(admin)` only
///       for data objects via `write_binary_gated`.
///
/// HW lesson #1: INS must be 0x41 (WRITE | AUTH_OBJECT), not 0x01.
pub unsafe fn write_userid(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    pin: &[u8],
    max_attempts: u16,
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    // S-7a — reject the silent-unlimited footgun + the PIN-objects cap.
    if max_attempts == 0 || max_attempts >= 256 {
        return Err(Se050Error::InvalidParam);
    }

    let mut apdu = ApduBuf::new(0x80, INS_WRITE | INS_AUTH_OBJECT, P1_USERID, P2_DEFAULT);

    let primary_ar = AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM;
    let (policy_buf, policy_len) = build_policy(obj_id, primary_ar, admin_auth_obj_id);
    apdu.tlv(TAG_POLICY, &policy_buf[..policy_len]);

    apdu.tlv(TAG_MAX_ATTEMPTS, &max_attempts.to_be_bytes());
    apdu.tlv_u32(TAG_1, obj_id);
    apdu.tlv(TAG_2, pin);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Create a UserID authentication object with UNLIMITED PIN attempts —
/// `TAG_MAX_ATTEMPTS` is omitted from the APDU, which AN12413 §4.7.1.5
/// Table 98 specifies as the "unlimited" encoding.
///
/// Use this ONLY where the lockout is enforced by some external
/// mechanism that compensates for the SE not bounding the attempt
/// count.  In this firmware that's:
///
/// - **`ADMIN_WIPE_OBJ`** — PIN is 16 bytes of hardware-root-derived
///   entropy (`hw::secret_keys::se050_admin_pin()`), brute force
///   infeasible at any timing budget; SE-side lockout would only ever
///   accidentally trigger on a hardware fault.
/// - **`DURESS_USERID_OBJ`** — the MCU page-124 attempt counter gates
///   lockout; an SE-side limit here would let a wrong duress PIN burn
///   real-PIN attempts on the same chip.
/// - **E2E test admin UserIDs (`TEST_ADMIN`)** — under
///   `e2e-test`/`se050-reset-e2e` feature gates; intentional.
///
/// This is the S-7a-compliant explicit form.  Most callers should use
/// [`write_userid`] which enforces `max_attempts ∈ 1..=255`.
pub unsafe fn write_userid_unlimited(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    pin: &[u8],
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_WRITE | INS_AUTH_OBJECT, P1_USERID, P2_DEFAULT);

    let primary_ar = AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM;
    let (policy_buf, policy_len) = build_policy(obj_id, primary_ar, admin_auth_obj_id);
    apdu.tlv(TAG_POLICY, &policy_buf[..policy_len]);

    // TAG_MAX_ATTEMPTS omitted → SE050 treats as "unlimited" per
    // AN12413 §4.7.1.5 (mirrors NXP plug-and-trust
    // `se05x_tlv.c:351-358 tlvSet_MaxAttemps`, which also omits the
    // TLV when its argument is 0).
    apdu.tlv_u32(TAG_1, obj_id);
    apdu.tlv(TAG_2, pin);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Write a binary object gated by UserID authentication, with optional
/// admin-delete entry.
///
/// Policy entries:
///   1. `auth_obj_id = <user>`, `ar = READ | WRITE | DELETE | REQUIRE_SM`
///   2. If `admin_auth_obj_id` is provided:
///      `auth_obj_id = <admin>`, `ar = DELETE | REQUIRE_SM`
///      (admin can wipe but not read — preserves hardware-enforced PIN gating
///       on entropy while giving the PIN-lockout path a way to clean up)
///
/// HW lesson #2: In each policy entry, auth_obj_id(4) comes BEFORE ar_header(4).
pub unsafe fn write_binary_gated(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    data: &[u8],
    auth_obj_id: u32,
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_WRITE, P1_BINARY, P2_DEFAULT);

    let primary_ar = AR_ALLOW_READ | AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM;
    let (policy_buf, policy_len) = build_policy(auth_obj_id, primary_ar, admin_auth_obj_id);
    apdu.tlv(TAG_POLICY, &policy_buf[..policy_len]);
    apdu.tlv_u32(TAG_1, obj_id);

    // TAG_3: file length (max allocation size)
    let file_len = data.len() as u16;
    apdu.tlv(TAG_3, &file_len.to_be_bytes());

    apdu.tlv(TAG_4, data);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Create a session authenticated against a UserID object.
///
/// Returns an 8-byte session ID (HW lesson #3).
///
/// **Silicon lockout path (2026-05-28).** When a UserID has exhausted
/// its `auth_attempts` budget, B-U585I-IOT02A refuses session creation
/// itself — `CreateSession` returns SW=0x6986 BEFORE any VERIFY can
/// run. Both `userid_silicon_lockout` and `pin_counter_persists_across_
/// reinit` stress tests show this cleanly once the A3 session-pending
/// artifact is cleared by an intervening `reinit()` (raw evidence in
/// the 2026-05-28 destructive run, tests 14 + 17). The prior assumption
/// — that lockout surfaces at `verify_session` with SW=0x6982 — was an
/// artifact of the chip being session-pending (Finding A3): with the
/// driver now `reinit()`ing after each failed verify, the TRUE lockout
/// code (0x6986 at session creation) is exposed. We translate it to
/// `Se050Error::AuthMethodBlocked` here so the unlock dispatch
/// (`classify_se050_unlock_error`) maps it to `UnlockError::PinLocked`
/// → `trigger_lockout_wipe`, exactly as the §25 Gap 4 contract
/// intends. Without this arm a locked UserID would mis-classify as
/// `InternalError` (no wipe).
pub unsafe fn create_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    auth_obj_id: u32,
) -> Result<[u8; 8], Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_CREATE_SESSION);
    let cmd = apdu.tlv_u32(TAG_1, auth_obj_id).finish(true);

    let mut resp = [0u8; 64];
    let n = match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(n) => n,
        // Locked-UserID path: 0x6986 (policy denial) on CreateSession.
        // See the doc above + `verify_session`'s matching arm.
        Err(Se050Error::Status(0x6986)) => return Err(Se050Error::AuthMethodBlocked),
        Err(e) => return Err(e),
    };

    let mut session_id = [0u8; 8];
    if let Some((_, value, _)) = tlv_parse(&resp[..n]) {
        if value.len() >= 8 {
            session_id.copy_from_slice(&value[..8]);
            return Ok(session_id);
        }
    }
    if n >= 8 {
        session_id.copy_from_slice(&resp[..8]);
        Ok(session_id)
    } else {
        Err(Se050Error::Transport)
    }
}

/// Verify a PIN against a UserID via an authenticated session.
///
/// The SE050 performs the PIN comparison internally. On failure it
/// decrements its hardware attempt counter.
///
/// All session commands use INS_PROCESS (0x05) wrapping:
///   outer: TAG_SESSION_ID(8) + TAG_1(inner_command)
pub unsafe fn verify_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    pin: &[u8],
) -> Result<(), Se050Error> {
    // Build inner command: MGMT / VerifySessionUserID / TAG_1(PIN)
    let mut inner = [0u8; 64];
    inner[0] = 0x80;
    inner[1] = INS_MGMT;
    inner[2] = P1_DEFAULT;
    inner[3] = P2_VERIFY_SESSION_USERID;
    let mut io = 5;
    io = tlv_put(&mut inner, io, TAG_1, pin);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;

    // Build outer PROCESS APDU
    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner[..io]);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(_) => Ok(()),
        // Wrong-PIN path: 0x6985 (`SM_ERR_CONDITIONS_NOT_SATISFIED`)
        // or 0x63Cx (counter remaining nibble; documented as
        // "Authentication failed, attempts left = x" in NXP's
        // A71CL HAL header which SE050 inherits via ISO 7816-4).
        Err(Se050Error::Status(sw)) if sw == 0x6985 || (sw & 0xFF00) == 0x6300 => {
            Err(Se050Error::PinIncorrect)
        }
        // UserID silicon-lock path: §25 Gap 4. AN12413 §4.3.1 Table 15
        // lists 0x6986 (`SM_ERR_COMMAND_NOT_ALLOWED`, "Command not
        // allowed — access denied based on object policy") as the
        // policy-denial code. On B-U585I-IOT02A the lockout actually
        // surfaces one step earlier — at `create_session` (SW=0x6986,
        // mapped there too) — but we keep this arm because a chip that
        // admits the session and rejects the VERIFY would land here.
        //
        // NOTE: SW=0x6982 is deliberately NOT mapped to
        // `AuthMethodBlocked`. The 2026-05-28 silicon run initially
        // suggested 0x6982 was the lockout code, but that was the
        // Finding-A3 session-pending TRANSIENT (recoverable via
        // `reinit()`), not a permanent lock — see
        // `docs/se050-silicon-findings.md` §4. Mapping a recoverable
        // transient to `AuthMethodBlocked` → `PinLocked` →
        // `trigger_lockout_wipe` would risk a false-positive wipe, so
        // 0x6982 propagates as `Status(0x6982)` (→ `InternalError`,
        // treated as transient, no wipe).
        Err(Se050Error::Status(sw)) if sw == 0x6986 => {
            Err(Se050Error::AuthMethodBlocked)
        }
        Err(e) => Err(e),
    }
}

/// Read a UserID-gated binary object through an authenticated session.
///
/// HW lesson #5: Do NOT include TAG_2 (offset) or TAG_3 (length) inside
/// an INS_PROCESS wrapper — they cause SW=0x6985. Use only TAG_1 (object ID).
pub unsafe fn read_authed(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    obj_id: u32,
    buf: &mut [u8],
) -> Result<usize, Se050Error> {
    // Inner read command: READ / TAG_1(object_id) / Le=0x00
    let mut inner = [0u8; 32];
    inner[0] = 0x80;
    inner[1] = INS_READ;
    inner[2] = P1_DEFAULT;
    inner[3] = P2_DEFAULT;
    let mut io = 5;
    io = tlv_put_u32(&mut inner, io, TAG_1, obj_id);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;
    inner[io] = 0x00; // Le inside inner command
    io += 1;

    // Outer PROCESS APDU
    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner[..io]);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; MAX_APDU];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;

    // Response contains TLV-wrapped data
    if let Some((_, value, _)) = tlv_parse(&resp[..n]) {
        if value.len() > buf.len() {
            return Err(Se050Error::BufferOverflow);
        }
        buf[..value.len()].copy_from_slice(value);
        Ok(value.len())
    } else if n > 0 && n <= buf.len() {
        buf[..n].copy_from_slice(&resp[..n]);
        Ok(n)
    } else {
        Ok(0)
    }
}

/// Delete a single secure object from the SE050.
///
/// Returns `Ok` if the object doesn't exist (SW=0x6985 — empirically the
/// chip's "no such OID" response; not formally documented in AN12413
/// Table 125 page 71, which only enumerates `SW_NO_ERROR`, but
/// consistent across observed traffic and what NXP's own
/// `iterative_delete_all` accepts).
///
/// **S-7b fix:** SW=0x6986 (`kSE05x_SW12_COMMAND_NOT_ALLOWED` per NXP
/// plug-and-trust `se05x_enums.h:84`) means "access denied based on
/// object policy" — the object exists but the current session lacks
/// `ALLOW_DELETE` for it.  Pre-S-7b this was silently mapped to `Ok`,
/// masking real policy-denial bugs (e.g. an unauthenticated sweep
/// silently "succeeding" on objects that still exist on chip).  Now
/// it propagates as `Se050Error::Status(0x6986)`, so the caller (
/// `iterative_delete_all`, `admin_factory_reset`, etc.) sees the
/// distinction between "already gone" and "needs different auth".
pub unsafe fn delete_object(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, 0x28); // P2=DELETE_OBJECT
    let cmd = apdu.tlv_u32(TAG_1, obj_id).finish(false);

    let mut resp = [0u8; 64];
    match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(_) => Ok(()),
        Err(Se050Error::Status(0x6985)) => Ok(()), // doesn't exist — idempotent
        // S-7b: 0x6986 is policy-denied → caller distinguishes "missing"
        // from "wrong auth".  Falls through to the generic Err arm.
        Err(e) => Err(e),
    }
}

/// Delete a UserID-gated secure object through an authenticated session.
///
/// Wraps the `DELETE_OBJECT` APDU inside an INS_PROCESS envelope with
/// `TAG_SESSION_ID` at the outer level (matching `read_authed` /
/// `verify_session`). Earlier ad-hoc implementations that sent
/// `INS=0x04 P2=0x28` with a top-level TAG_SESSION_ID were silently
/// ignoring the session and applying plain-SCP03 privileges → 0x6985/6986.
pub unsafe fn delete_object_authed(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    obj_id: u32,
) -> Result<(), Se050Error> {
    // Inner delete command: MGMT / DELETE_OBJECT / TAG_1(obj_id)
    let mut inner = [0u8; 32];
    inner[0] = 0x80;
    inner[1] = INS_MGMT;
    inner[2] = P1_DEFAULT;
    inner[3] = 0x28; // P2 = DELETE_OBJECT
    let mut io = 5;
    io = tlv_put_u32(&mut inner, io, TAG_1, obj_id);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;

    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner[..io]);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp).map(|_| ())
}

/// P2 for ReadIDList (kSE05x_P2_LIST).
const P2_LIST: u8 = 0x25;

/// P2 for ReadObjectAttributes (kSE05x_P2_ATTRIBUTES) — diagnostic.
const P2_ATTRIBUTES: u8 = 0x3B;

/// Read the on-chip policy attributes of a secure object. Useful for
/// debugging "why is delete refused?" questions — the response contains
/// the TAG_POLICY the object was created with.
pub unsafe fn read_object_attributes(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    buf: &mut [u8],
) -> Result<usize, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_ATTRIBUTES);
    apdu.tlv_u32(TAG_1, obj_id);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; 256];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;
    if let Some((_, val, _)) = tlv_parse(&resp[..n]) {
        let take = val.len().min(buf.len());
        buf[..take].copy_from_slice(&val[..take]);
        return Ok(take);
    }
    let take = n.min(buf.len());
    buf[..take].copy_from_slice(&resp[..take]);
    Ok(take)
}

/// Iteratively delete every user-created object on the SE050, mirroring
/// the NXP SDK's `Se05x_API_DeleteAll_Iterative`.
///
/// Two-pass: first tries plain SCP03 delete (handles default-policy
/// objects), then if `auth_obj_id`/`pin` are provided, creates a UserID
/// session and retries through `delete_object_authed`. Self-deletes
/// the UserID object at the end.
///
/// Skips reserved ranges (0x7FFFxxxx applet-reserved, 0x7DA0xxxx demo
/// auth, 0xF000_0000+ IoT Hub trust-provisioned).
///
/// Returns `(deleted, remaining_failed, auth_ok)`. `auth_ok` is true when
/// the unauthenticated pass cleaned everything OR the PIN authenticated
/// against the UserID; false when auth was attempted (or required) and
/// did not succeed. Lets the caller distinguish "wrong PIN" from
/// "objects survived authenticated delete (policy-blocked)".
pub unsafe fn iterative_delete_all(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    auth_obj_id: Option<u32>,
    pin: Option<&[u8]>,
) -> Result<(u16, u16, bool), Se050Error> {
    #[cfg(feature = "debug-log")]
    secure_log!("[SE050][erase] Pass 1: unauthenticated");

    let (mut deleted, mut failed) = sweep(t1, scp03, None)?;

    #[cfg(feature = "debug-log")]
    secure_log!(
        "[SE050][erase] Pass 1 done: {} deleted, {} left", deleted, failed
    );

    if failed == 0 {
        return Ok((deleted, 0, true));
    }

    let (uid, pin_bytes) = match (auth_obj_id, pin) {
        (Some(u), Some(p)) => (u, p),
        _ => return Ok((deleted, failed, false)),
    };

    if !check_exists(t1, scp03, uid).unwrap_or(false) {
        return Ok((deleted, failed, false));
    }

    let session_id = match create_session(t1, scp03, uid) {
        Ok(s) => s,
        Err(_) => return Ok((deleted, failed, false)),
    };

    if verify_session(t1, scp03, &session_id, pin_bytes).is_err() {
        let _ = close_session(t1, scp03, &session_id);
        return Ok((deleted, failed, false));
    }

    #[cfg(feature = "debug-log")]
    secure_log!(
        "[SE050][erase] Pass 2: authenticated (UserID=0x{:08x})", uid
    );

    let (auth_del, auth_fail) = sweep(t1, scp03, Some(&session_id))?;
    deleted += auth_del;
    failed = auth_fail;

    // Self-delete the UserID. Requires the UserID to have been created
    // with the self-deletable policy (see `write_userid`). Older UserIDs
    // without the policy stay put.
    if delete_object_authed(t1, scp03, &session_id, uid).is_ok()
        && !check_exists(t1, scp03, uid).unwrap_or(true)
    {
        deleted += 1;
    }

    let _ = close_session(t1, scp03, &session_id);
    Ok((deleted, failed, true))
}

unsafe fn sweep(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: Option<&[u8; 8]>,
) -> Result<(u16, u16), Se050Error> {
    let mut total_deleted = 0u16;
    let mut last_failed = 0u16;

    for _ in 0..10 {
        let mut cycle_deleted = 0u16;
        let mut cycle_failed = 0u16;
        let mut output_offset: u16 = 0;

        loop {
            let (more, list_byte_len, d, f) =
                delete_id_list_page(t1, scp03, output_offset, session_id)?;
            cycle_deleted += d;
            cycle_failed += f;
            output_offset = output_offset.saturating_add(list_byte_len as u16);
            if more != 0x01 || list_byte_len == 0 {
                break;
            }
        }

        total_deleted += cycle_deleted;
        last_failed = cycle_failed;
        if cycle_deleted == 0 {
            break;
        }
    }

    Ok((total_deleted, last_failed))
}

unsafe fn delete_id_list_page(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    output_offset: u16,
    session_id: Option<&[u8; 8]>,
) -> Result<(u8, usize, u16, u16), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_LIST);
    apdu.tlv(TAG_1, &output_offset.to_be_bytes());
    apdu.tlv(TAG_2, &[0xFF]);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; 1024];
    let resp_len = send_apdu(t1, scp03, cmd, &mut resp)?;
    if resp_len < 3 {
        return Ok((0x00, 0, 0, 0));
    }

    // BER-TLV: TAG_1(more_indicator, 1B) + TAG_2(id_list, N*4 bytes).
    // ID list can exceed 127 bytes so 0x82-prefixed lengths are required.
    let mut more = 0u8;
    let mut list_start = 0usize;
    let mut list_len = 0usize;

    let mut idx = 0;
    while idx + 1 < resp_len {
        let tag = resp[idx];
        idx += 1;
        let len_byte = resp[idx];
        idx += 1;
        let len: usize = if len_byte < 0x80 {
            len_byte as usize
        } else if len_byte == 0x81 && idx < resp_len {
            let l = resp[idx] as usize;
            idx += 1;
            l
        } else if len_byte == 0x82 && idx + 1 < resp_len {
            let l = ((resp[idx] as usize) << 8) | (resp[idx + 1] as usize);
            idx += 2;
            l
        } else {
            break;
        };
        if tag == TAG_1 && len == 1 && idx < resp_len {
            more = resp[idx];
        } else if tag == TAG_2 {
            list_start = idx;
            list_len = len;
        }
        idx = idx.saturating_add(len);
    }

    let mut deleted = 0u16;
    let mut failed = 0u16;
    let list_end = list_start.saturating_add(list_len).min(resp_len);
    let mut i = list_start;
    while i + 3 < list_end {
        let id = ((resp[i] as u32) << 24)
            | ((resp[i + 1] as u32) << 16)
            | ((resp[i + 2] as u32) << 8)
            | (resp[i + 3] as u32);
        i += 4;

        if id == 0
            || (id & 0xFFFF_0000) == 0x7FFF_0000
            || (id & 0xFFF0_0000) == 0x7DA0_0000
            || id >= 0xF000_0000
        {
            continue;
        }

        let result = match session_id {
            Some(sid) => delete_object_authed(t1, scp03, sid, id),
            None => delete_object(t1, scp03, id),
        };

        match result {
            Ok(()) => {
                if check_exists(t1, scp03, id).unwrap_or(false) {
                    failed += 1;
                } else {
                    deleted += 1;
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[SE050][erase]   0x{:08x} deleted", id
                    );
                }
            }
            Err(_e) => {
                failed += 1;
                #[cfg(feature = "debug-log")]
                secure_log!(
                    "[SE050][erase]   0x{:08x} FAILED: {:?}", id, _e
                );
            }
        }
    }

    Ok((more, list_len, deleted, failed))
}

/// Per-`GetRandom`-APDU request ceiling over the SCP03 secure channel.
///
/// **Silicon limit (B-U585I-IOT02A, 2026-05-28).** A single `GetRandom`
/// over SCP03 succeeds up to **224 bytes** and is rejected with
/// SW=0x6985 at **240 bytes** (empirically bracketed by the
/// `get_random_size_boundary` stress probe: 16/32/48/64/96/128/160/
/// 192/224 OK, 240/256 FAIL). The cause is the encrypted response
/// frame: `TLV(TAG_1,N) + SW`, R-ENC-padded to a 16-byte multiple plus
/// the 8-byte R-MAC, must fit the SE050's ~256-byte secure-response
/// frame — which 224 does (≈248 B on the wire) and 240 does not
/// (≈264 B). The NXP plug-and-trust SDK has the same caveat as a TODO
/// (`fsl_sss_se05x_apis.c` — "Replace 512 with max rsp buffer size
/// based on with/without SCP") and resolves it by chunking; we do the
/// same. 128 is chosen as a clean, comfortably-safe chunk below 224.
const GET_RANDOM_MAX_CHUNK: usize = 128;

/// `Se05x_API_GetRandom` (NXP AN12413 §5.13.1) — fill `out` with bytes
/// from the SE050 hardware TRNG over the established SCP03 channel.
///
/// Requests larger than [`GET_RANDOM_MAX_CHUNK`] are split across
/// multiple `GetRandom` APDUs (the SE050 rejects an oversized single
/// request over SCP03 — see that constant). This mirrors the NXP SDK's
/// `sss_se05x_rng_get_random` chunking loop, so any `out.len()` is
/// accepted. Each APDU's response is `TLV(TAG_1, random_bytes)`.
///
/// The XOR-mix layer (`hw::rng_strong`) is what makes this strong:
/// even if the SE050 TRNG is biased / compromised, the XOR with the
/// STM32 TRNG and OPTIGA TRNG preserves entropy from the remaining
/// sources. We never trust a single SE-TRNG output blindly.
pub unsafe fn get_random(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    out: &mut [u8],
) -> Result<usize, Se050Error> {
    if out.is_empty() {
        return Err(Se050Error::InvalidParam);
    }

    let mut filled = 0usize;
    while filled < out.len() {
        let chunk = (out.len() - filled).min(GET_RANDOM_MAX_CHUNK);

        let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_RANDOM);
        let size = chunk as u16;
        apdu.tlv(TAG_1, &size.to_be_bytes());
        let cmd = apdu.finish(true);

        let mut resp = [0u8; 320];
        let n = send_apdu(t1, scp03, cmd, &mut resp)?;
        let (_, value, _) = tlv_parse(&resp[..n]).ok_or(Se050Error::Transport)?;
        if value.len() < chunk {
            // Chip returned fewer bytes than requested — treat as a
            // transport / framing fault rather than silently
            // under-filling the caller's buffer with stale zeros.
            return Err(Se050Error::Transport);
        }
        out[filled..filled + chunk].copy_from_slice(&value[..chunk]);
        filled += chunk;
    }
    Ok(filled)
}

/// Close a session on the SE050.
pub unsafe fn close_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
) -> Result<(), Se050Error> {
    // Inner close: MGMT / CloseSession (no payload)
    let inner: [u8; 4] = [0x80, INS_MGMT, P1_DEFAULT, 0x1C];

    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    let _ = send_apdu(t1, scp03, cmd, &mut resp);
    Ok(())
}
