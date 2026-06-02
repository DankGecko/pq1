//! SCP03 (Secure Channel Protocol 03) for SE050.
//!
//! Establishes an authenticated, encrypted channel with the SE050 using
//! GlobalPlatform SCP03. After session establishment every command is
//! MAC'd (C-MAC) and encrypted (C-DEC), AND every response is MAC'd
//! (R-MAC) and encrypted (R-ENC). This is GP SCP03 security level
//! 0x33 — the "all four" mode.
//!
//! **Why 0x33, not 0x03 (the pre-S-5 value).** S-5 (`docs/security-review-
//! 2026-05.md` §C-7) — at level 0x03 the SE050 returns responses in
//! cleartext on the I²C bus, leaking `half_E` every unlock. NXP's own
//! reference (`fsl_sss_se05x_scp03.c`) ships at 0x33; SE050 conforms
//! to GP SCP03 per AN12413 §4.5.3.2, which defers to GP Amendment D
//! Table 7-6 (every P1 in {0x00, 0x01, 0x03, 0x11, 0x13, 0x33} is
//! valid).

// Pure-logic primitives live in `crate::scp03_logic` so the NIST
// AES-128 / CMAC vectors + the GP `PUT KEY` layout tests run under
// `cargo test -p sphincs-tz-secure` (this module is `feature = "se050"`
// + `not(test)`-gated in `main.rs`, so its own `#[cfg(test)]` blocks
// would never compile). Re-export the surface so existing call sites
// (and `Se050::rotate_scp03_keys`) keep working unchanged.
pub use crate::scp03_logic::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_ecb_encrypt, build_put_key_apdu, cmac_aes128,
    keys_are_factory_default, KEY_VERSION, PLATFORM_DEK, PLATFORM_ENC, PLATFORM_MAC,
};
use crate::scp03_logic::{
    build_derivation_data, kdf, DD_CARD_CRYPTOGRAM, DD_HOST_CRYPTOGRAM, DD_S_ENC, DD_S_MAC,
    DD_S_RMAC,
};

use super::apdu::Se050Error;

// The factory-key fallback only makes sense when the build *prefers*
// derived keys (otherwise the preferred set already IS the factory keys
// and there is nothing to fall back from). Catch the nonsensical combo
// at compile time rather than shipping a no-op flag. (Defense-in-depth:
// dead today because Cargo.toml declares the feature edge
// `se050-scp03-allow-factory-fallback = ["se050-derived-scp03"]`; this
// fires only if that edge is ever removed.)
#[cfg(all(
    feature = "se050-scp03-allow-factory-fallback",
    not(feature = "se050-derived-scp03")
))]
compile_error!(
    "se050-scp03-allow-factory-fallback requires se050-derived-scp03 \
     (without derived keys the preferred set already is the factory keys)"
);

// Constants `PLATFORM_ENC/MAC/DEK`, `KEY_VERSION`, the SCP03 KDF
// derivation-data constants, and the pure crypto helpers all live in
// `crate::scp03_logic` now (see the `use` block at the top of this
// file) — kept un-gated so the host test build can run the NIST KATs
// + the GP `PUT KEY` layout assertions.

/// Resolve the SCP03 static keys this build should *prefer* — `(S-ENC,
/// S-MAC, DEK)`.
///
/// - Without `se050-derived-scp03` (the default): the published factory
///   constants from `scp03_logic::PLATFORM_*`.
/// - With `se050-derived-scp03`: the per-device keys from
///   `hw::secret_keys::se050_scp03_{enc,mac,dek}_key()` (BHK-rooted in a
///   `bhk`-on build; DHUK / OTP per build otherwise). A device whose chip
///   has been `PUT KEY`-rotated holds exactly these; one that hasn't still
///   holds the factory keys — `establish()` probes the preferred set first
///   and falls back to `PLATFORM_*` on a card-cryptogram mismatch, so one
///   firmware copes with both. `KEY_VERSION` stays `0x0B` either way (the
///   rotation replaces keyset `0x0B` in place, it does not add a new KVN).
///
/// Lives here (not in `scp03_logic`) because the derived-key path imports
/// `hw::secret_keys`, and the `hw` module is `not(test)`-gated — keeping
/// this stub in the gated `se050` module keeps `scp03_logic` host-clean.
pub fn load_platform_keys() -> Result<([u8; 16], [u8; 16], [u8; 16]), Se050Error> {
    #[cfg(not(feature = "se050-derived-scp03"))]
    {
        Ok((PLATFORM_ENC, PLATFORM_MAC, PLATFORM_DEK))
    }
    #[cfg(feature = "se050-derived-scp03")]
    {
        use crate::hw::secret_keys;
        let enc = secret_keys::se050_scp03_enc_key().map_err(|_| Se050Error::Scp03)?;
        let mac = secret_keys::se050_scp03_mac_key().map_err(|_| Se050Error::Scp03)?;
        let dek = secret_keys::se050_scp03_dek_key().map_err(|_| Se050Error::Scp03)?;
        Ok((enc, mac, dek))
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// SCP03 session — holds derived session keys and MAC chaining value.
pub struct Scp03Session {
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    /// MAC Chaining Value — updated after every wrapped command.
    pub mcv: [u8; 16],
    /// Command counter for IV derivation (big-endian, incremented per command).
    pub counter: [u8; 16],
    /// Whether the session is established.
    pub active: bool,
}

impl Scp03Session {
    pub const fn new() -> Self {
        Self {
            s_enc: [0; 16],
            s_mac: [0; 16],
            s_rmac: [0; 16],
            mcv: [0; 16],
            counter: [0; 16],
            active: false,
        }
    }

    fn inc_counter(&mut self) {
        for i in (0..16).rev() {
            self.counter[i] = self.counter[i].wrapping_add(1);
            if self.counter[i] != 0 {
                break;
            }
        }
    }
}

// AES-128 ECB/CBC + CMAC primitives and the SP 800-108 derivation-data
// builder + `kdf` block-emitter all live in `crate::scp03_logic` now
// (imported at the top of this file).

// ---------------------------------------------------------------------------
// Session establishment
// ---------------------------------------------------------------------------

/// Establish an SCP03 session with the SE050.
///
/// Probe-on-boot: tries the keys this build *prefers* (the derived
/// per-device keys when `se050-derived-scp03` is on; the published
/// factory constants otherwise — see `load_platform_keys`). If that
/// fails the card-cryptogram check (the signal that the chip holds a
/// different key set), it retries once with the factory constants —
/// but ONLY in a build that sets `se050-scp03-allow-factory-fallback`
/// (the provisioning/rotation tool, §29, which must open a factory-key
/// session to send GP PUT KEY). A runtime-signing SHIP build omits that
/// flag and therefore **fails closed** on a derived-key mismatch rather
/// than silently downgrading to the attacker-known published keys.
/// `KEY_VERSION` is `0x0B` either way.
pub unsafe fn establish(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
) -> Result<(), Se050Error> {
    let (enc, mac, _dek) = load_platform_keys()?;

    match establish_with_keys(session, t1, &enc, &mac) {
        Ok(()) => Ok(()),
        Err(e) => {
            // The published-factory-key fallback is GATED to the
            // provisioning/rotation tool (`se050-scp03-allow-factory-
            // fallback`). In a runtime-signing build this whole arm is
            // compiled out, so a derived-key mismatch returns `Err(e)`
            // and the SE050 stays locked — fail CLOSED, never fall back
            // to the AN12436 keys an attacker also holds. When the flag
            // IS set, retry once on a key-related failure (card-cryptogram
            // mismatch `Scp03` or a status word like `0x6A88`); never
            // retry a pure transport glitch.
            #[cfg(all(
                feature = "se050-derived-scp03",
                feature = "se050-scp03-allow-factory-fallback"
            ))]
            if matches!(e, Se050Error::Scp03 | Se050Error::Status(_)) {
                #[cfg(feature = "debug-log")]
                secure_log!("[SCP03] derived-key establish failed ({:?}); falling back to factory keys", e);
                return establish_with_keys(session, t1, &PLATFORM_ENC, &PLATFORM_MAC);
            }
            Err(e)
        }
    }
}

/// One INITIALIZE-UPDATE + EXTERNAL-AUTHENTICATE handshake using the
/// given static `(S-ENC, S-MAC)` keys. Returns `Se050Error::Scp03` on a
/// card-cryptogram mismatch (the "wrong keys" signal the caller uses to
/// decide whether to retry with a different set).
unsafe fn establish_with_keys(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
    static_enc: &[u8; 16],
    static_mac: &[u8; 16],
) -> Result<(), Se050Error> {
    // Generate 8-byte host challenge from hardware TRNG
    let mut host_challenge = [0u8; 8];
    crate::rng::fill(&mut host_challenge).map_err(|_| Se050Error::Scp03)?;

    // --- INITIALIZE UPDATE ---
    let mut init_update = [0u8; 13];
    init_update[0] = 0x80; // CLA
    init_update[1] = 0x50; // INS_INITIALIZE_UPDATE
    init_update[2] = KEY_VERSION;
    init_update[3] = 0x00;
    init_update[4] = 0x08; // Lc
    init_update[5..13].copy_from_slice(&host_challenge);

    let mut resp = [0u8; 64];
    let n = t1.transceive(&init_update, &mut resp).map_err(|_| Se050Error::Transport)?;

    if n < 31 {
        return Err(Se050Error::Scp03);
    }

    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    if sw != 0x9000 {
        return Err(Se050Error::Status(sw));
    }

    // Parse: KeyDivData(10) + KeyInfo(3) + CardChallenge(8) + CardCryptogram(8)
    let mut card_challenge = [0u8; 8];
    card_challenge.copy_from_slice(&resp[13..21]);
    let mut card_cryptogram = [0u8; 8];
    card_cryptogram.copy_from_slice(&resp[21..29]);

    // --- Derive session keys ---
    let dd_enc = build_derivation_data(DD_S_ENC, 0x0080, &host_challenge, &card_challenge);
    let dd_mac = build_derivation_data(DD_S_MAC, 0x0080, &host_challenge, &card_challenge);
    let dd_rmac = build_derivation_data(DD_S_RMAC, 0x0080, &host_challenge, &card_challenge);

    session.s_enc = kdf(static_enc, &dd_enc);
    session.s_mac = kdf(static_mac, &dd_mac);
    session.s_rmac = kdf(static_mac, &dd_rmac);

    // --- Verify card cryptogram ---
    let dd_card = build_derivation_data(DD_CARD_CRYPTOGRAM, 0x0040, &host_challenge, &card_challenge);
    let card_crypto_computed = kdf(&session.s_mac, &dd_card);

    if card_crypto_computed[..8] != card_cryptogram[..] {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] Card cryptogram MISMATCH");
        return Err(Se050Error::Scp03);
    }

    // --- Compute host cryptogram ---
    let dd_host = build_derivation_data(DD_HOST_CRYPTOGRAM, 0x0040, &host_challenge, &card_challenge);
    let host_crypto_full = kdf(&session.s_mac, &dd_host);
    let host_cryptogram = &host_crypto_full[..8];

    // --- EXTERNAL AUTHENTICATE ---
    // P1=0x33: C-DECRYPTION | R-ENCRYPTION | C-MAC | R-MAC.  S-5 fix —
    // GP Amendment D Table 7-6 (page 35); NXP plug-and-trust
    // `fsl_sss_se05x_scp03.c:186-198` (`SECLVL_CDEC_RENC_CMAC_RMAC`).
    let header = [0x84u8, 0x82, 0x33, 0x00, 0x10];
    session.mcv = [0; 16];
    let mac_full = cmac_aes128(&session.s_mac, &[&session.mcv, &header, host_cryptogram]);
    session.mcv = mac_full;

    let mut ext_auth = [0u8; 21];
    ext_auth[0] = 0x84;
    ext_auth[1] = 0x82;
    ext_auth[2] = 0x33;
    ext_auth[3] = 0x00;
    ext_auth[4] = 0x10; // Lc = 16 (8 host crypto + 8 MAC)
    ext_auth[5..13].copy_from_slice(host_cryptogram);
    ext_auth[13..21].copy_from_slice(&mac_full[..8]);

    let mut ext_resp = [0u8; 32];
    let ext_n = t1.transceive(&ext_auth, &mut ext_resp).map_err(|_| Se050Error::Transport)?;

    if ext_n < 2 {
        return Err(Se050Error::Scp03);
    }
    let ext_sw = ((ext_resp[ext_n - 2] as u16) << 8) | (ext_resp[ext_n - 1] as u16);
    if ext_sw != 0x9000 {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] EXT AUTH SW=0x{:04x}", ext_sw);
        return Err(Se050Error::Status(ext_sw));
    }

    session.counter = [0; 16];
    session.counter[15] = 0x01;
    session.active = true;

    #[cfg(feature = "debug-log")]
    secure_log!("[SCP03] Session established");

    Ok(())
}

// ---------------------------------------------------------------------------
// APDU MAC + encryption wrapping
// ---------------------------------------------------------------------------

/// Compute the command ICV (Initial Chaining Value) for AES-CBC encryption.
///
/// GP Amendment D §6.2.6: `ICV = AES-ECB-Enc(S-ENC, padded_counter)` where
/// the counter is left-padded with zeroes to one block. (`session.counter`
/// already lives in that left-padded representation — 15 high zero bytes
/// then the counter value in the low byte(s).)
fn command_icv(session: &Scp03Session) -> [u8; 16] {
    aes128_ecb_encrypt(&session.s_enc, &session.counter)
}

/// Compute the response ICV for AES-CBC decryption of an R-ENC response.
///
/// GP Amendment D §6.2.7 (page 30): the response uses the SAME padded
/// counter block as the matching command, with one byte changed —
/// "Before encryption, the most significant byte of this block shall be
/// set to '80'." That separates response ICVs from command ICVs even
/// though both share `S-ENC` and `counter`.
///
/// Mirrors `nxpSCP03_Get_ResponseICV` in NXP plug-and-trust
/// (`hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c:296-330`).
fn response_icv(session: &Scp03Session) -> [u8; 16] {
    let mut block = session.counter;
    block[0] = 0x80;
    aes128_ecb_encrypt(&session.s_enc, &block)
}

/// Wrap an APDU with SCP03 C-MAC and C-DEC (command encryption).
///
/// Always applies both C-MAC and C-DEC. The counter is left at the
/// command's value — `unwrap_response()` increments it on success so the
/// wrap/unwrap pair uses the same counter (GP Amd D §6.2.6 + §6.2.7), and
/// a transport-level loss of the response keeps host/card counters in
/// sync (the card also only advances after successfully sending the
/// response).
pub fn wrap_apdu(
    session: &mut Scp03Session,
    apdu: &[u8],
    out: &mut [u8],
) -> usize {
    if !session.active || apdu.len() < 4 {
        out[..apdu.len()].copy_from_slice(apdu);
        return apdu.len();
    }

    // Parse incoming APDU to locate header and data
    let extended = apdu.len() >= 7 && apdu[4] == 0x00;
    let (hdr_len, data_len) = if extended {
        let lc = ((apdu[5] as usize) << 8) | (apdu[6] as usize);
        (7, lc)
    } else if apdu.len() > 5 {
        (5, apdu.len() - 5)
    } else {
        (apdu.len(), 0)
    };
    let has_data = data_len > 0;

    // --- C-DEC: encrypt command data ---
    let enc_len = if has_data {
        let mut enc_buf = [0u8; 1024];
        enc_buf[..data_len].copy_from_slice(&apdu[hdr_len..hdr_len + data_len]);
        // ISO 7816-4 padding: 0x80 then zeros to next 16-byte boundary
        let mut padded_len = data_len;
        enc_buf[padded_len] = 0x80;
        padded_len += 1;
        while padded_len % 16 != 0 {
            enc_buf[padded_len] = 0x00;
            padded_len += 1;
        }
        let icv = command_icv(session);
        aes128_cbc_encrypt(&session.s_enc, &icv, &mut enc_buf[..padded_len]);
        // Place encrypted data at offset 7 (extended Lc position)
        out[7..7 + padded_len].copy_from_slice(&enc_buf[..padded_len]);
        padded_len
    } else {
        0
    };

    // New Lc = encrypted data + 8-byte MAC
    let new_lc = enc_len + 8;
    let use_extended = extended || new_lc >= 256;
    let out_hdr_len = if use_extended { 7 } else { 5 };

    // Shift data to correct position if header length changed
    if has_data && !use_extended {
        for i in 0..enc_len {
            out[5 + i] = out[7 + i];
        }
    }

    // Write header
    out[0] = apdu[0] | 0x04; // Set CLA security bit
    out[1] = apdu[1];
    out[2] = apdu[2];
    out[3] = apdu[3];

    if use_extended {
        out[4] = 0x00;
        out[5] = (new_lc >> 8) as u8;
        out[6] = (new_lc & 0xFF) as u8;
    } else {
        out[4] = new_lc as u8;
    }

    // Compute C-MAC
    let mac_header = &out[0..out_hdr_len];
    let mac_data = if has_data {
        &out[out_hdr_len..out_hdr_len + enc_len]
    } else {
        &[] as &[u8]
    };
    let mac_full = cmac_aes128(&session.s_mac, &[&session.mcv, mac_header, mac_data]);

    // Append 8-byte MAC
    let mac_offset = out_hdr_len + enc_len;
    out[mac_offset..mac_offset + 8].copy_from_slice(&mac_full[..8]);
    session.mcv = mac_full;

    mac_offset + 8
}

// ---------------------------------------------------------------------------
// SCP03 response unwrap — R-MAC verify + R-ENC decrypt
// ---------------------------------------------------------------------------

/// Errors specific to `unwrap_response`. Surfaced via `Se050Error::Scp03`
/// upstream — the variant exists for diagnostic logging.
#[derive(Debug)]
pub enum UnwrapError {
    /// Response was shorter than 2 bytes (not even a SW).
    Truncated,
    /// SCP03 session is not active — caller should bypass unwrap.
    Inactive,
    /// Response length is in the "no man's land" between 2 (bare SW) and
    /// 10 (minimum protected response = R-MAC + SW), with no valid
    /// interpretation under GP Amendment D §6.2.5.
    MalformedLength,
    /// R-MAC verification failed in constant time.
    RMacMismatch,
    /// Encrypted body length was not a multiple of 16 (ISO 7816-4 padded
    /// AES-CBC must be).
    BadCiphertextLen,
    /// ISO 7816-4 depad found no `0x80` sentinel.
    BadPadding,
    /// Output buffer too small for the plaintext.
    Overflow,
}

impl From<UnwrapError> for super::apdu::Se050Error {
    fn from(_: UnwrapError) -> Self {
        super::apdu::Se050Error::Scp03
    }
}

/// Constant-time equality on two 8-byte slices.
///
/// Uses `subtle::ConstantTimeEq` rather than a hand-rolled XOR-OR loop —
/// the loop is correct in principle but rustc + future LLVM versions
/// can introduce vectorised early-exit code that breaks the CT
/// property.  `subtle` wraps the comparison in `core::hint::black_box`
/// and volatile reads to defeat reordering.  Matches CLAUDE.md's
/// "`subtle` for constant-time compares" convention used throughout
/// the rest of the secure world.
fn ct_eq_8(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    debug_assert_eq!(a.len(), 8);
    debug_assert_eq!(b.len(), 8);
    a.ct_eq(b).into()
}

/// Unwrap an SCP03-protected response APDU (R-MAC verify, optionally
/// R-ENC decrypt) and place `plaintext_body || SW1 SW2` into `out`.
///
/// Returns the number of bytes written to `out` (≥ 2). The last two
/// are always the status word (`SW1 SW2`) — for downstream handlers that
/// already expect the raw form `body || SW`.
///
/// Handles the three GP Amd D §6.2.5 cases:
/// 1. **Bare error (length 2):** SW1 SW2 only, no R-MAC. Per §6.2.5
///    first sentence — "no R-MAC shall be generated and no protection
///    shall be applied to a response that includes an error status
///    word". All SW ∉ {`9000`, `62xx`, `63xx`} → bare. Verified by
///    matching `len == 2`; we *don't* re-classify by SW value because
///    a SW=9000 response with R-ENC will be ≥ 10 bytes (R-MAC + SW
///    minimum) and a SW=9000 with no data is also ≥ 10 bytes (still
///    has R-MAC).
/// 2. **No-body protected (length 10):** R-MAC(8) || SW(2). Empty
///    response data field — R-MAC still computed over `MCV || SW`
///    (§6.2.5 last paragraph + §6.2.7 "no encryption shall be applied
///    to a response where there is no response data field: in this
///    case the message shall be protected as defined in section
///    6.2.5").
/// 3. **Full protected (length ≥ 26):** ciphertext_body || R-MAC(8)
///    || SW(2). Ciphertext is a multiple of 16. R-MAC over `MCV ||
///    ciphertext_body || SW`. Decrypt with `response_icv()`, depad
///    via ISO 7816-4 (scan from end for `0x80`).
///
/// Mirrors `nxpSCP03_Decrypt_ResponseAPDU` in NXP plug-and-trust
/// (`hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c:124-248`). On success
/// the encryption counter is incremented (so the wrap/unwrap pair share
/// one counter value, and the next wrap uses `counter + 1`). On failure
/// the counter is **not** advanced — both ends roll back together.
pub fn unwrap_response(
    session: &mut Scp03Session,
    wrapped: &[u8],
    out: &mut [u8],
) -> Result<usize, UnwrapError> {
    if !session.active {
        return Err(UnwrapError::Inactive);
    }
    let n = wrapped.len();
    if n < 2 {
        return Err(UnwrapError::Truncated);
    }

    // Case 1 — bare error response: just SW1 SW2.  No R-MAC, no R-ENC.
    // GP Amd D §6.2.5 first paragraph.
    if n == 2 {
        if out.len() < 2 {
            return Err(UnwrapError::Overflow);
        }
        out[0] = wrapped[0];
        out[1] = wrapped[1];
        // No counter increment — the card did not produce a protected
        // response, so the counter contract isn't "consumed" yet. This
        // matches NXP's `nxScp03_Com.c` path that returns early on
        // bare-SW responses before the inc_command_counter call.
        return Ok(2);
    }

    if n < 10 {
        return Err(UnwrapError::MalformedLength);
    }

    // Case 2 + Case 3 share the R-MAC verify path.  Layout:
    //   wrapped[..n-10]    = ciphertext body (may be empty in case 2)
    //   wrapped[n-10..n-2] = 8-byte R-MAC
    //   wrapped[n-2..n]    = SW1 SW2
    let body_end = n - 10;
    let body = &wrapped[..body_end];
    let rmac_recv = &wrapped[body_end..body_end + 8];
    let sw = &wrapped[n - 2..];

    // GP Amd D §6.2.5 + Figure 6-3:
    //   R-MAC = CMAC(S-RMAC, MCV || ciphered_body || SW)[..8]
    // The MCV is the full 16-byte command CMAC produced by `wrap_apdu`
    // (`session.mcv`); it is NOT updated by `unwrap_response`.
    let mac_full = cmac_aes128(&session.s_rmac, &[&session.mcv, body, sw]);
    if !ct_eq_8(&mac_full[..8], rmac_recv) {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] R-MAC MISMATCH");
        return Err(UnwrapError::RMacMismatch);
    }

    // Case 2 — empty body: just write the SW.
    if body_end == 0 {
        if out.len() < 2 {
            return Err(UnwrapError::Overflow);
        }
        out[0] = sw[0];
        out[1] = sw[1];
        session.inc_counter();
        return Ok(2);
    }

    // Case 3 — decrypt body, depad, append SW.
    if body_end % 16 != 0 {
        return Err(UnwrapError::BadCiphertextLen);
    }

    let mut plain = [0u8; 1024];
    if body_end > plain.len() {
        return Err(UnwrapError::Overflow);
    }
    plain[..body_end].copy_from_slice(body);

    let icv = response_icv(session);
    aes128_cbc_decrypt(&session.s_enc, &icv, &mut plain[..body_end]);

    // ISO 7816-4 depad: scan back from end of last block for the `0x80`
    // sentinel.  GP Amd D §6.2.7 + GP Card Spec §B.2.3.
    let mut pad_pos = body_end;
    while pad_pos > 0 {
        pad_pos -= 1;
        if plain[pad_pos] == 0x80 {
            break;
        }
        if plain[pad_pos] != 0x00 {
            return Err(UnwrapError::BadPadding);
        }
        if pad_pos + 16 <= body_end {
            // Spec mandates padding lies in the last block only — scanning
            // past one full block back means there was no `0x80` and
            // every trailing byte was `0x00`.  Reject.
            return Err(UnwrapError::BadPadding);
        }
    }
    if plain[pad_pos] != 0x80 {
        return Err(UnwrapError::BadPadding);
    }
    let plaintext_len = pad_pos;

    if out.len() < plaintext_len + 2 {
        return Err(UnwrapError::Overflow);
    }
    out[..plaintext_len].copy_from_slice(&plain[..plaintext_len]);
    out[plaintext_len] = sw[0];
    out[plaintext_len + 1] = sw[1];

    session.inc_counter();

    Ok(plaintext_len + 2)
}

// `aes128_cbc_decrypt` lives in `crate::scp03_logic` (re-exported via
// the `pub use` block at the top of this file) so the round-trip KATs
// in `scp03_logic::tests` exercise both directions on the host.

// `build_put_key_apdu` lives in `crate::scp03_logic` now (re-exported via
// `pub use` at the top of this file). Tests for the APDU layout + KCV +
// AES/CMAC primitives also live there — and unlike the `#[cfg(test)]`
// block that used to be here, they actually run under
// `cargo test -p sphincs-tz-secure` because `scp03_logic` is un-gated.
