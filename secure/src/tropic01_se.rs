/// Real TROPIC01 Secure Element via semihosting SPI bridge.
///
/// Establishes an e2e encrypted session (X25519 Noise_KK1 + AES-256-GCM)
/// for every command batch. All r-mem and MAC-and-Destroy operations go
/// through the encrypted tunnel — the SPHINCS+ private key never travels
/// in plaintext over the SPI bus.

use crate::semihosting_spi::SemihostingSpi;
use crate::secure_element::{SecureElement, SeError};
use cortex_m_semihosting::nr;
use zeroize::Zeroize;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

/// Device path for the TROPIC01 USB dongle (null-terminated for semihosting).
const DEVICE_PATH: &[u8] = b"/dev/ttyACM0\0";

/// Read random bytes from the host's /dev/urandom via semihosting.
fn semihosting_random(buf: &mut [u8]) -> Result<(), SeError> {
    let path = b"/dev/urandom\0";
    let fd = unsafe {
        cortex_m_semihosting::syscall!(OPEN, path.as_ptr(), nr::open::R_BINARY, path.len() - 1)
    };
    if fd as isize == -1 {
        return Err(SeError::InternalError);
    }
    let not_read = unsafe {
        cortex_m_semihosting::syscall!(READ, fd, buf.as_mut_ptr(), buf.len())
    };
    unsafe { cortex_m_semihosting::syscall!(CLOSE, fd) };
    if not_read != 0 {
        return Err(SeError::InternalError);
    }
    Ok(())
}

/// Generate an ephemeral X25519 keypair using host randomness.
fn generate_ephemeral() -> Result<(PublicKey, StaticSecret), SeError> {
    let mut key_bytes = [0u8; 32];
    semihosting_random(&mut key_bytes)?;
    let secret = StaticSecret::from(key_bytes);
    let public = PublicKey::from(&secret);
    Ok((public, secret))
}

/// Execute a closure with an active, e2e-encrypted TROPIC01 session.
///
/// Each call opens the SPI port, reboots the chip, performs X25519 key exchange
/// (Noise_KK1 protocol), executes the closure, and closes the session.
/// All commands within the closure are AES-256-GCM encrypted end-to-end.
///
/// This macro exists because `ActiveSession` is a private type in the tropic01
/// crate, so we cannot store the session in a struct field.
macro_rules! with_session {
    ($session:ident, $body:block) => {{
        let spi = SemihostingSpi::open(DEVICE_PATH)
            .map_err(|_| SeError::InternalError)?;
        let mut tropic = Tropic01::new(spi);

        // Reboot chip to clean state
        tropic.startup_req(tropic01::StartupReq::Reboot)
            .map_err(|_| SeError::InternalError)?;

        // Generate ephemeral X25519 keypair (random from host /dev/urandom)
        let (ehpub, ehpriv) = generate_ephemeral()?;

        // Pre-shared pairing keys (production slot 0)
        let shpub: PublicKey = SH0PUB_PROD0.into();
        let shpriv: StaticSecret = SH0PRIV_PROD0.into();

        // Establish e2e encrypted session (Noise_KK1 handshake)
        // After this, all commands are AES-256-GCM encrypted over SPI.
        let mut $session = tropic
            .session_start(&X25519Dalek, shpub, shpriv, ehpub, ehpriv, 0)
            .map_err(|(_, _e)| SeError::InternalError)?;

        let __result = { $body };

        // Close session (zeroizes session keys)
        $session.session_abort().ok();
        __result
    }};
}

/// TROPIC01 SecureElement implementation.
///
/// Each method establishes a fresh e2e encrypted session, performs the
/// operation, and closes the session. This is how the desktop CLI works too.
pub struct Tropic01SecureElement;

impl Tropic01SecureElement {
    pub const fn new() -> Self {
        Self
    }
}

impl SecureElement for Tropic01SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError> {
        with_session!(session, {
            session
                .r_mem_data_write(U16::new(slot), data)
                .map_err(|_| SeError::InternalError)
        })
    }

    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError> {
        with_session!(session, {
            let data = session
                .r_mem_data_read(U16::new(slot))
                .map_err(|_| SeError::SlotNotFound)?;
            let len = data.len();
            if buf.len() < len {
                return Err(SeError::InvalidParameter);
            }
            buf[..len].copy_from_slice(data);
            Ok(len)
        })
    }

    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError> {
        with_session!(session, {
            session
                .r_mem_data_erase(U16::new(slot))
                .map_err(|_| SeError::InternalError)
        })
    }

    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError> {
        with_session!(session, {
            let result = session
                .mac_and_destroy(U16::new(slot), data_in)
                .map_err(|_| SeError::InternalError)?;
            Ok(*result)
        })
    }
}

/// Batch operations that need multiple commands in one session.
/// These avoid the overhead of re-establishing a session for each command.
impl Tropic01SecureElement {
    /// Enroll a key: performs multiple r_mem_write + mac_and_destroy in one session.
    pub fn batch_enroll(
        &mut self,
        encrypted_sk_blob: &[u8],
        pin_state_blob: &[u8],
        verifying_key: &[u8],
        master_secret: &[u8; 32],
        pin: &[u8; 8],
        max_attempts: u8,
    ) -> Result<(), SeError> {
        use crate::crypto::{macd_init_input, macd_pin_input, aes_encrypt_inplace, PER_SLOT_CT_LEN};

        with_session!(session, {
            secure_log!("  [T01] Session established (e2e encrypted)");

            // Initialize MAC-and-Destroy slots
            secure_log!("  [T01] Initializing {} MACD slots...", max_attempts);
            let mut encrypted_secrets = [[0u8; PER_SLOT_CT_LEN]; 10];

            for j in 0..max_attempts {
                let init_in = macd_init_input(master_secret, j);
                let pin_in = macd_pin_input(pin, j);

                session.mac_and_destroy(U16::new(j as u16), &init_in)
                    .map_err(|_| SeError::InternalError)?;
                let mut w_j: [u8; 32] = *session
                    .mac_and_destroy(U16::new(j as u16), &pin_in)
                    .map_err(|_| SeError::InternalError)?;
                session.mac_and_destroy(U16::new(j as u16), &init_in)
                    .map_err(|_| SeError::InternalError)?;

                let mut ct_buf = [0u8; PER_SLOT_CT_LEN];
                ct_buf[..32].copy_from_slice(master_secret);
                aes_encrypt_inplace(&w_j, &mut ct_buf, 32, j);
                encrypted_secrets[j as usize] = ct_buf;
                w_j.zeroize();
            }
            secure_log!("  [T01] MACD slots ready");

            // Store encrypted signing key
            session.r_mem_data_erase(U16::new(0)).ok();
            session.r_mem_data_write(U16::new(0), encrypted_sk_blob)
                .map_err(|_| SeError::InternalError)?;

            // Store PIN state
            let mut pin_state = [0u8; 512];
            pin_state[0] = 0; // next_index = 0
            let mut offset = 1;
            for j in 0..max_attempts as usize {
                pin_state[offset..offset + PER_SLOT_CT_LEN]
                    .copy_from_slice(&encrypted_secrets[j]);
                offset += PER_SLOT_CT_LEN;
            }
            session.r_mem_data_erase(U16::new(1)).ok();
            session.r_mem_data_write(U16::new(1), &pin_state[..offset])
                .map_err(|_| SeError::InternalError)?;

            // Store verifying key
            session.r_mem_data_erase(U16::new(2)).ok();
            session.r_mem_data_write(U16::new(2), verifying_key)
                .map_err(|_| SeError::InternalError)?;

            secure_log!("  [T01] All data stored on chip (e2e encrypted)");
            Ok(())
        })
    }

    /// Verify PIN: reads state, does MACD, re-inits slots — all in one session.
    pub fn batch_verify_pin(
        &mut self,
        pin: &[u8; 8],
        max_attempts: u8,
    ) -> Result<[u8; 32], SeError> {
        use crate::crypto::*;

        with_session!(session, {
            // Read PIN state
            let state_data = session.r_mem_data_read(U16::new(1))
                .map_err(|_| SeError::InternalError)?;
            let mut state_buf = [0u8; 512];
            let state_len = state_data.len();
            state_buf[..state_len].copy_from_slice(state_data);

            let ps = deserialize_pin_state(&state_buf, state_len)
                .map_err(|_| SeError::InternalError)?;

            if ps.next_index >= max_attempts {
                session.r_mem_data_erase(U16::new(0)).ok();
                session.r_mem_data_erase(U16::new(1)).ok();
                return Err(SeError::SlotExpired); // PIN locked
            }

            // MAC-and-Destroy authentication
            let j = ps.next_index;
            let pin_in = macd_pin_input(pin, j);
            let mut w_j: [u8; 32] = *session
                .mac_and_destroy(U16::new(j as u16), &pin_in)
                .map_err(|_| SeError::InternalError)?;

            // Try decrypting master secret
            let mut ct_buf = [0u8; PER_SLOT_CT_LEN];
            ct_buf.copy_from_slice(&ps.encrypted_secrets[j as usize]);

            match aes_decrypt_inplace(&w_j, &mut ct_buf, PER_SLOT_CT_LEN, j) {
                Ok(32) => {
                    let mut master_secret = [0u8; 32];
                    master_secret.copy_from_slice(&ct_buf[..32]);
                    ct_buf.zeroize();
                    w_j.zeroize();

                    // Re-initialize all MACD slots
                    for slot_j in 0..max_attempts {
                        let init_in = macd_init_input(&master_secret, slot_j);
                        session.mac_and_destroy(U16::new(slot_j as u16), &init_in)
                            .map_err(|_| SeError::InternalError)?;
                    }

                    // Reset attempt counter
                    let mut new_state = [0u8; 512];
                    let len = serialize_pin_state(0, &ps.encrypted_secrets, &mut new_state);
                    session.r_mem_data_erase(U16::new(1)).ok();
                    session.r_mem_data_write(U16::new(1), &new_state[..len])
                        .map_err(|_| SeError::InternalError)?;

                    Ok(master_secret)
                }
                _ => {
                    // Wrong PIN — advance counter
                    ct_buf.zeroize();
                    w_j.zeroize();

                    let new_index = j + 1;
                    if new_index >= max_attempts {
                        session.r_mem_data_erase(U16::new(0)).ok();
                        session.r_mem_data_erase(U16::new(1)).ok();
                        session.r_mem_data_erase(U16::new(2)).ok();
                        return Err(SeError::SlotExpired);
                    }
                    let mut new_state = [0u8; 512];
                    let len = serialize_pin_state(new_index, &ps.encrypted_secrets, &mut new_state);
                    session.r_mem_data_erase(U16::new(1)).ok();
                    session.r_mem_data_write(U16::new(1), &new_state[..len]).ok();
                    Err(SeError::InvalidParameter) // PIN incorrect
                }
            }
        })
    }

    /// Read the encrypted SK blob and verifying key in one session.
    pub fn batch_read_key_material(
        &mut self,
        sk_blob: &mut [u8],
        vk_buf: &mut [u8],
    ) -> Result<(usize, usize), SeError> {
        with_session!(session, {
            let sk_data = session.r_mem_data_read(U16::new(0))
                .map_err(|_| SeError::SlotNotFound)?;
            let sk_len = sk_data.len();
            sk_blob[..sk_len].copy_from_slice(sk_data);

            let vk_data = session.r_mem_data_read(U16::new(2))
                .map_err(|_| SeError::SlotNotFound)?;
            let vk_len = vk_data.len();
            vk_buf[..vk_len].copy_from_slice(vk_data);

            Ok((sk_len, vk_len))
        })
    }

    /// Read PIN state (remaining attempts) in one session.
    pub fn batch_read_pin_state(&mut self) -> Result<u8, SeError> {
        with_session!(session, {
            let data = session.r_mem_data_read(U16::new(1))
                .map_err(|_| SeError::SlotNotFound)?;
            if data.is_empty() {
                return Err(SeError::InternalError);
            }
            let next_index = data[0];
            Ok(next_index)
        })
    }

    /// Get random bytes from the TROPIC01's hardware TRNG.
    pub fn get_trng_bytes(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        with_session!(session, {
            // get_random_value takes a u8 count, so we chunk if needed
            let mut offset = 0;
            while offset < buf.len() {
                let remaining = buf.len() - offset;
                let chunk = if remaining > 255 { 255 } else { remaining as u8 };
                let random = session
                    .get_random_value(chunk)
                    .map_err(|_| SeError::InternalError)?;
                let got = random.len().min(chunk as usize);
                buf[offset..offset + got].copy_from_slice(&random[..got]);
                offset += got;
            }
            Ok(())
        })
    }
}
