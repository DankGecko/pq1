/// Secure Element abstraction — trait + mock for QEMU.
///
/// On real hardware, implement this trait wrapping the tropic01 crate.
/// On QEMU, the MockSecureElement stores data in secure SRAM.

#[derive(Debug)]
pub enum SeError {
    SlotNotFound,
    SlotExpired,
    InvalidParameter,
    InternalError,
}

pub trait SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError>;
    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError>;
    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError>;
    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError>;
}

// ---------------------------------------------------------------------------
// Mock Secure Element for QEMU
// ---------------------------------------------------------------------------

const NUM_RMEM_SLOTS: usize = 8;
const MAX_RMEM_DATA: usize = 512;
const NUM_MACD_SLOTS: usize = 16;

pub struct MockSecureElement {
    rmem_occupied: [bool; NUM_RMEM_SLOTS],
    rmem_len: [usize; NUM_RMEM_SLOTS],
    rmem_data: [[u8; MAX_RMEM_DATA]; NUM_RMEM_SLOTS],
    macd_initialized: [bool; NUM_MACD_SLOTS],
    macd_state: [[u8; 32]; NUM_MACD_SLOTS],
}

impl MockSecureElement {
    pub const fn new() -> Self {
        Self {
            rmem_occupied: [false; NUM_RMEM_SLOTS],
            rmem_len: [0; NUM_RMEM_SLOTS],
            rmem_data: [[0u8; MAX_RMEM_DATA]; NUM_RMEM_SLOTS],
            macd_initialized: [false; NUM_MACD_SLOTS],
            macd_state: [[0u8; 32]; NUM_MACD_SLOTS],
        }
    }
}

/// Simple HMAC-SHA256 for MACD simulation.
/// Uses the hmac crate (no_std compatible).
fn hmac_sha256(key: &[u8; 32], data: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

impl SecureElement for MockSecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError> {
        let s = slot as usize;
        if s >= NUM_RMEM_SLOTS {
            return Err(SeError::SlotNotFound);
        }
        if data.len() > MAX_RMEM_DATA {
            return Err(SeError::InvalidParameter);
        }
        self.rmem_data[s][..data.len()].copy_from_slice(data);
        self.rmem_len[s] = data.len();
        self.rmem_occupied[s] = true;
        Ok(())
    }

    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError> {
        let s = slot as usize;
        if s >= NUM_RMEM_SLOTS || !self.rmem_occupied[s] {
            return Err(SeError::SlotNotFound);
        }
        let len = self.rmem_len[s];
        if buf.len() < len {
            return Err(SeError::InvalidParameter);
        }
        buf[..len].copy_from_slice(&self.rmem_data[s][..len]);
        Ok(len)
    }

    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError> {
        let s = slot as usize;
        if s >= NUM_RMEM_SLOTS {
            return Err(SeError::SlotNotFound);
        }
        self.rmem_data[s] = [0u8; MAX_RMEM_DATA];
        self.rmem_len[s] = 0;
        self.rmem_occupied[s] = false;
        Ok(())
    }

    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError> {
        let s = slot as usize;
        if s >= NUM_MACD_SLOTS {
            return Err(SeError::SlotNotFound);
        }
        // Simplified mock: HMAC(data_in, slot_state_or_zeros).
        // Each call replaces slot_state with data_in (like TROPIC01's
        // "overwrite slot with input" behavior for re-init).
        // Output = HMAC(data_in, previous_state) — deterministic per (input, state) pair.
        let output = if self.macd_initialized[s] {
            hmac_sha256(data_in, &self.macd_state[s])
        } else {
            self.macd_initialized[s] = true;
            hmac_sha256(data_in, data_in)
        };
        // Store data_in as new state (not output) — this ensures that
        // calling with the same init_in restores the slot to a known state,
        // matching TROPIC01's re-initialization behavior.
        self.macd_state[s] = *data_in;
        Ok(output)
    }
}
