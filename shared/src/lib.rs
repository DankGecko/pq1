#![no_std]

// ---------------------------------------------------------------------------
// SLH-DSA-SHA2-128f sizes
// ---------------------------------------------------------------------------

pub const SIGNING_KEY_LEN: usize = 64;
pub const VERIFYING_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 17_088;
pub const PIN_LEN: usize = 8;
pub const TX_HASH_LEN: usize = 32;
pub const MAX_ATTEMPTS: u8 = 9;

// ---------------------------------------------------------------------------
// Non-secure SRAM boundaries (mps2-an505)
// Used by secure world to validate NS pointers.
// ---------------------------------------------------------------------------

/// mps2-an505: SSRAM-1 NS alias, offset 128KB (secure stack in first 128KB)
pub const NS_SRAM_BASE: u32 = 0x2802_0000;
pub const NS_SRAM_END: u32 = 0x2822_0000;

// ---------------------------------------------------------------------------
// NSC return status codes
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NscStatus {
    Ok = 0,
    PinIncorrect = 1,
    PinLocked = 2,
    CryptoError = 3,
    InvalidPointer = 4,
    NotInitialized = 5,
    InternalError = 0xFFFF_FFFF,
}

impl From<u32> for NscStatus {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::PinIncorrect,
            2 => Self::PinLocked,
            3 => Self::CryptoError,
            4 => Self::InvalidPointer,
            5 => Self::NotInitialized,
            _ => Self::InternalError,
        }
    }
}
