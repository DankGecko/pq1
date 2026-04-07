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

/// Maximum size of an unsigned EIP-1559 transaction envelope passed across
/// the gateway. The secure world copies the bytes into its own stack buffer
/// before parsing, so this also bounds that buffer.
pub const MAX_TX_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// Non-secure SRAM boundaries (mps2-an505)
// Used by secure world to validate NS pointers.
// ---------------------------------------------------------------------------

/// mps2-an505: SSRAM-1 NS alias, offset 128KB (secure stack in first 128KB)
pub const NS_SRAM_BASE: u32 = 0x2802_0000;
pub const NS_SRAM_END: u32 = 0x2822_0000;

/// mps2-an505: SSRAM-0 NS alias starting at offset 2 MB (first 2 MB are
/// secure flash). NS firmware code + read-only data lives here. The secure
/// gateway accepts NS-flash pointers as read-only inputs (e.g. an unsigned
/// tx envelope embedded as a `static`), but never as a write target.
pub const NS_FLASH_BASE: u32 = 0x0020_0000;
pub const NS_FLASH_END: u32 = 0x0040_0000;

/// Shared-memory gateway mailbox region (must be excluded from NS pointer
/// validation so NS cannot trick the secure handler into reading from /
/// writing to its own command buffer).
pub const SHARED_MAILBOX_BASE: u32 = 0x2802_FF00;
pub const SHARED_MAILBOX_END: u32 = 0x2802_FF18;

// ---------------------------------------------------------------------------
// Gateway command IDs
// ---------------------------------------------------------------------------

pub const CMD_NONE: u32 = 0;
pub const CMD_GET_REMAINING: u32 = 1;
pub const CMD_REQUEST_UNLOCK: u32 = 2;
pub const CMD_GET_PUBKEY: u32 = 3;
pub const CMD_SIGN: u32 = 4;

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
    UserRejected = 6,
    IdleWipe = 7,
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
            6 => Self::UserRejected,
            7 => Self::IdleWipe,
            _ => Self::InternalError,
        }
    }
}
