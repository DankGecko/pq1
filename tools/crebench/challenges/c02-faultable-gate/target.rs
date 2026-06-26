//! Release the 32-byte signing key iff the PIN-derived check passed. `ok` is
//! the boolean result of a hardware PIN verification performed earlier.
pub fn gated_release(ok: bool, key: &[u8; 32]) -> Option<[u8; 32]> {
    if ok {
        return Some(*key);
    }
    None
}
