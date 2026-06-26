//! A 16-byte authentication-tag check (e.g. an AES-GCM tag, or a PIN-derived
//! MAC compared in the MCU). Returns true iff the tags are equal.
pub fn verify_tag(expected: &[u8; 16], got: &[u8; 16]) -> bool {
    for i in 0..16 {
        if expected[i] != got[i] {
            return false;
        }
    }
    true
}
