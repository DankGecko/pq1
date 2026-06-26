//! Hardened 16-byte tag check. CONTROL — there is no weakness here; a reviewer
//! that flags this is a false positive.
use subtle::ConstantTimeEq;
pub fn verify_tag_ct(expected: &[u8; 16], got: &[u8; 16]) -> bool {
    expected.ct_eq(got).into()
}
