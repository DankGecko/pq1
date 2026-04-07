//! Poseidon hash over the BLS12-381 scalar field.
//!
//! Matches the `poseidon-bls12381` npm package used by ZKlarity's Circom
//! circuit. The implementation follows the Hades design strategy:
//!
//!   state = [0, input_0, input_1, ..., input_{N-1}]   (capacity = 0 at index 0)
//!   for RF/2 full rounds:   ARK → S-box(all) → MDS
//!   for RP   partial rounds: ARK → S-box([0]) → MDS
//!   for RF/2 full rounds:   ARK → S-box(all) → MDS
//!   output = state[0]
//!
//! S-box: x^5 (alpha = 5)

use bls12_381::Scalar;
use super::poseidon_constants::{poseidon3, poseidon6, ScalarBytes};

/// Maximum state width (poseidon6 has t=7).
const MAX_T: usize = 8;

/// Convert a 32-byte LE array to a Scalar.
fn scalar_from_le(bytes: &ScalarBytes) -> Scalar {
    Option::from(Scalar::from_bytes(bytes)).expect("invalid scalar")
}

/// x^5 in the scalar field.
#[inline(always)]
fn sbox(x: Scalar) -> Scalar {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Multiply state by the MDS matrix (in-place).
#[inline]
fn mds_mix(state: &mut [Scalar; MAX_T], mds: &[[Scalar; MAX_T]; MAX_T], t: usize) {
    let mut out = [Scalar::zero(); MAX_T];
    for i in 0..t {
        let mut acc = Scalar::zero();
        for k in 0..t {
            acc += mds[i][k] * state[k];
        }
        out[i] = acc;
    }
    for i in 0..t {
        state[i] = out[i];
    }
}

/// Run the Poseidon permutation.
fn poseidon_perm(
    inputs: &[Scalar],
    t: usize,
    rf: usize,
    rp: usize,
    rc: &[ScalarBytes],
    mds_raw: &[[ScalarBytes; MAX_T]; MAX_T],
) -> Scalar {
    let rf_half = rf / 2;

    // Initialize state: [capacity=0, input_0, input_1, ...]
    let mut state = [Scalar::zero(); MAX_T];
    for (i, inp) in inputs.iter().enumerate() {
        state[i + 1] = *inp;
    }

    // Pre-load MDS matrix into Scalars
    let mut mds = [[Scalar::zero(); MAX_T]; MAX_T];
    for i in 0..t {
        for j in 0..t {
            mds[i][j] = scalar_from_le(&mds_raw[i][j]);
        }
    }

    let mut rc_idx = 0;

    // Full rounds (first half)
    for _ in 0..rf_half {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..t {
            state[j] = sbox(state[j]);
        }
        mds_mix(&mut state, &mds, t);
    }

    // Partial rounds
    for _ in 0..rp {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        state[0] = sbox(state[0]);
        mds_mix(&mut state, &mds, t);
    }

    // Full rounds (second half)
    for _ in 0..rf_half {
        for j in 0..t {
            state[j] += scalar_from_le(&rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..t {
            state[j] = sbox(state[j]);
        }
        mds_mix(&mut state, &mds, t);
    }

    state[0]
}

/// Hash N bytes using Poseidon, matching ZKlarity's PoseidonBytes(N) template.
///
/// Bytes are packed into blocks of 31 (big-endian into field elements),
/// padded with zeros to fill the last block. Then Poseidon is applied
/// to the resulting field elements.
///
/// Supports N=164 (calldata, 6 blocks → poseidon6) and N=64 (readable, 3 blocks → poseidon3).
pub fn poseidon_bytes(bytes: &[u8], n: usize) -> Scalar {
    let n_blocks = (n + 30) / 31; // ceil(n / 31)

    // Pack bytes into field elements (31 bytes per element, big-endian)
    let mut fields = [Scalar::zero(); 7]; // max 7 for poseidon6
    let s256 = Scalar::from(256u64);
    for b in 0..n_blocks {
        let mut acc = Scalar::zero();
        for i in 0..31 {
            let idx = b * 31 + i;
            let byte_val = if idx < bytes.len() && idx < n {
                bytes[idx]
            } else {
                0u8
            };
            acc = acc * s256 + Scalar::from(byte_val as u64);
        }
        fields[b] = acc;
    }

    let inputs = &fields[..n_blocks];

    match n_blocks {
        3 => {
            let mut mds = [[[0u8; 32]; MAX_T]; MAX_T];
            for i in 0..poseidon3::T {
                for j in 0..poseidon3::T {
                    mds[i][j] = poseidon3::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon3::T, poseidon3::RF, poseidon3::RP, &poseidon3::RC, &mds)
        }
        6 => {
            let mut mds = [[[0u8; 32]; MAX_T]; MAX_T];
            for i in 0..poseidon6::T {
                for j in 0..poseidon6::T {
                    mds[i][j] = poseidon6::MDS[i][j];
                }
            }
            poseidon_perm(inputs, poseidon6::T, poseidon6::RF, poseidon6::RP, &poseidon6::RC, &mds)
        }
        _ => panic!("unsupported block count"),
    }
}
