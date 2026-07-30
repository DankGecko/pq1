//! The arm token in TAMP backup registers `BKP8..31` (FROZEN-JRN-IFACE-3
//! + §6.2 L2028–2062): 24 words of magic/slot-code/complement fields,
//! seals, binding hash, and the state pair. `BKP0..7` remain the
//! exclusive BHK allocation and are not modeled here.
//!
//! Compile-time pins prove the layout offsets, complement pairs, slot
//! codes, state-pair Hamming distances (32 over the 64-bit pair), and the
//! 139-byte `PQFW_A3` binding preimage length.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use fw_manifest::v6::PhysicalSlot;

// ---------------------------------------------------------------------------
// Frozen constants (§6.2 L2031–2062)
// ---------------------------------------------------------------------------

/// The token spans exactly BKP8..=31 (24 words).
pub const TOKEN_WORDS: usize = 24;
/// First backup register owned by the token.
pub const TOKEN_FIRST_REG: u8 = 8;
/// Last backup register owned by the token.
pub const TOKEN_LAST_REG: u8 = 31;

pub const MAGIC_ARM3: u32 = 0x4152_4D33;
pub const MAGIC_B2CC: u32 = 0xBEAD_B2CC;
pub const SEAL_0: (u32, u32) = (0x1357_9BDF, 0xECA8_6420);
pub const SEAL_1: (u32, u32) = (0x2468_ACE0, 0xDB97_531F);

/// Physical slot codes `(code, complement)`.
pub const SLOT_CODE_A: (u32, u32) = (0x3C3C_A5A5, 0xC3C3_5A5A);
/// See [`SLOT_CODE_A`].
pub const SLOT_CODE_B: (u32, u32) = (0x9696_6969, 0x6969_9696);

/// State pairs `(state, complement)`.
pub const STATE_INVALID: (u32, u32) = (0xA5A5_A5A5, 0x5A5A_5A5A);
/// `ARM_READY`: a bound candidate awaits its one handoff.
pub const STATE_ARM_READY: (u32, u32) = (0x3C3C_3C3C, 0xC3C3_C3C3);
/// `ATTEMPTED`: the candidate consumed its one handoff.
pub const STATE_ATTEMPTED: (u32, u32) = (0x9696_9696, 0x6969_6969);

/// Word offsets within the 24-word token (BKP8 == offset 0).
pub const WORD_MAGIC: usize = 0;
pub const WORD_SLOT_CODE: usize = 2;
pub const WORD_R: usize = 4;
pub const WORD_E: usize = 6;
pub const WORD_T: usize = 8;
pub const WORD_BINDING: usize = 10;
pub const WORD_SEAL_0: usize = 18;
pub const WORD_SEAL_1: usize = 20;
pub const WORD_STATE: usize = 22;

/// Exact 7-byte binding domain.
pub const ARM_TOKEN_DOMAIN: &[u8; 7] = b"PQFW_A3";
/// Exact 7-byte PIN-budget state (`CleanPinBudget` CLEAN10): full clean
/// (ten attempts remaining) is the only accepted arming state
/// (FROZEN-JRN-IFACE-3 L462–468).
pub const PIN_BUDGET_STATE: &[u8; 7] = b"CLEAN10";
/// Binding preimage length: 7 + 1 + 4 + 4 + 4 + 16 + 32 + 32 + 32 + 7.
pub const ARM_TOKEN_PREIMAGE_LEN: usize = 139;

/// `R`/`E` validity range (same as the manifest core).
pub const VERSION_MIN: u32 = 1;
/// See [`VERSION_MIN`].
pub const VERSION_MAX: u32 = 0xFFFF_FFFE;
/// `T` must additionally satisfy `T <= 0xFFFF_FFFD` so no reserved
/// sentinel can reach the writer (§10 L3577–3580).
pub const T_MAX: u32 = 0xFFFF_FFFD;

// ---------------------------------------------------------------------------
// Compile-time pins
// ---------------------------------------------------------------------------

const fn hd(a: u32, b: u32) -> u32 {
    (a ^ b).count_ones()
}

const _: () = assert!(TOKEN_WORDS == 24);
const _: () = assert!(TOKEN_LAST_REG - TOKEN_FIRST_REG + 1 == TOKEN_WORDS as u8);
const _: () = assert!(ARM_TOKEN_PREIMAGE_LEN == 7 + 1 + 4 + 4 + 4 + 16 + 32 + 32 + 32 + 7);
// Complement pairs.
const _: () = assert!(SLOT_CODE_A.1 == !SLOT_CODE_A.0);
const _: () = assert!(SLOT_CODE_B.1 == !SLOT_CODE_B.0);
const _: () = assert!(STATE_INVALID.1 == !STATE_INVALID.0);
const _: () = assert!(STATE_ARM_READY.1 == !STATE_ARM_READY.0);
const _: () = assert!(STATE_ATTEMPTED.1 == !STATE_ATTEMPTED.0);
const _: () = assert!(SEAL_0.1 == !SEAL_0.0);
const _: () = assert!(SEAL_1.1 == !SEAL_1.0);
// Each valid state pair is Hamming distance 32 from either other pair
// (over the 64-bit (state, complement) concatenation).
const _: () = assert!(hd(STATE_ARM_READY.0, STATE_ATTEMPTED.0) + hd(STATE_ARM_READY.1, STATE_ATTEMPTED.1) == 32);
const _: () = assert!(hd(STATE_ARM_READY.0, STATE_INVALID.0) + hd(STATE_ARM_READY.1, STATE_INVALID.1) == 32);
const _: () = assert!(hd(STATE_ATTEMPTED.0, STATE_INVALID.0) + hd(STATE_ATTEMPTED.1, STATE_INVALID.1) == 32);
// Reset (0,0) is not any valid state.
const _: () = assert!(STATE_ARM_READY.0 != 0 && STATE_ATTEMPTED.0 != 0);

// ---------------------------------------------------------------------------
// State + binding
// ---------------------------------------------------------------------------

/// The two live token states. `INVALID` (and reset `(0,0)` and every
/// one-word transition intermediate) is never a valid state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArmState {
    ArmReady,
    Attempted,
}

impl ArmState {
    pub const fn pair(self) -> (u32, u32) {
        match self {
            ArmState::ArmReady => STATE_ARM_READY,
            ArmState::Attempted => STATE_ATTEMPTED,
        }
    }
}

/// Everything the binding hash commits to: this installation, candidate,
/// fallback manifest, and boot/session (FROZEN-JRN-IFACE-3 L462–464).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArmBinding {
    pub slot: PhysicalSlot,
    pub r: u32,
    pub e: u32,
    /// Checked `T = E - 1`; additionally `T <= 0xFFFF_FFFD`.
    pub t: u32,
    pub install_id: [u8; 16],
    pub manifest_digest: [u8; 32],
    pub secure_hash: [u8; 32],
    pub nonsecure_hash: [u8; 32],
}

impl ArmBinding {
    /// The exact 139-byte preimage:
    /// `domain[7] || slot || R || E || T || install_id[16] ||
    /// manifest_digest[32] || secure_hash[32] || nonsecure_hash[32] ||
    /// PIN_BUDGET_STATE[7]` (integers big-endian).
    pub fn preimage(&self) -> [u8; ARM_TOKEN_PREIMAGE_LEN] {
        let mut p = [0u8; ARM_TOKEN_PREIMAGE_LEN];
        p[0..7].copy_from_slice(ARM_TOKEN_DOMAIN);
        p[7] = self.slot.to_u8();
        p[8..12].copy_from_slice(&self.r.to_be_bytes());
        p[12..16].copy_from_slice(&self.e.to_be_bytes());
        p[16..20].copy_from_slice(&self.t.to_be_bytes());
        p[20..36].copy_from_slice(&self.install_id);
        p[36..68].copy_from_slice(&self.manifest_digest);
        p[68..100].copy_from_slice(&self.secure_hash);
        p[100..132].copy_from_slice(&self.nonsecure_hash);
        p[132..139].copy_from_slice(PIN_BUDGET_STATE);
        p
    }

    /// `SHA-256(preimage)`.
    pub fn binding_hash(&self) -> [u8; 32] {
        Sha256::digest(self.preimage()).into()
    }
}

/// What a token decode can reject on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenError {
    BadMagic,
    BadSlotCode,
    BadComplement,
    BadSeal,
    BadState,
    OutOfRangeVersion,
    /// Checked `T != E - 1` or `T > 0xFFFF_FFFD`.
    InconsistentTarget,
    /// Recomputed binding hash mismatch (corruption, wrong artifact, or
    /// companion-supplied values — the decoder never trusts those).
    BindingMismatch,
    /// Token's physical slot does not match the expected slot.
    SlotMismatch,
}

/// A structurally valid token before binding verification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StructuralToken {
    pub state: ArmState,
    pub slot: PhysicalSlot,
    pub r: u32,
    pub e: u32,
    pub t: u32,
    stored_binding_hash: [u8; 32],
}

/// A decoded, structurally valid arm token whose binding matched the
/// supplied artifact fields. Deliberately NOT `Copy`/`Clone`: a live
/// token is a one-time arming capability owned linearly by the intent
/// that consumed it (FROZEN-JRN-IFACE-3 at-most-once discipline).
#[derive(PartialEq, Eq, Debug)]
pub struct ArmToken {
    pub state: ArmState,
    pub binding: ArmBinding,
}

fn slot_code(slot: PhysicalSlot) -> (u32, u32) {
    match slot {
        PhysicalSlot::A => SLOT_CODE_A,
        PhysicalSlot::B => SLOT_CODE_B,
    }
}

impl ArmToken {
    /// Structural decode only: magic, slot code + complement, R/E/T
    /// complement pairs, seals, state pair, ranges, checked `T == E - 1`,
    /// `T <= T_MAX`. Does NOT check the binding hash — see
    /// [`ArmToken::decode_and_bind`].
    pub fn decode_structure(words: &[u32; TOKEN_WORDS]) -> Result<StructuralToken, TokenError> {
        if words[WORD_MAGIC] != MAGIC_ARM3 || words[WORD_MAGIC + 1] != MAGIC_B2CC {
            return Err(TokenError::BadMagic);
        }
        let slot = if (words[WORD_SLOT_CODE], words[WORD_SLOT_CODE + 1]) == SLOT_CODE_A {
            PhysicalSlot::A
        } else if (words[WORD_SLOT_CODE], words[WORD_SLOT_CODE + 1]) == SLOT_CODE_B {
            PhysicalSlot::B
        } else {
            return Err(TokenError::BadSlotCode);
        };
        let (r, e, t) = (words[WORD_R], words[WORD_E], words[WORD_T]);
        if words[WORD_R + 1] != !r || words[WORD_E + 1] != !e || words[WORD_T + 1] != !t {
            return Err(TokenError::BadComplement);
        }
        if (words[WORD_SEAL_0], words[WORD_SEAL_0 + 1]) != SEAL_0
            || (words[WORD_SEAL_1], words[WORD_SEAL_1 + 1]) != SEAL_1
        {
            return Err(TokenError::BadSeal);
        }
        let state = match (words[WORD_STATE], words[WORD_STATE + 1]) {
            STATE_ARM_READY => ArmState::ArmReady,
            STATE_ATTEMPTED => ArmState::Attempted,
            _ => return Err(TokenError::BadState),
        };
        if !(VERSION_MIN..=VERSION_MAX).contains(&r) {
            return Err(TokenError::OutOfRangeVersion);
        }
        if !(VERSION_MIN..=VERSION_MAX).contains(&e) {
            return Err(TokenError::OutOfRangeVersion);
        }
        if t > T_MAX || e.checked_sub(1) != Some(t) {
            return Err(TokenError::InconsistentTarget);
        }
        let mut stored_binding_hash = [0u8; 32];
        for i in 0..8 {
            stored_binding_hash[i * 4..i * 4 + 4]
                .copy_from_slice(&words[WORD_BINDING + i].to_be_bytes());
        }
        Ok(StructuralToken {
            state,
            slot,
            r,
            e,
            t,
            stored_binding_hash,
        })
    }

    /// Full decode: structural checks PLUS slot match and a recomputed
    /// binding against the supplied artifact identity fields (install id,
    /// manifest digest, image hashes). A binding-mismatched token grants
    /// no authority (§6.2 L2191–2193).
    pub fn decode_and_bind(
        words: &[u32; TOKEN_WORDS],
        expected_slot: PhysicalSlot,
        install_id: &[u8; 16],
        manifest_digest: &[u8; 32],
        secure_hash: &[u8; 32],
        nonsecure_hash: &[u8; 32],
    ) -> Result<ArmToken, TokenError> {
        let structural = ArmToken::decode_structure(words)?;
        let binding = ArmBinding {
            slot: structural.slot,
            r: structural.r,
            e: structural.e,
            t: structural.t,
            install_id: *install_id,
            manifest_digest: *manifest_digest,
            secure_hash: *secure_hash,
            nonsecure_hash: *nonsecure_hash,
        };
        if binding.slot != expected_slot {
            return Err(TokenError::SlotMismatch);
        }
        if !bool::from(
            binding
                .binding_hash()
                .ct_eq(&structural.stored_binding_hash),
        ) {
            return Err(TokenError::BindingMismatch);
        }
        Ok(ArmToken {
            state: structural.state,
            binding,
        })
    }

    /// Encode a token (writer side; used by the fake backend and tests).
    pub fn encode(state: ArmState, binding: &ArmBinding) -> [u32; TOKEN_WORDS] {
        let mut w = [0u32; TOKEN_WORDS];
        w[WORD_MAGIC] = MAGIC_ARM3;
        w[WORD_MAGIC + 1] = MAGIC_B2CC;
        let (code, code_inv) = slot_code(binding.slot);
        w[WORD_SLOT_CODE] = code;
        w[WORD_SLOT_CODE + 1] = code_inv;
        w[WORD_R] = binding.r;
        w[WORD_R + 1] = !binding.r;
        w[WORD_E] = binding.e;
        w[WORD_E + 1] = !binding.e;
        w[WORD_T] = binding.t;
        w[WORD_T + 1] = !binding.t;
        let hash = binding.binding_hash();
        for i in 0..8 {
            let mut word = [0u8; 4];
            word.copy_from_slice(&hash[i * 4..i * 4 + 4]);
            w[WORD_BINDING + i] = u32::from_be_bytes(word);
        }
        w[WORD_SEAL_0] = SEAL_0.0;
        w[WORD_SEAL_0 + 1] = SEAL_0.1;
        w[WORD_SEAL_1] = SEAL_1.0;
        w[WORD_SEAL_1 + 1] = SEAL_1.1;
        let (s, s_inv) = state.pair();
        w[WORD_STATE] = s;
        w[WORD_STATE + 1] = s_inv;
        w
    }
}
