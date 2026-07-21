//! Shared authenticated-field admissibility policy.
//!
//! The host compiler knows the Solidity / EIP-712 terminal type, while the
//! device receives only compact authenticated IR.  Schema v6 carries one
//! mandatory [`TerminalKind`] byte in every field's parameter blob plus the
//! original ABI width for integer terminals.  Both sides execute this module's
//! same exhaustive matrix before a field can be admitted or rendered.  Keeping
//! the matrix here prevents compiler completeness accounting, nested address
//! coverage, and the device preflight from assigning different meaning to the
//! same formatter opcode.

use crate::ir::FormatOp;

/// Authenticated semantic kind of the value reached by a field path.
///
/// Values are wire constants carried by `PARAM_TERMINAL_KIND`.  Arrays carry
/// the kind of each rendered element; array-ness remains explicit in the path
/// bytecode (`ArrayAll`).  These values were introduced by schema v4 and remain
/// byte-for-byte stable in schema v6; do not renumber them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TerminalKind {
    Unsigned = 0x01,
    Signed = 0x02,
    Address = 0x03,
    Bool = 0x04,
    FixedBytes = 0x05,
    DynamicString = 0x06,
    DynamicBytes = 0x07,
    ConstantText = 0x08,
    NestedStruct = 0x09,
    /// The signed EIP-712 member is the 32-byte `keccak256(string_bytes)` word.
    /// A separately supplied exact preimage may be displayed only after the
    /// renderer authenticates it against that word. This is deliberately not
    /// [`DynamicString`](Self::DynamicString), whose `FollowOffset` semantics
    /// belong exclusively to contract calldata.
    Eip712StringHashWord = 0x0A,
}

impl TerminalKind {
    pub const ALL: [Self; 10] = [
        Self::Unsigned,
        Self::Signed,
        Self::Address,
        Self::Bool,
        Self::FixedBytes,
        Self::DynamicString,
        Self::DynamicBytes,
        Self::ConstantText,
        Self::NestedStruct,
        Self::Eip712StringHashWord,
    ];
}

impl TryFrom<u8> for TerminalKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Unsigned),
            0x02 => Ok(Self::Signed),
            0x03 => Ok(Self::Address),
            0x04 => Ok(Self::Bool),
            0x05 => Ok(Self::FixedBytes),
            0x06 => Ok(Self::DynamicString),
            0x07 => Ok(Self::DynamicBytes),
            0x08 => Ok(Self::ConstantText),
            0x09 => Ok(Self::NestedStruct),
            0x0A => Ok(Self::Eip712StringHashWord),
            _ => Err(()),
        }
    }
}

/// Return whether a 32-byte ABI word is the canonical encoding of an integer
/// terminal with the authenticated width `width_bytes`.
///
/// Unsigned narrow integers must have an all-zero prefix. Signed narrow
/// integers must have the exact sign-extension prefix selected by the high bit
/// of the first retained byte. Full-width (32-byte) integer words preserve all
/// bits. Invalid widths and non-integer terminal kinds always fail closed.
#[must_use]
pub const fn integer_word_is_canonical(
    kind: TerminalKind,
    width_bytes: u8,
    word: &[u8; 32],
) -> bool {
    if width_bytes == 0 || width_bytes > 32 {
        return false;
    }

    let prefix_len = 32 - width_bytes as usize;
    let prefix_byte = match kind {
        TerminalKind::Unsigned => 0x00,
        TerminalKind::Signed => {
            if word[prefix_len] & 0x80 == 0 {
                0x00
            } else {
                0xff
            }
        }
        _ => return false,
    };

    let mut index = 0usize;
    while index < prefix_len {
        if word[index] != prefix_byte {
            return false;
        }
        index += 1;
    }
    true
}

/// Semantic parameter-presence bitmap.  Visibility's selector byte and the
/// mandatory terminal-kind and integer-width bytes are carried separately.
/// The interpolation program is format metadata and the exact-word guard is an
/// orthogonal precondition; both are stripped before this field-local policy
/// runs and validated by `Erc7730Ir`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParamMask(u32);

impl ParamMask {
    pub const TOKEN_PATH: Self = Self(1 << 0);
    pub const TOKEN: Self = Self(1 << 1);
    pub const THRESHOLD: Self = Self(1 << 2);
    pub const MESSAGE: Self = Self(1 << 3);
    pub const ADDR_TYPES: Self = Self(1 << 4);
    pub const ADDR_SOURCES: Self = Self(1 << 5);
    pub const DATE_ENCODING: Self = Self(1 << 6);
    pub const ENUM_REF: Self = Self(1 << 7);
    pub const DECIMALS: Self = Self(1 << 8);
    pub const BASE: Self = Self(1 << 9);
    pub const PREFIX: Self = Self(1 << 10);
    pub const SUFFIX: Self = Self(1 << 11);
    pub const NESTED_SELECTOR: Self = Self(1 << 12);
    pub const NESTED_CALLEE: Self = Self(1 << 13);
    pub const FALLBACK_LABEL: Self = Self(1 << 14);
    pub const CONST_VALUE: Self = Self(1 << 15);
    pub const VISIBILITY_VALUES: Self = Self(1 << 16);
    pub const NESTED_STRUCT: Self = Self(1 << 17);
    pub const NATIVE_CURRENCY: Self = Self(1 << 18);
    pub const DYNAMIC_KIND: Self = Self(1 << 19);
    pub const NFT_COLLECTION: Self = Self(1 << 20);
    pub const NFT_COLLECTION_PATH: Self = Self(1 << 21);
    pub const SENDER_ADDRESS: Self = Self(1 << 22);
    pub const EXACT_EMPTY_BYTES: Self = Self(1 << 23);
    pub const EIP712_STRING_PREIMAGE: Self = Self(1 << 24);

    pub const NONE: Self = Self(0);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    #[must_use]
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// A label that is empty or consists only of display-padding spaces has no
/// visible semantic role.  Both compiler and device use this exact predicate.
#[must_use]
pub fn label_has_visible_glyph(label: &[u8]) -> bool {
    label.iter().any(|&byte| byte != b' ')
}

/// Why a field failed the shared policy.  Host code maps this to a detailed
/// build diagnostic; the device maps every variant to a hard refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    FormatterType,
    ParameterApplicability,
    ParameterRequirement,
    UnsupportedFormatter,
}

/// A direct field path is credited as displaying its signed terminal value
/// only when this returns true.  Since [`validate_field`] has already enforced
/// the exact type matrix, every accepted formatter is injective or falls back
/// to an exact raw representation for this terminal class.
#[must_use]
pub const fn directly_displays_terminal(op: FormatOp, kind: TerminalKind) -> bool {
    formatter_accepts_terminal(op, kind)
        && !matches!(op, FormatOp::Calldata | FormatOp::Encrypted)
        && !matches!(kind, TerminalKind::NestedStruct)
}

/// Only `tokenAmount` consumes `tokenPath` and necessarily appends either a
/// verified identity or a loud full unverified address page.  No other
/// formatter may receive address-coverage credit for that parameter.
#[must_use]
pub const fn token_path_displays_identity(op: FormatOp, kind: TerminalKind) -> bool {
    matches!(op, FormatOp::TokenAmount) && matches!(kind, TerminalKind::Unsigned)
}

/// Complete formatter × authenticated-terminal-kind allowlist.
#[must_use]
pub const fn formatter_accepts_terminal(op: FormatOp, kind: TerminalKind) -> bool {
    match op {
        FormatOp::Raw => matches!(
            kind,
            TerminalKind::Unsigned
                | TerminalKind::Signed
                | TerminalKind::Address
                | TerminalKind::Bool
                | TerminalKind::FixedBytes
                | TerminalKind::DynamicString
                | TerminalKind::DynamicBytes
                | TerminalKind::ConstantText
                | TerminalKind::NestedStruct
                | TerminalKind::Eip712StringHashWord
        ),
        FormatOp::Amount
        | FormatOp::TokenAmount
        | FormatOp::NftName
        | FormatOp::Date
        | FormatOp::Duration
        | FormatOp::Unit
        | FormatOp::ChainId => matches!(kind, TerminalKind::Unsigned),
        FormatOp::Enum => matches!(kind, TerminalKind::Unsigned | TerminalKind::Bool),
        FormatOp::AddressName | FormatOp::TokenTicker | FormatOp::InteroperableAddressName => {
            matches!(kind, TerminalKind::Address)
        }
        // The nested renderer is still gated by an exact parent enrollment and
        // does not directly display this terminal.  This field-local rule only
        // permits the authenticated bytes + callee metadata shape; deep IR
        // validation owns the parent identity, ordinal, and path checks.
        FormatOp::UniswapV3Path => matches!(kind, TerminalKind::DynamicBytes),
        FormatOp::Calldata => matches!(kind, TerminalKind::DynamicBytes),
        // No honest successful renderer exists for encrypted data.
        FormatOp::Encrypted => false,
    }
}

/// Validate one field's formatter, semantic parameters, and authenticated
/// terminal kind.  This function is deliberately exhaustive over every
/// `FormatOp`; adding a formatter requires choosing both type and parameter
/// semantics here before either compiler or device accepts it.
pub const fn validate_field(
    op: FormatOp,
    kind: TerminalKind,
    params: ParamMask,
) -> Result<(), PolicyError> {
    if !formatter_accepts_terminal(op, kind) {
        return if matches!(op, FormatOp::Encrypted) {
            Err(PolicyError::UnsupportedFormatter)
        } else {
            Err(PolicyError::FormatterType)
        };
    }

    let (allowed, required) = match op {
        FormatOp::Raw => match kind {
            TerminalKind::DynamicString => (ParamMask::DYNAMIC_KIND, ParamMask::DYNAMIC_KIND),
            TerminalKind::DynamicBytes => (
                ParamMask::DYNAMIC_KIND.union(ParamMask::EXACT_EMPTY_BYTES),
                ParamMask::DYNAMIC_KIND.union(ParamMask::EXACT_EMPTY_BYTES),
            ),
            TerminalKind::ConstantText => (ParamMask::CONST_VALUE, ParamMask::CONST_VALUE),
            TerminalKind::NestedStruct => (ParamMask::NESTED_STRUCT, ParamMask::NESTED_STRUCT),
            TerminalKind::Eip712StringHashWord => (
                ParamMask::EIP712_STRING_PREIMAGE,
                ParamMask::EIP712_STRING_PREIMAGE,
            ),
            _ => (ParamMask::NONE, ParamMask::NONE),
        },
        FormatOp::Amount | FormatOp::Duration | FormatOp::ChainId => {
            (ParamMask::NONE, ParamMask::NONE)
        }
        FormatOp::TokenAmount => (
            ParamMask::TOKEN_PATH
                .union(ParamMask::TOKEN)
                .union(ParamMask::THRESHOLD)
                .union(ParamMask::MESSAGE)
                .union(ParamMask::NATIVE_CURRENCY),
            ParamMask::NONE,
        ),
        FormatOp::NftName => (
            ParamMask::NFT_COLLECTION.union(ParamMask::NFT_COLLECTION_PATH),
            ParamMask::NONE,
        ),
        FormatOp::Date => (ParamMask::DATE_ENCODING, ParamMask::NONE),
        FormatOp::AddressName => (
            ParamMask::ADDR_TYPES
                .union(ParamMask::ADDR_SOURCES)
                .union(ParamMask::SENDER_ADDRESS),
            ParamMask::NONE,
        ),
        FormatOp::Enum => (ParamMask::ENUM_REF, ParamMask::ENUM_REF),
        FormatOp::Unit => (
            ParamMask::BASE
                .union(ParamMask::DECIMALS)
                .union(ParamMask::PREFIX),
            ParamMask::BASE,
        ),
        FormatOp::TokenTicker | FormatOp::InteroperableAddressName => {
            (ParamMask::NONE, ParamMask::NONE)
        }
        FormatOp::UniswapV3Path => (ParamMask::DYNAMIC_KIND, ParamMask::DYNAMIC_KIND),
        FormatOp::Calldata => (
            ParamMask::DYNAMIC_KIND.union(ParamMask::NESTED_CALLEE),
            ParamMask::DYNAMIC_KIND.union(ParamMask::NESTED_CALLEE),
        ),
        FormatOp::Encrypted => return Err(PolicyError::UnsupportedFormatter),
    };

    if !params.is_subset_of(allowed) {
        return Err(PolicyError::ParameterApplicability);
    }
    if !params.contains(required) {
        return Err(PolicyError::ParameterRequirement);
    }

    // Formatter-specific relationships that a simple allowed/required mask
    // cannot express.
    if matches!(op, FormatOp::TokenAmount) {
        let has_path = params.contains(ParamMask::TOKEN_PATH);
        let has_literal = params.contains(ParamMask::TOKEN);
        // ERC-7730 permits an amount with no token identity.  The renderer
        // treats it as an unbound exact/raw amount (and marks threshold text
        // unverified); it must not be mistaken for tokenPath coverage.  Two
        // competing identity sources, however, are non-canonical.
        if has_path && has_literal
            || params.contains(ParamMask::MESSAGE) && !params.contains(ParamMask::THRESHOLD)
            || params.contains(ParamMask::NATIVE_CURRENCY) && !(has_path || has_literal)
        {
            return Err(PolicyError::ParameterRequirement);
        }
    }
    if matches!(op, FormatOp::NftName)
        && params.contains(ParamMask::NFT_COLLECTION)
            == params.contains(ParamMask::NFT_COLLECTION_PATH)
    {
        return Err(PolicyError::ParameterRequirement);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_is_total_and_known_good_pairs_are_exact() {
        for op in FormatOp::ALL {
            for kind in TerminalKind::ALL {
                let _ = formatter_accepts_terminal(op, kind);
                let _ = directly_displays_terminal(op, kind);
            }
        }
        assert!(formatter_accepts_terminal(
            FormatOp::AddressName,
            TerminalKind::Address
        ));
        assert!(!formatter_accepts_terminal(
            FormatOp::AddressName,
            TerminalKind::Unsigned
        ));
        assert!(formatter_accepts_terminal(
            FormatOp::Duration,
            TerminalKind::Unsigned
        ));
        assert!(!formatter_accepts_terminal(
            FormatOp::Duration,
            TerminalKind::Address
        ));
        assert!(formatter_accepts_terminal(
            FormatOp::Enum,
            TerminalKind::Unsigned
        ));
        assert!(formatter_accepts_terminal(
            FormatOp::Enum,
            TerminalKind::Bool
        ));
        assert!(!formatter_accepts_terminal(
            FormatOp::Enum,
            TerminalKind::Signed
        ));
        assert!(!formatter_accepts_terminal(
            FormatOp::Encrypted,
            TerminalKind::FixedBytes
        ));
        assert!(formatter_accepts_terminal(
            FormatOp::Calldata,
            TerminalKind::DynamicBytes
        ));
        assert!(!formatter_accepts_terminal(
            FormatOp::Calldata,
            TerminalKind::FixedBytes
        ));
    }

    #[test]
    fn integer_word_canonicality_covers_every_byte_width() {
        for width in 1u8..=32 {
            let prefix_len = 32 - width as usize;

            let zero = [0u8; 32];
            assert!(integer_word_is_canonical(
                TerminalKind::Unsigned,
                width,
                &zero
            ));
            assert!(integer_word_is_canonical(
                TerminalKind::Signed,
                width,
                &zero
            ));

            let mut unsigned_max = [0u8; 32];
            unsigned_max[prefix_len..].fill(0xff);
            assert!(integer_word_is_canonical(
                TerminalKind::Unsigned,
                width,
                &unsigned_max
            ));

            let mut signed_max = [0u8; 32];
            signed_max[prefix_len] = 0x7f;
            signed_max[prefix_len + 1..].fill(0xff);
            assert!(integer_word_is_canonical(
                TerminalKind::Signed,
                width,
                &signed_max
            ));

            let negative_one = [0xffu8; 32];
            assert!(integer_word_is_canonical(
                TerminalKind::Signed,
                width,
                &negative_one
            ));

            let mut signed_min = [0xffu8; 32];
            signed_min[prefix_len] = 0x80;
            signed_min[prefix_len + 1..].fill(0x00);
            assert!(integer_word_is_canonical(
                TerminalKind::Signed,
                width,
                &signed_min
            ));

            if width < 32 {
                let mut dirty_unsigned = zero;
                dirty_unsigned[prefix_len - 1] = 1;
                assert!(!integer_word_is_canonical(
                    TerminalKind::Unsigned,
                    width,
                    &dirty_unsigned
                ));

                let mut missing_sign_extension = zero;
                missing_sign_extension[prefix_len] = 0x80;
                assert!(!integer_word_is_canonical(
                    TerminalKind::Signed,
                    width,
                    &missing_sign_extension
                ));

                let mut dirty_positive_extension = [0xffu8; 32];
                dirty_positive_extension[prefix_len] = 0x7f;
                assert!(!integer_word_is_canonical(
                    TerminalKind::Signed,
                    width,
                    &dirty_positive_extension
                ));
            }
        }
    }

    #[test]
    fn integer_word_canonicality_is_fail_closed_and_preserves_full_width() {
        let arbitrary = [
            0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        for kind in [TerminalKind::Unsigned, TerminalKind::Signed] {
            assert!(integer_word_is_canonical(kind, 32, &arbitrary));
            for invalid_width in [0, 33, u8::MAX] {
                assert!(!integer_word_is_canonical(kind, invalid_width, &arbitrary));
            }
        }
        for kind in TerminalKind::ALL {
            if !matches!(kind, TerminalKind::Unsigned | TerminalKind::Signed) {
                assert!(!integer_word_is_canonical(kind, 32, &arbitrary));
            }
        }
    }

    #[test]
    fn parameter_policy_rejects_ignored_semantics() {
        assert_eq!(
            validate_field(FormatOp::Raw, TerminalKind::Unsigned, ParamMask::TOKEN_PATH),
            Err(PolicyError::ParameterApplicability)
        );
        assert_eq!(
            validate_field(FormatOp::Enum, TerminalKind::Unsigned, ParamMask::NONE),
            Err(PolicyError::ParameterRequirement)
        );
        assert_eq!(
            validate_field(FormatOp::Enum, TerminalKind::Bool, ParamMask::NONE),
            Err(PolicyError::ParameterRequirement)
        );
        assert!(validate_field(FormatOp::Enum, TerminalKind::Bool, ParamMask::ENUM_REF).is_ok());
        assert!(validate_field(
            FormatOp::TokenAmount,
            TerminalKind::Unsigned,
            ParamMask::TOKEN_PATH.union(ParamMask::THRESHOLD)
        )
        .is_ok());
        assert!(validate_field(
            FormatOp::TokenAmount,
            TerminalKind::Unsigned,
            ParamMask::TOKEN_PATH.union(ParamMask::TOKEN)
        )
        .is_err());
        assert!(validate_field(
            FormatOp::TokenAmount,
            TerminalKind::Unsigned,
            ParamMask::THRESHOLD.union(ParamMask::MESSAGE)
        )
        .is_ok());
        assert!(validate_field(
            FormatOp::AddressName,
            TerminalKind::Address,
            ParamMask::SENDER_ADDRESS
        )
        .is_ok());
        assert_eq!(
            validate_field(
                FormatOp::InteroperableAddressName,
                TerminalKind::Address,
                ParamMask::SENDER_ADDRESS
            ),
            Err(PolicyError::ParameterApplicability)
        );
        assert_eq!(
            validate_field(
                FormatOp::Raw,
                TerminalKind::Address,
                ParamMask::SENDER_ADDRESS
            ),
            Err(PolicyError::ParameterApplicability)
        );
        assert_eq!(
            validate_field(
                FormatOp::Raw,
                TerminalKind::DynamicBytes,
                ParamMask::DYNAMIC_KIND
            ),
            Err(PolicyError::ParameterRequirement)
        );
        assert!(validate_field(
            FormatOp::Raw,
            TerminalKind::DynamicBytes,
            ParamMask::DYNAMIC_KIND.union(ParamMask::EXACT_EMPTY_BYTES)
        )
        .is_ok());
        assert_eq!(
            validate_field(
                FormatOp::Raw,
                TerminalKind::DynamicString,
                ParamMask::DYNAMIC_KIND.union(ParamMask::EXACT_EMPTY_BYTES)
            ),
            Err(PolicyError::ParameterApplicability)
        );
        assert_eq!(
            validate_field(
                FormatOp::UniswapV3Path,
                TerminalKind::DynamicBytes,
                ParamMask::DYNAMIC_KIND.union(ParamMask::EXACT_EMPTY_BYTES)
            ),
            Err(PolicyError::ParameterApplicability)
        );
        assert!(validate_field(
            FormatOp::Raw,
            TerminalKind::Eip712StringHashWord,
            ParamMask::EIP712_STRING_PREIMAGE
        )
        .is_ok());
        assert_eq!(
            validate_field(
                FormatOp::Raw,
                TerminalKind::Eip712StringHashWord,
                ParamMask::NONE
            ),
            Err(PolicyError::ParameterRequirement)
        );
        assert_eq!(
            validate_field(
                FormatOp::Raw,
                TerminalKind::Eip712StringHashWord,
                ParamMask::EIP712_STRING_PREIMAGE.union(ParamMask::DYNAMIC_KIND)
            ),
            Err(PolicyError::ParameterApplicability)
        );
        assert_eq!(
            validate_field(
                FormatOp::Amount,
                TerminalKind::Eip712StringHashWord,
                ParamMask::EIP712_STRING_PREIMAGE
            ),
            Err(PolicyError::FormatterType)
        );
        let calldata_params = ParamMask::DYNAMIC_KIND.union(ParamMask::NESTED_CALLEE);
        assert!(validate_field(
            FormatOp::Calldata,
            TerminalKind::DynamicBytes,
            calldata_params
        )
        .is_ok());
        assert_eq!(
            validate_field(
                FormatOp::Calldata,
                TerminalKind::DynamicBytes,
                calldata_params.union(ParamMask::NESTED_SELECTOR)
            ),
            Err(PolicyError::ParameterApplicability)
        );
        assert_eq!(
            validate_field(
                FormatOp::Calldata,
                TerminalKind::DynamicBytes,
                ParamMask::DYNAMIC_KIND
            ),
            Err(PolicyError::ParameterRequirement)
        );
    }

    #[test]
    fn only_token_amount_credits_token_path_identity() {
        for op in FormatOp::ALL {
            assert_eq!(
                token_path_displays_identity(op, TerminalKind::Unsigned),
                op == FormatOp::TokenAmount
            );
        }
        assert!(!token_path_displays_identity(
            FormatOp::TokenAmount,
            TerminalKind::Address
        ));
    }
}
