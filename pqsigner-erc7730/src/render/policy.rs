//! Shared authenticated-field admissibility policy.
//!
//! The host compiler knows the Solidity / EIP-712 terminal type, while the
//! device receives only compact authenticated IR.  Schema v4 therefore carries
//! one mandatory [`TerminalKind`] byte in every field's parameter blob.  Both
//! sides execute this module's same exhaustive matrix before a field can be
//! admitted or rendered.  Keeping the matrix here prevents compiler
//! completeness accounting, nested address coverage, and the device preflight
//! from assigning different meaning to the same formatter opcode.

use crate::ir::FormatOp;

/// Authenticated semantic kind of the value reached by a field path.
///
/// Values are wire constants carried by `PARAM_TERMINAL_KIND`.  Arrays carry
/// the kind of each rendered element; array-ness remains explicit in the path
/// bytecode (`ArrayAll`).  Do not renumber after schema v4 ships.
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
}

impl TerminalKind {
    pub const ALL: [Self; 9] = [
        Self::Unsigned,
        Self::Signed,
        Self::Address,
        Self::Bool,
        Self::FixedBytes,
        Self::DynamicString,
        Self::DynamicBytes,
        Self::ConstantText,
        Self::NestedStruct,
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
            _ => Err(()),
        }
    }
}

/// Semantic parameter-presence bitmap.  Visibility's selector byte and the
/// mandatory terminal-kind byte are carried separately.  The interpolation
/// program is format metadata and is stripped before this field-local policy
/// runs; its placement and targets are validated by `Erc7730Ir`.
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
                | TerminalKind::ConstantText
                | TerminalKind::NestedStruct
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
        // Neither has an honest successful renderer in this firmware.  Keep
        // them explicit so adding a new opcode cannot inherit permissive
        // behavior through a wildcard arm.
        FormatOp::Calldata | FormatOp::Encrypted => false,
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
        return if matches!(op, FormatOp::Calldata | FormatOp::Encrypted) {
            Err(PolicyError::UnsupportedFormatter)
        } else {
            Err(PolicyError::FormatterType)
        };
    }

    let (allowed, required) = match op {
        FormatOp::Raw => match kind {
            TerminalKind::DynamicString => (ParamMask::DYNAMIC_KIND, ParamMask::DYNAMIC_KIND),
            TerminalKind::ConstantText => (ParamMask::CONST_VALUE, ParamMask::CONST_VALUE),
            TerminalKind::NestedStruct => (ParamMask::NESTED_STRUCT, ParamMask::NESTED_STRUCT),
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
            ParamMask::ADDR_TYPES.union(ParamMask::ADDR_SOURCES),
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
        FormatOp::Calldata | FormatOp::Encrypted => return Err(PolicyError::UnsupportedFormatter),
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
