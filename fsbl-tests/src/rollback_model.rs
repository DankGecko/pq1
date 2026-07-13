//! Host-only executable model of the Draft-0.9 journal decoder and selector.
//!
//! This module models only the frozen software boundary.  In particular it
//! does not choose, emulate, or approve a TAMP, flash-durability, ECC, or OTP
//! backend.  A caller must supply already-typed marker observations; this
//! model never derives `BlankVirgin` or `DurablyCleanExact` authority from a
//! raw flash read.  Unit tests use an explicitly named assumption helper only
//! to exercise the frozen byte constants after that external proof boundary.

/// Exact manifest activation marker frozen by Draft 0.9.
pub const QW_PENDING: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x0f,
];

/// Exact manifest acceptance marker frozen by Draft 0.9.
pub const QW_CONFIRMED: [u8; 16] = [
    0xaa, 0x55, 0x99, 0x66, 0xf0, 0x0f, 0xc3, 0x3c, 0x55, 0xaa, 0x66, 0x99, 0x0f, 0xf0, 0x3c, 0xc3,
];

pub const ARM_TOKEN_DOMAIN: &[u8; 7] = b"PQFW_A1";
pub const ARM_TOKEN_PREIMAGE_LEN: usize = 116;

const ARM_MAGIC: (u32, u32) = (0x4152_4d31, 0xbead_b2ce);
const ARM_SEAL_1: (u32, u32) = (0x1357_9bdf, 0xeca8_6420);
const ARM_SEAL_2: (u32, u32) = (0x2468_ace0, 0xdb97_531f);
const STATE_INVALID: (u32, u32) = (0xa5a5_a5a5, 0x5a5a_5a5a);
const STATE_ARM_READY: (u32, u32) = (0x3c3c_3c3c, 0xc3c3_c3c3);
const STATE_ATTEMPTED: (u32, u32) = (0x9696_9696, 0x6969_6969);

pub const MAX_RELEASE_OR_EPOCH: u32 = 0xffff_fffe;
pub const MAX_TARGET_FLOOR: u32 = 0xffff_fffd;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    #[must_use]
    pub const fn manifest_tag(self) -> u8 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    const fn token_code(self) -> (u32, u32) {
        match self {
            Self::A => (0x3c3c_a5a5, 0xc3c3_5a5a),
            Self::B => (0x9696_6969, 0x6969_9696),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkerKind {
    Pending,
    Confirmed,
}

/// Opaque evidence that the still-open journal backend has already proved an
/// exact marker both ECC-clean and durable.  The private field prevents raw
/// bytes outside this module from being elevated to durability authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurablyCleanMarker(MarkerKind);

impl DurablyCleanMarker {
    const fn kind(self) -> MarkerKind {
        self.0
    }
}

/// Opaque evidence that the physical layer proved an all-`0xFF` marker QW
/// virgin, including the independent no-launch condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlankVirginProof(());

/// A marker read after the still-open physical durability/ECC layer has
/// attributed it.  The variants intentionally distinguish an erased virgin
/// QW from an all-FF-looking QW after a possible launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkerObservation {
    BlankVirgin(BlankVirginProof),
    DurablyCleanExact(DurablyCleanMarker),
    UnknownMayHaveLaunched,
    Corrected,
    Uncorrectable,
    Malformed,
}

impl MarkerObservation {
    /// Unit-test-only assumption at the open virginity boundary.
    #[cfg(test)]
    #[must_use]
    const fn assume_blank_virgin_for_test() -> Self {
        Self::BlankVirgin(BlankVirginProof(()))
    }

    /// Unit-test-only assumption at the open durability boundary.
    ///
    /// This validates the frozen exact bytes, but does not pretend that byte
    /// equality proves ECC cleanliness, retention margin, or no interruption.
    /// Production code cannot call this helper.
    #[cfg(test)]
    #[must_use]
    fn assume_durably_clean_for_test(bytes: &[u8; 16]) -> Self {
        if bytes == &QW_PENDING {
            Self::DurablyCleanExact(DurablyCleanMarker(MarkerKind::Pending))
        } else if bytes == &QW_CONFIRMED {
            Self::DurablyCleanExact(DurablyCleanMarker(MarkerKind::Confirmed))
        } else {
            Self::Malformed
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedIdentity {
    pub slot: Slot,
    pub release: u32,
    pub epoch: u32,
    /// Recomputed SHA-256 binding, represented as the eight big-endian words
    /// stored in BKP18..25.
    pub binding_words: [u32; 8],
}

impl VerifiedIdentity {
    #[must_use]
    pub fn target_floor(self) -> Option<u32> {
        if !(1..=MAX_RELEASE_OR_EPOCH).contains(&self.release)
            || !(1..=MAX_RELEASE_OR_EPOCH).contains(&self.epoch)
        {
            return None;
        }
        let target = self.epoch.checked_sub(1)?;
        (target <= MAX_TARGET_FLOOR).then_some(target)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenObservation {
    Missing,
    Words([u32; 24]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmState {
    Ready,
    Attempted,
}

/// Validate the exact BKP8..31 token against a fully verified manifest
/// identity.  The expected binding is recomputed by the caller; token bytes
/// never select their own identity.
#[must_use]
pub fn decode_arm_token(
    observation: &TokenObservation,
    expected: VerifiedIdentity,
) -> Option<ArmState> {
    let TokenObservation::Words(words) = observation else {
        return None;
    };
    let target = expected.target_floor()?;
    let slot_code = expected.slot.token_code();

    if (words[0], words[1]) != ARM_MAGIC
        || (words[2], words[3]) != slot_code
        || words[4] != expected.release
        || words[5] != !expected.release
        || words[6] != expected.epoch
        || words[7] != !expected.epoch
        || words[8] != target
        || words[9] != !target
        || words[10..18] != expected.binding_words
        || (words[18], words[19]) != ARM_SEAL_1
        || (words[20], words[21]) != ARM_SEAL_2
    {
        return None;
    }

    match (words[22], words[23]) {
        STATE_ARM_READY => Some(ArmState::Ready),
        STATE_ATTEMPTED => Some(ArmState::Attempted),
        STATE_INVALID => None,
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmedFloorRelation {
    EpochBumpPreFloor,
    AtFloor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalState {
    Uninstalled,
    Pending {
        release: u32,
        epoch: u32,
    },
    Attempted {
        release: u32,
        epoch: u32,
    },
    Confirmed {
        release: u32,
        epoch: u32,
        relation: ConfirmedFloorRelation,
    },
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositeObservation {
    pub pending: MarkerObservation,
    pub confirmed: MarkerObservation,
    pub token: TokenObservation,
    pub identity: VerifiedIdentity,
    pub floor: u32,
}

/// Decode exactly the composite states frozen in Draft 0.9 section 6.2.
/// Every unlisted tuple fails closed to `Malformed`.
#[must_use]
pub fn decode_composite(observation: &CompositeObservation) -> LogicalState {
    use MarkerObservation::DurablyCleanExact;

    if matches!(observation.pending, MarkerObservation::BlankVirgin(_))
        && matches!(observation.confirmed, MarkerObservation::BlankVirgin(_))
    {
        return LogicalState::Uninstalled;
    }

    let Some(target) = observation.identity.target_floor() else {
        return LogicalState::Malformed;
    };
    let release = observation.identity.release;
    let epoch = observation.identity.epoch;

    match (observation.pending, observation.confirmed) {
        (DurablyCleanExact(marker), MarkerObservation::BlankVirgin(_))
            if marker.kind() == MarkerKind::Pending && epoch > observation.floor =>
        {
            match decode_arm_token(&observation.token, observation.identity) {
                Some(ArmState::Ready) => LogicalState::Pending { release, epoch },
                Some(ArmState::Attempted) => LogicalState::Attempted { release, epoch },
                None => LogicalState::Malformed,
            }
        }
        (DurablyCleanExact(pending), DurablyCleanExact(confirmed))
            if pending.kind() == MarkerKind::Pending
                && confirmed.kind() == MarkerKind::Confirmed =>
        {
            let relation = if observation.floor < target {
                ConfirmedFloorRelation::EpochBumpPreFloor
            } else if observation.floor == target {
                ConfirmedFloorRelation::AtFloor
            } else {
                return LogicalState::Malformed;
            };
            LogicalState::Confirmed {
                release,
                epoch,
                relation,
            }
        }
        _ => LogicalState::Malformed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    Halt,
    EstablishThenBootConfirmed {
        slot: Slot,
        release: u32,
        epoch: u32,
        target_floor: u32,
    },
    ArmAndTryPending {
        candidate: Slot,
        fallback: Slot,
        release: u32,
        epoch: u32,
    },
}

#[derive(Clone, Copy)]
struct Candidate {
    slot: Slot,
    release: u32,
    epoch: u32,
}

fn candidate(slot: Slot, release: u32, epoch: u32) -> Option<Candidate> {
    VerifiedIdentity {
        slot,
        release,
        epoch,
        binding_words: [0; 8],
    }
    .target_floor()?;
    Some(Candidate {
        slot,
        release,
        epoch,
    })
}

fn as_confirmed(slot: Slot, state: LogicalState) -> Option<Candidate> {
    if let LogicalState::Confirmed { release, epoch, .. } = state {
        candidate(slot, release, epoch)
    } else {
        None
    }
}

fn as_pending(slot: Slot, state: LogicalState) -> Option<Candidate> {
    if let LogicalState::Pending { release, epoch } = state {
        candidate(slot, release, epoch)
    } else {
        None
    }
}

fn select_confirmed(candidate: Candidate) -> Selection {
    Selection::EstablishThenBootConfirmed {
        slot: candidate.slot,
        release: candidate.release,
        epoch: candidate.epoch,
        target_floor: candidate.epoch - 1,
    }
}

/// Pure section-7.2 confirmed-preserving selector.
///
/// This returns the required logical action; it does not claim that floor
/// establishment or TAMP arming succeeded and never models either backend.
#[must_use]
pub fn select(slot_a: LogicalState, slot_b: LogicalState) -> Selection {
    let a_confirmed = as_confirmed(Slot::A, slot_a);
    let b_confirmed = as_confirmed(Slot::B, slot_b);

    match (a_confirmed, b_confirmed) {
        (Some(a), Some(b)) => {
            // Security epoch first, release second, physical slot A on exact
            // equality.  `>=` deliberately gives A the fixed tie-break.
            let preferred = if (a.epoch, a.release) >= (b.epoch, b.release) {
                a
            } else {
                b
            };
            select_confirmed(preferred)
        }
        (Some(confirmed), None) | (None, Some(confirmed)) => {
            let other_state = if confirmed.slot == Slot::A {
                slot_b
            } else {
                slot_a
            };
            if let Some(pending) = as_pending(
                if confirmed.slot == Slot::A {
                    Slot::B
                } else {
                    Slot::A
                },
                other_state,
            ) {
                if pending.release > confirmed.release && pending.epoch >= confirmed.epoch {
                    return Selection::ArmAndTryPending {
                        candidate: pending.slot,
                        fallback: confirmed.slot,
                        release: pending.release,
                        epoch: pending.epoch,
                    };
                }
            }
            // ATTEMPTED, malformed, uninstalled, and every non-qualifying
            // pending tuple are unable to suppress the confirmed fallback.
            select_confirmed(confirmed)
        }
        (None, None) => Selection::Halt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: [u32; 8] = [
        0x1672_7042,
        0x3f35_f16b,
        0xcdec_ad4e,
        0x9e19_817a,
        0xc87b_06bb,
        0x8838_483b,
        0xe8b9_7636,
        0x476c_7b7a,
    ];

    fn identity(slot: Slot, release: u32, epoch: u32) -> VerifiedIdentity {
        VerifiedIdentity {
            slot,
            release,
            epoch,
            binding_words: BINDING,
        }
    }

    fn token(expected: VerifiedIdentity, state: ArmState) -> TokenObservation {
        let mut words = [0_u32; 24];
        let target = expected.epoch - 1;
        let slot = expected.slot.token_code();
        words[0..2].copy_from_slice(&[ARM_MAGIC.0, ARM_MAGIC.1]);
        words[2..4].copy_from_slice(&[slot.0, slot.1]);
        words[4..6].copy_from_slice(&[expected.release, !expected.release]);
        words[6..8].copy_from_slice(&[expected.epoch, !expected.epoch]);
        words[8..10].copy_from_slice(&[target, !target]);
        words[10..18].copy_from_slice(&expected.binding_words);
        words[18..20].copy_from_slice(&[ARM_SEAL_1.0, ARM_SEAL_1.1]);
        words[20..22].copy_from_slice(&[ARM_SEAL_2.0, ARM_SEAL_2.1]);
        let pair = match state {
            ArmState::Ready => STATE_ARM_READY,
            ArmState::Attempted => STATE_ATTEMPTED,
        };
        words[22..24].copy_from_slice(&[pair.0, pair.1]);
        TokenObservation::Words(words)
    }

    fn observation(
        pending: MarkerObservation,
        confirmed: MarkerObservation,
        token_observation: TokenObservation,
        floor: u32,
    ) -> CompositeObservation {
        CompositeObservation {
            pending,
            confirmed,
            token: token_observation,
            identity: identity(Slot::B, 9, 4),
            floor,
        }
    }

    fn confirmed(release: u32, epoch: u32) -> LogicalState {
        LogicalState::Confirmed {
            release,
            epoch,
            relation: ConfirmedFloorRelation::AtFloor,
        }
    }

    fn exact_marker(kind: MarkerKind) -> MarkerObservation {
        MarkerObservation::DurablyCleanExact(DurablyCleanMarker(kind))
    }

    fn blank_marker() -> MarkerObservation {
        MarkerObservation::assume_blank_virgin_for_test()
    }

    #[test]
    fn frozen_marker_and_token_constants_are_exact() {
        assert_eq!(ARM_TOKEN_DOMAIN, b"PQFW_A1");
        assert_eq!(ARM_TOKEN_PREIMAGE_LEN, 116);
        assert_eq!(
            MarkerObservation::assume_durably_clean_for_test(&QW_PENDING),
            exact_marker(MarkerKind::Pending)
        );
        assert_eq!(
            MarkerObservation::assume_durably_clean_for_test(&QW_CONFIRMED),
            exact_marker(MarkerKind::Confirmed)
        );

        for bit in 0..128 {
            let mut pending = QW_PENDING;
            pending[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                MarkerObservation::assume_durably_clean_for_test(&pending),
                MarkerObservation::Malformed
            );

            let mut confirmed = QW_CONFIRMED;
            confirmed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                MarkerObservation::assume_durably_clean_for_test(&confirmed),
                MarkerObservation::Malformed
            );
        }
    }

    #[test]
    fn exact_tokens_validate_only_for_the_bound_identity_and_state() {
        // Frozen Section-6.1/6.2 fixture, including T=0x05060707 and the
        // exact eight-word binding digest above.
        let expected = identity(Slot::B, 0x0102_0304, 0x0506_0708);
        assert_eq!(
            decode_arm_token(&token(expected, ArmState::Ready), expected),
            Some(ArmState::Ready)
        );
        assert_eq!(
            decode_arm_token(&token(expected, ArmState::Attempted), expected),
            Some(ArmState::Attempted)
        );
        assert_eq!(decode_arm_token(&TokenObservation::Missing, expected), None);

        for index in 0..24 {
            for bit in 0..32 {
                let TokenObservation::Words(mut words) = token(expected, ArmState::Ready) else {
                    unreachable!();
                };
                words[index] ^= 1_u32 << bit;
                assert_eq!(
                    decode_arm_token(&TokenObservation::Words(words), expected),
                    None,
                    "word {index}, bit {bit}"
                );
            }
        }

        let TokenObservation::Words(mut invalid_state) = token(expected, ArmState::Ready) else {
            unreachable!();
        };
        invalid_state[22..24].copy_from_slice(&[STATE_INVALID.0, STATE_INVALID.1]);
        assert_eq!(
            decode_arm_token(&TokenObservation::Words(invalid_state), expected),
            None
        );
        invalid_state[22..24].copy_from_slice(&[0, 0]);
        assert_eq!(
            decode_arm_token(&TokenObservation::Words(invalid_state), expected),
            None
        );

        for mismatch in [
            identity(Slot::A, 0x0102_0304, 0x0506_0708),
            identity(Slot::B, 0x0102_0303, 0x0506_0708),
            identity(Slot::B, 0x0102_0304, 0x0506_0709),
            VerifiedIdentity {
                binding_words: [0; 8],
                ..expected
            },
        ] {
            assert_eq!(
                decode_arm_token(&token(expected, ArmState::Ready), mismatch),
                None
            );
        }
    }

    #[test]
    fn composite_decoder_accepts_only_the_frozen_state_tuples() {
        let expected = identity(Slot::B, 9, 4);
        let blank = blank_marker();
        let pending = exact_marker(MarkerKind::Pending);
        let confirmed_marker = exact_marker(MarkerKind::Confirmed);

        assert_eq!(
            decode_composite(&observation(blank, blank, TokenObservation::Missing, 3)),
            LogicalState::Uninstalled
        );
        assert_eq!(
            decode_composite(&observation(
                pending,
                blank,
                token(expected, ArmState::Ready),
                3
            )),
            LogicalState::Pending {
                release: 9,
                epoch: 4
            }
        );
        assert_eq!(
            decode_composite(&observation(
                pending,
                blank,
                token(expected, ArmState::Attempted),
                3
            )),
            LogicalState::Attempted {
                release: 9,
                epoch: 4
            }
        );
        assert_eq!(
            decode_composite(&observation(
                pending,
                confirmed_marker,
                TokenObservation::Missing,
                2
            )),
            LogicalState::Confirmed {
                release: 9,
                epoch: 4,
                relation: ConfirmedFloorRelation::EpochBumpPreFloor
            }
        );
        assert_eq!(
            decode_composite(&observation(
                pending,
                confirmed_marker,
                TokenObservation::Missing,
                3
            )),
            LogicalState::Confirmed {
                release: 9,
                epoch: 4,
                relation: ConfirmedFloorRelation::AtFloor
            }
        );
    }

    #[test]
    fn every_unlisted_marker_tuple_is_malformed() {
        let observations = [
            blank_marker(),
            exact_marker(MarkerKind::Pending),
            exact_marker(MarkerKind::Confirmed),
            MarkerObservation::UnknownMayHaveLaunched,
            MarkerObservation::Corrected,
            MarkerObservation::Uncorrectable,
            MarkerObservation::Malformed,
        ];
        let expected = identity(Slot::B, 9, 4);

        for pending in observations {
            for confirmed_marker in observations {
                let decoded = decode_composite(&observation(
                    pending,
                    confirmed_marker,
                    token(expected, ArmState::Ready),
                    3,
                ));
                let accepted = (pending == blank_marker() && confirmed_marker == blank_marker())
                    || (pending == exact_marker(MarkerKind::Pending)
                        && confirmed_marker == blank_marker())
                    || (pending == exact_marker(MarkerKind::Pending)
                        && confirmed_marker == exact_marker(MarkerKind::Confirmed));
                assert_eq!(
                    decoded != LogicalState::Malformed,
                    accepted,
                    "{pending:?}/{confirmed_marker:?}"
                );
            }
        }
    }

    #[test]
    fn token_loss_mismatch_and_bad_floor_fail_closed() {
        let pending = exact_marker(MarkerKind::Pending);
        let blank = blank_marker();
        let expected = identity(Slot::B, 9, 4);

        assert_eq!(
            decode_composite(&observation(pending, blank, TokenObservation::Missing, 3)),
            LogicalState::Malformed
        );
        assert_eq!(
            decode_composite(&observation(
                pending,
                blank,
                token(identity(Slot::A, 9, 4), ArmState::Ready),
                3
            )),
            LogicalState::Malformed
        );
        assert_eq!(
            decode_composite(&observation(
                pending,
                blank,
                token(expected, ArmState::Ready),
                4
            )),
            LogicalState::Malformed
        );

        let mut bad_range = observation(pending, blank, token(expected, ArmState::Ready), 3);
        bad_range.identity.release = 0;
        assert_eq!(decode_composite(&bad_range), LogicalState::Malformed);
        bad_range.identity = identity(Slot::B, 9, u32::MAX);
        assert_eq!(decode_composite(&bad_range), LogicalState::Malformed);

        let confirmed_marker = exact_marker(MarkerKind::Confirmed);
        assert_eq!(
            decode_composite(&observation(
                pending,
                confirmed_marker,
                TokenObservation::Missing,
                4
            )),
            LogicalState::Malformed
        );
    }

    #[test]
    fn no_confirmed_slot_always_halts() {
        let states = [
            LogicalState::Uninstalled,
            LogicalState::Pending {
                release: 2,
                epoch: 1,
            },
            LogicalState::Attempted {
                release: 2,
                epoch: 1,
            },
            LogicalState::Malformed,
        ];
        for a in states {
            for b in states {
                assert_eq!(select(a, b), Selection::Halt, "{a:?}/{b:?}");
            }
        }
    }

    #[test]
    fn qualifying_pending_is_tried_once_with_confirmed_fallback() {
        let fallback = confirmed(5, 2);
        let candidate = LogicalState::Pending {
            release: 6,
            epoch: 2,
        };
        assert_eq!(
            select(fallback, candidate),
            Selection::ArmAndTryPending {
                candidate: Slot::B,
                fallback: Slot::A,
                release: 6,
                epoch: 2
            }
        );
        assert_eq!(
            select(candidate, fallback),
            Selection::ArmAndTryPending {
                candidate: Slot::A,
                fallback: Slot::B,
                release: 6,
                epoch: 2
            }
        );
    }

    #[test]
    fn ambiguous_or_nonqualifying_pending_never_suppresses_confirmed() {
        let fallback = confirmed(5, 2);
        for candidate in [
            LogicalState::Pending {
                release: 5,
                epoch: 2,
            },
            LogicalState::Pending {
                release: 4,
                epoch: 3,
            },
            LogicalState::Pending {
                release: 6,
                epoch: 1,
            },
            LogicalState::Pending {
                release: 5,
                epoch: 3,
            },
            LogicalState::Attempted {
                release: 99,
                epoch: 99,
            },
            LogicalState::Malformed,
            LogicalState::Uninstalled,
        ] {
            assert_eq!(
                select(fallback, candidate),
                Selection::EstablishThenBootConfirmed {
                    slot: Slot::A,
                    release: 5,
                    epoch: 2,
                    target_floor: 1
                },
                "{candidate:?}"
            );
        }
    }

    #[test]
    fn two_confirmed_order_by_epoch_then_release_then_slot_a() {
        let cases = [
            (confirmed(100, 2), confirmed(1, 3), Slot::B, 1, 3),
            (confirmed(1, 3), confirmed(100, 2), Slot::A, 1, 3),
            (confirmed(6, 3), confirmed(5, 3), Slot::A, 6, 3),
            (confirmed(5, 3), confirmed(6, 3), Slot::B, 6, 3),
            (confirmed(5, 3), confirmed(5, 3), Slot::A, 5, 3),
        ];
        for (a, b, slot, release, epoch) in cases {
            assert_eq!(
                select(a, b),
                Selection::EstablishThenBootConfirmed {
                    slot,
                    release,
                    epoch,
                    target_floor: epoch - 1
                }
            );
        }
    }
}
