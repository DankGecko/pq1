//! Nonshipping resource-envelope arithmetic for rollback Draft 0.9.
//!
//! This is deliberately not a footprint pass for a production backend.  It
//! makes the warning limits and fail-closed arithmetic executable while the
//! final manifest, journal, ECC, floor codec, durable stage, and FI boundary
//! remain host-only models. `CombinedDraft09` is an externally established
//! provenance assertion: this arithmetic cannot inspect an ELF and prove that
//! the final components are actually present.

#![forbid(unsafe_code)]

const FSBL_ORIGIN: u64 = 0x0c00_0000;
const LEGACY_LINKER_CEILING: u64 = 32 * 1024;
const FSBL_IMMUTABLE_CEILING: u64 = 40 * 1024;
const FSBL_WARNING_LIMIT: u64 = 38_912;
const SRAM_ORIGIN: u64 = 0x3000_0000;
const STACK_START: u64 = 0x3000_4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateKind {
    LegacyBaseline,
    PlaceholderProxy,
    CombinedDraft09,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlashReceipt {
    kind: CandidateKind,
    load_origin: u64,
    load_end: u64,
}

impl FlashReceipt {
    fn physical_span(self) -> Option<u64> {
        self.load_end.checked_sub(self.load_origin)
    }

    fn warning_headroom(self) -> Option<u64> {
        let span = self.physical_span()?;
        FSBL_WARNING_LIMIT.checked_sub(span)
    }

    fn ceiling_headroom(self) -> Option<u64> {
        let span = self.physical_span()?;
        FSBL_IMMUTABLE_CEILING.checked_sub(span)
    }

    /// Arithmetic eligibility after an independent build/provenance gate has
    /// established that `kind` truthfully describes a combined candidate.
    fn passes_warning_arithmetic_if_proven_combined(self) -> bool {
        self.kind == CandidateKind::CombinedDraft09
            && self.load_origin == FSBL_ORIGIN
            && self.warning_headroom().is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RamReceipt {
    static_end: u64,
    stack_start: u64,
    worst_case_stack: Option<u64>,
    margin: u64,
    guard: u64,
}

impl RamReceipt {
    fn available(self) -> Option<u64> {
        if self.static_end < SRAM_ORIGIN || self.stack_start != STACK_START {
            return None;
        }
        self.stack_start.checked_sub(self.static_end)
    }

    fn required(self) -> Option<u64> {
        if self.margin == 0 {
            return None;
        }
        self.worst_case_stack?
            .checked_add(self.margin)?
            .checked_add(self.guard)
    }

    fn remaining(self) -> Option<u64> {
        self.available()?.checked_sub(self.required()?)
    }
}

#[test]
fn frozen_geometry_and_warning_reservation_are_exact() {
    assert_eq!(FSBL_IMMUTABLE_CEILING, 40_960);
    assert_eq!(LEGACY_LINKER_CEILING, 32_768);
    assert_eq!(FSBL_WARNING_LIMIT, 38_912);
    assert_eq!(FSBL_IMMUTABLE_CEILING - FSBL_WARNING_LIMIT, 2_048);
    assert_eq!(STACK_START - SRAM_ORIGIN, 16_384);
}

#[test]
fn current_legacy_baseline_is_measurement_only_not_draft09_headroom() {
    // 2026-07-13 release link at master 6aac004c, dev-sized vendor key and
    // explicit `legacy-fw-rollback-unsafe`.  The single non-empty PT_LOAD was
    // 0x0c00_0000..0x0c00_6ea0.  None of the final Draft 0.9 backend exists in
    // this ELF, so the arithmetic cannot be cited as usable design headroom.
    let baseline = FlashReceipt {
        kind: CandidateKind::LegacyBaseline,
        load_origin: FSBL_ORIGIN,
        load_end: FSBL_ORIGIN + 0x6ea0,
    };
    assert_eq!(baseline.physical_span(), Some(28_320));
    assert_eq!(
        LEGACY_LINKER_CEILING - baseline.physical_span().unwrap(),
        4_448
    );
    assert_eq!(baseline.warning_headroom(), Some(10_592));
    assert_eq!(baseline.ceiling_headroom(), Some(12_640));
    assert!(!baseline.passes_warning_arithmetic_if_proven_combined());
}

#[test]
fn prior_placeholder_proxy_remains_amber_even_below_warning_limit() {
    let proxy = FlashReceipt {
        kind: CandidateKind::PlaceholderProxy,
        load_origin: FSBL_ORIGIN,
        load_end: FSBL_ORIGIN + 38_860,
    };
    assert_eq!(proxy.warning_headroom(), Some(52));
    assert_eq!(proxy.ceiling_headroom(), Some(2_100));
    assert!(!proxy.passes_warning_arithmetic_if_proven_combined());
}

#[test]
fn only_a_true_combined_candidate_can_pass_the_warning_classifier() {
    let exact_limit = FlashReceipt {
        kind: CandidateKind::CombinedDraft09,
        load_origin: FSBL_ORIGIN,
        load_end: FSBL_ORIGIN + FSBL_WARNING_LIMIT,
    };
    assert_eq!(exact_limit.warning_headroom(), Some(0));
    assert!(exact_limit.passes_warning_arithmetic_if_proven_combined());

    let one_over = FlashReceipt {
        load_end: exact_limit.load_end + 1,
        ..exact_limit
    };
    assert_eq!(one_over.warning_headroom(), None);
    assert!(!one_over.passes_warning_arithmetic_if_proven_combined());

    let shifted_origin = FlashReceipt {
        load_origin: FSBL_ORIGIN + 1,
        load_end: FSBL_ORIGIN + 1 + FSBL_WARNING_LIMIT,
        ..exact_limit
    };
    assert!(!shifted_origin.passes_warning_arithmetic_if_proven_combined());
}

#[test]
fn flash_and_ram_arithmetic_fail_closed_without_wraparound() {
    let backwards = FlashReceipt {
        kind: CandidateKind::CombinedDraft09,
        load_origin: FSBL_ORIGIN,
        load_end: FSBL_ORIGIN - 1,
    };
    assert_eq!(backwards.physical_span(), None);
    assert!(!backwards.passes_warning_arithmetic_if_proven_combined());

    let no_stack_bound = RamReceipt {
        static_end: SRAM_ORIGIN,
        stack_start: STACK_START,
        worst_case_stack: None,
        margin: 512,
        guard: 256,
    };
    assert_eq!(no_stack_bound.remaining(), None);

    let static_past_stack = RamReceipt {
        static_end: STACK_START + 1,
        worst_case_stack: Some(1),
        ..no_stack_bound
    };
    assert_eq!(static_past_stack.available(), None);
    assert_eq!(static_past_stack.remaining(), None);

    let static_before_sram = RamReceipt {
        static_end: SRAM_ORIGIN - 1,
        worst_case_stack: Some(1),
        ..no_stack_bound
    };
    assert_eq!(static_before_sram.available(), None);

    let wrong_stack_start = RamReceipt {
        stack_start: STACK_START + 4,
        worst_case_stack: Some(1),
        ..no_stack_bound
    };
    assert_eq!(wrong_stack_start.available(), None);

    let required_overflow = RamReceipt {
        static_end: SRAM_ORIGIN,
        stack_start: STACK_START,
        worst_case_stack: Some(u64::MAX),
        margin: 1,
        guard: 0,
    };
    assert_eq!(required_overflow.required(), None);
    assert_eq!(required_overflow.remaining(), None);

    let insufficient = RamReceipt {
        static_end: SRAM_ORIGIN,
        stack_start: STACK_START,
        worst_case_stack: Some(16_000),
        margin: 512,
        guard: 0,
    };
    assert_eq!(insufficient.remaining(), None);

    let zero_margin = RamReceipt {
        static_end: SRAM_ORIGIN,
        stack_start: STACK_START,
        worst_case_stack: Some(1),
        margin: 0,
        guard: 0,
    };
    assert_eq!(zero_margin.required(), None);
    assert_eq!(zero_margin.remaining(), None);
}

#[test]
fn current_legacy_static_gap_is_not_a_worst_case_stack_receipt() {
    let baseline_ram = RamReceipt {
        static_end: SRAM_ORIGIN,
        stack_start: STACK_START,
        worst_case_stack: None,
        margin: 0,
        guard: 0,
    };
    assert_eq!(baseline_ram.available(), Some(16_384));
    assert_eq!(baseline_ram.required(), None);
    assert_eq!(baseline_ram.remaining(), None);
}
