//! libFuzzer harness for the FULL ERC-7730 renderer dispatch — descriptor
//! parse → `find_format_by_selector` → per-`FormatOp` field render → `Pages`
//! emission.
//!
//! The renderer moved out of the secure crate's `#[cfg(not(test))]`-gated
//! `tx::display` tree into `pqsigner_erc7730::display::render` (see
//! `docs/erc7730-renderer-fuzzability.md`), so this harness now host-links and
//! drives `render_erc7730_pages` itself — the exact code that paints the OLED
//! rows the user confirms. That is the highest-value fuzz surface on the render
//! path: the per-field formatters do decimal-scaling / address-truncation / hex
//! / `checked_sub` column math on attacker-controlled calldata under
//! `overflow-checks = true`, where any slip is a panic = DoS on the trusted
//! display. (The Pages-independent byte-writers are also fuzzed directly by
//! `erc7730_display_primitives`; this harness reaches them THROUGH the real
//! descriptor-driven dispatch, so it also covers path resolution, visibility,
//! nested descent, and the page-budget ladder.)
//!
//! `VerifiedDescriptor` wraps the parsed IR directly here — the Merkle-proof +
//! `(chain_id, contract)` binding gate is a SEPARATE concern fuzzed by
//! `erc7730_verify_bundle`, so bypassing it maximises render coverage over
//! arbitrary (well-formed-enough-to-parse) descriptors.
//!
//! Contract under test: for ANY `(descriptor, tx, calldata)`, every entry point
//! must RETURN (`Ok`/`Err`) — never panic, OOB-read, or overflow.
//!
//! Strategy: `data[..4]`/`data[4..8]` are two probe selectors (match +
//! no-match branches); `data[8..]` is the raw IR. Each parsed format is then
//! rendered with its OWN 4-byte selector (a random selector matches a parsed
//! format ~never), so the field renderers actually run, over a calldata body
//! and an envelope `tx` both derived from the fuzz bytes.

#![no_main]
use libfuzzer_sys::fuzz_target;

use pqsigner_erc7730::bundle::VerifiedDescriptor;
use pqsigner_erc7730::display::render::render_erc7730_pages;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_tx::names::NameResolver;
use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};

/// Calldata scratch: 4-byte selector + 64 words of body — covers the static
/// head of essentially every real format; a format whose field slot reaches
/// past the supplied body declines safely (no panic), it just renders less.
const CALLDATA_CAP: usize = 4 + 64 * 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let (Ok(selector_a), Ok(selector_b)) = (
        <[u8; 4]>::try_from(&data[..4]),
        <[u8; 4]>::try_from(&data[4..8]),
    ) else {
        return;
    };
    let ir_bytes = &data[8..];
    if ir_bytes.is_empty() {
        return;
    }

    // 1. Parse — must never panic on adversarial bytes.
    let Ok(ir) = Erc7730Ir::parse(ir_bytes) else {
        return;
    };

    // 2. Descriptor-side dispatch: both the match and no-match branches, plus
    //    the field-table walk (prior bug history — see the crate's regression
    //    tests).
    let _ = ir.find_format_by_selector(&selector_a);
    let _ = ir.find_format_by_selector(&selector_b);
    for fmt_result in ir.format_iter() {
        let Ok(fmt) = fmt_result else {
            continue;
        };
        for field_result in fmt.fields() {
            let _ = field_result;
        }
    }

    // 3. FULL render → `Pages` emission (the on-device confirm screen).
    let descriptor = VerifiedDescriptor { ir };

    // Envelope tx: the container fields the renderer reads (@.value, chain_id,
    // @.from-derived) come from here; derive them from the fuzz bytes.
    let mut tx = Eip1559Tx::default();
    tx.chain_id = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let mut to = [0u8; 20];
    for (i, b) in to.iter_mut().enumerate() {
        *b = ir_bytes[i % ir_bytes.len()];
    }
    tx.to = Some(to);
    let mut val = [0u8; 32];
    for (i, b) in val.iter_mut().enumerate() {
        *b = ir_bytes[(i + 7) % ir_bytes.len()];
    }
    tx.value = U256(val);

    let resolver = NameResolver::default();

    for fmt_result in descriptor.ir.format_iter() {
        let Ok(fmt) = fmt_result else {
            continue;
        };
        // Dispatch with the format's REAL selector so the field renderers run;
        // fill the body with fuzz bytes so the amount/address formatters see
        // adversarial word values.
        let mut calldata = [0u8; CALLDATA_CAP];
        calldata[..4].copy_from_slice(&fmt.selector);
        for (i, b) in calldata[4..].iter_mut().enumerate() {
            *b = ir_bytes[i % ir_bytes.len()];
        }
        let _ = render_erc7730_pages(&tx, &calldata, &descriptor, None, &resolver);
    }
});
