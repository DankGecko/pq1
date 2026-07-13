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
//! Input framing is `[u16 ir_len BE][ir][payload]`. Keeping the authenticated
//! descriptor and attacker-controlled calldata in separate regions is
//! load-bearing for coverage: mutating a calldata word must not first corrupt
//! the valid IR seed and strand the run in `Erc7730Ir::parse`. Each parsed
//! format is rendered with its OWN 4-byte selector (a random selector matches
//! a parsed format ~never), over a calldata body and envelope derived only from
//! `payload` (falling back to IR bytes for tiny malformed seeds).

#![no_main]
use libfuzzer_sys::fuzz_target;

use pqsigner_erc7730::bundle::VerifiedDescriptor;
use pqsigner_erc7730::display::render::{
    render_erc7730_eip712_pages, render_erc7730_eip712_pages_v3, render_erc7730_pages,
};
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir};
use pqsigner_tx::names::NameResolver;
use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};

/// Scratch capacity: 64 head words plus eight words for a canonical sole
/// dynamic tail (array counts through seven, including the first over-limit
/// witness). Formats larger than this still exercise their short-frame
/// rejection path.
const BODY_WORD_CAP: usize = 72;
const BODY_CAP: usize = BODY_WORD_CAP * 32;
const CALLDATA_CAP: usize = 4 + BODY_CAP;

fn fuzz_byte(bytes: &[u8], index: usize) -> u8 {
    bytes[index % bytes.len()]
}

fn put_abi_usize_word(word: &mut [u8], value: usize) {
    debug_assert_eq!(word.len(), 32);
    word.fill(0);
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let ir_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let Some(ir_end) = 2usize.checked_add(ir_len) else {
        return;
    };
    if ir_len == 0 || ir_end > data.len() {
        return;
    }
    let ir_bytes = &data[2..ir_end];
    let payload = &data[ir_end..];

    // 1. Parse — must never panic on adversarial bytes.
    let Ok(ir) = Erc7730Ir::parse(ir_bytes) else {
        return;
    };

    // 2. Descriptor-side dispatch: both the match and no-match branches, plus
    //    the field-table walk (prior bug history — see the crate's regression
    //    tests).
    let fuzz_bytes = if payload.is_empty() {
        ir_bytes
    } else {
        payload
    };
    let mut selector_a = [0u8; 4];
    let mut selector_b = [0u8; 4];
    for i in 0..4 {
        selector_a[i] = fuzz_bytes[i % fuzz_bytes.len()];
        selector_b[i] = fuzz_bytes[(i + 4) % fuzz_bytes.len()];
    }
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
    let chain_id = ir.chain_id;
    let verifying_contract = ir.contract;
    let context_kind = ir.context_kind;
    let descriptor = VerifiedDescriptor { ir };

    // Envelope tx: the container fields the renderer reads (@.value, chain_id,
    // @.from-derived) come from here; derive them from the fuzz bytes.
    let mut tx = Eip1559Tx::default();
    let mut chain = [0u8; 8];
    for (i, b) in chain.iter_mut().enumerate() {
        *b = fuzz_bytes[i % fuzz_bytes.len()];
    }
    tx.chain_id = u64::from_le_bytes(chain);
    let mut to = [0u8; 20];
    for (i, b) in to.iter_mut().enumerate() {
        *b = fuzz_bytes[(i + 8) % fuzz_bytes.len()];
    }
    tx.to = Some(to);
    let mut val = [0u8; 32];
    for (i, b) in val.iter_mut().enumerate() {
        *b = fuzz_bytes[(i + 28) % fuzz_bytes.len()];
    }
    tx.value = U256(val);

    let resolver = NameResolver::default();

    for fmt_result in descriptor.ir.format_iter() {
        let Ok(fmt) = fmt_result else {
            continue;
        };
        let Some(head_len) = (fmt.static_head_words as usize).checked_mul(32) else {
            continue;
        };

        match context_kind {
            ContextKind::Contract => {
                let mut calldata = [0u8; CALLDATA_CAP];
                calldata[..4].copy_from_slice(&fmt.selector);
                for (i, b) in calldata[4..].iter_mut().enumerate() {
                    *b = fuzz_byte(fuzz_bytes, i + 60);
                }

                // First drive arbitrary/truncated/overlong framing. Length is
                // independent of the IR, so libFuzzer can explore every
                // boundary without corrupting the valid descriptor seed.
                let arbitrary_len =
                    u16::from_be_bytes([fuzz_byte(fuzz_bytes, 56), fuzz_byte(fuzz_bytes, 57)])
                        as usize
                        % (CALLDATA_CAP + 1);
                let _ = render_erc7730_pages(
                    &tx,
                    &calldata[..arbitrary_len],
                    &descriptor,
                    None,
                    &resolver,
                );

                if head_len > BODY_CAP {
                    continue;
                }

                // Exact all-static framing. This is the load-bearing path
                // that actually crosses validate_contract_calldata_framing
                // for the majority of production formats.
                let exact_len = 4 + head_len;
                let _ =
                    render_erc7730_pages(&tx, &calldata[..exact_len], &descriptor, None, &resolver);

                // Random high bytes almost always violate canonical ABI
                // address padding (chance 2^-96), which can strand every
                // later field in an address-heavy format. Exercise a second
                // exact frame with every word address-canonical while keeping
                // the low 160 bits attacker-controlled.
                for (word_index, word) in calldata[4..4 + head_len].chunks_exact_mut(32).enumerate()
                {
                    word[..12].fill(0);
                    for (i, b) in word[12..].iter_mut().enumerate() {
                        *b = fuzz_byte(fuzz_bytes, 320 + word_index * 20 + i);
                    }
                }
                let _ =
                    render_erc7730_pages(&tx, &calldata[..exact_len], &descriptor, None, &resolver);

                // Canonical sole-dynamic candidates. Put head_end in every
                // head word: the one authenticated dynamic slot therefore
                // has the correct offset, while static scalar/address fields
                // remain canonically encoded values. One candidate is a
                // padded printable string and the other a primitive array;
                // the format preflight selects the applicable topology.
                for word in calldata[4..4 + head_len].chunks_exact_mut(32) {
                    put_abi_usize_word(word, head_len);
                }

                let string_len = fuzz_byte(fuzz_bytes, 58) as usize % 65;
                let string_padded = string_len.div_ceil(32) * 32;
                let string_body_len = head_len + 32 + string_padded;
                if string_body_len <= BODY_CAP {
                    put_abi_usize_word(&mut calldata[4 + head_len..4 + head_len + 32], string_len);
                    calldata[4 + head_len + 32..4 + string_body_len].fill(0);
                    for i in 0..string_len {
                        calldata[4 + head_len + 32 + i] =
                            0x20 + fuzz_byte(fuzz_bytes, i + 96) % 0x5f;
                    }
                    let _ = render_erc7730_pages(
                        &tx,
                        &calldata[..4 + string_body_len],
                        &descriptor,
                        None,
                        &resolver,
                    );
                }

                let array_count = fuzz_byte(fuzz_bytes, 59) as usize % 8;
                let array_body_len = head_len + 32 + array_count * 32;
                if array_body_len <= BODY_CAP {
                    put_abi_usize_word(&mut calldata[4 + head_len..4 + head_len + 32], array_count);
                    for (index, word) in calldata[4 + head_len + 32..4 + array_body_len]
                        .chunks_exact_mut(32)
                        .enumerate()
                    {
                        // Canonical for address[] (top 12 bytes zero) and a
                        // perfectly valid small uint256 for numeric arrays.
                        word.fill(0);
                        for (i, b) in word[12..].iter_mut().enumerate() {
                            *b = fuzz_byte(fuzz_bytes, 160 + index * 20 + i);
                        }
                    }
                    let _ = render_erc7730_pages(
                        &tx,
                        &calldata[..4 + array_body_len],
                        &descriptor,
                        None,
                        &resolver,
                    );
                }
            }
            ContextKind::Eip712 => {
                if head_len > BODY_CAP {
                    continue;
                }
                let mut encoded_data = [0u8; BODY_CAP];
                for (i, b) in encoded_data.iter_mut().enumerate() {
                    *b = fuzz_byte(fuzz_bytes, i + 60);
                }
                let nested_len = (fuzz_byte(fuzz_bytes, 58) as usize)
                    .min(fuzz_bytes.len())
                    .min(256);
                let nested_blob = &fuzz_bytes[..nested_len];

                // Exact typed-data frame through BOTH public entry points.
                // V2 reaches every non-nested production leaf; V3 additionally
                // drives nested-record parsing/reconciliation with hostile
                // companion bytes.
                let _ = render_erc7730_eip712_pages(
                    chain_id,
                    &verifying_contract,
                    &fmt.type_hash,
                    &encoded_data[..head_len],
                    &descriptor,
                    None,
                    &resolver,
                );
                let _ = render_erc7730_eip712_pages_v3(
                    chain_id,
                    &verifying_contract,
                    &fmt.type_hash,
                    &encoded_data[..head_len],
                    nested_blob,
                    &descriptor,
                    None,
                    &resolver,
                );

                // A second exact frame keeps every word address-canonical
                // (zero top 12 bytes), so address formatters are not stranded
                // behind random dirty-padding rejection. Numeric/enum fields
                // still receive attacker-controlled low 160 bits.
                for (word_index, word) in encoded_data[..head_len].chunks_exact_mut(32).enumerate()
                {
                    word[..12].fill(0);
                    for (i, b) in word[12..].iter_mut().enumerate() {
                        *b = fuzz_byte(fuzz_bytes, 320 + word_index * 20 + i);
                    }
                }
                let _ = render_erc7730_eip712_pages(
                    chain_id,
                    &verifying_contract,
                    &fmt.type_hash,
                    &encoded_data[..head_len],
                    &descriptor,
                    None,
                    &resolver,
                );

                // And independently fuzz the exact-length guard.
                let arbitrary_len =
                    u16::from_be_bytes([fuzz_byte(fuzz_bytes, 56), fuzz_byte(fuzz_bytes, 57)])
                        as usize
                        % (BODY_CAP + 1);
                let _ = render_erc7730_eip712_pages_v3(
                    chain_id,
                    &verifying_contract,
                    &fmt.type_hash,
                    &encoded_data[..arbitrary_len],
                    nested_blob,
                    &descriptor,
                    None,
                    &resolver,
                );
            }
        }
    }
});
