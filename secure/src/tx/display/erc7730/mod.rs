//! ERC-7730 clear-signing renderer — UI-bound half.
//!
//! Pure-logic pieces (TLV parameter parser, visibility evaluator,
//! `RenderErr`) live at `crate::tx::erc7730_render::*` so host-test
//! builds (which gate out `crate::tx::display`) can still exercise
//! them. This module owns the [`Pages`]-using formatter dispatcher,
//! intent renderer, and nested-calldata recursor.
//!
//! Entry points:
//!
//! - [`render_erc7730_pages`] — contract context (EIP-1559 UserOp
//!   execution against a known smart contract).
//! - [`render_erc7730_eip712_pages`] — EIP-712 typed-data offchain
//!   signs driven by `OFFCHAIN_KIND_EIP712_TYPED = 2` (Step 7).
//!
//! Both consume a [`VerifiedDescriptor`] minted by Phase 3's bundle
//! verifier and produce a [`Pages`] object the existing
//! [`crate::ui::confirm::confirm`] loop drives.
//!
//! Returning [`RenderErr`] from the entry points is how the renderer
//! tells [`super::pick_sign_pages`] "I don't have a clean rendering
//! for this transaction — please fall through to the next ladder
//! rung." See the per-variant docs on
//! [`crate::tx::erc7730_render::RenderErr`].

mod calldata_nested;
pub(crate) mod formatters;
mod intent;

use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use super::primitives::{
    chain_name, write_chain, write_fee_budget_row, write_gas, write_gwei, write_line,
    write_nonce_row, write_tip_row,
};
use crate::tx::eip1559::Eip1559Tx;
use crate::tx::erc7730::VerifiedDescriptor;
use crate::tx::erc7730_render::params::parse as parse_params;
use crate::tx::erc7730_render::visibility::{should_render_with_mode, Action};
use crate::tx::erc7730_render::RenderErr;

use super::Pages;

/// Compact-mode display toggle (Phase 5 item 10).
///
/// When `true`, the renderer skips fields marked `Visibility::Optional`
/// — the on-wire byte is unchanged; only the renderer's interpretation
/// differs (Phase 4 collapsed Optional → Always for ALL descriptors;
/// this distinguishes them under an opt-in flag).
///
/// Defaults to `false` so existing fixtures stay byte-identical. A
/// future settings-page toggle can flip this const at runtime via a
/// volatile flag in `crate::ui::settings` (deferred — Phase 5 v1 ships
/// the const-only switch).
pub const COMPACT_MODE: bool = false;

/// Belt-and-braces stack canary for the ERC-7730 renderer (Phase 5
/// item 11). The walker recurses for nested calldata (capped at depth
/// 4 in the renderer, depth 8 in the walker proper); a hostile
/// descriptor that somehow defeats the depth cap and recurses
/// unbounded would smash the stack silently. Writing a known sentinel
/// to a stack-resident `u32` at entry and asserting equality at exit
/// catches that class of bug — any stack overrun that smashes the
/// canary panics the secure world (which the panic handler routes
/// through `secure_log!` + halt) instead of being silently
/// undetectable. See `docs/security/HARDENING.md §"ERC-7730 timing channels"`
/// for the surrounding threat-model context.
const STACK_CANARY: u32 = 0xDEAD_BEEF;

/// Entry point for contract-context renders. Phase 4 wires this into
/// [`super::pick_sign_pages`] between the Safe-V1 rung and the
/// plain-ETH check.
pub fn render_erc7730_pages<'ir>(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, RenderErr> {
    // Stack canary (Phase 5 item 11). Volatile read/write so LLVM
    // cannot prove the value is dead and remove the check.
    let mut canary: u32 = 0;
    // SAFETY: `canary` is a unique local; the volatile write defeats
    // dead-store elimination so a stack-overrun stomp on the slot is
    // observable at function exit.
    unsafe { core::ptr::write_volatile(&mut canary, STACK_CANARY) };

    let result = render_erc7730_pages_inner(tx, inner_data, descriptor, erc20, resolver);

    // SAFETY: same slot we wrote to above; no other context can have
    // written it (secure world is single-threaded + non-reentrant).
    let final_canary = unsafe { core::ptr::read_volatile(&canary) };
    assert!(
        final_canary == STACK_CANARY,
        "ERC-7730 renderer stack canary smashed (got {:#x}, expected {:#x})",
        final_canary,
        STACK_CANARY
    );
    result
}

fn render_erc7730_pages_inner<'ir>(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, RenderErr> {
    // 1. Locate the format by 4-byte calldata selector.
    if inner_data.len() < 4 {
        return Err(RenderErr::NoFormat);
    }
    let selector: [u8; 4] = inner_data[..4].try_into().unwrap();
    let format = descriptor
        .ir
        .find_format_by_selector(&selector)
        .map_err(|_| RenderErr::Reject("7730 bad formats"))?
        .ok_or(RenderErr::NoFormat)?;
    // Head-bound guard (defence-in-depth behind the width-aware path
    // slots). Truncate the calldata body to the format's ABI static head
    // so any field whose resolved slot lands beyond the static head — a
    // malformed descriptor reading into the dynamic tail — fails the
    // walker's `body.get(slot..)` bound and is rejected, never silently
    // rendered. Field slots are always < static_head_words by
    // construction, so this never rejects a well-formed descriptor. See
    // `docs/security/VULN-erc7730-walker-slot-confusion.md`.
    let body = head_bounded_body(&inner_data[4..], format.static_head_words)?;
    // The FULL (untruncated) body is handed ONLY to the dynamic-array
    // renderer, which follows a sole-dynamic-array tail with its own exact-
    // placement bounds checks. Scalar fields keep using the head-bounded
    // `body` above — their slot-confusion defense is unchanged.
    let full_body = &inner_data[4..];

    // 2. Allocate the page buffer (grows via push_blank).
    let mut pages = Pages::with_len(0);

    // 3. Banner — page 0.
    intent::render_intent_banner(&mut pages, &descriptor.ir, &format)?;

    // 4. Iterate fields.
    render_fields(
        &mut pages,
        &descriptor.ir,
        &format,
        body,
        full_body,
        tx,
        erc20,
        resolver,
    )?;

    // 5. Envelope pages (chain / fee / nonce). Mirrors the tail of the
    //    erc20_known renderer so the user always sees gas + chain
    //    information regardless of which descriptor lit up.
    append_envelope_pages(&mut pages, tx)?;

    // 6. Final confirm-button page.
    append_confirm_page(&mut pages)?;

    Ok(pages)
}

/// Entry point for EIP-712 typed-data renders driven by the
/// `OFFCHAIN_KIND_EIP712_TYPED = 2` sign path. Caller passes the
/// companion-supplied `primary_type_hash` + `encoded_data` so the
/// renderer can locate the right
/// [`pqsigner_erc7730::ir::FormatHeader`] and walk the typed-data
/// fields.
pub fn render_erc7730_eip712_pages<'ir>(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, RenderErr> {
    // Stack canary (Phase 5 item 11) — see render_erc7730_pages above.
    let mut canary: u32 = 0;
    // SAFETY: unique local, volatile write defeats dead-store
    // elimination.
    unsafe { core::ptr::write_volatile(&mut canary, STACK_CANARY) };

    let result = render_erc7730_eip712_pages_inner(
        chain_id,
        verifying_contract,
        primary_type_hash,
        encoded_data,
        descriptor,
        erc20,
        resolver,
    );

    // SAFETY: same slot we wrote to above.
    let final_canary = unsafe { core::ptr::read_volatile(&canary) };
    assert!(
        final_canary == STACK_CANARY,
        "ERC-7730 EIP-712 renderer stack canary smashed (got {:#x}, expected {:#x})",
        final_canary,
        STACK_CANARY
    );
    result
}

fn render_erc7730_eip712_pages_inner<'ir>(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, RenderErr> {
    // 1. Locate the format by the FULL 32-byte primary-type hash and bind
    //    it constant-time (audit M-5). The 4-byte selector only picks the
    //    display template; the signature commits to the full
    //    `primary_type_hash`, so selecting on a 4-byte prefix would let a
    //    companion render template A while the contract honours a
    //    different type B whose hash shares A's first 4 bytes. Matching
    //    all 32 bytes closes that gap.
    use subtle::ConstantTimeEq;
    let mut format = None;
    for entry in descriptor.ir.format_iter() {
        let header = entry.map_err(|_| RenderErr::Reject("7730 bad formats"))?;
        if bool::from(header.type_hash.ct_eq(primary_type_hash)) {
            format = Some(header);
            break;
        }
    }
    let format = format.ok_or(RenderErr::NoFormat)?;

    // 2. Build a synthetic envelope tx so the formatters can render
    //    `@.chainId` / `@.to` / `@.value` against the EIP-712 domain.
    //    `value` defaults to zero (no on-chain transfer for typed-data
    //    signing); `to` is the verifying contract.
    let synth_tx = Eip1559Tx {
        chain_id,
        nonce: 0,
        max_priority_fee_per_gas: crate::tx::eip1559::U256::zero(),
        max_fee_per_gas: crate::tx::eip1559::U256::zero(),
        gas_limit: 0,
        to: Some(*verifying_contract),
        value: crate::tx::eip1559::U256::zero(),
        data_len: 0,
        access_list_count: 0,
        signing_hash: [0u8; 32],
    };

    // Head-bound guard — see `render_erc7730_pages_inner`. For EIP-712
    // `encodeData` every member is exactly one 32-byte word, so
    // `static_head_words` is the member count and the body is the encoded
    // member words. Unlike calldata there is NO dynamic tail, so require an
    // EXACT length rather than the `>=` that `head_bounded_body` allows: a
    // companion must not be able to append extra member words that fold
    // into the signed `structHash` (`keccak(primary_type_hash ||
    // encoded_data)`) but render past `static_head_words` and never
    // display. Without this, a blessed descriptor that under-declares
    // `static_head_words` would let those trailing words be
    // signed-but-not-shown (audit defense-in-depth 2026-06-11). On a
    // mismatch the caller falls back to the raw32 page, which honestly
    // shows the EIP-712 final digest as an opaque hash.
    let head_len = (format.static_head_words as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 ed head overflow"))?;
    if encoded_data.len() != head_len {
        return Err(RenderErr::Reject("7730 ed len"));
    }
    let body = head_bounded_body(encoded_data, format.static_head_words)?;

    let mut pages = Pages::with_len(0);
    intent::render_intent_banner(&mut pages, &descriptor.ir, &format)?;
    // EIP-712 `encodeData` is all one-word members — no dynamic tail — so the
    // full body IS the head body; an `[]` field (nonsensical here) safely
    // declines inside `render_array` (its tail/length checks fail).
    render_fields(
        &mut pages,
        &descriptor.ir,
        &format,
        body,
        body,
        &synth_tx,
        erc20,
        resolver,
    )?;
    append_eip712_chain_page(&mut pages, chain_id)?;
    append_confirm_page(&mut pages)?;
    Ok(pages)
}

/// Clamp a structured body to its format's ABI static head
/// (`static_head_words` × 32 bytes). Rejects a body too short to contain
/// the full static head (truncated / malformed calldata). The returned
/// slice is what every field walker sees, so a path slot that would read
/// past the static head falls outside it and is rejected by the walker's
/// bounds check rather than silently resolving into the dynamic tail.
fn head_bounded_body(body: &[u8], static_head_words: u16) -> Result<&[u8], RenderErr> {
    let head_len = (static_head_words as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 head overflow"))?;
    body.get(..head_len).ok_or(RenderErr::Reject("7730 short head"))
}

fn render_fields(
    pages: &mut Pages,
    ir: &crate::tx::erc7730::Erc7730Ir<'_>,
    format: &crate::tx::erc7730::FormatHeader<'_>,
    body: &[u8],
    full_body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        match should_render_with_mode(&params, None, COMPACT_MODE) {
            Action::Render => {
                // A field whose path ends in `[]` (ArrayAll) renders every
                // element of a sole dynamic array — it needs the FULL body and
                // its own exact-placement tail walk. Every other field stays on
                // the head-bounded `body` + the existing formatter dispatch
                // (byte-identical scalar path).
                if formatters::path_ends_with_array_all(ir, field.path_off)? {
                    formatters::render_array(
                        &field,
                        pages,
                        ir,
                        full_body,
                        format.static_head_words,
                        tx,
                        erc20,
                        resolver,
                        &params,
                    )?;
                } else if formatters::path_is_dynamic_leaf(ir, field.path_off)? {
                    // C1: a dynamic `bytes`/`string` leaf — its value is in the
                    // calldata tail (needs the FULL body).
                    formatters::render_dynamic_bytes(
                        &field, pages, ir, full_body, tx, erc20, resolver, &params,
                    )?;
                } else if formatters::path_needs_full_body(ir, field.path_off)? {
                    // C2: a scalar field reached by descending a dynamic offset
                    // (dynamic-tuple member) — same scalar renderers, FULL body.
                    formatters::dispatch(&field, pages, ir, full_body, tx, erc20, resolver, &params)?;
                } else {
                    // Static-head scalar — head-bounded body (byte-identical).
                    formatters::dispatch(&field, pages, ir, body, tx, erc20, resolver, &params)?;
                }
            }
            Action::Skip => continue,
            Action::Reject(msg) => return Err(RenderErr::Reject(msg)),
        }
    }
    Ok(())
}

fn append_envelope_pages(pages: &mut Pages, tx: &Eip1559Tx) -> Result<(), RenderErr> {
    // Chain.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Chain:");
    write_chain(pages.row_mut(p, 1), tx.chain_id);
    write_line(pages.row_mut(p, 2), chain_name(tx.chain_id));
    write_line(pages.row_mut(p, 3), "> next");

    // Fees.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Max fee:");
    let _ = write_gwei(pages.row_mut(p, 1), &tx.max_fee_per_gas);
    write_tip_row(pages.row_mut(p, 2), &tx.max_priority_fee_per_gas);
    write_line(pages.row_mut(p, 3), "> next");

    // Worst-case fee budget + gas.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Worst-case:");
    write_fee_budget_row(pages.row_mut(p, 1), &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(pages.row_mut(p, 2), tx.gas_limit);
    write_line(pages.row_mut(p, 3), "> next");

    // Nonce.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_nonce_row(pages.row_mut(p, 0), tx.nonce);
    write_line(pages.row_mut(p, 3), "> next");

    Ok(())
}

fn append_eip712_chain_page(pages: &mut Pages, chain_id: u64) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Chain:");
    write_chain(pages.row_mut(p, 1), chain_id);
    write_line(pages.row_mut(p, 2), chain_name(chain_id));
    write_line(pages.row_mut(p, 3), "> next");
    Ok(())
}

fn append_confirm_page(pages: &mut Pages) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 2), "L=Cancel");
    write_line(pages.row_mut(p, 3), "R=Confirm");
    Ok(())
}
