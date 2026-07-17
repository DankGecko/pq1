//! ERC-7730 clear-signing renderer — UI-bound half.
//!
//! Pure-logic pieces (TLV parameter parser, visibility evaluator,
//! `RenderErr`) live at `crate::render::*` so host-test
//! builds (which gate out `crate::tx::display`) can still exercise
//! them. This module owns the [`Pages`]-using formatter dispatcher,
//! intent renderer, and nested-calldata recursor.
//!
//! Entry points:
//!
//! - [`render_erc7730_pages`] — contract context (EIP-1559 UserOp
//!   execution against a known smart contract).
//! - [`render_erc7730_pages_with_signer`] — the same contract context with an
//!   independently derived device signer, required to resolve `@.from`.
//! - [`render_erc7730_eip712_pages`] — EIP-712 typed-data offchain
//!   signs driven by `OFFCHAIN_KIND_EIP712_TYPED = 2` (Step 7).
//! - [`render_erc7730_eip712_pages_v3`] — the v3 EIP-712 typed-data path.
//!
//! All consume a [`VerifiedDescriptor`] minted by Phase 3's bundle
//! verifier and produce a [`Pages`] object the existing
//! [`crate::ui::confirm::confirm`] loop drives.
//!
//! Returning [`RenderErr`] from the entry points is how the renderer tells the
//! secure dispatcher "I don't have a clean rendering for this transaction."
//! A verified descriptor error is a hard refusal, and the independently pinned
//! known-call filter also refuses omission/malformed-proof downgrade attempts.
//! See the per-variant docs on
//! [`crate::render::RenderErr`].

pub mod amount_decision;
mod calldata_nested;
pub mod formatters;
pub mod intent;
pub mod nested;

use pqsigner_tx::erc20::bundle::Erc20Metadata;
use pqsigner_tx::names::NameResolver;
use super::primitives::{
    format_u64, hex_nibble, known_native_ticker, write_array_item_row, write_chain, write_line,
    write_native_amount_two_rows, write_native_currency_row, AmountFit,
};
use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};
use crate::bundle::VerifiedDescriptor;
use crate::render::params::parse as parse_params;
use crate::render::visibility::{should_render_with_mode, Action};
use crate::render::RenderErr;

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

/// Maximum nested-EIP-712 struct descent depth the device renders (v3 deep
/// types). A top-level nested-struct anchor is depth 1; a struct/array-of-struct
/// member of it is depth 2, etc. Kept in lockstep with dbgen's `MAX_STRUCT_DEPTH`
/// (8): the pinned IR is finite, but the device enforces its own bound so the
/// recursion is Kani-tractable and stack-safe even against a crafted-deep IR — a
/// deeper member declines the whole format (fail-closed).
const MAX_NESTED_DEPTH: u8 = 8;

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
    render_erc7730_pages_scoped(tx, inner_data, descriptor, erc20, resolver, None)
}

/// Contract-context render with an independently derived UserOperation sender.
///
/// This is the only entry point that can resolve descriptor `@.from`. The
/// secure handlers pass their already-FI-bound `sender` explicitly; the
/// generic contract renderer above and both EIP-712 renderers retain no sender
/// context and therefore fail closed on `@.from`.
pub fn render_erc7730_pages_with_signer<'ir>(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    device_signer: &[u8; 20],
) -> Result<Pages, RenderErr> {
    render_erc7730_pages_scoped(
        tx,
        inner_data,
        descriptor,
        erc20,
        resolver,
        Some(device_signer),
    )
}

fn render_erc7730_pages_scoped<'ir>(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    device_signer: Option<&[u8; 20]>,
) -> Result<Pages, RenderErr> {
    // Stack canary (Phase 5 item 11). Volatile read/write so LLVM
    // cannot prove the value is dead and remove the check.
    let mut canary: u32 = 0;
    // SAFETY: `canary` is a unique local; the volatile write defeats
    // dead-store elimination so a stack-overrun stomp on the slot is
    // observable at function exit.
    unsafe { core::ptr::write_volatile(&mut canary, STACK_CANARY) };

    let result = render_erc7730_pages_inner(
        tx,
        inner_data,
        descriptor,
        erc20,
        resolver,
        device_signer,
    );

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
    device_signer: Option<&[u8; 20]>,
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
    // `docs/security/vulns/VULN-erc7730-walker-slot-confusion.md`.
    let body = head_bounded_body(&inner_data[4..], format.static_head_words)?;
    // The FULL (untruncated) body is handed only to canonical dynamic-tail
    // validation/rendering (sole string/bytes, primitive array, or tokenPath
    // container). Static scalar fields keep using the head-bounded `body`.
    let full_body = &inner_data[4..];

    // Canonical ABI framing is a format-wide property, not a visible-field
    // property. Run the preflight before painting any pages and before
    // visibility can skip a field: all-static calls must consume exactly the
    // authenticated head, while every supported dynamic shape must be one
    // exact whole tail. C2 dynamic tuples and relaxed multi-array tails are
    // unprovable from the current IR and hard-refuse.
    formatters::validate_contract_calldata_framing(&descriptor.ir, &format, full_body)?;

    // 2. Allocate the page buffer (grows via push_blank).
    let mut pages = Pages::with_len(0);

    // 3. Banner — page 0. Exact-zero approval wording is derived only when a
    // Merkle-authenticated ERC-20 capability binds this chain+contract and the
    // signed calldata is the strict canonical `approve(address,uint256)`
    // frame. Selector-only inference is forbidden because ERC-721 collides.
    let derived_intent = authenticated_contract_intent(
        tx,
        inner_data,
        &descriptor.ir,
        &format,
        body,
        erc20,
    )?;
    intent::render_intent_banner(&mut pages, &descriptor.ir, &format, derived_intent)?;

    // 4. Iterate fields. Contract-context formats never carry a
    //    `PARAM_NESTED_STRUCT` field (dbgen only emits it for EIP-712), so the
    //    nested descent never triggers here — pass an empty context.
    let field_pages_before = pages.as_slice().len();
    render_fields(
        &mut pages,
        &descriptor.ir,
        &format,
        body,
        full_body,
        tx,
        erc20,
        resolver,
        device_signer,
        &mut NestedCtx::default(),
    )?;

    // 4b. WYSIWYS belt (VULN-erc7730-visible-never-noparam-clearsign). A
    // contract-context known shape that DECLARES fields but renders NONE of
    // them — every field `visible:"never"` — would otherwise present a
    // trusted clear-sign (banner + envelope + confirm) with none of the
    // call's parameters shown: a blind-sign wearing a reassuring clear-sign
    // banner, worse than an honest loud blind-sign. Reject the render; the
    // secure dispatcher hard-refuses this verified/known tuple. The build-time
    // visibility gate (`dbgen::erc7730::check_field_visibility`) already
    // prevents such descriptors entering the Merkle-pinned root; this is the
    // on-device structural backstop that holds even if one ever slips in.
    // Zero-field formats (`deposit()`) declare no fields and are unaffected;
    // payable stakes (`submit`) render their `@.value` field and pass.
    if format.field_count > 0 && pages.as_slice().len() == field_pages_before {
        return Err(RenderErr::Reject("7730 no visible fields"));
    }

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
/// [`crate::ir::FormatHeader`] and walk the typed-data
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

    // V2 kind: no nested-struct section (an empty `nested_blob`). A nested
    // format signed via kind=2 therefore Rejects at the descent (no record to
    // pull) — a companion must use `OFFCHAIN_KIND_EIP712_TYPED_V3`.
    let result = render_erc7730_eip712_pages_inner(
        chain_id,
        verifying_contract,
        primary_type_hash,
        encoded_data,
        &[],
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

/// Entry point for the `OFFCHAIN_KIND_EIP712_TYPED_V3 = 3` sign path — the
/// nested-EIP-712 variant. Identical to [`render_erc7730_eip712_pages`] plus the
/// companion-supplied DFS `nested_blob` (`[u16 len][nested_ed]` records) that
/// backs the nested-struct DISPLAY binding.
///
/// The device threads `nested_blob` into the nested-aware renderer: for each
/// `PARAM_NESTED_STRUCT` member it verifies `hash_struct(pinned type_hash,
/// nested_ed) == the committed hashStruct word` (constant-time) BEFORE expanding
/// the members, and enforces the E1 reconciliation (`records_consumed ==
/// pinned nested_descent_count` ∧ `cursor == nested_blob.len()`). The bare
/// `0x01` belt marker (an unsupported nested shape) still declines the whole
/// format — the fail-safe, inverted not removed.
pub fn render_erc7730_eip712_pages_v3<'ir>(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    nested_blob: &[u8],
    descriptor: &'ir VerifiedDescriptor<'ir>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, RenderErr> {
    // Stack canary (Phase 5 item 11) — same discipline as the V2 entry.
    let mut canary: u32 = 0;
    // SAFETY: unique local, volatile write defeats dead-store elimination.
    unsafe { core::ptr::write_volatile(&mut canary, STACK_CANARY) };

    let result = render_erc7730_eip712_pages_inner(
        chain_id,
        verifying_contract,
        primary_type_hash,
        encoded_data,
        nested_blob,
        descriptor,
        erc20,
        resolver,
    );

    // SAFETY: same slot we wrote to above.
    let final_canary = unsafe { core::ptr::read_volatile(&canary) };
    assert!(
        final_canary == STACK_CANARY,
        "ERC-7730 EIP-712 V3 renderer stack canary smashed (got {:#x}, expected {:#x})",
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
    nested_blob: &[u8],
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
        max_priority_fee_per_gas: pqsigner_tx_core::eip1559::U256::zero(),
        max_fee_per_gas: pqsigner_tx_core::eip1559::U256::zero(),
        gas_limit: 0,
        to: Some(*verifying_contract),
        value: pqsigner_tx_core::eip1559::U256::zero(),
        data_len: 0,
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: None,
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
    // mismatch the typed-data signing request refuses; it cannot silently
    // downgrade to a raw32 authorization.
    let head_len = (format.static_head_words as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 ed head overflow"))?;
    if encoded_data.len() != head_len {
        return Err(RenderErr::Reject("7730 ed len"));
    }
    let body = head_bounded_body(encoded_data, format.static_head_words)?;

    let mut pages = Pages::with_len(0);
    intent::render_intent_banner(&mut pages, &descriptor.ir, &format, None)?;
    // EIP-712 `encodeData` is all one-word members — no dynamic tail — so the
    // full body IS the head body; an `[]` field (nonsensical here) safely
    // declines inside `render_array` (its tail/length checks fail).
    let field_pages_before = pages.as_slice().len();
    let mut nested_ctx = NestedCtx {
        blob: nested_blob,
        cursor: 0,
        records_consumed: 0,
    };
    render_fields(
        &mut pages,
        &descriptor.ir,
        &format,
        body,
        body,
        &synth_tx,
        erc20,
        resolver,
        None,
        &mut nested_ctx,
    )?;
    // E1 reconciliation (the top-level analog of the belt): the device must have
    // BOUND every nested descent point the descriptor pins, and consumed the
    // WHOLE `nested_blob`. `nested_descent_count` is dbgen-pinned INDEPENDENT of
    // this traversal, so a regression that makes descent conditional
    // under-consumes and trips here; a `cursor != blob.len()` means a companion
    // padded the blob with an unbound record (E4-3). Either → decline.
    if nested_ctx.records_consumed != format.nested_descent_count as u16 {
        return Err(RenderErr::Reject("7730 nested descent mismatch"));
    }
    if nested_ctx.cursor != nested_blob.len() {
        return Err(RenderErr::Reject("7730 nested blob trailing"));
    }
    // WYSIWYS belt (VULN-erc7730-visible-never-noparam-clearsign), typed-data
    // sibling of the calldata guard above. A typed-data format that declares
    // members but renders none (all `visible:"never"`) would sign an
    // off-chain approval showing nothing; refuse the typed-data request. No
    // native-value rescue exists for EIP-712, so the guard is unconditional.
    if format.field_count > 0 && pages.as_slice().len() == field_pages_before {
        return Err(RenderErr::Reject("7730 no visible members"));
    }
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

/// Derive presentation copy only from an authenticated ERC-20 capability and
/// the exact signed calldata. The strict decoder requires the canonical
/// 68-byte ABI frame (including zero address padding and no trailing bytes),
/// while the metadata match and authenticated field-shape witness establish
/// ERC-20 semantics despite the shared ERC-721 `approve(address,uint256)`
/// selector.
fn authenticated_contract_intent<'a>(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    ir: &crate::ir::Erc7730Ir<'_>,
    format: &crate::ir::FormatHeader<'_>,
    body: &[u8],
    erc20: Option<&Erc20Metadata<'a>>,
) -> Result<Option<&'static [u8]>, RenderErr> {
    let Some(meta) = erc20 else {
        return Ok(None);
    };
    if meta.chain_id != tx.chain_id
        || tx.to.as_ref() != Some(&meta.contract)
        || ir.chain_id != tx.chain_id
        || ir.contract != meta.contract
    {
        return Ok(None);
    }
    let exact_zero_approve = matches!(
        pqsigner_tx::erc20::calldata::parse_erc20_calldata(inner_data),
        Some(pqsigner_tx::erc20::calldata::Erc20Call::Approve { amount, .. })
            if amount.is_zero()
    );
    if !exact_zero_approve || format.static_head_words != 2 {
        return Ok(None);
    }

    // The copy must not replace or launder incomplete descriptor fields. Pin
    // an authenticated semantic witness in the selected IR: word 0 is visibly
    // rendered as an address, and word 1 is visibly rendered as a token amount
    // whose tokenPath resolves to this exact metadata-bound contract. The
    // TokenAmount renderer then necessarily paints the zero and appends the
    // full token-contract identity page; the normal envelope keeps chain
    // visible. A canonical ERC-721 approve has the same selector/framing but
    // uses NftName/Raw for word 1, so it cannot satisfy this witness.
    let mut spender_visible = false;
    let mut allowance_visible = false;
    for entry in format.fields() {
        let field = entry.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        if !matches!(
            should_render_with_mode(&params, None, COMPACT_MODE),
            Action::Render
        ) {
            continue;
        }
        let op = crate::ir::FormatOp::try_from(field.format_op)
            .map_err(|_| RenderErr::Reject("7730 bad format op"))?;
        match op {
            crate::ir::FormatOp::AddressName => {
                if let formatters::Resolved::Slot32(word) =
                    formatters::resolve_path(ir, field.path_off, body)?
                {
                    if core::ptr::eq(word.as_ptr(), body.as_ptr()) {
                        spender_visible = true;
                    }
                }
            }
            crate::ir::FormatOp::TokenAmount => {
                if let formatters::Resolved::Slot32(word) =
                    formatters::resolve_path(ir, field.path_off, body)?
                {
                    if core::ptr::eq(word.as_ptr(), body[32..].as_ptr())
                        && formatters::resolve_token_address(ir, body, tx, &params)?
                            == meta.contract
                    {
                        allowance_visible = true;
                    }
                }
            }
            _ => {}
        }
    }
    Ok((spender_visible && allowance_visible).then_some(b"Revoke approval"))
}

/// Threaded through [`render_fields`] to carry the nested-EIP-712 struct DFS
/// state (Phase 5). Empty (`Default`) for the calldata path and for a non-nested
/// typed message; a V3 typed message supplies the companion `blob` and the
/// renderer advances `cursor` + `records_consumed` as it binds each nested
/// member. The EIP-712 inner reconciles the final state against the format's
/// PINNED `nested_descent_count` (E1) + `blob.len()` (E4-3).
#[derive(Default)]
struct NestedCtx<'a> {
    blob: &'a [u8],
    cursor: usize,
    records_consumed: u16,
}

fn render_fields(
    pages: &mut Pages,
    ir: &crate::ir::Erc7730Ir<'_>,
    format: &crate::ir::FormatHeader<'_>,
    body: &[u8],
    full_body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    device_signer: Option<&[u8; 20]>,
    nested: &mut NestedCtx<'_>,
) -> Result<(), RenderErr> {
    for field_result in format.fields() {
        let field = field_result.map_err(|_| RenderErr::Reject("7730 bad field"))?;
        let params = parse_params(ir, field.param_off)?;
        // Nested-EIP-712 struct descent (Phase 5). E1: the descent + keccak
        // binding run on the STRUCTURAL marker ALONE, BEFORE and INDEPENDENT of
        // the visibility decision — a hidden/skipped sub-field is just a word
        // the hash already covers, but the WHOLE member's `hashStruct` word is
        // ALWAYS bound. `params.nested_struct` carries the raw payload; the bare
        // `0x01` belt marker (an unsupported nested shape dbgen refused to
        // expand) still declines the whole format — the fail-safe, inverted not
        // removed. See `docs/erc7730-nested-eip712-render-design.md`.
        if let Some(payload) = params.nested_struct {
            if payload.first() == Some(&0x01) {
                // Bare belt marker: dbgen could not build a v0x03 block for this
                // nested member (array / depth>1 / uncovered address / …) →
                // reject the WHOLE typed-data request.
                return Err(RenderErr::Reject("7730 eip712 nested unsupported"));
            }
            render_nested_struct(
                pages,
                ir,
                payload,
                body,
                nested,
                1,
                tx,
                erc20,
                resolver,
                device_signer,
            )?;
            continue;
        }
        render_one_field(
            pages,
            ir,
            &field,
            &params,
            body,
            full_body,
            format.static_head_words,
            tx,
            erc20,
            resolver,
            device_signer,
        )?;
    }
    Ok(())
}

/// Render one already-parsed field (top-level OR a nested sub-field) against
/// `body` (+ `full_body` for the dynamic-tail cases). Extracted so the nested
/// descent renders a sub-field byte-identically to a top-level field, with the
/// nested member's `encodeData` as the body (LOCAL resolution).
#[allow(clippy::too_many_arguments)]
fn render_one_field(
    pages: &mut Pages,
    ir: &crate::ir::Erc7730Ir<'_>,
    field: &crate::ir::FieldEntry<'_>,
    params: &crate::render::params::ParamSet<'_>,
    body: &[u8],
    full_body: &[u8],
    static_head_words: u16,
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    device_signer: Option<&[u8; 20]>,
) -> Result<(), RenderErr> {
    match should_render_with_mode(params, None, COMPACT_MODE) {
        Action::Render => {
            // Full-body dynamic resolution is safe only after the first
            // signature-fixed word has been proven to lie in the declared ABI
            // head. Keep this runtime belt independent of dbgen's slot
            // compiler; malformed authenticated IR must still fail closed.
            formatters::validate_path_static_head(ir, field.path_off, static_head_words)?;
            formatters::validate_token_path_static_head(params, static_head_words)?;
            // A field whose path ends in `[]` (ArrayAll) renders every
            // element of a sole dynamic array — it needs the FULL body and
            // its own exact-placement tail walk. Every other field stays on
            // the head-bounded `body` + the existing formatter dispatch
            // (byte-identical scalar path). A nested sub-field never routes
            // here (nested_ed is exact-length, no `[]` member in v1).
            if formatters::path_ends_with_array_all(ir, field.path_off)? {
                formatters::render_array(
                    field,
                    pages,
                    ir,
                    full_body,
                    static_head_words,
                    tx,
                    erc20,
                    resolver,
                    params,
                )?;
            } else if formatters::path_is_dynamic_leaf(ir, field.path_off)? {
                // C1: a dynamic `bytes`/`string` leaf — its value is in the
                // calldata tail (needs the FULL body).
                formatters::render_dynamic_bytes(
                    field,
                    pages,
                    ir,
                    full_body,
                    static_head_words,
                    tx,
                    erc20,
                    resolver,
                    params,
                )?;
            } else if formatters::path_needs_full_body(ir, field.path_off)? {
                // C2 dynamic-tuple placement cannot be reconstructed exactly
                // from today's IR (the nested head width/tail topology is not
                // encoded). The format-wide preflight already rejects it,
                // and this local belt prevents a future call-site bypass.
                return Err(RenderErr::Reject("7730 C2 framing unsupported"));
            } else if formatters::token_path_needs_full_body(params) {
                // A Tier-B tokenPath is accepted only after the format-wide
                // preflight proved a sole C1 bytes/address[] whole tail. Paint
                // against the same full body; malformed extraction cannot
                // degrade to raw because preflight resolves it first.
                formatters::dispatch(
                    field,
                    pages,
                    ir,
                    full_body,
                    tx,
                    erc20,
                    resolver,
                    params,
                    device_signer,
                )?;
            } else {
                // Static-head scalar — head-bounded body (byte-identical).
                formatters::dispatch(
                    field,
                    pages,
                    ir,
                    body,
                    tx,
                    erc20,
                    resolver,
                    params,
                    device_signer,
                )?;
            }
            Ok(())
        }
        Action::Skip => Ok(()),
        Action::Reject(msg) => Err(RenderErr::Reject(msg)),
    }
}

/// Bind + render one nested-EIP-712 member — a single struct (v1) OR a
/// single-level array-of-struct (`T[]`, v2).
///
/// The security spine: the member's committed word sits at `word_pos` of the
/// SIGNED `parent_body`. For a single struct it is `keccak(type_hash ‖ ed)`; for
/// an array it is `keccak(hashStruct(el0) ‖ … ‖ hashStruct(elN))` (the EIP-712
/// `T[]` encoding). The device requires that committed word to equal the value it
/// recomputes from the companion's `nested.blob` (constant-time) BEFORE rendering
/// ANY sub-field → shown ⟺ signed by collision-resistance. Every decline is a
/// hard `Err` that unwinds the whole render (the caller discards the partial
/// `Pages`), so a mismatch never leaks a partially-rendered member (E4-1).
#[allow(clippy::too_many_arguments)]
fn render_nested_struct(
    pages: &mut Pages,
    ir: &crate::ir::Erc7730Ir<'_>,
    payload: &[u8],
    parent_body: &[u8],
    nested: &mut NestedCtx<'_>,
    depth: u8,
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    device_signer: Option<&[u8; 20]>,
) -> Result<(), RenderErr> {
    use crate::render::nested as pn;
    use subtle::ConstantTimeEq;

    // Bound the recursion (v3 depth-2+): the pinned IR is finite, but a
    // depth guard keeps the descent Kani-bounded and stack-safe even against a
    // (hypothetical) crafted-deep pinned IR. `MAX_NESTED_DEPTH` matches dbgen's
    // `MAX_STRUCT_DEPTH`; a deeper member declines the whole format.
    if depth > MAX_NESTED_DEPTH {
        return Err(RenderErr::Reject("7730 nested too deep"));
    }

    // 1. Parse the pinned v0x03 payload (bounds-checked, pure).
    let np = pn::parse_nested_struct_param(payload)?;

    // 2. The committed word in the parent's SIGNED encoded_data.
    let wp = (np.word_pos as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 nested wp ovf"))?;
    let committed: &[u8; 32] = parent_body
        .get(wp..wp + 32)
        .ok_or(RenderErr::Reject("7730 nested wp oob"))?
        .try_into()
        .map_err(|_| RenderErr::Reject("7730 nested cw"))?;

    // 3. Count this member as ONE descent point (E1) — single OR array. The
    //    dbgen-pinned `nested_descent_count` counts anchors, not records, so the
    //    reconciliation holds for arrays (the `cursor == blob.len()` check proves
    //    the element records were consumed exactly).
    nested.records_consumed = nested
        .records_consumed
        .checked_add(1)
        .ok_or(RenderErr::Reject("7730 nested count ovf"))?;

    // 4. Each element's `encodeData` is EXACTLY `member_count × 32` (rule 1).
    let expected = (np.member_count as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 nested mc ovf"))?;

    if np.is_array {
        // ── v2 array-of-struct ─────────────────────────────────────────────
        // Wire: `[u16 elem_count]` then `elem_count` × `[u16 len][elem_ed]`.
        let ec = nested
            .blob
            .get(nested.cursor..nested.cursor + 2)
            .ok_or(RenderErr::Reject("7730 nested no elemcount"))?;
        let elem_count = u16::from_be_bytes([ec[0], ec[1]]) as usize;
        nested.cursor += 2;
        // `elem_count == 0` does NOT trip the top-level "no visible members" belt
        // (a sibling top-level field renders), so a companion could bind
        // `keccak("")` and clear-sign an empty batch — decline explicitly.
        if elem_count == 0 {
            return Err(RenderErr::Reject("7730 nested array empty"));
        }
        if elem_count > crate::ir::MAX_NESTED_ARRAY {
            return Err(RenderErr::Reject("7730 nested array cap"));
        }

        // Collect every element (bounded stack buffer), verifying each is exactly
        // `member_count × 32`, THEN bind the whole array BEFORE rendering
        // (collect-verify-then-render preserves WYSIWYS + atomicity).
        let mut elems: [&[u8]; crate::ir::MAX_NESTED_ARRAY] =
            [&[][..]; crate::ir::MAX_NESTED_ARRAY];
        for slot in elems.iter_mut().take(elem_count) {
            let (elem_ed, nc) = pn::read_next_nested_ed(nested.blob, nested.cursor)?;
            nested.cursor = nc;
            if elem_ed.len() != expected {
                return Err(RenderErr::Reject("7730 nested ed len"));
            }
            *slot = elem_ed;
        }
        // THE ARRAY BINDING — keccak(concat of per-element hashStructs) ==
        // committed, constant-time. A lied `elem_count`, a swapped/edited element,
        // or a wrong committed word all break the equality → decline.
        let bind = nested::hash_struct_array(np.type_hash, &elems[..elem_count]);
        if !bool::from(bind.ct_eq(committed)) {
            return Err(RenderErr::Reject("7730 nested array binding"));
        }
        // E2 address-coverage + E4-2 bounds ONCE (every element is the same
        // pinned struct shape → same addr_word_bmp + sub-field ordinals).
        pn::validate_nested_structure(ir, &np, COMPACT_MODE)?;
        // Render each element with an "Item i of N" divider. `push_blank` → Err
        // on page-budget overflow → decline (NEVER truncate a tail — that is the
        // array-hiding WYSIWYS break one level down).
        for (i, elem_ed) in elems.iter().enumerate().take(elem_count) {
            let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
            write_array_item_row(pages.row_mut(p, 0), i, elem_count);
            render_nested_subfields(
                pages,
                ir,
                &np,
                elem_ed,
                nested,
                depth,
                tx,
                erc20,
                resolver,
                device_signer,
            )?;
        }
        return Ok(());
    }

    // ── v1 single nested struct ────────────────────────────────────────────
    let (nested_ed, nc) = pn::read_next_nested_ed(nested.blob, nested.cursor)?;
    nested.cursor = nc;
    if nested_ed.len() != expected {
        return Err(RenderErr::Reject("7730 nested ed len"));
    }
    // THE BINDING — keccak(pinned type_hash ‖ nested_ed) == committed word.
    let hs = nested::hash_struct(np.type_hash, nested_ed);
    if !bool::from(hs.ct_eq(committed)) {
        return Err(RenderErr::Reject("7730 nested binding"));
    }
    pn::validate_nested_structure(ir, &np, COMPACT_MODE)?;
    render_nested_subfields(
        pages,
        ir,
        &np,
        nested_ed,
        nested,
        depth,
        tx,
        erc20,
        resolver,
        device_signer,
    )?;
    Ok(())
}

/// Render every visible sub-field of a nested struct against `nested_ed` (its
/// exact-length member body — LOCAL resolution). Shared by the v1 single-struct
/// path and each v2 array element. A sub-field that is itself nested (depth > 1)
/// is a v3 shape dbgen does not emit — decline rather than recurse into
/// un-verified territory.
#[allow(clippy::too_many_arguments)]
fn render_nested_subfields(
    pages: &mut Pages,
    ir: &crate::ir::Erc7730Ir<'_>,
    np: &crate::render::nested::NestedStructParam<'_>,
    nested_ed: &[u8],
    nested: &mut NestedCtx<'_>,
    depth: u8,
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    device_signer: Option<&[u8; 20]>,
) -> Result<(), RenderErr> {
    for sf in np.sub_fields() {
        let sf = sf.map_err(|_| RenderErr::Reject("7730 nested subfield"))?;
        let sf_params = parse_params(ir, sf.param_off)?;
        // v3 depth-2+: a sub-field that is ITSELF a nested struct/array-of-struct
        // (`witness.info`, `witness.outputs`). Recurse: the CURRENT struct's
        // `nested_ed` is the child's `parent_body` — the child's committed
        // `hashStruct`/array word sits at its `word_pos` inside `nested_ed`, which
        // this struct's binding already verified against its own parent. The shared
        // DFS `nested` cursor consumes the next record + counts one more descent
        // (E1 reconciliation); `depth + 1` is bounded by the guard in
        // `render_nested_struct`. The bare `0x01` belt marker (an unsupported nested
        // shape dbgen refused to expand) still declines the WHOLE format.
        if let Some(sf_payload) = sf_params.nested_struct {
            if sf_payload.first() == Some(&0x01) {
                return Err(RenderErr::Reject("7730 nested subfield unsupported"));
            }
            render_nested_struct(
                pages,
                ir,
                sf_payload,
                nested_ed,
                nested,
                depth + 1,
                tx,
                erc20,
                resolver,
                device_signer,
            )?;
            continue;
        }
        // Elementary sub-field. `nested_ed` is exact-length (no dynamic tail):
        // body == full_body, and the static head width is the member count.
        render_one_field(
            pages,
            ir,
            &sf,
            &sf_params,
            nested_ed,
            nested_ed,
            np.member_count,
            tx,
            erc20,
            resolver,
            device_signer,
        )?;
    }
    Ok(())
}

fn append_envelope_pages(pages: &mut Pages, tx: &Eip1559Tx) -> Result<(), RenderErr> {
    let exact_gas_limit = match tx.userop_fields.as_ref() {
        Some(fields) => userop_gas_total(fields)?,
        None => tx.gas_limit,
    };

    if known_native_ticker(tx.chain_id).is_none() && !tx.value.is_zero() {
        // The dispatcher splices one mandatory native-value page around this
        // ERC-7730 render. Prove here that its two value rows can paint the
        // unknown-chain integer exactly; its loud overflow marker is not an
        // acceptable substitute for binding a signed value to the screen.
        let mut raw_hi = [b' '; super::DISPLAY_COLS];
        let mut raw_lo = [b' '; super::DISPLAY_COLS];
        if write_native_amount_two_rows(
            &mut raw_hi,
            &mut raw_lo,
            &tx.value,
            tx.chain_id,
        ) != AmountFit::Full
        {
            return Err(RenderErr::Reject("7730 raw native value too wide"));
        }
    }

    // Chain.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Network:");
    let [_, r1, r2, foot] = pages.page_mut(p);
    write_chain(r1, r2, tx.chain_id);
    write_line(foot, "> next");

    if known_native_ticker(tx.chain_id).is_some() {
        // The chain table authenticates an 18-decimal native unit. Keep the
        // friendly gwei/native scale, but paint every base-unit digit exactly:
        // the older 3-decimal helper made 1 wei and 2 wei both read
        // `0.000 gwei`, while overflow markers collapsed arbitrary fee bombs.
        append_known_chain_fee_pages(pages, tx, exact_gas_limit)?;
    } else {
        // Unknown chain: neither "gwei" nor an 18-decimal native amount is
        // authenticated. Preserve the same two-page budget, but paint every
        // fee operand as its exact raw base-unit integer. If an adversarially
        // large number cannot fit losslessly, reject the verified call rather
        // than round, truncate, or silently assume a decimal scale.
        append_unknown_chain_fee_pages(pages, tx, exact_gas_limit)?;
    }

    if let Some(fields) = tx.userop_fields.as_ref() {
        // The secure handler is the sole producer and global prover of the
        // canonical call/verification/pre-verification gas page. Keep the
        // ERC-7730 envelope's exact aggregate fee calculation and full nonce,
        // but do not create a second gas-triple page here.
        append_userop_nonce_pages(pages, &fields.nonce)?;
    } else {
        // Native EIP-1559 nonce. Its u64 decimal can exceed the old one-row
        // `Nonce: N` sink; use the otherwise-empty value rows losslessly.
        let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_line(pages.row_mut(p, 0), "Nonce:");
        let [_, nonce_hi, nonce_lo, foot] = pages.page_mut(p);
        write_u64_decimal_two_rows_exact(nonce_hi, nonce_lo, tx.nonce)?;
        write_line(foot, "> next");
    }

    Ok(())
}

/// Exact known-chain fee pages using the same two-page budget as the legacy
/// rounded renderer. Gas-price operands use all nine gwei fractional digits;
/// the maximum total uses all 18 native-asset fractional digits. Trimming only
/// removes trailing zeroes, so the representation remains injective.
fn append_known_chain_fee_pages(
    pages: &mut Pages,
    tx: &Eip1559Tx,
    gas_limit: u64,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Max fee/gwei:");
    write_u256_scaled_exact(pages.row_mut(p, 1), &tx.max_fee_per_gas, 9)?;
    write_line(pages.row_mut(p, 2), "Tip/gwei:");
    write_u256_scaled_exact(pages.row_mut(p, 3), &tx.max_priority_fee_per_gas, 9)?;

    let (budget, overflow) = tx.max_fee_per_gas.saturating_mul_u64(gas_limit);
    if overflow {
        return Err(RenderErr::Reject("7730 fee multiplication overflow"));
    }
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_native_currency_row(pages.row_mut(p, 0), b"Max total/", tx.chain_id, b":");
    let [_, total_hi, total_lo, gas] = pages.page_mut(p);
    write_u256_scaled_two_rows_exact(total_hi, total_lo, &budget, 18)?;
    write_u64_decimal_with_prefix(gas, b"Gas:", gas_limit)?;
    Ok(())
}

fn write_u256_scaled_exact(
    row: &mut [u8; super::DISPLAY_COLS],
    value: &U256,
    decimals: u32,
) -> Result<(), RenderErr> {
    *row = [b' '; super::DISPLAY_COLS];
    let mut digits = [0u8; 96];
    let n = value
        .format_decimal(decimals, decimals, true, &mut digits)
        .filter(|&n| n <= super::DISPLAY_COLS)
        .ok_or(RenderErr::Reject("7730 exact scaled fee too wide"))?;
    row[..n].copy_from_slice(&digits[..n]);
    Ok(())
}

fn write_u256_scaled_two_rows_exact(
    row1: &mut [u8; super::DISPLAY_COLS],
    row2: &mut [u8; super::DISPLAY_COLS],
    value: &U256,
    decimals: u32,
) -> Result<(), RenderErr> {
    *row1 = [b' '; super::DISPLAY_COLS];
    *row2 = [b' '; super::DISPLAY_COLS];
    let mut digits = [0u8; 96];
    let n = value
        .format_decimal(decimals, decimals, true, &mut digits)
        .filter(|&n| n <= 2 * super::DISPLAY_COLS - 1)
        .ok_or(RenderErr::Reject("7730 exact native fee too wide"))?;
    if n <= super::DISPLAY_COLS {
        row1[..n].copy_from_slice(&digits[..n]);
        return Ok(());
    }
    let first = super::DISPLAY_COLS - 1;
    row1[..first].copy_from_slice(&digits[..first]);
    row1[first] = b'>';
    row2[..n - first].copy_from_slice(&digits[first..n]);
    Ok(())
}

fn userop_gas_total(
    fields: &pqsigner_tx_core::eip1559::UserOpDisplayFields,
) -> Result<u64, RenderErr> {
    let call = u256_to_u64_exact(&fields.call_gas_limit)
        .ok_or(RenderErr::Reject("7730 call gas exceeds u64"))?;
    let verification = u256_to_u64_exact(&fields.verification_gas_limit)
        .ok_or(RenderErr::Reject("7730 verify gas exceeds u64"))?;
    let pre = u256_to_u64_exact(&fields.pre_verification_gas)
        .ok_or(RenderErr::Reject("7730 prever gas exceeds u64"))?;
    call.checked_add(verification)
        .and_then(|v| v.checked_add(pre))
        .ok_or(RenderErr::Reject("7730 userop gas sum overflow"))
}

fn u256_to_u64_exact(value: &U256) -> Option<u64> {
    if value.0[..24].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(value.0[24..].try_into().ok()?))
}

/// Full 256-bit UserOperation nonce, four 16-hex-digit rows. EntryPoint v0.6
/// uses the high 192 bits as a nonce key, so displaying only the low u64 is not
/// faithful even when the sequence component is small.
fn append_userop_nonce_pages(pages: &mut Pages, nonce: &U256) -> Result<(), RenderErr> {
    let first = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(first, 0), "Nonce (hex):");
    write_hex_word_row(pages.row_mut(first, 1), &nonce.0[0..8]);
    write_hex_word_row(pages.row_mut(first, 2), &nonce.0[8..16]);
    write_hex_word_row(pages.row_mut(first, 3), &nonce.0[16..24]);

    let second = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_hex_word_row(pages.row_mut(second, 0), &nonce.0[24..32]);
    write_line(pages.row_mut(second, 3), "> next");
    Ok(())
}

fn write_hex_word_row(row: &mut [u8; super::DISPLAY_COLS], bytes: &[u8]) {
    *row = [b' '; super::DISPLAY_COLS];
    debug_assert_eq!(bytes.len(), 8);
    for (i, &byte) in bytes.iter().enumerate() {
        row[2 * i] = hex_nibble(byte >> 4);
        row[2 * i + 1] = hex_nibble(byte & 0x0f);
    }
}

/// Render unknown-chain fee operands without assuming a native-asset decimal
/// scale. The compact bounds are deliberately fail-closed: realistic gas
/// prices fit one 16-cell row and realistic gas limits fit after `Gas:`, while
/// larger attacker-controlled values reject instead of aliasing on screen.
fn append_unknown_chain_fee_pages(
    pages: &mut Pages,
    tx: &Eip1559Tx,
    gas_limit: u64,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Max fee/base:");
    write_u256_decimal_exact(pages.row_mut(p, 1), &tx.max_fee_per_gas)?;
    write_line(pages.row_mut(p, 2), "Tip/base:");
    write_u256_decimal_exact(pages.row_mut(p, 3), &tx.max_priority_fee_per_gas)?;

    let (budget, overflow) = tx.max_fee_per_gas.saturating_mul_u64(gas_limit);
    if overflow {
        return Err(RenderErr::Reject("7730 raw fee overflow"));
    }

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_u64_decimal_with_prefix(pages.row_mut(p, 0), b"Gas:", gas_limit)?;
    write_line(pages.row_mut(p, 1), "Max total/base:");
    let [_, _, total_hi, total_lo] = pages.page_mut(p);
    write_u256_decimal_two_rows_exact(total_hi, total_lo, &budget)?;
    Ok(())
}

fn write_u256_decimal_exact(
    row: &mut [u8; super::DISPLAY_COLS],
    value: &U256,
) -> Result<(), RenderErr> {
    *row = [b' '; super::DISPLAY_COLS];
    let mut digits = [0u8; 80];
    let n = value
        .format_decimal(0, 0, false, &mut digits)
        .filter(|&n| n <= super::DISPLAY_COLS)
        .ok_or(RenderErr::Reject("7730 raw fee too wide"))?;
    row[..n].copy_from_slice(&digits[..n]);
    Ok(())
}

fn write_u256_decimal_two_rows_exact(
    row1: &mut [u8; super::DISPLAY_COLS],
    row2: &mut [u8; super::DISPLAY_COLS],
    value: &U256,
) -> Result<(), RenderErr> {
    *row1 = [b' '; super::DISPLAY_COLS];
    *row2 = [b' '; super::DISPLAY_COLS];
    let mut digits = [0u8; 80];
    let n = value
        .format_decimal(0, 0, false, &mut digits)
        .filter(|&n| n <= 2 * super::DISPLAY_COLS - 1)
        .ok_or(RenderErr::Reject("7730 raw total too wide"))?;
    if n <= super::DISPLAY_COLS {
        row1[..n].copy_from_slice(&digits[..n]);
        return Ok(());
    }

    // Reserve the last cell of row 1 for an explicit continuation marker.
    // The canonical decimal digits read left-to-right across the two rows;
    // none is replaced by the marker.
    let first = super::DISPLAY_COLS - 1;
    row1[..first].copy_from_slice(&digits[..first]);
    row1[first] = b'>';
    let rest = n - first;
    row2[..rest].copy_from_slice(&digits[first..n]);
    Ok(())
}

fn write_u64_decimal_two_rows_exact(
    row1: &mut [u8; super::DISPLAY_COLS],
    row2: &mut [u8; super::DISPLAY_COLS],
    value: u64,
) -> Result<(), RenderErr> {
    *row1 = [b' '; super::DISPLAY_COLS];
    *row2 = [b' '; super::DISPLAY_COLS];
    let mut digits = [0u8; 20];
    let n = format_u64(value, &mut digits).ok_or(RenderErr::Reject("7730 raw nonce"))?;
    if n <= super::DISPLAY_COLS {
        row1[..n].copy_from_slice(&digits[..n]);
        return Ok(());
    }

    // A u64 has at most 20 digits. Reserve one continuation marker without
    // replacing a digit, leaving at most five digits for the second row.
    let first = super::DISPLAY_COLS - 1;
    row1[..first].copy_from_slice(&digits[..first]);
    row1[first] = b'>';
    row2[..n - first].copy_from_slice(&digits[first..n]);
    Ok(())
}

fn write_u64_decimal_with_prefix(
    row: &mut [u8; super::DISPLAY_COLS],
    prefix: &[u8],
    value: u64,
) -> Result<(), RenderErr> {
    *row = [b' '; super::DISPLAY_COLS];
    let mut digits = [0u8; 20];
    let n = format_u64(value, &mut digits).ok_or(RenderErr::Reject("7730 raw gas"))?;
    if prefix.len().saturating_add(n) > super::DISPLAY_COLS {
        return Err(RenderErr::Reject("7730 raw gas too wide"));
    }
    row[..prefix.len()].copy_from_slice(prefix);
    row[prefix.len()..prefix.len() + n].copy_from_slice(&digits[..n]);
    Ok(())
}

fn append_eip712_chain_page(pages: &mut Pages, chain_id: u64) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 0), "Network:");
    let [_, r1, r2, foot] = pages.page_mut(p);
    write_chain(r1, r2, chain_id);
    write_line(foot, "> next");
    Ok(())
}

fn append_confirm_page(pages: &mut Pages) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p, 2), "L=Cancel");
    write_line(pages.row_mut(p, 3), "R=Confirm");
    Ok(())
}

#[cfg(test)]
mod unknown_chain_fee_tests {
    use super::*;
    use pqsigner_tx_core::eip1559::UserOpDisplayFields;

    fn u256_from_u128(value: u128) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    fn unknown_fee_tx(max_fee: u128, tip: u128, gas_limit: u64) -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 4_242_424_242,
            nonce: 7,
            max_priority_fee_per_gas: u256_from_u128(tip),
            max_fee_per_gas: u256_from_u128(max_fee),
            gas_limit,
            ..Eip1559Tx::default()
        }
    }

    fn trimmed(row: &[u8; super::super::DISPLAY_COLS]) -> &[u8] {
        let end = row
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |idx| idx + 1);
        &row[..end]
    }

    #[test]
    fn unknown_chain_fee_envelope_is_exact_raw_base_units() {
        let tx = unknown_fee_tx(30_000_000_001, 1_234_567_890, 30_000_000);
        let mut pages = Pages::with_len(0);
        append_envelope_pages(&mut pages, &tx).expect("realistic raw fees fit");

        assert_eq!(pages.len, 4, "the envelope page budget must not grow");
        assert_eq!(trimmed(&pages.buf[1][0]), b"Max fee/base:");
        assert_eq!(trimmed(&pages.buf[1][1]), b"30000000001");
        assert_eq!(trimmed(&pages.buf[1][2]), b"Tip/base:");
        assert_eq!(trimmed(&pages.buf[1][3]), b"1234567890");
        assert_eq!(trimmed(&pages.buf[2][0]), b"Gas:30000000");
        assert_eq!(trimmed(&pages.buf[2][1]), b"Max total/base:");

        let mut total = [0u8; 32];
        let mut total_len = 0usize;
        for &cell in pages.buf[2][2].iter().chain(pages.buf[2][3].iter()) {
            if cell.is_ascii_digit() {
                total[total_len] = cell;
                total_len += 1;
            }
        }
        assert_eq!(&total[..total_len], b"900000000030000000");
        assert_eq!(pages.buf[2][2][super::super::DISPLAY_COLS - 1], b'>');

        assert!(pages.as_slice().iter().flatten().all(|row| {
            !row.windows(4).any(|w| w == b"gwei")
                && !row.windows(3).any(|w| w == b"ETH")
        }));
    }

    #[test]
    fn distinct_unknown_chain_fee_words_do_not_round_to_same_page() {
        let mut one = Pages::with_len(0);
        let mut two = Pages::with_len(0);
        append_envelope_pages(&mut one, &unknown_fee_tx(1, 0, 21_000)).unwrap();
        append_envelope_pages(&mut two, &unknown_fee_tx(2, 0, 21_000)).unwrap();

        // The old gwei renderer rounded both one and two raw base units to the
        // same displayed zero. Exact raw rendering binds the changed signed
        // word to a changed cell.
        assert_eq!(trimmed(&one.buf[1][1]), b"1");
        assert_eq!(trimmed(&two.buf[1][1]), b"2");
        assert_ne!(one.buf[1], two.buf[1]);
    }

    #[test]
    fn unknown_chain_fee_that_cannot_fit_exactly_rejects() {
        // Seventeen decimal digits do not fit the one-row exact max-fee sink.
        // The renderer must refuse; it may never scale/truncate this word.
        let tx = unknown_fee_tx(10_000_000_000_000_000, 0, 21_000);
        let mut pages = Pages::with_len(0);
        assert!(matches!(
            append_envelope_pages(&mut pages, &tx),
            Err(RenderErr::Reject("7730 raw fee too wide"))
        ));
    }

    #[test]
    fn unknown_chain_native_value_that_cannot_fit_exactly_rejects() {
        let mut tx = unknown_fee_tx(1, 0, 21_000);
        tx.value = U256([0xff; 32]);
        let mut pages = Pages::with_len(0);
        assert!(matches!(
            append_envelope_pages(&mut pages, &tx),
            Err(RenderErr::Reject("7730 raw native value too wide"))
        ));
        assert_eq!(pages.len, 0, "value preflight must run before page writes");
    }

    #[test]
    fn known_chain_keeps_exact_gwei_and_native_unit_path() {
        let mut tx = unknown_fee_tx(1, 2, 21_000);
        tx.chain_id = 1;
        let mut pages = Pages::with_len(0);
        append_envelope_pages(&mut pages, &tx).unwrap();
        assert_eq!(trimmed(&pages.buf[1][0]), b"Max fee/gwei:");
        assert_eq!(trimmed(&pages.buf[1][1]), b"0.000000001");
        assert_eq!(trimmed(&pages.buf[1][2]), b"Tip/gwei:");
        assert_eq!(trimmed(&pages.buf[1][3]), b"0.000000002");
        assert_eq!(trimmed(&pages.buf[2][0]), b"Max total/ETH:");
    }

    #[test]
    fn distinct_known_chain_fee_words_do_not_round_to_same_page() {
        let mut one_tx = unknown_fee_tx(1, 0, 21_000);
        one_tx.chain_id = 1;
        let mut two_tx = unknown_fee_tx(2, 0, 21_000);
        two_tx.chain_id = 1;
        let mut one = Pages::with_len(0);
        let mut two = Pages::with_len(0);
        append_envelope_pages(&mut one, &one_tx).unwrap();
        append_envelope_pages(&mut two, &two_tx).unwrap();
        assert_eq!(trimmed(&one.buf[1][1]), b"0.000000001");
        assert_eq!(trimmed(&two.buf[1][1]), b"0.000000002");
        assert_ne!(one.buf[1], two.buf[1]);
    }

    #[test]
    fn known_chain_fee_that_cannot_render_exactly_rejects() {
        let mut tx = unknown_fee_tx(0, 0, 21_000);
        tx.chain_id = 1;
        tx.max_fee_per_gas = U256([0xff; 32]);
        let mut pages = Pages::with_len(0);
        assert!(matches!(
            append_envelope_pages(&mut pages, &tx),
            Err(RenderErr::Reject("7730 exact scaled fee too wide"))
        ));
    }

    #[test]
    fn full_u64_nonce_is_lossless_across_two_rows() {
        let mut tx = unknown_fee_tx(1, 0, 21_000);
        tx.nonce = u64::MAX;
        let mut pages = Pages::with_len(0);
        append_envelope_pages(&mut pages, &tx).unwrap();
        assert_eq!(trimmed(&pages.buf[3][0]), b"Nonce:");
        assert_eq!(trimmed(&pages.buf[3][1]), b"184467440737095>");
        assert_eq!(trimmed(&pages.buf[3][2]), b"51615");
    }

    #[test]
    fn userop_gas_components_are_left_to_the_handler_owned_lane() {
        let mut a = unknown_fee_tx(1, 0, 0);
        a.userop_fields = Some(UserOpDisplayFields {
            nonce: u256_from_u128(7),
            call_gas_limit: u256_from_u128(21_000),
            verification_gas_limit: u256_from_u128(100_000),
            pre_verification_gas: u256_from_u128(50_000),
        });
        let mut b = unknown_fee_tx(1, 0, 0);
        b.userop_fields = Some(UserOpDisplayFields {
            nonce: u256_from_u128(7),
            call_gas_limit: u256_from_u128(100_000),
            verification_gas_limit: u256_from_u128(21_000),
            pre_verification_gas: u256_from_u128(50_000),
        });
        let mut pa = Pages::with_len(0);
        let mut pb = Pages::with_len(0);
        append_envelope_pages(&mut pa, &a).unwrap();
        append_envelope_pages(&mut pb, &b).unwrap();
        assert_eq!(pa.len, 5);
        assert_eq!(pb.len, 5);
        assert_eq!(pa.as_slice(), pb.as_slice());
        for row in pa.as_slice().iter().flatten() {
            let row = trimmed(row);
            assert!(
                !row.starts_with(b"Call:")
                    && !row.starts_with(b"Verify:")
                    && !row.starts_with(b"PreVer:")
                    && !row.starts_with(b"Total:"),
                "ERC-7730 must not reintroduce the handler-owned gas page"
            );
        }
    }

    #[test]
    fn userop_nonce_high_bits_are_rendered_in_full() {
        let mut tx = unknown_fee_tx(1, 0, 0);
        let mut nonce = [0u8; 32];
        nonce[0] = 0xab;
        nonce[31] = 0xcd;
        tx.userop_fields = Some(UserOpDisplayFields {
            nonce: U256(nonce),
            call_gas_limit: u256_from_u128(21_000),
            verification_gas_limit: u256_from_u128(100_000),
            pre_verification_gas: u256_from_u128(50_000),
        });
        let mut pages = Pages::with_len(0);
        append_envelope_pages(&mut pages, &tx).unwrap();
        assert_eq!(trimmed(&pages.buf[3][0]), b"Nonce (hex):");
        assert_eq!(trimmed(&pages.buf[3][1]), b"ab00000000000000");
        assert_eq!(trimmed(&pages.buf[4][0]), b"00000000000000cd");
    }

    #[test]
    fn oversized_userop_gas_component_rejects_instead_of_saturating() {
        let mut tx = unknown_fee_tx(1, 0, 0);
        tx.userop_fields = Some(UserOpDisplayFields {
            nonce: U256::zero(),
            call_gas_limit: U256([0xff; 32]),
            verification_gas_limit: u256_from_u128(1),
            pre_verification_gas: u256_from_u128(1),
        });
        let mut pages = Pages::with_len(0);
        assert!(matches!(
            append_envelope_pages(&mut pages, &tx),
            Err(RenderErr::Reject("7730 call gas exceeds u64"))
        ));
        assert_eq!(pages.len, 0);
    }
}
