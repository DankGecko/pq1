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
pub(crate) mod nested;

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
        &mut NestedCtx::default(),
    )?;

    // 4b. WYSIWYS belt (VULN-erc7730-visible-never-noparam-clearsign). A
    // contract-context known shape that DECLARES fields but renders NONE of
    // them — every field `visible:"never"` — would otherwise present a
    // trusted clear-sign (banner + envelope + confirm) with none of the
    // call's parameters shown: a blind-sign wearing a reassuring clear-sign
    // banner, worse than an honest loud blind-sign. Refuse and fall through
    // to the blind-sign ladder (raw target / selector). The build-time
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
    // off-chain approval showing nothing; refuse so the caller falls back to
    // the honest raw-digest page. No native-value rescue exists for EIP-712,
    // so the guard is unconditional.
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
    ir: &crate::tx::erc7730::Erc7730Ir<'_>,
    format: &crate::tx::erc7730::FormatHeader<'_>,
    body: &[u8],
    full_body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
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
                // decline the WHOLE format to blind-sign.
                return Err(RenderErr::Reject("7730 eip712 nested unsupported"));
            }
            render_nested_struct(pages, ir, payload, body, nested, tx, erc20, resolver)?;
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
    ir: &crate::tx::erc7730::Erc7730Ir<'_>,
    field: &crate::tx::erc7730::FieldEntry<'_>,
    params: &crate::tx::erc7730_render::params::ParamSet<'_>,
    body: &[u8],
    full_body: &[u8],
    static_head_words: u16,
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    match should_render_with_mode(params, None, COMPACT_MODE) {
        Action::Render => {
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
                    field, pages, ir, full_body, tx, erc20, resolver, params,
                )?;
            } else if formatters::path_needs_full_body(ir, field.path_off)?
                || formatters::token_path_needs_full_body(params)
            {
                // C2 / Tier B: a scalar field reached by descending a dynamic
                // offset (dynamic-tuple member) — OR a `tokenAmount` whose
                // `tokenPath` extracts a token id from a dynamic swap leg
                // (packed `bytes path`, `address[]`), even if the amount field
                // itself is static-head. Same scalar renderers, FULL body.
                formatters::dispatch(field, pages, ir, full_body, tx, erc20, resolver, params)?;
            } else {
                // Static-head scalar — head-bounded body (byte-identical).
                formatters::dispatch(field, pages, ir, body, tx, erc20, resolver, params)?;
            }
            Ok(())
        }
        Action::Skip => Ok(()),
        Action::Reject(msg) => Err(RenderErr::Reject(msg)),
    }
}

/// Bind + render one nested-EIP-712 struct member (Phase 5, v1 single-level).
///
/// The security spine: the member's `hashStruct` word sits at `word_pos` of the
/// SIGNED `parent_body`. The companion supplies the member's `encodeData` as the
/// next DFS record in `nested.blob`; this function requires
/// `keccak(dbgen-pinned type_hash ‖ nested_ed) == that committed word`
/// (constant-time) BEFORE rendering any sub-field → shown ⟺ signed by
/// collision-resistance. Every decline is a hard `Err` that unwinds the whole
/// render (the caller discards the partial `Pages`), so a mismatch never leaks a
/// partially-rendered nested member (E4-1 atomicity).
#[allow(clippy::too_many_arguments)]
fn render_nested_struct(
    pages: &mut Pages,
    ir: &crate::tx::erc7730::Erc7730Ir<'_>,
    payload: &[u8],
    parent_body: &[u8],
    nested: &mut NestedCtx<'_>,
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    use pqsigner_erc7730::render::nested as pn;
    use subtle::ConstantTimeEq;

    // 1. Parse the pinned v0x03 payload (bounds-checked, pure).
    let np = pn::parse_nested_struct_param(payload)?;
    // 2. v1 is single-level NON-array. An array member is a v2 shape dbgen does
    //    NOT emit as a v0x03 block; refuse belt-and-suspenders.
    if np.is_array {
        return Err(RenderErr::Reject("7730 nested array v2"));
    }
    // 3. The committed `hashStruct` word in the parent's signed encoded_data.
    let wp = (np.word_pos as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 nested wp ovf"))?;
    let committed = parent_body
        .get(wp..wp + 32)
        .ok_or(RenderErr::Reject("7730 nested wp oob"))?;
    let committed: &[u8; 32] = committed
        .try_into()
        .map_err(|_| RenderErr::Reject("7730 nested cw"))?;

    // 4. Pull the next DFS `nested_ed` record + COUNT it (E1: unconditional).
    let (nested_ed, new_cursor) = pn::read_next_nested_ed(nested.blob, nested.cursor)?;
    nested.cursor = new_cursor;
    nested.records_consumed = nested
        .records_consumed
        .checked_add(1)
        .ok_or(RenderErr::Reject("7730 nested count ovf"))?;

    // 5. Exact length: `nested_ed == member_count × 32` (rule 1 — hash the
    //    COMPLETE member, so trailing signed-but-unshown words are impossible).
    let expected = (np.member_count as usize)
        .checked_mul(32)
        .ok_or(RenderErr::Reject("7730 nested mc ovf"))?;
    if nested_ed.len() != expected {
        return Err(RenderErr::Reject("7730 nested ed len"));
    }

    // 6. THE BINDING — keccak(pinned type_hash ‖ nested_ed) == committed word,
    //    constant-time. Shown ⟺ signed by collision-resistance.
    let hs = nested::hash_struct(np.type_hash, nested_ed);
    if !bool::from(hs.ct_eq(committed)) {
        return Err(RenderErr::Reject("7730 nested binding"));
    }

    // 7. E2 address-coverage backstop + E4-2 local-ordinal bounds (pure,
    //    independent of the build gate). Every address-typed local word must be
    //    bound by a SHOWN sub-field's render path OR its tokenPath — `COMPACT_MODE`
    //    is threaded so coverage tracks exactly what the renderer displays (a
    //    hidden/skipped sub-field covers nothing).
    pn::validate_nested_structure(ir, &np, COMPACT_MODE)?;

    // 8. Render each visible sub-field against `nested_ed` (LOCAL resolution).
    for sf in np.sub_fields() {
        let sf = sf.map_err(|_| RenderErr::Reject("7730 nested subfield"))?;
        let sf_params = parse_params(ir, sf.param_off)?;
        // v1 is single-level: a nested sub-field (depth > 1) is a v3 shape dbgen
        // does not emit — decline rather than recurse into un-verified territory.
        if sf_params.nested_struct.is_some() {
            return Err(RenderErr::Reject("7730 nested depth v3"));
        }
        // `nested_ed` is the exact-length member body (no dynamic tail), so
        // body == full_body and the static head width is the member count.
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
        )?;
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
