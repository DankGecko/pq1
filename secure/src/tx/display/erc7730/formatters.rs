//! Per-formatter renderers driven by `FormatOp` (0x01..0x0E).
//!
//! Each formatter writes 1–2 pages into the supplied [`Pages`] buffer
//! and returns `Result<(), RenderErr>`. Page budget is enforced via
//! [`Pages::push_blank`] returning `Err(())` on overflow, which we map
//! to `RenderErr::PageBudget`.
//!
//! ## Path resolution
//!
//! Phase 4 ships a minimal direct path walker rather than going through
//! `pqsigner_erc7730::walker::resolve_path`. The reason: Phase 3's
//! walker requires an [`AbiView`] tree describing the runtime ABI
//! shape, and the on-device IR does not carry ABI type information
//! (the host-side `dbgen` knows the format-key signature but does not
//! emit it on-wire). Phase 4 sidesteps the gap by walking the path
//! program manually, accumulating a slot offset, and reading the
//! corresponding 32-byte word straight out of `inner_data` post-
//! selector. Each formatter then re-interprets those 32 bytes per the
//! type its `FormatOp` implies (uint256, address, bool, …).
//!
//! For STATIC types (uint*, int*, address, bytes32, bool, static
//! tuples) this is correct. DYNAMIC types (bytes, string, dynamic
//! arrays, dynamic tuples) are out of scope for Phase 4 — the slot
//! would carry a 32-byte BE offset rather than the value, and a
//! formatter that tried to render it as Uint would surface the offset
//! instead of the value. The seed corpus is all static types except
//! `OpenSea` ([`bytes`] for `calldata`/`replacementPattern`), which
//! the `Calldata` formatter routes through `calldata_nested` (which
//! itself rejects in Phase 4 and falls through to blind-sign).

use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use super::super::primitives::{
    chain_name, write_addr_full, write_addr_full_or_name, write_amount_two_rows,
    write_line, AmountFit,
};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::tx::erc7730::{container_field, Erc7730Ir, FieldEntry, FormatOp, PathOp};
use crate::tx::erc7730_render::params::{
    ParamSet, DATE_ENC_BLOCKHEIGHT, DATE_ENC_TIMESTAMP,
};
use crate::tx::erc7730_render::RenderErr;
use crate::ui::{ascii_str, DISPLAY_COLS};

use super::Pages;

/// Resolved form of a path program — either a slot inside the
/// structured calldata body or a well-known envelope field.
pub(super) enum Resolved<'a> {
    /// 32-byte BE word from `body[slot * 32 .. (slot+1) * 32]`.
    Slot32(&'a [u8; 32]),
    /// `@`-rooted access; caller looks up the field on `tx`.
    Container(u16),
}

/// Walk a path program (length-prefixed at `ir.pool[path_off]`) and
/// produce a [`Resolved`] reference. Fails on:
///
/// - empty / missing path (`path_off == 0` or pool out-of-range);
/// - unsupported root (`$` metadata);
/// - non-`FieldIdx` descent (`ArrayIdx`/`ArrayLast`/`ArrayAll`/
///   `ArraySlice` — Phase 4 only renders static-tuple paths);
/// - slot offset past the supplied `body`.
pub(super) fn resolve_path<'a>(
    ir: &Erc7730Ir<'_>,
    path_off: u16,
    body: &'a [u8],
) -> Result<Resolved<'a>, RenderErr> {
    if path_off == 0 {
        return Err(RenderErr::Reject("7730 missing path"));
    }
    let off = path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 truncated path"))?;
    if prog.is_empty() {
        return Err(RenderErr::Reject("7730 empty path"));
    }

    let root = PathOp::try_from(prog[0]).map_err(|_| RenderErr::Reject("7730 bad root"))?;
    let mut p = 1usize;

    match root {
        PathOp::RootStructured => {
            // Sum FieldIdx values → byte slot.
            let mut slot = 0usize;
            while p < prog.len() {
                let op = PathOp::try_from(prog[p])
                    .map_err(|_| RenderErr::Reject("7730 bad op"))?;
                p += 1;
                match op {
                    PathOp::FieldIdx => {
                        if p + 2 > prog.len() {
                            return Err(RenderErr::Reject("7730 trunc field"));
                        }
                        let idx = u16::from_be_bytes([prog[p], prog[p + 1]]) as usize;
                        p += 2;
                        slot = slot
                            .checked_add(idx)
                            .ok_or(RenderErr::Reject("7730 slot ovf"))?;
                    }
                    PathOp::ArrayIdx
                    | PathOp::ArrayLast
                    | PathOp::ArraySlice
                    | PathOp::ArrayAll
                    | PathOp::RootStructured
                    | PathOp::RootContainer
                    | PathOp::RootMetadata => {
                        return Err(RenderErr::Reject("7730 path op p4 unsup"));
                    }
                }
            }
            let start = slot
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let end = start
                .checked_add(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let word = body
                .get(start..end)
                .ok_or(RenderErr::Reject("7730 short body"))?;
            // Slice → array conversion is infallible (we just checked
            // the length) but TryInto wants Result, so unwrap is fine.
            Ok(Resolved::Slot32(<&[u8; 32]>::try_from(word).unwrap()))
        }
        PathOp::RootContainer => {
            if p + 3 > prog.len() {
                return Err(RenderErr::Reject("7730 trunc cnt"));
            }
            if prog[p] != PathOp::FieldIdx as u8 {
                return Err(RenderErr::Reject("7730 cnt bad op"));
            }
            let field_idx = u16::from_be_bytes([prog[p + 1], prog[p + 2]]);
            // Tail must be empty (we only support a single `@.<name>`
            // step in Phase 4 — sub-fields of the envelope are not a
            // thing for any current ERC-7730 descriptor).
            if p + 3 != prog.len() {
                return Err(RenderErr::Reject("7730 cnt deep"));
            }
            Ok(Resolved::Container(field_idx))
        }
        PathOp::RootMetadata => Err(RenderErr::Reject("7730 $ root unsup")),
        PathOp::FieldIdx
        | PathOp::ArrayIdx
        | PathOp::ArrayLast
        | PathOp::ArraySlice
        | PathOp::ArrayAll => Err(RenderErr::Reject("7730 path no root")),
    }
}

/// Read a container field value (u256-shaped) by its keccak-prefix
/// index. Returns a 32-byte BE word equivalent for the formatter to
/// re-interpret.
pub(super) fn container_u256(tx: &Eip1559Tx, idx: u16) -> Result<[u8; 32], RenderErr> {
    match idx {
        container_field::VALUE => Ok(tx.value.0),
        container_field::CHAIN_ID => {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&tx.chain_id.to_be_bytes());
            Ok(b)
        }
        container_field::NONCE => {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&tx.nonce.to_be_bytes());
            Ok(b)
        }
        _ => Err(RenderErr::Reject("7730 cnt no u256")),
    }
}

/// Read a container field as an address. Returns the 20-byte slice for
/// `@.to` / `@.from`.
pub(super) fn container_addr(tx: &Eip1559Tx, idx: u16) -> Result<[u8; 20], RenderErr> {
    match idx {
        container_field::TO => tx.to.ok_or(RenderErr::Reject("7730 no to")),
        // `@.from` is the AA wallet's own address — derived elsewhere
        // (cmd_sign_userop computes it) and not available at the display
        // layer. Returning 0x00… here was a confirm-X-sign-Y (finding F4):
        // the OLED showed 0x0000…0000 while the signed UserOp executed from
        // the real, nonzero AA wallet. Refuse rather than render a zero for
        // a nonzero signed value; wire a real @.from value in if a descriptor
        // ever needs it.
        container_field::FROM => Err(RenderErr::Reject("7730 from unbound")),
        _ => Err(RenderErr::Reject("7730 cnt no addr")),
    }
}

/// Dispatcher — one renderer per `FormatOp`. Step 3 reads
/// `field.format_op`, parses params, walks the path, and emits 1–2
/// pages. Visibility filtering happens in the entry-point loop.
pub(super) fn dispatch(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // A constant-annotation field carries no path; render its literal
    // (attested, Merkle-pinned) string directly, bypassing the format-op
    // path resolution (which would reject on the absent path).
    if let Some(cv) = params.const_value {
        return render_const(field, pages, cv);
    }
    let op = FormatOp::try_from(field.format_op)
        .map_err(|_| RenderErr::Reject("7730 bad format op"))?;
    match op {
        FormatOp::Raw => render_raw(field, pages, ir, body, tx, params),
        FormatOp::Amount => render_amount(field, pages, ir, body, tx, params),
        FormatOp::TokenAmount => {
            render_token_amount(field, pages, ir, body, tx, erc20, resolver, params)
        }
        FormatOp::NftName => render_nft_name(field, pages, ir, body, tx, resolver, params),
        FormatOp::Date => render_date(field, pages, ir, body, tx, params),
        FormatOp::Duration => render_duration(field, pages, ir, body, tx),
        FormatOp::AddressName => render_address_name(field, pages, ir, body, tx, resolver),
        FormatOp::Enum => render_enum(field, pages, ir, body, tx, params),
        FormatOp::Unit => render_unit(field, pages, ir, body, tx, params),
        FormatOp::Calldata => super::calldata_nested::render(field, pages, params),
        FormatOp::ChainId => render_chain_id(field, pages, ir, body, tx),
        FormatOp::TokenTicker => {
            render_token_ticker(field, pages, ir, body, tx, erc20, resolver, params)
        }
        FormatOp::InteroperableAddressName => {
            render_interop_address_name(field, pages, ir, body, tx, resolver)
        }
        FormatOp::Encrypted => render_encrypted(field, pages, params),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Per-FormatOp renderers
// ─────────────────────────────────────────────────────────────────────

fn render_raw(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        // Propagate the Reject instead of rendering a zero word for an
        // unsupported container (finding F4): `unwrap_or([0u8; 32])` showed an
        // all-zero 32-byte value while the signed UserOp committed a nonzero
        // one (e.g. raw `@.to`). Fail closed.
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    // A 16-col row holds 16 hex chars = 8 bytes, so the full 32-byte signed
    // word needs FOUR hex rows. Render it across two pages (16 bytes each)
    // so EVERY signed byte is shown. The old single-page form passed two
    // 16-byte slices to `write_hex_word`, which caps at 8 bytes/row, so it
    // silently dropped bytes 8..16 and 24..32 — for a big-endian uint256
    // that is the entire low-order half, making any value < 2^64 render as
    // all-zeros with a benign "> next" footer (WYSIWYS magnitude-hiding;
    // fixed 2026-06-26). Page budget is enforced by `push_blank`'s
    // PageBudget error, same as before.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    {
        let [_, row1, row2, row3] = pages.page_mut(p);
        write_hex_word(row1, &bytes[0..8]);
        write_hex_word(row2, &bytes[8..16]);
        write_line(row3, "1/2 > next");
    }
    let p2 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p2, field.label);
    {
        let [_, row1, row2, row3] = pages.page_mut(p2);
        write_hex_word(row1, &bytes[16..24]);
        write_hex_word(row2, &bytes[24..32]);
        write_line(row3, "2/2 > next");
    }
    Ok(())
}

fn render_amount(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let raw = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let value = U256(raw);
    let decimals = u32::from(params.decimals.unwrap_or(18));
    let unit_bytes = params.base.unwrap_or(b"ETH");
    let [_, r1, r2, foot] = pages.page_mut(p);
    let fit = write_amount_two_rows(r1, r2, &value, decimals, 6, true, true, ascii_str(unit_bytes));
    write_line(
        foot,
        match fit {
            AmountFit::Full => "> next",
            AmountFit::Overflow => "!AMOUNT OVERFLOW",
        },
    );
    Ok(())
}

fn render_token_amount(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // Resolve the amount slot.
    let raw = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let value = U256(raw);

    // Resolve token contract address (params.tokenPath wins; falls
    // back to params.token literal). Used to decide which decimals /
    // symbol to display.
    let token_addr = resolve_token_address(ir, body, tx, params).ok();

    // Match against the supplied `erc20` bundle only when the addresses
    // agree. A `None` here means the token could NOT be bound to a
    // Merkle-verified metadata entry — we do not know its decimals.
    let bound: Option<(u32, &[u8])> = match (token_addr, erc20) {
        (Some(addr), Some(meta)) if addr == meta.contract => {
            Some((u32::from(meta.decimals), meta.symbol))
        }
        _ => None,
    };

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, foot] = pages.page_mut(p);

    match bound {
        Some((decimals, ticker)) => {
            // Threshold check (Aragon/Coinbase Wallet/Rabby convention):
            // when the descriptor supplies a `threshold` param and the
            // on-chain value is greater-than-or-equal, render
            // "unlimited <ticker>" instead of the digit string. BE byte
            // arrays compare lexicographically — which is the same as
            // numeric on full-width u256, so a direct `>=` over the raw
            // bytes is correct.
            if let Some(threshold) = params.threshold {
                if value.0 >= *threshold {
                    write_unlimited_row(r1, ticker);
                    write_line(foot, "> next");
                    return Ok(());
                }
            }
            let fit =
                write_amount_two_rows(r1, r2, &value, decimals, 6, true, true, ascii_str(ticker));
            write_line(
                foot,
                match fit {
                    AmountFit::Full => "> next",
                    AmountFit::Overflow => "!AMOUNT OVERFLOW",
                },
            );
        }
        None => {
            // Audit M-4: never present a scaled decimal with an assumed
            // scale. Without verified `decimals` a 6-decimal token would
            // render 10^12× off while *looking* authoritative. Show the
            // RAW integer (no scaling) and label the unknown scale loudly
            // so the user knows the magnitude is uninterpreted.
            let fit = write_amount_two_rows(r1, r2, &value, 0, 0, false, true, "");
            write_line(
                foot,
                match fit {
                    AmountFit::Full => "! raw, dec=?",
                    AmountFit::Overflow => "!AMOUNT OVERFLOW",
                },
            );
        }
    }

    // Audit 2026-06-25 MEDIUM-1: with no Merkle-verified metadata we cannot
    // show decimals/symbol — but the token *identity* is still a signed
    // operand. A descriptor that covers the token only via a `tokenPath`
    // (Aave `withdraw` `asset`, Uniswap `tokenIn`/`tokenOut`) has no address
    // field of its own, so a companion that withholds the optional ERC-20
    // metadata trailer would otherwise have the user approve a
    // transfer/withdraw/swap of an UNNAMED token. Render the resolved
    // address on its own page (resolver-aware) so the contract identity is
    // never omitted from the trusted display. We only emit the extra page in
    // the unbound case — when `bound` is `Some` the symbol already names the
    // token. If the address could not be resolved at all there is nothing to
    // bind; the amount page already carries the loud `! raw, dec=?` footer,
    // and the page-budget gate fails closed to blind-sign on overflow.
    if bound.is_none() {
        if let Some(addr) = token_addr {
            let ap = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
            write_label_row(pages, ap, b"Token (UNVERIFIED)");
            let [_, ar1, ar2, ar3] = pages.page_mut(ap);
            write_addr_full_or_name(ar1, ar2, ar3, &addr, tx.chain_id, resolver);
        }
    }
    Ok(())
}

/// Render `"unlimited <ticker>"` into a single 16-col OLED row. Used
/// by `render_token_amount` when the descriptor's `threshold` param
/// classifies the on-chain value as the approve-all sentinel.
fn write_unlimited_row(row: &mut [u8; DISPLAY_COLS], ticker: &[u8]) {
    let mut buf = [b' '; DISPLAY_COLS];
    let prefix = b"unlimited ";
    let n = core::cmp::min(prefix.len(), buf.len());
    buf[..n].copy_from_slice(&prefix[..n]);
    let room = buf.len() - n;
    let take = core::cmp::min(ticker.len(), room);
    buf[n..n + take].copy_from_slice(&ticker[..take]);
    *row = buf;
}

fn render_nft_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    _resolver: &NameResolver<'_>,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // Audit M-7: the Phase-4 stub rendered the raw on-chain integer (the
    // NFT token id) under the semantic `NftName` label and discarded the
    // collection-name resolution — an opaque number wearing a verified
    // intent banner. Until the NFT-name resolver lands, REJECT so the
    // priority ladder falls through to blind-sign (consistent with how
    // `Calldata` and `MustMatch` already reject), rather than presenting
    // a misreadable value as if it were resolved.
    let _ = (field, pages, ir, body, tx);
    Err(RenderErr::Reject("7730 nftName unsupported"))
}

fn render_date(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let secs = match read_u64_be_tail(&bytes) {
        Some(s) => s,
        None => {
            // Signed uint256 exceeds u64: its low 64 bits as a date/block
            // would be unrelated to what is signed. Fail loud, never a
            // misleading small value (audit 2026-06-23).
            let [_, r1, r2, foot] = pages.page_mut(p);
            write_line(r1, "! TIME >2^64");
            write_line(r2, "(overflow)");
            write_line(foot, "> next");
            return Ok(());
        }
    };
    let enc = params.date_encoding.unwrap_or(DATE_ENC_TIMESTAMP);
    let [_, r1, r2, foot] = pages.page_mut(p);
    if enc == DATE_ENC_BLOCKHEIGHT {
        // The block id is the signed deadline/expiry, so EVERY digit is
        // security-relevant: a far-future block height must never render as a
        // near one. The previous "block #N" form fed the full u64 `secs`
        // straight into `write_decimal_into`, which silently DROPS low-order
        // digits once the 16-col row fills. With the 7-char "block #" prefix
        // only 9 digits fit, so a >=10-digit height rendered as its top 9
        // digits — e.g. block 12_345_678_901 painted "block #123456789"
        // (~100x understated, yet a plausible near deadline) while the
        // signature committed to the full value. Show the full magnitude
        // instead: the compact "block #N" inline form while every digit fits
        // (the unchanged common case: heights < 1e9), otherwise a label on r1
        // and the full number on its own row r2. An absurd >16-digit value
        // (>= 1e16 — not a real block height on any chain) fails LOUD rather
        // than truncating, mirroring the timestamp branch's `! YEAR >9999`
        // and the `! CHAIN >2^64` guard (audit 2026-06-26 — the
        // magnitude-hiding sibling of the date-year fix 7df062d3).
        const BLOCK_PREFIX: &[u8] = b"block #";
        if BLOCK_PREFIX.len() + decimal_digits(secs) <= DISPLAY_COLS {
            let mut row = [b' '; DISPLAY_COLS];
            let mut pos = 0;
            for &b in BLOCK_PREFIX {
                row[pos] = b;
                pos += 1;
            }
            write_decimal_into(&mut row, pos, secs);
            *r1 = row;
        } else if decimal_digits(secs) <= DISPLAY_COLS {
            write_line(r1, "Block height:");
            let mut row = [b' '; DISPLAY_COLS];
            write_decimal_into(&mut row, 0, secs);
            *r2 = row;
        } else {
            write_line(r1, "Block height:");
            write_line(r2, "! >1e16 (ovf)");
        }
    } else {
        format_iso8601_utc(secs, r1, r2);
    }
    write_line(foot, "> next");
    Ok(())
}

fn render_duration(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let secs = match read_u64_be_tail(&bytes) {
        Some(s) => s,
        None => {
            // Signed uint256 exceeds u64: fail loud rather than render a
            // truncated duration (audit 2026-06-23).
            let [_, r1, _r2, foot] = pages.page_mut(p);
            write_line(r1, "! DUR >2^64");
            write_line(foot, "> next");
            return Ok(());
        }
    };
    let [_, r1, _r2, foot] = pages.page_mut(p);
    format_duration(secs, r1);
    write_line(foot, "> next");
    Ok(())
}

fn render_address_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    let addr = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => {
            // address is right-aligned in a 32-byte slot.
            let mut a = [0u8; 20];
            a.copy_from_slice(&b[12..]);
            a
        }
        Resolved::Container(idx) => container_addr(tx, idx)?,
    };
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, r3] = pages.page_mut(p);
    write_addr_full_or_name(r1, r2, r3, &addr, tx.chain_id, resolver);
    Ok(())
}

/// Render a constant-annotation field — a path-less `{value,label}` whose
/// `value` is a fixed (attested) string carried in the IR pool. Not bound
/// to calldata, so there is no path to resolve: it shows the same text for
/// every transaction (e.g. the ERC-4626 vault share/asset tickers). The
/// string is Merkle-pinned, so it is no more trusted than the field label
/// or intent banner.
fn render_const(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    value: &[u8],
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, r3] = pages.page_mut(p);
    let rows: [&mut [u8; DISPLAY_COLS]; 3] = [r1, r2, r3];
    let mut chunks = value.chunks(DISPLAY_COLS);
    for row in rows {
        match chunks.next() {
            Some(c) => write_line_bytes(row, c),
            None => write_line_bytes(row, b""),
        }
    }
    Ok(())
}

fn render_enum(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // Resolve the field's value (a single static-head word). `@`-container
    // enums are not a shape any descriptor uses, so a container resolution
    // is refused (decline-to-blind) rather than guessed.
    let value: [u8; 32] = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(_) => return Err(RenderErr::Reject("7730 enum on container")),
    };
    // The descriptor MUST carry an `enum_ref` → the interned value→label
    // table; without it there is nothing to resolve against.
    let enum_off = params
        .enum_ref
        .ok_or(RenderErr::Reject("7730 enum no ref"))?;
    // Audit M-7: render the RESOLVED label, never the bare index. A value
    // outside the declared set, or a malformed table, declines-to-blind
    // rather than showing an opaque/garbled gloss under the verified
    // intent banner (consistent with `Calldata` / `MustMatch`).
    let label = crate::tx::erc7730_render::enums::lookup_enum_label(ir.pool, enum_off, &value)?
        .ok_or(RenderErr::Reject("7730 enum value unknown"))?;
    // A label longer than the three value rows would have to be truncated
    // on the trusted display — refuse rather than show a partial gloss.
    if label.len() > 3 * DISPLAY_COLS {
        return Err(RenderErr::Reject("7730 enum label too long"));
    }
    let _ = tx;
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, r3] = pages.page_mut(p);
    let rows: [&mut [u8; DISPLAY_COLS]; 3] = [r1, r2, r3];
    let mut chunks = label.chunks(DISPLAY_COLS);
    for row in rows {
        match chunks.next() {
            Some(c) => write_line_bytes(row, c),
            None => write_line_bytes(row, b""),
        }
    }
    Ok(())
}

fn render_unit(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let value = U256(bytes);
    let decimals = u32::from(params.decimals.unwrap_or(0));
    let unit_bytes = params.base.unwrap_or(b"");
    let [_, r1, r2, foot] = pages.page_mut(p);
    let fit = write_amount_two_rows(r1, r2, &value, decimals, 6, true, true, ascii_str(unit_bytes));
    write_line(
        foot,
        match fit {
            AmountFit::Full => "> next",
            AmountFit::Overflow => "!UNIT OVERFLOW",
        },
    );
    Ok(())
}

fn render_chain_id(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    // FAITHFUL formatter (audit 2026-06-26 — faithless-formatter class). Render
    // the chain id at the field's OWN signed word, not `tx.chain_id`
    // unconditionally. The old body discarded `field.path`/`body`, so a field
    // pointing at a calldata / typed-data word (e.g. a cross-chain bridge's
    // destination chain) displayed the UserOp's *execution* chain while the
    // signature committed to a different value (display != signed) — and the
    // host completeness lint still credited the field as covered, so the gap
    // shipped unwarned. `@.chainId` resolves through the container arm to
    // `tx.chain_id`, preserving the envelope use-case.
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let [_, r1, r2, foot] = pages.page_mut(p);
    match read_u64_be_tail(&bytes) {
        Some(cid) if decimal_digits(cid) <= DISPLAY_COLS => {
            // "<decimal id>" on row 1, "<chain_name>" on row 2.
            let mut decimal = [b' '; DISPLAY_COLS];
            write_decimal_into(&mut decimal, 0, cid);
            *r1 = decimal;
            write_line(r2, chain_name(cid));
        }
        // A 17-20 digit chain id is <= u64 but cannot be shown in full on a
        // 16-col row, and names no real EVM chain. Fail loud rather than let
        // `write_decimal_into` silently drop the low digits (which would paint
        // a different, smaller chain number than the one signed) — same policy
        // as the >u64 arm below.
        Some(_) => {
            write_line(r1, "! CHAIN >1e16");
            write_line(r2, "(too large)");
        }
        // A chain id wider than u64 cannot name a real EVM chain; fail loud
        // rather than render a truncated low-64-bit value (same policy as the
        // date / duration `>2^64` guard).
        None => {
            write_line(r1, "! CHAIN >2^64");
            write_line(r2, "(overflow)");
        }
    }
    write_line(foot, "> next");
    Ok(())
}

fn render_token_ticker(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    // FAITHFUL formatter (audit 2026-06-26 — faithless-formatter class). The
    // token is the field's OWN resolved address word (FMT_TOKEN_TICKER carries
    // no `tokenPath` param — dbgen emits none), so resolve `field.path` rather
    // than a param. The old body resolved only `params.tokenPath`/`token`
    // (always absent here, so it ALWAYS fell to "(unknown token)") and, when
    // unbound, hid the token IDENTITY outright — yet the completeness lint
    // credits `field.path` as covered, so the signed token operand went unshown.
    let addr = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => {
            // address is right-aligned in a 32-byte slot.
            let mut a = [0u8; 20];
            a.copy_from_slice(&b[12..]);
            a
        }
        Resolved::Container(idx) => container_addr(tx, idx)?,
    };
    match erc20 {
        Some(meta) if addr == meta.contract => {
            let [_, r1, _r2, foot] = pages.page_mut(p);
            write_line_bytes(r1, meta.symbol);
            write_line(foot, "> next");
        }
        // No Merkle-verified ticker for this address — NEVER hide the token
        // identity. Show the full 40-hex address (resolver-aware) across rows
        // 1-3 so the signed token operand is always on the trusted display
        // (mirrors render_token_amount's unbound "Token (UNVERIFIED)" page).
        _ => {
            let [_, r1, r2, r3] = pages.page_mut(p);
            write_addr_full_or_name(r1, r2, r3, &addr, tx.chain_id, resolver);
        }
    }
    Ok(())
}

fn render_interop_address_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    _resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    // ERC-3770 long form: `eip155:<chainId>:0x<addr>`. The chain short-
    // name registry is out of scope (would require a separate name DB
    // on-device); long form is unambiguous and self-describing.
    let addr = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => {
            let mut a = [0u8; 20];
            a.copy_from_slice(&b[12..]);
            a
        }
        Resolved::Container(idx) => container_addr(tx, idx)?,
    };
    let p1 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p1, field.label);
    let [_, r1, _r2, foot1] = pages.page_mut(p1);
    let mut row = [b' '; DISPLAY_COLS];
    let mut pos = 0;
    for &b in b"eip155:" {
        if pos < row.len() {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal_into(&mut row, pos, tx.chain_id);
    if pos < row.len() {
        row[pos] = b':';
    }
    *r1 = row;
    write_line(foot1, "> next");

    let p2 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p2, 0), "Address:");
    let [_, r1, r2, r3] = pages.page_mut(p2);
    write_addr_full(r1, r2, r3, &addr);
    Ok(())
}

fn render_encrypted(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // WYSIWYS (audit 2026-06-29 — encrypted formatter signed-but-not-shown).
    //
    // The old body painted a benign "[ENCRYPTED]" + descriptor-pinned
    // `fallback_label` page and returned `Ok(())` WITHOUT ever resolving the
    // field's path — so the 32-byte signed operand at that path (a recipient,
    // an amount, a spender) was committed to the digest but NEVER shown, on a
    // page that looks like a normal clear-sign confirmation. It was the only
    // formatter that "succeeds" while hiding a signed value; every sibling
    // (`render_enum`, `render_nft_name`, …) declines-to-blind when it cannot
    // faithfully display, which routes the whole tx to a loud blind-sign page.
    // Because the field is a normal *visible* field (not `visible:"never"`),
    // the dbgen H-3 coverage lint credited it as shown — there was no build-
    // time or on-device signal that an operand was hidden.
    //
    // There is no honest way to clear-sign a value the format says to hide, so
    // REJECT (decline-to-blind) exactly like `render_enum`: the dispatcher
    // falls through to the blind-sign ladder (loud warning + raw calldata
    // fingerprint) on the UserOp path, and refuses on the off-chain typed
    // path. `dbgen::parse_format_name` additionally refuses `format:
    // "encrypted"` at build time, so the pinned corpus can never emit this
    // opcode — this arm is the runtime safety net if a hand-built TLV ever
    // sets 0x0E.
    let _ = (field, pages, params);
    Err(RenderErr::Reject("7730 encrypted field"))
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

pub(super) fn write_label_row(pages: &mut Pages, page: usize, label: &[u8]) {
    let row = pages.row_mut(page, 0);
    // Reuse the same "ASCII bytes into 16-col row, space-padded"
    // semantics that blind_sign uses for verified-name labels.
    write_line_bytes(row, label);
}

pub(super) fn write_line_bytes(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let n = text.len().min(DISPLAY_COLS);
    row[..n].copy_from_slice(&text[..n]);
}

/// Write 16 bytes of hex (32 chars) into a 16-col row. Used by Raw +
/// fingerprint pages. We deliberately do NOT include the "0x" prefix
/// — the next-page row would lose 2 visual chars and the hex pages
/// are visually anchored by row separators.
fn write_hex_word(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let take = bytes.len().min(DISPLAY_COLS / 2);
    for (i, &b) in bytes[..take].iter().enumerate() {
        row[i * 2] = hex_nibble(b >> 4);
        row[i * 2 + 1] = hex_nibble(b & 0x0F);
    }
}

#[inline]
pub(super) fn hex_nibble(n: u8) -> u8 {
    match n & 0x0F {
        0..=9 => b'0' + n,
        v => b'a' + (v - 10),
    }
}

/// Read the low 8 bytes of a 32-byte BE word as a u64, requiring the
/// high 24 bytes to be zero. Returns `None` when the signed value exceeds
/// `u64` — the caller MUST then paint a loud overflow marker rather than a
/// silently-truncated date/duration. A companion controls these
/// `uint256` words, so the pre-2026-06-23 silent truncation let a benign
/// low-64-bit timestamp display while an unbounded validity window was
/// signed (audit 2026-06-23 — date/duration high-byte truncation).
fn read_u64_be_tail(bytes: &[u8; 32]) -> Option<u64> {
    if bytes[..24].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(bytes[24..].try_into().unwrap()))
}

/// Number of decimal digits needed to render `n` (`0` counts as one
/// digit). Used by the magnitude-critical formatters (block-height date,
/// chain id) to detect — BEFORE painting — that `write_decimal_into` would
/// have to drop low-order digits to fit the row, so they can render the
/// full value across rows or fail loud instead of silently understating
/// the signed magnitude.
pub(super) fn decimal_digits(n: u64) -> usize {
    let mut count = 1usize;
    let mut m = n / 10;
    while m > 0 {
        count += 1;
        m /= 10;
    }
    count
}

/// Format a u64 as decimal at `out[pos..]`. Returns the new position.
///
/// NOTE: this STOPS at the end of the row, silently dropping any digits
/// that don't fit (it writes most-significant-first). That is acceptable
/// only for callers where a dropped low-order digit is cosmetic
/// (`format_duration`'s sub-day components, the interop chain-label
/// prefix). Callers rendering a security-critical magnitude must gate on
/// [`decimal_digits`] first — see `render_date` (blockHeight) and
/// `render_chain_id` — so a magnitude is never silently understated.
pub(super) fn write_decimal_into(
    out: &mut [u8; DISPLAY_COLS],
    pos: usize,
    mut n: u64,
) -> usize {
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    if n == 0 {
        if pos < out.len() {
            out[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    while n > 0 && i < buf.len() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut p = pos;
    for j in (0..i).rev() {
        if p >= out.len() {
            break;
        }
        out[p] = buf[j];
        p += 1;
    }
    p
}

/// Render unix-seconds `secs` into rows `r1` + `r2` as `YYYY-MM-DD` /
/// `HH:MM:SS UTC`. Always-fits since the format is < 16 chars per row.
fn format_iso8601_utc(
    secs: u64,
    r1: &mut [u8; DISPLAY_COLS],
    r2: &mut [u8; DISPLAY_COLS],
) {
    let (year, mon, day, hour, min, sec) = unix_to_ymdhms(secs);

    // WYSIWYS (audit 2026-06-26 — date year truncation). The 4-digit
    // "YYYY" field can only honestly show years 0..=9999. `read_u64_be_tail`
    // accepts any timestamp <= u64::MAX (year ~584e9), and the prior
    // `as u16` cast in `unix_to_ymdhms` wrapped the year mod 65536 — so a
    // perpetual EIP-3009 `validBefore` (true year ~67570, unix ~2.07e12)
    // rendered as a benign "2034" while the signature committed to an
    // effectively-unbounded validity window. Fail LOUD, matching the
    // sibling `! TIME >2^64` guard, so a far-future expiry can never read
    // as a near one (display != signed).
    if !(0..=9999).contains(&year) {
        write_line(r1, "! YEAR >9999");
        write_line(r2, "(far-future)");
        return;
    }
    let year = year as u16; // safe: 0..=9999 after the guard above

    for cell in r1.iter_mut() {
        *cell = b' ';
    }
    for cell in r2.iter_mut() {
        *cell = b' ';
    }

    // Row 1: "YYYY-MM-DD" (10 chars), padded.
    write_2digit(&mut r1[0..2], (year / 100) as u8);
    write_2digit(&mut r1[2..4], (year % 100) as u8);
    r1[4] = b'-';
    write_2digit(&mut r1[5..7], mon);
    r1[7] = b'-';
    write_2digit(&mut r1[8..10], day);

    // Row 2: "HH:MM:SS UTC" (12 chars).
    write_2digit(&mut r2[0..2], hour);
    r2[2] = b':';
    write_2digit(&mut r2[3..5], min);
    r2[5] = b':';
    write_2digit(&mut r2[6..8], sec);
    r2[9] = b'U';
    r2[10] = b'T';
    r2[11] = b'C';
}

fn write_2digit(out: &mut [u8], n: u8) {
    out[0] = b'0' + (n / 10) % 10;
    out[1] = b'0' + (n % 10);
}

/// Convert unix seconds → `(year, month, day, hour, min, sec)` UTC.
/// Civil-from-days algorithm by Howard Hinnant (public domain).
fn unix_to_ymdhms(secs: u64) -> (i64, u8, u8, u8, u8, u8) {
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let hour = (sod / 3600) as u8;
    let min = ((sod % 3600) / 60) as u8;
    let sec = (sod % 60) as u8;

    // Civil-from-days: offset by 719_468 so 1970-01-01 → 0.
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    // Full i64 year — deliberately NOT truncated to u16. The old `as u16`
    // cast wrapped the year mod 65536, so a far-future timestamp (a u64
    // second count `read_u64_be_tail` accepts) rendered as a benign near
    // year. `format_iso8601_utc` now fails loud on any year outside
    // 0..=9999 (audit 2026-06-26 — date year truncation).
    let year = y + if m <= 2 { 1 } else { 0 };

    (year, m, d, hour, min, sec)
}

/// "Xd Yh Zm Ws" duration into a single row. Omits leading zero
/// components.
fn format_duration(mut secs: u64, row: &mut [u8; DISPLAY_COLS]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let d = secs / 86_400;
    secs %= 86_400;
    let h = secs / 3600;
    secs %= 3600;
    let m = secs / 60;
    let s = secs % 60;
    let mut pos = 0usize;
    if d > 0 {
        pos = write_decimal_into(row, pos, d);
        if pos < row.len() {
            row[pos] = b'd';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    if h > 0 || d > 0 {
        pos = write_decimal_into(row, pos, h);
        if pos < row.len() {
            row[pos] = b'h';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    if m > 0 || h > 0 || d > 0 {
        pos = write_decimal_into(row, pos, m);
        if pos < row.len() {
            row[pos] = b'm';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    pos = write_decimal_into(row, pos, s);
    if pos < row.len() {
        row[pos] = b's';
    }
}

/// Resolve the token contract address from a `tokenAmount` /
/// `tokenTicker` field's parameters: `params.token_path` wins, then
/// `params.token` literal.
fn resolve_token_address(
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<[u8; 20], RenderErr> {
    if let Some(tp) = params.token_path {
        // tp is a path program (NO leading length byte — dbgen pushes
        // it raw via `push_tlv(PARAM_TOKEN_PATH, &prog)`). Resolve
        // it directly without re-parsing through `path_bytes`.
        return resolve_path_bytes(tp, body, tx).map(|w| {
            let mut a = [0u8; 20];
            a.copy_from_slice(&w[12..]);
            a
        });
    }
    if let Some(t) = params.token {
        return Ok(*t);
    }
    let _ = ir;
    Err(RenderErr::Reject("7730 no token"))
}

/// Resolve a path program (raw, no length prefix) to a 32-byte word.
/// Mirrors [`resolve_path`] but operates on a pre-extracted program
/// slice — used by `tokenPath` which is stored as a raw program inside
/// the parameter TLV blob.
fn resolve_path_bytes(prog: &[u8], body: &[u8], tx: &Eip1559Tx) -> Result<[u8; 32], RenderErr> {
    if prog.is_empty() {
        return Err(RenderErr::Reject("7730 empty path"));
    }
    let root = PathOp::try_from(prog[0]).map_err(|_| RenderErr::Reject("7730 bad root"))?;
    let mut p = 1usize;

    match root {
        PathOp::RootStructured => {
            let mut slot = 0usize;
            while p < prog.len() {
                let op = PathOp::try_from(prog[p])
                    .map_err(|_| RenderErr::Reject("7730 bad op"))?;
                p += 1;
                match op {
                    PathOp::FieldIdx => {
                        if p + 2 > prog.len() {
                            return Err(RenderErr::Reject("7730 trunc field"));
                        }
                        let idx = u16::from_be_bytes([prog[p], prog[p + 1]]) as usize;
                        p += 2;
                        slot = slot
                            .checked_add(idx)
                            .ok_or(RenderErr::Reject("7730 slot ovf"))?;
                    }
                    _ => return Err(RenderErr::Reject("7730 path p4 unsup")),
                }
            }
            let start = slot
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let end = start
                .checked_add(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let word = body
                .get(start..end)
                .ok_or(RenderErr::Reject("7730 short body"))?;
            let mut out = [0u8; 32];
            out.copy_from_slice(word);
            Ok(out)
        }
        PathOp::RootContainer => {
            if p + 3 != prog.len() || prog[p] != PathOp::FieldIdx as u8 {
                return Err(RenderErr::Reject("7730 cnt bad"));
            }
            let idx = u16::from_be_bytes([prog[p + 1], prog[p + 2]]);
            match idx {
                container_field::TO => {
                    let addr = tx.to.ok_or(RenderErr::Reject("7730 no to"))?;
                    let mut out = [0u8; 32];
                    out[12..].copy_from_slice(&addr);
                    Ok(out)
                }
                _ => container_u256(tx, idx),
            }
        }
        _ => Err(RenderErr::Reject("7730 path no root")),
    }
}


#[cfg(test)]
mod walker_slot_confusion_fixed {
    //! REGRESSION (clear-signing forgery — FIXED): the walker computes a
    //! head-word slot by SUMMING `FieldIdx` values. That is correct ONLY
    //! when each emitted `FieldIdx` is the field's true ABI *head-word
    //! offset*. dbgen now emits exactly that (see
    //! `dbgen::erc7730::compile_structured_contract_path`); previously it
    //! emitted a logical ordinal, so a field preceded by a multi-word
    //! static type (fixed array `T[N]`, non-leading static tuple)
    //! resolved to the wrong word and the trusted display showed one
    //! value while the contract executed on another.
    //!
    //! These tests pin the on-device half: fed a correctly-compiled
    //! head-slot program, the walker reads the EVM-decoded word (display
    //! == signed); and the head-bound guard rejects any slot that reaches
    //! past the format's static head. See
    //! `docs/security/VULN-erc7730-walker-slot-confusion.md`.
    use super::*;
    use crate::tx::erc7730::{ContextKind, Erc7730Ir};

    /// Build a throwaway `Erc7730Ir` whose `pool` holds a single compiled
    /// path program at offset 1. Only `pool` matters for `resolve_path`.
    fn ir_with_path(prog: &[u8]) -> Erc7730Ir<'static> {
        let mut pool = std::vec::Vec::with_capacity(prog.len() + 2);
        pool.push(0x00);
        pool.push(prog.len() as u8);
        pool.extend_from_slice(prog);
        let pool: &'static [u8] = std::boxed::Box::leak(pool.into_boxed_slice());
        Erc7730Ir {
            schema_ver: crate::tx::erc7730::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool,
            formats: &[],
            raw: &[],
        }
    }

    /// Encode the calldata BODY (post-selector) for
    /// `f(uint256[3] arr, address to)`. ABI head layout:
    ///   word0 = arr[0], word1 = arr[1], word2 = arr[2], word3 = to.
    fn body_uint3arr_then_addr(arr1_marker: u8, real_to: [u8; 20]) -> [u8; 128] {
        let mut body = [0u8; 128];
        body[32 + 12..32 + 32].copy_from_slice(&[arr1_marker; 20]); // arr[1]
        body[96 + 12..96 + 32].copy_from_slice(&real_to); // to (word 3)
        body
    }

    fn addr_of(w: Resolved<'_>) -> [u8; 20] {
        match w {
            Resolved::Slot32(b) => {
                let mut a = [0u8; 20];
                a.copy_from_slice(&b[12..]);
                a
            }
            Resolved::Container(_) => panic!("unexpected container"),
        }
    }

    #[test]
    fn walker_reads_to_with_head_slot_program() {
        // dbgen now emits `to`'s ABI head-word slot 3 (it is preceded by
        // the 3-word `uint256[3] arr`), encoded as `FieldIdx(3)`.
        let prog = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0x00,
            0x03, // FieldIdx(3) — head-word slot, NOT logical ordinal 1
        ];
        let ir = ir_with_path(&prog);

        let arr1_marker = 0xBE; // attacker-controlled benign-looking word 1
        let real_to = [0xADu8; 20]; // the address the EVM actually uses
        let body = body_uint3arr_then_addr(arr1_marker, real_to);

        let shown = addr_of(resolve_path(&ir, 1, &body).expect("path resolves"));

        // DISPLAY == SIGNED: the walker reads head word 3 — the exact word
        // the EVM decodes as `to`. The attacker can no longer divert the
        // displayed recipient by stuffing word 1.
        assert_eq!(shown, real_to, "walker reads the EVM-decoded `to` (word 3)");
        assert_ne!(shown, [arr1_marker; 20], "walker does NOT read arr[1]");
    }

    #[test]
    fn nested_static_tuple_slot_sums_to_head_word() {
        // `g((uint256 a, uint256 b) s, address to)`: `to` is at ABI head
        // word 2 (the static tuple inlines 2 words). dbgen emits
        // FieldIdx(2) [tuple base] + FieldIdx(0) summing to 2. The walker
        // reads word 2.
        let prog = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0x00,
            0x02, // tuple base offset (s occupies words 0..2)
            PathOp::FieldIdx as u8,
            0x00,
            0x00, // (+0) — `to` follows the tuple
        ];
        let ir = ir_with_path(&prog);
        let mut body = [0u8; 96];
        let real_to = [0xCDu8; 20];
        body[64 + 12..64 + 32].copy_from_slice(&real_to); // word 2 = to
        let shown = addr_of(resolve_path(&ir, 1, &body).expect("resolves"));
        assert_eq!(shown, real_to, "summed head slot 2 reads the real `to`");
    }

    #[test]
    fn head_bound_guard_rejects_out_of_head_slot() {
        // A (malformed) program whose slot reaches word 3 while the format
        // declares a 2-word static head. `head_bounded_body` truncates the
        // body to 2 words, so the walker's bounds check rejects the read
        // instead of resolving into the dynamic tail.
        let prog = [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0x00,
            0x03, // slot 3 — past the 2-word static head
        ];
        let ir = ir_with_path(&prog);
        let full_body = [0u8; 128]; // 4 words on the wire
        let bounded =
            super::super::head_bounded_body(&full_body, 2).expect("2-word head present");
        assert_eq!(bounded.len(), 64, "body clamped to the 2-word static head");
        assert!(
            resolve_path(&ir, 1, bounded).is_err(),
            "slot past the static head is rejected, not silently rendered"
        );
    }

    #[test]
    fn head_bound_guard_rejects_short_head() {
        // Calldata too short to even contain the declared static head.
        let short = [0u8; 32]; // 1 word, but the format needs 2
        assert!(super::super::head_bounded_body(&short, 2).is_err());
    }
}

#[cfg(test)]
mod date_overflow_fixed {
    //! REGRESSION (audit 2026-06-23 — date/duration high-byte truncation).
    //! `read_u64_be_tail` used to keep only the low 8 bytes of a signed
    //! `uint256`, so a companion-controlled `validBefore` / `validAfter`
    //! with non-zero high bytes displayed a benign low-64-bit timestamp
    //! while an unbounded validity window was signed. The reader now
    //! rejects any value above `u64::MAX`; the date/duration renderers
    //! paint a loud `! TIME >2^64` / `! DUR >2^64` marker on `None`.
    use super::read_u64_be_tail;

    #[test]
    fn high_bytes_set_returns_none() {
        let mut w = [0u8; 32];
        w[23] = 1; // first byte above the low-8 tail
        assert_eq!(read_u64_be_tail(&w), None);
    }

    #[test]
    fn u64_range_round_trips() {
        let mut w = [0u8; 32];
        w[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(read_u64_be_tail(&w), Some(u64::MAX));
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(read_u64_be_tail(&five), Some(5));
        assert_eq!(read_u64_be_tail(&[0u8; 32]), Some(0));
    }
}

#[cfg(test)]
mod date_year_truncation_fixed {
    //! REGRESSION (audit 2026-06-26 — date year `u16` truncation).
    //!
    //! `read_u64_be_tail` accepts every timestamp `<= u64::MAX`, but
    //! `unix_to_ymdhms` used to cast the computed year `as u16`, wrapping it
    //! mod 65536. A companion-controlled `validBefore` (EIP-3009
    //! `TransferWithAuthorization`, the pinned `circle-usdc-twa` descriptor,
    //! `format:"date"`) of true year 67570 (unix ~2.07e12) therefore
    //! rendered the benign "2034" while the signature committed to an
    //! effectively-perpetual validity window — a display != signed gap and
    //! the unfixed residual of the 2026-06-23 `>2^64` fix. The renderer now
    //! returns the full i64 year and fails loud (`! YEAR >9999`) outside
    //! 0..=9999.
    use super::{format_iso8601_utc, unix_to_ymdhms, DISPLAY_COLS};

    #[test]
    fn unix_to_ymdhms_returns_untruncated_year() {
        // 2.1e12 s ≈ year 68515 — far past the 4-digit field but within the
        // u64 the date reader accepts. The year must come back whole, never
        // wrapped (68515 mod 65536 = 2979 was the pre-fix lie).
        let (year, ..) = unix_to_ymdhms(2_100_000_000_000);
        assert!(year > 9999, "year must not wrap; got {year}");
        assert_ne!(year, 2979, "year must not be the mod-65536 wrap value");
    }

    #[test]
    fn far_future_timestamp_within_u64_fails_loud() {
        // The concrete exploit vector: a perpetual `validBefore` that the
        // reader passes (<= u64::MAX) must NEVER render as a plausible near
        // year. It paints the loud marker instead.
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        format_iso8601_utc(2_100_000_000_000, &mut r1, &mut r2);
        assert_eq!(&r1[..12], b"! YEAR >9999");
        // And crucially must not read as any benign near year.
        assert_ne!(&r1[..4], b"2979");
        assert_ne!(&r1[..4], b"2034");
    }

    #[test]
    fn year_9999_boundary_renders_but_year_10000_fails_loud() {
        // 9999-12-31T23:59:59Z is the last honestly-renderable second.
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        format_iso8601_utc(253_402_300_799, &mut r1, &mut r2);
        assert_eq!(&r1[..4], b"9999");
        // 10000-01-01T00:00:00Z is the first that cannot.
        let mut r1b = [b' '; DISPLAY_COLS];
        let mut r2b = [b' '; DISPLAY_COLS];
        format_iso8601_utc(253_402_300_800, &mut r1b, &mut r2b);
        assert_eq!(&r1b[..12], b"! YEAR >9999");
    }

    #[test]
    fn ordinary_dates_still_render_unchanged() {
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        // 2024-01-01T00:00:00Z.
        format_iso8601_utc(1_704_067_200, &mut r1, &mut r2);
        assert_eq!(&r1[..10], b"2024-01-01");
        assert_eq!(&r2[..9], b"00:00:00 ");
    }
}

#[cfg(test)]
mod faithless_formatter_fixed {
    //! REGRESSION (audit 2026-06-26 — faithless-formatter class).
    //!
    //! `render_chain_id` and `render_token_ticker` discarded `field.path` and
    //! rendered an envelope / param value instead of the field's signed word,
    //! while dbgen's completeness lint (`check_*_field_completeness`) credited
    //! the field as covering its ABI word — a display != signed gap primed to
    //! fire the moment a `chainId` / `tokenTicker` descriptor shipped (e.g. a
    //! cross-chain bridge's destination chain). Both now resolve `field.path`
    //! and render THAT word; `tokenTicker` additionally shows the token
    //! identity (full address) when no Merkle-verified ticker is bound.
    use super::*;
    use crate::tx::erc7730::{container_field, ContextKind, Erc7730Ir};

    /// Build a throwaway `Erc7730Ir` whose `pool` holds a single compiled path
    /// program at offset 1 (mirrors `walker_slot_confusion_fixed::ir_with_path`).
    fn ir_with_path(prog: &[u8]) -> Erc7730Ir<'static> {
        let mut pool = std::vec::Vec::with_capacity(prog.len() + 2);
        pool.push(0x00);
        pool.push(prog.len() as u8);
        pool.extend_from_slice(prog);
        let pool: &'static [u8] = std::boxed::Box::leak(pool.into_boxed_slice());
        Erc7730Ir {
            schema_ver: crate::tx::erc7730::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool,
            formats: &[],
            raw: &[],
        }
    }

    /// `RootStructured` path program reading head word `slot`.
    fn slot_prog(slot: u16) -> [u8; 4] {
        [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            (slot >> 8) as u8,
            slot as u8,
        ]
    }

    fn envelope_chain(chain_id: u64) -> Eip1559Tx {
        Eip1559Tx {
            chain_id,
            nonce: 0,
            max_priority_fee_per_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            gas_limit: 0,
            to: Some([0u8; 20]),
            value: U256::zero(),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
        }
    }

    fn field(op: FormatOp) -> FieldEntry<'static> {
        FieldEntry {
            format_op: op as u8,
            label: b"Dest",
            path_off: 1,
            param_off: 0,
        }
    }

    #[test]
    fn chain_id_renders_field_word_not_envelope() {
        // Field path -> head word 0 = 8453 (Base); envelope chain = 1 (Mainnet).
        // The faithful formatter must show the SIGNED 8453, not the envelope 1.
        let ir = ir_with_path(&slot_prog(0));
        let mut body = [0u8; 32];
        body[24..32].copy_from_slice(&8453u64.to_be_bytes());
        let tx = envelope_chain(1);
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &body, &tx)
            .expect("renders");
        assert_eq!(&pages.buf[0][1][..4], b"8453", "shows the field's signed chain id");
        assert_eq!(
            &pages.buf[0][2][..6],
            b"(Base)",
            "names the field's chain, not the envelope"
        );
        // The pre-fix lie was the envelope chain (1 / Mainnet).
        assert_ne!(&pages.buf[0][2][..9], b"(Mainnet)");
    }

    #[test]
    fn chain_id_container_root_still_shows_envelope() {
        // `@.chainId` (container root) must keep rendering `tx.chain_id`.
        let prog = [
            PathOp::RootContainer as u8,
            PathOp::FieldIdx as u8,
            (container_field::CHAIN_ID >> 8) as u8,
            container_field::CHAIN_ID as u8,
        ];
        let ir = ir_with_path(&prog);
        let tx = envelope_chain(10); // Optimism
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &[], &tx)
            .expect("renders");
        assert_eq!(&pages.buf[0][1][..2], b"10");
        assert_eq!(&pages.buf[0][2][..10], b"(Optimism)");
    }

    #[test]
    fn chain_id_above_u64_fails_loud() {
        // A >u64 word can't name a real chain; never render a truncated value.
        let ir = ir_with_path(&slot_prog(0));
        let mut body = [0u8; 32];
        body[0] = 1; // high byte set -> > u64
        let tx = envelope_chain(1);
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &body, &tx)
            .expect("renders");
        assert_eq!(&pages.buf[0][1][..13], b"! CHAIN >2^64");
    }

    #[test]
    fn chain_id_seventeen_digits_within_u64_fails_loud() {
        // A 17-digit chain id is <= u64 but cannot fit a 16-col row in full;
        // `write_decimal_into` would silently drop its low digit, painting a
        // different (smaller) chain number than the one signed. Fail loud.
        let ir = ir_with_path(&slot_prog(0));
        let mut body = [0u8; 32];
        // 12_345_678_901_234_567 = 17 digits, < u64::MAX.
        body[24..32].copy_from_slice(&12_345_678_901_234_567u64.to_be_bytes());
        let tx = envelope_chain(1);
        let mut pages = Pages::with_len(0);
        render_chain_id(&field(FormatOp::ChainId), &mut pages, &ir, &body, &tx)
            .expect("renders");
        assert_eq!(&pages.buf[0][1][..13], b"! CHAIN >1e16");
        // Never the silently-truncated top-16-digit value.
        assert_ne!(&pages.buf[0][1][..4], b"1234");
    }

    #[test]
    fn token_ticker_unbound_shows_address_not_unknown() {
        // Field path -> head word 0 = token address; no erc20 metadata bound.
        // The faithful formatter must show the address (token identity), not
        // the old "(unknown token)" that hid the signed operand.
        let ir = ir_with_path(&slot_prog(0));
        let token = [0xABu8; 20];
        let mut body = [0u8; 32];
        body[12..32].copy_from_slice(&token);
        let tx = envelope_chain(1);
        let resolver = NameResolver::new();
        let params = ParamSet::default();
        let mut pages = Pages::with_len(0);
        render_token_ticker(
            &field(FormatOp::TokenTicker),
            &mut pages,
            &ir,
            &body,
            &tx,
            None,
            &resolver,
            &params,
        )
        .expect("renders");
        // Full address shown: write_addr_full_or_name paints "0x" + hex on r1.
        assert_eq!(&pages.buf[0][1][..2], b"0x");
        assert_eq!(pages.buf[0][1][2], b'a', "first nibble of 0xAB");
        assert_eq!(pages.buf[0][1][3], b'b');
        // The pre-fix hid the operand behind this literal.
        assert_ne!(&pages.buf[0][1][..15], b"(unknown token)");
    }

    #[test]
    fn token_ticker_bound_shows_symbol() {
        let ir = ir_with_path(&slot_prog(0));
        let token = [0xCDu8; 20];
        let mut body = [0u8; 32];
        body[12..32].copy_from_slice(&token);
        let tx = envelope_chain(1);
        let meta = Erc20Metadata {
            chain_id: 1,
            contract: token,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        };
        let resolver = NameResolver::new();
        let params = ParamSet::default();
        let mut pages = Pages::with_len(0);
        render_token_ticker(
            &field(FormatOp::TokenTicker),
            &mut pages,
            &ir,
            &body,
            &tx,
            Some(&meta),
            &resolver,
            &params,
        )
        .expect("renders");
        assert_eq!(&pages.buf[0][1][..4], b"USDC");
    }
}

#[cfg(test)]
mod block_height_magnitude_fixed {
    //! REGRESSION (audit 2026-06-26 — magnitude-hiding class).
    //!
    //! `render_date`'s blockHeight branch rendered the signed u64 block id
    //! with `write_decimal_into`, which silently drops low-order digits once
    //! the 16-col row fills. With the 7-char "block #" prefix only 9 digits
    //! fit, so a >=10-digit deadline rendered as its top 9 digits — e.g.
    //! block 12_345_678_901 painted "block #123456789" (~100x understated),
    //! a far-future authorization expiry the user reads as near while the
    //! signature commits to the full value. Same display != signed
    //! magnitude-hiding class as the date-year u16 truncation (commit
    //! 7df062d3); the blockHeight sibling had no guard. The fix shows the
    //! FULL magnitude (inline while it fits, else label + full number on r2)
    //! and fails loud only for absurd >16-digit values.
    use super::*;
    use crate::tx::erc7730::{ContextKind, Erc7730Ir};

    /// Throwaway IR whose `pool` holds one compiled path program at offset 1
    /// (mirrors `faithless_formatter_fixed::ir_with_path`).
    fn ir_with_path(prog: &[u8]) -> Erc7730Ir<'static> {
        let mut pool = std::vec::Vec::with_capacity(prog.len() + 2);
        pool.push(0x00);
        pool.push(prog.len() as u8);
        pool.extend_from_slice(prog);
        let pool: &'static [u8] = std::boxed::Box::leak(pool.into_boxed_slice());
        Erc7730Ir {
            schema_ver: crate::tx::erc7730::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool,
            formats: &[],
            raw: &[],
        }
    }

    fn slot0_prog() -> [u8; 4] {
        [
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            0,
            0,
        ]
    }

    fn envelope() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            gas_limit: 0,
            to: Some([0u8; 20]),
            value: U256::zero(),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
        }
    }

    fn date_field() -> FieldEntry<'static> {
        FieldEntry {
            format_op: FormatOp::Date as u8,
            label: b"Expiry",
            path_off: 1,
            param_off: 0,
        }
    }

    /// Render a blockHeight `date` field over a signed word = `block`.
    fn render_block(block: u64) -> Pages {
        let ir = ir_with_path(&slot0_prog());
        let mut body = [0u8; 32];
        body[24..32].copy_from_slice(&block.to_be_bytes());
        let tx = envelope();
        let mut params = ParamSet::default();
        params.date_encoding = Some(DATE_ENC_BLOCKHEIGHT);
        let mut pages = Pages::with_len(0);
        render_date(&date_field(), &mut pages, &ir, &body, &tx, &params).expect("renders");
        pages
    }

    #[test]
    fn small_block_height_renders_inline_unchanged() {
        // < 1e9 (9 digits): the unchanged compact form on row 1.
        let pages = render_block(21_000_000);
        assert_eq!(&pages.buf[0][1][..15], b"block #21000000");
    }

    #[test]
    fn nine_digit_block_height_still_inline() {
        // 999_999_999 — the largest height that fits "block #N" on one row.
        let pages = render_block(999_999_999);
        assert_eq!(&pages.buf[0][1][..16], b"block #999999999");
    }

    #[test]
    fn large_block_height_shows_full_magnitude_not_truncated() {
        // The concrete exploit value: 12_345_678_901 (11 digits). The pre-fix
        // code rendered "block #123456789" (top 9 digits, ~100x understated).
        let pages = render_block(12_345_678_901);
        // Row 1 must NOT be the truncated top-9 lie.
        assert_ne!(&pages.buf[0][1][..15], b"block #12345678");
        assert_eq!(&pages.buf[0][1][..13], b"Block height:");
        // The FULL block id appears on row 2.
        assert_eq!(&pages.buf[0][2][..11], b"12345678901");
    }

    #[test]
    fn sixteen_digit_block_height_shows_full_on_row2() {
        // 1_000_000_000_000_000 (16 digits) is the widest value still shown
        // in full on its own 16-col row.
        let pages = render_block(1_000_000_000_000_000);
        assert_eq!(&pages.buf[0][1][..13], b"Block height:");
        assert_eq!(&pages.buf[0][2][..16], b"1000000000000000");
    }

    #[test]
    fn absurd_block_height_fails_loud_never_truncates() {
        // >16 digits (>= 1e16 — not a real block height on any chain). Must
        // fail loud, never paint a silently-truncated value.
        let pages = render_block(12_345_678_901_234_567); // 17 digits
        assert_eq!(&pages.buf[0][1][..13], b"Block height:");
        assert_eq!(&pages.buf[0][2][..13], b"! >1e16 (ovf)");
        // No truncated digit string anywhere on the value rows.
        assert_ne!(&pages.buf[0][2][..4], b"1234");
    }
}

#[cfg(test)]
mod encrypted_formatter_declines {
    //! REGRESSION (audit 2026-06-29 — `encrypted` formatter signed-but-not-shown).
    //!
    //! `render_encrypted` used to paint a benign "[ENCRYPTED]" + descriptor
    //! `fallback_label` page and return `Ok(())` WITHOUT resolving the field's
    //! path — so the 32-byte signed operand at that path (recipient / amount /
    //! spender) was committed to the digest but never shown, on a page that
    //! looks like a normal clear-sign confirmation. It was the only formatter
    //! that "succeeds" while hiding a signed value, and because the field is a
    //! normal *visible* field the dbgen H-3 coverage lint credited it as
    //! shown. It now declines-to-blind (`RenderErr::Reject`) like `render_enum`,
    //! so the dispatcher falls through to the loud blind-sign ladder (UserOp
    //! path) / refuses (off-chain typed path). `dbgen::parse_format_name` also
    //! refuses `format:"encrypted"` at build time.
    use super::*;
    use crate::tx::erc7730::{ContextKind, Erc7730Ir};

    fn empty_ir() -> Erc7730Ir<'static> {
        Erc7730Ir {
            schema_ver: crate::tx::erc7730::SCHEMA_VER,
            context_kind: ContextKind::Contract,
            chain_id: 1,
            contract: [0u8; 20],
            descriptor_hash: [0u8; 32],
            domain_separator: [0u8; 32],
            owner: &[],
            contract_name: &[],
            pool: &[],
            formats: &[],
            raw: &[],
        }
    }

    fn envelope() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            gas_limit: 0,
            to: Some([0u8; 20]),
            value: U256::zero(),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
        }
    }

    /// `render_encrypted` must REJECT — never emit a confirmable page — even
    /// when a `fallback_label` is present (the worst case: the descriptor
    /// supplies a plausible benign label the old code would have shown).
    #[test]
    fn render_encrypted_declines_to_blind_even_with_fallback_label() {
        let mut params = ParamSet::default();
        params.fallback_label = Some(b"Recipient address");
        let field = FieldEntry {
            format_op: FormatOp::Encrypted as u8,
            label: b"Recipient",
            path_off: 0,
            param_off: 0,
        };
        let mut pages = Pages::with_len(0);
        let r = render_encrypted(&field, &mut pages, &params);
        assert!(
            matches!(r, Err(RenderErr::Reject("7730 encrypted field"))),
            "encrypted formatter must decline-to-blind, got {r:?}"
        );
        // No page may be produced — a confirmable "[ENCRYPTED]" page is exactly
        // the signed-but-not-shown surface this fix removes.
        assert_eq!(pages.len, 0, "encrypted field must not emit a page");
    }

    /// Routed through `dispatch`, a `FormatOp::Encrypted` field aborts the
    /// whole descriptor render (Err) so the tx falls to the blind-sign ladder
    /// — it can never produce a benign clear-sign page that hides the operand.
    #[test]
    fn dispatch_encrypted_aborts_render() {
        let ir = empty_ir();
        let tx = envelope();
        let body = [0u8; 32];
        let resolver = crate::names::NameResolver::new();
        let params = ParamSet::default();
        let field = FieldEntry {
            format_op: FormatOp::Encrypted as u8,
            label: b"amount",
            path_off: 0,
            param_off: 0,
        };
        let mut pages = Pages::with_len(0);
        let r = dispatch(
            &field, &mut pages, &ir, &body, &tx, None, &resolver, &params,
        );
        assert!(r.is_err(), "encrypted field must abort the descriptor render");
        assert_eq!(pages.len, 0, "no page may be emitted for an encrypted field");
    }
}
