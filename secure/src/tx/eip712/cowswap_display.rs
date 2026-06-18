//! Trusted-UI page renderer for CowSwap GPv2Order clear-signing.
//!
//! Consumes a verified order (`VerifiedCowswapV3`): the 204-byte packed
//! `canonical` GPv2Order plus two `CowLeg`s describing how each swap leg
//! should render. `canonical` is bound to the signed setPreSignature
//! calldata by the native keccak cross-check in
//! `crate::tx::eip712::cowswap::verify`, so every field rendered here is
//! provably the order the chain will act on.
//!
//! Each leg renders one of two ways:
//!
//!   * `CowLeg::Decoded` — the leg's ERC-20 bundle Merkle-verified
//!     against `ERC20_DB_ROOT`, so the firmware shows `<amount> <symbol>`
//!     with `decimals` applied (the same fixed-width, anti-spoof
//!     amount formatter the ERC-20 transfer path uses). 1 page.
//!   * `CowLeg::AddrHex` — no usable bundle: the firmware shows the raw
//!     20-byte token address + the full uint256 amount as hex so the
//!     user can still verify magnitudes without trusting the host for
//!     decimals. 2 pages.
//!
//! There is no Groth16 proof and no Poseidon registry — token metadata
//! is decoded on-device against a firmware-pinned Merkle root, lifting
//! the old 256-token / 6-char-symbol circuit cap entirely.

use crate::tx::display::Pages;
use crate::tx::eip712::cowswap::CowLeg;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

// ---------------------------------------------------------------------------
// Canonical field slice offsets (must match
// `secure/src/tx/eip712/cowswap.rs::decode_canonical`).
// ---------------------------------------------------------------------------

const OFF_CHAIN_ID: usize = 0;
const OFF_SELL_TOKEN: usize = 8;
const OFF_BUY_TOKEN: usize = 28;
const OFF_RECEIVER: usize = 48;
const OFF_SELL_AMOUNT: usize = 68;
const OFF_BUY_AMOUNT: usize = 100;
const OFF_FEE_AMOUNT: usize = 132;
const OFF_VALID_TO: usize = 164;
const OFF_KIND: usize = 168;
const OFF_PARTIAL: usize = 169;
const OFF_SELL_TOKEN_BAL: usize = 170;
const OFF_BUY_TOKEN_BAL: usize = 171;
const OFF_APP_DATA: usize = 172;

#[derive(Clone, Copy)]
enum Side {
    Sell,
    Buy,
}

/// Number of body pages a leg occupies: 1 when decoded (amount+symbol),
/// 2 in AddrHex mode (token address page + uint256 hex page).
const fn leg_page_count(decoded: bool) -> usize {
    if decoded {
        1
    } else {
        2
    }
}

/// Total order-body page count for the given leg modes. Used by the
/// Safe-wrapped renderer to pre-size its `Pages` before calling
/// [`append_order_body_pages`].
///
/// Body = sell leg + buy leg + receiver + (expires/partial) + (fee/bal) +
/// appData → `leg(sell) + leg(buy) + 4`.
#[must_use]
pub fn order_body_page_count(sell: &CowLeg, buy: &CowLeg) -> usize {
    leg_page_count(sell.is_decoded()) + leg_page_count(buy.is_decoded()) + 4
}

/// Produce the full confirmation flow for a verified CowSwap order.
///
/// Page layout: header (chain + kind) → order body → confirm. The page
/// count depends on the leg modes (8 when both legs decode, up to 10
/// when both fall back to AddrHex).
pub fn render_cowswap_pages(canonical: &[u8; 204], sell: &CowLeg, buy: &CowLeg) -> Pages {
    let total = 1 + order_body_page_count(sell, buy) + 1;
    let mut pages = Pages::empty_with_len(total);

    let chain_id = read_chain_id(canonical);

    // ── Page 0: Header / chain / chain-name / kind ────────────────────
    write_line(&mut pages.row_mut(0, 0), "Sign CowSwap?");
    write_chain_row(&mut pages.row_mut(0, 1), chain_id);
    write_line(&mut pages.row_mut(0, 2), chain_name_str(chain_id));
    write_line(&mut pages.row_mut(0, 3), order_kind_label(canonical));

    // ── Order body (shared with the Safe-wrapped flow) ───────────────
    let next = append_order_body_pages(&mut pages, 1, canonical, sell, buy, None);
    debug_assert_eq!(next, total - 1);

    // ── Final page: Confirm ──────────────────────────────────────────
    write_line(&mut pages.row_mut(next, 0), "");
    write_line(&mut pages.row_mut(next, 1), "  Long-press:");
    write_line(&mut pages.row_mut(next, 2), "L=Cancel");
    write_line(&mut pages.row_mut(next, 3), "R=Confirm");

    pages
}

/// Write the order-body pages of a verified CoW order into an
/// already-sized `Pages` buffer starting at index `start`; returns the
/// index of the first page after the body.
///
/// Shared core of [`render_cowswap_pages`] (direct flow) and the
/// Safe-wrapped combined renderer in `crate::tx::display::safe_display`
/// — one body implementation, two framings.
///
/// `owner_label`: GPv2 semantics give `receiver == address(0)` the
/// meaning "proceeds go to the order's owner". The direct flow passes
/// `None` (renders the zero address verbatim); the Safe-wrapped flow
/// passes a label like `"(= the Safe)"` so the user understands where
/// the bought tokens land.
pub fn append_order_body_pages(
    pages: &mut Pages,
    start: usize,
    canonical: &[u8; 204],
    sell: &CowLeg,
    buy: &CowLeg,
    owner_label: Option<&str>,
) -> usize {
    let kind = canonical[OFF_KIND];
    let mut p = start;

    // ── Sell leg ─────────────────────────────────────────────────────
    p = append_leg(pages, p, canonical, sell, Side::Sell, kind);
    // ── Buy leg ──────────────────────────────────────────────────────
    p = append_leg(pages, p, canonical, buy, Side::Buy, kind);

    // ── Receiver ─────────────────────────────────────────────────────
    write_line(&mut pages.row_mut(p, 0), "Receiver:");
    let receiver: [u8; 20] = canonical[OFF_RECEIVER..OFF_RECEIVER + 20]
        .try_into()
        .expect("20-byte slice");
    match owner_label {
        Some(label) if receiver == [0u8; 20] => {
            write_line(&mut pages.row_mut(p, 1), label);
            write_line(&mut pages.row_mut(p, 2), "");
        }
        _ => {
            let page = pages.page_mut(p);
            let (head, tail) = page.split_at_mut(2);
            write_addr_two_rows(&mut head[1], &mut tail[0], &receiver);
        }
    }
    write_line(&mut pages.row_mut(p, 3), "> next");
    p += 1;

    // ── Expires + partiallyFillable ──────────────────────────────────
    write_line(&mut pages.row_mut(p, 0), "Expires:");
    let valid_to = u32::from_be_bytes([
        canonical[OFF_VALID_TO],
        canonical[OFF_VALID_TO + 1],
        canonical[OFF_VALID_TO + 2],
        canonical[OFF_VALID_TO + 3],
    ]);
    write_u32_row(&mut pages.row_mut(p, 1), "unix ", valid_to);
    write_partial_row(&mut pages.row_mut(p, 2), canonical[OFF_PARTIAL]);
    write_line(&mut pages.row_mut(p, 3), "> next");
    p += 1;

    // ── Fee + balance kinds ──────────────────────────────────────────
    write_line(&mut pages.row_mut(p, 0), "Fee:");
    write_fee_row(
        &mut pages.row_mut(p, 1),
        &canonical[OFF_FEE_AMOUNT..OFF_FEE_AMOUNT + 32],
    );
    write_balance_row(
        &mut pages.row_mut(p, 2),
        canonical[OFF_SELL_TOKEN_BAL],
        canonical[OFF_BUY_TOKEN_BAL],
    );
    write_line(&mut pages.row_mut(p, 3), "> next");
    p += 1;

    // ── appData ──────────────────────────────────────────────────────
    write_line(&mut pages.row_mut(p, 0), "appData:");
    let app = &canonical[OFF_APP_DATA..OFF_APP_DATA + 32];
    write_app_data_prefix(&mut pages.row_mut(p, 1), app);
    write_app_data_suffix(&mut pages.row_mut(p, 2), app);
    write_line(&mut pages.row_mut(p, 3), "> next");
    p += 1;

    p
}

/// Render a single swap leg starting at page `p`; returns the next free
/// page index.
fn append_leg(
    pages: &mut Pages,
    p: usize,
    canonical: &[u8; 204],
    leg: &CowLeg,
    side: Side,
    kind: u8,
) -> usize {
    let (token_off, amount_off) = match side {
        Side::Sell => (OFF_SELL_TOKEN, OFF_SELL_AMOUNT),
        Side::Buy => (OFF_BUY_TOKEN, OFF_BUY_AMOUNT),
    };

    match leg {
        CowLeg::Decoded {
            decimals,
            symbol,
            symbol_len,
        } => {
            // One page: label / amount (2 rows) / "> next".
            write_line(&mut pages.row_mut(p, 0), leg_label(kind, side));
            let amount: [u8; 32] = canonical[amount_off..amount_off + 32]
                .try_into()
                .expect("32-byte slice");
            {
                let page = pages.page_mut(p);
                let (head, tail) = page.split_at_mut(2);
                crate::tx::display::primitives::write_cow_leg_amount(
                    &mut head[1],
                    &mut tail[0],
                    &amount,
                    *decimals,
                    &symbol[..*symbol_len as usize],
                );
            }
            write_line(&mut pages.row_mut(p, 3), "> next");
            p + 1
        }
        CowLeg::AddrHex => {
            // Page A: token addr + amount-page hint.
            let label: &str = match side {
                Side::Sell => "Sell token:",
                Side::Buy => "Buy  token:",
            };
            write_line(&mut pages.row_mut(p, 0), label);
            let token: [u8; 20] = canonical[token_off..token_off + 20]
                .try_into()
                .expect("20-byte slice");
            {
                let page = pages.page_mut(p);
                let (head, tail) = page.split_at_mut(2);
                write_addr_two_rows(&mut head[1], &mut tail[0], &token);
            }
            write_line(
                &mut pages.row_mut(p, 3),
                match side {
                    Side::Sell => "sellAmt(hex) >",
                    Side::Buy => "buyAmt(hex)  >",
                },
            );
            // Page B: full 32-byte uint256 amount as hex.
            write_uint256_hex_page(pages, p + 1, &canonical[amount_off..amount_off + 32]);
            p + 2
        }
    }
}

/// Per-leg label reflecting the order kind so the user sees which side
/// is the exact amount and which is the limit (WYSIWYS):
///   * SELL order: sell is exact, buy is a minimum.
///   * BUY  order: buy is exact, sell is a maximum.
fn leg_label(kind: u8, side: Side) -> &'static str {
    match (kind, side) {
        (0, Side::Sell) => "Sell exactly:",
        (0, Side::Buy) => "Buy >= (min):",
        (_, Side::Sell) => "Sell <= (max):",
        (_, Side::Buy) => "Buy exactly:",
    }
}

/// "kind=SELL" / "kind=BUY" banner row.
#[must_use]
pub fn order_kind_label(canonical: &[u8; 204]) -> &'static str {
    if canonical[OFF_KIND] == 0 {
        "kind=SELL"
    } else {
        "kind=BUY"
    }
}

fn read_chain_id(canonical: &[u8; 204]) -> u64 {
    u64::from_be_bytes([
        canonical[OFF_CHAIN_ID],
        canonical[OFF_CHAIN_ID + 1],
        canonical[OFF_CHAIN_ID + 2],
        canonical[OFF_CHAIN_ID + 3],
        canonical[OFF_CHAIN_ID + 4],
        canonical[OFF_CHAIN_ID + 5],
        canonical[OFF_CHAIN_ID + 6],
        canonical[OFF_CHAIN_ID + 7],
    ])
}

/// Render a 32-byte BE uint256 as 4 rows × 16 hex chars (no prefix /
/// no label — the preceding page tells the user this is the amount).
fn write_uint256_hex_page(pages: &mut Pages, page_idx: usize, bytes: &[u8]) {
    for row_idx in 0..DISPLAY_ROWS {
        let row = pages.row_mut(page_idx, row_idx);
        *row = [b' '; DISPLAY_COLS];
        let start = row_idx * 8; // 8 bytes per row → 16 hex chars
        for i in 0..8 {
            let b = bytes[start + i];
            row[i * 2] = hex_nibble(b >> 4);
            row[i * 2 + 1] = hex_nibble(b & 0x0f);
        }
    }
}

// ---------------------------------------------------------------------------
// Row helpers
// ---------------------------------------------------------------------------

fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
    *row = [b' '; DISPLAY_COLS];
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

fn write_chain_row(row: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"chain ";
    row[..prefix.len()].copy_from_slice(prefix);
    let mut tmp = [0u8; 16];
    let n = format_u64_decimal(chain_id, &mut tmp);
    let off = prefix.len();
    let copy = core::cmp::min(n, DISPLAY_COLS - off);
    row[off..off + copy].copy_from_slice(&tmp[..copy]);
}

fn chain_name_str(chain_id: u64) -> &'static str {
    match chain_id {
        1 => "(Mainnet)",
        10 => "(Optimism)",
        56 => "(BSC)",
        100 => "(Gnosis)",
        137 => "(Polygon)",
        8453 => "(Base)",
        42161 => "(Arbitrum)",
        11155111 => "(Sepolia)",
        _ => "",
    }
}

/// Render a 20-byte address across two rows:
///
///   row1: "0x" + first 7 bytes hex (14 chars) → 16 chars
///   row2: "..." + last 6 bytes hex (12 chars + 3 dots + 1 pad) → 16 chars
fn write_addr_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        row1[2 + i * 2] = hex_nibble(addr[i] >> 4);
        row1[2 + i * 2 + 1] = hex_nibble(addr[i] & 0x0f);
    }
    row2[0] = b'.';
    row2[1] = b'.';
    row2[2] = b'.';
    row2[3] = b' ';
    // Last 6 bytes of the address = 12 hex chars at cols 4..16.
    for i in 0..6 {
        let b = addr[14 + i];
        row2[4 + i * 2] = hex_nibble(b >> 4);
        row2[4 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

fn write_u32_row(row: &mut [u8; DISPLAY_COLS], prefix: &str, value: u32) {
    *row = [b' '; DISPLAY_COLS];
    let p = prefix.as_bytes();
    let n = core::cmp::min(p.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&p[..n]);
    let mut tmp = [0u8; 16];
    let k = format_u64_decimal(value as u64, &mut tmp);
    let off = n;
    let copy = core::cmp::min(k, DISPLAY_COLS - off);
    row[off..off + copy].copy_from_slice(&tmp[..copy]);
}

fn write_partial_row(row: &mut [u8; DISPLAY_COLS], partial: u8) {
    write_line(row, if partial == 0 { "Partial: no" } else { "Partial: yes" });
}

/// Render the low 7 bytes of a 32-byte fee amount as "0x" + 14 hex
/// chars = 16 chars exactly.
fn write_fee_row(row: &mut [u8; DISPLAY_COLS], fee: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'0';
    row[1] = b'x';
    let start = 32 - 7;
    for i in 0..7 {
        let b = fee[start + i];
        row[2 + i * 2] = hex_nibble(b >> 4);
        row[2 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

/// Render the sell/buy balance kinds as:
///   "src:S dst:D"   where S ∈ {e,x,i} (erc20, external, internal)
///                         D ∈ {e,i}   (erc20, internal)
fn write_balance_row(row: &mut [u8; DISPLAY_COLS], sell_bal: u8, buy_bal: u8) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"src:";
    row[..4].copy_from_slice(prefix);
    row[4] = balance_char_sell(sell_bal);
    row[5] = b' ';
    row[6] = b'd';
    row[7] = b's';
    row[8] = b't';
    row[9] = b':';
    row[10] = balance_char_buy(buy_bal);
}

fn balance_char_sell(b: u8) -> u8 {
    match b {
        0 => b'e', // erc20
        1 => b'x', // external
        2 => b'i', // internal
        _ => b'?',
    }
}

fn balance_char_buy(b: u8) -> u8 {
    match b {
        0 => b'e', // erc20
        1 => b'i', // internal
        _ => b'?',
    }
}

/// Render "0x" + first 7 bytes of appData hex = 16 chars.
fn write_app_data_prefix(row: &mut [u8; DISPLAY_COLS], app: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'0';
    row[1] = b'x';
    for i in 0..7 {
        let b = app[i];
        row[2 + i * 2] = hex_nibble(b >> 4);
        row[2 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

/// Render "..." + last 6 bytes of appData hex = 16 chars.
fn write_app_data_suffix(row: &mut [u8; DISPLAY_COLS], app: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'.';
    row[1] = b'.';
    row[2] = b'.';
    row[3] = b' ';
    for i in 0..6 {
        let b = app[26 + i];
        row[4 + i * 2] = hex_nibble(b >> 4);
        row[4 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn format_u64_decimal(mut n: u64, out: &mut [u8]) -> usize {
    if n == 0 {
        if !out.is_empty() {
            out[0] = b'0';
            return 1;
        }
        return 0;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let len = core::cmp::min(i, out.len());
    for j in 0..len {
        out[j] = buf[i - 1 - j];
    }
    len
}
