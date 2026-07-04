//! Row-level formatting helpers shared by every renderer in this
//! directory. `pub` so only the sibling submodules under
//! `display::` consume them — external crates get the high-level
//! `render_*_pages` entry points.
//!
//! Design rules for every helper in this file:
//!
//! * **Never silently truncate a number.** The OLED is the trusted
//!   display; a truncated value is as dangerous as a wrong one. When
//!   something won't fit, return `false` / `AmountFit::Overflow` and
//!   let the caller render a visible warning.
//! * **No panics on any input** (including attacker-supplied values).
//!   `#![no_std]`, no alloc, no heap.
//! * **Left-aligned, space-padded rows.** Every helper takes a
//!   `&mut [u8; DISPLAY_COLS]` and writes exactly one row's worth of
//!   ASCII. Rows are pre-cleared to `b' '` before any data is written.

use pqsigner_tx::erc20::bundle::Erc20Metadata;
use pqsigner_tx::erc20::calldata::Erc20Call;
use pqsigner_tx_core::eip1559::U256;
use pqsigner_tx_core::hash::keccak256;
use super::DISPLAY_COLS;

// ---------------------------------------------------------------------------
// Low-level row primitives
// ---------------------------------------------------------------------------

/// Overwrite `row` with `text`, left-aligned. Truncates to `DISPLAY_COLS`
/// and pads the tail with spaces. Intended for fixed label strings that
/// are known to fit — NEVER feed it attacker-controlled data.
pub fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
    *row = [b' '; DISPLAY_COLS];
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

/// Append `text` to `row` starting at `pos`. Returns the new write
/// position. Bytes that overflow the row are dropped — caller must
/// check `pos == start + text.len()` if it needs a "fit" guarantee.
fn append(row: &mut [u8; DISPLAY_COLS], pos: usize, text: &[u8]) -> usize {
    let mut p = pos;
    for &b in text {
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = b;
        p += 1;
    }
    p
}

pub fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

/// Decimal-format a `u64` into `out`. Returns `Some(n)` on success or
/// `None` if the canonical decimal representation does not fit. Unlike
/// the old helper this one refuses to silently truncate.
pub fn format_u64(mut n: u64, out: &mut [u8]) -> Option<usize> {
    if n == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'0';
        return Some(1);
    }
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    if i > out.len() {
        return None;
    }
    for j in 0..i {
        out[j] = buf[i - 1 - j];
    }
    Some(i)
}

// ---------------------------------------------------------------------------
// Amount rendering
// ---------------------------------------------------------------------------

/// Outcome of a width-aware amount render. `Full` means every digit of
/// the value was painted; `Overflow` means the caller must render a
/// truncation banner because even the 2-row fallback couldn't hold the
/// number.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AmountFit {
    Full,
    Overflow,
}

/// F14#3 collapse-to-zero guard: true iff `digits` (a `format_decimal`
/// output) represents zero — every byte is `'0'` or the decimal point.
///
/// Used to refuse rendering a NONZERO transfer amount that scaled by an
/// (untrusted) `decimals` formats to `"0"` / `"0.000000"`. A poisoned
/// ERC-7730 descriptor could otherwise inflate `params.decimals` so a
/// balance-draining amount paints as a harmless-looking near-zero — the user
/// confirms "0" while signing a large transfer. Amount sinks pass
/// `reject_zero_collapse = true` so they paint the loud overflow banner
/// instead; FEE/gas formatters (gwei/wei) pass `false` because a genuinely
/// tiny fee rendering as `"0.000"` is truthful, not a hidden magnitude.
#[inline]
pub fn formatted_collapses_to_zero(value: &U256, digits: &[u8]) -> bool {
    !value.is_zero() && digits.iter().all(|&b| b == b'0' || b == b'.')
}

/// Try to emit `<amount> <unit>` on a single row.
///
///   * `trim_trailing_zeros = true` for ETH/gwei (shorter form looks
///     cleaner).
///   * `trim_trailing_zeros = false` for ERC-20 token amounts — fixed
///     widths block visual spoofing.
///
/// Returns `true` on success. On failure, the row is left unchanged;
/// caller should fall back to [`write_amount_two_rows`].
pub fn try_write_amount_single_row(
    row: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    reject_zero_collapse: bool,
    unit: &str,
) -> bool {
    let unit_bytes = unit.as_bytes();
    // 1 space separator between amount and unit.
    let budget = match DISPLAY_COLS.checked_sub(unit_bytes.len() + 1) {
        Some(b) => b,
        None => return false, // unit alone would overflow row
    };
    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac_digits, trim_trailing_zeros, &mut tmp) {
        Some(n) if n <= budget => n,
        _ => return false,
    };
    // F14#3: refuse a nonzero amount that collapsed to all-zero digits (the
    // caller falls back to the 2-row sink, which also rejects → overflow
    // banner). Fee/gas callers pass `reject_zero_collapse = false`.
    if reject_zero_collapse && formatted_collapses_to_zero(value, &tmp[..n]) {
        return false;
    }

    *row = [b' '; DISPLAY_COLS];
    row[..n].copy_from_slice(&tmp[..n]);
    row[n] = b' ';
    row[n + 1..n + 1 + unit_bytes.len()].copy_from_slice(unit_bytes);
    true
}

/// Emit `<amount> <unit>` across two rows. The amount's integer part
/// lands on the first row; the fractional tail and the unit go on the
/// second row. This handles amounts whose full decimal representation
/// is up to
///
/// `DISPLAY_COLS + DISPLAY_COLS - unit.len() - 2  ≈ 30 chars`
///
/// which comfortably covers every practical ETH value. For the
/// unrealistic `2^256 - 1 wei` class of inputs the function returns
/// `AmountFit::Overflow` and the caller must paint a banner.
pub fn write_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    reject_zero_collapse: bool,
    unit: &str,
) -> AmountFit {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let unit_bytes = unit.as_bytes();

    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac_digits, trim_trailing_zeros, &mut tmp) {
        Some(n) => n,
        None => return AmountFit::Overflow,
    };
    let digits = &tmp[..n];

    // F14#3: a nonzero transfer amount that scaled to all-zero digits is a
    // hidden-magnitude render — paint the loud overflow banner, never a
    // misleading near-zero. (Fee/gas paths pass `reject_zero_collapse = false`.)
    if reject_zero_collapse && formatted_collapses_to_zero(value, digits) {
        return AmountFit::Overflow;
    }

    // Prefer to split the formatted string at the decimal point so row 1
    // is "<integer>" and row 2 is ".<fraction> <unit>".
    let dot_pos = digits.iter().position(|&b| b == b'.');

    match dot_pos {
        Some(dp) => {
            // Integer part: digits[..dp]. Must fit on row 1 on its own.
            if dp > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row1[..dp].copy_from_slice(&digits[..dp]);
            // Row 2: ".<fraction> <unit>"
            let tail = &digits[dp..]; // includes '.'
            let need2 = tail.len() + 1 + unit_bytes.len();
            if need2 > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row2[..tail.len()].copy_from_slice(tail);
            row2[tail.len()] = b' ';
            row2[tail.len() + 1..tail.len() + 1 + unit_bytes.len()]
                .copy_from_slice(unit_bytes);
            AmountFit::Full
        }
        None => {
            // Pure integer. Split halfway if needed.
            let need1 = n;
            let need2 = unit_bytes.len();
            if need1 <= DISPLAY_COLS && need2 + 1 <= DISPLAY_COLS {
                // Integer on row 1, unit alone on row 2.
                row1[..need1].copy_from_slice(digits);
                row2[..need2].copy_from_slice(unit_bytes);
                AmountFit::Full
            } else if n <= 2 * DISPLAY_COLS && unit_bytes.len() < DISPLAY_COLS {
                // Split integer across rows, unit takes its own chars on row 2.
                let first = core::cmp::min(n, DISPLAY_COLS);
                row1[..first].copy_from_slice(&digits[..first]);
                let rest = &digits[first..];
                if rest.len() + 1 + unit_bytes.len() > DISPLAY_COLS {
                    return AmountFit::Overflow;
                }
                row2[..rest.len()].copy_from_slice(rest);
                row2[rest.len()] = b' ';
                row2[rest.len() + 1..rest.len() + 1 + unit_bytes.len()]
                    .copy_from_slice(unit_bytes);
                AmountFit::Full
            } else {
                AmountFit::Overflow
            }
        }
    }
}

/// Paint `<amount> <unit>` preferring a SINGLE row (`"0.5 ETH"`), spilling to
/// two rows only when it doesn't fit — the same single-row-first policy the
/// native ETH/token paths already use (`write_eth_two_rows`), so an ERC-7730
/// amount no longer always splits into a lone integer row + a `".5 unit"` row.
/// Blanks `row2` on the single-row path. Preserves the F14#3 zero-collapse
/// guard: BOTH sinks reject a nonzero value that formats to all-zero digits, so
/// the single-row shortcut can never hide a magnitude the two-row form would
/// have flagged. (review 4.3)
#[allow(clippy::too_many_arguments)]
pub fn write_amount_single_or_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    reject_zero_collapse: bool,
    unit: &str,
) -> AmountFit {
    if try_write_amount_single_row(
        row1,
        value,
        decimals,
        frac_digits,
        trim_trailing_zeros,
        reject_zero_collapse,
        unit,
    ) {
        *row2 = [b' '; DISPLAY_COLS];
        return AmountFit::Full;
    }
    write_amount_two_rows(
        row1,
        row2,
        value,
        decimals,
        frac_digits,
        trim_trailing_zeros,
        reject_zero_collapse,
        unit,
    )
}

// ---------------------------------------------------------------------------
// Address rendering — FULL 40 hex chars across three rows
// ---------------------------------------------------------------------------

/// Paint the full 40-hex representation of a 20-byte address across
/// three rows of 16 columns:
///
/// ```text
///   row1: "0x"  + first  7 bytes (14 hex chars, 16 col total)
///   row2: next  8 bytes (16 hex chars, 16 col total)
///   row3: last  5 bytes (10 hex chars + 6 space pad, 16 col total)
/// ```
///
/// Showing the full address eliminates the old collision window the
/// truncated 7+8 hex layout exposed (an attacker could brute-force a
/// 5-byte middle to make a hostile address look identical on screen).
/// EIP-55 mixed-case hex of a 20-byte address — 40 ASCII chars, no `0x`.
///
/// This is the canonical display form everywhere else (Etherscan, wallets,
/// dapps), so the device address is directly comparable char-for-char, and the
/// casing carries EIP-55's own single-character transposition check. The bytes
/// are unchanged — casing only — so there is NO WYSIWYS change, just a more
/// verifiable rendering. Uppercases hex letter `i` iff nibble `i` of
/// `keccak256(lowercase_ascii_hex)` is ≥ 8 (digits are never cased).
fn eip55_hex(addr: &[u8; 20]) -> [u8; 40] {
    let mut hex = [0u8; 40];
    for (i, &b) in addr.iter().enumerate() {
        hex[i * 2] = hex_nibble(b >> 4);
        hex[i * 2 + 1] = hex_nibble(b & 0x0f);
    }
    let hash = keccak256(&hex);
    for i in 0..40 {
        if hex[i].is_ascii_alphabetic() {
            let nibble = if i % 2 == 0 { hash[i / 2] >> 4 } else { hash[i / 2] & 0x0f };
            if nibble >= 8 {
                hex[i] = hex[i].to_ascii_uppercase();
            }
        }
    }
    hex
}

pub fn write_addr_full(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    *row3 = [b' '; DISPLAY_COLS];

    let hex = eip55_hex(addr);
    // Row 1: "0x" + bytes 0..7  (2 + 14 = 16 cols)
    row1[0] = b'0';
    row1[1] = b'x';
    row1[2..16].copy_from_slice(&hex[0..14]);
    // Row 2: bytes 7..15  (16 cols)
    row2[..16].copy_from_slice(&hex[14..30]);
    // Row 3: bytes 15..20 — 5 bytes = 10 hex chars, padded to 16
    row3[..10].copy_from_slice(&hex[30..40]);
}

/// Like [`write_addr_full`] but first consults the merkle-verified
/// address-name DB via the supplied [`NameResolver`]. On a DB hit the
/// three rows render as:
///
/// ```text
///   row1: "+ <name row 1 ...>"     (up to 14 chars after the sentinel)
///   row2: " <name row 2 ...>"      (up to 15 chars; blank if name fits row1)
///   row3: "0xAABBCCDD…EEFFAABB"    (first 4 + last 4 bytes, disambiguation)
/// ```
///
/// The leading `+` sentinel is user-visible proof that the secure world
/// matched the address against a signed DB entry — raw-hex fallback
/// never carries it. On a DB miss we delegate to [`write_addr_full`].
pub fn write_addr_full_or_name(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    addr: &[u8; 20],
    chain_id: u64,
    resolver: &pqsigner_tx::names::NameResolver<'_>,
) {
    if let Some(name) = resolver.lookup(chain_id, addr) {
        *row1 = [b' '; DISPLAY_COLS];
        *row2 = [b' '; DISPLAY_COLS];
        *row3 = [b' '; DISPLAY_COLS];

        // Rows 0..=1: sentinel + name, split across two rows if needed.
        row1[0] = b'+';
        row1[1] = b' ';
        let name_room_r1 = DISPLAY_COLS - 2; // after "+ "
        let n1 = core::cmp::min(name.len(), name_room_r1);
        row1[2..2 + n1].copy_from_slice(&name[..n1]);
        if name.len() > name_room_r1 {
            // Leave col 0 blank, start at col 1 to align visually under
            // the name's first char.
            let rest = &name[name_room_r1..];
            let room_r2 = DISPLAY_COLS - 1;
            let n2 = core::cmp::min(rest.len(), room_r2);
            row2[1..1 + n2].copy_from_slice(&rest[..n2]);
        }

        // Row 3: truncated hex for disambiguation — first 3 bytes, a TWO-dot
        // ellipsis, last 3 bytes: "0x112233..AABBCC" = 2+6+2+6 = 16 cols (fits
        // exactly). A single dot read like a typo inside the hex (review 4.13).
        // EIP-55 casing is computed over the FULL address (never the truncated
        // string), then the shown slices (chars 0..6 and 34..40) are copied out.
        let hex = eip55_hex(addr);
        row3[0] = b'0';
        row3[1] = b'x';
        row3[2..8].copy_from_slice(&hex[0..6]);
        row3[8] = b'.';
        row3[9] = b'.';
        row3[10..16].copy_from_slice(&hex[34..40]);
    } else {
        write_addr_full(row1, row2, row3, addr);
    }
}

// ---------------------------------------------------------------------------
// Chain identification
// ---------------------------------------------------------------------------

/// Human-readable chain label, shown on the row BELOW the numeric
/// `Chain: <id>` (`write_chain`) — so the id is always the ground truth and
/// this label is advisory. The list covers the chains the vendored ERC-7730
/// registry actually ships descriptors for (a wrong label would misrepresent
/// the network, so only high-confidence mainnet ids are added; the rest fall
/// through to `(unknown chain)`). We say `(unknown chain)` rather than
/// `(UNVERIFIED)` so the stronger `UNVERIFIED` marker keeps a single meaning
/// (an unverified *token*); the numeric id shown above already lets the user
/// confirm the network.
pub fn chain_name(chain_id: u64) -> &'static str {
    match chain_id {
        1 => "(Mainnet)",
        10 => "(Optimism)",
        14 => "(Flare)",
        30 => "(Rootstock)",
        56 => "(BSC)",
        100 => "(Gnosis)",
        137 => "(Polygon)",
        146 => "(Sonic)",
        250 => "(Fantom)",
        324 => "(zkSync Era)",
        999 => "(HyperEVM)",
        1329 => "(Sei)",
        8217 => "(Kaia)",
        8453 => "(Base)",
        42161 => "(Arbitrum)",
        42220 => "(Celo)",
        43114 => "(Avalanche)",
        59144 => "(Linea)",
        534352 => "(Scroll)",
        11155111 => "(Sepolia)",
        84532 => "(BaseSepolia)",
        _ => "(unknown chain)",
    }
}

/// Native-currency ticker for a chain — the default unit for the ERC-7730
/// `amount` format when the descriptor doesn't pin `params.base`. Previously
/// hardcoded "ETH", so a Polygon/BSC/Avalanche native amount rendered with the
/// WRONG ticker (review 3.5). Only the chains whose native symbol is certain
/// are mapped; unknown chains keep the "ETH" default (most unmapped EVM chains
/// are ETH-gas L2s, and a descriptor-supplied `base` always overrides). ETH-gas
/// L2s (Optimism/Base/Arbitrum/Linea/Scroll/zkSync/Sepolia) also resolve to ETH
/// via the fallback, so they need no explicit arm.
pub fn native_ticker(chain_id: u64) -> &'static [u8] {
    match chain_id {
        56 => b"BNB",
        137 => b"POL",
        146 => b"S",
        250 => b"FTM",
        100 => b"xDAI",
        42220 => b"CELO",
        43114 => b"AVAX",
        14 => b"FLR",
        30 => b"RBTC",
        999 => b"HYPE",
        1329 => b"SEI",
        8217 => b"KAIA",
        _ => b"ETH",
    }
}

pub fn write_chain(row: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Chain: ";
    let mut pos = append(row, 0, prefix);
    let mut tmp = [0u8; 20];
    match format_u64(chain_id, &mut tmp) {
        Some(n) if pos + n <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
        _ => {
            // Chain id doesn't even fit as decimal — put a marker.
            pos = append(row, pos, b"!OVF");
        }
    }
    let _ = pos;
}

// ---------------------------------------------------------------------------
// ETH / gwei / gas formatting
// ---------------------------------------------------------------------------

/// Number of fractional digits shown for every ETH amount. Fixed (not
/// auto-shrunk to fit a row) and matched to the ERC-20 token policy
/// (`write_token_amount_two_rows` uses `min(decimals, 6)`).
const ETH_FRAC_DIGITS: u32 = 6;

/// Paint an ETH value across (up to) two rows.
///
/// Row 1 carries the integer portion; row 2 carries the fractional tail
/// plus "ETH". The helper short-circuits to a single row when the whole
/// thing fits. Returns `AmountFit::Overflow` for pathological values — a
/// 17+ digit integer can't be rendered, and the caller paints a banner.
///
/// **Anti-spoof (audit M-6).** The fractional width is FIXED at
/// [`ETH_FRAC_DIGITS`] and trailing zeros are NOT trimmed — identical to
/// the ERC-20 token-amount policy. The previous implementation tried
/// progressively fewer fractional digits (6 → 4 → 2 → 0) to squeeze the
/// value onto one row and trimmed trailing zeros, so two distinct
/// amounts could render to the same string when the renderer silently
/// dropped the digits that distinguished them. Fixing the width removes
/// that collision class; any value that still doesn't fit overflows
/// loudly rather than aliasing.
pub fn write_eth_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
) -> AmountFit {
    // Single row if the fixed-width form fits. `reject_zero_collapse = true`:
    // an ETH transfer is an amount, so a nonzero value rendering as
    // "0.000000 ETH" must overflow loudly, not hide its magnitude (F14#3).
    if try_write_amount_single_row(row1, value, 18, ETH_FRAC_DIGITS, false, true, "ETH") {
        *row2 = [b' '; DISPLAY_COLS];
        return AmountFit::Full;
    }
    // Otherwise spill the SAME fixed-width form across two rows.
    write_amount_two_rows(row1, row2, value, 18, ETH_FRAC_DIGITS, false, true, "ETH")
}

/// Paint a gas-price value in gwei on a single row. Uses 3 fractional
/// digits by default; degrades precision if the integer portion needs
/// more room. Returns `false` if even the integer form doesn't fit —
/// in practice only possible for attacker-crafted 2^256-class inputs.
pub fn write_gwei(row: &mut [u8; DISPLAY_COLS], value: &U256) -> bool {
    // `reject_zero_collapse = false`: a genuinely tiny gas price rendering as
    // "0.000 gwei" is truthful (a fee, not a transfer amount), so do NOT flip
    // it to an overflow banner (F14#3 applies only to transfer amounts).
    for &frac in &[3u32, 2, 1, 0] {
        if try_write_amount_single_row(row, value, 9, frac, true, false, "gwei") {
            return true;
        }
    }
    // Last-ditch: raw wei as integer, labelled "wei". Prevents a silent
    // gap on the screen; the user sees an unexpectedly large number.
    for &frac in &[0u32] {
        if try_write_amount_single_row(row, value, 0, frac, true, false, "wei") {
            return true;
        }
    }
    write_line(row, "!OVERFLOW");
    false
}

/// "(gas: N)" limited to a single row. For gas limits that don't fit
/// in decimal on 16 cols (> 10^15-ish) we emit "(gas: !OVF)" — the
/// attacker-control path that would trip this is already a fee-bomb.
pub fn write_gas(row: &mut [u8; DISPLAY_COLS], gas: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"(gas: ");
    let mut tmp = [0u8; 20];
    match format_u64(gas, &mut tmp) {
        Some(n) if pos + n + 1 <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
        _ => {
            pos = append(row, pos, b"!OVF");
        }
    }
    if pos < DISPLAY_COLS {
        row[pos] = b')';
    }
}

/// "Tip: N gwei" on a single row. Same graceful degradation as
/// [`write_gwei`].
pub fn write_tip_row(row: &mut [u8; DISPLAY_COLS], tip: &U256) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Tip: ");
    let mut tmp = [0u8; 96];
    let mut wrote = false;
    for &frac in &[3u32, 2, 1, 0] {
        if let Some(n) = tip.format_decimal(9, frac, true, &mut tmp) {
            if pos + n + 5 <= DISPLAY_COLS {
                row[pos..pos + n].copy_from_slice(&tmp[..n]);
                pos += n;
                pos = append(row, pos, b" gwei");
                let _ = pos;
                wrote = true;
                break;
            }
        }
    }
    if !wrote {
        let _ = append(row, 5, b"!OVF");
    }
}

/// "Max: X ETH" worst-case fee budget on a single row. Computed as
/// `max_fee_per_gas * gas_limit`. Silently clamps to U256::MAX on
/// multiplication overflow; the caller sees a suspiciously huge value
/// rather than a wrong-by-modulus one.
pub fn write_fee_budget_row(
    row: &mut [u8; DISPLAY_COLS],
    max_fee_per_gas: &U256,
    gas_limit: u64,
) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Max: ");
    let (budget, _overflow) = max_fee_per_gas.saturating_mul_u64(gas_limit);
    let mut tmp = [0u8; 96];
    let mut wrote = false;
    for &frac in &[4u32, 3, 2, 1, 0] {
        if let Some(n) = budget.format_decimal(18, frac, true, &mut tmp) {
            if pos + n + 4 <= DISPLAY_COLS {
                row[pos..pos + n].copy_from_slice(&tmp[..n]);
                pos += n;
                pos = append(row, pos, b" ETH");
                let _ = pos;
                wrote = true;
                break;
            }
        }
    }
    if !wrote {
        let _ = append(row, 5, b"!OVF");
    }
}

/// "Item X of Y" divider row for a nested array-of-struct (`T[]`) render (v2) —
/// separates each element's page group. `idx` is 0-based; the row shows 1-based.
pub fn write_array_item_row(row: &mut [u8; DISPLAY_COLS], idx: usize, count: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Item ");
    let mut tmp = [0u8; 20];
    if let Some(n) = format_u64((idx as u64).saturating_add(1), &mut tmp) {
        if pos + n <= DISPLAY_COLS {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
    }
    pos = append(row, pos, b" of ");
    if let Some(n) = format_u64(count as u64, &mut tmp) {
        if pos + n <= DISPLAY_COLS {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
    }
    let _ = pos;
}

pub fn write_nonce_row(row: &mut [u8; DISPLAY_COLS], nonce: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Nonce: ");
    let mut tmp = [0u8; 20];
    match format_u64(nonce, &mut tmp) {
        Some(n) if pos + n <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
        }
        _ => {
            let _ = append(row, pos, b"!OVF");
            return;
        }
    }
    let _ = pos;
}

pub fn write_selector_row(row: &mut [u8; DISPLAY_COLS], data: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Sel: ");
    if data.len() >= 4 {
        if pos + 10 <= DISPLAY_COLS {
            row[pos] = b'0';
            row[pos + 1] = b'x';
            pos += 2;
            for i in 0..4 {
                row[pos] = hex_nibble(data[i] >> 4);
                row[pos + 1] = hex_nibble(data[i] & 0x0f);
                pos += 2;
            }
        }
    } else {
        let _ = append(row, pos, b"(none)");
    }
}

pub fn write_data_len_row(row: &mut [u8; DISPLAY_COLS], len: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = append(row, 0, b"Data: ");
    let mut tmp = [0u8; 20];
    match format_u64(len as u64, &mut tmp) {
        Some(n) if pos + n + 2 <= DISPLAY_COLS => {
            row[pos..pos + n].copy_from_slice(&tmp[..n]);
            pos += n;
            let _ = append(row, pos, b" B");
        }
        _ => {
            let _ = append(row, pos, b"!OVF");
        }
    }
}

/// Render the first 7 and last 6 bytes of `hash` as
/// "0x<14 hex>...<12 hex>" across two rows. Used on the blind-sign
/// page so the user can compare a dapp-shown calldata hash against
/// what the wallet is actually going to sign.
pub fn write_calldata_hash_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    hash: &[u8; 32],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        row1[2 + i * 2] = hex_nibble(hash[i] >> 4);
        row1[2 + i * 2 + 1] = hex_nibble(hash[i] & 0x0f);
    }
    row2[0] = b'.';
    row2[1] = b'.';
    row2[2] = b'.';
    row2[3] = b' ';
    for i in 0..6 {
        let b = hash[26 + i];
        row2[4 + i * 2] = hex_nibble(b >> 4);
        row2[4 + i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

// ---------------------------------------------------------------------------
// ERC-20 specific
// ---------------------------------------------------------------------------

pub fn write_erc20_header(
    row: &mut [u8; DISPLAY_COLS],
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
) {
    *row = [b' '; DISPLAY_COLS];
    let verb: &[u8] = match call {
        Erc20Call::Transfer { .. } => b"Send ",
        Erc20Call::TransferFrom { .. } => b"From ",
        Erc20Call::Approve { .. } => b"Approve ",
    };
    let pos = append(row, 0, verb);
    let symbol = meta.symbol;
    let copy = core::cmp::min(symbol.len(), DISPLAY_COLS.saturating_sub(pos));
    if copy > 0 {
        row[pos..pos + copy].copy_from_slice(&symbol[..copy]);
    }
}

pub fn write_token_name(row: &mut [u8; DISPLAY_COLS], meta: &Erc20Metadata<'_>) {
    *row = [b' '; DISPLAY_COLS];
    let copy = core::cmp::min(meta.name.len(), DISPLAY_COLS);
    row[..copy].copy_from_slice(&meta.name[..copy]);
}

/// Render a token amount across up to 2 rows, fixed-width (no
/// trailing-zero trim) so visual-spoofing attacks can't succeed. If
/// the amount overflows both rows the function returns
/// `AmountFit::Overflow` and the caller renders a banner.
pub fn write_token_amount_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    amount: &U256,
    meta: &Erc20Metadata<'_>,
) -> AmountFit {
    // Mirror format_decimal's "decimals-bounded fractional width":
    // frac_digits = min(decimals, 6). For 0-decimal tokens we collapse
    // to pure integer.
    let decimals = meta.decimals as u32;
    let frac = core::cmp::min(decimals, 6);
    let unit_bytes = meta.symbol;

    // Try single row first.
    if single_row_amount_fixed(row1, amount, decimals, frac, unit_bytes) {
        *row2 = [b' '; DISPLAY_COLS];
        return AmountFit::Full;
    }

    // 2-row fallback. Symbol can be up to MAX_DISPLAY_FIELD = 64 bytes
    // from the bundle, but we trust only the first DISPLAY_COLS-1 of
    // it on screen.
    write_amount_two_rows_bytes(row1, row2, amount, decimals, frac, false, unit_bytes)
}

/// CoW swap-leg amount renderer. Formats a 32-byte big-endian amount
/// with `decimals` applied and `symbol` appended, across up to two rows,
/// reusing the same fixed-width (anti-spoof) machinery as the ERC-20
/// transfer path. Keeps the `U256`/`Erc20Metadata`/`AmountFit` plumbing
/// internal so `cowswap_display` (outside the `display` module) can call
/// it with primitive types only.
///
/// Returns `false` on overflow — the magnitude exceeds two rows — and in
/// that case writes a "(amount too big)" marker into `row2` rather than
/// spilling onto an un-budgeted extra page. A decoded CoW amount is
/// astronomically unlikely to overflow (it would need ~16+ decimal
/// digits), but failing safe keeps the page count the renderer
/// pre-computed exact.
pub fn write_cow_leg_amount(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    amount_be: &[u8; 32],
    decimals: u8,
    symbol: &[u8],
) -> bool {
    let amount = U256(*amount_be);
    let meta = Erc20Metadata {
        chain_id: 0,
        contract: [0u8; 20],
        decimals,
        name: &[],
        symbol,
    };
    match write_token_amount_two_rows(row1, row2, &amount, &meta) {
        AmountFit::Full => true,
        AmountFit::Overflow => {
            *row1 = [b' '; DISPLAY_COLS];
            *row2 = [b' '; DISPLAY_COLS];
            let msg = b"(amount too big)";
            row2[..msg.len()].copy_from_slice(msg);
            false
        }
    }
}

fn single_row_amount_fixed(
    row: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac: u32,
    unit_bytes: &[u8],
) -> bool {
    let budget = match DISPLAY_COLS.checked_sub(unit_bytes.len() + 1) {
        Some(b) => b,
        None => return false,
    };
    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac, false, &mut tmp) {
        Some(n) if n <= budget => n,
        _ => return false,
    };
    // F14#3: token amounts always reject the zero-collapse — fall back to the
    // 2-row sink (which also rejects → overflow banner) rather than paint a
    // nonzero amount as "0".
    if formatted_collapses_to_zero(value, &tmp[..n]) {
        return false;
    }
    *row = [b' '; DISPLAY_COLS];
    row[..n].copy_from_slice(&tmp[..n]);
    row[n] = b' ';
    row[n + 1..n + 1 + unit_bytes.len()].copy_from_slice(unit_bytes);
    true
}

fn write_amount_two_rows_bytes(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
    decimals: u32,
    frac_digits: u32,
    trim_trailing_zeros: bool,
    unit_bytes: &[u8],
) -> AmountFit {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];

    let mut tmp = [0u8; 96];
    let n = match value.format_decimal(decimals, frac_digits, trim_trailing_zeros, &mut tmp) {
        Some(n) => n,
        None => return AmountFit::Overflow,
    };
    let digits = &tmp[..n];

    // F14#3: token amounts reject the nonzero-collapse-to-zero render.
    if formatted_collapses_to_zero(value, digits) {
        return AmountFit::Overflow;
    }

    let dot_pos = digits.iter().position(|&b| b == b'.');
    let unit_copy = core::cmp::min(unit_bytes.len(), DISPLAY_COLS.saturating_sub(1));
    let unit = &unit_bytes[..unit_copy];

    match dot_pos {
        Some(dp) => {
            if dp > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row1[..dp].copy_from_slice(&digits[..dp]);
            let tail = &digits[dp..];
            let need2 = tail.len() + 1 + unit.len();
            if need2 > DISPLAY_COLS {
                return AmountFit::Overflow;
            }
            row2[..tail.len()].copy_from_slice(tail);
            row2[tail.len()] = b' ';
            row2[tail.len() + 1..tail.len() + 1 + unit.len()].copy_from_slice(unit);
            AmountFit::Full
        }
        None => {
            if n <= DISPLAY_COLS && 1 + unit.len() <= DISPLAY_COLS {
                row1[..n].copy_from_slice(digits);
                row2[..unit.len()].copy_from_slice(unit);
                AmountFit::Full
            } else {
                AmountFit::Overflow
            }
        }
    }
}

#[cfg(test)]
mod eip55_tests {
    use super::eip55_hex;

    /// The four canonical EIP-55 reference vectors (from the EIP text).
    #[test]
    fn eip55_matches_reference_vectors() {
        let cases: &[([u8; 20], &[u8; 40])] = &[
            (
                [
                    0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66,
                    0x94, 0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
                ],
                b"5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                [
                    0xfb, 0x69, 0x16, 0x09, 0x5c, 0xa1, 0xdf, 0x60, 0xbb, 0x79, 0xce, 0x92, 0xce,
                    0x3e, 0xa7, 0x4c, 0x37, 0xc5, 0xd3, 0x59,
                ],
                b"fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                [
                    0xdb, 0xf0, 0x3b, 0x40, 0x7c, 0x01, 0xe7, 0xcd, 0x3c, 0xbe, 0xa9, 0x95, 0x09,
                    0xd9, 0x3f, 0x8d, 0xdd, 0xc8, 0xc6, 0xfb,
                ],
                b"dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                [
                    0xd1, 0x22, 0x0a, 0x0c, 0xf4, 0x7c, 0x7b, 0x9b, 0xe7, 0xa2, 0xe6, 0xba, 0x89,
                    0xf4, 0x29, 0x76, 0x2e, 0x7b, 0x9a, 0xdb,
                ],
                b"D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];
        for (addr, want) in cases {
            let got = eip55_hex(addr);
            assert_eq!(&got, *want, "EIP-55 mismatch for {want:?}");
        }
    }
}

#[cfg(kani)]
mod kani_harness {
    //! Tier-P0 ∀ proof of the full-address hex skeleton (FV frontier Track 2
    //! M3, 2026-07-04).

    use super::*;

    /// Independent hex oracle: a lookup TABLE, not the code's arithmetic
    /// `hex_nibble`.
    const HEX_LOWER_TAB: &[u8; 16] = b"0123456789abcdef";

    /// ∀ 20-byte addresses: `write_addr_full` (the unresolved-name arm's
    /// painter) shows `0x` + ALL 40 nibbles of the address across rows 1-3
    /// in order, each nibble VALUE bound to the independent table. EIP-55
    /// (landed 2026-07-04, commit 89c9e4c3) picks per-letter CASE from
    /// `keccak256(lowercase_hex)` — the case bits are deliberately left
    /// unbound (binding them would put the hash preimage in the proof
    /// obligation): a letter cell may only be the correct hex letter in
    /// either case, and a digit cell is exactly the digit (digits are never
    /// cased). So no address can render with a wrong / reordered / dropped
    /// nibble regardless of what the case rule computes — the value
    /// skeleton is exact ∀; the casing itself is pinned by the concrete
    /// EIP-55 reference-vector witness below and `eip55_tests`.
    #[kani::proof]
    #[kani::unwind(210)]
    fn addr_full_nibble_values_bind() {
        let addr: [u8; 20] = kani::any();
        let mut r1 = [0u8; DISPLAY_COLS];
        let mut r2 = [0u8; DISPLAY_COLS];
        let mut r3 = [0u8; DISPLAY_COLS];
        write_addr_full(&mut r1, &mut r2, &mut r3, &addr);
        assert!(r1[0] == b'0' && r1[1] == b'x');
        let mut i = 0usize;
        while i < 40 {
            let nib = if i % 2 == 0 {
                addr[i / 2] >> 4
            } else {
                addr[i / 2] & 0x0f
            };
            let lower = HEX_LOWER_TAB[nib as usize];
            let got = if i < 14 {
                r1[2 + i]
            } else if i < 30 {
                r2[i - 14]
            } else {
                r3[i - 30]
            };
            if lower.is_ascii_digit() {
                assert!(got == lower); // digits are never cased
            } else {
                assert!(got == lower || got == lower - 32); // exact letter, either case
            }
            i += 1;
        }
        // Row-3 tail is space padding — no stray content after the address.
        let mut c = 10usize;
        while c < DISPLAY_COLS {
            assert!(r3[c] == b' ');
            c += 1;
        }
    }

    /// Non-vacuity + exact-case witness: EIP-55 reference vector 1
    /// (`0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`) lands across the three
    /// rows with the reference casing.
    #[kani::proof]
    #[kani::unwind(210)]
    fn addr_full_eip55_reference_vector_concrete() {
        let addr: [u8; 20] = [
            0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94,
            0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
        ];
        let mut r1 = [0u8; DISPLAY_COLS];
        let mut r2 = [0u8; DISPLAY_COLS];
        let mut r3 = [0u8; DISPLAY_COLS];
        write_addr_full(&mut r1, &mut r2, &mut r3, &addr);
        assert!(r1 == *b"0x5aAeb6053F3E94");
        assert!(r2 == *b"C9b9A09f33669435");
        assert!(r3 == *b"E7Ef1BeAed      ");
    }
}
