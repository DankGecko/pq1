//! libFuzzer harness for the ERC-7730 display *primitives* — the pure
//! row-buffer byte-writers extracted to `pqsigner_erc7730::display::primitives`
//! so they can be host-linked (they were previously trapped behind the secure
//! crate's `#[cfg(not(test))]`-gated `tx::display` tree; see
//! `docs/erc7730-renderer-fuzzability.md`).
//!
//! ## Why this is the high-value target
//!
//! The firmware release profile sets `overflow-checks = true`. The amount
//! writers (`write_amount_two_rows`, `write_amount_single_or_two_rows`,
//! `write_token_amount_two_rows`, `write_cow_leg_amount`, `write_fee_budget_row`,
//! `write_eth_two_rows`, `write_gwei`) run **decimal-scaling + `checked_sub`
//! column-budget arithmetic on an attacker-controlled `U256`** — the value
//! comes straight from calldata. An arithmetic slip there is a panic = DoS on
//! the trusted-display path, exactly where the wallet must never abort. The
//! descriptor-side path this crate already fuzzes (`erc7730_render_dispatch`)
//! never exercises this byte arithmetic, so this harness covers the
//! highest-panic-density code on the render path.
//!
//! Non-vacuity: the fuzzer controls `value × decimals × frac_digits × unit-len`
//! independently (32 value bytes, raw `decimals`/`frac` bytes reaching the
//! 0/6/18/255 boundaries, and a length-controlled unit/symbol reaching empty
//! and longer-than-fits), so it drives the scaling and column-budget branches,
//! not just the memcpy tails. The contract under test is total: EVERY call must
//! return (never panic / OOB / overflow), matching the "No panics on any input"
//! design rule these helpers are held to.

#![no_main]
use libfuzzer_sys::fuzz_target;

use pqsigner_erc7730::display::primitives as prim;
use pqsigner_tx::erc20::bundle::Erc20Metadata;
use pqsigner_tx_core::eip1559::U256;

const COLS: usize = 16;
/// Cap the synthesised unit/symbol length: well past the 16-col row so the
/// column-budget `checked_sub`/`saturating_sub` paths are hit, without letting
/// libFuzzer waste effort on unbounded strings.
const MAX_UNIT: usize = 40;

fuzz_target!(|data: &[u8]| {
    // 32 value bytes + decimals + frac + flags = 35 control bytes minimum.
    if data.len() < 35 {
        return;
    }
    let mut val = [0u8; 32];
    val.copy_from_slice(&data[..32]);
    let value = U256(val);

    // Raw bytes reach the 0/6/18/255 decimal boundaries the callers hit and the
    // out-of-range extremes they must survive.
    let decimals_u8 = data[32];
    let decimals = u32::from(decimals_u8);
    let frac = u32::from(data[33]);
    let flags = data[34];
    let trim = flags & 0b01 != 0;
    let reject_zero = flags & 0b10 != 0;

    // A chain_id / gas_limit drawn from the same bytes (drives write_chain /
    // write_gas / write_fee_budget_row and the chain/ticker lookups). Built by
    // copy (not `try_into().unwrap()`) so the harness itself can never panic —
    // a harness panic is a false-positive libFuzzer crash.
    let mut s8 = [0u8; 8];
    s8.copy_from_slice(&val[..8]);
    let scalar = u64::from_le_bytes(s8);

    // Two ways to feed the "unit" dimension:
    //  * `unit_str`: a VALID-ASCII string of fuzz-controlled LENGTH (0..MAX_UNIT)
    //    for the `&str`-typed amount writers — exercises the column-budget math
    //    across empty → longer-than-fits without the from_utf8 filter collapsing
    //    every non-ASCII input to "".
    //  * `symbol`: the RAW fuzz bytes for the `&[u8]`-typed token writers (no
    //    UTF-8 constraint — arbitrary + long symbols).
    let tail = data.get(35..).unwrap_or(&[]);
    let symbol = &tail[..tail.len().min(MAX_UNIT)];
    let mut unit_buf = [0u8; MAX_UNIT];
    let unit_len = symbol.len();
    for (i, &b) in symbol.iter().enumerate() {
        // Map to printable ASCII letters/digits so the whole slice is a valid
        // &str whose LENGTH is what varies.
        unit_buf[i] = b'A' + (b % 26);
    }
    let unit_str = core::str::from_utf8(&unit_buf[..unit_len]).unwrap_or("");

    let mut r1 = [b' '; COLS];
    let mut r2 = [b' '; COLS];
    let mut r3 = [b' '; COLS];

    // ── Amount / decimal-scaling writers (the checked_sub budget surface) ──
    let _ = prim::write_amount_two_rows(
        &mut r1, &mut r2, &value, decimals, frac, trim, reject_zero, unit_str,
    );
    let _ = prim::write_amount_single_or_two_rows(
        &mut r1, &mut r2, &value, decimals, frac, trim, reject_zero, unit_str,
    );
    let _ = prim::write_eth_two_rows(&mut r1, &mut r2, &value);
    let _ = prim::write_gwei(&mut r1, &value);
    prim::write_tip_row(&mut r1, &value);
    prim::write_gas(&mut r1, scalar);
    prim::write_fee_budget_row(&mut r1, &value, scalar);

    // ── Chain / ticker naming (index / lookup surface) ──
    prim::write_chain(&mut r1, scalar);
    let _ = prim::chain_name(scalar);
    let _ = prim::native_ticker(scalar);

    // ── Token-amount writers (decimals as u8, raw &[u8] symbol) ──
    let meta = Erc20Metadata {
        chain_id: scalar,
        contract: [0u8; 20],
        decimals: decimals_u8,
        name: b"",
        symbol,
    };
    let _ = prim::write_token_amount_two_rows(&mut r1, &mut r2, &value, &meta);
    let _ = prim::write_cow_leg_amount(&mut r1, &mut r2, &val, decimals_u8, symbol);

    // ── Address truncation (hex placement) ──
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&val[..20]);
    prim::write_addr_full(&mut r1, &mut r2, &mut r3, &addr);
});
