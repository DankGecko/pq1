//! Render an `Eip1559Tx` into a fixed set of 4-line × 16-col confirmation
//! pages for the secure UI.
//!
//! Layout (5 pages):
//!
//! ```text
//! Page 1: Confirm Tx?     Page 2: To:           Page 3: Value:
//!         Chain: <n>             0x1234abcd...          1.234567 ETH
//!         <chain name>           ...efgh5678            (gas: <limit>)
//!         > next                 > next                 > next
//!
//! Page 4: Max fee:        Page 5: Data: <n>B
//!         <gwei> gwei            Nonce: <n>
//!         Tip: <gwei>            L=Cancel
//!         > next                 R=Confirm
//! ```

use super::eip1559::{Eip1559Tx, U256};
use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

const NUM_PAGES: usize = 5;
pub const MAX_PAGES: usize = NUM_PAGES;

pub struct Pages {
    buf: [Page; NUM_PAGES],
    len: usize,
}

impl Pages {
    pub fn as_slice(&self) -> &[Page] {
        &self.buf[..self.len]
    }
}

pub fn render_pages(tx: &Eip1559Tx) -> Pages {
    let mut pages = Pages {
        buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; NUM_PAGES],
        len: NUM_PAGES,
    };

    // Page 0: Confirm Tx? + chain
    write_line(&mut pages.buf[0][0], "Confirm Tx?");
    write_chain(&mut pages.buf[0][1], tx.chain_id);
    write_line(&mut pages.buf[0][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: To
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    } else {
        write_line(&mut pages.buf[1][1], "(create)");
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: Value
    write_line(&mut pages.buf[2][0], "Value:");
    write_eth(&mut pages.buf[2][1], &tx.value);
    write_gas(&mut pages.buf[2][2], tx.gas_limit);
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: Fees
    write_line(&mut pages.buf[3][0], "Max fee:");
    write_gwei(&mut pages.buf[3][1], &tx.max_fee_per_gas);
    {
        let mut row2 = [b' '; DISPLAY_COLS];
        let prefix = b"Tip: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = tx.max_priority_fee_per_gas.format_decimal(9, 3, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        let suffix = b" gwei";
        for &b in suffix {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        pages.buf[3][2] = row2;
    }
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: Data + nonce + confirm/cancel
    {
        let mut row0 = [b' '; DISPLAY_COLS];
        let prefix = b"Data: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = format_u64(tx.data_len as u64, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        let suffix = b" B";
        for &b in suffix {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        pages.buf[4][0] = row0;
    }
    {
        let mut row1 = [b' '; DISPLAY_COLS];
        let prefix = b"Nonce: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row1[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = format_u64(tx.nonce, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row1[pos] = b;
                pos += 1;
            }
        }
        pages.buf[4][1] = row1;
    }
    write_line(&mut pages.buf[4][2], "L=Cancel");
    write_line(&mut pages.buf[4][3], "R=Confirm");

    pages
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_line(row: &mut [u8; DISPLAY_COLS], text: &str) {
    *row = [b' '; DISPLAY_COLS];
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

fn write_chain(row: &mut [u8; DISPLAY_COLS], chain_id: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Chain: ";
    row[..prefix.len()].copy_from_slice(prefix);
    let mut tmp = [0u8; 16];
    let n = format_u64(chain_id, &mut tmp);
    let off = prefix.len();
    let copy = core::cmp::min(n, DISPLAY_COLS - off);
    row[off..off + copy].copy_from_slice(&tmp[..copy]);
}

fn chain_name(chain_id: u64) -> &'static str {
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

fn write_addr(row1: &mut [u8; DISPLAY_COLS], row2: &mut [u8; DISPLAY_COLS], addr: &[u8; 20]) {
    // Row 1: 0x + first 7 hex bytes (14 chars) = 16 chars total
    // Row 2: last 7 hex bytes + .. + last byte = also 16 chars
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        row1[2 + i * 2] = hex_nibble(addr[i] >> 4);
        row1[2 + i * 2 + 1] = hex_nibble(addr[i] & 0x0f);
    }
    // Row 2: last 8 bytes
    for i in 0..8 {
        let b = addr[12 + i];
        row2[i * 2] = hex_nibble(b >> 4);
        row2[i * 2 + 1] = hex_nibble(b & 0x0f);
    }
}

fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn write_eth(row: &mut [u8; DISPLAY_COLS], value: &U256) {
    *row = [b' '; DISPLAY_COLS];
    let mut tmp = [0u8; 16];
    let n = value.format_decimal(18, 6, &mut tmp);
    let copy = core::cmp::min(n, DISPLAY_COLS - 4);
    row[..copy].copy_from_slice(&tmp[..copy]);
    if copy + 4 <= DISPLAY_COLS {
        row[copy] = b' ';
        row[copy + 1] = b'E';
        row[copy + 2] = b'T';
        row[copy + 3] = b'H';
    }
}

fn write_gwei(row: &mut [u8; DISPLAY_COLS], value: &U256) {
    *row = [b' '; DISPLAY_COLS];
    let mut tmp = [0u8; 16];
    let n = value.format_decimal(9, 3, &mut tmp);
    let copy = core::cmp::min(n, DISPLAY_COLS - 5);
    row[..copy].copy_from_slice(&tmp[..copy]);
    if copy + 5 <= DISPLAY_COLS {
        row[copy] = b' ';
        row[copy + 1] = b'g';
        row[copy + 2] = b'w';
        row[copy + 3] = b'e';
        row[copy + 4] = b'i';
    }
}

fn write_gas(row: &mut [u8; DISPLAY_COLS], gas: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"(gas: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let mut tmp = [0u8; 16];
    let n = format_u64(gas, &mut tmp);
    for &b in &tmp[..n] {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    if pos < DISPLAY_COLS {
        row[pos] = b')';
    }
}

pub fn format_u64(mut n: u64, out: &mut [u8]) -> usize {
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
