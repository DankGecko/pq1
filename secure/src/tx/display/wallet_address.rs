//! Standalone "Wallet addr #N" verification page for the opt-in
//! show-on-device flag of `CMD_GET_WALLET_ADDRESS` (#472, Trezor
//! receive-address parity).
//!
//! When the companion sets the flag, the handler shows the derived
//! CREATE2 address on the trusted OLED behind a physical confirm BEFORE
//! anything is written to the NS buffer, so a hostile companion cannot
//! silently substitute the address the user thinks they are receiving
//! funds on. The page binds the exact `account_index` being answered —
//! without it a companion could request account N's address while the
//! user believes they are verifying account 0.
//!
//! Layout (16 cols × 4 rows): header row, then the full EIP-55 address
//! across the remaining three rows via the canonical `write_addr_full`
//! primitive — no truncation, no name substitution. The address consumes
//! every row below the header, so there is no separate `L=`/`R=` footer
//! row; the single-page confirm's scroll-to-end gate passes immediately
//! and the #488 page-position indicator overlays the address tail row's
//! free columns at draw time.

use super::primitives;
use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Build the single wallet-address verification page.
///
/// Returns `None` (fail closed — the caller maps this to a refusal) when
/// the account index exceeds the 8-bit wire field or the header cannot
/// be rendered in full, mirroring [`super::value_page`]'s signer-identity
/// page. Never fires for a handler-validated index; the recheck exists so
/// a faulted flag decode cannot paint a truncated/aliased account number.
#[must_use]
pub fn build_wallet_address_page(account_index: u32, address: &[u8; 20]) -> Option<Page> {
    // The wire field is exactly eight bits. Recheck at the display
    // boundary so a faulted flag decode cannot paint a truncated/aliased
    // account number.
    if account_index > 255 {
        return None;
    }
    const PREFIX: &[u8] = b"Wallet addr #";
    let mut page: Page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    let mut digits = [0u8; 3];
    let n = primitives::format_u64(u64::from(account_index), &mut digits)?;
    if PREFIX.len() + n > DISPLAY_COLS {
        return None;
    }
    page[0][..PREFIX.len()].copy_from_slice(PREFIX);
    page[0][PREFIX.len()..PREFIX.len() + n].copy_from_slice(&digits[..n]);
    let [_label, a, b, c] = &mut page;
    primitives::write_addr_full(a, b, c, address);
    Some(page)
}
