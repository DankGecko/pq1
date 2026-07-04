//! Intent banner — page 0 of every ERC-7730 render.
//!
//! Renders the verified `owner` / `contractName` (anti-spoof: ASCII-
//! clean, truncated to 15 chars by the host pipeline) plus the
//! format's intent string ("Sign", "Wrap", "Swap", "Approve", …) into
//! a single page. The first user-visible page must make it
//! unambiguous which descriptor is in play.
//!
//! ## interpolatedIntent
//!
//! Phase 4 v1 omits `{path}` substitution. The seed corpus's intent
//! strings are all static literals ("Send", "Wrap", "Swap on Uniswap",
//! …) so there is nothing to interpolate. When a descriptor that uses
//! interpolatedIntent lands in the registry, Phase 5 wires the path-
//! lookup-and-format substitution machinery; until then, the
//! formatter dispatch loop renders interpolation tokens verbatim
//! (e.g., "Send {amount} {token}" prints with the braces still in).
//! That's intentionally ugly so a user-facing review notices.

use super::super::primitives::write_line;
use crate::ir::{Erc7730Ir, FormatHeader};

use super::formatters::write_line_bytes;
use super::Pages;
use crate::render::RenderErr;

/// Number of pages [`render_intent_banner`] writes. Always allocates
/// at least the intent page; the `erc7730-dev-unattested` Cargo
/// feature adds a preceding "DEV UNATTESTED" warning page.
#[cfg(feature = "erc7730-dev-unattested")]
pub const INTENT_BANNER_PAGES: usize = 2;
#[cfg(not(feature = "erc7730-dev-unattested"))]
pub const INTENT_BANNER_PAGES: usize = 1;

/// Write the intent banner page. Always allocates exactly one page.
///
/// Under the `erc7730-dev-unattested` Cargo feature, allocates an
/// EXTRA preceding page with a "DEV UNATTESTED" warning row so a dev
/// confirming on a bring-up build cannot miss that the host-side
/// attestation gate was relaxed. The feature is mutually exclusive
/// with `mode-production` (compile_error in `nsc/mod.rs`), so a
/// shipped build will never render this row.
pub(super) fn render_intent_banner(
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
) -> Result<(), RenderErr> {
    #[cfg(feature = "erc7730-dev-unattested")]
    {
        let warn = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_line(pages.row_mut(warn, 0), "** DEV BUILD **");
        write_line(pages.row_mut(warn, 1), "Unattested");
        write_line(pages.row_mut(warn, 2), "descriptor");
        write_line(pages.row_mut(warn, 3), "> next");
    }

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;

    // The intent is the descriptor author's single most important string (the
    // flow title). The confirm page + the field pages already establish this is
    // a signing flow, so we DROP the old "Sign: " prefix — which left only 10
    // chars and chopped "Withdraw Collateral from Morpho Market" to
    // "Sign: Withdraw C" — and give the intent up to TWO rows (32 chars).
    //
    // Layout (intent is ASCII-clean, ≤ 254 B by the host pipeline):
    //   short intent (≤ 16): row0 = intent, row1 = owner, row2 = contract name;
    //   long intent  (> 16): rows 0-1 = intent (32 chars, a visible `~` in the
    //                        last cell when it runs past 32), row2 = contract
    //                        name (owner drops — the intent earns the space).
    //   row3 = "> next" nav hint (unchanged, for cross-page consistency).
    const W: usize = 16;
    let intent = format.intent;

    let mut row0 = [b' '; W];
    let r0_take = intent.len().min(W);
    row0[..r0_take].copy_from_slice(&intent[..r0_take]);
    *pages.row_mut(p, 0) = row0;

    if intent.len() > W {
        let mut row1 = [b' '; W];
        let end = intent.len().min(2 * W);
        let take = end - W;
        row1[..take].copy_from_slice(&intent[W..end]);
        // Meaning-bearing truncation marker: the intent runs past what two rows
        // can show, so replace the last cell with `~` (never silently clip).
        if intent.len() > 2 * W {
            row1[W - 1] = b'~';
        }
        *pages.row_mut(p, 1) = row1;
        write_line_bytes(pages.row_mut(p, 2), ir.contract_name);
    } else {
        write_line_bytes(pages.row_mut(p, 1), ir.owner);
        write_line_bytes(pages.row_mut(p, 2), ir.contract_name);
    }
    write_line(pages.row_mut(p, 3), "> next");

    Ok(())
}
