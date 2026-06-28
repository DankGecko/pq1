//! Render a parsed transaction into a fixed-size set of 4-line × 16-col
//! confirmation pages for the secure UI.
//!
//! ## Submodule layout
//!
//! Each renderer has its own file, keyed by the `TxKind` it covers.
//! Adding a new trust level / render flavour means creating a sibling
//! submodule, re-exporting its `render_*_pages` entry point from this
//! `mod.rs`, and teaching [`super::super::erc20::dispatch::TxKind`]
//! (or whichever dispatcher produces the new case) to return it. The
//! command handler in `nsc/cmd_sign.rs` then only needs one extra
//! `TxKind::* => render_*_pages(...)` match arm.
//!
//!   * [`value_transfer`]    — plain ETH transfer, no calldata
//!   * [`erc20_known`]       — decoded ERC20 call, token in the trusted DB
//!   * [`erc20_unknown`]     — decoded ERC20 call, token NOT in the DB
//!   * [`blind_sign`]        — non-empty calldata that doesn't decode
//!
//! [`primitives`] holds every row-level helper (hex formatting, gwei
//! formatting, `write_line`, …) so the renderers read as sequences of
//! declarative "fill row N with X" calls rather than bit-twiddling.

#[cfg(not(test))]
pub mod batch;
mod blind_sign;
mod eip1271;
mod erc20_known;
mod erc20_unknown;
pub mod erc7730;
pub mod erc8213;
pub(super) mod primitives;
#[cfg(not(test))]
mod safe_display;
#[cfg(not(test))]
mod safe_mgmt;
mod slot_rotation;
mod typed_call;
mod value_page;
// `pub(crate)` so the render-only golden harness (`ui::golden`) can drive the
// renderer directly; private otherwise.
pub(crate) mod value_transfer;

pub(crate) use value_page::enforce_paymaster_page;
pub use blind_sign::render_blind_sign_pages;
pub use eip1271::{render_eip1271_personal_sign_pages, render_eip1271_raw32_pages};
pub use erc20_known::render_erc20_known_pages;
pub use erc20_unknown::render_erc20_unknown_pages;
#[cfg(not(test))]
pub use safe_display::{
    multisend_sign_gate, render_safe_exec_pages, render_safe_v1_pages, MultisendGate,
};
pub use slot_rotation::build_slot_rotation_pages;
pub use value_transfer::render_pages;

use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Maximum number of confirmation pages any renderer can produce.
///
/// Must be at least as large as the longest `render_*_pages` output:
///
///   * plain value transfer                 → 6 pages
///   * erc20_known / erc20_unknown          → 8 pages
///     (9 for `transferFrom`: + the "From (debited)" source-account page)
///   * blind_sign (no selector bundle)      → 9 pages
///   * blind_sign (with verified FUNCTION)  → 10 pages
///   * contract_creation                    → 8 pages
///   * cowswap EIP-712 render (see
///     `crate::tx::eip712::cowswap_display`) → 10 pages, +2 gas-fee
///     splice = 12
///   * Safe-wrapped CoW presign (Safe surface with the v3 order as its
///     inner pages) → 3 header + 3 refund + 1 inner-ETH + 1 context
///     banner + 8 body (addr mode) + 1 confirm = 17, +1 native-value
///     splice + 2 gas-fee splice + 2 ERC-8213 fingerprint pages = 22;
///     +1 batch banner = 23; +1 safeTxGas page (when non-zero) = 24
///   * Safe multiSend batch (per record: 1 divider + optional value
///     page + the record's own pages; the CoW record costs 1 banner +
///     6/8 body). NOT statically bounded — the handlers'
///     `multisend_sign_gate` page-budget check refuses any composition
///     whose exact total (same per-kind counts the renderer uses)
///     would exceed `MAX_PAGES`; the Safe-UI approve+presign flow in
///     addr mode with 3 refund pages + batch banner + the +2 gas-fee
///     splice lands on 27 exactly.
///   * typed_call (Phase 2 calldata decode) → up to 14 pages
///     (banner + up to 6 typed args + To + Value + Chain + 2 fee
///     pages + Nonce; declines past `MAX_TYPED_ARGS_RENDERED = 6`)
///   * batch sign per-tx wrapper (see
///     `crate::tx::display::batch::wrap_pages_with_batch_banner`) →
///     same as the wrapped renderer + 1 banner page = up to 15
///   * EIP-1271 PersonalSign render →
///     5 fixed pages (banner / chain / account+slot / signer addr /
///     final confirm) + `ceil(MAX_OFFCHAIN_PERSONAL_SIGN_LEN / 48)`
///     message pages = up to 5 + ceil(700 / 48) = 5 + 15 = 20.
///
/// Two dispatcher-level page splices add to the per-renderer counts above
/// for the flows that don't emit them inline (applied in
/// [`pick_sign_pages`] after the chosen renderer returns):
///
///   * native-ETH value page (+1) when the outer UserOp `value != 0`
///     (`value_page::enforce_native_value_page`).
///   * gas/fee pages (+2: "Max fee" + "Worst-case") for the Safe / CoW /
///     v1-ZK surfaces, which — unlike value_transfer / erc20 / typed_call
///     / blind_sign / erc7730 — do not show gas inline
///     (`value_page::enforce_gas_pages`; audit 2026-06-19).
///
/// Bumping this costs `4 × 16 = 64` extra stack bytes per page (×2
/// transiently while the batch banner wrap holds two `Pages`), so grow
/// it deliberately and not speculatively. 22 → 24 accompanied the
/// multiSend clear-sign feature; 24 → 27 accompanied the Safe gas-refund
/// magnitude page (+1 refund page: the worst-case
/// (CEILING+baseGas)*gasPrice total) and the Safe/CoW gas/fee splice (+2)
/// so the worst realistic flow — the Safe-UI approve+presign multiSend
/// (AddrHex legs + 3 refund pages + record values + batch banner + gas +
/// ERC-8213 fingerprints) — landed on 27. 27 → 28 accompanied the Safe
/// `safeTxGas` page (+1, conditional on `safeTxGas != 0`; audit 2026-06-26),
/// so that same worst-case flow carrying a non-zero `safeTxGas` lands on 28
/// exactly without truncation. `multisend_sign_gate` counts the page too, so
/// the budget still fails closed (refuse, never truncate).
pub const MAX_PAGES: usize = 28;

/// A buffer of up to [`MAX_PAGES`] pre-rendered confirmation pages.
///
/// Owned-by-value: every renderer returns a fresh `Pages` on the stack
/// and the caller hands `pages.as_slice()` to
/// [`crate::ui::confirm::confirm`] for the navigation loop. The buffer
/// is always allocated for the full [`MAX_PAGES`] so that only `len`
/// changes between renderers — callers must never index past `len`.
pub struct Pages {
    /// The full `MAX_PAGES`-sized page buffer. Visible only to sibling
    /// submodules under `display::` so the per-`TxKind` renderers can
    /// write directly into their own slots without going through
    /// `row_mut`/`page_mut` for every line — external callers must use
    /// [`Pages::as_slice`] instead.
    pub(super) buf: [Page; MAX_PAGES],
    pub(super) len: usize,
}

impl Pages {
    /// View the visible pages (indices `0..len`) as a slice. This is
    /// what `confirm()` consumes.
    pub fn as_slice(&self) -> &[Page] {
        &self.buf[..self.len]
    }

    /// Construct a page bundle with exactly `len` visible pages,
    /// pre-filled with ASCII space. Used both internally by the
    /// EIP-1559 renderers in this directory and externally by the
    /// CowSwap EIP-712 renderer in
    /// `crate::tx::eip712::cowswap_display`.
    pub fn empty_with_len(len: usize) -> Self {
        assert!(len <= MAX_PAGES, "Pages::empty_with_len: len > MAX_PAGES");
        Pages {
            buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; MAX_PAGES],
            len,
        }
    }

    /// Mutable access to a single row within a single page. Bounds-
    /// checked; panics on out-of-range indices (which would indicate
    /// a firmware bug since both come from compile-time constants).
    pub fn row_mut(&mut self, page: usize, row: usize) -> &mut [u8; DISPLAY_COLS] {
        assert!(page < self.len);
        assert!(row < DISPLAY_ROWS);
        &mut self.buf[page][row]
    }

    /// Mutable access to the full row array of one page. Used by
    /// renderers that need to mutate two rows of the same page
    /// simultaneously (via `split_at_mut`), which the row-at-a-time
    /// `row_mut` helper above can't express without tripping the
    /// borrow checker.
    pub fn page_mut(&mut self, page: usize) -> &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS] {
        assert!(page < self.len);
        &mut self.buf[page]
    }

    /// Renderer-local shortcut for `empty_with_len`. Kept private so
    /// the sibling submodules can `use super::Pages;` and call
    /// `Pages::with_len(...)`.
    pub(super) fn with_len(len: usize) -> Self {
        Self::empty_with_len(len)
    }

    /// Bump `len` by one and return the index of the newly-visible page.
    /// Returns `Err(())` when the buffer is already full; renderers map
    /// that to `RenderErr::PageBudget` and fall through to a less rich
    /// rendering ladder rung. The returned page is pre-cleared to ASCII
    /// space (matches every other allocation path).
    pub(super) fn push_blank(&mut self) -> Result<usize, ()> {
        if self.len >= MAX_PAGES {
            return Err(());
        }
        // The full MAX_PAGES buffer was zero-cleared at construction;
        // older renderers that overran past `len` via `Pages::empty()`
        // and then bumped it leave stale bytes behind. Re-clear the slot
        // here so dynamic-push renderers don't inherit prior content.
        self.buf[self.len] = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
        let idx = self.len;
        self.len += 1;
        Ok(idx)
    }
}

/// Pick the right renderer for a CMD_SIGN_USEROP trusted-UI confirm.
///
/// Centralises the priority ladder — the handler stays a pure
/// orchestrator and the "which display wins when multiple trailers
/// verify" decision lives in one place:
///
///   1. v3 CoW EIP-712 (full 8-page GPv2Order breakdown from the
///      circuit-bound canonical + readable).
///   2. v1 ZK clear-sign (circuit-attested readable string + EIP-1559
///      summary pages).
///   3. Safe v1 inner-tx render (verified canonical SafeTx).
///   4. ERC-7730 descriptor (verified against the firmware-pinned
///      `ERC7730_DESCRIPTORS_ROOT`; binding cross-checked against
///      `(chain_id, to)`).
///   5. Plain value transfer (empty inner calldata).
///   6. ERC-20 with verified metadata (token name/symbol/decimals).
///   7. ERC-20 shape-only (unverified token — bare hex decode).
///   8. Typed-call selector + verified ABI walk.
///   9. Blind-sign (calldata that doesn't decode as ERC-20 / typed).
///
/// Ordering is load-bearing. In particular (1) beats (2) so a CoW
/// setPreSignature UserOp that also happens to satisfy the v1 circuit
/// renders the 8-page order, not the weaker "Pre-sign CowSwap order"
/// string. The handler's downgrade-mitigation gate enforces this
/// separately at refuse-to-sign level. (3) is above (4) so a Safe
/// `execTransaction` carrying an ERC-7730 descriptor for an inner
/// call still renders the outer Safe banner first — the descriptor
/// would be for the inner call, which the Safe renderer dispatches
/// through its own inner-tx ladder.
///
/// Combination rule: when BOTH a v3 order and a Safe context verified
/// (Safe-wrapped CoW presign — the handler bound the order to the
/// SafeTx inner calldata with uid owner = the Safe), the render routes
/// through the Safe surface with the order as its inner pages. A bare
/// CoW render would hide the SafeTx's signed refund parameters, which
/// are a drain channel (see `safe_display.rs`).
///
/// # Refusal (fail-closed)
///
/// Returns `Err(())` when the dispatcher-level native-ETH value page is
/// mandatory (`tx.value != 0`) but cannot be spliced because the chosen
/// renderer already filled `MAX_PAGES`. Callers MUST map `Err(())` to a
/// refuse-to-sign — releasing a signature whose native `value` was never
/// displayed is exactly the C-1 ETH-drain class this gate exists to close.
#[cfg(not(test))]
#[allow(clippy::too_many_arguments)]
pub fn pick_sign_pages(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    v1: Option<&crate::zk::VerifiedClearSignV1>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
) -> Result<Pages, ()> {
    // `pick_sign_pages_inner` returns `Err(())` when a Safe-surface render
    // refuses (page budget exceeded / page-accounting self-check failed);
    // propagate it so the handler maps it to a refuse-to-sign rather than
    // showing a buffer with a hidden signed value (audit 2026-06-27).
    let mut pages = pick_sign_pages_inner(
        tx, inner_data, v3, v1, safe_v1, safe_exec, erc7730, erc20, selector, resolver,
    )?;
    // Dispatcher-level WYSIWYS invariant (audit C-1 / H-2 / M-8; hardened
    // 2026-06-18).
    //
    // The outer UserOp `value` is signed verbatim into
    // `executeWithOffchainCount(ownerIndex, count, target, value, data)`
    // and forwarded on chain via `target.call{value: value}(data)`, but
    // several renderers surface only token / inner-tx semantics and never
    // the native ETH. Rather than trust each renderer to opt in, EVERY
    // sign confirm funnels through here: when `value` is non-zero we splice
    // in a dedicated, loud value page right after the renderer's banner so
    // the user always sees the ETH the signature commits to.
    //
    // `enforce_native_value_page` is now FI-hardened (the skip-on-zero
    // decision is sentinel-gated, not a bare `if value.is_zero()`) and
    // FAILS CLOSED: if `value != 0` and the loud page cannot be spliced
    // (the renderer already filled `MAX_PAGES`), it returns `Err(())` and
    // we propagate it so the caller REFUSES to sign rather than release a
    // signature over ETH the user never saw. The helper lives in
    // `value_page.rs` so the host-test scaffold can mount and exercise the
    // real body (this dispatcher is `cfg(not(test))`).
    value_page::enforce_native_value_page(&mut pages, &tx.value)?;

    // Dispatcher-level WYSIWYS invariant (audit 2026-06-19 — gas/fee pages).
    //
    // The five signed EntryPoint v0.6 fee fields (callGasLimit,
    // verificationGasLimit, preVerificationGas, maxFeePerGas,
    // maxPriorityFeePerGas) are committed to by the UserOp signature, and the
    // wallet pays the resulting EntryPoint prefund out of its own native ETH.
    // Most renderers emit the two standard gas pages inline (the same
    // "Max fee" / "Worst-case" pair value_transfer shows), but the Safe, CoW
    // and v1-ZK surfaces historically did NOT — so a fee-bomb UserOp (huge
    // maxFeePerGas / gas limits, no paymaster) drained the wallet's ETH as
    // gas behind a benign Safe/CoW confirm with no fee page on screen.
    //
    // Rather than trust each of those renderers to opt in, splice the same
    // two pages here for exactly the flows that lack them. `needs_gas`
    // mirrors the branch precedence in `pick_sign_pages_inner`: any
    // v3 / v1 / safe trailer routes to a gas-less renderer; every other
    // outcome (erc7730 / value / erc20 / typed-call / blind-sign) already
    // shows gas, so splicing there would DOUBLE the pages. Fails CLOSED on a
    // full buffer (same refuse-to-sign contract as the value page).
    let needs_gas =
        v3.is_some() || v1.is_some() || safe_v1.is_some() || safe_exec.is_some();
    if needs_gas {
        value_page::enforce_gas_pages(&mut pages, tx)?;
    }
    Ok(pages)
}

#[cfg(not(test))]
#[allow(clippy::too_many_arguments)]
fn pick_sign_pages_inner(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    v1: Option<&crate::zk::VerifiedClearSignV1>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
) -> Result<Pages, ()> {
    if let Some(v3) = v3 {
        // Safe-wrapped CoW presign: when the v3 order was verified
        // against a Safe flow's inner calldata (the handler bound uid
        // owner == the Safe via `safe::cow_binding`), the Safe surface
        // must stay visible — its banner, address, nonce and above all
        // the gas-refund pages are signed facts a bare CoW render would
        // hide (the refund channel is a full-balance drain vector, see
        // `safe_display.rs`). The order renders as the Safe's inner-tx
        // pages instead. ERC-20 metadata can apply to a multiSend
        // RECORD (the Safe-UI flow batches `approve(sellToken)` next to
        // the presign), so the address-matched bundle is threaded
        // through; the single-call presign arm ignores it.
        if let Some(safe) = safe_v1 {
            let inner_meta = safe_inner_meta(erc20, &safe_v1_inner_to(safe), safe.raw_data);
            return render_safe_v1_pages(safe, Some(v3), inner_meta, resolver);
        }
        if let Some(exec) = safe_exec {
            let inner_meta = safe_inner_meta(erc20, &exec.decoded.to, exec.decoded.data);
            return render_safe_exec_pages(exec, Some(v3), inner_meta, resolver);
        }
        return Ok(crate::tx::eip712::cowswap_display::render_cowswap_pages(
            &v3.canonical,
            &v3.sell,
            &v3.buy,
        ));
    }
    if let Some(v1) = v1 {
        return Ok(crate::zk::render_clear_sign_pages(tx, &v1.readable, resolver));
    }
    if let Some(safe) = safe_v1 {
        // For Safe inner-tx ERC-20 rendering, only apply the outer
        // ERC-20 metadata bundle when its contract address matches the
        // inner-tx target — a Safe call carrying USDC metadata is
        // useful only if the inner `to` is in fact USDC — or, for a
        // multiSend batch, when one of the packed records targets the
        // token (the renderer re-matches per record before applying).
        let inner_meta = safe_inner_meta(erc20, &safe_v1_inner_to(safe), safe.raw_data);
        return render_safe_v1_pages(safe, None, inner_meta, resolver);
    }
    if let Some(exec) = safe_exec {
        // Same address-match rule for the exec path, multiSend records
        // included. This pairs with the approveHash branch above so
        // both Safe surfaces handle ERC-20 attribution consistently.
        let inner_meta = safe_inner_meta(erc20, &exec.decoded.to, exec.decoded.data);
        return render_safe_exec_pages(exec, None, inner_meta, resolver);
    }
    if let Some(d) = erc7730 {
        match erc7730::render_erc7730_pages(tx, inner_data, d, erc20, resolver) {
            Ok(pages) => return Ok(pages),
            Err(crate::tx::erc7730_render::RenderErr::Reject(msg)) => {
                crate::ui::show_status("Sign", msg);
                // Fall through to the next ladder rung so the user
                // still sees the transaction in a less-rich form
                // (typed-call selector / blind-sign / ERC-20). The
                // banner above gives them the reason.
            }
            Err(_) => {
                // NoFormat / PageBudget — fall through silently.
            }
        }
    }
    if inner_data.is_empty() {
        return Ok(render_pages(tx, resolver));
    }
    match crate::erc20::calldata::parse_erc20_calldata(inner_data) {
        Some(call) => {
            // WYSIWYS per-flow address-match gate (audit 2026-06-28 —
            // `v1_ms` metadata mis-attribution).
            //
            // This is the DIRECT ERC-20 branch: control only reaches here
            // when NO Safe / CoW / v1 context was verified (every Safe
            // surface returned above through its own `safe_inner_meta`
            // re-match). On a direct call the wallet itself is `msg.sender`
            // and `tx.to` IS the token contract, so the ONLY legitimate
            // attribution is `meta.contract == tx.to`.
            //
            // The handler-side acceptance gate (`verified_meta`) also
            // admits a bundle whose contract sits inside a Safe-flow
            // multiSend record (`exec_ms` / `v1_ms` / `safe_exec_inner_*`).
            // Those disjuncts are evaluated from companion trailer bytes
            // and are NOT valid on the direct path — a transfer to token Y
            // must never render with token T's name/symbol/decimals just
            // because an (unrelated, possibly non-verifying) Safe trailer
            // referenced T. Re-check the address here and fall back to the
            // raw `erc20_unknown` render on any mismatch. This is the
            // per-flow gate the handler comments rely on; previously it
            // existed only for the Safe surfaces.
            let matched = erc20
                .filter(|meta| value_page::direct_erc20_meta_matches(&meta.contract, tx.to.as_ref()));
            Ok(match matched {
                Some(meta) => render_erc20_known_pages(tx, &call, meta, resolver),
                None => render_erc20_unknown_pages(tx, &call, resolver),
            })
        }
        // The verified selector → text-sig mapping (if any) is only
        // consulted when nothing else has decoded the calldata. Phase 2
        // first tries to ABI-decode the calldata against the verified
        // type list; on any parse / shape failure (or any type the
        // first cut declines) we fall through to the Phase 1 BLIND
        // SIGN flow, which itself surfaces the FUNCTION page above
        // the warning header.
        None => {
            if let Some(meta) = selector {
                if let Some(pages) =
                    typed_call::try_render_typed_call(tx, inner_data, meta, resolver)
                {
                    return Ok(pages);
                }
            }
            Ok(render_blind_sign_pages(tx, inner_data, selector, resolver))
        }
    }
}

/// Inner `to` decoded from a verified `safe_v1` canonical.
#[cfg(not(test))]
fn safe_v1_inner_to(safe: &crate::tx::eip712::safe::VerifiedSafeV1<'_>) -> [u8; 20] {
    let mut t = [0u8; 20];
    t.copy_from_slice(
        &safe.canonical[sphincs_tz_shared::SAFE_OFF_TO..sphincs_tz_shared::SAFE_OFF_TO + 20],
    );
    t
}

/// Address-match filter for ERC-20 metadata on the Safe surfaces: the
/// bundle applies when its contract is the inner `to`, or — for a
/// multiSend batch — when one of the packed records targets it.
/// (`any_record_to_matches` returns false for anything that is not a
/// well-formed multiSend.) The renderer still re-matches per record
/// before applying the metadata, so this is routing, not the trust
/// gate.
#[cfg(not(test))]
fn safe_inner_meta<'m>(
    erc20: Option<&'m crate::erc20::bundle::Erc20Metadata<'m>>,
    inner_to: &[u8; 20],
    raw_data: &[u8],
) -> Option<&'m crate::erc20::bundle::Erc20Metadata<'m>> {
    erc20.filter(|m| {
        m.contract == *inner_to
            || crate::tx::eip712::safe::multi_send::any_record_to_matches(
                raw_data,
                &m.contract,
            )
    })
}
