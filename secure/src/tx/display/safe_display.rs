//! Trust level — Safe-multisig `approveHash` clear-sign.
//!
//! Rendered when the gateway receives a `safe_v1` trailer that has
//! passed every cross-check in
//! `crate::tx::eip712::safe::verify_and_bind_trailer`. At that point
//! the firmware has cryptographically-bound `(canonical SafeTx,
//! raw_data)` so the renderer can show the inner transaction's
//! semantic content alongside the Safe-level metadata that distinguish
//! "approving a Safe tx" from "calling something directly".
//!
//! Page layout (variable, capped at [`super::MAX_PAGES`]):
//!
//! ```text
//!   0: "Approve Safe TX"     1: "Safe:"             2: "SafeTx Nonce: N"
//!      Chain: <n>                <addr full>            Op: Call
//!      <chain name>              <addr full>            <inner kind hint>
//!      > next                    <addr full>            > next
//!
//!   refund (2 pages, only when a gas refund is configured — i.e. any of
//!          gasPrice / gasToken / refundReceiver is non-zero):
//!          A: "! GAS REFUND" + "Safe pays in:" + token (addr or "ETH")
//!          B: "Refund to:"   + refundReceiver (full addr, or "tx.origin")
//!          Surfaces the Safe gas-refund drain channel — a *token* refund
//!          has no on-chain gasPrice cap.
//!
//!   inner-ETH (1 page, only when SafeTx `value != 0` and the inner kind
//!          is not PlainEth/EmptyCall): "Safe sends ETH:" + amount. The
//!          PlainEth branch shows the value inline instead.
//!
//!   N..M: inner-tx pages (one of):
//!         * plain ETH transfer  (2 pages: "Inner to" + "Send ETH")
//!         * ERC-20 known        (4 pages: header + recipient + amount + contract)
//!         * ERC-20 unknown      (4 pages: same shape, no symbol)
//!         * Safe-mgmt           (1..3 pages, per-op intent banner;
//!                                see [`super::safe_mgmt`]). Fires
//!                                when `canonical.to == safe_address`
//!                                and selector matches one of the
//!                                eight Safe v1.3.0+ singleton ops.
//!         * CoW presign         (7 or 9 pages: "CowSwap order / for
//!                                this Safe" context banner + the v3
//!                                order body from
//!                                `crate::tx::eip712::cowswap_display`.
//!                                Fires only when the handler verified
//!                                a CoW v3 trailer against the SafeTx
//!                                inner calldata with owner = the Safe;
//!                                see `safe::cow_binding`).
//!         * multiSend batch     (per record: 1 divider page "MSend rec
//!                                i/N" + target, an explicit value page
//!                                when the record forwards ETH a kind
//!                                doesn't show inline, then the
//!                                record's own pages through the SAME
//!                                per-kind arms above — incl. the CoW
//!                                presign body on the v3-bound record.
//!                                Fires only for an allowlisted
//!                                `MultiSendCallOnly` DELEGATECALL; see
//!                                `safe::multi_send`).
//!         * unknown Safe op     (3 pages: "Unknown Safe op" + Inner-to + selector/hash)
//!         * blind-sign          (3 pages: "Unknown call" + "Inner to" + selector/hash)
//!
//!   last: "L=Cancel"
//!         "R=Confirm"
//! ```
//!
//! The `Op:` row is honest: `Op: Call` for operation 0, `Op: MultiSend`
//! for the allowlisted DELEGATECALL batch (the only operation-1 shape
//! the verifiers in `crate::tx::eip712::safe::{verify, exec_decode}`
//! let through), and a loud `! Op: DELEGATE` for the impossible-state
//! remainder, which renders as blind-sign.

use super::primitives::{
    chain_name, format_u64, write_addr_full_or_name, write_calldata_hash_rows, write_chain,
    write_data_len_row, write_erc20_header, write_eth_two_rows, write_line, write_selector_row,
    write_token_amount_two_rows, write_token_name, AmountFit,
};
use super::safe_mgmt::{
    classify_safe_mgmt, page_count as safe_mgmt_page_count, render_safe_mgmt_pages, SafeMgmtOp,
};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, parse_erc20_calldata, Erc20Call};
use crate::names::NameResolver;
use crate::tx::eip1559::U256;
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::cowswap_display::{
    append_order_body_pages, order_body_page_count, order_kind_label,
};
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::{
    self, classify_record_kind, record_needs_value_page, MsRecordIter, MsRecordKind,
};
use crate::tx::eip712::safe::{
    decode_canonical, safe_inner_is_cow_presign, SafeTx, VerifiedSafeExec, VerifiedSafeV1,
};
use crate::ui::DISPLAY_COLS;
use sphincs_tz_shared::GPV2_VAULT_RELAYER_ADDRESS;

/// Number of fixed Safe-level header pages rendered before the inner-tx
/// pages and the trailing confirm page.
const SAFE_HEADER_PAGES: usize = 3;

/// Which Safe flow the render is being driven from. Used to pick the
/// banner string on page 0 and decide what to show on the metadata page
/// (approveHash carries a SafeTx nonce in the canonical; execTransaction
/// only sees the SafeTx nonce on-chain at execution time).
#[derive(Copy, Clone)]
enum SafeRenderFlavour {
    /// `approveHash(bytes32)` — the firmware re-derived the SafeTx hash
    /// from the trailer's canonical and bound it to the calldata
    /// argument. The user is approving the hash now; the Safe will
    /// execute it later once threshold approvals collect.
    ApproveHash { nonce: [u8; 32] },
    /// `execTransaction(...)` — the wallet is the EOA-equivalent
    /// triggering the Safe to execute. SafeTx fields come from the
    /// calldata directly (no separate trailer). Nonce is determined
    /// by the Safe's storage at execution time and is not visible
    /// to the firmware. Refund fields (gasPrice / gasToken /
    /// refundReceiver) ride in [`SafeRenderInput`] for both flavours,
    /// so the renderer surfaces them identically regardless of flow.
    ExecTransaction,
}

/// Normalised input to the shared Safe rendering body. Approve-hash and
/// exec-transaction both reduce to the same display surface: chain, Safe
/// address, op + inner-kind hint, inner-tx pages, confirm.
struct SafeRenderInput<'a> {
    flavour: SafeRenderFlavour,
    chain_id: u64,
    safe_address: [u8; 20],
    to: [u8; 20],
    /// SafeTx operation byte. `0` = Call. `1` = DelegateCall — only
    /// reachable for an allowlisted MultiSendCallOnly batch (the
    /// verifiers' operation gates refuse everything else); rendered as
    /// `Op: MultiSend` with per-record pages. Anything else on this
    /// field is an impossible state rendered as a loud `! Op: DELEGATE`.
    operation: u8,
    value: [u8; 32],
    raw_data: &'a [u8],
    /// keccak256(raw_data). For approveHash this comes from the
    /// canonical (already byte-equal to keccak256(raw_data) by the
    /// verifier's bind step); for exec we compute it here so the
    /// blind-sign branches can still surface it.
    data_hash: [u8; 32],
    /// SafeTx refund parameters. All three are folded into the signed
    /// `safeTxHash` (EIP-712 struct hash) but are NOT otherwise visible
    /// in the inner-tx semantics, so the renderer must surface them
    /// explicitly: when `gasPrice > 0` the Safe pays
    /// `(gasUsed + baseGas) * gasPrice` of `gasToken` (or ETH when
    /// `gasToken == 0`) to `refundReceiver` (or `tx.origin` when
    /// `refundReceiver == 0`). A *token* refund has no on-chain cap on
    /// `gasPrice`, so an attacker who hides these fields can drain the
    /// Safe's entire balance of a chosen ERC-20 behind a benign-looking
    /// inner call. See `docs/companion/safe-multisig-clear-sign.md`.
    gas_price: [u8; 32],
    gas_token: [u8; 20],
    refund_receiver: [u8; 20],
}

/// Render a verified `safe_v1` trailer.
///
/// `tx_chain_id` is the outer UserOp's chain id — already cross-checked
/// against `canonical.chain_id` by the verifier, so passing either is
/// equivalent. We use the canonical's value for display-correctness.
/// `erc20` is the optional Merkle-verified ERC-20 metadata bundle from
/// the *outer* trailer chain; we apply it to the inner-tx's `to` only
/// when the addresses match (a Safe inner call to USDC carries the
/// metadata for USDC, not for the Safe contract).
/// `cow` is the optional CoW v3 order the handler verified against this
/// SafeTx's inner calldata (owner = the Safe) — when present, the
/// inner-tx pages become the full order intent instead of blind-sign.
pub fn render_safe_v1_pages(
    safe: &VerifiedSafeV1<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Pages {
    // The verifier already proved the canonical decodes; mirror that
    // success here without re-erroring (a fresh `Err` would only fire
    // if the trailer parser was bypassed, which is impossible).
    let tx = decode_canonical(&safe.canonical).unwrap_or(SafeTx {
        chain_id: 0,
        safe_address: [0u8; 20],
        to: [0u8; 20],
        value: [0u8; 32],
        data_hash: [0u8; 32],
        operation: 0,
        safe_tx_gas: [0u8; 32],
        base_gas: [0u8; 32],
        gas_price: [0u8; 32],
        gas_token: [0u8; 20],
        refund_receiver: [0u8; 20],
        nonce: [0u8; 32],
    });

    let input = SafeRenderInput {
        flavour: SafeRenderFlavour::ApproveHash { nonce: tx.nonce },
        chain_id: tx.chain_id,
        safe_address: tx.safe_address,
        to: tx.to,
        operation: tx.operation,
        value: tx.value,
        raw_data: safe.raw_data,
        data_hash: tx.data_hash,
        gas_price: tx.gas_price,
        gas_token: tx.gas_token,
        refund_receiver: tx.refund_receiver,
    };
    render_safe_pages_inner(&input, cow, erc20, resolver)
}

/// Render a verified `execTransaction(...)` UserOp.
///
/// Mirrors `render_safe_v1_pages` but for the direct-execution flow:
/// the wallet is acting as the EOA that calls `execTransaction` on a
/// Safe, carrying co-signers' approvals in the function's `signatures`
/// argument. SafeTx fields come from the decoded calldata; the SafeTx
/// nonce is *not* visible (the Safe reads it from storage at execution
/// time), so the metadata page surfaces an "(execute now)" row in place
/// of the approve-hash nonce.
///
/// `erc20` follows the same address-match rule as the approveHash path:
/// we apply outer-trailer metadata only when its contract address
/// matches the decoded inner `to`. The decoded `signatures` blob is
/// left intentionally undisplayed — it is multi-owner content and
/// surfacing it would only add noise to the on-device confirm.
/// `cow` mirrors [`render_safe_v1_pages`]: a CoW v3 order verified
/// against the decoded SafeTx inner calldata with owner = the Safe.
pub fn render_safe_exec_pages(
    exec: &VerifiedSafeExec<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Pages {
    let d = &exec.decoded;
    // The verifier proved `operation` is either 0 (Call) or an
    // allowlisted MultiSendCallOnly DELEGATECALL; the Op row + record
    // routing key off the byte. Compute the data hash for the
    // blind-sign / unknown-Safe-op branches that show it.
    let data_hash = keccak(d.data);
    let input = SafeRenderInput {
        flavour: SafeRenderFlavour::ExecTransaction,
        chain_id: exec.chain_id,
        safe_address: exec.safe_address,
        to: d.to,
        operation: d.operation,
        value: d.value,
        raw_data: d.data,
        data_hash,
        gas_price: d.gas_price,
        gas_token: d.gas_token,
        refund_receiver: d.refund_receiver,
    };
    render_safe_pages_inner(&input, cow, erc20, resolver)
}

/// Shared rendering body for both approveHash and execTransaction.
fn render_safe_pages_inner(
    input: &SafeRenderInput<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Pages {
    // Local field aliases to keep the existing rendering body readable.
    // We deliberately preserve the names the previous monolithic
    // function used (`tx.to`, `safe.raw_data`, …) so the diff stays
    // small.
    let tx = SafeTxFields {
        chain_id: input.chain_id,
        safe_address: input.safe_address,
        to: input.to,
        value: input.value,
        data_hash: input.data_hash,
    };
    let safe = SafeRawData {
        raw_data: input.raw_data,
    };

    // Refund-risk pages are added for BOTH approveHash and
    // execTransaction whenever the SafeTx configures a gas refund.
    // Safe pays `(gasUsed + baseGas) * gasPrice` of `gasToken` (ETH when
    // `gasToken == 0`) to `refundReceiver` (`tx.origin` when zero). The
    // on-chain trigger is `gasPrice > 0`; a *token* refund has no
    // gasPrice cap, so a hidden refund is a full-ERC-20-balance drain
    // channel dressed up behind a benign inner call. We surface it
    // whenever any refund field is set — a non-zero gasToken /
    // refundReceiver with gasPrice 0 is anomalous enough to show too.
    // Two pages: banner + gasToken, then the full refundReceiver address.
    let refund_active = input.gas_price.iter().any(|&b| b != 0)
        || input.gas_token.iter().any(|&b| b != 0)
        || input.refund_receiver.iter().any(|&b| b != 0);

    // Decide inner-tx flavor up-front so we can size the page count.
    // ERC-20 calldata renders as `Erc20Known` only when metadata is
    // *both* present and address-matches the inner `to`; otherwise we
    // fall back to `Erc20Unknown` (still readable shape, just no
    // symbol/decimals).
    //
    // Safe self-calls (`tx.to == tx.safe_address`) are routed to the
    // Safe-mgmt decoder first: a positive classification yields a
    // per-op intent banner; an unrecognised selector falls into the
    // loud "Unknown Safe op" blind-sign branch so the user can tell
    // it apart from a generic opaque inner call.
    let inner_value = U256(tx.value);
    // An allowlisted MultiSendCallOnly DELEGATECALL renders per-record
    // pages (the verdict gate in the handlers already enforced the hard
    // rules + the page budget). The claim predicate is the SAME
    // `multi_send::is_multisend_claim` the verifiers' operation gates
    // and the CoW-binding resolver use, so verify, gate and render
    // cannot disagree about what counts as a multiSend. A claim that
    // fails to decode here is an impossible state (the gate refused it)
    // and falls to the loud blind branch under a `! Op: DELEGATE` row —
    // fail-safe, never fail-rich.
    //
    // Otherwise, a handler-verified CoW v3 order takes the inner slot
    // outright — the v3 pipeline already byte-bound the canonical to
    // this SafeTx's raw_data (digest/validTo) and to the Safe address
    // (uid owner). The predicate re-check is defensive only: if the
    // dispatcher ever paired a `cow` with a non-presign inner call
    // (logic bug, memory fault), we ignore it and fall through to the
    // normal ladder, which lands on the loud blind-sign page.
    let inner_kind = if multi_send::is_multisend_claim(input.operation, &tx.to, safe.raw_data) {
        let cow_body = safe_cow_pages(cow);
        let count = multi_send::summarize(safe.raw_data)
            .map(|s| s.record_count)
            .unwrap_or(0);
        match multi_send::records_pages_total(safe.raw_data, &tx.safe_address, cow_body) {
            Some(total) if count > 0 => InnerKind::MultiSend {
                count,
                inner_pages: total,
            },
            _ => InnerKind::Blind,
        }
    } else {
        match cow {
            Some(v3) if safe_inner_is_cow_presign(&tx.to, safe.raw_data) => {
                InnerKind::CowswapPresign(v3)
            }
            _ => {
                if tx.to == tx.safe_address && !safe.raw_data.is_empty() {
                    match classify_safe_mgmt(safe.raw_data) {
                        Some(op) => InnerKind::SafeMgmt(op),
                        None => InnerKind::UnknownSafeSelf,
                    }
                } else {
                    match classify_inner(safe.raw_data, &inner_value) {
                        InnerKind::Erc20Known(call) if erc20.is_some() => {
                            InnerKind::Erc20Known(call)
                        }
                        InnerKind::Erc20Known(call) => InnerKind::Erc20Unknown(call),
                        other => other,
                    }
                }
            }
        }
    };
    let inner_pages = inner_kind_page_count(&inner_kind);
    let refund_pages = if refund_active { 2 } else { 0 };
    // Inner SafeTx `value` (ETH the Safe forwards to `to` on execution)
    // is shown inline only by the PlainEth branch. For every other inner
    // kind a non-zero value would otherwise be invisible even though it
    // is bound into the signed safeTxHash, so splice a dedicated page.
    let show_inner_eth = !inner_value.is_zero()
        && !matches!(inner_kind, InnerKind::PlainEth | InnerKind::EmptyCall);
    let inner_eth_pages = usize::from(show_inner_eth);
    let total_pages =
        SAFE_HEADER_PAGES + refund_pages + inner_eth_pages + inner_pages + 1; // +1 = confirm
    let total_pages = core::cmp::min(total_pages, super::MAX_PAGES);
    let mut pages = Pages::with_len(total_pages);

    // ── Page 0: banner + chain ──────────────────────────────────────
    let banner = match input.flavour {
        SafeRenderFlavour::ApproveHash { .. } => "Approve Safe TX",
        SafeRenderFlavour::ExecTransaction => "Execute Safe TX",
    };
    write_line(&mut pages.buf[0][0], banner);
    write_chain(&mut pages.buf[0][1], tx.chain_id);
    write_line(&mut pages.buf[0][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: Safe address (full) ─────────────────────────────────
    write_line(&mut pages.buf[1][0], "Safe:");
    {
        let [_lbl, a, b, c] = &mut pages.buf[1];
        write_addr_full_or_name(a, b, c, &tx.safe_address, tx.chain_id, resolver);
    }

    // ── Page 2: Safe-level metadata (flavour-specific top row + op +
    //          inner-kind hint) ──────────────────────────────────────
    match input.flavour {
        SafeRenderFlavour::ApproveHash { nonce } => {
            write_safe_nonce_row(&mut pages.buf[2][0], &nonce);
        }
        SafeRenderFlavour::ExecTransaction => {
            // No SafeTx nonce visible from calldata — the Safe reads it
            // from storage at execution time. Surface the flow so the
            // user can tell this apart from an approveHash render at a
            // glance.
            write_line(&mut pages.buf[2][0], "(execute now)");
        }
    }
    // Honest Op row: `Call` for operation 0; `MultiSend` for the
    // allowlisted DELEGATECALL batch the record pages decode; a loud
    // `! Op: DELEGATE` for the impossible-state remainder (operation 1
    // that the verifiers should have refused — render falls to Blind).
    let op_row = if input.operation == 0 {
        "Op: Call"
    } else if matches!(inner_kind, InnerKind::MultiSend { .. }) {
        "Op: MultiSend"
    } else {
        "! Op: DELEGATE"
    };
    write_line(&mut pages.buf[2][1], op_row);
    match &inner_kind {
        InnerKind::MultiSend { count, .. } => {
            write_msend_hint_row(&mut pages.buf[2][2], *count);
        }
        kind => write_line(&mut pages.buf[2][2], inner_kind_hint(kind)),
    }
    write_line(&mut pages.buf[2][3], "> next");

    // ── Optional refund pages: gasToken + refundReceiver ────────────
    //
    // Rendered for BOTH flavours when any refund field is set. The user
    // is paying `(gasUsed + baseGas) * gasPrice` in `gasToken` (ETH when
    // `gasToken == 0`) to `refundReceiver`. We cannot decode the exact
    // amount (it depends on runtime gas usage), but the *token* and the
    // *recipient* are the WYSIWYS-critical facts: a token refund has no
    // on-chain gasPrice cap, so without these pages an attacker could
    // drain the Safe's full balance of a chosen ERC-20 to themselves
    // behind a benign-looking inner call.
    let mut next_page = SAFE_HEADER_PAGES;
    if refund_active {
        // Page A: banner + the token the refund is paid in.
        write_line(&mut pages.buf[next_page][0], "! GAS REFUND");
        write_line(&mut pages.buf[next_page][1], "Safe pays in:");
        if input.gas_token.iter().all(|&b| b == 0) {
            write_line(&mut pages.buf[next_page][2], "ETH (native)");
        } else {
            // Token refund (no gasPrice cap) — show the token address so
            // the user can recognise "wait, that's my USDC".
            write_short_addr(&mut pages.buf[next_page][2], &input.gas_token);
        }
        write_line(&mut pages.buf[next_page][3], "> next");
        next_page += 1;

        // Page B: who receives the refund (full address, resolver-aware).
        write_line(&mut pages.buf[next_page][0], "Refund to:");
        if input.refund_receiver.iter().all(|&b| b == 0) {
            write_line(&mut pages.buf[next_page][1], "tx.origin");
            write_line(&mut pages.buf[next_page][2], "(whoever execs)");
            write_line(&mut pages.buf[next_page][3], "> next");
        } else {
            let [_lbl, a, b, c] = &mut pages.buf[next_page];
            write_addr_full_or_name(
                a,
                b,
                c,
                &input.refund_receiver,
                tx.chain_id,
                resolver,
            );
        }
        next_page += 1;
    }

    // ── Optional inner-ETH page ─────────────────────────────────────
    //
    // The PlainEth branch already shows the value inline; for every
    // other inner kind a non-zero SafeTx `value` is otherwise invisible.
    if show_inner_eth {
        write_line(&mut pages.buf[next_page][0], "Safe sends ETH:");
        {
            let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
            let fit = write_eth_two_rows(r1, r2, &inner_value);
            write_line(
                foot,
                match fit {
                    AmountFit::Full => "> next",
                    AmountFit::Overflow => "!AMOUNT OVERFLOW",
                },
            );
        }
        next_page += 1;
    }

    // ── Inner-tx pages ──────────────────────────────────────────────
    //
    // Single-call SafeTxs render exactly one classified inner; a
    // multiSend renders divider + (optional value page) + classified
    // pages PER RECORD through the same `append_inner_kind_pages` body
    // — one render implementation for both shapes.
    match &inner_kind {
        InnerKind::MultiSend { count, .. } => {
            next_page = append_multisend_pages(
                &mut pages, next_page, input, *count, cow, erc20, resolver,
            );
        }
        kind => {
            let ctx = InnerRenderCtx {
                chain_id: tx.chain_id,
                safe_address: tx.safe_address,
                to: tx.to,
                value: inner_value,
                data: safe.raw_data,
                data_hash: tx.data_hash,
                erc20,
                resolver,
            };
            next_page = append_inner_kind_pages(&mut pages, next_page, kind, &ctx);
        }
    }

    // ── Final: confirm prompt ───────────────────────────────────────
    if next_page < total_pages {
        write_line(&mut pages.buf[next_page][0], "Long-press to");
        write_line(&mut pages.buf[next_page][1], "");
        write_line(&mut pages.buf[next_page][2], "L=Cancel");
        write_line(&mut pages.buf[next_page][3], "R=Confirm");
    }

    pages
}

// ---------------------------------------------------------------------------
// Handler-facing multiSend gate
// ---------------------------------------------------------------------------

/// Verdict of [`multisend_sign_gate`].
pub enum MultisendGate {
    /// The Safe context's inner call is not a claimed multiSend —
    /// nothing for this gate to do.
    NotMultiSend,
    /// Claimed multiSend that must refuse to sign: a hard-rule
    /// violation (malformed framing, record op != 0, record cap, ≥2
    /// presign claims) or a trusted-display page-budget overflow.
    /// Handlers show `("Safe sign", reason)` and return
    /// `InvalidPointer` — a DELEGATECALL payload has no degraded
    /// render.
    Reject(&'static str),
    /// Decodes under every hard rule and fits the page budget.
    Ok,
}

/// One shared accept/refuse decision for a verified Safe context whose
/// inner call claims an allowlisted multiSend — called by BOTH the
/// single-tx and batch handlers so the two cannot drift.
///
/// `reserved_pages` is the handler-specific page overhead outside this
/// renderer: the dispatcher's native-value page (1 when the outer
/// UserOp `value != 0`), the two ERC-8213 fingerprint pages, and the
/// batch banner (batch handler only).
///
/// The budget arithmetic mirrors `render_safe_pages_inner` exactly:
/// fixed header(3) + refund(0|2) + SafeTx-value page(0|1) + the
/// per-record total from `multi_send::records_pages_total` (the SAME
/// classification + per-kind counts the renderer uses) + confirm(1).
pub fn multisend_sign_gate(
    safe_v1: Option<&VerifiedSafeV1<'_>>,
    safe_exec: Option<&VerifiedSafeExec<'_>>,
    cow: Option<&VerifiedCowswapV3>,
    reserved_pages: usize,
) -> MultisendGate {
    // Same precedence as `safe::cow_binding::resolve_cow_binding`:
    // a verified approveHash context wins over exec.
    let (operation, to, raw, safe_address, refund_active, safe_value_nonzero) =
        if let Some(s) = safe_v1 {
            let Ok(tx) = decode_canonical(&s.canonical) else {
                // The verifier proved the canonical decodes; stay
                // fail-safe if this is ever reached.
                return MultisendGate::Reject("msend canonical");
            };
            (
                tx.operation,
                tx.to,
                s.raw_data,
                tx.safe_address,
                tx.gas_price.iter().any(|&b| b != 0)
                    || tx.gas_token.iter().any(|&b| b != 0)
                    || tx.refund_receiver.iter().any(|&b| b != 0),
                tx.value.iter().any(|&b| b != 0),
            )
        } else if let Some(e) = safe_exec {
            let d = &e.decoded;
            (
                d.operation,
                d.to,
                d.data,
                e.safe_address,
                d.gas_price.iter().any(|&b| b != 0)
                    || d.gas_token.iter().any(|&b| b != 0)
                    || d.refund_receiver.iter().any(|&b| b != 0),
                d.value.iter().any(|&b| b != 0),
            )
        } else {
            return MultisendGate::NotMultiSend;
        };

    match multi_send::multisend_verdict(operation, &to, raw) {
        multi_send::MsVerdict::NotMultiSend => return MultisendGate::NotMultiSend,
        multi_send::MsVerdict::Reject(reason) => return MultisendGate::Reject(reason),
        multi_send::MsVerdict::Accept(_) => {}
    }

    // Page budget — refuse instead of truncating: a record the user
    // never saw is exactly the attack class this feature closes.
    let cow_body = safe_cow_pages(cow);
    let Some(inner_pages) = multi_send::records_pages_total(raw, &safe_address, cow_body)
    else {
        return MultisendGate::Reject("msend malformed");
    };
    let fixed = SAFE_HEADER_PAGES
        + if refund_active { 2 } else { 0 }
        + usize::from(safe_value_nonzero)
        + 1; // trailing confirm page
    if fixed + inner_pages + reserved_pages > super::MAX_PAGES {
        return MultisendGate::Reject("msend too long");
    }
    MultisendGate::Ok
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Lightweight view of the SafeTx fields the renderer needs. Lets the
/// shared body keep its `tx.foo` references after the refactor without
/// dragging the full canonical decode into the exec path.
struct SafeTxFields {
    chain_id: u64,
    safe_address: [u8; 20],
    to: [u8; 20],
    value: [u8; 32],
    data_hash: [u8; 32],
}

/// Twin of [`SafeTxFields`] for the raw inner-call payload. Borrows
/// from the gateway's TOCTOU snapshot (approveHash) or the inner_data
/// snapshot (exec).
struct SafeRawData<'a> {
    raw_data: &'a [u8],
}

enum InnerKind<'a> {
    EmptyCall,
    PlainEth,
    Erc20Known(Erc20Call),
    Erc20Unknown(Erc20Call),
    /// Inner call targets `safe_address` and decoded as one of the
    /// recognised Safe-native owner/module/guard/fallback ops.
    SafeMgmt(SafeMgmtOp),
    /// Inner call is `setPreSignature` on GPv2Settlement and the
    /// handler verified a CoW v3 trailer against it (orderUid digest /
    /// validTo bound to `raw_data`, uid owner == the Safe). Renders
    /// the full order intent via the shared cowswap_display body.
    CowswapPresign(&'a VerifiedCowswapV3),
    /// Inner call targets `safe_address` but the selector is not in
    /// the recognised Safe-native set — loud blind-sign with an
    /// explicit "Unknown Safe op" warning so the user can tell this
    /// apart from a generic opaque call.
    UnknownSafeSelf,
    /// Allowlisted `MultiSendCallOnly` DELEGATECALL batch: every packed
    /// record renders its own divider + classified pages through
    /// [`append_multisend_pages`]. `inner_pages` is the exact total
    /// from `multi_send::records_pages_total` (same per-kind counts the
    /// handlers' page-budget gate used).
    MultiSend { count: usize, inner_pages: usize },
    Blind,
}

/// Produce a one-line semantic hint about the inner tx, e.g.
/// `"Inner: ERC-20"`. Bounded to 16 ASCII columns.
fn inner_kind_hint(kind: &InnerKind<'_>) -> &'static str {
    match kind {
        InnerKind::EmptyCall => "(empty call)",
        InnerKind::PlainEth => "Inner: ETH xfer",
        InnerKind::Erc20Known(_) => "Inner: ERC-20",
        InnerKind::Erc20Unknown(_) => "Inner: ERC-20?",
        InnerKind::SafeMgmt(_) => "Inner: Safe mgmt",
        InnerKind::CowswapPresign(_) => "Inner: CoW order",
        InnerKind::UnknownSafeSelf => "! Unkn self-call",
        // The MultiSend hint carries the record count and is written by
        // `write_msend_hint_row` instead; this arm is a fallback.
        InnerKind::MultiSend { .. } => "Inner: MultiSend",
        InnerKind::Blind => "! Inner: opaque",
    }
}

/// Content pages for one classified inner (no divider / value pages —
/// those are multiSend-record concerns counted by the caller). Must
/// stay in lockstep with `multi_send::record_content_pages`, which the
/// handlers' page-budget gate uses for the same per-kind counts: the
/// MultiSend arm's total here IS `records_pages_total` (shared fn), and
/// each non-MultiSend arm's literal mirrors its `record_content_pages`
/// arm — a divergence would show as blank or truncated pages in the
/// QEMU multiSend e2e scenarios.
/// Body + context-banner page count for a Safe-wrapped CoW presign.
/// Each leg is 2 pages in both modes, so the body is a constant 8 and
/// this returns 9 regardless of whether `cow` is present; the absent
/// case still computes it via the AddrHex legs for symmetry.
fn safe_cow_pages(cow: Option<&VerifiedCowswapV3>) -> usize {
    use crate::tx::eip712::cowswap::CowLeg;
    1 + cow.map_or(
        order_body_page_count(&CowLeg::AddrHex, &CowLeg::AddrHex),
        |v| order_body_page_count(&v.sell, &v.buy),
    )
}

fn inner_kind_page_count(kind: &InnerKind<'_>) -> usize {
    match kind {
        InnerKind::EmptyCall => 1,
        InnerKind::PlainEth => 2,
        InnerKind::Erc20Known(_) | InnerKind::Erc20Unknown(_) => 4,
        InnerKind::SafeMgmt(op) => safe_mgmt_page_count(op),
        // Context banner + the shared CoW order body (constant 8 pages).
        InnerKind::CowswapPresign(v3) => safe_cow_pages(Some(v3)),
        InnerKind::UnknownSafeSelf => 3,
        InnerKind::MultiSend { inner_pages, .. } => *inner_pages,
        InnerKind::Blind => 3,
    }
}

/// Everything one inner render needs, scoped so a multiSend record and
/// a single-call SafeTx flow through the same arm bodies. `data_hash`
/// is the bound SafeTx data hash for the single-call shape and
/// `keccak(record.data)` for a record (the record bytes sit inside the
/// data_hash-bound blob, so the recompute is honest).
struct InnerRenderCtx<'a, 'r> {
    chain_id: u64,
    safe_address: [u8; 20],
    to: [u8; 20],
    value: U256,
    data: &'a [u8],
    data_hash: [u8; 32],
    erc20: Option<&'a Erc20Metadata<'a>>,
    resolver: &'a NameResolver<'r>,
}

/// Append the pages for one classified inner (a single-call SafeTx's
/// inner call, or one multiSend record). Returns the next free page.
///
/// The arm bodies are the former inline match in
/// `render_safe_pages_inner`, parameterised over [`InnerRenderCtx`] —
/// behaviour for single-call SafeTxs is unchanged.
fn append_inner_kind_pages(
    pages: &mut Pages,
    start: usize,
    kind: &InnerKind<'_>,
    ctx: &InnerRenderCtx<'_, '_>,
) -> usize {
    let mut next_page = start;
    match kind {
        InnerKind::EmptyCall => {
            // P_n: "Inner: empty call" / "Inner to:" / addr-summary / "> next"
            write_line(&mut pages.buf[next_page][0], "Inner: empty");
            write_line(&mut pages.buf[next_page][1], "(no calldata)");
            // Use a compact name+truncated-hex form by writing just one
            // row's worth of address. The full address is on the next
            // page if we had room, but for the empty-call case we save
            // a page.
            write_short_addr(&mut pages.buf[next_page][2], &ctx.to);
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
        }
        InnerKind::PlainEth => {
            // P_n: "Inner to:" + addr full
            write_line(&mut pages.buf[next_page][0], "Inner to:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
            next_page += 1;
            // P_n+1: "Send ETH:" + amount
            write_line(&mut pages.buf[next_page][0], "Send ETH:");
            {
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                let fit = write_eth_two_rows(r1, r2, &ctx.value);
                write_line(
                    foot,
                    match fit {
                        AmountFit::Full => "> next",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
            }
            next_page += 1;
        }
        InnerKind::Erc20Known(call) => {
            let meta = ctx
                .erc20
                .expect("InnerKind::Erc20Known implies erc20 metadata present");
            // P_n: "Send/Approve SYM" + token name + native-ETH warn + "> next"
            write_erc20_header(&mut pages.buf[next_page][0], call, meta);
            write_token_name(&mut pages.buf[next_page][1], meta);
            if !ctx.value.is_zero() {
                write_line(&mut pages.buf[next_page][2], "! native ETH!");
            }
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            next_page = append_erc20_tail_pages(pages, next_page, call, Some(meta), ctx);
        }
        InnerKind::Erc20Unknown(call) => {
            // P_n: "ERC-20 call" / "(unverified)" + native-ETH warn + "> next"
            write_line(&mut pages.buf[next_page][0], "ERC-20 call");
            write_line(&mut pages.buf[next_page][1], "(unverified)");
            if !ctx.value.is_zero() {
                write_line(&mut pages.buf[next_page][2], "! native ETH!");
            }
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            next_page = append_erc20_tail_pages(pages, next_page, call, None, ctx);
        }
        InnerKind::Blind => {
            // P_n: loud banner
            write_line(&mut pages.buf[next_page][0], "! BLIND SIGN");
            write_line(&mut pages.buf[next_page][1], "Unknown call");
            write_line(&mut pages.buf[next_page][2], "Verify on dapp");
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            // P_n+1: "Inner to:" + addr (full)
            write_line(&mut pages.buf[next_page][0], "Inner to:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
            next_page += 1;
            // P_n+2: selector + data length + first/last data-hash bytes
            write_selector_row(&mut pages.buf[next_page][0], ctx.data);
            write_data_len_row(&mut pages.buf[next_page][1], ctx.data.len());
            // Reuse the "calldata hash" 2-row layout but spread it
            // over rows 2 + 3 so we surface the inner data's keccak
            // (which `ctx.data_hash` already commits to via the bind).
            {
                let [_a, _b, r1, r2] = &mut pages.buf[next_page];
                write_calldata_hash_rows(r1, r2, &ctx.data_hash);
            }
            next_page += 1;
        }
        InnerKind::SafeMgmt(op) => {
            next_page = render_safe_mgmt_pages(
                pages,
                next_page,
                op,
                ctx.chain_id,
                &ctx.safe_address,
                ctx.resolver,
            );
        }
        InnerKind::CowswapPresign(v3) => {
            // P_n: context banner — the load-bearing linkage page. The
            // user must understand that the order shown on the next
            // pages is owned by (sells the funds of) THIS Safe, not the
            // wallet. The short-form Safe address lets them eyeball it
            // against the full-address page 1 without flipping back.
            write_line(&mut pages.buf[next_page][0], "CowSwap order");
            write_line(&mut pages.buf[next_page][1], "for this Safe:");
            write_short_addr(&mut pages.buf[next_page][2], &ctx.safe_address);
            // Surface the sell/buy direction on the context banner; the
            // per-leg labels in the body restate it but this keeps it
            // visible up-front (the direct flow shows it on page 0).
            write_line(&mut pages.buf[next_page][3], order_kind_label(&v3.canonical));
            next_page += 1;
            // P_n+1..: the shared CoW order body. Zero receiver renders
            // as "(= the Safe)" — GPv2 routes proceeds to the uid owner,
            // which the handler verified is this Safe.
            next_page = append_order_body_pages(
                pages,
                next_page,
                &v3.canonical,
                &v3.sell,
                &v3.buy,
                Some("(= the Safe)"),
            );
        }
        InnerKind::UnknownSafeSelf => {
            // Loud variant of Blind that distinguishes "self-call to the
            // Safe contract with an unrecognised selector" from a generic
            // opaque inner call. The user sees the extra warning row and
            // can refuse if the dapp didn't ask for a Safe-mgmt op.
            write_line(&mut pages.buf[next_page][0], "! UNKNOWN SAFE OP");
            write_line(&mut pages.buf[next_page][1], "Self-call to Safe");
            write_line(&mut pages.buf[next_page][2], "Verify off-device");
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            // Inner `to` (= Safe address; rendered full so a name in the
            // names bundle still lights up).
            write_line(&mut pages.buf[next_page][0], "Inner to (Safe):");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
            next_page += 1;
            // Selector + data length + bound data-hash (matches the
            // Blind branch's last page so the user can compare on-device).
            write_selector_row(&mut pages.buf[next_page][0], ctx.data);
            write_data_len_row(&mut pages.buf[next_page][1], ctx.data.len());
            {
                let [_a, _b, r1, r2] = &mut pages.buf[next_page];
                write_calldata_hash_rows(r1, r2, &ctx.data_hash);
            }
            next_page += 1;
        }
        InnerKind::MultiSend { .. } => {
            // Unreachable: the caller routes MultiSend through
            // `append_multisend_pages` (records never classify as
            // MultiSend — `classify_record_kind` has no such arm, so
            // there is no recursion either). Render nothing.
            debug_assert!(false, "MultiSend must not reach append_inner_kind_pages");
        }
    }
    next_page
}

/// Shared recipient/amount/contract tail (3 pages) for the two ERC-20
/// flavours — `meta = Some` renders decimals + symbol, `None` renders
/// the raw hex amount. The label page above differs per flavour and
/// stays at the call sites.
fn append_erc20_tail_pages(
    pages: &mut Pages,
    start: usize,
    call: &Erc20Call,
    meta: Option<&Erc20Metadata<'_>>,
    ctx: &InnerRenderCtx<'_, '_>,
) -> usize {
    let mut next_page = start;
    // Recipient/spender (full address). An `approve` whose spender is
    // the pinned CoW vault relayer gets a verified human label — the
    // equality is against the rodata constant, not companion data.
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. }
            if recipient == GPV2_VAULT_RELAYER_ADDRESS =>
        {
            "CoW VaultRelayer"
        }
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[next_page][0], recipient_label);
    {
        let [_lbl, a, b, c] = &mut pages.buf[next_page];
        write_addr_full_or_name(a, b, c, &recipient, ctx.chain_id, ctx.resolver);
    }
    next_page += 1;
    // Amount (with unlimited-approve guard).
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    match meta {
        Some(meta) => {
            write_line(&mut pages.buf[next_page][0], "Amount:");
            if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
                write_line(&mut pages.buf[next_page][1], "unlimited");
                write_line(&mut pages.buf[next_page][2], "");
                write_line(&mut pages.buf[next_page][3], "> next");
            } else {
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                let fit = write_token_amount_two_rows(r1, r2, &amount, meta);
                write_line(
                    foot,
                    match fit {
                        AmountFit::Full => "> next",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
            }
        }
        None => {
            // Raw amount (no decimals known) — hex tail across two rows
            // so the user can compare against a dapp's hex.
            write_line(&mut pages.buf[next_page][0], "Raw amount:");
            if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
                write_line(&mut pages.buf[next_page][1], "unlimited");
                write_line(&mut pages.buf[next_page][2], "");
                write_line(&mut pages.buf[next_page][3], "> next");
            } else {
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                write_raw_uint_two_rows(r1, r2, &amount);
                write_line(foot, "> next");
            }
        }
    }
    next_page += 1;
    // Contract (full address) — anti-spoof.
    write_line(&mut pages.buf[next_page][0], "Contract:");
    {
        let [_lbl, a, b, c] = &mut pages.buf[next_page];
        write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
    }
    next_page += 1;
    next_page
}

/// Render every record of an allowlisted multiSend batch: divider page
/// ("MSend rec i/N" + target), an explicit value page for any record
/// that forwards ETH without showing it inline, then the record's
/// classified pages via [`append_inner_kind_pages`].
fn append_multisend_pages(
    pages: &mut Pages,
    start: usize,
    input: &SafeRenderInput<'_>,
    count: usize,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> usize {
    let mut p = start;
    let Ok(packed) = multi_send::decode_multisend(input.raw_data) else {
        // Unreachable post-gate; the classification block already fell
        // to Blind for undecodable claims.
        return p;
    };
    // The record the verified CoW order is bound to (unique presign
    // claim) — the same selection the resolver made, re-derived from
    // the same bytes.
    let presign_unique_idx = multi_send::summarize(input.raw_data)
        .ok()
        .filter(|s| s.presign_claims == 1)
        .map(|s| s.presign_idx);
    let mut idx = 0usize;
    for rec in MsRecordIter::new(packed) {
        // Decode errors are unreachable post-gate (summarize already
        // walked every record); stop cleanly rather than render a
        // half-decoded batch.
        let Ok(rec) = rec else { break };
        write_msend_divider_page(pages, p, idx, count, &rec.to);
        p += 1;
        let value = U256(rec.value);
        let raw_kind =
            classify_record_kind(&rec.to, value.is_zero(), rec.data, &input.safe_address);
        if record_needs_value_page(&raw_kind, value.is_zero()) {
            write_record_value_page(pages, p, &value);
            p += 1;
        }
        // Metadata applies per record by address match — same rule the
        // single-call picker uses for the inner `to`.
        let rec_meta = erc20.filter(|m| m.contract == rec.to);
        let kind: InnerKind<'_> = match raw_kind {
            MsRecordKind::EmptyCall => InnerKind::EmptyCall,
            MsRecordKind::PlainEth => InnerKind::PlainEth,
            MsRecordKind::Erc20(call) if rec_meta.is_some() => InnerKind::Erc20Known(call),
            MsRecordKind::Erc20(call) => InnerKind::Erc20Unknown(call),
            MsRecordKind::SafeMgmt(op) => InnerKind::SafeMgmt(op),
            MsRecordKind::UnknownSafeSelf => InnerKind::UnknownSafeSelf,
            // The CoW order renders ONLY on the record the handler
            // verified the v3 trailer against (unique presign claim).
            // Any other pairing is an impossible state — fall to the
            // loud blind pages, never fail-rich.
            MsRecordKind::CowPresignClaim => match (cow, presign_unique_idx) {
                (Some(v3), Some(pi)) if pi == idx => InnerKind::CowswapPresign(v3),
                _ => InnerKind::Blind,
            },
            MsRecordKind::Blind => InnerKind::Blind,
        };
        let ctx = InnerRenderCtx {
            chain_id: input.chain_id,
            safe_address: input.safe_address,
            to: rec.to,
            value,
            data: rec.data,
            data_hash: keccak(rec.data),
            erc20: rec_meta,
            resolver,
        };
        p = append_inner_kind_pages(pages, p, &kind, &ctx);
        idx += 1;
    }
    p
}

/// Divider page before each multiSend record: position, target address
/// (short form — ERC-20 / blind / mgmt pages repeat it in full).
fn write_msend_divider_page(
    pages: &mut Pages,
    page: usize,
    idx: usize,
    count: usize,
    to: &[u8; 20],
) {
    {
        let row = &mut pages.buf[page][0];
        *row = [b' '; DISPLAY_COLS];
        let prefix = b"MSend rec ";
        row[..prefix.len()].copy_from_slice(prefix);
        // `idx` is 0-based; show 1-based "i/N". Both bounded to one
        // digit by MULTISEND_MAX_RECORDS (6).
        row[prefix.len()] = b'1' + (idx as u8);
        row[prefix.len() + 1] = b'/';
        row[prefix.len() + 2] = b'0' + (count as u8);
    }
    write_line(&mut pages.buf[page][1], "to:");
    write_short_addr(&mut pages.buf[page][2], to);
    write_line(&mut pages.buf[page][3], "> next");
}

/// Dedicated value page for a multiSend record whose kind doesn't show
/// its forwarded ETH inline — mirrors the SafeTx-level "Safe sends ETH"
/// page.
fn write_record_value_page(pages: &mut Pages, page: usize, value: &U256) {
    write_line(&mut pages.buf[page][0], "Rec sends ETH:");
    let [_lbl, r1, r2, foot] = &mut pages.buf[page];
    let fit = write_eth_two_rows(r1, r2, value);
    write_line(
        foot,
        match fit {
            AmountFit::Full => "> next",
            AmountFit::Overflow => "!AMOUNT OVERFLOW",
        },
    );
}

/// Page-2 hint row for the multiSend flow: "Inner: MSend xN".
fn write_msend_hint_row(row: &mut [u8; DISPLAY_COLS], count: usize) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Inner: MSend x";
    row[..prefix.len()].copy_from_slice(prefix);
    // Bounded to one digit by MULTISEND_MAX_RECORDS (6).
    row[prefix.len()] = b'0' + (count as u8).min(9);
}

// The returned `InnerKind` never borrows from the arguments — the
// lifetime parameter only exists for the `CowswapPresign` variant,
// which this classifier never produces (the caller selects it from the
// handler-verified `cow` before consulting the ladder).
fn classify_inner<'a>(raw_data: &[u8], value: &U256) -> InnerKind<'a> {
    if raw_data.is_empty() {
        if value.is_zero() {
            InnerKind::EmptyCall
        } else {
            InnerKind::PlainEth
        }
    } else {
        match parse_erc20_calldata(raw_data) {
            Some(call) => {
                // We can't decide here whether the metadata is going
                // to be present (the caller passes it separately and
                // also has to address-match it). Default to
                // `Erc20Known` and let the renderer fall back if the
                // metadata is absent or mismatched. Mismatch handling
                // happens in `pick_sign_pages` (the caller suppresses
                // the metadata when contracts don't align).
                InnerKind::Erc20Known(call)
            }
            None => InnerKind::Blind,
        }
    }
}

/// Wrap [`super::primitives::write_nonce_row`]'s u64 path: SafeTx
/// nonces are uint256s on-chain, but in practice they fit in a u64
/// for the foreseeable future. If the high 24 bytes are non-zero we
/// fall back to a hex-tail render so the user knows it overflowed.
fn write_safe_nonce_row(row: &mut [u8; DISPLAY_COLS], nonce_be: &[u8; 32]) {
    // Check if the upper 24 bytes are zero so we can render as decimal.
    let high_nonzero = nonce_be[..24].iter().any(|&b| b != 0);
    if !high_nonzero {
        let n = u64::from_be_bytes([
            nonce_be[24],
            nonce_be[25],
            nonce_be[26],
            nonce_be[27],
            nonce_be[28],
            nonce_be[29],
            nonce_be[30],
            nonce_be[31],
        ]);
        // Reuse the existing nonce-row primitive but with our own
        // label so it reads "SafeTx Nonce: N" rather than "Nonce: N".
        // We can't reuse write_nonce_row's prefix, so format here.
        *row = [b' '; DISPLAY_COLS];
        let prefix = b"SafeTx Nonce: ";
        let n_pre = core::cmp::min(prefix.len(), row.len());
        row[..n_pre].copy_from_slice(&prefix[..n_pre]);
        let mut tmp = [0u8; 20];
        if let Some(width) = format_u64(n, &mut tmp) {
            let start = n_pre;
            if start + width <= row.len() {
                row[start..start + width].copy_from_slice(&tmp[..width]);
            } else {
                // overflow marker
                let _ = write_overflow_marker(row, n_pre);
            }
        } else {
            let _ = write_overflow_marker(row, n_pre);
        }
    } else {
        // Pathological: nonce > u64::MAX. Render as
        // "SafeTx N: >2^64" which is unmistakable.
        let prefix = b"SafeTx N: >2^64";
        *row = [b' '; DISPLAY_COLS];
        let n = core::cmp::min(prefix.len(), row.len());
        row[..n].copy_from_slice(&prefix[..n]);
    }
}

fn write_overflow_marker(
    row: &mut [u8; DISPLAY_COLS],
    pos: usize,
) -> usize {
    let marker = b"!OVF";
    let space = row.len().saturating_sub(pos);
    let n = core::cmp::min(marker.len(), space);
    row[pos..pos + n].copy_from_slice(&marker[..n]);
    pos + n
}

/// Render the first 4 + last 4 bytes of an address into a single
/// 16-column row: "0xAABBCCDD..EEFFAABB" — 2+8+2+8 = 20 chars,
/// truncated to 16 by dropping the trailing 4 hex chars when needed.
/// This is a one-row alternative to [`write_addr_full_or_name`] for
/// pages that only have a single line to spare.
fn write_short_addr(row: &mut [u8; DISPLAY_COLS], addr: &[u8; 20]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'0';
    row[1] = b'x';
    let hex = b"0123456789abcdef";
    // First 3 bytes
    for i in 0..3 {
        row[2 + i * 2] = hex[(addr[i] >> 4) as usize];
        row[2 + i * 2 + 1] = hex[(addr[i] & 0x0f) as usize];
    }
    row[8] = b'.';
    row[9] = b'.';
    // Last 3 bytes
    for i in 0..3 {
        let b = addr[17 + i];
        row[10 + i * 2] = hex[(b >> 4) as usize];
        row[10 + i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
}

/// Render a U256 hex tail across two rows: row1 = "0x" + first 7 bytes,
/// row2 = ".. " + last 6 bytes. Used for the unverified-token "raw
/// amount" page where we don't know the decimals. Mirrors the calldata
/// hash 2-row layout for visual consistency.
fn write_raw_uint_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let hex = b"0123456789abcdef";
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        let b = value.0[i];
        row1[2 + i * 2] = hex[(b >> 4) as usize];
        row1[2 + i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
    row2[0] = b'.';
    row2[1] = b'.';
    row2[2] = b'.';
    row2[3] = b' ';
    for i in 0..6 {
        let b = value.0[26 + i];
        row2[4 + i * 2] = hex[(b >> 4) as usize];
        row2[4 + i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
}

