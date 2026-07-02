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
//!   0: "Approve Safe TX"     1: "Safe:"             2: "SafeTx #N"
//!      Chain: <n>                <addr full>            Op: Call
//!      <chain name>              <addr full>            <inner kind hint>
//!      > next                    <addr full>            > next
//!
//!   refund (3 pages, only when a gas refund is configured — i.e. any of
//!          gasPrice / gasToken / refundReceiver is non-zero):
//!          A: "! GAS REFUND" + "Safe pays in:" + token (addr or "ETH")
//!          B: "Refund up to:" + worst-case (CEILING+baseGas)*gasPrice at
//!             full token magnitude (CEILING over-approximates the runtime
//!             gasUsed). This single total bounds every drain vector and
//!             vanishes to 0 only when the worst-case debit is truly
//!             negligible — so no drain can hide behind it.
//!          C: "Refund to:"   + refundReceiver (full addr, or "tx.origin")
//!          The total debit is (gasUsed+baseGas)*gasPrice with gasUsed
//!          runtime; B shows the worst-case bound. A *token* refund has no
//!          on-chain gasPrice cap, so without B an attacker could move the
//!          Safe's whole balance "as gas" behind an amount-less screen
//!          (audit 2026-06-19).
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
    write_data_len_row, write_erc20_header, write_eth_two_rows, write_gas, write_line,
    write_selector_row, write_token_amount_two_rows, write_token_name, AmountFit,
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

/// FI-robust "must this signed-value page be shown?" decision.
///
/// Returns `true` (SHOW) unless `safe_to_skip` is proven true through a
/// Hamming-distant sentinel double-evaluation (`fi::check_true_into_sentinel`
/// + `black_box`). A single glitch on the `safe_to_skip` predicate therefore
/// cannot turn a fund-bearing page from SHOW into SKIP — it can only fail
/// *towards* showing the page. This is the Safe-surface analogue of
/// `value_page::enforce_native_value_page`'s skip gate, and is shared by the
/// renderer AND the budget gate so a fault in either path defaults to the
/// safe (show / over-count) direction (audit 2026-06-27 — HIGH: the
/// inner-ETH / refund / safeTxGas page presence was previously a bare
/// `.iter().any()` boolean, single-fault-skippable like the pre-fix
/// native-value gate).
fn must_show_unless_robustly_skippable(safe_to_skip: bool) -> bool {
    crate::fi::check_true_into_sentinel(|| core::hint::black_box(safe_to_skip))
        != crate::fi::OK_SENTINEL
}

/// True when EVERY byte of `field` is zero — the "robustly absent" predicate
/// fed to [`must_show_unless_robustly_skippable`]. Kept as one helper so the
/// renderer and the gate test field-presence identically (no divergence).
fn all_zero(field: &[u8]) -> bool {
    field.iter().all(|&b| b == 0)
}

/// SafeTx refund is configured when ANY of `gasPrice` / `gasToken` /
/// `refundReceiver` is non-zero. One source of truth for the renderer and
/// the budget gate.
fn refund_is_active(gas_price: &[u8; 32], gas_token: &[u8; 20], refund_receiver: &[u8; 20]) -> bool {
    must_show_unless_robustly_skippable(
        all_zero(gas_price) && all_zero(gas_token) && all_zero(refund_receiver),
    )
}

/// Fixed (non-inner-tx, non-inner-ETH) Safe overhead page count:
/// header(3) + refund(0|3) + safeTxGas(0|1) + trailing confirm(1).
///
/// The SINGLE source of truth shared by `render_safe_pages_inner`'s
/// `total_pages` and `multisend_sign_gate`'s `fixed`, so the count the gate
/// approves and the count the renderer produces can never diverge (a
/// divergence is what would otherwise drive the renderer's page-accounting
/// refusal / the historic silent `min(.., MAX_PAGES)` truncation).
fn safe_fixed_overhead_pages(refund_active: bool, safe_tx_gas_active: bool) -> usize {
    SAFE_HEADER_PAGES
        + if refund_active { 3 } else { 0 }
        + usize::from(safe_tx_gas_active)
        + 1 // trailing confirm page
}

/// Over-approximation of the runtime `gasUsed` term used to bound the Safe
/// gas-refund worst-case `(gasUsed + baseGas) * gasPrice` on the refund
/// magnitude page. The on-chain `gasUsed` is not a signed field, so the
/// trusted display cannot show an exact refund; it shows an upper bound
/// using this ceiling (the Ethereum-mainnet block gas limit, a
/// representative cap). For a legitimate refund this over-states the debit
/// (hence the "up to" label); on chains with a higher block limit it is no
/// longer a strict maximum but still scales with — and stays large for —
/// any real drain. See the refund-page comment in `render_safe_pages_inner`.
const GAS_USED_CEILING: u64 = 30_000_000;

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
    /// SafeTx `baseGas` (signed, EIP-712 struct field). The refund debit is
    /// `(gasUsed + baseGas) * gasPrice`; `baseGas` is uncapped, so an
    /// attacker can drain via a huge `baseGas` with a tiny `gasPrice` (which
    /// would make the per-gas RATE page look benign). We therefore also
    /// render the `baseGas * gasPrice` base component so that drain vector
    /// is visible (audit 2026-06-19, hardened after adversarial review).
    base_gas: [u8; 32],
    /// SafeTx `safeTxGas` (signed, EIP-712 struct field, canonical word 4).
    /// It bounds the gas forwarded to the inner call; crucially, Safe's
    /// `require(success || safeTxGas != 0 || gasPrice != 0)` means a NON-ZERO
    /// `safeTxGas` lets `execTransaction` SUCCEED — burning the nonce and
    /// paying any refund — even when the inner call runs out of gas and
    /// reverts. A hidden non-zero `safeTxGas` therefore lets the displayed
    /// inner action ("transfer 100 USDC") silently no-op while the user
    /// believes it executed: a WYSIWYS integrity gap. Surfaced on its own
    /// page whenever non-zero (audit 2026-06-26).
    safe_tx_gas: [u8; 32],
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
) -> Result<Pages, ()> {
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
        base_gas: tx.base_gas,
        safe_tx_gas: tx.safe_tx_gas,
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
) -> Result<Pages, ()> {
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
        base_gas: d.base_gas,
        safe_tx_gas: d.safe_tx_gas,
    };
    render_safe_pages_inner(&input, cow, erc20, resolver)
}

/// Shared rendering body for both approveHash and execTransaction.
///
/// Returns `Err(())` — mapped by the dispatcher to a refuse-to-sign — when
/// the page budget is exceeded or the page-accounting self-check fails. It
/// NEVER silently truncates: a page that renders a signed value (inner ETH,
/// gas refund, a multiSend record) must either be shown or the signature
/// refused (audit 2026-06-27 — fail-closed replacement for the historic
/// `min(total_pages, MAX_PAGES)` clamp).
fn render_safe_pages_inner(
    input: &SafeRenderInput<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, ()> {
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
    // FI-robust: defaults to SHOW unless all three refund fields are
    // provably zero (see `must_show_unless_robustly_skippable`). A hidden
    // *token* refund is a full-ERC-20-balance drain channel, so a single
    // fault must never be able to skip these pages.
    let refund_active =
        refund_is_active(&input.gas_price, &input.gas_token, &input.refund_receiver);

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
    // The refund block is 3 pages when configured (token + worst-case refund
    // MAGNITUDE + recipient, audit 2026-06-19); that count now lives in the
    // shared `safe_fixed_overhead_pages` so the renderer and the budget gate
    // cannot disagree about it.
    //
    // Inner SafeTx `value` (ETH the Safe forwards to `to` on execution)
    // is shown inline only by the PlainEth branch. For every other inner
    // kind a non-zero value would otherwise be invisible even though it
    // is bound into the signed safeTxHash, so splice a dedicated page.
    // FI-robust: defaults to SHOW unless the inner value is provably zero or
    // the value is already rendered inline (PlainEth / EmptyCall). The
    // inner-ETH the Safe forwards to `to` is committed into the signed
    // safeTxHash and is gated ONLY here — the dispatcher's
    // `enforce_native_value_page` covers the *outer* UserOp value, not this
    // one — so a single-fault skip would hide an ETH drain (audit 2026-06-27).
    let inline_value_kind = matches!(inner_kind, InnerKind::PlainEth | InnerKind::EmptyCall);
    let show_inner_eth =
        must_show_unless_robustly_skippable(inner_value.is_zero() || inline_value_kind);
    let inner_eth_pages = usize::from(show_inner_eth);
    // safeTxGas page (audit 2026-06-26): shown whenever non-zero — it is
    // signed into the safeTxHash but invisible in the inner-tx semantics,
    // and a non-zero value lets the inner call silently fail while the outer
    // tx still succeeds (see `SafeRenderInput::safe_tx_gas`). Kept in
    // lockstep with the `multisend_sign_gate` `fixed` term so the budget gate
    // REFUSES (rather than truncates) any multiSend whose total would
    // overflow MAX_PAGES.
    // FI-robust (same rationale): a hidden non-zero safeTxGas lets the inner
    // call silently no-op while the nonce is burned and any refund paid.
    let show_safe_tx_gas = must_show_unless_robustly_skippable(all_zero(&input.safe_tx_gas));
    let total_pages =
        safe_fixed_overhead_pages(refund_active, show_safe_tx_gas) + inner_eth_pages + inner_pages;
    // Fail CLOSED, never truncate: a page that renders a signed value must be
    // shown or the signature refused. The old `min(total_pages, MAX_PAGES)`
    // silently dropped trailing pages (records) when the gate/renderer page
    // counts diverged — exactly the signed-but-not-shown class this audit
    // closes (2026-06-27). `multisend_sign_gate` already refuses over-budget
    // multiSends up front; this is the renderer-local backstop for every
    // Safe shape (single-call included), so the WYSIWYS guarantee no longer
    // rests solely on the external gate.
    if total_pages > super::MAX_PAGES {
        return Err(());
    }
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
        if input.gas_token.iter().all(|&b| b == 0) {
            write_line(&mut pages.buf[next_page][0], "! GAS REFUND");
            write_line(&mut pages.buf[next_page][1], "Safe pays in:");
            write_line(&mut pages.buf[next_page][2], "ETH (native)");
            write_line(&mut pages.buf[next_page][3], "> next");
        } else {
            // Token refund (no on-chain gasPrice cap) — show the FULL token
            // address, resolver-aware, so the user can actually recognise
            // "wait, that's my USDC". The old `write_short_addr` showed only
            // 6 of 20 bytes AND skipped the name DB, defeating that exact
            // purpose: a draining refund denominated in a chosen ERC-20 could
            // pass for a worthless-token refund because the user could read
            // neither the full address nor the token's name (audit
            // 2026-06-26). Mirrors the full-address treatment of the refund
            // recipient (page C) and every other contract/recipient address
            // on this surface. Still ONE page — the 40-hex / resolved name
            // occupies rows 1-3 — so the 3-page refund budget and the
            // `multisend_sign_gate` lockstep are unchanged.
            write_line(&mut pages.buf[next_page][0], "! REFUND TOKEN:");
            let [_lbl, a, b, c] = &mut pages.buf[next_page];
            write_addr_full_or_name(a, b, c, &input.gas_token, tx.chain_id, resolver);
        }
        next_page += 1;

        // Page B: the WORST-CASE refund magnitude (audit 2026-06-19;
        // hardened across two adversarial review rounds).
        //
        // On-chain the Safe pays `(gasUsed + baseGas) * gasPrice` of
        // `gasToken` to `refundReceiver`. `gasUsed` is a RUNTIME quantity,
        // attacker-influenced via the inner call but BOUNDED by the block
        // gas limit (`GAS_USED_CEILING`); `baseGas` and `gasPrice` are
        // signed and uncapped. We therefore render the worst-case TOTAL
        //
        //     (GAS_USED_CEILING + baseGas) * gasPrice
        //
        // at full token magnitude. This is the right number to show because
        // it equals the largest the refund debit can be, so it vanishes to
        // "0.000000" ONLY when the actual worst-case debit is itself a
        // negligible sub-unit amount — no real drain can hide behind it.
        //
        // Earlier attempts failed here: the `baseGas*gasPrice` FLOOR read
        // "0" when an attacker set `baseGas = 0` and drained via `gasUsed`;
        // and a per-gas RATE (`gasPrice` scaled by the token's decimals)
        // rounded a 15-token gasUsed-driven drain to "0.000000" because the
        // rate is divided by `10^decimals`. The TOTAL has neither flaw.
        //
        // `gasUsed` is over-approximated by a fixed ceiling rather than the
        // exact runtime value, so for a legitimate refund this page shows an
        // upper bound (labelled "up to"); a token gas-refund is rare and
        // always worth scrutinising, so a conservative ceiling is the safe
        // direction. On chains whose block limit exceeds the ceiling the
        // bound is still large for any real drain (it scales with the
        // drain), just not a strict maximum.
        write_line(&mut pages.buf[next_page][0], "Refund up to:");
        {
            // baseGas + ceiling, reduced to u64 (a baseGas beyond u64 makes
            // the worst case astronomically large → handled as overflow).
            let (base_u64, base_overflow) = u64_be_tail(&input.base_gas);
            let gas_units = base_u64.saturating_add(GAS_USED_CEILING);
            let (worst, mul_overflow) =
                U256(input.gas_price).saturating_mul_u64(gas_units);
            let huge = base_overflow || mul_overflow;
            let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
            if huge {
                // Exceeds 2^256 — unrenderable but unmistakably enormous.
                // Fail loud; never a misleading small number.
                write_line(r1, "!HUGE");
                write_line(r2, "(refuse)");
                write_line(foot, "@30M gas est");
            } else {
                // gasToken == 0 → ETH (18 dec). gasToken matching the
                // address-checked inner bundle → its decimals + symbol.
                // Otherwise the raw integer in base units. Overflow paints a
                // loud banner rather than dropping the high-order digits.
                let fit = if input.gas_token.iter().all(|&b| b == 0) {
                    write_eth_two_rows(r1, r2, &worst)
                } else if let Some(m) =
                    erc20.filter(|m| m.contract == input.gas_token)
                {
                    write_token_amount_two_rows(r1, r2, &worst, m)
                } else {
                    let units = Erc20Metadata {
                        chain_id: 0,
                        contract: [0u8; 20],
                        decimals: 0,
                        name: &[],
                        symbol: b"units",
                    };
                    write_token_amount_two_rows(r1, r2, &worst, &units)
                };
                write_line(
                    foot,
                    match fit {
                        // Footer doubles as the gas-ceiling disclosure so the
                        // "up to" is honest about its assumption.
                        AmountFit::Full => "@30M gas est",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
            }
        }
        next_page += 1;

        // Page C: who receives the refund (full address, resolver-aware).
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

    // ── Optional safeTxGas page ─────────────────────────────────────
    //
    // `safeTxGas` is signed into the safeTxHash but is invisible in the
    // inner-tx semantics. A non-zero value lets `execTransaction` succeed
    // even if the inner call runs out of gas (Safe's
    // `require(success || safeTxGas != 0 || gasPrice != 0)`), so the inner
    // action can silently no-op while the nonce is burned and any refund is
    // paid. Surface it whenever non-zero (audit 2026-06-26).
    if show_safe_tx_gas {
        write_line(&mut pages.buf[next_page][0], "SafeTx gas:");
        {
            let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
            let (units, overflow) = u64_be_tail(&input.safe_tx_gas);
            if overflow {
                // > u64 gas is absurd; never misrepresent it as a small value.
                write_line(r1, "!HUGE (>u64)");
            } else {
                write_gas(r1, units);
            }
            // Why it matters: a non-zero safeTxGas can let the inner call
            // silently fail while the outer Safe tx still succeeds.
            write_line(r2, "inner may no-op");
            write_line(foot, "> next");
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

    // ── Page-accounting self-check (WYSIWYS class backstop) ─────────
    //
    // Every page that was COUNTED into `total_pages` must have been
    // WRITTEN: the inner-tx appenders advance `next_page` by exactly the
    // page count `inner_kind_page_count` reported, the fixed/refund/value/
    // gas pages were spliced above, and the trailing confirm page occupies
    // the final slot — so the invariant is `next_page + 1 == total_pages`.
    //
    // If it ever fails, the renderer produced fewer (or more) pages than it
    // counted — i.e. a page that renders a signed value was dropped, or a
    // gate/renderer page-count divergence slipped through. Rather than show
    // a buffer with a hidden value we refuse to sign. This is the generic
    // net that closes the whole "signed-but-not-shown via a dropped page"
    // class, independent of any single presence flag being right
    // (audit 2026-06-27).
    if next_page + 1 != total_pages {
        return Err(());
    }

    // ── Final: confirm prompt ───────────────────────────────────────
    write_line(&mut pages.buf[next_page][0], "Long-press to");
    write_line(&mut pages.buf[next_page][1], "");
    write_line(&mut pages.buf[next_page][2], "L=Cancel");
    write_line(&mut pages.buf[next_page][3], "R=Confirm");

    Ok(pages)
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
    let (operation, to, raw, safe_address, refund_active, safe_value_nonzero, safe_tx_gas_nonzero) =
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
                // SAME FI-robust flags + helpers the renderer uses, so the
                // gate's `fixed` and the renderer's `total_pages` cannot
                // diverge (and a fault biases both toward over-counting →
                // refuse, the fail-closed direction).
                refund_is_active(&tx.gas_price, &tx.gas_token, &tx.refund_receiver),
                must_show_unless_robustly_skippable(all_zero(&tx.value)),
                must_show_unless_robustly_skippable(all_zero(&tx.safe_tx_gas)),
            )
        } else if let Some(e) = safe_exec {
            let d = &e.decoded;
            (
                d.operation,
                d.to,
                d.data,
                e.safe_address,
                refund_is_active(&d.gas_price, &d.gas_token, &d.refund_receiver),
                must_show_unless_robustly_skippable(all_zero(&d.value)),
                must_show_unless_robustly_skippable(all_zero(&d.safe_tx_gas)),
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
    // Shared overhead helper (header + refund + safeTxGas + confirm) — the
    // SAME function the renderer's `total_pages` uses — plus the inner-ETH
    // page, so the gate counts exactly what the renderer will produce.
    let fixed = safe_fixed_overhead_pages(refund_active, safe_tx_gas_nonzero)
        + usize::from(safe_value_nonzero);
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
        // 4 = header + recipient + amount + contract; +1 for the
        // transferFrom `From (debited)` page (kept in lockstep with
        // `append_erc20_tail_pages` and `multi_send::record_content_pages`).
        InnerKind::Erc20Known(call) | InnerKind::Erc20Unknown(call) => {
            4 + usize::from(matches!(call, Erc20Call::TransferFrom { .. }))
        }
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
            // P_n: "Empty call to:" + the FULL target address (rows 1-3),
            // resolver-aware. An empty call still triggers `to`'s
            // receive()/fallback(), and `to` is a signed field, so it must be
            // shown in full like every other inner `to`. EmptyCall was the one
            // inner kind that never repeated `to` in full — the old
            // `write_short_addr` showed 6 of 20 bytes and skipped the name DB
            // (audit 2026-06-26), violating the per-record divider's own
            // "ERC-20 / blind / mgmt pages repeat it in full" invariant. Stays
            // ONE page (the 40-hex / resolved name fills rows 1-3), so
            // `inner_kind_page_count` / `record_content_pages` (= 1) and the
            // multiSend page-budget lockstep are unchanged.
            write_line(&mut pages.buf[next_page][0], "Empty call to:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
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
    // From (debited account) — transferFrom only. The `from` is a signed
    // calldata operand that names a THIRD-PARTY account being pulled (not
    // the wallet/Safe), so it gets its own page; hiding it is the same
    // WYSIWYS gap closed on the direct ERC-20 renderers (audit 2026-06-18).
    // This +1 page for transferFrom is mirrored by `inner_kind_page_count`
    // and `multi_send::record_content_pages` so the multiSend page-budget
    // gate stays exact.
    if let Erc20Call::TransferFrom { from, .. } = call {
        write_line(&mut pages.buf[next_page][0], "From (debited):");
        let [_lbl, a, b, c] = &mut pages.buf[next_page];
        write_addr_full_or_name(a, b, c, from, ctx.chain_id, ctx.resolver);
        next_page += 1;
    }
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
            // Raw amount, decimals unknown. Render the FULL integer
            // magnitude (no decimals, "units" suffix) with a loud overflow
            // banner — NEVER a middle-truncated hex that hides the
            // magnitude (audit 2026-06-23 — Safe-inner unverified-ERC-20
            // amount magnitude-hiding drain). The companion can force this
            // `meta == None` arm for ANY token by withholding the optional
            // ERC-20 metadata trailer, so the old head-7/tail-6 hex (bytes
            // 7..26 dropped) let a benign-looking `0x000…0064` tail hide a
            // huge transfer the wallet/Safe was signing. This mirrors the
            // top-level `erc20_unknown` renderer (full decimal, loud
            // overflow) and the refund-page unknown-token treatment.
            write_line(&mut pages.buf[next_page][0], "Raw amount:");
            if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
                write_line(&mut pages.buf[next_page][1], "unlimited");
                write_line(&mut pages.buf[next_page][2], "");
                write_line(&mut pages.buf[next_page][3], "> next");
            } else {
                let units = Erc20Metadata {
                    chain_id: 0,
                    contract: [0u8; 20],
                    decimals: 0,
                    name: &[],
                    symbol: b"units",
                };
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                let fit = write_token_amount_two_rows(r1, r2, &amount, &units);
                write_line(
                    foot,
                    match fit {
                        AmountFit::Full => "> next",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
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
        // Use our own label so this can't be confused with the inner-tx
        // `write_nonce_row` "Nonce:" — but keep it short. On a 16-column row
        // "SafeTx Nonce: " (14 cols) left only 2 columns for digits, so any
        // nonce >= 100 (i.e. essentially every active Safe, whose nonce
        // increments per executed tx) rendered as the "!O" overflow marker and
        // the user could not read it to cross-check against the dApp. "SafeTx #"
        // (8 cols) leaves 8 digit columns (up to 99_999_999) — more than any
        // realistic Safe nonce; anything larger still falls to the loud marker.
        *row = [b' '; DISPLAY_COLS];
        let prefix = b"SafeTx #";
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

/// Decode the low 8 bytes of a 32-byte big-endian uint as a `u64`.
/// Returns `(value, overflowed)` with `overflowed == true` (and `value ==
/// u64::MAX`) when the high 24 bytes are non-zero — i.e. the operand
/// exceeds `u64::MAX`. Used for the `baseGas * gasPrice` base-cost page via
/// [`U256::saturating_mul_u64`]; a `baseGas` beyond `u64` makes the cost
/// astronomically large, which the caller renders as a loud `!HUGE`.
fn u64_be_tail(be: &[u8; 32]) -> (u64, bool) {
    let high_nonzero = be[..24].iter().any(|&b| b != 0);
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&be[24..32]);
    if high_nonzero {
        (u64::MAX, true)
    } else {
        (u64::from_be_bytes(tail), false)
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

// `write_raw_uint_two_rows` (head-7/tail-6 hex of a 32-byte amount) was
// removed 2026-06-23: it hid the middle 19 bytes of the signed amount, a
// magnitude-hiding WYSIWYS drain on the unverified-ERC-20 path. The
// "Raw amount:" page now renders the full integer magnitude via
// `write_token_amount_two_rows` with a loud overflow fallback (see the
// `meta == None` arm of `append_erc20_tail_pages`).

