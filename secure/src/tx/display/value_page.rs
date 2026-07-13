//! Dispatcher-level native-ETH `value` invariant (audit C-1 / H-2 / M-8).
//!
//! The outer UserOp `value` is signed verbatim into
//! `executeWithOffchainCount(ownerIndex, count, target, value, data)`, but
//! several renderers historically surfaced only token / inner-tx semantics
//! and never the native ETH — so a malicious companion could display a
//! benign token transfer while signing an ETH-draining `call{value}` to an
//! attacker contract.
//!
//! Rather than trust each renderer to opt in, EVERY sign confirm funnels
//! through [`enforce_native_value_page`] (called by
//! [`super::pick_sign_pages`]): when `value != 0` it splices a dedicated,
//! loud value page in right after the renderer's banner. A future renderer
//! physically cannot forget it.
//!
//! Lives in its own file (not `mod.rs`) so the host-test scaffold
//! (`crate::display_under_test`) can `#[path]`-mount it and exercise the
//! real body — `mod.rs`'s `pick_sign_pages` dispatcher pulls in
//! firmware-only deps and is gated `#[cfg(not(test))]`.

use super::primitives;
use super::Pages;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// SHA-256("") — the sentinel the companion sends for an absent
/// `paymasterAndData` (mirrors `crate::aa::userop::SHA256_EMPTY`; copied
/// here so the host-test `#[path]` mount of this file does not pull in the
/// `aa` crate). Used by [`enforce_paymaster_page`] to decide presence.
const SHA256_OF_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
    0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
    0xb8, 0x55,
];

/// One mandatory full signer-identity page per confirmation set.
pub(crate) const SIGNER_IDENTITY_PAGES: usize = 1;
/// One mandatory full target-contract page per transaction confirmation.
pub(crate) const TARGET_IDENTITY_PAGES: usize = 1;

type SignerIdentityPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];
type TargetIdentityPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// Splice the mandatory UserOp signer page immediately after the leading
/// banner.
///
/// `account_index` selects a distinct mnemonic-derived wallet, while `sender`
/// is the CREATE2 address independently derived and companion-bound in the
/// secure handler. Both are signed-context facts: omitting them lets a hostile
/// companion reuse otherwise identical intent pages while signing from a
/// different account. "Signer" is deliberate: a Safe or `transferFrom` call
/// may debit an address other than this outer PQ wallet, so labelling it
/// "From" would create a second trusted-display ambiguity. The address is
/// rendered in full EIP-55 form across all three remaining rows; no name
/// substitution or truncated fingerprint is permitted.
///
/// The page is unconditional and fails closed. A full page buffer or an
/// out-of-range account index returns `Err(())`, and every UserOp caller maps
/// that to a refusal before confirmation/signing.
#[inline(never)]
pub(crate) fn enforce_from_page(
    pages: &mut Pages,
    account_index: u32,
    sender: &[u8; 20],
) -> Result<(), ()> {
    let page = build_signer_identity_page(account_index, sender).ok_or(())?;
    let at = if pages.len >= 1 { 1 } else { 0 };
    let idx = insert_blank(pages, at)?;
    pages.buf[idx] = page;
    Ok(())
}

/// Exact all-64-byte readback predicate for the handler's FI completion gate.
pub(crate) fn from_page_matches(
    pages: &Pages,
    page_index: usize,
    account_index: u32,
    sender: &[u8; 20],
) -> bool {
    let Some(expected) = build_signer_identity_page(account_index, sender) else {
        return false;
    };
    let Some(actual) = pages.as_slice().get(page_index) else {
        return false;
    };
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

/// FI-hardened completion proof for [`enforce_from_page`].
///
/// The caller records `prior_len`, invokes the non-inlined inserter, scrubs the
/// ABI sentinel register, then requires this function to return
/// [`crate::fi::OK_SENTINEL`]. Skipping the insert leaves the length/page check
/// false; skipping this proof after the scrub leaves a non-OK return register.
#[inline(never)]
pub(crate) fn from_page_proof(
    pages: &Pages,
    prior_len: usize,
    account_index: u32,
    sender: &[u8; 20],
) -> u32 {
    let page_index = usize::from(prior_len >= 1);
    let Some(expected_len) = prior_len.checked_add(SIGNER_IDENTITY_PAGES) else {
        return crate::fi::FAIL_SENTINEL;
    };
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(pages.len == expected_len)
            && from_page_matches(pages, page_index, account_index, sender)
    })
}

fn build_signer_identity_page(
    account_index: u32,
    sender: &[u8; 20],
) -> Option<SignerIdentityPage> {
    // The wire field is exactly eight bits. Recheck at the display boundary so
    // a faulted flag decode cannot paint a truncated/aliased account number.
    if account_index > 255 {
        return None;
    }
    const PREFIX: &[u8] = b"Signer acct #";
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    let mut digits = [0u8; 3];
    let n = primitives::format_u64(u64::from(account_index), &mut digits)?;
    if PREFIX.len() + n > DISPLAY_COLS {
        return None;
    }
    page[0][..PREFIX.len()].copy_from_slice(PREFIX);
    page[0][PREFIX.len()..PREFIX.len() + n].copy_from_slice(&digits[..n]);
    let [_label, a, b, c] = &mut page;
    primitives::write_addr_full(a, b, c, sender);
    Some(page)
}

/// Insert the mandatory full target-contract page immediately after the
/// signer identity page.
///
/// ERC-7730 intent pages can otherwise consume the whole semantic surface
/// without showing the outer call target. A descriptor is bound to the target
/// in secure world, but that cryptographic binding does not tell the user which
/// contract will receive the signed call. The raw EIP-55 address is therefore
/// always shown for each single transaction / batch member, independent of the
/// selected semantic renderer or name database.
#[inline(never)]
pub(crate) fn enforce_target_page(
    pages: &mut Pages,
    target: &[u8; 20],
) -> Result<(), ()> {
    let page = build_target_identity_page(target);
    // Callers insert the signer page first, so index 2 establishes the fixed
    // banner → signer → target ordering. Clamp only for the pure helper's
    // empty/synthetic test use; the FI proof below requires the exact index.
    let at = core::cmp::min(2, pages.len);
    let idx = insert_blank(pages, at)?;
    pages.buf[idx] = page;
    Ok(())
}

/// Exact all-64-byte readback predicate for the mandatory target page.
pub(crate) fn target_page_matches(
    pages: &Pages,
    page_index: usize,
    target: &[u8; 20],
) -> bool {
    let expected = build_target_identity_page(target);
    let Some(actual) = pages.as_slice().get(page_index) else {
        return false;
    };
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

/// FI-hardened completion proof for [`enforce_target_page`].
///
/// Callers record `prior_len` after the signer proof, invoke the non-inlined
/// inserter, scrub the sentinel register, then require this independent
/// length/full-page recomputation to return `OK_SENTINEL`.
#[inline(never)]
pub(crate) fn target_page_proof(
    pages: &Pages,
    prior_len: usize,
    target: &[u8; 20],
) -> u32 {
    let Some(expected_len) = prior_len.checked_add(TARGET_IDENTITY_PAGES) else {
        return crate::fi::FAIL_SENTINEL;
    };
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(pages.len == expected_len)
            && target_page_matches(pages, 2, target)
    })
}

fn build_target_identity_page(target: &[u8; 20]) -> TargetIdentityPage {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    page[0].copy_from_slice(b"Target contract:");
    let [_label, a, b, c] = &mut page;
    primitives::write_addr_full(a, b, c, target);
    page
}

/// Splice a loud native-ETH `value` page into an already-rendered page set
/// when `value != 0`, reporting whether the WYSIWYS invariant holds.
///
/// The page lands at index 1 (immediately after the banner) for
/// prominence. Two hardening properties (audit 2026-06-18 — native-value
/// WYSIWYS gate), because the outer UserOp `value` is signed verbatim into
/// `executeWithOffchainCount(...)` and forwarded on chain via
/// `target.call{value: value}(data)` — so hiding it is an ETH drain behind
/// a benign confirm (the same class as audit C-1 / H-2 / M-8):
///
///   * **FI-hardened skip decision.** The dangerous outcome is *skipping*
///     the value page on a non-zero value. The skip path is therefore
///     gated on a Hamming-distant sentinel proof that `value == 0`
///     (`fi::check_true_into_sentinel` double-evaluates the predicate with
///     `wait_random` between, then commits the verdict to a volatile
///     sentinel). A single fault that tries to force the skip on a
///     non-zero value cannot produce `OK_SENTINEL`, so control falls
///     through to the mandatory splice — matching the FI bar every other
///     sign-path gate already meets. A bare `if value.is_zero()` was one
///     instruction-skip away from dropping the page.
///   * **Fails CLOSED on a full page buffer.** If `value != 0` and the
///     page cannot be spliced (`pages.len == MAX_PAGES`), returns
///     `Err(())` so the caller REFUSES to sign rather than release a
///     signature over ETH the user never saw. The old code silently
///     skipped on a false assumption ("every renderer that reaches
///     `MAX_PAGES` already shows the value"), which is untrue for the
///     dynamically-grown ERC-7730 calldata renderer (`6 + N_visible`
///     pages): a future ≥18-visible-field payable descriptor would have
///     dropped the value page with no fault at all. Refusing is the
///     dispatcher-level analogue of the multiSend gate's "refuse rather
///     than truncate" rule.
///
/// Returns `Ok(())` when the invariant holds (value robustly zero, or the
/// loud page was spliced) and `Err(())` when a mandatory value page could
/// not be spliced — the caller must map that to a refuse-to-sign. The
/// `Result` is `#[must_use]` by construction, so `pick_sign_pages`'s `?`
/// can never silently drop the refusal.
pub(super) fn enforce_native_value_page(
    pages: &mut Pages,
    value: &U256,
    chain_id: u64,
) -> Result<(), ()> {
    // Skip ONLY on a sentinel-robust proof that `value == 0`. `black_box`
    // keeps the two internal evaluations of the predicate from collapsing
    // into one (F-1). Any other outcome — value non-zero, or a glitched
    // zero-check — flows to the mandatory splice below.
    let may_skip =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(value.is_zero()));
    if may_skip == crate::fi::OK_SENTINEL {
        return Ok(());
    }
    // value is non-zero (or the zero-check was faulted): a loud value page
    // is MANDATORY. Splice it; `?` fails CLOSED when the buffer is full so
    // the caller refuses to sign instead of hiding the ETH.
    let at = if pages.len >= 1 { 1 } else { 0 };
    let idx = insert_blank(pages, at)?;
    primitives::write_native_currency_row(pages.row_mut(idx, 0), b"! NATIVE ", chain_id, b"");
    let [_lbl, r1, r2, foot] = pages.page_mut(idx);
    let fit = primitives::write_native_amount_two_rows(r1, r2, value, chain_id);
    primitives::write_line(
        foot,
        match fit {
            primitives::AmountFit::Full => "> next",
            primitives::AmountFit::Overflow => "!AMOUNT OVERFLOW",
        },
    );
    Ok(())
}

/// Splice the two standard gas/fee pages (identical to value_transfer
/// pages 3-4) immediately before the renderer's trailing page (the confirm
/// prompt on the Safe and CoW surfaces).
///
/// Called by [`super::pick_sign_pages`] for the Safe / CoW / ERC-7730
/// surfaces, which — unlike every other renderer — do not emit gas pages
/// of their own. The five EntryPoint v0.6 fee fields are committed to by
/// the UserOp signature and the wallet pays the EntryPoint prefund out of
/// its own native ETH; hiding them is a fee-bomb drain behind a benign
/// confirm (audit 2026-06-19 — the WYSIWYS sibling of the native-value
/// gate above).
///
/// Unlike [`enforce_native_value_page`] there is no skip-on-zero decision
/// (gas is shown unconditionally, matching every other renderer), so there
/// is no FI skip gate to harden here. The only failure mode is a full page
/// buffer, which FAILS CLOSED: the check is performed up-front so the
/// splice is atomic (never a single orphaned gas page) and the caller maps
/// `Err(())` to a refuse-to-sign.
pub(super) fn enforce_gas_pages(pages: &mut Pages, tx: &Eip1559Tx) -> Result<(), ()> {
    // Atomic budget check: both pages or neither.
    if pages.len + 2 > super::MAX_PAGES {
        return Err(());
    }
    // Insert just before the trailing page so the gas pages read after the
    // semantic content, matching value_transfer's "Max fee" / "Worst-case"
    // ordering. `at` clamps to 0 for the (impossible here) empty-buffer case.
    let at = pages.len.saturating_sub(1);
    // Page A: "Max fee:" + max_fee_per_gas (gwei) + priority tip.
    let a = insert_blank(pages, at)?;
    primitives::write_line(pages.row_mut(a, 0), "Max fee:");
    let _ = primitives::write_gwei(pages.row_mut(a, 1), &tx.max_fee_per_gas);
    primitives::write_tip_row(pages.row_mut(a, 2), &tx.max_priority_fee_per_gas);
    primitives::write_line(pages.row_mut(a, 3), "> next");
    // Page B: "Worst-case:" + max_fee_per_gas * gas_limit (ETH) + gas limit.
    let b = insert_blank(pages, a + 1)?;
    primitives::write_line(pages.row_mut(b, 0), "Worst-case:");
    primitives::write_native_fee_budget_row(
        pages.row_mut(b, 1),
        &tx.max_fee_per_gas,
        tx.gas_limit,
        tx.chain_id,
    );
    primitives::write_gas(pages.row_mut(b, 2), tx.gas_limit);
    primitives::write_line(pages.row_mut(b, 3), "> next");
    Ok(())
}

/// Splice a loud "! PAYMASTER SET" page when the UserOp carries a
/// non-empty `paymasterAndData` field, reporting whether the WYSIWYS
/// invariant holds.
///
/// **STATUS — ACCEPTED RISK, not a ship blocker (decision 2026-06-27, owner
/// confirmed 2026-06-28).** The paymaster-unshown gap below was assessed and
/// explicitly does NOT warrant a fix: PQ1 ships no paymaster-using companion
/// flow, so the page is *optional* belt-and-suspenders hardening retained in
/// the tree rather than a required WYSIWYS closure. It is wired into both
/// sign handlers and behaves exactly like the mandatory gates, but its
/// absence would not block a release. Do not re-raise the underlying issue;
/// keep this note if the gate is touched.
///
/// The EntryPoint v0.6 `paymasterAndData` is committed to by the UserOp
/// signature (its digest is folded into `compute_sphincs_digest_v06`),
/// but the firmware only ever receives `sha256(paymasterAndData)` over the
/// wire — it cannot show *which* paymaster, only that one is present. A
/// paymaster materially changes the transaction's economics: gas is paid by
/// the sponsor instead of the wallet's native ETH, and a *token* paymaster's
/// `postOp` debits the user in ERC-20 tokens. A malicious companion can
/// route an otherwise-benign UserOp through a paymaster the user previously
/// approved, draining tokens as "gas" behind a confirm whose only fee page
/// ("Worst-case: X ETH") actively misdirects. Hiding the paymaster is
/// therefore the same signed-but-not-shown class as the native-value gate
/// above (audit 2026-06-27).
///
/// `paymaster_and_data_hash` is the on-wire `sha256(paymasterAndData)`
/// (the companion sends [`SHA256_OF_EMPTY`] when no paymaster is set), and
/// presence is recomputed from those bytes *inside* the sentinel closure so
/// a single glitch on one comparison cannot force the skip. Two hardening
/// properties mirror [`enforce_native_value_page`]:
///
///   * **FI-hardened skip decision.** The dangerous outcome is *skipping*
///     the warning when a paymaster IS present, so the skip path is gated on
///     a Hamming-distant sentinel proof that the hash equals the empty-bytes
///     hash. A single fault that tries to force the skip on a present
///     paymaster cannot produce `OK_SENTINEL`, so control falls through to
///     the mandatory splice.
///   * **Fails CLOSED on a full page buffer.** If a paymaster is present and
///     the page cannot be spliced (`pages.len == MAX_PAGES`), returns
///     `Err(())` so the caller REFUSES to sign rather than release a
///     signature over a sponsor the user never saw.
///
/// Returns `Ok(())` when the invariant holds (no paymaster, or the loud page
/// was spliced) and `Err(())` when a mandatory page could not be spliced.
pub(crate) fn enforce_paymaster_page(
    pages: &mut Pages,
    paymaster_and_data_hash: &[u8; 32],
) -> Result<(), ()> {
    // Skip ONLY on a sentinel-robust proof that the hash is the empty-bytes
    // hash (no paymaster). Recompute the byte compare inside the closure (it
    // is double-evaluated, `black_box`'d to defeat CSE) so a glitch on a
    // single load/compare cannot mask a present paymaster. Any other
    // outcome — non-empty hash, or a glitched compare — flows to the
    // mandatory splice below.
    let may_skip = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(*paymaster_and_data_hash == SHA256_OF_EMPTY)
    });
    if may_skip == crate::fi::OK_SENTINEL {
        return Ok(());
    }
    // Paymaster present (or the absence-check was faulted): a loud page is
    // MANDATORY. Splice it right after the banner; `?` fails CLOSED when the
    // buffer is full so the caller refuses to sign instead of hiding the
    // sponsor.
    let at = if pages.len >= 1 { 1 } else { 0 };
    let idx = insert_blank(pages, at)?;
    primitives::write_line(pages.row_mut(idx, 0), "! PAYMASTER SET");
    primitives::write_line(pages.row_mut(idx, 1), "Gas sponsored");
    primitives::write_line(pages.row_mut(idx, 2), "may debit tokens");
    primitives::write_line(pages.row_mut(idx, 3), "> next");
    Ok(())
}

/// Insert a blank page at index `at`, shifting the pages currently at
/// `at..len` one slot toward the back. Returns the index of the new
/// (cleared) page, or `Err(())` when the buffer is already full.
fn insert_blank(pages: &mut Pages, at: usize) -> Result<usize, ()> {
    if pages.len >= super::MAX_PAGES {
        return Err(());
    }
    let at = core::cmp::min(at, pages.len);
    // Shift back-to-front so we never clobber a page we still need to move.
    // `Page` is `Copy`, so the array assignment is a byte copy.
    let mut i = pages.len;
    while i > at {
        pages.buf[i] = pages.buf[i - 1];
        i -= 1;
    }
    pages.buf[at] = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    pages.len += 1;
    Ok(at)
}

/// WYSIWYS per-flow address-match gate for the DIRECT ERC-20 render path
/// (audit 2026-06-28 — `v1_ms` metadata mis-attribution).
///
/// `crate::tx::display::pick_sign_pages_inner` reaches its direct ERC-20
/// branch only when NO Safe / CoW / v1 context verified — i.e. the wallet
/// itself is `msg.sender` and `tx.to` IS the token being called. The only
/// legitimate metadata attribution there is therefore `meta.contract ==
/// tx.to`.
///
/// The handler supplies only Merkle+chain-verified metadata. The dispatcher
/// then grants it independently per selected surface: verified Safe execution
/// facts for Safe, signed tokenPath resolution for ERC-7730, and this exact
/// outer-target equality for direct ERC-20. A `transfer` to token Y must never
/// render with token T's name/symbol/decimals merely because another surface
/// could legitimately use T.
///
/// Returns `true` only when the bundle's contract equals the call target,
/// so the caller can fall back to the raw `erc20_unknown` render on any
/// mismatch (including the no-target contract-creation shape). This is the
/// direct-path gate is deliberately local to the branch that consumes it.
#[must_use]
pub(crate) fn direct_erc20_meta_matches(
    meta_contract: &[u8; 20],
    tx_to: Option<&[u8; 20]>,
) -> bool {
    tx_to.is_some_and(|to| meta_contract == to)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_wei() -> U256 {
        let mut v = [0u8; 32];
        v[31] = 1;
        U256(v)
    }

    fn gwei(n: u64) -> U256 {
        // n * 1e9 wei, fits a u64 for any realistic gas price.
        let wei = (n as u128) * 1_000_000_000u128;
        let mut v = [0u8; 32];
        v[16..32].copy_from_slice(&wei.to_be_bytes());
        U256(v)
    }

    fn fee_tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: gwei(2),
            max_fee_per_gas: gwei(50),
            gas_limit: 21_000,
            to: Some([0x11u8; 20]),
            value: U256::zero(),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
            userop_fields: None,
        }
    }

    #[test]
    fn from_page_shows_account_and_full_derived_address() {
        let sender = [0xabu8; 20];
        let mut pages = Pages::with_len(2);
        primitives::write_line(pages.row_mut(0, 0), "Sign transfer?");
        primitives::write_line(pages.row_mut(1, 3), "R=Confirm");

        assert!(enforce_from_page(&mut pages, 255, &sender).is_ok());
        assert_eq!(pages.len, 3);
        assert_eq!(&pages.buf[1][0], b"Signer acct #255");

        // The identity page uses the exact full-address primitive: 0x + all
        // 40 EIP-55 nibbles across rows 1..=3, never a short address/name.
        let mut expected = [[b' '; DISPLAY_COLS]; 3];
        let [a, b, c] = &mut expected;
        primitives::write_addr_full(a, b, c, &sender);
        assert_eq!(&pages.buf[1][1..4], &expected);

        // Existing banner/confirm content is shifted, not overwritten.
        assert_eq!(&pages.buf[0][0][..14], b"Sign transfer?");
        assert_eq!(&pages.buf[2][3][..9], b"R=Confirm");
    }

    #[test]
    fn account_flip_changes_confirmed_from_page() {
        let sender = [0x42u8; 20];
        let mut account_zero = Pages::with_len(1);
        let mut account_one = Pages::with_len(1);
        assert!(enforce_from_page(&mut account_zero, 0, &sender).is_ok());
        assert!(enforce_from_page(&mut account_one, 1, &sender).is_ok());
        assert_ne!(
            account_zero.buf[1], account_one.buf[1],
            "changing only account_index must change trusted-display bytes"
        );
        assert_eq!(&account_zero.buf[1][0][..14], b"Signer acct #0");
        assert_eq!(&account_one.buf[1][0][..14], b"Signer acct #1");
        assert!(from_page_matches(&account_zero, 1, 0, &sender));
        assert!(!from_page_matches(&account_zero, 1, 1, &sender));
    }

    #[test]
    fn every_sender_byte_is_bound_into_the_signer_page() {
        let sender = [0x42u8; 20];
        let mut pages = Pages::with_len(1);
        enforce_from_page(&mut pages, 7, &sender).unwrap();
        assert!(from_page_matches(&pages, 1, 7, &sender));
        for i in 0..sender.len() {
            let mut changed = sender;
            changed[i] ^= 1;
            assert!(!from_page_matches(&pages, 1, 7, &changed));
        }
    }

    #[test]
    fn signer_page_completion_proof_fails_before_or_after_corruption() {
        let sender = [0x24u8; 20];
        let mut pages = Pages::with_len(1);
        assert_ne!(from_page_proof(&pages, 1, 3, &sender), crate::fi::OK_SENTINEL);
        enforce_from_page(&mut pages, 3, &sender).unwrap();
        assert_eq!(from_page_proof(&pages, 1, 3, &sender), crate::fi::OK_SENTINEL);
        pages.buf[1][2][7] ^= 1;
        assert_ne!(from_page_proof(&pages, 1, 3, &sender), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn target_page_follows_signer_and_shows_full_address() {
        let sender = [0x11u8; 20];
        let target = [0xabu8; 20];
        let mut pages = Pages::with_len(1);
        enforce_from_page(&mut pages, 4, &sender).unwrap();
        enforce_target_page(&mut pages, &target).unwrap();

        assert_eq!(pages.len, 3);
        assert_eq!(&pages.buf[1][0][..14], b"Signer acct #4");
        assert_eq!(&pages.buf[2][0], b"Target contract:");
        let mut expected = [[b' '; DISPLAY_COLS]; 3];
        let [a, b, c] = &mut expected;
        primitives::write_addr_full(a, b, c, &target);
        assert_eq!(&pages.buf[2][1..4], &expected);
        assert!(target_page_matches(&pages, 2, &target));
    }

    #[test]
    fn target_flip_changes_page_and_completion_proof_is_fail_closed() {
        let sender = [0x22u8; 20];
        let target = [0x44u8; 20];
        let mut pages = Pages::with_len(1);
        enforce_from_page(&mut pages, 0, &sender).unwrap();
        let before = pages.len;
        assert_ne!(
            target_page_proof(&pages, before, &target),
            crate::fi::OK_SENTINEL
        );
        enforce_target_page(&mut pages, &target).unwrap();
        assert_eq!(
            target_page_proof(&pages, before, &target),
            crate::fi::OK_SENTINEL
        );
        for i in 0..target.len() {
            let mut changed = target;
            changed[i] ^= 1;
            assert!(!target_page_matches(&pages, 2, &changed));
            assert_ne!(
                target_page_proof(&pages, before, &changed),
                crate::fi::OK_SENTINEL
            );
        }
        pages.buf[2][3][9] ^= 1;
        assert_ne!(
            target_page_proof(&pages, before, &target),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn target_page_full_buffer_fails_closed() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        assert!(enforce_target_page(&mut pages, &[0x55u8; 20]).is_err());
        assert_eq!(pages.len, super::super::MAX_PAGES);
    }

    #[test]
    fn from_page_full_buffer_and_bad_account_fail_closed() {
        let sender = [0x11u8; 20];
        let mut full = Pages::with_len(super::super::MAX_PAGES);
        assert!(enforce_from_page(&mut full, 0, &sender).is_err());
        assert_eq!(full.len, super::super::MAX_PAGES);

        let mut bad_account = Pages::with_len(1);
        assert!(enforce_from_page(&mut bad_account, 256, &sender).is_err());
        assert_eq!(bad_account.len, 1, "invalid account must not add a page");
    }

    /// Audit C-1 regression. The invariant is applied uniformly to the
    /// final page set regardless of which renderer (TxKind) produced it,
    /// so a single test over a synthetic banner+body+confirm set proves
    /// the per-TxKind guarantee: a non-zero `value` always yields a loud
    /// value page right after the banner.
    #[test]
    fn nonzero_value_inserts_loud_value_page_after_banner() {
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "! Unknown token");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        assert!(enforce_native_value_page(&mut pages, &one_wei(), 1).is_ok());
        assert_eq!(pages.len, 4, "a value page must be inserted");
        // Banner stays first; the loud value page is now second.
        assert_eq!(&pages.buf[0][0][..15], b"! Unknown token");
        assert_eq!(&pages.buf[1][0][..12], b"! NATIVE ETH");
        // The original body shifted back by one — nothing clobbered.
        assert_eq!(&pages.buf[3][2][..8], b"L=Cancel");
    }

    #[test]
    fn nonzero_value_page_uses_chain_native_ticker() {
        let mut pages = Pages::with_len(2);
        assert!(enforce_native_value_page(&mut pages, &one_wei(), 56).is_ok());
        assert_eq!(&pages.buf[1][0][..12], b"! NATIVE BNB");
        let rows = &pages.buf[1];
        assert!(rows.iter().all(|row| !row.windows(3).any(|w| w == b"ETH")));
    }

    /// Audit 2026-06-28 regression — `v1_ms` metadata mis-attribution.
    /// On the DIRECT ERC-20 render path the bundle metadata may only be
    /// applied when its contract matches the call target. A bundle for
    /// token T (e.g. routed via a bogus `safe_v1` multiSend record) must
    /// NOT be applied to a `transfer` whose `tx.to` is the unrelated token
    /// Y — otherwise the OLED would show "Send <T.symbol>" with T's
    /// decimals for a transfer of Y.
    #[test]
    fn direct_erc20_meta_gate_rejects_mismatched_contract() {
        let token_y = [0xAAu8; 20]; // the real call target
        let token_t = [0xBBu8; 20]; // the bundle's (mis-attributed) token
        // Mismatch → reject (renderer falls back to erc20_unknown).
        assert!(!direct_erc20_meta_matches(&token_t, Some(&token_y)));
    }

    /// Positive: a legitimate direct ERC-20 call (bundle contract == the
    /// call target) is accepted, so the rich `erc20_known` render still
    /// fires for honest transfers.
    #[test]
    fn direct_erc20_meta_gate_accepts_matching_contract() {
        let token = [0xCDu8; 20];
        assert!(direct_erc20_meta_matches(&token, Some(&token)));
    }

    /// A contract-creation / no-`to` shape can never match a token bundle,
    /// so the gate declines (fail-safe to raw render) rather than panicking
    /// or accepting a bundle for a `None` target.
    #[test]
    fn direct_erc20_meta_gate_rejects_absent_target() {
        let token = [0x01u8; 20];
        assert!(!direct_erc20_meta_matches(&token, None));
    }

    /// A near-miss (single trailing byte differs) is still a mismatch —
    /// the compare is full-width, not a truncated prefix.
    #[test]
    fn direct_erc20_meta_gate_is_full_width() {
        let mut a = [0x42u8; 20];
        let mut b = [0x42u8; 20];
        a[19] = 0x00;
        b[19] = 0x01;
        assert!(!direct_erc20_meta_matches(&a, Some(&b)));
    }

    /// A zero `value` must NOT add a page (no spurious "0 ETH" page), and
    /// reports `Ok` (invariant holds — nothing to show).
    #[test]
    fn zero_value_adds_no_page() {
        let mut pages = Pages::with_len(3);
        assert!(enforce_native_value_page(&mut pages, &U256::zero(), 1).is_ok());
        assert_eq!(pages.len, 3);
    }

    /// `insert_blank` on a full buffer fails closed instead of panicking,
    /// so the invariant degrades gracefully rather than overrunning.
    #[test]
    fn insert_blank_on_full_buffer_is_err() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        assert!(insert_blank(&mut pages, 1).is_err());
    }

    /// Audit 2026-06-18 regression — FAIL CLOSED. A non-zero `value` that
    /// cannot be spliced because the renderer already filled the page
    /// budget must return `Err(())` (caller refuses to sign), NOT silently
    /// drop the loud ETH page. Pages are left unchanged so nothing
    /// confirmable hides the value.
    #[test]
    fn nonzero_value_full_buffer_fails_closed() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        let before = pages.len;
        assert!(
            enforce_native_value_page(&mut pages, &one_wei(), 1).is_err(),
            "non-zero value on a full buffer must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced or dropped");
    }

    /// A non-zero value with exactly one free slot must splice the loud
    /// page (the common case for the short value-hiding renderers, which
    /// never approach the cap).
    #[test]
    fn nonzero_value_with_room_splices_and_reports_ok() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES - 1);
        assert!(enforce_native_value_page(&mut pages, &one_wei(), 1).is_ok());
        assert_eq!(pages.len, super::super::MAX_PAGES);
        assert_eq!(&pages.buf[1][0][..12], b"! NATIVE ETH");
    }

    /// Audit 2026-06-19 — gas/fee WYSIWYS splice. The two gas pages are
    /// inserted right before the renderer's trailing (confirm) page, so a
    /// Safe/CoW confirm can no longer hide the signed maxFeePerGas / gas
    /// limits. Banner stays first, confirm stays last.
    #[test]
    fn gas_pages_spliced_before_confirm() {
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "Sign CowSwap?");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        assert!(enforce_gas_pages(&mut pages, &fee_tx()).is_ok());
        assert_eq!(pages.len, 5, "two gas pages must be inserted");
        // Original banner first; confirm shifted to the last slot.
        assert_eq!(&pages.buf[0][0][..13], b"Sign CowSwap?");
        assert_eq!(&pages.buf[4][2][..8], b"L=Cancel");
        // Gas pages sit just before the confirm page.
        assert_eq!(&pages.buf[2][0][..8], b"Max fee:");
        assert_eq!(&pages.buf[3][0][..11], b"Worst-case:");
    }

    /// FAIL CLOSED + ATOMIC. With fewer than two free slots the gas splice
    /// must refuse (caller refuses to sign) and leave the page set
    /// untouched — never a single orphaned gas page hiding the other.
    #[test]
    fn gas_pages_insufficient_room_fails_closed_atomically() {
        // Exactly one free slot — not enough for the two-page splice.
        let mut pages = Pages::with_len(super::super::MAX_PAGES - 1);
        let before = pages.len;
        assert!(
            enforce_gas_pages(&mut pages, &fee_tx()).is_err(),
            "fewer than two free slots must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced (atomic)");
    }

    /// Audit 2026-06-27 — paymaster WYSIWYS. A present paymaster must splice
    /// a loud page right after the banner so the user can never authorise a
    /// sponsored UserOp (whose token-paymaster may debit ERC-20 for "gas")
    /// without seeing it.
    #[test]
    fn paymaster_present_inserts_loud_page_after_banner() {
        let present = [0x11u8; 32]; // any non-empty-bytes hash
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "Send ETH?");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        assert!(enforce_paymaster_page(&mut pages, &present).is_ok());
        assert_eq!(pages.len, 4, "a paymaster page must be inserted");
        assert_eq!(&pages.buf[0][0][..9], b"Send ETH?");
        assert_eq!(&pages.buf[1][0][..15], b"! PAYMASTER SET");
        assert_eq!(&pages.buf[3][2][..8], b"L=Cancel");
    }

    /// Absent paymaster (hash == SHA-256("")) must add no page and report Ok.
    #[test]
    fn paymaster_absent_adds_no_page() {
        let mut pages = Pages::with_len(3);
        assert!(enforce_paymaster_page(&mut pages, &SHA256_OF_EMPTY).is_ok());
        assert_eq!(pages.len, 3);
    }

    /// FAIL CLOSED. A present paymaster that cannot be spliced because the
    /// renderer already filled the budget must return `Err(())` (caller
    /// refuses to sign), never silently drop the warning.
    #[test]
    fn paymaster_present_full_buffer_fails_closed() {
        let present = [0x11u8; 32];
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        let before = pages.len;
        assert!(
            enforce_paymaster_page(&mut pages, &present).is_err(),
            "present paymaster on a full buffer must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced or dropped");
    }
}
