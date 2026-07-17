//! `pick_sign_pages` — the CMD_SIGN_USEROP trusted-UI render dispatcher.
//!
//! Extracted verbatim from `tx/display/mod.rs` (2026-07-06) into its own
//! file so the WYSIWYS glue harness can `#[path]`-mount the REAL body on
//! the host (see `crate::display_under_test::dispatch` and
//! `display_under_test/wysiwys_dispatch_differential_tests.rs`). Every
//! sibling-renderer reference is `super::`-qualified so the body resolves
//! identically under both parents:
//!
//!   * production: `super` = `crate::tx::display` (this directory's
//!     `mod.rs`, which declares `mod dispatch;` under `cfg(not(test))`),
//!   * host tests: `super` = `crate::display_under_test` (the scaffold,
//!     which mounts the same per-renderer source files).
//!
//! No logic change — the function bodies are byte-identical to the
//! pre-extraction `mod.rs` versions apart from the path qualification.

const UNSET_PAGE_INDEX: usize = usize::MAX;

/// Caller-owned receipts for dispatcher-appended native-value and legacy-fee
/// pages. The secure handler keeps this object alive until the final confirm
/// boundary, so skipping the dispatcher enforcer, its immediate proof, or the
/// later complete-set recheck leaves an independently observable failure.
pub(crate) struct DispatchPageProofs {
    native_prior_len: usize,
    legacy_fee_prior_len: usize,
    native_cfi: crate::fi::CfiCounter,
    legacy_fee_cfi: crate::fi::CfiCounter,
}

impl DispatchPageProofs {
    pub(crate) const fn new() -> Self {
        Self {
            native_prior_len: UNSET_PAGE_INDEX,
            legacy_fee_prior_len: UNSET_PAGE_INDEX,
            native_cfi: crate::fi::CfiCounter::new(),
            legacy_fee_cfi: crate::fi::CfiCounter::new(),
        }
    }

    fn is_pristine(&self) -> bool {
        self.native_prior_len == UNSET_PAGE_INDEX
            && self.legacy_fee_prior_len == UNSET_PAGE_INDEX
    }

    /// Account for a caller-owned prefix wrapper (the batch banner) that is
    /// constructed after dispatch. A skipped or wrong shift makes the final
    /// exact-index proof fail closed.
    pub(crate) fn shift_indices(&mut self, by: usize) -> Result<(), ()> {
        self.native_prior_len = self.native_prior_len.checked_add(by).ok_or(())?;
        if self.legacy_fee_prior_len != UNSET_PAGE_INDEX {
            self.legacy_fee_prior_len =
                self.legacy_fee_prior_len.checked_add(by).ok_or(())?;
        }
        Ok(())
    }

    /// Final-boundary CFI/content/uniqueness recheck after every later append.
    #[inline(never)]
    pub(crate) fn final_set_proof(
        &self,
        pages: &super::Pages,
        tx: &crate::tx::eip1559::Eip1559Tx,
        legacy_fee_required: bool,
    ) -> u32 {
        let native_cfi = self
            .native_cfi
            .check_into_sentinel(super::value_page::NATIVE_VALUE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let native_pages = super::value_page::native_value_final_set_proof(
            pages,
            self.native_prior_len,
            &tx.value,
            tx.chain_id,
        );
        crate::fi::scrub_sentinel_register();
        let legacy_cfi = self.legacy_fee_cfi.check_into_sentinel(if legacy_fee_required {
            super::value_page::LEGACY_FEE_CFI_EXPECTED
        } else {
            crate::fi::CfiCounter::INIT_VALUE
        });
        crate::fi::scrub_sentinel_register();
        let legacy_pages = if legacy_fee_required {
            super::value_page::legacy_fee_pages_final_set_proof(
                pages,
                self.legacy_fee_prior_len,
                tx,
            )
        } else {
            crate::fi::check_true_into_sentinel(|| {
                core::hint::black_box(self.legacy_fee_prior_len == UNSET_PAGE_INDEX)
            })
        };
        let all_ok = native_cfi == crate::fi::OK_SENTINEL
            && native_pages == crate::fi::OK_SENTINEL
            && legacy_cfi == crate::fi::OK_SENTINEL
            && legacy_pages == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(all_ok))
    }
}

/// Safe/CoW renderers omit the legacy friendly fee envelope; all other
/// renderer branches already produce it themselves.
#[must_use]
pub(crate) const fn legacy_fee_pages_required(
    cow_present: bool,
    safe_v1_present: bool,
    safe_exec_present: bool,
) -> bool {
    cow_present || safe_v1_present || safe_exec_present
}

/// Pick the right renderer for a CMD_SIGN_USEROP trusted-UI confirm.
///
/// Centralises the priority ladder — the handler stays a pure
/// orchestrator and the "which display wins when multiple trailers
/// verify" decision lives in one place:
///
///   1. Native CoW EIP-712 (full GPv2Order breakdown from the
///      secure-world-decoded canonical order).
///   2. Safe v1 inner-tx render (verified canonical SafeTx).
///   3. ERC-7730 descriptor (verified against the firmware-pinned
///      `ERC7730_DESCRIPTORS_ROOT`; binding cross-checked against
///      `(chain_id, to)`).
///   4. Known-call omission filter: a registry-known/Bloom-positive tuple
///      without a successfully bound descriptor hard-refuses.
///   5. Plain value transfer (empty inner calldata).
///   6. ERC-20 with verified metadata (token name/symbol/decimals).
///   7. ERC-20 shape-only (unverified token — bare hex decode).
///   8. Typed-call selector + verified ABI walk.
///   9. Blind-sign, only after known-call non-membership succeeds.
///
/// Ordering is load-bearing. In particular, the native CoW route must
/// retain priority over generic typed-call/descriptor rendering so a
/// setPreSignature UserOp renders the complete order intent. The handler's
/// downgrade-mitigation gate enforces this separately at refuse-to-sign
/// level. (2) is above (3) so a Safe
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
#[allow(clippy::too_many_arguments)]
pub fn pick_sign_pages(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    device_signer: &[u8; 20],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    proofs: &mut DispatchPageProofs,
) -> Result<super::Pages, ()> {
    if !proofs.is_pristine() {
        return Err(());
    }
    // `pick_sign_pages_inner` returns `Err(())` when a Safe-surface render
    // refuses (page budget exceeded / page-accounting self-check failed);
    // propagate it so the handler maps it to a refuse-to-sign rather than
    // showing a buffer with a hidden signed value (audit 2026-06-27).
    let mut pages = pick_sign_pages_inner(
        tx,
        inner_data,
        device_signer,
        v3,
        safe_v1,
        safe_exec,
        erc7730,
        erc20,
        selector,
        resolver,
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
    proofs.native_prior_len = pages.len;
    super::value_page::enforce_native_value_page(
        &mut pages,
        &tx.value,
        tx.chain_id,
        &mut proofs.native_cfi,
    )?;
    crate::fi::scrub_sentinel_register();
    let native_cfi_verdict = proofs
        .native_cfi
        .check_into_sentinel(super::value_page::NATIVE_VALUE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let native_page_verdict = super::value_page::native_value_page_proof(
        &pages,
        proofs.native_prior_len,
        &tx.value,
        tx.chain_id,
    );
    if native_cfi_verdict != crate::fi::OK_SENTINEL
        || native_page_verdict != crate::fi::OK_SENTINEL
    {
        return Err(());
    }

    // Dispatcher-level WYSIWYS invariant (audit 2026-06-19 — gas/fee pages).
    //
    // The five signed EntryPoint v0.6 fee fields (callGasLimit,
    // verificationGasLimit, preVerificationGas, maxFeePerGas,
    // maxPriorityFeePerGas) are committed to by the UserOp signature, and the
    // wallet pays the resulting EntryPoint prefund out of its own native ETH.
    // Most renderers emit the two standard gas pages inline (the same
    // "Max fee" / "Worst-case" pair value_transfer shows), but the Safe and
    // CoW surfaces historically did NOT — so a fee-bomb UserOp (huge
    // maxFeePerGas / gas limits, no paymaster) drained the wallet's ETH as
    // gas behind a benign Safe/CoW confirm with no fee page on screen.
    //
    // Rather than trust each of those renderers to opt in, splice the same
    // two pages here for exactly the flows that lack them. `needs_gas`
    // mirrors the branch precedence in `pick_sign_pages_inner`: any
    // v3 / safe trailer routes to a gas-less renderer; every other
    // outcome (erc7730 / value / erc20 / typed-call / blind-sign) already
    // shows gas, so splicing there would DOUBLE the pages. Fails CLOSED on a
    // full buffer (same refuse-to-sign contract as the value page).
    let needs_gas = legacy_fee_pages_required(
        v3.is_some(),
        safe_v1.is_some(),
        safe_exec.is_some(),
    );
    if needs_gas {
        proofs.legacy_fee_prior_len = pages.len;
        super::value_page::enforce_gas_pages(
            &mut pages,
            tx,
            &mut proofs.legacy_fee_cfi,
        )?;
        crate::fi::scrub_sentinel_register();
        let legacy_fee_cfi_verdict = proofs
            .legacy_fee_cfi
            .check_into_sentinel(super::value_page::LEGACY_FEE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let legacy_fee_page_verdict = super::value_page::legacy_fee_pages_proof(
            &pages,
            proofs.legacy_fee_prior_len,
            tx,
        );
        if legacy_fee_cfi_verdict != crate::fi::OK_SENTINEL
            || legacy_fee_page_verdict != crate::fi::OK_SENTINEL
        {
            return Err(());
        }
    }
    Ok(pages)
}

#[allow(clippy::too_many_arguments)]
fn pick_sign_pages_inner(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    device_signer: &[u8; 20],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
) -> Result<super::Pages, ()> {
    // Handler verification already enforces this before dispatch. Repeat the
    // public-envelope bind locally so future or host-only call sites cannot
    // lend metadata from another chain to any renderer. Surface-specific
    // contract/tokenPath checks below remain mandatory as a separate axis.
    let erc20 = erc20.filter(|meta| meta.chain_id == tx.chain_id);

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
            let inner_meta = safe_inner_meta(
                erc20,
                safe.canonical[sphincs_tz_shared::SAFE_OFF_OPERATION],
                &safe_v1_inner_to(safe),
                safe.raw_data,
            );
            return super::safe_display::render_safe_v1_pages(safe, Some(v3), inner_meta, resolver);
        }
        if let Some(exec) = safe_exec {
            let inner_meta = safe_inner_meta(
                erc20,
                exec.decoded.operation,
                &exec.decoded.to,
                exec.decoded.data,
            );
            return super::safe_display::render_safe_exec_pages(exec, Some(v3), inner_meta, resolver);
        }
        return Ok(crate::tx::eip712::cowswap_display::render_cowswap_pages(
            &v3.canonical,
            &v3.sell,
            &v3.buy,
        ));
    }
    if let Some(safe) = safe_v1 {
        // For Safe inner-tx ERC-20 rendering, only apply the outer
        // ERC-20 metadata bundle when its contract address matches the
        // inner-tx target — a Safe call carrying USDC metadata is
        // useful only if the inner `to` is in fact USDC — or, for a
        // multiSend batch, when one of the packed records targets the
        // token (the renderer re-matches per record before applying).
        let inner_meta = safe_inner_meta(
            erc20,
            safe.canonical[sphincs_tz_shared::SAFE_OFF_OPERATION],
            &safe_v1_inner_to(safe),
            safe.raw_data,
        );
        return super::safe_display::render_safe_v1_pages(safe, None, inner_meta, resolver);
    }
    if let Some(exec) = safe_exec {
        // Same address-match rule for the exec path, multiSend records
        // included. This pairs with the approveHash branch above so
        // both Safe surfaces handle ERC-20 attribution consistently.
        let inner_meta = safe_inner_meta(
            erc20,
            exec.decoded.operation,
            &exec.decoded.to,
            exec.decoded.data,
        );
        return super::safe_display::render_safe_exec_pages(exec, None, inner_meta, resolver);
    }
    if let Some(d) = erc7730 {
        match super::erc7730::render_erc7730_pages_with_signer(
            tx,
            inner_data,
            d,
            erc20,
            resolver,
            device_signer,
        ) {
            Ok(pages) => return Ok(pages),
            Err(error) => return refuse_verified_erc7730(error),
        }
    }
    // A Merkle root authenticates a supplied descriptor but cannot, by itself,
    // reveal that a hostile companion omitted one. The firmware-pinned known-
    // call filter supplies that missing non-optional membership signal. Once a
    // registry-declared `(chain, target, selector)` is known, absence/malformed binding
    // is a hard refusal rather than permission to downgrade to ERC-20, typed-
    // call, or blind-sign pages. Higher-priority native Safe/CoW decoders have
    // already returned above and remain valid without an ERC-7730 trailer.
    {
        // Route the proof unconditionally. The old outer `if let` was itself a
        // one-instruction permission branch: skipping it bypassed every A/B
        // gate below. A missing target and short calldata are represented
        // canonically and proven just like any other tuple; Bloom false
        // positives only refuse, which is safe.
        let mut target = [0u8; 20];
        let mut target_present = 0u32;
        // SAFETY: unique local. Start from a materialized FAIL state so a
        // skipped `Some` route cannot inherit a permissive stack value.
        unsafe {
            core::ptr::write_volatile(
                &mut target_present,
                crate::fi::FAIL_SENTINEL,
            );
        }
        if let Some(actual) = tx.to.as_ref() {
            target.copy_from_slice(actual);
            // SAFETY: unique live local; volatile publication makes a skipped
            // target-copy route observable in both final permission gates.
            unsafe {
                core::ptr::write_volatile(
                    &mut target_present,
                    crate::fi::OK_SENTINEL,
                );
            }
        }
        let mut selector = [0u8; 4];
        let selector_len = core::cmp::min(inner_data.len(), selector.len());
        selector[..selector_len].copy_from_slice(&inner_data[..selector_len]);
        // Permission to fall through is the security-sensitive direction.
        // The verdict slot starts FAIL and the CFI counter belongs to this
        // caller but is bumped inside the non-inlined proof. Skipping the whole
        // call therefore cannot turn attacker-controlled argument registers
        // into an accidental OK return value.
        let mut unknown_verdict_slot = 0u32;
        // SAFETY: unique local. The volatile FAIL materialization is
        // load-bearing: an ordinary initialization is dead on the normal path
        // (the callee overwrites it) and LTO could erase it, leaving stale
        // stack data if a fault skips the call.
        unsafe {
            core::ptr::write_volatile(
                &mut unknown_verdict_slot,
                crate::fi::FAIL_SENTINEL,
            );
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let mut unknown_cfi = crate::fi::CfiCounter::new();
        crate::tx::erc7730::prove_unknown_contract_call(
            tx.chain_id,
            &target,
            &selector,
            &mut unknown_verdict_slot,
            &mut unknown_cfi,
        );
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // Gate A independently materializes both permission proofs. Gate B
        // repeats the volatile read and caller-CFI check after a randomized
        // gap, so a skipped reject branch still lands at another reject.
        // SAFETY: local was initialized above and remains live; the proof's
        // unique mutable borrow ended before this independent readback.
        let unknown_verdict_a = unsafe {
            core::ptr::read_volatile(&unknown_verdict_slot)
        };
        let unknown_cfi_verdict_a =
            unknown_cfi.check_into_sentinel(crate::tx::erc7730::CFI_KNOWN_EXPECTED);
        let route_a = match tx.to.as_ref() {
            Some(actual) => {
                // SAFETY: initialized above and independently materialized at
                // the gate that consumes it.
                let present = unsafe { core::ptr::read_volatile(&target_present) };
                present == crate::fi::OK_SENTINEL
                    && actual == &target
                    && selector[..selector_len] == inner_data[..selector_len]
            }
            None => {
                // Contract creation has no catalogue target. It still queries
                // the all-zero sentinel tuple so a Bloom collision refuses.
                target == [0u8; 20]
                    && selector[..selector_len] == inner_data[..selector_len]
            }
        };
        let unknown_all_ok_a = unknown_verdict_a == crate::fi::OK_SENTINEL
            && unknown_cfi_verdict_a == crate::fi::OK_SENTINEL
            && route_a;
        crate::fi::scrub_sentinel_register();
        let unknown_gate_a =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(unknown_all_ok_a));
        crate::fi::scrub_sentinel_register();
        if unknown_gate_a != crate::fi::OK_SENTINEL {
            secure_log!(
                "erc7730 clear-sign refused: known call omitted descriptor"
            );
            crate::ui::show_status("Sign refused", "7730 proof needed");
            return Err(());
        }
        crate::fi::wait_random();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: same live local, independently re-read after the randomized
        // gap instead of reusing gate A's cached evidence.
        let unknown_verdict_b = unsafe {
            core::ptr::read_volatile(&unknown_verdict_slot)
        };
        let unknown_cfi_verdict_b =
            unknown_cfi.check_into_sentinel(crate::tx::erc7730::CFI_KNOWN_EXPECTED);
        let route_b = match tx.to.as_ref() {
            Some(actual) => {
                // SAFETY: same initialized local, re-read after the gap.
                let present = unsafe { core::ptr::read_volatile(&target_present) };
                present == crate::fi::OK_SENTINEL
                    && actual == &target
                    && selector[..selector_len] == inner_data[..selector_len]
            }
            None => {
                target == [0u8; 20]
                    && selector[..selector_len] == inner_data[..selector_len]
            }
        };
        let unknown_all_ok_b = unknown_verdict_b == crate::fi::OK_SENTINEL
            && unknown_cfi_verdict_b == crate::fi::OK_SENTINEL
            && route_b;
        crate::fi::scrub_sentinel_register();
        let unknown_gate_b =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(unknown_all_ok_b));
        crate::fi::scrub_sentinel_register();
        if unknown_gate_b != crate::fi::OK_SENTINEL {
            secure_log!(
                "erc7730 clear-sign refused: known call omitted descriptor"
            );
            crate::ui::show_status("Sign refused", "7730 proof needed");
            return Err(());
        }
    }
    if inner_data.is_empty() {
        return Ok(super::value_transfer::render_pages(tx, resolver));
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
            // `erc20` has only Merkle+chain authority here. Safe branches
            // returned above after matching verified Safe execution facts;
            // direct ERC-7730 returned after matching its signed tokenPath.
            // Neither grants authority to this direct ERC-20 branch. Re-check
            // the outer contract and fall back to the raw unknown-token view
            // on mismatch.
            let matched = erc20
                .filter(|meta| super::value_page::direct_erc20_meta_matches(&meta.contract, tx.to.as_ref()));
            Ok(match matched {
                Some(meta) => super::erc20_known::render_erc20_known_pages(tx, &call, meta, resolver),
                None => super::erc20_unknown::render_erc20_unknown_pages(tx, &call, resolver),
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
                    super::typed_call::try_render_typed_call(tx, inner_data, meta, resolver)
                {
                    return Ok(pages);
                }
            }
            Ok(super::blind_sign::render_blind_sign_pages(tx, inner_data, selector, resolver))
        }
    }
}

/// Apply the one permitted policy to a render error from a descriptor that has
/// already verified and bound to this request: hard refusal.  Keeping this as
/// one executable function lets host tests enumerate every [`RenderErr`]
/// variant without manufacturing a descriptor fixture for each diagnostic.
fn refuse_verified_erc7730(
    error: crate::tx::erc7730_render::RenderErr,
) -> Result<super::Pages, ()> {
    use crate::tx::erc7730_render::RenderErr;
    use pqsigner_erc7730::render::VerifiedDescriptorErrorPolicy;

    match error.verified_descriptor_policy() {
        VerifiedDescriptorErrorPolicy::HardRefuse => {}
    }

    match error {
        RenderErr::Reject(msg) => {
            // `msg` is a developer trace tag (e.g. "7730 nested blob
            // trailing") — not user-facing text, and several exceed the
            // 16-col row. Keep the tag in the debug log and refuse: once a
            // descriptor has verified and bound to this transaction, a
            // renderer failure is an integrity failure, not permission to
            // downgrade to a weaker typed/blind-sign interpretation.
            // Bare invocation — `secure_log!` is a `macro_rules!` in
            // main.rs without `#[macro_export]`, textually scoped: the
            // `crate::secure_log!` path form fails E0433 under
            // `debug-log` (only the cfg'd-out no-op arm is suggested).
            secure_log!("erc7730 clear-sign refused: {}", msg);
            let _ = msg;
            crate::ui::show_status("Sign refused", "clear-sign failed");
        }
        RenderErr::NoFormat => {
            secure_log!("erc7730 clear-sign refused: no format");
            crate::ui::show_status("Sign refused", "clear-sign format");
        }
        RenderErr::PageBudget => {
            secure_log!("erc7730 clear-sign refused: page budget");
            crate::ui::show_status("Sign refused", "clear-sign pages");
        }
    }
    Err(())
}

#[cfg(test)]
mod semantic_guard_tests {
    use super::refuse_verified_erc7730;
    use crate::tx::erc7730_render::RenderErr;

    #[test]
    fn every_verified_descriptor_render_error_is_fatal() {
        for error in [
            RenderErr::Reject("semantic guard"),
            RenderErr::NoFormat,
            RenderErr::PageBudget,
        ] {
            assert!(
                refuse_verified_erc7730(error).is_err(),
                "verified descriptor errors must never enter a weaker renderer"
            );
        }
    }
}

/// Inner `to` decoded from a verified `safe_v1` canonical.
fn safe_v1_inner_to(safe: &crate::tx::eip712::safe::VerifiedSafeV1<'_>) -> [u8; 20] {
    let mut t = [0u8; 20];
    t.copy_from_slice(
        &safe.canonical[sphincs_tz_shared::SAFE_OFF_TO..sphincs_tz_shared::SAFE_OFF_TO + 20],
    );
    t
}

/// Address-match filter for ERC-20 metadata on the Safe surfaces: the bundle
/// applies when its contract is the verified inner `to`, or when one of the
/// records in a verified pinned `MultiSendCallOnly` delegatecall targets it.
/// The renderer still re-matches per record before applying the metadata.
fn safe_inner_meta<'m>(
    erc20: Option<&'m crate::erc20::bundle::Erc20Metadata<'m>>,
    operation: u8,
    inner_to: &[u8; 20],
    raw_data: &[u8],
) -> Option<&'m crate::erc20::bundle::Erc20Metadata<'m>> {
    erc20.filter(|m| {
        crate::tx::eip712::safe::erc20_metadata_matches_verified_safe_call(
            operation,
            inner_to,
            raw_data,
            &m.contract,
        )
    })
}
