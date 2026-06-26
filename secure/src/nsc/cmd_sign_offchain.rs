//! CMD_SIGN_OFFCHAIN — produce a SPHINCS+C10 signature for an EIP-1271
//! (off-chain) signing request.
//!
//! Two modes selected by the `kind` byte at offset 13:
//!
//!   * **`OFFCHAIN_KIND_PERSONAL_SIGN` (1)** — the companion sends the
//!     raw `personal_sign` message bytes. The firmware itself computes
//!     the `personal_sign` prefix hash, wraps it via Solady's nested
//!     EIP-712 (PersonalSign workflow), shows the message text on the
//!     trusted display, and signs the resulting hash. This is the only
//!     mode that gives the user real visibility into what they're
//!     approving.
//!
//!   * **`OFFCHAIN_KIND_RAW32` (0)** — fallback for cases where the
//!     companion only has the dapp's final 32-byte hash `H` (e.g. a
//!     typed-data digest the firmware can't decode). The companion
//!     supplies the RAW `H` (the value it passes to `isValidSignature`),
//!     NOT a pre-nested value; the firmware applies the Solady
//!     replay-safe EIP-712 nesting (`replay_safe_hash`) to `H` itself,
//!     signs that, and renders `H` as hex. Nesting on-device keeps the
//!     signed value keccak-bound to the wallet domain so it can never
//!     coincide with the bare SHA-256 `sphincsDigest` the on-chain UserOp
//!     path verifies — without this the path was a UserOp-forgery oracle
//!     (`raw32(sphincsDigest(drainOp))` → valid Type-2 sig; fixed
//!     2026-06-11). Still a blind hash sign for the user (flagged as
//!     such), but its blast radius is an EIP-1271 attestation of `H`, not
//!     a forgeable UserOp.
//!
//! Slot-key safety:
//!   * Enforces the bounded-recovery rule
//!     `local_offchain - last_userop < MAX_OFFCHAIN_GAP` so the next
//!     UserOp definitely publishes the count, capping the worst-case
//!     unbacked off-chain sigs at `MAX_OFFCHAIN_GAP`.
//!   * Enforces the per-slot cap `local_offchain + 1 <= MAX_SLOT_USES`
//!     pre-emptively. The on-chain combined cap is the primary defence
//!     (it observes both `slotUses` and `offchainSigCount`); this
//!     in-firmware check is defence-in-depth so a faulted firmware
//!     still cannot produce a sig past the SPHINCS+ usage budget.
//!   * Refuses for slots the firmware has no flash record of —
//!     forces a Type 1 slot registration via CMD_SIGN_USEROP after
//!     a fresh-from-seed restore, so the firmware's view of the
//!     local count is grounded in its own signing history.
//!
//! Security policy:
//!   * Requires `pin_verified`.
//!   * `ownerIndex == 0` (bootstrap) is forbidden — the bootstrap key
//!     signs only Type 1 slot registrations. EIP-1271 sigs are slot-
//!     authorised. The on-chain `_erc1271IsValidSignatureNowCalldata`
//!     enforces the same rule; this is duplicated here so a faulted
//!     firmware does not leak bootstrap budget through the off-chain
//!     path.

use sphincs_tz_shared::{
    EIP6492_BLOB_LEN, EIP6492_FACTORY_CALLDATA_LEN, MAX_ACCOUNT_INDEX,
    MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN, MAX_OFFCHAIN_EIP712_TYPED_LEN, MAX_OFFCHAIN_GAP,
    MAX_OFFCHAIN_PERSONAL_SIGN_LEN, MAX_SLOT_USES, NscStatus, OFFCHAIN_FLAGS_MASK,
    OFFCHAIN_FLAG_ACCOUNT_DEPLOYED, OFFCHAIN_KIND_EIP712_TYPED, OFFCHAIN_KIND_PERSONAL_SIGN,
    OFFCHAIN_KIND_RAW32, PQ_SMART_WALLET_FACTORY, SIGNATURE_LEN, SIGN_OFFCHAIN_HEADER_LEN,
    SIGN_OFFCHAIN_INPUT_FLAGS_OFF, SIGN_OFFCHAIN_INPUT_KIND_OFF, SIGN_OFFCHAIN_INPUT_MAX_LEN,
    SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF, SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF,
    SIGN_OFFCHAIN_OUTPUT_COUNT_OFF, SIGN_OFFCHAIN_OUTPUT_LEN, SIGN_OFFCHAIN_OUTPUT_LEN_6492,
    SIGN_OFFCHAIN_OUTPUT_SIG_OFF, SIG_WRAPPER_LEN,
};
use zeroize::{Zeroize, Zeroizing};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. The body
/// snapshots the NS input under `validate_ns_read_ptr`, writes the
/// signed response under `validate_ns_write_ptr`, and touches
/// `static mut` driver state (`SE`, `SLOT_CACHE`, `SNAP_BUF`) under
/// the single-threaded dispatcher invariant + `HandlerGuard`.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // HIGH-7: keep secrets resident across the slot-keygen window.
    let _busy = super::HandlerGuard::enter();

    crate::ui::show_status("EIP-1271", "validating...");

    // ── 1. Unlock check ─────────────────────────────────────────────
    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        crate::ui::show_status("EIP-1271", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    // ── 2. Pointer + length validation ───────────────────────────────
    let in_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len < SIGN_OFFCHAIN_HEADER_LEN || total_len > SIGN_OFFCHAIN_INPUT_MAX_LEN {
        crate::ui::show_status("EIP-1271", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    // HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS-pointer
    // checks (a bare `if !validate` is single-fault FAIL-OUT → OOB R/W across
    // the S/NS boundary). Same idiom as the §14 6492 re-validation below.
    let read_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_read_ptr(args.arg0, total_len)
    });
    if read_ptr_ok != crate::fi::OK_SENTINEL {
        return NscStatus::InvalidPointer as u32;
    }
    // NS-write-buffer length depends on the flags byte (deployed → bare
    // 4016 B; counterfactual → ERC-6492 wrapped 8616 B). Validate
    // against the larger size after we've read the flag byte; for now,
    // validate the smaller deployed size so any unmapped output buffer
    // fails fast before we touch SE state. The 6492-path write below
    // performs its own larger validation immediately after parsing the
    // flag.
    let write_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN)
    });
    if write_ptr_ok != crate::fi::OK_SENTINEL {
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    //
    // Shared with the sibling sign handlers via `super::SIGN_SNAP_BUF`
    // (one buffer for all three; safe under the non-reentrant dispatcher —
    // see the buffer's doc comment). `total_len` was already gated `>
    // SIGN_OFFCHAIN_INPUT_MAX_LEN` above, and the const assert pins that
    // max ≤ the shared buffer, so the `..total_len` slice can never
    // overrun.
    const _: () = assert!(SIGN_OFFCHAIN_INPUT_MAX_LEN <= super::SIGN_SNAP_BUF_LEN);
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    let snap_full = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
    let snap = &mut snap_full[..total_len];
    for i in 0..total_len {
        snap[i] = core::ptr::read_volatile(in_ptr.add(i));
    }

    // ── 4. Parse header ─────────────────────────────────────────────
    let account_index = snap[0] as u32;
    let chain_id = u64::from_be_bytes([
        snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7], snap[8],
    ]);
    let slot_index = u32::from_be_bytes([snap[9], snap[10], snap[11], snap[12]]);
    let kind = snap[SIGN_OFFCHAIN_INPUT_KIND_OFF];
    let payload_len = u16::from_be_bytes([
        snap[SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF],
        snap[SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF + 1],
    ]) as usize;
    let flags = snap[SIGN_OFFCHAIN_INPUT_FLAGS_OFF];

    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }
    if SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF + payload_len != total_len {
        crate::ui::show_status("EIP-1271", "bad payload_len");
        return NscStatus::InvalidPointer as u32;
    }

    // Flags: only `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED` (bit 0) is defined.
    // Any other bit set is either a wire-format error or a bit-flip;
    // reject so a stale companion can't accidentally request an
    // unimplemented mode.
    if flags & !OFFCHAIN_FLAGS_MASK != 0 {
        crate::ui::show_status("EIP-1271", "bad flags");
        return NscStatus::InvalidPointer as u32;
    }
    let account_deployed = flags & OFFCHAIN_FLAG_ACCOUNT_DEPLOYED != 0;

    // ERC-6492 path constraint: the factory's `createAccount(...)`
    // seeds only ownerIndex 0 (bootstrap) + ownerIndex 1 (slot 0). A
    // wrapped sig on any other slot is unverifiable because that slot
    // doesn't exist after the factory call runs. Refuse early.
    if !account_deployed && slot_index != 0 {
        crate::ui::show_status("EIP-1271", "6492 needs slot 0");
        return NscStatus::InvalidPointer as u32;
    }

    // When ERC-6492 wrapping is requested, the output buffer is
    // larger. Validate the full extent now that we know the mode.
    if !account_deployed
        && crate::fi::check_true_into_sentinel(|| {
            validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN_6492)
        }) != crate::fi::OK_SENTINEL
    {
        return NscStatus::InvalidPointer as u32;
    }

    // Per-kind payload constraints. Bound checks first so kind-specific
    // hash construction never sees out-of-range data.
    match kind {
        OFFCHAIN_KIND_RAW32 => {
            if payload_len != 32 {
                crate::ui::show_status("EIP-1271", "raw32 needs 32 B");
                return NscStatus::InvalidPointer as u32;
            }
        }
        OFFCHAIN_KIND_PERSONAL_SIGN => {
            if payload_len > MAX_OFFCHAIN_PERSONAL_SIGN_LEN {
                crate::ui::show_status("EIP-1271", "msg too long");
                return NscStatus::InvalidPointer as u32;
            }
        }
        OFFCHAIN_KIND_EIP712_TYPED => {
            if payload_len > MAX_OFFCHAIN_EIP712_TYPED_LEN {
                crate::ui::show_status("EIP-1271", "typed too long");
                return NscStatus::InvalidPointer as u32;
            }
            // Minimum payload: dsep_present(2) + dsep(32) + pth(32) +
            // edl(2) + edata(0) + trailer_len(2) + trailer(0) = 70 B.
            if payload_len < 2 + 32 + 32 + 2 + 2 {
                crate::ui::show_status("EIP-1271", "typed too short");
                return NscStatus::InvalidPointer as u32;
            }
        }
        _ => {
            crate::ui::show_status("EIP-1271", "bad kind");
            return NscStatus::InvalidPointer as u32;
        }
    }

    let payload = &snap[SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF..SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF + payload_len];

    // ── 5. Slot key + registration probe ────────────────────────────
    let slot_flash_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);
    // MEDIUM-1 / MEDIUM-3 (audit counter-replay 20260611): if the slot is
    // unregistered, the ERC-6492 counterfactual path (account_deployed==0,
    // slot 0) is the ONLY case allowed to proceed — every other
    // unregistered slot is refused (invariant #9: force a Type-1 rotation
    // to a fresh slot first). Two changes from the prior design:
    //   * MEDIUM-3: the registration entry is NO LONGER written here. The
    //     old code committed a flash entry BEFORE the §9 user confirm,
    //     letting a malicious companion mint durable page-123 state — and
    //     wear the page toward its erase-endurance limit — with zero
    //     consent (it could simply abandon the confirm). We defer the
    //     write to AFTER the confirm; the durable counter bump in §13
    //     registers the slot, so a cancelled request leaves no trace.
    //   * MEDIUM-1: the counterfactual case resets this slot's off-chain
    //     budget view to zero. A wallet that is actually deployed-and-used
    //     but whose page-123 state was lost (seed-restore onto a fresh
    //     device) would be re-enabled at count 0 here if the companion
    //     lies `account_deployed=0`. The trusted display surfaces the
    //     pre-deploy/counterfactual assumption loudly (see
    //     `render_eip1271_*` "Pre-deploy" warning) so the user can catch
    //     the lie and cancel. The deeper desync (the device cannot read
    //     the chain's `offchainSigCount`) is bounded by the §6 cap +
    //     CMD_OFFCHAIN_SYNC and is documented as residual.
    if !crate::offchain_state::offchain_count_is_registered(&slot_flash_key) {
        // Only the ERC-6492 counterfactual path (account_deployed==0, slot
        // 0) may proceed on an unregistered slot; every other unregistered
        // slot is refused. The §13 durable bump (offchain_count -> 1)
        // registers the counterfactual slot post-confirm — no flash write
        // happens before the user confirms.
        if account_deployed || slot_index != 0 {
            crate::ui::show_status("EIP-1271", "slot unregistered");
            return NscStatus::OffchainSlotUnregistered as u32;
        }
    }

    // ── 6. Gap + cap checks (firmware-side defence in depth) ────────
    // F-10 hardening: read each counter twice with a randomised gap
    // between, then halt if the two reads disagree. This defeats a
    // single-shot stuck-at fault on the value-holding register *after*
    // a successful flash scan — the second scan refreshes the register
    // from flash, so the second read won't carry a faulted value
    // forward. `offchain_count_read` / `last_userop_count_read` already
    // forward+reverse-scan internally (F-12), so a glitched scan
    // returns `u64::MAX`, which the cap check below also rejects.
    let last_userop_a = crate::offchain_state::last_userop_count_read(&slot_flash_key);
    crate::fi::wait_random();
    let last_userop_b = crate::offchain_state::last_userop_count_read(&slot_flash_key);
    if last_userop_a != last_userop_b || last_userop_a == u64::MAX {
        crate::ui::show_status("EIP-1271", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let last_userop = last_userop_a;

    let local_offchain_a = crate::offchain_state::offchain_count_read(&slot_flash_key);
    crate::fi::wait_random();
    let local_offchain_b = crate::offchain_state::offchain_count_read(&slot_flash_key);
    if local_offchain_a != local_offchain_b || local_offchain_a == u64::MAX {
        crate::ui::show_status("EIP-1271", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let mut local_offchain = local_offchain_a;
    if last_userop > local_offchain {
        if crate::offchain_state::offchain_count_promote_to(&slot_flash_key, last_userop)
            .is_err()
        {
            crate::ui::show_status("EIP-1271", "repair fail");
            return NscStatus::InternalError as u32;
        }
        local_offchain = last_userop;
    }

    // MEDIUM-2 (audit counter-replay 20260611): read the durable Type-2
    // UserOp-signature tally so the cap below bounds the *combined*
    // slot-key usage (off-chain + UserOp), not off-chain alone. Both kinds
    // of signature share one SPHINCS+ few-time budget, but the chain never
    // sees a pure off-chain sig (isValidSignature is view-only), so this is
    // the only enforcement point for the combined cap on the off-chain
    // path. Double-read + halt-on-mismatch like the counters above; a
    // glitched read returns u64::MAX, which saturates and refuses.
    let userop_sigs_a = crate::offchain_state::userop_sigs_read(&slot_flash_key);
    crate::fi::wait_random();
    let userop_sigs_b = crate::offchain_state::userop_sigs_read(&slot_flash_key);
    if userop_sigs_a != userop_sigs_b {
        crate::ui::show_status("EIP-1271", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let userop_sigs = userop_sigs_a;

    let gap = local_offchain.saturating_sub(last_userop);
    if gap >= MAX_OFFCHAIN_GAP {
        crate::ui::show_status("EIP-1271", "publish first");
        return NscStatus::OffchainGapExceeded as u32;
    }
    let new_count = match local_offchain.checked_add(1) {
        Some(v) => v,
        None => return NscStatus::OffchainCapExceeded as u32,
    };
    // Combined cap: this off-chain sig plus every Type-2 UserOp sig this
    // firmware has produced for the slot must stay within the few-time
    // budget. `saturating_add` keeps a glitched u64::MAX read fail-closed.
    if userop_sigs.saturating_add(new_count) > MAX_SLOT_USES {
        crate::ui::show_status("EIP-1271", "slot exhausted");
        return NscStatus::OffchainCapExceeded as u32;
    }
    // F-10 belt-and-braces: re-derive the gate inputs and re-check.
    // A second pass forces a glitch to land in *both* windows.
    crate::fi::wait_random();
    let gap_recheck = local_offchain.saturating_sub(last_userop);
    if gap_recheck >= MAX_OFFCHAIN_GAP
        || userop_sigs.saturating_add(new_count) > MAX_SLOT_USES
    {
        crate::ui::show_status("EIP-1271", "fi tampered");
        return NscStatus::InternalError as u32;
    }

    // ── 7. Reconstruct entropy + slot master per-account ────────────
    let master_secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(super::state::peek_state(|s| s.master_secret));
    let mut entropy_blob = Zeroizing::new([0u8; 64]);
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut *entropy_blob) {
            Ok(l) => l,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };
    let entropy = Zeroizing::new(
        match crate::crypto::decrypt_entropy_blob(
            &entropy_blob[..entropy_blob_len],
            &*master_secret,
        ) {
            Ok(e) => e,
            Err(_) => return NscStatus::CryptoError as u32,
        },
    );
    let slot_master_entropy: Zeroizing<[u8; 32]> = Zeroizing::new(
        crate::crypto::slot_master_entropy_from_entropy(&*entropy, account_index),
    );

    // ── 7b. EIP-712 typed-data + ERC-7730 (kind=2): parse + verify
    //        + render + Solady-nested replay-safe wrap + confirm ──
    //
    // Phase 4 (this commit) completes the path:
    //   1. Parse + verify the trailer bundle against
    //      `ERC7730_DESCRIPTORS_ROOT`, cross-check the binding
    //      (chain_id + domain_separator) — same as Phase 3.
    //   2. Compute the EIP-712 final hash from the companion-supplied
    //      `(domain_separator, primary_type_hash, encoded_data)`.
    //   3. Wrap the 32-byte EIP-712 hash through Solady's nested
    //      PersonalSign envelope — the on-chain Solady dispatcher
    //      accepts it because our `SignatureWrapper` carries no
    //      appended data (see `aa/src/eip1271.rs:5-8` and
    //      `contracts/smart-wallet/src/PQSmartWallet.sol:362-395`).
    //      NO new typehash, NO on-chain change.
    //   4. Render via `display::erc7730::render_erc7730_eip712_pages`
    //      so the user sees field-level descriptor pages, append the
    //      ERC-8213 `Eip712Final` fingerprint, and confirm. On render
    //      failure, REFUSE (finding F6) — this is a verified known shape,
    //      so we never fall back to a raw-hash blind sign here.
    let mut hash_to_sign = [0u8; 32];
    let mut wallet_addr = [0u8; 20];
    let mut already_confirmed = false;

    if kind == OFFCHAIN_KIND_EIP712_TYPED {
        let mut p = 0usize;
        let domain_sep_present =
            u16::from_be_bytes([payload[p], payload[p + 1]]) != 0;
        p += 2;
        if !domain_sep_present {
            crate::ui::show_status("EIP-1271", "7730 missing ds");
            return NscStatus::InvalidPointer as u32;
        }
        let mut domain_separator = [0u8; 32];
        domain_separator.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let mut primary_type_hash = [0u8; 32];
        primary_type_hash.copy_from_slice(&payload[p..p + 32]);
        p += 32;
        let encoded_data_len =
            u16::from_be_bytes([payload[p], payload[p + 1]]) as usize;
        p += 2;
        if encoded_data_len > MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
            || p + encoded_data_len > payload.len()
        {
            crate::ui::show_status("EIP-1271", "bad ed_len");
            return NscStatus::InvalidPointer as u32;
        }
        let encoded_data = &payload[p..p + encoded_data_len];
        p += encoded_data_len;
        // Trailer: `[u16 BE len][bundle]`.
        if p + 2 > payload.len() {
            crate::ui::show_status("EIP-1271", "no trailer");
            return NscStatus::InvalidPointer as u32;
        }
        let trailer_len = u16::from_be_bytes([payload[p], payload[p + 1]]) as usize;
        p += 2;
        if trailer_len == 0 {
            crate::ui::show_status("EIP-1271", "empty trailer");
            return NscStatus::InvalidPointer as u32;
        }
        if p + trailer_len != payload.len() {
            crate::ui::show_status("EIP-1271", "bad trailer_len");
            return NscStatus::InvalidPointer as u32;
        }
        let trailer = &payload[p..p + trailer_len];
        let v = match crate::tx::erc7730::verify_erc7730_bundle(
            trailer,
            &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
        ) {
            Ok(v) => v,
            Err(_e) => {
                crate::ui::show_status("EIP-1271", "7730 bundle fail");
                return NscStatus::InvalidPointer as u32;
            }
        };
        // FI-hardened binding cross-check (Phase 5 item 6).
        // Compute the verdict once, then double-evaluate via
        // `check_true_into_sentinel` with `wait_random` between
        // so a single-fault glitch that flips the `.is_err()`
        // ALSO has to defeat a Hamming-distant sentinel compare.
        // Mirrors the verify-before-release pattern in
        // `crypto::c10_sign_verified_with_progress`.
        // `domain_separator` is the companion-supplied domain the
        // signature commits to (folded into `final_eip712` below); the
        // descriptor's pinned `ir.domain_separator` cryptographically
        // binds the verifying contract through it, so there is no separate
        // contract argument to compare (audit L-11).
        let eip712_bind_ok = crate::tx::erc7730::cross_check_eip712(
            &v.ir,
            chain_id,
            &domain_separator,
        )
        .is_ok();
        crate::fi::wait_random();
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(eip712_bind_ok))
            != crate::fi::OK_SENTINEL
        {
            crate::ui::show_status("EIP-1271", "7730 binding fail");
            return NscStatus::InvalidPointer as u32;
        }
        #[cfg(feature = "debug-log")]
        {
            let c = &v.ir.contract;
            secure_log!(
                "[ERC-7730] offchain typed match chain={} contract=0x{:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}{:02x} ir_len={} ed_len={}",
                v.ir.chain_id,
                c[0], c[1], c[2], c[3],
                c[16], c[17], c[18], c[19],
                v.ir.raw.len(),
                encoded_data_len,
            );
        }

        // EIP-712 final hash:
        //   structHash = keccak256(typehash || encoded_data)
        //   final      = keccak256(0x1901 || ds || structHash)
        let struct_hash = {
            use sha3::{Digest, Keccak256};
            let mut h = Keccak256::new();
            h.update(primary_type_hash);
            h.update(encoded_data);
            let mut o = [0u8; 32];
            o.copy_from_slice(&h.finalize());
            o
        };
        let final_eip712 = pqsigner_tx_core::erc8213::eip712_final_hash(
            &domain_separator,
            &struct_hash,
        );

        // Bootstrap pubkey + wallet address (same lookup-or-derive as
        // PERSONAL_SIGN below; entropy is already in scope from §7).
        let cached =
            super::state::with_state(|s| s.bootstrap_cache_lookup(account_index));
        let (master_pk_seed_32, master_pk_root_32) = match cached {
            Some(pair) => pair,
            None => {
                crate::ui::show_progress("C10 keygen", 0);
                let (c10_sk, pk_seed_32, pk_root_32) =
                    crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                        &*entropy,
                        account_index,
                        |p| crate::ui::show_progress("C10 keygen", p),
                    );
                drop(c10_sk);
                super::state::with_state(|s| {
                    s.bootstrap_cache_insert(account_index, pk_seed_32, pk_root_32);
                });
                (pk_seed_32, pk_root_32)
            }
        };
        wallet_addr =
            crate::aa::eip1271::proxy_address(&master_pk_seed_32, &master_pk_root_32);

        // Solady replay-safe nesting of the 32-byte EIP-712 final hash.
        // `final_eip712` IS the `H` a dapp passes to `isValidSignature`,
        // so we wrap it directly via `replay_safe_hash` (NO inner EIP-191
        // prefix — that's only for the PersonalSign *message* path). The
        // on-chain dispatcher (`Solady.ERC1271`) wraps the dapp-supplied
        // `H` through the exact same PersonalSign envelope when verifying,
        // so this signature validates without any on-chain change (no new
        // typehash, no TypedDataSign appended-data branch).
        hash_to_sign = crate::aa::eip1271::replay_safe_hash(
            chain_id,
            &wallet_addr,
            &final_eip712,
        );

        // Render via the ERC-7730 descriptor + append fingerprint.
        use crate::ui::confirm::{confirm, ConfirmResult};
        let resolver = crate::names::NameResolver::new();
        let mut pages = match crate::tx::display::erc7730::render_erc7730_eip712_pages(
            chain_id,
            &v.ir.contract,
            &primary_type_hash,
            encoded_data,
            &v,
            None,
            &resolver,
        ) {
            Ok(p) => p,
            // Fail closed (finding F6): this descriptor already passed
            // verify_erc7730_bundle + cross_check_eip712 — it is a known,
            // verified shape. Falling back to render_eip1271_raw32_pages here
            // (showing/signing the bare EIP-712 hash) turned the clear-sign
            // path into a blind-sign oracle for a structured payload whenever
            // an attacker could force a RenderErr. Refuse rather than
            // blind-sign a value whose human-readable intent could not render.
            Err(_) => {
                crate::ui::show_status("Sign refused", "render failed");
                return NscStatus::InternalError as u32;
            }
        };
        // Fail closed if the EIP-712 final fingerprint page can't be appended
        // (F5): it is the mandatory binding between the displayed typed-data
        // intent and the digest being signed; dropping it silently and signing
        // anyway is a confirm-without-fingerprint.
        if crate::tx::display::erc8213::append_fingerprint_page(
            &mut pages,
            crate::tx::display::erc8213::Kind::Eip712Final(final_eip712),
        )
        .is_err()
        {
            crate::ui::show_status("Sign refused", "fp unshown");
            return NscStatus::InternalError as u32;
        }
        match confirm(pages.as_slice()) {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                crate::ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
        already_confirmed = true;
    }

    // ── 8. PersonalSign + raw32 hash construction (kind=0/1) ───────
    //
    // The firmware computes the final replay-safe hash itself from the
    // raw message — that's the whole point of the "show real text"
    // trusted-display contract. It needs the wallet's CREATE2 proxy
    // address, which depends on the bootstrap C10 pubkey for this
    // account. We pull it from `bootstrap_cache` if warm and derive on
    // demand otherwise (<1 s on first hit per session).
    //
    // For kind=0 (raw32) the same nesting is applied to the dapp's raw
    // 32-byte hash `H` — the firmware never signs `H` bare (see the
    // RAW32 doc at the top of this file). The kind=2 branch in §7b
    // populates `hash_to_sign` already.
    match kind {
        OFFCHAIN_KIND_RAW32 | OFFCHAIN_KIND_PERSONAL_SIGN => {
            // Both kinds perform the Solady replay-safe EIP-712 nesting in
            // the SECURE WORLD — the firmware, never the companion,
            // controls the nesting. This binds the signed value to this
            // wallet's domain (verifyingContract + chainId) and, crucially,
            // keeps it keccak-nested so it can NEVER coincide with the bare
            // SHA-256 `sphincsDigest` the on-chain Type-1/Type-2 UserOp path
            // verifies. A bare-signed raw32 value would be a UserOp-forgery
            // oracle (`raw32(sphincsDigest(drainOp))` → valid Type-2 sig);
            // nesting on-device closes that (audit fix 2026-06-11).
            //
            // Look up the bootstrap pubkey (needed for the wallet's CREATE2
            // proxy address = EIP-712 verifyingContract); derive on miss
            // (<1 s, cached for the session).
            let cached =
                super::state::with_state(|s| s.bootstrap_cache_lookup(account_index));
            let (master_pk_seed_32, master_pk_root_32) = match cached {
                Some(pair) => pair,
                None => {
                    crate::ui::show_progress("C10 keygen", 0);
                    let (c10_sk, pk_seed_32, pk_root_32) =
                        crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                            &*entropy,
                            account_index,
                            |p| crate::ui::show_progress("C10 keygen", p),
                        );
                    drop(c10_sk); // ZeroizeOnDrop wipes sk_seed.
                    super::state::with_state(|s| {
                        s.bootstrap_cache_insert(account_index, pk_seed_32, pk_root_32);
                    });
                    (pk_seed_32, pk_root_32)
                }
            };
            wallet_addr =
                crate::aa::eip1271::proxy_address(&master_pk_seed_32, &master_pk_root_32);
            hash_to_sign = if kind == OFFCHAIN_KIND_RAW32 {
                // `payload` is the dapp's RAW 32-byte hash H (the value it
                // passes to `isValidSignature`); validated to exactly 32 B
                // in §4. Nest on-device — do NOT sign it bare.
                let mut raw_h = [0u8; 32];
                raw_h.copy_from_slice(payload);
                crate::aa::eip1271::replay_safe_hash(chain_id, &wallet_addr, &raw_h)
            } else {
                // PersonalSign: EIP-191-prefix the message, then nest.
                crate::aa::eip1271::personal_sign_replay_safe_hash(
                    chain_id, &wallet_addr, payload,
                )
            };
        }
        OFFCHAIN_KIND_EIP712_TYPED => {
            // hash_to_sign already populated in §7b.
        }
        _ => return NscStatus::InternalError as u32, // unreachable past §4
    }

    // ── 9. Trusted-display confirmation + ERC-8213 fingerprint ─────
    //
    // kind=2 already confirmed in §7b (it needed the descriptor +
    // EIP-712 final hash to render meaningful pages). For kind=0/1
    // we render the existing personal-sign / raw32 pages and append
    // the ERC-8213 fingerprint here.
    if !already_confirmed {
        use crate::ui::confirm::{confirm, ConfirmResult};
        // For raw32 the user-meaningful value is the dapp's raw hash H
        // (= payload), NOT the firmware-internal replay-safe nesting now
        // held in `hash_to_sign`. Show + fingerprint H so the user can
        // cross-check it against the dapp's "you are signing 0x…" prompt.
        let mut raw_h = [0u8; 32];
        if kind == OFFCHAIN_KIND_RAW32 {
            raw_h.copy_from_slice(payload);
        }
        let mut pages = match kind {
            OFFCHAIN_KIND_PERSONAL_SIGN => crate::tx::display::render_eip1271_personal_sign_pages(
                chain_id,
                account_index,
                slot_index,
                &wallet_addr,
                payload,
                new_count,
                last_userop,
                MAX_SLOT_USES,
                account_deployed,
            ),
            _ => crate::tx::display::render_eip1271_raw32_pages(
                chain_id,
                account_index,
                slot_index,
                &raw_h,
                new_count,
                last_userop,
                MAX_SLOT_USES,
                account_deployed,
            ),
        };
        let fingerprint_kind = match kind {
            OFFCHAIN_KIND_PERSONAL_SIGN => {
                // PersonalSign signs the message via Solady's nested
                // EIP-712 wrap; the user-visible fingerprint is the
                // calldata digest of the raw message so they can
                // cross-check against `cast keccak ...` on the
                // companion. The wrapped `hash_to_sign` is firmware-
                // internal and would be confusing to display here.
                let digest = pqsigner_tx_core::erc8213::calldata_digest(payload);
                crate::tx::display::erc8213::Kind::CalldataDigest(digest)
            }
            _ => crate::tx::display::erc8213::Kind::Raw32(raw_h),
        };
        // Fail closed if the fingerprint page can't be appended (F5).
        if crate::tx::display::erc8213::append_fingerprint_page(&mut pages, fingerprint_kind)
            .is_err()
        {
            crate::ui::show_status("Sign refused", "fp unshown");
            return NscStatus::InternalError as u32;
        }
        match confirm(pages.as_slice()) {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                crate::ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
    }

    // ── 10. Slot C10 keygen (shared cache with cmd_sign_userop) ────
    let need_keygen = super::state::peek_state(|_| {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE`. Single-threaded gateway: the closure runs
        // synchronously inside the `peek_state` scope, and no other
        // handler can be active concurrently.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        match cached {
            Some(c) => {
                c.account_index != account_index
                    || c.chain_id != chain_id
                    || c.slot_index != slot_index
            }
            None => true,
        }
    });
    if need_keygen {
        crate::ui::show_progress("Slot keygen", 0);
        let (slot_sk, _slot_pk_seed_32, _slot_pk_root_32) =
            crate::crypto::derive_c10_slot_keypair_with_progress(
                &*slot_master_entropy,
                chain_id,
                slot_index,
                |p| crate::ui::show_progress("Slot keygen", p),
            );
        // SAFETY: category 5 — exclusive write to `static mut
        // SLOT_CACHE`. Single-threaded non-reentrant dispatcher +
        // `HandlerGuard` prevent any concurrent reader or SysTick
        // wipe from observing a torn cache entry. Any displaced
        // prior `CachedSlot` drops here; its `ZeroizeOnDrop` wipes
        // the previous SK.
        *core::ptr::addr_of_mut!(super::state::SLOT_CACHE) = Some(CachedSlot {
            account_index,
            chain_id,
            slot_index,
            key: slot_sk,
        });
        super::state::with_state(|s| {
            s.slot_master_entropy.zeroize();
            crate::fi::zeroize_barrier();
            s.slot_master_entropy = *slot_master_entropy;
            s.slot_master_derived.set_true();
        });
    }

    // ── 11. C10 sign ────────────────────────────────────────────────
    crate::ui::show_progress("EIP-1271 sign", 0);
    let sig = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE`. The cache was populated above (or already
        // valid) under the same non-reentrant dispatcher; no
        // concurrent mutator can swap it out from under this read.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => return NscStatus::InternalError as u32,
        };
        match crate::crypto::c10_sign_verified_with_progress(
            slot_ref,
            &hash_to_sign,
            |p| crate::ui::show_progress("EIP-1271 sign", p),
        ) {
            Ok(s) => s,
            Err(_) => return NscStatus::CryptoError as u32,
        }
    };
    debug_assert_eq!(sig.len(), SIGNATURE_LEN);

    // ── 12. FI-hardened verify-before-release ──────────────────────
    let (v1, v2) = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE` for the verify-before-release FI guard. Same
        // single-threaded-dispatcher rationale as the sign block above.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => return NscStatus::InternalError as u32,
        };
        let v1 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &hash_to_sign, &sig);
        crate::fi::wait_random();
        let v2 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &hash_to_sign, &sig);
        (v1, v2)
    };
    // F16: black_box each verdict so LLVM cannot CSE-merge the helper's two
    // closure evaluations (the F-1 idiom the single-bool gates here already
    // use); the two `verify()` calls split by `wait_random` above are the
    // CSE-proof redundancy, this matches their bar.
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(v1) && core::hint::black_box(v2))
        != crate::fi::OK_SENTINEL
    {
        crate::ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // ── 13. Bump the durable counter AFTER verify ──────────────────
    if crate::offchain_state::offchain_count_bump(&slot_flash_key, new_count).is_err() {
        crate::ui::show_status("Counter bump", "FAIL");
        return NscStatus::InternalError as u32;
    }

    // ── 14. Write response ──────────────────────────────────────────
    //
    // Two wire modes:
    //   * deployed: `[count(8)] [c10_sig(4008)]`              = 4016 B
    //   * 6492:     `[count(8)] [eip6492 blob(8608)]`         = 8616 B
    let count_be = new_count.to_be_bytes();
    for i in 0..8 {
        core::ptr::write_volatile(
            out_ptr.add(SIGN_OFFCHAIN_OUTPUT_COUNT_OFF + i),
            count_be[i],
        );
    }

    if account_deployed {
        // Existing path — byte-identical to pre-EIP-6492 builds.
        for i in 0..SIGNATURE_LEN {
            core::ptr::write_volatile(out_ptr.add(SIGN_OFFCHAIN_OUTPUT_SIG_OFF + i), sig[i]);
        }
    } else {
        // FI hardening: bind the larger write to a larger validation in
        // THIS branch. The 8616-byte (`SIGN_OFFCHAIN_OUTPUT_LEN_6492`)
        // extent was validated at the §4 gate only when `account_deployed`
        // read false *there*; this branch is entered on a second read of
        // the same un-hardened bool. A single fault that flips it
        // true→false between the gate and here would otherwise reach the
        // 8616-byte blob write below against a buffer only proven
        // NS-writable for the 4016-byte deployed extent — a ~4600-byte
        // overrun across the NS/secure-SRAM boundary. Re-validate the full
        // 6492 extent now, double-evaluated through a hamming-distant
        // sentinel (same pattern as F-8 in `nsc::ns_ptr`), so reaching the
        // larger write *requires* a passing larger validation in the same
        // branch: two coordinated faults are needed instead of one.
        let extent_ok = crate::fi::check_true_into_sentinel(|| {
            validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN_6492)
        });
        if extent_ok != crate::fi::OK_SENTINEL {
            crate::ui::show_status("EIP-1271", "bad out 6492");
            return NscStatus::InvalidPointer as u32;
        }

        // ERC-6492 counterfactual path.
        //
        // 1. Build the inner SignatureWrapper `(uint256 ownerIndex,
        //    bytes c10Sig)`. ownerIndex = slot_index + 1 = 1 (slot 0
        //    is always at ownerIndex 1; ownerIndex 0 is bootstrap).
        // 2. Derive the bootstrap C10 master keypair and slot-0 pubkey
        //    halves; build the factory calldata that would deploy
        //    this wallet, signed by the bootstrap key.
        // 3. ABI-encode `(factory, fc, sigWrapper) || MAGIC_6492`.
        let mut inner_wrapper: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
            Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
        super::sig_wrapper::encode_signature_wrapper(
            &mut *inner_wrapper,
            (slot_index as u64) + 1,
            &sig,
        );

        // Bootstrap C10 keypair + slot-0 pubkey halves. The bootstrap
        // SK is needed to sign the factory-add-slot digest; we always
        // re-derive it (the SK is not cached — only the public halves
        // are, in `bootstrap_cache`).
        crate::ui::show_progress("C10 keygen", 0);
        let (master_c10_sk, master_pk_seed_32, master_pk_root_32) =
            crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                &*entropy,
                account_index,
                |p| crate::ui::show_progress("C10 keygen", p),
            );
        // Refresh cache for subsequent CMD_GET_WALLET_ADDRESS / repeat
        // calls.
        super::state::with_state(|s| {
            s.bootstrap_cache_insert(account_index, master_pk_seed_32, master_pk_root_32);
        });

        // Slot-0 pubkey halves from the SLOT_CACHE (slot keygen
        // already ran above in step 10). The cached secret key
        // exposes the pubkey halves via `pk_seed()` / `pk_root()`.
        let (slot0_pk_seed_32, slot0_pk_root_32) = {
            // SAFETY: category 5 — read-only borrow of `static mut
            // SLOT_CACHE`. Single-threaded dispatcher; the slot
            // keygen above populated the cache for this exact
            // (account, chain, slot=0).
            let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
            match cached {
                Some(c) => {
                    let mut seed = [0u8; 32];
                    let mut root = [0u8; 32];
                    seed[..16].copy_from_slice(&c.key.pk_seed()[..16]);
                    root[..16].copy_from_slice(&c.key.pk_root()[..16]);
                    (seed, root)
                }
                None => {
                    drop(master_c10_sk);
                    crate::ui::show_status("EIP-1271", "slot cache MIA");
                    return NscStatus::InternalError as u32;
                }
            }
        };

        // Build factoryCalldata into a Zeroizing stack buffer.
        let mut fc: Zeroizing<[u8; EIP6492_FACTORY_CALLDATA_LEN]> =
            Zeroizing::new([0u8; EIP6492_FACTORY_CALLDATA_LEN]);
        if let Err(status) = super::factory_calldata::build(
            &mut *fc,
            chain_id,
            &master_c10_sk,
            &master_pk_seed_32,
            &master_pk_root_32,
            &slot0_pk_seed_32,
            &slot0_pk_root_32,
            |p| crate::ui::show_progress("C10 sign", p),
        ) {
            drop(master_c10_sk);
            crate::ui::show_status("EIP-1271", "factory sign FAIL");
            return status as u32;
        }
        drop(master_c10_sk); // ZeroizeOnDrop wipes sk_seed.

        // Build the ERC-6492 blob.
        let mut blob: Zeroizing<[u8; EIP6492_BLOB_LEN]> =
            Zeroizing::new([0u8; EIP6492_BLOB_LEN]);
        crate::aa::eip6492::wrap_signature(
            &mut *blob,
            &PQ_SMART_WALLET_FACTORY,
            &*fc,
            &*inner_wrapper,
        );

        // Volatile-copy into the NS output buffer (after the 8-byte
        // count prefix).
        for i in 0..EIP6492_BLOB_LEN {
            core::ptr::write_volatile(out_ptr.add(8 + i), blob[i]);
        }
    }

    // L-2: wipe the TOCTOU snapshot on exit.
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    crate::timeout::reset_activity();
    crate::ui::show_status("Signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    crate::ui::show_status("PQSigner OS", "Ready");
    NscStatus::Ok as u32
}
