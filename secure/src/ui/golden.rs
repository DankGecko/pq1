//! Render-only golden-screenshot harness (#21 — a FAST ui-golden gate).
//!
//! Renders a curated set of display screens directly through the production
//! renderers and flushes each page (which, under `ui-capture`, emits a
//! `[UI-FP]` fingerprint), WITHOUT the C10 keygen/sign that makes the
//! e2e-based `ui-golden` target too slow on QEMU's software SHA-256 (it reached
//! only one scenario in ~150 s). Build with `ui-golden-render,ui-capture` and
//! diff the fingerprints against `tests/ui_golden_render_fixtures.json`.
//!
//! v1 covers the value-transfer renderer (the core path: it exercises the
//! shared `primitives` — amount/address/chain/fee formatting — used by every
//! other screen). Extend `screens()` with ERC-20 / Safe / CoW inputs to widen
//! coverage; each added screen appends `[UI-FP]` frames, so just regenerate the
//! fixtures (`make ui-golden-render-bless`).
#![cfg(feature = "ui-golden-render")]

use crate::names::NameResolver;
use crate::tx::display::value_transfer;
use crate::tx::eip1559::{Eip1559Tx, U256};

/// A `u128` amount (wei) as a big-endian [`U256`].
fn wei(n: u128) -> U256 {
    let mut b = [0u8; 32];
    b[16..].copy_from_slice(&n.to_be_bytes());
    U256(b)
}

fn tx(chain_id: u64, to: Option<[u8; 20]>, value: U256, nonce: u64, data_len: usize) -> Eip1559Tx {
    Eip1559Tx {
        chain_id,
        nonce,
        max_priority_fee_per_gas: wei(1_500_000_000), // 1.5 gwei
        max_fee_per_gas: wei(30_000_000_000),         // 30 gwei
        gas_limit: 21_000,
        to,
        value,
        data_len,
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: None,
    }
}

/// The curated screen corpus. Order is stable — fixtures key on frame index.
fn screens() -> [Eip1559Tx; 5] {
    [
        // 1 ETH on Ethereum mainnet.
        tx(1, Some([0xAB; 20]), wei(1_000_000_000_000_000_000), 0, 0),
        // 1 wei — exercises the exact known-chain base-unit fallback.
        tx(1, Some([0x11; 20]), wei(1), 5, 0),
        // 123.456789 ETH on Base (8453) — multi-digit value + chain name.
        tx(8453, Some([0xCD; 20]), wei(123_456_789_000_000_000_000), 42, 0),
        // Contract creation (to = None) with calldata.
        tx(1, None, U256::zero(), 7, 96),
        // Contract call (value 0) on Optimism (10) with calldata.
        tx(10, Some([0xEF; 20]), U256::zero(), 1, 68),
    ]
}

/// Render every curated screen, then exit cleanly so `probe-rs`/QEMU returns.
/// Each rendered page emits one `[UI-FP]` line over the secure log.
pub fn render_golden_and_halt() -> ! {
    // The harness runs early in boot, before the main `ui::init()`; bring the
    // display up so render_page's flush reaches the capture backend.
    crate::ui::init();
    let resolver = NameResolver::new();
    for t in &screens() {
        let pages = value_transfer::render_pages(t, &resolver);
        crate::ui::confirm::render_capture_pages(pages.as_slice());
    }
    cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
    #[allow(unreachable_code)]
    loop {
        cortex_m::asm::wfe();
    }
}
