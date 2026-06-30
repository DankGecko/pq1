//! `pqsigner-tx` — pure-logic Solidity-ABI trust gates.
//!
//! Hosts:
//!
//! - [`cowswap_order`] — pure field-decode of the 204-byte canonical
//!   CowSwap `GPv2Order` packed encoding (Kani decode-soundness verified).
//! - [`erc20`] — ERC-20 metadata Merkle DB + strict `transfer` /
//!   `transferFrom` / `approve` calldata decoder + dispatch.
//! - [`multisend`] — strict Safe `MultiSendCallOnly` outer-framing
//!   decoder (Kani canonical-acceptance / soundness verified).
//! - [`names`] — address-name DB + stack-resident [`names::NameResolver`].
//! - [`safe_tx`] — pure byte-layout decoders for the Safe SafeTx
//!   clear-sign path: the 281-byte canonical typed-data
//!   ([`safe_tx::decode_canonical`], Kani exhaustive biconditional) and
//!   the `execTransaction(...)` calldata with dynamic `data`/`signatures`
//!   ([`safe_tx::decode_exec_transaction`], Kani no-read-past-end +
//!   fixed-field soundness).
//! - [`selectors`] — function-selector → text-sig DB.
//!
//! The `verify_*_bundle` Merkle verifiers all take a `root: &[u8; 32]`
//! parameter so the embedded `secure/src/db_roots.rs` constants can be
//! injected from the call site instead of hard-coded into the crate.
//! That keeps `pqsigner-tx` reusable by any future host-side
//! reference-signer that exercises the same trust gates.
//!
//! Phase 5 PR 5.4 of the modularity refactor extracted these out of
//! `secure/src/{erc20,names,selectors}/`. Existing call sites continue
//! to work because the secure-side `mod.rs` files now re-export from
//! here and bake the embedded root into thin wrapper functions.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod wire;

pub mod cowswap_order;
pub mod erc20;
pub mod multisend;
pub mod names;
pub mod safe_tx;
pub mod selectors;
pub mod typed_call;
