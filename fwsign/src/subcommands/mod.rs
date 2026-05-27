//! Subcommand implementations. Each module is its own top-level
//! `run(..)` function called from `main.rs`.

pub mod dev_pubkey;
pub mod extract_sig;
pub mod gen_test_fixture;
pub mod inspect;
pub mod keygen;
pub mod pubkey;
pub mod sign;
pub mod verify;
pub mod verify_release;
