//! Host-side firmware measurement tool.
//!
//! Reads a secure-world ELF, reconstructs the flash image, SHA-256
//! hashes it, and outputs 8 BIP-39 words. The device displays the
//! same 8 words at boot so the user can visually compare.
//!
//! Usage:
//!
//!   cargo run -p fwmeasure -- path/to/sphincs-tz-secure
//!   cargo run -p fwmeasure -- path/to/image.elf --flash-base 0x0C00_E000
//!
//! Or via the Makefile:
//!
//!   make measure
//!
//! ## Slot-aware measurement
//!
//! The firmware-update subsystem places each A/B slot at a different
//! base address. When measuring a release artifact destined for a
//! specific slot, pass `--flash-base=<hex>` / `--flash-end=<hex>` to
//! override the enclosing measurement window. Overrides are strict:
//! every non-empty `PT_LOAD` must still fit wholly inside that window.

#[cfg(test)]
use fwmeasure::MAX_FLASH_SIZE;
use fwmeasure::{flatten_elf_with_overrides, LayoutOverrides};
use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};
use std::fmt::Display;
use std::{env, process};

const USAGE: &str = "Usage: fwmeasure <firmware.elf> [--flash-base=0xHEX] [--flash-end=0xHEX] [--require-secure-slot]";

/// Parsed command-line arguments.
struct Args {
    elf_path: String,
    flash_base_override: Option<u64>,
    flash_end_override: Option<u64>,
    require_secure_slot: bool,
}

fn die(msg: impl Display) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}

fn parse_args() -> Args {
    let mut elf_path: Option<String> = None;
    let mut flash_base_override: Option<u64> = None;
    let mut flash_end_override: Option<u64> = None;
    let mut require_secure_slot = false;

    for arg in env::args().skip(1) {
        if let Some(rest) = arg.strip_prefix("--flash-base=") {
            flash_base_override = Some(parse_hex(rest));
        } else if let Some(rest) = arg.strip_prefix("--flash-end=") {
            flash_end_override = Some(parse_hex(rest));
        } else if arg == "--require-secure-slot" {
            require_secure_slot = true;
        } else if let Some(prev) = elf_path.as_deref() {
            die(format_args!("Multiple ELF paths: {prev:?} and {arg:?}"));
        } else {
            elf_path = Some(arg);
        }
    }

    Args {
        elf_path: elf_path.unwrap_or_else(|| die(USAGE)),
        flash_base_override,
        flash_end_override,
        require_secure_slot,
    }
}

fn parse_hex(s: &str) -> u64 {
    let cleaned = s.trim_start_matches("0x").replace('_', "");
    u64::from_str_radix(&cleaned, 16)
        .unwrap_or_else(|e| die(format_args!("Cannot parse hex address {s:?}: {e}")))
}

fn format_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Print the 8 BIP-39 words to stdout, one per line ("N word").
/// `make verify-release` greps stdout for these.
fn print_words(hash: &[u8; 32]) {
    for (i, &idx) in hash_to_word_indices(hash).iter().enumerate() {
        println!("{} {}", i + 1, WORDLIST[idx as usize]);
    }
}

fn main() {
    let args = parse_args();
    let image = flatten_elf_with_overrides(
        std::path::Path::new(&args.elf_path),
        LayoutOverrides {
            flash_base: args.flash_base_override,
            flash_end: args.flash_end_override,
        },
    )
    .unwrap_or_else(|error| die(error));

    if args.require_secure_slot && image.bytes.len() > fw_manifest::SLOT_SECURE_CAPACITY as usize {
        die(format_args!(
            "secure image is {} bytes, above the fixed {}-byte slot capacity",
            image.bytes.len(),
            fw_manifest::SLOT_SECURE_CAPACITY
        ));
    }

    eprintln!("Flash base:  0x{:08X}", image.base);
    eprintln!(
        "Flash end:   0x{:08X} ({} bytes)",
        image.end(),
        image.bytes.len()
    );
    if args.require_secure_slot {
        eprintln!(
            "Flash limit: {} bytes (secure slot)",
            fw_manifest::SLOT_SECURE_CAPACITY
        );
    }
    eprintln!("SHA-256:     {}", format_hex(&image.hash));
    eprintln!();

    print_words(&image.hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- positive: parse_hex ----------------

    #[test]
    fn positive_parse_hex_accepts_prefix_and_underscores() {
        assert_eq!(parse_hex("0x0C00_E000"), 0x0C00_E000);
        assert_eq!(parse_hex("0C00E000"), 0x0C00_E000);
        assert_eq!(parse_hex("0x0"), 0);
    }

    #[test]
    fn positive_parse_hex_accepts_uppercase_and_lowercase_digits() {
        // The Makefile examples mix cases; tool must accept both.
        assert_eq!(parse_hex("0xDEADbeef"), 0xDEAD_BEEF);
        assert_eq!(parse_hex("deadbeef"), 0xDEAD_BEEF);
    }

    #[test]
    fn positive_parse_hex_accepts_u64_max() {
        // Per-slot bases on 64-bit fields must fit u64.
        assert_eq!(parse_hex("0xFFFFFFFFFFFFFFFF"), u64::MAX);
    }

    #[test]
    fn positive_parse_hex_strips_only_leading_0x_prefix() {
        // `strip_prefix("0x")` only strips a single leading `0x` —
        // confirm a value that legitimately contains '0' digits
        // after the prefix is preserved exactly.
        assert_eq!(parse_hex("0x000000000800E000"), 0x0800_E000);
    }

    // ---------------- positive: format_hex ----------------

    #[test]
    fn positive_format_hex_lowercase_zero_padded() {
        assert_eq!(format_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(format_hex(&[]), "");
    }

    #[test]
    fn positive_format_hex_full_sha256_length() {
        // SHA-256 hashes are 32 B → exactly 64 hex characters.
        let hash = [0xA5u8; 32];
        let hex = format_hex(&hash);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hex.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn positive_format_hex_pairs_per_byte() {
        // Every input byte must be exactly two hex chars; never 1 or 3.
        for b in 0u8..=255 {
            let s = format_hex(&[b]);
            assert_eq!(s.len(), 2, "byte 0x{b:02x} produced {s:?}");
        }
    }

    // ---------------- positive: invariants ----------------

    #[test]
    fn positive_max_flash_size_is_two_mib() {
        assert_eq!(MAX_FLASH_SIZE, 2 * 1024 * 1024);
    }

    #[test]
    fn positive_usage_string_documents_both_flags() {
        // Pin the help-text shape so refactors that drop/rename
        // either flag will be caught (companion docs reference both).
        assert!(USAGE.contains("--flash-base="));
        assert!(USAGE.contains("--flash-end="));
        assert!(USAGE.contains("--require-secure-slot"));
        assert!(USAGE.contains("<firmware.elf>"));
    }

    // ---------------- negative: parse_hex stripping behaviour ----------------

    #[test]
    fn negative_parse_hex_underscores_stripped_anywhere() {
        // Documenting the contract: `_` is dropped before parsing,
        // including in non-grouped positions. A future change that
        // narrowed the strip to "thousands grouping only" would
        // silently change accepted inputs.
        assert_eq!(parse_hex("0x__08__00__"), 0x0800);
    }

    #[test]
    fn negative_parse_hex_does_not_silently_accept_uppercase_0x() {
        // `strip_prefix("0x")` is case-sensitive — `0X` is NOT a
        // valid prefix. The hex parser will still accept the rest as
        // hex digits IF and only if every char is a valid hex digit.
        // `0X100` after strip is "0X100", and 'X' is not hex → must
        // fail. We can't exercise `die` directly (it calls
        // process::exit), but we can confirm `u64::from_str_radix`
        // rejects it, which is what `parse_hex` relies on.
        assert!(u64::from_str_radix("0X100", 16).is_err());
    }

    // ---------------- negative: format_hex is not Debug-leaking ----------------

    #[test]
    fn negative_format_hex_never_emits_uppercase() {
        // Receipts must be reproducible byte-for-byte. Any future
        // change to `{b:02X}` would break the "compare these hex
        // strings" UX with the device, which renders lowercase.
        for b in 0u8..=255 {
            let s = format_hex(&[b]);
            assert!(
                s.chars().all(|c| !c.is_ascii_uppercase()),
                "byte 0x{b:02x} produced uppercase {s:?}"
            );
        }
    }
}
