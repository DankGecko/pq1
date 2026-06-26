//! FSBL footprint CI gate.
//!
//! Builds `pqsigner-fsbl --release --target thumbv8m.main-none-eabi`
//! with the production link flags, runs `arm-none-eabi-size` on the
//! resulting ELF, and asserts the on-flash sections stay under the
//! WRP1A-locked FSBL flash region (32 KB at `0x0C00_0000`, per
//! `fsbl/memory-stm32u585.x: FLASH 32K`).
//!
//! Why this lives at the CI layer: the WRP1A region is irreversibly
//! locked at factory provisioning. A future PR that pushes FSBL over
//! 32 KB silently breaks production builds — better to fail
//! `cargo test` than to discover it at provisioning time.

use std::path::PathBuf;
use std::process::Command;

/// Hard ceiling for the FSBL: 32 KB across pages 0–3 of bank 1.
/// Matches `fsbl/memory-stm32u585.x: FLASH 32K`.
const FSBL_FLASH_CEILING: u64 = 32 * 1024;

/// Returns true if `arm-none-eabi-size` is on PATH.
fn toolchain_available() -> bool {
    Command::new("arm-none-eabi-size")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Walk up from the test's `current_dir` until we find the workspace
/// root (the dir containing `Cargo.toml` with `[workspace]`).
fn workspace_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            let s = std::fs::read_to_string(&candidate).unwrap_or_default();
            if s.contains("[workspace]") {
                return p;
            }
        }
        if !p.pop() {
            panic!("no [workspace] Cargo.toml above cwd");
        }
    }
}

#[test]
fn fsbl_release_flash_sections_fit_in_32kb() {
    if !toolchain_available() {
        eprintln!(
            "skipping: arm-none-eabi-size not on PATH. Install the \
             gcc-arm-none-eabi toolchain to enable this CI gate."
        );
        return;
    }

    let workspace = workspace_root();
    let target_dir = workspace.join("target/fsbl-footprint-test");

    let status = Command::new("cargo")
        .current_dir(&workspace)
        .env("RUSTFLAGS", "-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x")
        // F2: a release FSBL build hard-fails unless a real vendor pubkey
        // (FSBL_VENDOR_PUBKEY) or the explicit dev opt-in (FSBL_ALLOW_DEV_KEY)
        // is set. This is a SIZE test — the key content is irrelevant to the
        // footprint, and the built-in dev fixture key is the right size — so
        // opt into it here. (Production size is identical: a real 32-byte
        // pubkey embeds the same way.)
        .env("FSBL_ALLOW_DEV_KEY", "1")
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "thumbv8m.main-none-eabi",
            "--target-dir",
        ])
        .arg(&target_dir)
        .args(["-p", "pqsigner-fsbl"])
        .status()
        .expect("spawn cargo build");
    assert!(status.success(), "fsbl release build must succeed");

    let elf = target_dir.join("thumbv8m.main-none-eabi/release/pqsigner-fsbl");
    assert!(elf.exists(), "fsbl ELF not produced at {}", elf.display());

    let out = Command::new("arm-none-eabi-size")
        .arg("--format=sysv")
        .arg(&elf)
        .output()
        .expect("arm-none-eabi-size");
    assert!(out.status.success(), "arm-none-eabi-size failed");
    let text = String::from_utf8_lossy(&out.stdout);

    // Sum the sections that consume on-device flash. Mirrors the
    // Makefile's `make fsbl` size printout.
    let flash_sections = [
        ".vector_table",
        ".text",
        ".rodata",
        ".data",
        ".gnu.sgstubs",
    ];
    let mut total: u64 = 0;
    let mut per_section: Vec<(String, u64)> = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0];
        if !flash_sections.contains(&name) {
            continue;
        }
        let size: u64 = parts[1].parse().unwrap_or(0);
        total += size;
        per_section.push((name.to_string(), size));
    }

    eprintln!("FSBL footprint breakdown:");
    for (name, size) in &per_section {
        eprintln!("  {:<16} {:>6} bytes", name, size);
    }
    eprintln!(
        "  TOTAL            {:>6} bytes (ceiling {})",
        total, FSBL_FLASH_CEILING
    );

    assert!(
        total <= FSBL_FLASH_CEILING,
        "FSBL footprint {} exceeds WRP1A-locked 32 KB ceiling ({} bytes over). \
         Drop to WORDLIST_PREFIX4 (saves ~2 KB), shave non-essential FSBL \
         code, or — last resort — bump the FSBL allocation by one page \
         (changes the flash map; touches WRP1A config).",
        total,
        total - FSBL_FLASH_CEILING,
    );
}
