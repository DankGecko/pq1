//! Build script for the first-stage bootloader.
//!
//! Does two things:
//!
//! 1. Places `memory-stm32u585.x` where cortex-m-rt's `link.x` can find
//!    it (copies to OUT_DIR and adds OUT_DIR to the linker search path).
//!    The FSBL only ever builds for `thumbv8m.main-none-eabi`; there is
//!    no host-side smoke test for it because the full bring-up sequence
//!    only makes sense on real hardware.
//!
//! 2. Embeds the vendor SPHINCS+C10 public key from the path in the
//!    `FSBL_VENDOR_PUBKEY` environment variable into a generated
//!    `vendor_pubkey_bytes.rs` source file. Release builds MUST set
//!    this env var; if it's unset we fall back to a committed
//!    development pubkey at `fixtures/dev_pubkey.bin` (non-secret; the
//!    matching vendor SK is the one used by integration tests). The
//!    FSBL at boot time rejects a release signed by a different key
//!    than its compiled-in pubkey, so dev FSBLs cannot run
//!    production-signed firmware and vice versa — which is the
//!    intended safety property.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let is_thumbv = target.contains("thumbv");

    // --- Linker script (thumbv only) ----------------------------------------
    // Host builds (e.g. `cargo test` for the FSBL integration tests in
    // `fsbl/tests/`) compile the bin only to type-check it / to build
    // build-script outputs; the linker script and on-target link step
    // are not exercised.
    println!("cargo:rerun-if-changed=build.rs");
    if is_thumbv {
        fs::copy("memory-stm32u585.x", out_dir.join("memory.x"))
            .expect("copying memory-stm32u585.x");
        println!("cargo:rustc-link-search={}", out_dir.display());
        println!("cargo:rerun-if-changed=memory-stm32u585.x");
    }

    // --- Vendor pubkey embedding --------------------------------------------
    //
    // Production: FSBL_VENDOR_PUBKEY points at a 32-byte file produced by
    // `fwsign pubkey`. This is the file that will be burned into every
    // production FSBL image; changing it changes the set of releases the
    // device will accept.
    //
    // Dev: if FSBL_VENDOR_PUBKEY is unset, we regenerate a fixed-seed
    // development pubkey on the fly using sphincs-c10. The seed below is
    // the same one used by fwsign's integration tests (sign_verify_roundtrip),
    // so dev FSBLs and dev-signed .pqfw bundles verify against each other.
    println!("cargo:rerun-if-env-changed=FSBL_VENDOR_PUBKEY");

    let (pk_seed, pk_root, source_desc): ([u8; 16], [u8; 16], String) =
        if let Ok(path) = env::var("FSBL_VENDOR_PUBKEY") {
            println!("cargo:rerun-if-changed={path}");
            let bytes = fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
            if bytes.len() != 32 {
                panic!(
                    "{path}: expected 32 bytes (pk_seed[16] || pk_root[16]), got {}",
                    bytes.len()
                );
            }
            let mut s = [0u8; 16];
            let mut r = [0u8; 16];
            s.copy_from_slice(&bytes[..16]);
            r.copy_from_slice(&bytes[16..]);
            (s, r, format!("FSBL_VENDOR_PUBKEY={path}"))
        } else {
            // SECURITY (finding F2): the dev fallback below derives a FIXED,
            // committed SPHINCS+C10 vendor key (matching seed in
            // `fwsign/src/subcommands/dev_pubkey.rs`). Anyone with the source
            // tree can sign manifests that verify under it, so an FSBL built
            // with this key must NEVER leave the bench. Previously this path
            // only emitted a `cargo:warning` and built anyway — a
            // release-profile FSBL with `FSBL_VENDOR_PUBKEY` unset silently
            // embedded the public dev key. Now the dev fallback is an explicit
            // opt-in: a build with neither the real pubkey nor `FSBL_ALLOW_DEV_KEY`
            // is a hard error. `make fsbl` sets the opt-in for dev convenience;
            // `make fsbl-release` sets neither and provides the real pubkey.
            println!("cargo:rerun-if-env-changed=FSBL_ALLOW_DEV_KEY");
            if env::var("FSBL_ALLOW_DEV_KEY").is_err() {
                panic!(
                    "FSBL_VENDOR_PUBKEY is unset and FSBL_ALLOW_DEV_KEY is not set. \
                     Refusing to embed the committed development vendor key: an FSBL \
                     built with it accepts firmware signed by anyone holding the \
                     (public, in-tree) dev seed. Provide a real key via \
                     `FSBL_VENDOR_PUBKEY=<32-byte pubkey>` (production, e.g. \
                     `make fsbl-release`), or explicitly opt into the dev key with \
                     `FSBL_ALLOW_DEV_KEY=1` (bench/dev only, e.g. `make fsbl`)."
                );
            }
            println!("cargo:warning=FSBL_VENDOR_PUBKEY unset — using built-in dev fixture key (FSBL_ALLOW_DEV_KEY opt-in). DO NOT USE FOR PRODUCTION.");
            let dev_sk: [u8; 32] = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10,
            ];
            let dev_ps: [u8; 16] = [
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
                0xae, 0xaf,
            ];
            let sk = sphincs_c10::SigningKey::keygen(dev_sk, dev_ps);
            (*sk.pk_seed(), *sk.pk_root(), "built-in dev fixture".to_string())
        };

    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&pk_seed);
    bytes[16..].copy_from_slice(&pk_root);

    // Emit a source file with the pubkey as a literal byte array plus
    // its SHA-256 fingerprint. The fingerprint is pre-computed at build
    // time so the FSBL's vendor-fpr check is a plain memcmp at runtime.
    use sha2::{Digest, Sha256};
    let fpr: [u8; 32] = Sha256::digest(&bytes).into();

    let mut src = String::new();
    src.push_str("// AUTO-GENERATED by fsbl/build.rs — do not edit by hand.\n");
    src.push_str(&format!(
        "//\n// Source: {source_desc}\n// SHA-256(pubkey): {}\n\n",
        fpr.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    src.push_str("/// Vendor pk_seed (first 16 bytes of the 32-byte pubkey).\n");
    src.push_str(&format!("pub const VENDOR_PK_SEED: [u8; 16] = {:?};\n", &bytes[..16]));
    src.push_str("/// Vendor pk_root (last 16 bytes of the 32-byte pubkey).\n");
    src.push_str(&format!("pub const VENDOR_PK_ROOT: [u8; 16] = {:?};\n", &bytes[16..]));
    src.push_str(
        "/// SHA-256(pk_seed || pk_root). Pre-computed at build time so\n\
        /// the runtime vendor-fpr check is a memcmp.\n",
    );
    src.push_str(&format!("pub const VENDOR_PK_FPR: [u8; 32] = {:?};\n", fpr));

    fs::write(out_dir.join("vendor_pubkey_bytes.rs"), src)
        .expect("writing vendor_pubkey_bytes.rs");

    // --- Font table for the OLED fingerprint renderer ----------------------
    //
    // FSBL renders the 8-BIP-39-word firmware fingerprint on the OLED
    // BEFORE branching into the slot. It needs an ASCII font; we vendor
    // the same 5×8 raw bitmap the secure-world uses
    // (`secure/assets/font_5x8.raw`, MIT, from embedded-graphics) so the
    // FSBL row and the secure-world `measured_boot` row are visually
    // identical. ~480 bytes of rodata.
    generate_font_flat(&out_dir);
}

/// Generate `glyphs_5x8.rs` in OUT_DIR from `../secure/assets/font_5x8.raw`.
///
/// Output format mirrors `secure/build.rs::generate_font_flat` so the FSBL
/// and the secure world share the same glyph data — only the rendering
/// path differs (FSBL is no_std + minimal, secure-world goes through
/// embedded-graphics). Column-byte format: bit `r` of byte `c` = pixel at
/// column `c`, row `r` (0 = top). Matches SSD1306 page layout so the FSBL
/// blit can OR column-bytes directly into the framebuffer.
fn generate_font_flat(out_dir: &PathBuf) {
    let raw_path = "../secure/assets/font_5x8.raw";
    println!("cargo:rerun-if-changed={raw_path}");

    let raw = fs::read(raw_path).unwrap_or_else(|e| {
        panic!("vendored {raw_path} missing or unreadable: {e}")
    });

    const BITMAP_W: usize = 80;
    const BITMAP_H: usize = 48;
    const BYTES_PER_ROW: usize = BITMAP_W / 8; // 10
    assert_eq!(
        raw.len(),
        BITMAP_W * BITMAP_H / 8,
        "FONT_5X8 raw must be exactly {} bytes ({}×{}@1bpp); got {}",
        BITMAP_W * BITMAP_H / 8,
        BITMAP_W,
        BITMAP_H,
        raw.len()
    );

    const GLYPH_W: usize = 5;
    const GLYPH_H: usize = 8;
    const CHARS_PER_ROW: usize = 16;
    const FIRST_CHAR: u8 = 0x20;
    const LAST_CHAR: u8 = 0x7F;
    const N_GLYPHS: usize = (LAST_CHAR - FIRST_CHAR + 1) as usize; // 96

    let pixel = |px: usize, py: usize| -> bool {
        let byte = raw[py * BYTES_PER_ROW + px / 8];
        (byte >> (7 - (px % 8))) & 1 != 0
    };

    let mut out = String::new();
    out.push_str(
        "// AUTO-GENERATED by fsbl/build.rs from ../secure/assets/font_5x8.raw.\n\
         // MIT-licensed, vendored from embedded-graphics v0.8.2.\n\
         // See secure/assets/font_5x8.LICENSE for attribution.\n\n",
    );
    out.push_str(&format!("pub const FONT_FIRST_CHAR: u8 = 0x{FIRST_CHAR:02x};\n"));
    out.push_str(&format!("pub const FONT_LAST_CHAR: u8  = 0x{LAST_CHAR:02x};\n"));
    out.push_str(&format!("pub const FONT_GLYPH_W: usize = {GLYPH_W};\n"));
    out.push_str(&format!("pub const FONT_GLYPH_H: usize = {GLYPH_H};\n"));
    out.push_str(&format!("pub const FONT_N_GLYPHS: usize = {N_GLYPHS};\n\n"));
    out.push_str(
        "pub static FONT_FLAT_5X8: [[u8; FONT_GLYPH_W]; FONT_N_GLYPHS] = [\n",
    );

    for ch in FIRST_CHAR..=LAST_CHAR {
        let glyph_idx = (ch - FIRST_CHAR) as usize;
        let glyph_x = (glyph_idx % CHARS_PER_ROW) * GLYPH_W;
        let glyph_y = (glyph_idx / CHARS_PER_ROW) * GLYPH_H;

        let mut cols = [0u8; GLYPH_W];
        for cc in 0..GLYPH_W {
            let mut col_byte: u8 = 0;
            for row in 0..GLYPH_H {
                if pixel(glyph_x + cc, glyph_y + row) {
                    col_byte |= 1u8 << row;
                }
            }
            cols[cc] = col_byte;
        }

        let printable = if ch == b'\\' {
            "\\\\".to_string()
        } else if ch == 0x7F {
            "DEL".to_string()
        } else {
            format!("{}", ch as char)
        };
        out.push_str(&format!(
            "    /* 0x{ch:02x} {printable:>3} */ [0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x}],\n",
            cols[0], cols[1], cols[2], cols[3], cols[4]
        ));
    }
    out.push_str("];\n");

    fs::write(out_dir.join("glyphs_5x8.rs"), out).expect("writing glyphs_5x8.rs");
}
