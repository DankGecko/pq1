use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=memory.x");
    if env::var("TARGET").unwrap_or_default().contains("thumb") {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        fs::copy("memory.x", out.join("memory.x")).expect("copy memory.x");
        println!("cargo:rustc-link-search={}", out.display());
    }
}
