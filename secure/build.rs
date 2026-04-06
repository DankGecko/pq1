use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Copy memory.x
    fs::copy("memory.x", out_dir.join("memory.x")).unwrap();
    println!("cargo:rerun-if-changed=memory.x");

    // Find cortex-m-rt's link.x and modify it to place .gnu.sgstubs in NSC region
    // instead of FLASH. This is needed because QEMU 8.2.2's SG instruction check
    // reads through the MPC NS alias, so the veneers must be in NS MPC blocks.
    let link_x = find_link_x(&out_dir);
    let modified = link_x.replace(
        "} > FLASH\n  /* Place `__veneer_limit`",
        "} > NSC\n  /* Place `__veneer_limit`",
    );
    fs::write(out_dir.join("link.x"), modified).unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
}

fn find_link_x(out_dir: &PathBuf) -> String {
    // cortex-m-rt puts link.x in a sibling build directory
    let target_dir = out_dir
        .ancestors()
        .find(|p| p.file_name().map(|f| f == "build").unwrap_or(false))
        .expect("Could not find build directory");

    for entry in fs::read_dir(target_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("cortex-m-rt-") {
            let link_path = entry.path().join("out").join("link.x");
            if link_path.exists() {
                return fs::read_to_string(&link_path).unwrap();
            }
        }
    }
    panic!("Could not find cortex-m-rt's link.x");
}
