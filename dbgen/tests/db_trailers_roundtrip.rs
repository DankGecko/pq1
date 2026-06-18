//! Companion-stub round-trip for the now-host-side ERC-20 / names / VK
//! DBs.
//!
//! These three DBs no longer ship in the firmware image — they live
//! under `tools/companion-stub/` and the companion app builds the
//! per-tx `(entry, merkle_proof, leaf_index)` bundle. The device holds
//! only the 32-byte Merkle root and verifies the bundle in S-world.
//!
//! Each test runs the Python reference builder
//! (`tools/companion-stub/db_trailers.py`) against the committed blob,
//! then feeds its output back through the SAME on-device verifier the
//! secure world uses (`pqsigner_tx`), asserting:
//!   * a faithfully-built bundle verifies against the freshly-computed
//!     pinned root (correctness + the wire format stays locked to the
//!     Python builder byte-for-byte), and
//!   * a single tampered byte makes verification fail (forge-resistance
//!     — a malicious companion cannot fabricate an entry).

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Run `db_trailers.py <kind> --chain <c> --contract <addr>` and return
/// the emitted bundle bytes, or `None` if the script/blob is absent
/// (keeps CI green on a checkout that hasn't run dbgen).
fn build_bundle(kind: &str, chain: u64, contract: &str) -> Option<Vec<u8>> {
    let root = workspace_root();
    let stub = root.join("tools/companion-stub/db_trailers.py");
    let db = root.join(format!("tools/companion-stub/{kind}_db.bin"));
    if !stub.exists() || !db.exists() {
        eprintln!("(skipped) companion stub or {kind} blob missing — run `cargo run -p dbgen`");
        return None;
    }
    let out = Command::new("python3")
        .arg(&stub)
        .arg(kind)
        .arg("--db")
        .arg(&db)
        .arg("--chain")
        .arg(chain.to_string())
        .arg("--contract")
        .arg(contract)
        .output()
        .expect("run companion stub");
    if !out.status.success() {
        panic!(
            "db_trailers.py {kind} failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    assert!(!out.stdout.is_empty(), "stub produced empty {kind} bundle");
    Some(out.stdout)
}

fn parse_hex20(s: &str) -> [u8; 20] {
    let s = s.trim_start_matches("0x");
    let v = hex::decode(s).expect("hex");
    let mut a = [0u8; 20];
    a.copy_from_slice(&v);
    a
}

#[test]
fn companion_stub_erc20_verifies_against_on_device() {
    // Telcoin (TEL) on Base (8453) — a Contract entry in erc20.json.
    let contract = "0x09bE1692ca16e06f536F0038fF11D1dA8524aDB1";
    let Some(bundle) = build_bundle("erc20", 8453, contract) else {
        return;
    };
    let res = dbgen::erc20::build_db(&workspace_root().join("secure/data/erc20.json"))
        .expect("build erc20 db");

    let meta = pqsigner_tx::erc20::bundle::verify_erc20_bundle(&bundle, &res.root)
        .expect("erc20 bundle verifies against pinned root");
    assert_eq!(meta.chain_id, 8453);
    assert_eq!(meta.contract, parse_hex20(contract));
    assert_eq!(meta.symbol, b"TEL");
    assert_eq!(meta.decimals, 2);

    // Forge-resistance: flip a byte inside the canonical metadata (the
    // decimals field) — the Merkle proof no longer reconstructs the
    // root, so verification must fail.
    let mut tampered = bundle.clone();
    tampered[28] ^= 0x01; // 8 (chain) + 20 (contract) = decimals offset
    assert!(
        pqsigner_tx::erc20::bundle::verify_erc20_bundle(&tampered, &res.root).is_none(),
        "tampered erc20 bundle must be rejected"
    );
}

#[test]
fn companion_stub_names_verifies_against_on_device() {
    // Uniswap V3 Router — a wildcard-chain (chain_id 0) entry. Query
    // with a real chain id to exercise the two-phase fallback.
    let contract = "0xE592427A0AEce92De3Edee1F18E0157C05861564";
    let Some(bundle) = build_bundle("names", 1, contract) else {
        return;
    };
    let res = dbgen::names::build_db(&workspace_root().join("secure/data/names.json"))
        .expect("build names db");

    let meta = pqsigner_tx::names::bundle::verify_name_bundle(&bundle, &res.root)
        .expect("names bundle verifies against pinned root");
    assert_eq!(meta.address, parse_hex20(contract));
    assert_eq!(meta.chain_id, 0, "wildcard entry crosses as chain_id 0");
    assert_eq!(meta.name, b"Uniswap V3 Router");

    // Forge-resistance: flip a byte in the address field.
    let mut tampered = bundle.clone();
    tampered[8] ^= 0x01; // first address byte (after 8-byte chain_id)
    assert!(
        pqsigner_tx::names::bundle::verify_name_bundle(&tampered, &res.root).is_none(),
        "tampered names bundle must be rejected"
    );
}

#[test]
fn companion_stub_vk_verifies_against_on_device() {
    // CowSwap Settlement on mainnet — a VK entry in vks.json.
    let contract = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41";
    let Some(bundle) = build_bundle("vk", 1, contract) else {
        return;
    };
    let root = workspace_root();
    let res = dbgen::vks::build_db(
        &root.join("secure/data/vks.json"),
        &root.join("secure/data/vks"),
    )
    .expect("build vk db");

    // The full VK parse lives in the secure crate, but the security-
    // critical step is the Merkle proof against VK_DB_ROOT, which is the
    // host-runnable `pqsigner_tx::erc20::merkle::verify_proof`. Re-derive
    // the canonical leaf exactly as `secure/src/zk/vk_bundle.rs` does:
    // chain_id(8 LE) || contract(20) || vk(1056).
    const VK_BLOB_LEN: usize = 1056;
    assert!(bundle.len() > 8 + 20 + VK_BLOB_LEN + 8, "vk bundle too short");
    let leaf_index = u32::from_le_bytes(
        bundle[8 + 20 + VK_BLOB_LEN..8 + 20 + VK_BLOB_LEN + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let proof_depth = u32::from_le_bytes(
        bundle[8 + 20 + VK_BLOB_LEN + 4..8 + 20 + VK_BLOB_LEN + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let canonical = &bundle[..8 + 20 + VK_BLOB_LEN];
    let proof = &bundle[8 + 20 + VK_BLOB_LEN + 8..];
    assert_eq!(proof.len(), proof_depth * 32, "proof length consistent");

    assert!(
        pqsigner_tx::erc20::merkle::verify_proof(
            canonical, leaf_index, proof, proof_depth, &res.root,
        ),
        "vk bundle Merkle proof must verify against the pinned VK root"
    );

    // Forge-resistance: flip a byte inside the VK blob.
    let mut bad = canonical.to_vec();
    bad[8 + 20 + 10] ^= 0x01;
    assert!(
        !pqsigner_tx::erc20::merkle::verify_proof(
            &bad, leaf_index, proof, proof_depth, &res.root,
        ),
        "tampered VK leaf must be rejected"
    );
}
