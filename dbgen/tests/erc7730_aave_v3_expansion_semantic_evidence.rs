//! Offline evidence and renderer coverage for the bounded Aave V3 expansion in #378.
//!
//! This test binds four shared-address Pool deployments and the Ethereum
//! WrappedTokenGatewayV3 deployment at historical blocks. It deliberately does
//! not authorize later proxy upgrades, unevidenced deployments, permit routes,
//! transaction success, fallback, blind signing, hardware, or shipment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::{build_db_tolerant_with_erc20_capabilities, Erc7730BuildResult};
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::bundle::verify_erc7730_bundle;
use pqsigner_erc7730::display::render::render_erc7730_pages_with_signer_checked;
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, PathOp, Visibility};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx::names::NameResolver;
use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};
use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const POOL_PROXY: &str = "0x794a61358D6845594F94dc1DB02A252b5b4814aD";
const ADDRESSES_PROVIDER: &str = "0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb";
const BORROW_LOGIC: &str = "0x52Da0ce88202D1542543598D1e1e27F0d344726A";
const SUPPLY_LOGIC: &str = "0x584C7d8c4cb05304FE5Ac7fbc97f20A10Fb07564";
const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const GATEWAY: &str = "0xd01607c3C5eCABa394D8be377a08590149325722";
const WETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const ETHEREUM_POOL: &str = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2";
const GATEWAY_OWNER: &str = "0x5300A1a15135EA4dc7aD5A167152C01EFc9b192A";
const GATEWAY_DESCRIPTOR: &str = "calldata-WrappedTokenGatewayV3.json";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf()
}

fn pool_evidence() -> PathBuf {
    root().join("tests/erc7730-semantic-evidence/aave-v3-shared-pools")
}

fn gateway_evidence() -> PathBuf {
    root().join("tests/erc7730-semantic-evidence/aave-v3-ethereum-gateway")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid evidence hex")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read hex evidence {}: {error}", path.display())),
    )
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn abi_address(value: &Value) -> [u8; 20] {
    let word = decode_hex(value.as_str().expect("ABI address result"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..12], &[0u8; 12]);
    word[12..].try_into().expect("address word")
}

fn hex_u64(value: &Value) -> u64 {
    let text = value.as_str().expect("hex quantity");
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).expect("hex u64")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("selector")
}

fn selector_hex(signature: &str) -> String {
    format!("0x{}", hex::encode(selector(signature)))
}

fn collect_files(root: &Path, directory: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read evidence directory") {
        let entry = entry.expect("evidence entry");
        let kind = entry.file_type().expect("evidence file type");
        assert!(!kind.is_symlink(), "evidence must not contain symlinks");
        if kind.is_dir() {
            collect_files(root, &entry.path(), out);
        } else {
            out.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("file below evidence root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn assert_receipted_package(evidence: &Path, expected_artifacts: usize) -> Value {
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let artifacts = manifest["artifacts"].as_array().expect("artifact receipts");
    assert_eq!(artifacts.len(), expected_artifacts);
    let mut receipts = BTreeMap::new();
    for artifact in artifacts {
        let path = required_str(artifact, "path");
        assert!(
            receipts
                .insert(path.to_owned(), required_str(artifact, "sha256"))
                .is_none(),
            "duplicate receipt: {path}"
        );
        assert_eq!(
            sha256_hex(&fs::read(evidence.join(path)).expect("read receipted artifact")),
            required_str(artifact, "sha256"),
            "artifact receipt changed: {path}"
        );
    }
    let mut files = BTreeSet::new();
    collect_files(evidence, evidence, &mut files);
    files.remove("manifest.json");
    assert_eq!(
        files,
        receipts.keys().cloned().collect(),
        "every non-manifest artifact must be receipted exactly once"
    );
    manifest
}

fn results(batch: &Value) -> BTreeMap<u64, Value> {
    let mut out = BTreeMap::new();
    for item in batch.as_array().expect("RPC batch") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(item.get("error").is_none());
        let id = item["id"].as_u64().expect("RPC id");
        assert!(out.insert(id, item["result"].clone()).is_none());
    }
    out
}

fn request_map(evidence: &Path, directory: &str) -> BTreeMap<u64, Value> {
    let mut out = BTreeMap::new();
    for suffix in ["identity", "proxy", "links", "code", "admin"] {
        let path = evidence.join(format!("rpc/raw/{directory}/request-{suffix}.json"));
        for request in read_json(&path).as_array().expect("request batch") {
            let id = request["id"].as_u64().expect("request id");
            assert!(out.insert(id, request.clone()).is_none());
        }
    }
    out
}

fn response_map(evidence: &Path, directory: &str, provider: &str) -> BTreeMap<u64, Value> {
    let mut out = BTreeMap::new();
    for suffix in ["identity", "proxy", "links", "code", "admin"] {
        let path = evidence.join(format!(
            "rpc/raw/{directory}/response-{provider}-{suffix}.json"
        ));
        for (id, value) in results(&read_json(&path)) {
            assert!(out.insert(id, value).is_none());
        }
    }
    out
}

fn source_by_suffix<'a>(sources: &'a Value, suffix: &str) -> &'a Value {
    let matches = sources
        .as_object()
        .expect("standard-json sources")
        .iter()
        .filter(|(path, _)| path.ends_with(suffix))
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "one verified source ending in {suffix}");
    matches[0]
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn solidity_function<'a>(source: &'a str, name: &str) -> (&'a str, &'a str) {
    let needle = if name == "constructor" {
        "constructor(".to_owned()
    } else {
        format!("function {name}(")
    };
    let start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("source lost {name}"));
    let definition = &source[start..];
    let opening = definition.find('{').expect("function body");
    assert!(!definition[..opening].contains(';'));
    let mut depth = 0usize;
    for (offset, byte) in definition[opening..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return (
                        &definition[..opening],
                        &definition[opening..opening + offset + 1],
                    );
                }
            }
            _ => {}
        }
    }
    panic!("unclosed function {name}")
}

fn build_registry() -> Erc7730BuildResult {
    let root = root();
    let registry = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build ERC20 capabilities");
    build_db_tolerant_with_erc20_capabilities(
        &registry.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 catalogue")
    .0
}

fn synth_bundle(blob: &[u8], ir: &[u8], leaf_index: usize) -> Vec<u8> {
    let depth = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let proof_off = proofs_off + leaf_index * depth * 32;
    let mut bundle = Vec::new();
    bundle.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    bundle.extend_from_slice(ir);
    bundle.extend_from_slice(&(leaf_index as u32).to_be_bytes());
    bundle.extend_from_slice(&(depth as u32).to_be_bytes());
    bundle.extend_from_slice(&blob[proof_off..proof_off + depth * 32]);
    bundle
}

fn word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_address(value: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&value);
    word
}

fn calldata(signature: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    for word in words {
        out.extend_from_slice(word);
    }
    out
}

#[test]
fn shared_pool_fixed_block_evidence_is_complete_and_consistent() {
    let evidence = pool_evidence();
    let manifest = assert_receipted_package(&evidence, 93);
    assert!(required_str(&manifest, "boundary")
        .to_ascii_lowercase()
        .contains("future upgrades"));
    assert_eq!(manifest["contracts"]["pool_revision"].as_u64(), Some(11));
    assert_eq!(
        required_str(&manifest["contracts"], "eip1967_implementation_slot"),
        IMPLEMENTATION_SLOT
    );
    assert_eq!(
        required_str(&manifest["upstream"]["origin"], "commit"),
        "fd1fbd9150426ca8ace9cee45b4acf912ae84f5b"
    );
    assert_eq!(
        required_str(&manifest["upstream"]["address_book"], "commit"),
        "7e444a1e73b538fd0b9e093e5156401d6fccca7d"
    );

    let old = root().join("tests/erc7730-semantic-evidence/aave-v3-ethereum-pool");
    for file in [
        "PoolInstance.sol",
        "Pool.sol",
        "BorrowLogic.sol",
        "SupplyLogic.sol",
    ] {
        assert_eq!(
            fs::read(evidence.join("source").join(file)).unwrap(),
            fs::read(old.join("source").join(file)).unwrap(),
            "shared source must be the already-reviewed revision-11 source: {file}"
        );
    }
    assert_eq!(
        read_json(&evidence.join("abi/Pool.routes.abi.json")),
        read_json(&old.join("abi/Pool.routes.abi.json"))
    );

    for deployment in manifest["deployments"].as_array().expect("deployments") {
        let slug = required_str(deployment, "slug");
        let chain_id = deployment["chain_id"].as_u64().expect("chain id");
        let block_hash = required_str(deployment, "block_hash");
        let implementation = required_str(deployment, "implementation");
        let tag = json!({"blockHash": block_hash, "requireCanonical": true});
        let requests = request_map(&evidence, slug);
        assert_eq!(
            requests.keys().copied().collect::<BTreeSet<_>>(),
            (1..=15).collect()
        );
        assert_eq!(requests[&1]["method"], "eth_chainId");
        assert_eq!(requests[&2]["params"], json!([block_hash, false]));
        assert_eq!(
            requests[&3]["params"],
            json!([POOL_PROXY, IMPLEMENTATION_SLOT, tag.clone()])
        );
        for id in 3..=15 {
            if id == 15 || requests[&id]["method"] != "eth_chainId" {
                let params = requests[&id]["params"].as_array().expect("request params");
                if id != 2 {
                    assert_eq!(params.last(), Some(&tag), "EIP-1898 tag for id {id}");
                }
            }
        }
        for (id, target, data) in [
            (5, POOL_PROXY, selector_hex("ADDRESSES_PROVIDER()")),
            (6, POOL_PROXY, selector_hex("POOL_REVISION()")),
            (7, POOL_PROXY, selector_hex("getBorrowLogic()")),
            (8, POOL_PROXY, selector_hex("getSupplyLogic()")),
            (9, ADDRESSES_PROVIDER, selector_hex("getPool()")),
            (13, POOL_PROXY, selector_hex("implementation()")),
            (14, POOL_PROXY, selector_hex("admin()")),
        ] {
            assert_eq!(requests[&id]["params"][0]["to"], target);
            assert_eq!(requests[&id]["params"][0]["data"], data);
        }

        let providers = deployment["providers"].as_array().expect("two providers");
        assert_eq!(providers.len(), 2);
        let first = response_map(&evidence, slug, required_str(&providers[0], "name"));
        let second = response_map(&evidence, slug, required_str(&providers[1], "name"));
        assert_eq!(first.len(), 15);
        assert_eq!(second.len(), 15);
        for id in (1..=15).filter(|id| *id != 2) {
            assert_eq!(
                first[&id], second[&id],
                "provider disagreement: {slug} id {id}"
            );
        }
        for agreed in [&first, &second] {
            let block = &agreed[&2];
            assert_eq!(block["number"], deployment["block_number_hex"]);
            assert_eq!(block["hash"], deployment["block_hash"]);
            assert_eq!(block["parentHash"], deployment["parent_hash"]);
            assert_eq!(block["stateRoot"], deployment["state_root"]);
            assert_eq!(block["timestamp"], deployment["timestamp_hex"]);
        }
        assert_eq!(hex_u64(&first[&1]), chain_id);
        assert_eq!(abi_address(&first[&3]), address(implementation));
        assert_eq!(abi_address(&first[&5]), address(ADDRESSES_PROVIDER));
        assert_eq!(hex_u64(&first[&6]), 11);
        assert_eq!(abi_address(&first[&7]), address(BORROW_LOGIC));
        assert_eq!(abi_address(&first[&8]), address(SUPPLY_LOGIC));
        assert_eq!(abi_address(&first[&9]), address(POOL_PROXY));
        assert_eq!(abi_address(&first[&13]), address(implementation));
        assert_eq!(abi_address(&first[&14]), address(ADDRESSES_PROVIDER));
        assert!(!decode_hex(first[&15].as_str().expect("provider runtime")).is_empty());

        for (rpc_id, key) in [
            (4, "PoolProxy"),
            (10, "PoolImplementation"),
            (11, "BorrowLogic"),
            (12, "SupplyLogic"),
        ] {
            let runtime = read_hex(&evidence.join(format!("runtime/{key}.{slug}.hex")));
            assert_eq!(
                runtime,
                decode_hex(first[&rpc_id].as_str().expect("RPC code"))
            );
        }

        let address_book = normalized(
            &fs::read_to_string(evidence.join(format!(
                "source/AaveV3{}.sol",
                match slug {
                    "optimism" => "Optimism",
                    "polygon" => "Polygon",
                    "arbitrum" => "Arbitrum",
                    "avalanche" => "Avalanche",
                    _ => panic!("unexpected deployment"),
                }
            )))
            .unwrap(),
        );
        assert!(address_book.contains(POOL_PROXY));
        assert!(address_book.contains(ADDRESSES_PROVIDER));
        assert!(address_book.contains(implementation));

        if slug != "avalanche" {
            let report = read_json(&evidence.join(required_str(deployment, "verification")));
            assert_eq!(report["match"].as_str(), Some("match"));
            assert_eq!(required_str(&report, "chainId"), chain_id.to_string());
            assert_eq!(
                address(required_str(&report, "address")),
                address(implementation)
            );
            assert_eq!(report["compilation"]["name"], deployment["instance"]);
            assert_eq!(
                required_str(&report["compilation"], "compilerVersion"),
                "0.8.27+commit.40a35a09"
            );
            assert_eq!(
                decode_hex(required_str(&report["runtimeBytecode"], "onchainBytecode")),
                read_hex(&evidence.join(format!("runtime/PoolImplementation.{slug}.hex")))
            );
            for (file, suffix) in [
                ("PoolInstance.sol", "/instances/PoolInstance.sol"),
                ("Pool.sol", "/pool/Pool.sol"),
                ("BorrowLogic.sol", "/logic/BorrowLogic.sol"),
                ("SupplyLogic.sol", "/logic/SupplyLogic.sol"),
            ] {
                let metadata = source_by_suffix(&report["metadata"]["sources"], suffix);
                assert_eq!(
                    required_str(metadata, "keccak256"),
                    keccak_hex(&fs::read(evidence.join("source").join(file)).unwrap())
                );
            }
            if deployment["instance"] == "L2PoolInstance" {
                for (file, suffix) in [
                    ("L2PoolInstance.sol", "/instances/L2PoolInstance.sol"),
                    ("L2Pool.sol", "/pool/L2Pool.sol"),
                ] {
                    let metadata = source_by_suffix(&report["metadata"]["sources"], suffix);
                    assert_eq!(
                        required_str(metadata, "keccak256"),
                        keccak_hex(&fs::read(evidence.join("source").join(file)).unwrap())
                    );
                }
            }
        }
    }

    let routescan = read_json(&evidence.join("verification/Routescan.avalanche.json"));
    assert_eq!(routescan["status"].as_str(), Some("1"));
    let verified = &routescan["result"][0];
    assert_eq!(verified["ContractName"].as_str(), Some("PoolInstance"));
    assert_eq!(
        verified["CompilerVersion"].as_str(),
        Some("v0.8.27+commit.40a35a09")
    );
    let encoded = required_str(verified, "SourceCode");
    assert!(encoded.starts_with("{{") && encoded.ends_with("}}"));
    let standard: Value = serde_json::from_str(&encoded[1..encoded.len() - 1]).unwrap();
    for (file, suffix) in [
        ("PoolInstance.sol", "/instances/PoolInstance.sol"),
        ("Pool.sol", "/pool/Pool.sol"),
        ("BorrowLogic.sol", "/logic/BorrowLogic.sol"),
        ("SupplyLogic.sol", "/logic/SupplyLogic.sol"),
    ] {
        let archived = fs::read_to_string(evidence.join("source").join(file)).unwrap();
        assert_eq!(
            source_by_suffix(&standard["sources"], suffix)["content"].as_str(),
            Some(archived.as_str())
        );
    }
    let full_abi: Value = serde_json::from_str(required_str(verified, "ABI")).unwrap();
    for route in read_json(&evidence.join("abi/Pool.routes.abi.json"))
        .as_array()
        .unwrap()
    {
        assert!(full_abi.as_array().unwrap().contains(route));
    }
}

#[test]
fn gateway_fixed_block_source_and_descriptor_are_semantically_honest() {
    let evidence = gateway_evidence();
    let manifest = assert_receipted_package(&evidence, 14);
    let block_hash = required_str(&manifest["fixed_block"], "hash");
    let tag = json!({"blockHash": block_hash, "requireCanonical": true});
    let mut requests = BTreeMap::new();
    for suffix in ["identity", "immutables"] {
        for request in read_json(&evidence.join(format!("rpc/raw/request-{suffix}.json")))
            .as_array()
            .unwrap()
        {
            requests.insert(request["id"].as_u64().unwrap(), request.clone());
        }
    }
    assert_eq!(
        requests.keys().copied().collect::<Vec<_>>(),
        (1..=6).collect::<Vec<_>>()
    );
    assert_eq!(requests[&2]["params"], json!([block_hash, false]));
    assert_eq!(requests[&3]["params"], json!([GATEWAY, tag.clone()]));
    for (id, signature) in [(4, "WETH()"), (5, "POOL()"), (6, "owner()")] {
        assert_eq!(requests[&id]["params"][0]["to"], GATEWAY);
        assert_eq!(requests[&id]["params"][0]["data"], selector_hex(signature));
        assert_eq!(requests[&id]["params"][1], tag);
    }
    let provider = |name: &str| {
        let mut map = BTreeMap::new();
        for suffix in ["identity", "immutables"] {
            for (id, value) in results(&read_json(
                &evidence.join(format!("rpc/raw/response-{name}-{suffix}.json")),
            )) {
                map.insert(id, value);
            }
        }
        map
    };
    let drpc = provider("drpc");
    let mev = provider("mevblocker");
    assert_eq!(drpc, mev, "two fixed-block providers must agree exactly");
    assert_eq!(hex_u64(&drpc[&1]), 1);
    assert_eq!(drpc[&2]["hash"].as_str(), Some(block_hash));
    assert_eq!(drpc[&2]["number"], manifest["fixed_block"]["number_hex"]);
    assert_eq!(
        drpc[&2]["parentHash"],
        manifest["fixed_block"]["parent_hash"]
    );
    assert_eq!(drpc[&2]["stateRoot"], manifest["fixed_block"]["state_root"]);
    assert_eq!(
        drpc[&2]["timestamp"],
        manifest["fixed_block"]["timestamp_hex"]
    );
    assert_eq!(abi_address(&drpc[&4]), address(WETH));
    assert_eq!(abi_address(&drpc[&5]), address(ETHEREUM_POOL));
    assert_eq!(abi_address(&drpc[&6]), address(GATEWAY_OWNER));
    let runtime = read_hex(&evidence.join("runtime/WrappedTokenGatewayV3.ethereum-mainnet.hex"));
    assert_eq!(runtime, decode_hex(drpc[&3].as_str().unwrap()));

    let source = fs::read_to_string(evidence.join("source/WrappedTokenGatewayV3.sol")).unwrap();
    let constructor = normalized(solidity_function(&source, "constructor").1);
    for fragment in [
        "WETH = IWETH(weth);",
        "POOL = pool;",
        "transferOwnership(owner);",
        "IWETH(weth).approve(address(pool), type(uint256).max);",
    ] {
        assert!(constructor.contains(fragment));
    }
    let expected = [
        (
            "depositETH",
            [
                "WETH.deposit{value: msg.value}();",
                "POOL.deposit(address(WETH), msg.value, onBehalfOf, referralCode);",
            ]
            .as_slice(),
        ),
        (
            "repayETH",
            [
                "balanceOf( onBehalfOf )",
                "if (amount < paybackAmount)",
                "require(msg.value >= paybackAmount",
                "WETH.deposit{value: paybackAmount}();",
                "POOL.repay(",
                "onBehalfOf",
                "_safeTransferETH(msg.sender, msg.value - paybackAmount);",
            ]
            .as_slice(),
        ),
        (
            "borrowETH",
            [
                "POOL.borrow(",
                "referralCode, msg.sender",
                "WETH.withdraw(amount);",
                "_safeTransferETH(msg.sender, amount);",
            ]
            .as_slice(),
        ),
        (
            "withdrawETH",
            [
                "balanceOf(msg.sender);",
                "if (amount == type(uint256).max)",
                "amountToWithdraw = userBalance;",
                "aWETH.transferFrom(msg.sender, address(this), amountToWithdraw);",
                "POOL.withdraw(address(WETH), amountToWithdraw, address(this));",
                "_safeTransferETH(to, amountToWithdraw);",
            ]
            .as_slice(),
        ),
    ];
    for (name, fragments) in expected {
        let (header, body) = solidity_function(&source, name);
        assert!(normalized(header).contains(&format!("function {name}(address,")));
        let body = normalized(body);
        for fragment in fragments {
            assert!(
                body.contains(fragment),
                "{name} lost semantic fragment: {fragment}"
            );
        }
    }

    let route_abi = read_json(&evidence.join("abi/WrappedTokenGatewayV3.routes.abi.json"));
    assert_eq!(route_abi.as_array().map(Vec::len), Some(5));
    for item in route_abi.as_array().unwrap() {
        assert_eq!(item["inputs"][0]["name"].as_str(), Some(""));
    }
    let sourcify = read_json(&evidence.join("verification/Sourcify.json"));
    assert_eq!(sourcify["match"].as_str(), Some("exact_match"));
    assert_eq!(
        sourcify["compilation"]["name"].as_str(),
        Some("WrappedTokenGatewayV3")
    );
    assert_eq!(
        decode_hex(required_str(
            &sourcify["runtimeBytecode"],
            "onchainBytecode"
        )),
        runtime
    );
    assert_eq!(
        required_str(
            source_by_suffix(
                &sourcify["metadata"]["sources"],
                "/helpers/WrappedTokenGatewayV3.sol"
            ),
            "keccak256"
        ),
        keccak_hex(source.as_bytes())
    );
    let blockscout = read_json(&evidence.join("verification/Blockscout.json"));
    assert_eq!(blockscout["is_fully_verified"].as_bool(), Some(true));
    assert_eq!(blockscout["is_changed_bytecode"].as_bool(), Some(false));
    assert_eq!(
        decode_hex(required_str(&blockscout, "deployed_bytecode")),
        runtime
    );
    assert_eq!(
        required_str(&blockscout, "source_code").trim_end(),
        source.trim_end()
    );
    for route in route_abi.as_array().unwrap() {
        assert!(blockscout["abi"].as_array().unwrap().contains(route));
    }

    let installed = root().join(format!(
        "secure/data/erc7730-registry/registry/aave/{GATEWAY_DESCRIPTOR}"
    ));
    let curated = root().join(format!(
        "secure/data/erc7730/curations/files/registry/aave/{GATEWAY_DESCRIPTOR}"
    ));
    assert_eq!(fs::read(&installed).unwrap(), fs::read(&curated).unwrap());
    let descriptor = read_json(&installed);
    for (signature, fields) in descriptor["display"]["formats"]
        .as_object()
        .expect("gateway formats")
    {
        if signature.starts_with("withdrawETHWithPermit(") {
            continue;
        }
        let ignored = fields["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|field| field["path"].as_str() == Some("pool"))
            .collect::<Vec<_>>();
        assert_eq!(
            ignored.len(),
            1,
            "{signature} must display its ignored operand once"
        );
        assert_eq!(ignored[0]["label"].as_str(), Some("Ignored address"));
        assert_eq!(ignored[0]["format"].as_str(), Some("raw"));
        assert_eq!(ignored[0]["visible"].as_str(), Some("always"));
    }
}

#[test]
fn new_aave_evidence_is_bound_through_merkle_dispatch_and_rendering() {
    let registry = build_registry();
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let shared = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.chain_id != 1
                && entry.contract == address(POOL_PROXY)
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-lpv3.json")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        shared
            .iter()
            .map(|entry| entry.chain_id)
            .collect::<BTreeSet<_>>(),
        [10, 137, 42161, 43114].into_iter().collect()
    );
    let pool_refused = [
        "multicall(bytes[])",
        "repayWithPermit(address,uint256,uint256,address,uint256,uint8,bytes32,bytes32)",
        "supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)",
    ];
    for entry in shared {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).unwrap();
        assert_eq!(ir.format_count(), Ok(10));
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &registry.root).unwrap();
        assert_eq!(
            cross_check_contract(&verified.ir, entry.chain_id, &entry.contract),
            Ok(())
        );
        assert!(cross_check_contract(&verified.ir, entry.chain_id + 1, &entry.contract).is_err());
        let words = [word_address([0x11; 20]), word_u64(1)];
        let call = calldata("approvePositionManager(address,bool)", &words);
        let tx = Eip1559Tx {
            chain_id: entry.chain_id,
            to: Some(entry.contract),
            ..Eip1559Tx::default()
        };
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &call, &verified, None, &resolver, &signer,
        )
        .unwrap();
        assert!(rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0));
        for index in 0..2 {
            let mut mutated = call.clone();
            mutated[4 + index * 32 + 31] ^= 1;
            let changed = render_erc7730_pages_with_signer_checked(
                &tx, &mutated, &verified, None, &resolver, &signer,
            )
            .unwrap();
            assert_ne!(rendered.pages.as_slice(), changed.pages.as_slice());
            assert!(!rendered
                .transcript_receipt
                .exact_match(&changed.transcript_receipt));
        }
        for signature in pool_refused {
            let selector = selector(signature);
            assert!(ir.find_format_by_selector(&selector).unwrap().is_none());
            assert!(registry
                .known_calls
                .contains(&(entry.chain_id, entry.contract, selector)));
            assert!(known_call_may_contain(
                &registry.known_calls_bloom,
                entry.chain_id,
                &entry.contract,
                &selector
            ));
        }
    }

    let gateway_entries = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some(GATEWAY_DESCRIPTOR)
        })
        .collect::<Vec<_>>();
    assert_eq!(gateway_entries.len(), 13);
    let admitted = [
        "depositETH(address,address,uint16)",
        "repayETH(address,uint256,address)",
        "borrowETH(address,uint256,uint16)",
        "withdrawETH(address,uint256,address)",
    ];
    let admitted_selectors = admitted.into_iter().map(selector).collect::<BTreeSet<_>>();
    let permit =
        selector("withdrawETHWithPermit(address,uint256,address,uint256,uint8,bytes32,bytes32)");
    for entry in &gateway_entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).unwrap();
        assert_eq!(ir.format_count(), Ok(4));
        assert_eq!(
            ir.format_iter()
                .map(|format| format.unwrap().selector)
                .collect::<BTreeSet<_>>(),
            admitted_selectors
        );
        for format in ir.format_iter().map(Result::unwrap) {
            let ignored = format
                .fields()
                .map(Result::unwrap)
                .filter(|field| field.label == b"Ignored address")
                .collect::<Vec<_>>();
            assert_eq!(ignored.len(), 1);
            assert_eq!(FormatOp::try_from(ignored[0].format_op), Ok(FormatOp::Raw));
            assert_eq!(
                ir.path_bytes(ignored[0].path_off).unwrap(),
                [PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0]
            );
            let params = parse_params(&ir, ignored[0].param_off).unwrap();
            assert_eq!(params.visibility, Visibility::Always);
            assert_eq!(params.terminal_kind, Some(TerminalKind::Address));
        }
        assert!(ir.find_format_by_selector(&permit).unwrap().is_none());
        assert!(registry
            .known_calls
            .contains(&(entry.chain_id, entry.contract, permit)));
        assert!(known_call_may_contain(
            &registry.known_calls_bloom,
            entry.chain_id,
            &entry.contract,
            &permit
        ));
    }

    let mainnet = gateway_entries
        .into_iter()
        .find(|entry| entry.chain_id == 1 && entry.contract == address(GATEWAY))
        .expect("evidenced Ethereum gateway leaf");
    let bundle = synth_bundle(&registry.blob, &mainnet.ir_bytes, mainnet.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).unwrap();
    assert_eq!(
        cross_check_contract(&verified.ir, 1, &address(GATEWAY)),
        Ok(())
    );
    let ignored = word_address([0x11; 20]);
    let changed_ignored = word_address([0x12; 20]);
    let recipient = word_address([0x22; 20]);
    let changed_recipient = word_address([0x23; 20]);
    let one_eth = 1_000_000_000_000_000_000u64;
    let two_eth = 2_000_000_000_000_000_000u64;
    let cases = [
        (
            "depositETH(address,address,uint16)",
            [ignored, recipient, word_u64(7)],
            [changed_ignored, changed_recipient, word_u64(8)],
            one_eth,
        ),
        (
            "repayETH(address,uint256,address)",
            [ignored, word_u64(one_eth), recipient],
            [changed_ignored, word_u64(two_eth), changed_recipient],
            two_eth,
        ),
        (
            "borrowETH(address,uint256,uint16)",
            [ignored, word_u64(one_eth), word_u64(7)],
            [changed_ignored, word_u64(two_eth), word_u64(8)],
            0,
        ),
        (
            "withdrawETH(address,uint256,address)",
            [ignored, [0xff; 32], recipient],
            [changed_ignored, word_u64(one_eth), changed_recipient],
            0,
        ),
    ];
    for (signature, words, mutations, value) in cases {
        let call = calldata(signature, &words);
        let tx = Eip1559Tx {
            chain_id: 1,
            to: Some(address(GATEWAY)),
            value: U256(word_u64(value)),
            ..Eip1559Tx::default()
        };
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &call, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render {signature}: {error:?}"));
        assert!(rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0));
        for index in 0..3 {
            let mut mutated = call.clone();
            mutated[4 + index * 32..4 + (index + 1) * 32]
                .copy_from_slice(&mutations[index]);
            let changed = render_erc7730_pages_with_signer_checked(
                &tx, &mutated, &verified, None, &resolver, &signer,
            )
            .unwrap_or_else(|error| panic!("render {signature} word-{index} mutation: {error:?}"));
            assert_ne!(rendered.pages.as_slice(), changed.pages.as_slice());
            assert!(!rendered
                .transcript_receipt
                .exact_match(&changed.transcript_receipt));
        }
        if signature.starts_with("depositETH(") {
            let changed_tx = Eip1559Tx {
                value: U256(word_u64(value * 2)),
                ..tx
            };
            let changed = render_erc7730_pages_with_signer_checked(
                &changed_tx,
                &call,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .unwrap();
            assert_ne!(rendered.pages.as_slice(), changed.pages.as_slice());
            assert!(!rendered
                .transcript_receipt
                .exact_match(&changed.transcript_receipt));
        }
    }
}
