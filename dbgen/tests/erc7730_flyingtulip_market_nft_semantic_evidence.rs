//! Offline source, compiler, deployment, and renderer evidence for the bounded
//! FlyingTulip pFT/marketplace/PutManager slice in #497.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::{build_db_tolerant_with_erc20_capabilities, Erc7730BuildResult};
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::{parse as parse_params, NFT_COLLECTION_TO_PATH};
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EVIDENCE_PATH: &str = "tests/erc7730-semantic-evidence/flyingtulip-market-nft";
const ETHEREUM_HASH: &str = "0x6ef230ed8c6d2bd0eaf04e8e59953d2dfa035151e666101de3d7195aefec9af7";
const SONIC_HASH: &str = "0xe8fe0e2243aa3041d4741521601e695498f85cd8212cf1e5fe8cbd06910702cf";
const ZERO_ADDRESS: [u8; 20] = [0; 20];

const PFT_DEPLOYMENTS: &[(u64, &str)] = &[
    (1, "a4215daaf3745e14e96e169e0e7706c479ce04f2"),
    (146, "a4215daaf3745e14e96e169e0e7706c479ce04f2"),
    (146, "1d8051c90076faa5b683a3551ee4369d00f99d67"),
];
const PUT_DEPLOYMENTS: &[(u64, &str)] = &[
    (1, "ba49d0ac42f4fba4e24a8677a22218a4df75ebaa"),
    (146, "ba49d0ac42f4fba4e24a8677a22218a4df75ebaa"),
    (146, "abd838e9977fc76430d637ed35eccfaf178ce071"),
];
const MARKETPLACE_DEPLOYMENTS: &[(u64, &str)] =
    &[(146, "9bb958d459a97e3e37e11becf842e728167d9114")];

const PFT_ROUTES: &[&str] = &[
    "approve(address,uint256)",
    "setApprovalForAll(address,bool)",
];
const MARKETPLACE_ROUTES: &[&str] = &[
    "addListing(uint256,address,uint256,uint40)",
    "editListing(uint256,address,uint256,uint256)",
    "removeListing(uint256)",
];
const MARKETPLACE_REFUSALS: &[&str] = &[
    "buy(uint256,address,uint256,bytes32,(uint256,uint40,bytes))",
    "acceptBuyOffer((address,address,uint96,uint96,uint96,address,uint96,uint256,uint40),uint256,bytes,bytes,uint256,bytes32)",
];
const PUT_ROUTES: &[&str] = &["divest(uint256,uint256)", "withdrawFT(uint256,uint256)"];
const PUT_REFUSALS: &[&str] = &["invest(address,uint256,address,uint256,bytes32[])"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf()
}

fn evidence() -> PathBuf {
    root().join(EVIDENCE_PATH)
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

fn map_str<'a>(values: &'a BTreeMap<String, Value>, key: &str) -> &'a str {
    values[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid evidence hex")
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("selector")
}

fn collect_files(directory: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read evidence directory") {
        let entry = entry.expect("evidence entry");
        let kind = entry.file_type().expect("evidence file type");
        assert!(!kind.is_symlink(), "evidence may not contain symlinks");
        if kind.is_dir() {
            collect_files(&entry.path(), out);
        } else {
            let relative = entry
                .path()
                .strip_prefix(evidence())
                .expect("path below evidence root")
                .to_str()
                .expect("UTF-8 evidence path")
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn result_map(path: &Path) -> BTreeMap<String, Value> {
    read_json(path)
        .as_array()
        .expect("RPC response batch")
        .iter()
        .map(|response| {
            assert!(
                response.get("error").is_none(),
                "RPC evidence contains an error"
            );
            (
                required_str(response, "id").to_string(),
                response["result"].clone(),
            )
        })
        .collect()
}

fn merge_results(paths: &[PathBuf]) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for path in paths {
        for (id, result) in result_map(path) {
            assert!(out.insert(id, result).is_none(), "duplicate RPC id");
        }
    }
    out
}

fn sonic_results(provider: &str, suffix: &str) -> BTreeMap<String, Value> {
    result_map(
        &evidence()
            .join("rpc/raw")
            .join(format!("response-sonic-{provider}-{suffix}.json")),
    )
}

fn ethereum_identity(provider: &str) -> BTreeMap<String, Value> {
    merge_results(&["a", "b", "c"].map(|part| {
        evidence().join(format!(
            "rpc/raw/response-ethereum-{provider}-identity-{part}.json"
        ))
    }))
}

fn immutable_ranges(artifact: &Value) -> Vec<(usize, usize)> {
    artifact["evm"]["deployedBytecode"]["immutableReferences"]
        .as_object()
        .expect("immutable-reference map")
        .values()
        .flat_map(|references| references.as_array().expect("immutable spans"))
        .map(|reference| {
            (
                reference["start"].as_u64().expect("immutable start") as usize,
                reference["length"].as_u64().expect("immutable length") as usize,
            )
        })
        .collect()
}

fn normalized_runtime(mut runtime: Vec<u8>, ranges: &[(usize, usize)]) -> Vec<u8> {
    for &(start, length) in ranges {
        assert_eq!(length, 32, "only compiler-declared words are masked");
        assert!(start + length <= runtime.len());
        runtime[start..start + length].fill(0);
    }
    runtime
}

fn assert_compiled_runtime(artifact_path: &str, runtimes: &[&str]) {
    let artifact = read_json(&evidence().join(artifact_path));
    assert!(
        artifact["evm"]["deployedBytecode"]["linkReferences"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty),
        "runtime must not depend on unresolved libraries"
    );
    let compiled = decode_hex(required_str(&artifact["evm"]["deployedBytecode"], "object"));
    let ranges = immutable_ranges(&artifact);
    let expected = normalized_runtime(compiled, &ranges);
    for runtime in runtimes {
        let actual = decode_hex(runtime);
        assert_eq!(actual.len(), expected.len());
        assert_eq!(
            normalized_runtime(actual, &ranges),
            expected,
            "{artifact_path} runtime differs outside declared immutables"
        );
    }
}

fn source(bundle: &str, path: &str) -> String {
    let input = read_json(&evidence().join(bundle));
    required_str(&input["sources"][path], "content").to_string()
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn transaction_input<'a>(results: &'a BTreeMap<String, Value>, id: &str) -> &'a str {
    required_str(&results[id], "input")
}

fn result_address(result: &Value) -> [u8; 20] {
    let word = decode_hex(result.as_str().expect("word result"));
    assert_eq!(word.len(), 32);
    word[12..].try_into().expect("address word")
}

fn result_u64(result: &Value) -> u64 {
    let word = decode_hex(result.as_str().expect("integer result"));
    assert_eq!(word.len(), 32);
    u64::from_be_bytes(word[24..].try_into().expect("u64 word"))
}

fn result_string(result: &Value) -> String {
    let bytes = decode_hex(result.as_str().expect("ABI string result"));
    assert!(bytes.len() >= 64);
    let offset = usize::try_from(result_u64(&Value::String(format!(
        "0x{}",
        hex::encode(&bytes[..32])
    ))))
    .expect("string offset");
    let length = usize::try_from(result_u64(&Value::String(format!(
        "0x{}",
        hex::encode(&bytes[offset..offset + 32])
    ))))
    .expect("string length");
    String::from_utf8(bytes[offset + 32..offset + 32 + length].to_vec()).expect("UTF-8 ABI string")
}

fn build_registry() -> Erc7730BuildResult {
    let workspace = root();
    let registry = workspace.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&workspace.join("secure/data/erc20.json"))
        .expect("build ERC20 capabilities");
    build_db_tolerant_with_erc20_capabilities(
        &registry.join("registry"),
        &workspace.join("secure/data/erc7730/policy.toml"),
        Some(&registry),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 catalogue")
    .0
}

fn deployments(values: &[(u64, &str)]) -> BTreeSet<(u64, [u8; 20])> {
    values
        .iter()
        .map(|(chain, contract)| (*chain, address(contract)))
        .collect()
}

#[test]
fn flyingtulip_market_nft_evidence_is_complete_and_provider_agreed() {
    let manifest = read_json(&evidence().join("manifest.json"));
    assert_eq!(
        required_str(&manifest, "issue"),
        "https://github.com/EthereumPhone/PQ1/issues/497"
    );

    let declared: BTreeMap<_, _> = manifest["artifacts"]
        .as_array()
        .expect("artifact receipts")
        .iter()
        .map(|artifact| {
            (
                required_str(artifact, "path").to_string(),
                required_str(artifact, "sha256").to_string(),
            )
        })
        .collect();
    let mut actual = BTreeSet::new();
    collect_files(&evidence(), &mut actual);
    assert_eq!(
        actual,
        declared.keys().cloned().collect(),
        "every offline artifact must be receipted exactly once"
    );
    for (path, expected) in declared {
        assert_eq!(
            sha256_hex(&fs::read(evidence().join(&path)).expect("read evidence artifact")),
            expected,
            "evidence artifact drifted: {path}"
        );
    }

    let sonic_a = sonic_results("soniclabs", "identity");
    let sonic_b = sonic_results("publicnode", "identity");
    assert_eq!(sonic_a, sonic_b);
    assert_eq!(sonic_a["chain-id"].as_str(), Some("0x92"));
    assert_eq!(required_str(&sonic_a["block"], "hash"), SONIC_HASH);
    assert_eq!(sonic_a["block"]["number"].as_str(), Some("0x4918000"));
    assert_eq!(
        sonic_a["block"]["stateRoot"].as_str(),
        Some("0x7c8d728e11af622c3484a0e21de463dbdfd96a10d4fadbb0a4a33d8209d5968a")
    );

    let ethereum_a = ethereum_identity("mevblocker");
    let ethereum_b = ethereum_identity("tenderly");
    assert_eq!(ethereum_a, ethereum_b);
    assert_eq!(ethereum_a["chain-id"].as_str(), Some("0x1"));
    assert_eq!(required_str(&ethereum_a["block"], "hash"), ETHEREUM_HASH);
    assert_eq!(ethereum_a["block"]["number"].as_str(), Some("0x1871800"));
    assert_eq!(
        ethereum_a["block"]["stateRoot"].as_str(),
        Some("0x56201c1863e551e47e584fbe807a6200b8937e7d62a373a37e1342c0f113e27d")
    );

    for (results, id, expected) in [
        (
            &ethereum_a,
            "old-pft-implementation-slot",
            "c55253ea84050700e1efa8878d4a5053b6bf7c5e",
        ),
        (
            &ethereum_a,
            "old-put-implementation-slot",
            "1e4e741e5f0f4f258def137e1968716eddae4bf5",
        ),
        (
            &sonic_a,
            "old-pft-implementation-slot",
            "c55253ea84050700e1efa8878d4a5053b6bf7c5e",
        ),
        (
            &sonic_a,
            "new-pft-implementation-slot",
            "cf047256d5cd7354327213929214e5dad3a83326",
        ),
        (
            &sonic_a,
            "old-put-implementation-slot",
            "90ae2cac15f8d58a258f7b4a243657754469922a",
        ),
        (
            &sonic_a,
            "new-put-implementation-slot",
            "915220f3845d9d0db7960399c4e5ba0038f1170b",
        ),
        (
            &sonic_a,
            "marketplace-implementation-slot",
            "bdd1327024b66212bf1f6a6a7f8b21f81b1faca4",
        ),
    ] {
        assert_eq!(result_address(&results[id]), address(expected), "{id}");
    }

    assert_compiled_runtime(
        "compiler/pft.json",
        &[
            map_str(&ethereum_a, "old-pft-implementation-code"),
            map_str(&sonic_a, "old-pft-implementation-code"),
            map_str(&sonic_a, "new-pft-implementation-code"),
        ],
    );
    assert_compiled_runtime(
        "compiler/putmanager-ethereum.json",
        &[map_str(&ethereum_a, "old-put-implementation-code")],
    );
    assert_compiled_runtime(
        "compiler/putmanager-current.json",
        &[
            map_str(&sonic_a, "old-put-implementation-code"),
            map_str(&sonic_a, "new-put-implementation-code"),
        ],
    );
    assert_compiled_runtime(
        "compiler/marketplace.json",
        &[map_str(&sonic_a, "marketplace-implementation-code")],
    );

    let marketplace_artifact = read_json(&evidence().join("compiler/marketplace.json"));
    let pft_layout = marketplace_artifact["storageLayout"]["storage"]
        .as_array()
        .expect("marketplace storage layout")
        .iter()
        .find(|entry| entry["label"].as_str() == Some("_pFT"))
        .expect("marketplace _pFT slot");
    assert_eq!(pft_layout["slot"].as_str(), Some("0"));
    assert_eq!(
        result_address(&sonic_a["marketplace-pft-slot"]),
        address("1d8051c90076faa5b683a3551ee4369d00f99d67")
    );
    assert_eq!(
        result_address(&ethereum_a["old-pft-putmanager"]),
        address("ba49d0ac42f4fba4e24a8677a22218a4df75ebaa")
    );
    assert_eq!(
        result_address(&sonic_a["old-pft-putmanager"]),
        address("ba49d0ac42f4fba4e24a8677a22218a4df75ebaa")
    );
    assert_eq!(
        result_address(&sonic_a["new-pft-putmanager"]),
        address("abd838e9977fc76430d637ed35eccfaf178ce071")
    );
    assert_eq!(
        result_address(&ethereum_a["old-put-ft"]),
        address("5dd1a7a369e8273371d2dbf9d83356057088082c")
    );
    assert_eq!(
        result_address(&sonic_a["old-put-ft"]),
        address("5dd1a7a369e8273371d2dbf9d83356057088082c")
    );
    assert_eq!(
        result_address(&sonic_a["new-put-ft"]),
        address("26382a5331ddb46e7c0c101fb53480eb64a94ad9")
    );
    for (results, prefix) in [(&ethereum_a, "old"), (&sonic_a, "old"), (&sonic_a, "new")] {
        assert_eq!(
            result_string(&results[&format!("{prefix}-ft-symbol")]),
            "FT"
        );
        assert_eq!(result_u64(&results[&format!("{prefix}-ft-decimals")]), 18);
    }

    let sonic_tx_a = sonic_results("soniclabs", "creation-transactions");
    let sonic_tx_b = sonic_results("publicnode", "creation-transactions");
    for id in ["pft-old", "pft-new", "put-old", "put-new", "marketplace"] {
        for field in ["blockHash", "blockNumber", "from", "input", "to"] {
            assert_eq!(sonic_tx_a[id][field], sonic_tx_b[id][field], "{id} {field}");
        }
    }
    assert!(transaction_input(&sonic_tx_a, "put-old").ends_with(
        "0000000000000000000000005dd1a7a369e8273371d2dbf9d83356057088082c000000000000000000000000a4215daaf3745e14e96e169e0e7706c479ce04f2"
    ));
    assert!(transaction_input(&sonic_tx_a, "put-new").ends_with(
        "00000000000000000000000026382a5331ddb46e7c0c101fb53480eb64a94ad90000000000000000000000001d8051c90076faa5b683a3551ee4369d00f99d67"
    ));
    assert!(transaction_input(&sonic_tx_a, "marketplace")
        .ends_with("000000000000000000000000039e2fb66102314ce7b64ce5ce3e5183bc94ad38"));

    let ethereum_tx_a = result_map(
        &evidence().join("rpc/raw/response-ethereum-mevblocker-creation-transactions.json"),
    );
    let ethereum_tx_b = result_map(
        &evidence().join("rpc/raw/response-ethereum-tenderly-creation-transactions.json"),
    );
    for field in ["blockHash", "blockNumber", "from", "input", "to"] {
        assert_eq!(
            ethereum_tx_a["put-old"][field], ethereum_tx_b["put-old"][field],
            "Ethereum creation transaction {field}"
        );
    }
    assert!(transaction_input(&ethereum_tx_a, "put-old").ends_with(
        "0000000000000000000000005dd1a7a369e8273371d2dbf9d83356057088082c000000000000000000000000a4215daaf3745e14e96e169e0e7706c479ce04f2"
    ));
}

#[test]
fn flyingtulip_verified_sources_establish_the_displayed_effects() {
    let pft = normalized(&source(
        "explorer/pft.standard-input.json",
        "contracts/pFT.sol",
    ));
    let erc721 = normalized(&source(
        "explorer/pft.standard-input.json",
        "lib/openzeppelin-contracts-upgradeable/contracts/token/ERC721/ERC721Upgradeable.sol",
    ));
    for fragment in [
        r#"__ERC721_init("Flying Tulip PUT", "ftPUT");"#,
        "address public putManager;",
        "function withdrawFT(",
        "_put.ft -= _amount;",
        "_put.withdrawn += _amount;",
        "function divest(",
        "_put.burned += _amount;",
        "_put.amountRemaining -= _amountDivested;",
    ] {
        assert!(pft.contains(fragment), "pFT source lost: {fragment}");
    }
    for fragment in [
        "function approve(address to, uint256 tokenId)",
        "_approve(to, tokenId, _msgSender());",
        "function setApprovalForAll(address operator, bool approved)",
        "_setApprovalForAll(_msgSender(), operator, approved);",
    ] {
        assert!(erc721.contains(fragment), "ERC-721 source lost: {fragment}");
    }

    for bundle in [
        "explorer/putmanager-current.standard-input.json",
        "explorer/putmanager-ethereum.standard-input.json",
    ] {
        let put = normalized(&source(bundle, "contracts/PutManager.sol"));
        for fragment in [
            "function withdrawFT(uint256 id, uint256 amount)",
            "pFT.withdrawFT(msg.sender, id, amount, _capitalDivesting);",
            "FT.safeTransfer(msg.sender, amount);",
            "capitalDivesting[token] += _capitalDivesting;",
            "function divest(uint256 id, uint256 amount_ft)",
            "pFT.divest(msg.sender, id, amount_ft, _capitalDivesting);",
            "_vault.withdraw(_capitalDivesting, msg.sender);",
        ] {
            assert!(put.contains(fragment), "{bundle} lost: {fragment}");
        }
    }

    let market = normalized(&source(
        "explorer/marketplace.standard-input.json",
        "contracts/pFTMarketplace.sol",
    ));
    for fragment in [
        "uint40 expires; // timestamp when listing expires (type(uint40).max = never)",
        "function addListing(",
        "require(_pFT.ownerOf(tokenId) == msg.sender, NotOwner());",
        "_listings[tokenId] = Listing({ seller: msg.sender, token: token, price: SafeCast.toUint96(price), expires: expires });",
        "function editListing(",
        "listing.token = token;",
        "listing.price = SafeCast.toUint96(price);",
        "listing.expires = SafeCast.toUint40(expires);",
        "function removeListing(uint256 tokenId)",
        "_deleteListing(tokenId);",
        "function buy(",
        "uint256 buyerPaymentAmount = listing.price + takerFee;",
        "function acceptBuyOffer(",
    ] {
        assert!(market.contains(fragment), "marketplace source lost: {fragment}");
    }
}

#[test]
fn flyingtulip_catalogue_admits_only_the_evidenced_formats() {
    let registry = build_registry();
    let families = [
        (
            "calldata-PftNft.json",
            deployments(PFT_DEPLOYMENTS),
            PFT_ROUTES,
            &[][..],
        ),
        (
            "calldata-PftMarketplace.json",
            deployments(MARKETPLACE_DEPLOYMENTS),
            MARKETPLACE_ROUTES,
            MARKETPLACE_REFUSALS,
        ),
        (
            "calldata-PutManager.json",
            deployments(PUT_DEPLOYMENTS),
            PUT_ROUTES,
            PUT_REFUSALS,
        ),
    ];

    for (source_name, expected_deployments, admitted_routes, refused_routes) in families {
        let entries: Vec<_> = registry
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
            })
            .collect();
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.chain_id, entry.contract))
                .collect::<BTreeSet<_>>(),
            expected_deployments,
            "{source_name} deployment fence changed"
        );
        let admitted_selectors: BTreeSet<_> = admitted_routes
            .iter()
            .map(|route| selector(route))
            .collect();
        for entry in entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("FlyingTulip IR");
            assert_eq!(
                ir.format_iter()
                    .map(|format| format.expect("format").selector)
                    .collect::<BTreeSet<_>>(),
                admitted_selectors,
                "{source_name} admitted selector set changed"
            );
            for route in refused_routes {
                let refused = selector(route);
                assert!(ir.find_format_by_selector(&refused).unwrap().is_none());
                assert!(
                    registry
                        .known_calls
                        .contains(&(entry.chain_id, entry.contract, refused)),
                    "{source_name} {route} must remain exact-known"
                );
                assert!(known_call_may_contain(
                    &registry.known_calls_bloom,
                    entry.chain_id,
                    &entry.contract,
                    &refused
                ));
            }

            if source_name == "calldata-PftNft.json" {
                let approve = ir
                    .find_format_by_selector(&selector(PFT_ROUTES[0]))
                    .unwrap()
                    .expect("approve");
                let fields: Vec<_> = approve.fields().map(Result::unwrap).collect();
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[0].label, b"Approved account");
                assert_eq!(
                    parse_params(&ir, fields[1].param_off)
                        .expect("approval rule")
                        .const_value,
                    Some(b"Zero address clears approval".as_slice())
                );
                let nft = parse_params(&ir, fields[2].param_off).expect("position params");
                assert_eq!(
                    nft.nft_collection_path,
                    Some(NFT_COLLECTION_TO_PATH.as_slice())
                );
            } else if source_name == "calldata-PftMarketplace.json" {
                for route in &MARKETPLACE_ROUTES[..2] {
                    let format = ir
                        .find_format_by_selector(&selector(route))
                        .unwrap()
                        .expect("listing format");
                    let fields: Vec<_> = format.fields().map(Result::unwrap).collect();
                    assert_eq!(fields.len(), 4);
                    let amount = fields
                        .iter()
                        .find(|field| {
                            FormatOp::try_from(field.format_op) == Ok(FormatOp::TokenAmount)
                        })
                        .expect("asking amount");
                    let params = parse_params(&ir, amount.param_off).expect("asking params");
                    assert!(params.token_path.is_some());
                    assert_eq!(
                        params.native_currency_addresses,
                        Some(ZERO_ADDRESS.as_slice())
                    );
                    assert_eq!(
                        parse_params(&ir, fields[3].param_off)
                            .expect("expiry rule")
                            .const_value,
                        Some(b"Max uint40 means no expiry".as_slice())
                    );
                }
            } else {
                for route in PUT_ROUTES {
                    let format = ir
                        .find_format_by_selector(&selector(route))
                        .unwrap()
                        .expect("PUT exit format");
                    let fields: Vec<_> = format.fields().map(Result::unwrap).collect();
                    assert_eq!(fields.len(), 3);
                    assert_eq!(FormatOp::try_from(fields[0].format_op), Ok(FormatOp::Raw));
                    assert!(
                        fields.iter().all(|field| {
                            FormatOp::try_from(field.format_op) != Ok(FormatOp::NftName)
                        }),
                        "shared PutManager descriptor must not invent one pFT collection"
                    );
                    let amount = parse_params(&ir, fields[1].param_off).expect("FT unit");
                    assert_eq!(FormatOp::try_from(fields[1].format_op), Ok(FormatOp::Unit));
                    assert_eq!(amount.base, Some(b"FT".as_slice()));
                    assert_eq!(amount.decimals, Some(18));
                    assert_eq!(amount.prefix, Some(0));
                    assert!(parse_params(&ir, fields[2].param_off)
                        .expect("effect annotation")
                        .const_value
                        .is_some());
                }
            }
        }
    }
}
