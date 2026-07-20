//! Offline provenance and source-semantics checks for FlyingTulip SessionManager.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const ZERO_WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

const ASSET_LIMIT_EIP712_TYPE: &str = "AssetLimit(address token,uint256 limit)";
const SESSION_EIP712_TYPE: &str = "Session(address owner,address delegate,uint48 validAfter,uint48 validUntil,uint32 maxCalls,uint16 maxFeeBps,AssetLimit[] limits,bytes32 salt)AssetLimit(address token,uint256 limit)";
const ASSET_LIMIT_EIP712_TYPEHASH: &str =
    "0x269888c0029efe9424c548a264e5ee66803094ad203b068ca44e278b02db9d6f";
const SESSION_EIP712_TYPEHASH: &str =
    "0x10e2e916a5d944a9c9fa82748951934e444783850c4cb366694967607dbd2fc5";
const UINT256_MAX_HEX: &str = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const EIP712_NAME_IMMUTABLE_START: usize = 3_099;
const EIP712_VERSION_IMMUTABLE_START: usize = 3_140;

const DEPLOYMENTS: &[(u64, &str)] = &[
    (1, "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9"),
    (1, "f9f3ddf2e96cabef94e2634c326dc6dde99360f8"),
    (56, "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42"),
    (146, "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9"),
    (146, "109ae72778a0260571b9767477204f1ce41fbdff"),
    (146, "52ef449d44cc4205fa44bf644dee15611fc30734"),
    (43_114, "176592c8ed3f2d94ce4c3f1a4cff7d068176ac54"),
];

const FT_EIP712_DEPLOYMENTS: &[(u64, &str)] = &[
    (1, "f9f3ddf2e96cabef94e2634c326dc6dde99360f8"),
    (146, "109ae72778a0260571b9767477204f1ce41fbdff"),
];

const FTUSD_EIP712_DEPLOYMENTS: &[(u64, &str)] = &[
    (1, "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9"),
    (56, "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42"),
    (146, "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9"),
    (146, "52ef449d44cc4205fa44bf644dee15611fc30734"),
    (43_114, "176592c8ed3f2d94ce4c3f1a4cff7d068176ac54"),
];

const SOURCIFY_CAPTURES: &[(u64, &str, &str)] = &[
    (
        1,
        "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9",
        "50f840bf386d21335329c8579e87d1cc284631baaa7a433dcfd606c67864a3ec",
    ),
    (
        1,
        "f9f3ddf2e96cabef94e2634c326dc6dde99360f8",
        "bd0857ea6d2c1ff84a29b6666cb8df43e6bf8415c3b63ff9caeaed82a10e89ab",
    ),
    (
        56,
        "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42",
        "70fb95c92ea009db254baca8c4dc8fe43a678191156178934271b1c4b0a0e0cb",
    ),
];

const SOURCIFY_RESPONSE_PAYLOADS: &[(u64, &str, &str)] = &[
    (
        1,
        "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9",
        "8d263337d9718671ac10bff43c30ef492b758ace9f4ea50abc4558aaff6da955",
    ),
    (
        1,
        "f9f3ddf2e96cabef94e2634c326dc6dde99360f8",
        "f96a582d3ce17c4c938f97dd69795c3dc522418a0b43849a28dccf1969373ea5",
    ),
    (
        56,
        "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42",
        "aa26f9902c05a8240212081ae73c4e3b9a2c95c1f6cd49e7f66291282b1bfd11",
    ),
];

const RUNTIME_SHA256: &[(u64, &str, &str)] = &[
    (
        1,
        "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9",
        "c995727383accc2bb569c3f5fcce68899a51117df962a9a8d6846e6b0f730774",
    ),
    (
        1,
        "f9f3ddf2e96cabef94e2634c326dc6dde99360f8",
        "ec5257d4713a7c903d19ac6d2ad452e9e4a565c3caa8e91618330e0f64d5a289",
    ),
    (
        56,
        "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42",
        "faa685abb848681bffece9e98c70e130ac87e6c6e4f06863e8d4657756fa5a4c",
    ),
    (
        146,
        "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9",
        "f2364bfd877902fd54334011e24f72b34a45f9d1864ee95a501f3b91104e0560",
    ),
    (
        146,
        "109ae72778a0260571b9767477204f1ce41fbdff",
        "95ab7962a48d6c1d83ff71a4f20eef4a0950a52b1134c8edbaab5eb6186618b2",
    ),
    (
        146,
        "52ef449d44cc4205fa44bf644dee15611fc30734",
        "b3f853d7a027a4b4d4bbc0bea97c0f046cc3dc096c9318521be4484762968c78",
    ),
    (
        43_114,
        "176592c8ed3f2d94ce4c3f1a4cff7d068176ac54",
        "12e9e3a8f512319dc53318828be1a94c3dcadcedd08313bf24d6d29e261cac56",
    ),
];

const RUNTIME_KECCAK256: &[(u64, &str, &str)] = &[
    (
        1,
        "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9",
        "0x7c79d4c8c47cae453fbac541867210cef5dc2bdd5442b9410a9974113f9fc6fc",
    ),
    (
        1,
        "f9f3ddf2e96cabef94e2634c326dc6dde99360f8",
        "0xe124781a5e8c1269d960fb35d8bd62f38db701c927bbdaa46d62cb8820f7f8a0",
    ),
    (
        56,
        "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42",
        "0x7e800bd715549a1f94590ef8dbf4f152e1288706b33b3ec0d23459a5e55e8851",
    ),
    (
        146,
        "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9",
        "0x88b1282176acf1bb076b5015d7795d505d6bb47d5feb43a028d4b0106498ccd5",
    ),
    (
        146,
        "109ae72778a0260571b9767477204f1ce41fbdff",
        "0x83422d32980bb131efd7ce65f4347d093ac787dc4088d651714d00f210d83cf2",
    ),
    (
        146,
        "52ef449d44cc4205fa44bf644dee15611fc30734",
        "0xde23671e91175c3b3a60455faf55b967d607be76defb97eec6a1f1b87d5f768f",
    ),
    (
        43_114,
        "176592c8ed3f2d94ce4c3f1a4cff7d068176ac54",
        "0xe59d4a7c2a9536d567fa766d1859469f65b907111d381a3338f314b5bebd0952",
    ),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/flyingtulip-sessionmanager")
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
        .unwrap_or_else(|| panic!("manifest field {key} is a string"))
}

fn normalized_address(address: &str) -> String {
    address.trim_start_matches("0x").to_ascii_lowercase()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn decode_hex_text(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid hex evidence")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex_text(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).expect("serialize JSON string"));
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                canonical_json(value, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).expect("serialize JSON key"));
                output.push(':');
                canonical_json(&values[key], output);
            }
            output.push('}');
        }
    }
}

fn canonical_json_sha256(value: &Value) -> String {
    let mut encoded = String::new();
    canonical_json(value, &mut encoded);
    encoded.push('\n');
    sha256_hex(encoded.as_bytes())
}

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalized_solidity_function(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing Solidity signature: {signature}"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("function body opens");
    let mut depth = 0usize;
    let mut end = None;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("balanced Solidity braces");
                if depth == 0 {
                    end = Some(open + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let code = source[start..end.expect("complete Solidity function")]
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    normalized_whitespace(&code)
}

fn assert_fragments_in_order(haystack: &str, fragments: &[&str]) {
    let mut remainder = haystack;
    for fragment in fragments {
        let offset = remainder
            .find(fragment)
            .unwrap_or_else(|| panic!("missing ordered source fragment: {fragment}"));
        remainder = &remainder[offset + fragment.len()..];
    }
}

fn immutable_references(value: &Value) -> Vec<(usize, usize)> {
    let mut references = Vec::new();
    for entries in value
        .as_object()
        .expect("immutable references are keyed by AST id")
        .values()
    {
        for entry in entries.as_array().expect("immutable reference array") {
            references.push((
                entry["start"].as_u64().expect("immutable start") as usize,
                entry["length"].as_u64().expect("immutable length") as usize,
            ));
        }
    }
    references.sort_unstable();
    references
}

fn manifest_immutable_references(value: &Value) -> Vec<(usize, usize)> {
    let mut references: Vec<_> = value
        .as_array()
        .expect("manifest immutable references")
        .iter()
        .map(|entry| {
            (
                entry["start"].as_u64().expect("immutable start") as usize,
                entry["length"].as_u64().expect("immutable length") as usize,
            )
        })
        .collect();
    references.sort_unstable();
    references
}

fn deployment_set(value: &Value) -> BTreeSet<(u64, String)> {
    value
        .as_array()
        .expect("deployment array")
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"]
                    .as_u64()
                    .or_else(|| deployment["chain_id"].as_u64())
                    .expect("deployment chain id"),
                normalized_address(required_str(deployment, "address")),
            )
        })
        .collect()
}

fn find_deployment<'a>(manifest: &'a Value, chain_id: u64, address: &str) -> &'a Value {
    manifest["deployments"]
        .as_array()
        .expect("manifest deployments")
        .iter()
        .find(|deployment| {
            deployment["chain_id"].as_u64() == Some(chain_id)
                && normalized_address(required_str(deployment, "address")) == address
        })
        .unwrap_or_else(|| panic!("missing manifest deployment {chain_id}:{address}"))
}

fn find_build_family<'a>(manifest: &'a Value, id: &str) -> &'a Value {
    manifest["build_families"]
        .as_array()
        .expect("build families")
        .iter()
        .find(|family| required_str(family, "id") == id)
        .unwrap_or_else(|| panic!("missing build family {id}"))
}

fn find_known<'a>(values: &'a [(u64, &str, &str)], chain_id: u64, address: &str) -> &'a str {
    values
        .iter()
        .find(|(chain, candidate, _)| *chain == chain_id && *candidate == address)
        .map(|(_, _, value)| *value)
        .unwrap_or_else(|| panic!("missing known identity {chain_id}:{address}"))
}

fn source_content<'a>(capture: &'a Value, path: &str) -> &'a str {
    capture["sources"][path]["content"]
        .as_str()
        .unwrap_or_else(|| panic!("missing Sourcify source {path}"))
}

fn source_hash(capture: &Value, path: &str) -> String {
    sha256_hex(source_content(capture, path).as_bytes())
}

fn selector(signature: &str) -> String {
    format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
}

fn decode_short_string_immutable(runtime: &[u8], start: usize) -> String {
    let word = runtime
        .get(start..start + 32)
        .expect("ShortString immutable is inside the runtime");
    let length = usize::from(word[31]);
    assert!(length <= 31, "ShortString length fits its inline encoding");
    assert!(
        word[length..31].iter().all(|byte| *byte == 0),
        "ShortString padding is zero"
    );
    std::str::from_utf8(&word[..length])
        .expect("EIP-712 domain ShortString is UTF-8")
        .to_owned()
}

#[test]
fn flyingtulip_sessionmanager_fixed_block_provenance_and_semantics_are_bound() {
    let workspace = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert!(required_str(&manifest, "scope").contains("SessionManager"));

    let expected_deployments: BTreeSet<_> = DEPLOYMENTS
        .iter()
        .map(|(chain_id, address)| (*chain_id, (*address).to_owned()))
        .collect();
    assert_eq!(
        deployment_set(&manifest["descriptor"]["deployments"]),
        expected_deployments
    );
    assert_eq!(
        manifest["deployments"]
            .as_array()
            .expect("manifest deployment array")
            .len(),
        7
    );

    let descriptor_path = workspace.join(required_str(&manifest["descriptor"], "vendored_file"));
    let descriptor_bytes = fs::read(&descriptor_path).expect("read SessionManager descriptor");
    assert_eq!(
        sha256_hex(&descriptor_bytes),
        required_str(&manifest["descriptor"], "vendored_file_sha256")
    );
    let overlay_path = workspace.join(required_str(&manifest["descriptor"], "curation_overlay"));
    let overlay_bytes = fs::read(&overlay_path).expect("read SessionManager curation overlay");
    assert_eq!(
        sha256_hex(&overlay_bytes),
        required_str(&manifest["descriptor"], "curation_overlay_sha256")
    );
    assert_eq!(overlay_bytes, descriptor_bytes);
    let descriptor = read_json(&descriptor_path);
    assert_eq!(
        deployment_set(&descriptor["context"]["contract"]["deployments"]),
        expected_deployments
    );
    assert_eq!(
        descriptor["metadata"]["enums"]["targetAccess"]["0"].as_str(),
        Some("Disallow")
    );
    assert_eq!(
        descriptor["metadata"]["enums"]["targetAccess"]["1"].as_str(),
        Some("Allow")
    );

    let formats = descriptor["display"]["formats"]
        .as_object()
        .expect("SessionManager formats");
    let revoke = &formats["revokeSession(bytes32 sessionId)"];
    assert_eq!(revoke["intent"].as_str(), Some("Revoke session"));
    assert_eq!(revoke["fields"].as_array().expect("revoke fields").len(), 1);
    assert_eq!(revoke["fields"][0]["path"].as_str(), Some("sessionId"));
    assert_eq!(revoke["fields"][0]["label"].as_str(), Some("Session ID"));
    assert_eq!(revoke["fields"][0]["format"].as_str(), Some("raw"));
    assert_eq!(revoke["fields"][0]["visible"].as_str(), Some("always"));
    assert!(revoke.get("interpolatedIntent").is_none());

    let target = &formats["setAllowedTarget(address target, bool allowed)"];
    assert_eq!(target["intent"].as_str(), Some("Update allowed target"));
    assert_eq!(target["fields"][0]["path"].as_str(), Some("target"));
    assert_eq!(target["fields"][0]["label"].as_str(), Some("Target"));
    assert_eq!(target["fields"][0]["format"].as_str(), Some("addressName"));
    assert_eq!(target["fields"][0]["visible"].as_str(), Some("always"));
    assert_eq!(target["fields"][1]["path"].as_str(), Some("allowed"));
    assert_eq!(target["fields"][1]["label"].as_str(), Some("Access"));
    assert_eq!(target["fields"][1]["format"].as_str(), Some("enum"));
    assert_eq!(
        target["fields"][1]["params"]["$ref"].as_str(),
        Some("$.metadata.enums.targetAccess")
    );
    assert_eq!(target["fields"][1]["visible"].as_str(), Some("always"));
    assert!(target.get("interpolatedIntent").is_none());

    let transfer = &formats["transferOwnership(address newOwner)"];
    assert_eq!(transfer["intent"].as_str(), Some("Update pending owner"));
    assert_eq!(
        transfer["fields"]
            .as_array()
            .expect("ownership fields")
            .len(),
        1
    );
    assert_eq!(transfer["fields"][0]["path"].as_str(), Some("newOwner"));
    assert_eq!(
        transfer["fields"][0]["label"].as_str(),
        Some("Pending owner")
    );
    assert_eq!(
        transfer["fields"][0]["format"].as_str(),
        Some("addressName")
    );
    assert_eq!(transfer["fields"][0]["visible"].as_str(), Some("always"));
    assert!(transfer.get("interpolatedIntent").is_none());

    let admitted = BTreeMap::from([
        ("acceptOwnership()", "0x79ba5097"),
        ("renounceOwnership()", "0x715018a6"),
        ("revokeSession(bytes32)", "0xa7fed385"),
        ("setAllowedTarget(address,bool)", "0xca1dd22e"),
        ("transferOwnership(address)", "0xf2fde38b"),
    ]);
    let refused_signatures = BTreeMap::from([
        (
            "createSession(address,uint48,uint48,uint32,uint16,(address,uint256)[],bytes32)",
            ("createSession", "0xc14559e5"),
        ),
        (
            "createSessionBySig(address,address,uint48,uint48,uint32,uint16,(address,uint256)[],bytes32,bytes)",
            ("createSessionBySig", "0x74d36b01"),
        ),
        (
            "invalidateNonceBySig(bytes32,uint256,uint256,address,bytes)",
            ("invalidateNonceBySig", "0x90706897"),
        ),
        (
            "revokeSessionBySig(bytes32,uint256,bytes)",
            ("revokeSessionBySig", "0x1fc1db86"),
        ),
        (
            "setAllowedTargets(address[],bool)",
            ("setAllowedTargets", "0x01e2ae55"),
        ),
        (
            "validateAndConsume(address,uint256,(bytes32,bytes32,uint256,uint256,address,uint256),bytes,address)",
            ("validateAndConsume", "0xce5cb6c0"),
        ),
    ]);
    for (signature, expected_selector) in &admitted {
        assert_eq!(
            selector(signature),
            *expected_selector,
            "selector drift: {signature}"
        );
    }
    for (signature, (_, expected_selector)) in &refused_signatures {
        assert_eq!(
            selector(signature),
            *expected_selector,
            "selector drift: {signature}"
        );
    }
    let manifest_admitted: BTreeMap<_, _> = manifest["admitted_routes"]
        .as_array()
        .expect("admitted routes")
        .iter()
        .map(|route| {
            (
                required_str(route, "canonical_signature"),
                required_str(route, "selector"),
            )
        })
        .collect();
    let manifest_refused: BTreeMap<_, _> = manifest["refused_routes"]
        .as_array()
        .expect("refused routes")
        .iter()
        .map(|route| (required_str(route, "name"), required_str(route, "selector")))
        .collect();
    assert_eq!(manifest_admitted, admitted);
    assert_eq!(
        manifest_refused,
        refused_signatures
            .values()
            .copied()
            .collect::<BTreeMap<_, _>>()
    );

    let families = manifest["build_families"]
        .as_array()
        .expect("build families");
    assert_eq!(families.len(), 2);
    for family in families {
        assert_eq!(family["compiler"].as_str(), Some("0.8.30+commit.73712a01"));
        assert_eq!(family["language"].as_str(), Some("Solidity"));
        assert_eq!(family["settings"]["via_ir"].as_bool(), Some(true));
        assert_eq!(
            family["settings"]["optimizer_enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(family["settings"]["optimizer_runs"].as_u64(), Some(200));
        assert_eq!(family["settings"]["evm_version"].as_str(), Some("cancun"));
        assert_eq!(
            family["settings"]["metadata_append_cbor"].as_bool(),
            Some(false)
        );
        assert_eq!(
            family["settings"]["metadata_bytecode_hash"].as_str(),
            Some("none")
        );
        let runtime_bytes = family["runtime_bytes"]
            .as_u64()
            .expect("family runtime bytes");
        let (
            expected_primary_path,
            expected_primary_bytes,
            expected_primary_sha,
            expected_refs,
            expected_normalized,
        ) = match runtime_bytes {
            7_732 => (
                "contracts/SessionManager.sol",
                17_169,
                "5ea60be88555878e1e8ccce623e5cb3c5a0c72898713bea2aef1b937199c4075",
                vec![
                    (3099, 32),
                    (3140, 32),
                    (6756, 32),
                    (6810, 32),
                    (6889, 32),
                    (6927, 32),
                    (6993, 32),
                ],
                "b83ed0508ae63363153a93612a8b61968277602febfa92ddae1cfbb81a51fd6c",
            ),
            7_853 => (
                "contracts/session/SessionManager.sol",
                17_109,
                "5930f95d860deb404b74741a9099b01ec714f08b9f986f966195ada9e377f300",
                vec![
                    (3099, 32),
                    (3140, 32),
                    (6877, 32),
                    (6931, 32),
                    (7010, 32),
                    (7048, 32),
                    (7114, 32),
                ],
                "a86db0d2fffd878154e062f7e36d2b378e8c0fe7f4f5ed96ed2159d26cd04aa7",
            ),
            other => panic!("unexpected SessionManager runtime family length {other}"),
        };
        assert_eq!(
            required_str(&family["primary_source"], "capture_path"),
            expected_primary_path
        );
        assert_eq!(
            required_str(family, "fully_qualified_name"),
            format!("{expected_primary_path}:SessionManager")
        );
        assert_eq!(
            family["primary_source"]["bytes"].as_u64(),
            Some(expected_primary_bytes)
        );
        assert_eq!(
            required_str(&family["primary_source"], "sha256"),
            expected_primary_sha
        );
        assert_eq!(
            manifest_immutable_references(&family["immutable_references"]),
            expected_refs
        );
        assert_eq!(
            required_str(family, "normalized_runtime_sha256"),
            expected_normalized
        );
        let family_deployments: BTreeSet<_> = manifest["deployments"]
            .as_array()
            .expect("manifest deployments")
            .iter()
            .filter(|deployment| {
                required_str(deployment, "build_family") == required_str(family, "id")
            })
            .map(|deployment| {
                (
                    deployment["chain_id"].as_u64().expect("deployment chain"),
                    normalized_address(required_str(deployment, "address")),
                )
            })
            .collect();
        assert_eq!(deployment_set(&family["deployments"]), family_deployments);
    }
    assert_eq!(
        required_str(&manifest["canonical_abi"], "sha256"),
        "15ec3faceb037af1ff6e5378474e0b7f6ecb7e77e91d090e514781d0880f243d"
    );

    let manifest_deployments: BTreeSet<_> = manifest["deployments"]
        .as_array()
        .expect("manifest deployments")
        .iter()
        .map(|deployment| {
            (
                deployment["chain_id"].as_u64().expect("deployment chain"),
                normalized_address(required_str(deployment, "address")),
            )
        })
        .collect();
    assert_eq!(manifest_deployments, expected_deployments);

    let mut runtimes = BTreeMap::new();
    for (chain_id, address) in DEPLOYMENTS {
        let deployment = find_deployment(&manifest, *chain_id, address);
        let runtime_spec = &deployment["runtime"];
        let runtime_path = evidence.join(required_str(runtime_spec, "file"));
        let file_bytes = fs::read(&runtime_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", runtime_path.display()));
        assert_eq!(
            sha256_hex(&file_bytes),
            required_str(runtime_spec, "file_sha256")
        );
        let runtime = read_hex(&runtime_path);
        assert_eq!(
            runtime.len() as u64,
            runtime_spec["bytes"].as_u64().expect("runtime bytes")
        );
        assert_eq!(
            sha256_hex(&runtime),
            find_known(RUNTIME_SHA256, *chain_id, address)
        );
        assert_eq!(
            required_str(runtime_spec, "decoded_sha256"),
            find_known(RUNTIME_SHA256, *chain_id, address)
        );
        assert_eq!(
            keccak_hex(&runtime),
            find_known(RUNTIME_KECCAK256, *chain_id, address)
        );
        assert_eq!(
            required_str(runtime_spec, "keccak256"),
            find_known(RUNTIME_KECCAK256, *chain_id, address)
        );

        let family = find_build_family(&manifest, required_str(deployment, "build_family"));
        assert_eq!(
            runtime.len() as u64,
            family["runtime_bytes"]
                .as_u64()
                .expect("family runtime bytes")
        );
        let mut normalized = runtime.clone();
        for (start, length) in manifest_immutable_references(&family["immutable_references"]) {
            assert_eq!(length, 32);
            normalized[start..start + length].fill(0);
        }
        assert_eq!(
            sha256_hex(&normalized),
            required_str(family, "normalized_runtime_sha256")
        );
        assert_eq!(
            required_str(runtime_spec, "normalized_sha256"),
            required_str(family, "normalized_runtime_sha256")
        );
        runtimes.insert((*chain_id, (*address).to_owned()), runtime);
    }

    assert_eq!(
        keccak_hex(ASSET_LIMIT_EIP712_TYPE.as_bytes()),
        ASSET_LIMIT_EIP712_TYPEHASH
    );
    assert_eq!(
        keccak_hex(SESSION_EIP712_TYPE.as_bytes()),
        SESSION_EIP712_TYPEHASH
    );
    assert_eq!(decode_hex_text(UINT256_MAX_HEX), vec![0xff; 32]);
    let asset_limit_typehash = keccak256(ASSET_LIMIT_EIP712_TYPE.as_bytes());
    let session_typehash = keccak256(SESSION_EIP712_TYPE.as_bytes());
    for runtime in runtimes.values() {
        assert_eq!(
            runtime
                .windows(32)
                .filter(|window| *window == asset_limit_typehash.as_slice())
                .count(),
            1,
            "the deployed runtime contains the exact AssetLimit type hash once"
        );
        assert_eq!(
            runtime
                .windows(32)
                .filter(|window| *window == session_typehash.as_slice())
                .count(),
            1,
            "the deployed runtime contains the exact Session type hash once"
        );
    }

    let eip712_descriptor_specs: [(&str, &str, &[(u64, &str)]); 2] = [
        (
            "eip712-SessionManager-FT.json",
            "FT SessionManager",
            FT_EIP712_DEPLOYMENTS,
        ),
        (
            "eip712-SessionManager-ftUSD.json",
            "ftUSD SessionManager",
            FTUSD_EIP712_DEPLOYMENTS,
        ),
    ];
    let mut described_deployments = BTreeSet::new();
    for (file_name, domain_name, expected_partition) in eip712_descriptor_specs {
        let registry_path = workspace
            .join("secure/data/erc7730-registry/registry/flyingtulip")
            .join(file_name);
        let overlay_path = workspace
            .join("secure/data/erc7730/curations/files/registry/flyingtulip")
            .join(file_name);
        let registry_bytes = fs::read(&registry_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", registry_path.display()));
        let overlay_bytes = fs::read(&overlay_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", overlay_path.display()));
        assert_eq!(overlay_bytes, registry_bytes, "curation overlay drift");
        let descriptor: Value =
            serde_json::from_slice(&registry_bytes).expect("parse Session EIP-712 descriptor");

        let eip712_context = &descriptor["context"]["eip712"];
        assert_eq!(eip712_context["domain"]["name"].as_str(), Some(domain_name));
        assert_eq!(eip712_context["domain"]["version"].as_str(), Some("1"));
        let expected_partition: BTreeSet<_> = expected_partition
            .iter()
            .map(|(chain_id, address)| (*chain_id, (*address).to_owned()))
            .collect();
        let actual_partition = deployment_set(&eip712_context["deployments"]);
        assert_eq!(actual_partition, expected_partition);
        for deployment in &actual_partition {
            assert!(
                described_deployments.insert(deployment.clone()),
                "EIP-712 deployment partitions do not overlap"
            );
            let runtime = runtimes
                .get(deployment)
                .expect("descriptor deployment has archived runtime evidence");
            assert_eq!(
                decode_short_string_immutable(runtime, EIP712_NAME_IMMUTABLE_START),
                domain_name
            );
            assert_eq!(
                decode_short_string_immutable(runtime, EIP712_VERSION_IMMUTABLE_START),
                "1"
            );
        }

        let formats = descriptor["display"]["formats"]
            .as_object()
            .expect("Session EIP-712 formats");
        assert_eq!(formats.len(), 1);
        let format = formats
            .get(SESSION_EIP712_TYPE)
            .expect("exact Session and AssetLimit EIP-712 type graph");
        let fields = format["fields"].as_array().expect("Session display fields");
        assert_eq!(fields.len(), 8);
        assert_eq!(
            fields
                .iter()
                .map(|field| required_str(field, "path"))
                .collect::<Vec<_>>(),
            vec![
                "owner",
                "delegate",
                "validAfter",
                "validUntil",
                "maxCalls",
                "maxFeeBps",
                "limits.[].limit",
                "salt",
            ]
        );
        assert!(fields
            .iter()
            .all(|field| field["visible"].as_str() == Some("always")));

        let limit = &fields[6];
        assert_eq!(limit["format"].as_str(), Some("tokenAmount"));
        assert_eq!(
            limit["params"]["tokenPath"].as_str(),
            Some("limits.[].token")
        );
        assert_eq!(limit["params"]["threshold"].as_str(), Some(UINT256_MAX_HEX));
        assert_eq!(limit["params"]["message"].as_str(), Some("Unlimited"));
        assert_eq!(fields[7]["format"].as_str(), Some("raw"));
    }
    assert_eq!(described_deployments, expected_deployments);

    let mut captures_by_family: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for capture_spec in manifest["sourcify_captures"]
        .as_array()
        .expect("Sourcify captures")
    {
        let path = evidence.join(required_str(capture_spec, "path"));
        let file_bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            sha256_hex(&file_bytes),
            required_str(capture_spec, "file_sha256")
        );
        assert_eq!(file_bytes.last(), Some(&b'\n'));
        assert_eq!(
            sha256_hex(&file_bytes[..file_bytes.len() - 1]),
            required_str(capture_spec, "response_payload_sha256")
        );
        let capture: Value =
            serde_json::from_slice(&file_bytes).expect("parse archived Sourcify response");
        let chain_id = capture_spec["chain_id"].as_u64().expect("capture chain");
        let address = normalized_address(required_str(capture_spec, "address"));
        assert_eq!(
            capture["chainId"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok()),
            Some(chain_id)
        );
        assert_eq!(
            normalized_address(required_str(&capture, "address")),
            address
        );
        assert_eq!(capture["match"].as_str(), Some("match"));
        assert_eq!(capture["creationMatch"].as_str(), Some("match"));
        assert_eq!(capture["runtimeMatch"].as_str(), Some("match"));
        assert_eq!(capture_spec["match"].as_str(), capture["match"].as_str());
        assert_eq!(
            capture_spec["creation_match"].as_str(),
            capture["creationMatch"].as_str()
        );
        assert_eq!(
            capture_spec["runtime_match"].as_str(),
            capture["runtimeMatch"].as_str()
        );
        assert_eq!(
            capture_spec["verified_at_utc"].as_str(),
            capture["verifiedAt"].as_str()
        );
        assert_eq!(capture["proxyResolution"]["isProxy"].as_bool(), Some(false));
        assert!(capture["proxyResolution"]["implementations"]
            .as_array()
            .expect("Sourcify implementation list")
            .is_empty());

        let compiler = &capture["compilation"];
        assert_eq!(compiler["language"].as_str(), Some("Solidity"));
        assert_eq!(compiler["compiler"].as_str(), Some("solc"));
        assert_eq!(
            compiler["compilerVersion"].as_str(),
            Some("0.8.30+commit.73712a01")
        );
        assert_eq!(compiler["name"].as_str(), Some("SessionManager"));
        let settings = &compiler["compilerSettings"];
        assert_eq!(settings["viaIR"].as_bool(), Some(true));
        assert_eq!(settings["optimizer"]["enabled"].as_bool(), Some(true));
        assert_eq!(settings["optimizer"]["runs"].as_u64(), Some(200));
        assert_eq!(settings["evmVersion"].as_str(), Some("cancun"));
        assert_eq!(settings["metadata"]["appendCBOR"].as_bool(), Some(false));
        assert_eq!(settings["metadata"]["bytecodeHash"].as_str(), Some("none"));

        let deployment = find_deployment(&manifest, chain_id, &address);
        let family_id = required_str(deployment, "build_family");
        assert_eq!(required_str(capture_spec, "build_family"), family_id);
        let family = find_build_family(&manifest, family_id);
        let primary_path = required_str(&family["primary_source"], "capture_path");
        let expected_fully_qualified_name = format!("{primary_path}:SessionManager");
        assert_eq!(
            compiler["fullyQualifiedName"].as_str(),
            Some(expected_fully_qualified_name.as_str())
        );
        assert_eq!(
            source_content(&capture, primary_path).len() as u64,
            family["primary_source"]["bytes"]
                .as_u64()
                .expect("source bytes")
        );
        assert_eq!(
            source_hash(&capture, primary_path),
            required_str(&family["primary_source"], "sha256")
        );
        assert_eq!(
            source_hash(
                &capture,
                "lib/openzeppelin-contracts/contracts/access/Ownable.sol"
            ),
            required_str(&manifest["shared_source"]["ownable"], "sha256")
        );
        assert_eq!(
            source_content(
                &capture,
                required_str(&manifest["shared_source"]["ownable"], "capture_path")
            )
            .len() as u64,
            manifest["shared_source"]["ownable"]["bytes"]
                .as_u64()
                .expect("Ownable bytes")
        );
        assert_eq!(
            source_hash(
                &capture,
                "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol"
            ),
            required_str(&manifest["shared_source"]["ownable2step"], "sha256")
        );
        assert_eq!(
            source_content(
                &capture,
                required_str(&manifest["shared_source"]["ownable2step"], "capture_path")
            )
            .len() as u64,
            manifest["shared_source"]["ownable2step"]["bytes"]
                .as_u64()
                .expect("Ownable2Step bytes")
        );
        assert_eq!(
            canonical_json_sha256(&capture["abi"]),
            "15ec3faceb037af1ff6e5378474e0b7f6ecb7e77e91d090e514781d0880f243d"
        );

        let references = immutable_references(&capture["runtimeBytecode"]["immutableReferences"]);
        assert_eq!(
            references,
            manifest_immutable_references(&family["immutable_references"])
        );
        let onchain = decode_hex_text(required_str(&capture["runtimeBytecode"], "onchainBytecode"));
        assert_eq!(onchain, runtimes[&(chain_id, address.clone())]);
        let recompiled = decode_hex_text(required_str(
            &capture["runtimeBytecode"],
            "recompiledBytecode",
        ));
        assert_eq!(
            sha256_hex(&recompiled),
            required_str(family, "normalized_runtime_sha256")
        );
        let mut normalized = onchain;
        for (start, length) in references {
            normalized[start..start + length].fill(0);
        }
        assert_eq!(normalized, recompiled);

        captures_by_family
            .entry(family_id.to_owned())
            .or_default()
            .push(capture);
    }
    assert_eq!(captures_by_family.values().map(Vec::len).sum::<usize>(), 3);

    for (chain_id, address, expected_hash) in SOURCIFY_CAPTURES {
        let capture_spec = manifest["sourcify_captures"]
            .as_array()
            .expect("Sourcify captures")
            .iter()
            .find(|capture| {
                capture["chain_id"].as_u64() == Some(*chain_id)
                    && normalized_address(required_str(capture, "address")) == *address
            })
            .unwrap_or_else(|| panic!("missing Sourcify capture {chain_id}:{address}"));
        let raw = fs::read(evidence.join(required_str(capture_spec, "path")))
            .expect("read Sourcify capture for hard pin");
        assert_eq!(sha256_hex(&raw), *expected_hash);
        assert_eq!(
            sha256_hex(&raw[..raw.len() - 1]),
            find_known(SOURCIFY_RESPONSE_PAYLOADS, *chain_id, address)
        );
    }

    let mut primary_sources = Vec::new();
    for (family_id, captures) in &captures_by_family {
        let family = find_build_family(&manifest, family_id);
        let primary_path = required_str(&family["primary_source"], "capture_path");
        let primary = source_content(&captures[0], primary_path);
        for capture in captures {
            assert_eq!(source_content(capture, primary_path), primary);
        }
        let expected_domain_name = required_str(&family["primary_source"], "eip712_domain_name");
        assert_eq!(
            normalized_solidity_function(primary, "constructor("),
            format!(
                "constructor(address initialOwner) EIP712(\"{expected_domain_name}\", \"1\") Ownable(initialOwner) {{}}"
            )
        );
        primary_sources.push(primary);
    }
    assert_eq!(primary_sources.len(), 2);
    for primary in &primary_sources {
        let normalized_primary = normalized_whitespace(primary);
        assert_fragments_in_order(
            &normalized_primary,
            &[
                "bytes32 private constant _ASSET_LIMIT_TYPEHASH =",
                ASSET_LIMIT_EIP712_TYPE,
                "bytes32 private constant _SESSION_TYPEHASH =",
                SESSION_EIP712_TYPE,
            ],
        );

        let create_by_signature =
            normalized_solidity_function(primary, "function createSessionBySig(");
        assert_fragments_in_order(
            &create_by_signature,
            &[
                "bytes32 limitsHash = _hashLimits(limits);",
                "bytes32 digest = _hashTypedDataV4(",
                "keccak256(",
                "abi.encode(",
                "_SESSION_TYPEHASH,",
                "owner_,",
                "delegate,",
                "validAfter,",
                "validUntil,",
                "maxCalls,",
                "maxFeeBps,",
                "limitsHash,",
                "salt",
                "if (!SignatureChecker.isValidSignatureNow(owner_, digest, ownerSignature)) {",
                "revert InvalidSignature();",
                "sessionId = _createSession(",
                "owner_, delegate, validAfter, validUntil, maxCalls, maxFeeBps, limits, salt",
            ],
        );

        let hash_limits = normalized_solidity_function(primary, "function _hashLimits(");
        assert_fragments_in_order(
            &hash_limits,
            &[
                "uint256 len = limits.length;",
                "bytes32[] memory hashes = new bytes32[](len);",
                "for (uint256 i = 0; i < len; i++) {",
                "hashes[i] = keccak256(abi.encode(_ASSET_LIMIT_TYPEHASH, limits[i].token, limits[i].limit));",
                "return keccak256(abi.encodePacked(hashes));",
            ],
        );

        let create_session = normalized_solidity_function(primary, "function _createSession(");
        assert_fragments_in_order(
            &create_session,
            &[
                "address token = limits[i].token;",
                "uint256 limit = limits[i].limit;",
                "if (token == address(0)) revert ZeroAddress();",
                "if (limit == 0) revert AssetNotAllowed(token);",
                "if (tokenAllowance[sessionId][token] != 0) revert DuplicateAsset(token);",
                "tokenAllowance[sessionId][token] = limit;",
            ],
        );

        let validate = normalized_solidity_function(primary, "function validateAndConsume(");
        let allowance_rule = "if (spendAmount != 0) { if (spendToken == address(0)) revert ZeroAddress(); uint256 allowance = tokenAllowance[call.sessionId][spendToken]; if (allowance == 0) revert AssetNotAllowed(spendToken); if (allowance != type(uint256).max) { if (spendAmount > allowance) { revert AssetLimitExceeded(spendToken, spendAmount, allowance); } tokenAllowance[call.sessionId][spendToken] = allowance - spendAmount; } }";
        assert!(validate.contains(allowance_rule));
        assert_eq!(
            validate
                .matches("tokenAllowance[call.sessionId][spendToken] =")
                .count(),
            1,
            "the finite-allowance branch is the only allowance write"
        );

        let revoke = normalized_solidity_function(primary, "function revokeSession(");
        assert_fragments_in_order(
            &revoke,
            &[
                "SessionConfig memory s = sessions[sessionId];",
                "if (s.owner == address(0)) revert SessionNotFound(sessionId);",
                "if (msg.sender != s.owner) revert NotSessionOwner(sessionId, msg.sender);",
                "if (revoked[sessionId]) revert SessionIsRevoked(sessionId);",
                "revoked[sessionId] = true;",
                "emit SessionRevoked(sessionId, s.owner);",
            ],
        );
        let set_target = normalized_solidity_function(primary, "function setAllowedTarget(");
        assert!(set_target.contains(
            "function setAllowedTarget(address target, bool allowed) external onlyOwner { _setAllowedTarget(target, allowed); }"
        ));
        let set_target_internal =
            normalized_solidity_function(primary, "function _setAllowedTarget(");
        assert_fragments_in_order(
            &set_target_internal,
            &[
                "if (target == address(0)) revert ZeroAddress();",
                "allowedTarget[target] = allowed;",
                "emit AllowedTargetUpdated(target, allowed);",
            ],
        );
    }
    assert_eq!(
        normalized_solidity_function(primary_sources[0], "function revokeSession("),
        normalized_solidity_function(primary_sources[1], "function revokeSession(")
    );
    assert_eq!(
        normalized_solidity_function(primary_sources[0], "function setAllowedTarget("),
        normalized_solidity_function(primary_sources[1], "function setAllowedTarget(")
    );
    assert_eq!(
        normalized_solidity_function(primary_sources[0], "function _setAllowedTarget("),
        normalized_solidity_function(primary_sources[1], "function _setAllowedTarget(")
    );
    assert_eq!(
        normalized_solidity_function(primary_sources[0], "function createSessionBySig("),
        normalized_solidity_function(primary_sources[1], "function createSessionBySig(")
    );
    assert_eq!(
        normalized_solidity_function(primary_sources[0], "function _hashLimits("),
        normalized_solidity_function(primary_sources[1], "function _hashLimits(")
    );
    assert_eq!(
        normalized_solidity_function(primary_sources[0], "function validateAndConsume("),
        normalized_solidity_function(primary_sources[1], "function validateAndConsume(")
    );

    let first_capture = captures_by_family
        .values()
        .next()
        .and_then(|captures| captures.first())
        .expect("at least one Sourcify capture");
    let eip712 = source_content(
        first_capture,
        "lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol",
    );
    let eip712_constructor = normalized_solidity_function(eip712, "constructor(");
    assert_fragments_in_order(
        &eip712_constructor,
        &[
            "_name = name.toShortStringWithFallback(_nameFallback);",
            "_version = version.toShortStringWithFallback(_versionFallback);",
            "_hashedName = keccak256(bytes(name));",
            "_hashedVersion = keccak256(bytes(version));",
        ],
    );
    let typed_data_hash = normalized_solidity_function(eip712, "function _hashTypedDataV4(");
    assert!(typed_data_hash
        .contains("return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);"));

    let short_strings = source_content(
        first_capture,
        "lib/openzeppelin-contracts/contracts/utils/ShortStrings.sol",
    );
    let encode_short_string =
        normalized_solidity_function(short_strings, "function toShortString(");
    assert_fragments_in_order(
        &encode_short_string,
        &[
            "bytes memory bstr = bytes(str);",
            "if (bstr.length > 0x1f)",
            "return ShortString.wrap(bytes32(uint256(bytes32(bstr)) | bstr.length));",
        ],
    );
    let decode_short_string =
        normalized_solidity_function(short_strings, "function toString(ShortString");
    assert_fragments_in_order(
        &decode_short_string,
        &[
            "uint256 len = byteLength(sstr);",
            "mstore(str, len)",
            "mstore(add(str, 0x20), sstr)",
            "return str;",
        ],
    );

    let ownable = source_content(
        first_capture,
        "lib/openzeppelin-contracts/contracts/access/Ownable.sol",
    );
    let only_owner = normalized_solidity_function(ownable, "modifier onlyOwner()");
    assert!(only_owner.contains("_checkOwner(); _;"));
    let check_owner = normalized_solidity_function(ownable, "function _checkOwner()");
    assert!(check_owner.contains(
        "if (owner() != _msgSender()) { revert OwnableUnauthorizedAccount(_msgSender()); }"
    ));

    let ownable_two_step = source_content(
        first_capture,
        "lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol",
    );
    let transfer_ownership =
        normalized_solidity_function(ownable_two_step, "function transferOwnership(");
    assert_fragments_in_order(
        &transfer_ownership,
        &[
            "public virtual override onlyOwner",
            "_pendingOwner = newOwner;",
            "emit OwnershipTransferStarted(owner(), newOwner);",
        ],
    );
    assert!(!transfer_ownership.contains("newOwner == address(0)"));
    assert!(!transfer_ownership.contains("_transferOwnership(newOwner)"));
    let accept_ownership =
        normalized_solidity_function(ownable_two_step, "function acceptOwnership(");
    assert_fragments_in_order(
        &accept_ownership,
        &[
            "address sender = _msgSender();",
            "if (pendingOwner() != sender)",
            "revert OwnableUnauthorizedAccount(sender);",
            "_transferOwnership(sender);",
        ],
    );
    let finalize_ownership =
        normalized_solidity_function(ownable_two_step, "function _transferOwnership(");
    assert_fragments_in_order(
        &finalize_ownership,
        &[
            "delete _pendingOwner;",
            "super._transferOwnership(newOwner);",
        ],
    );

    let receipt_path = evidence.join(required_str(&manifest["fixed_block_receipt"], "path"));
    let receipt_bytes = fs::read(&receipt_path).expect("read fixed-block receipt");
    assert_eq!(
        sha256_hex(&receipt_bytes),
        "ceff893e0b2f7b45597bd0c14f0c894d22a41941cbc00b3139e59fa94bbc7e16"
    );
    assert_eq!(
        sha256_hex(&receipt_bytes),
        required_str(&manifest["fixed_block_receipt"], "sha256")
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("parse fixed-block receipt");
    assert_eq!(
        receipt["proxy_slots"]["implementation"].as_str(),
        Some("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
    );
    assert_eq!(
        receipt["proxy_slots"]["admin"].as_str(),
        Some("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
    );
    assert_eq!(
        receipt["proxy_slots"]["beacon"].as_str(),
        Some("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")
    );

    let expected_headers = BTreeMap::from([
        (
            1u64,
            (
                25_572_303u64,
                "0x18633cf",
                "0xa25d10de4629dfcf1c04918573a88e22dafe46f57aa040e656d165390c9f25a8",
                "0xb4fc82abc66910cd96b56bb245dcdae2af48111e831ededf615fe351e64395fd",
                1_784_530_943u64,
                "2026-07-20T07:02:23Z",
            ),
        ),
        (
            56u64,
            (
                111_063_903u64,
                "0x69eb35f",
                "0x0553475f8e725c169d86cd7e3c5299c08eeac6ddb60cd22a283917a262891449",
                "0xea1cd575ec69b443e6568c8bb84f6c6f8d70ba66aee5e99d5303086cad6de11f",
                1_784_538_246u64,
                "2026-07-20T09:04:06Z",
            ),
        ),
        (
            146u64,
            (
                76_223_125u64,
                "0x48b1295",
                "0x67e183e96e60f3a47b541e46e4db7960cba7d919ea47c6e4ab51db8d07f3c01c",
                "0x18259c4f7aef70429fe18fe185769b0ee61300bdd249ee4277045f6f667ab9ad",
                1_784_530_944u64,
                "2026-07-20T07:02:24Z",
            ),
        ),
        (
            43_114u64,
            (
                90_778_000u64,
                "0x5692990",
                "0x3ee78fade9e6def9fa07b239b8d177d2210bf4eab5e30cb7872f6acca2ce0a5c",
                "0x2a347c1656510c7e245096cd25d94873373a372c5473da2169df88795154aa3c",
                1_784_538_179u64,
                "2026-07-20T09:02:59Z",
            ),
        ),
    ]);
    let networks = receipt["networks"].as_array().expect("receipt networks");
    assert_eq!(networks.len(), 4);
    let mut receipt_deployments = BTreeSet::new();
    let mut unavailable_slot_observations = 0usize;
    for network in networks {
        let chain_id = network["chain_id"].as_u64().expect("receipt chain id");
        let expected_header = expected_headers
            .get(&chain_id)
            .unwrap_or_else(|| panic!("unexpected receipt chain {chain_id}"));
        let block = &network["block"];
        assert_eq!(block["number"].as_u64(), Some(expected_header.0));
        assert_eq!(block["number_hex"].as_str(), Some(expected_header.1));
        assert_eq!(block["hash"].as_str(), Some(expected_header.2));
        assert_eq!(block["state_root"].as_str(), Some(expected_header.3));
        assert_eq!(block["timestamp"].as_u64(), Some(expected_header.4));
        assert_eq!(block["timestamp_utc"].as_str(), Some(expected_header.5));
        let providers: BTreeSet<_> = block["observed_identically_by"]
            .as_array()
            .expect("header providers")
            .iter()
            .map(|provider| provider.as_str().expect("provider URL"))
            .collect();
        assert_eq!(providers.len(), 2);

        let expected_network_deployments: BTreeSet<_> = DEPLOYMENTS
            .iter()
            .filter(|(deployment_chain, _)| *deployment_chain == chain_id)
            .map(|(deployment_chain, address)| (*deployment_chain, (*address).to_owned()))
            .collect();
        let actual_network_deployments: BTreeSet<_> = network["deployments"]
            .as_array()
            .expect("network deployments")
            .iter()
            .map(|deployment| {
                (
                    chain_id,
                    normalized_address(required_str(deployment, "address")),
                )
            })
            .collect();
        assert_eq!(actual_network_deployments, expected_network_deployments);

        for receipt_deployment in network["deployments"]
            .as_array()
            .expect("receipt deployments")
        {
            let address = normalized_address(required_str(receipt_deployment, "address"));
            receipt_deployments.insert((chain_id, address.clone()));
            let deployment = find_deployment(&manifest, chain_id, &address);
            assert_eq!(
                receipt_deployment["runtime_file"].as_str(),
                deployment["runtime"]["file"].as_str()
            );
            assert_eq!(
                receipt_deployment["runtime"]["bytes"].as_u64(),
                deployment["runtime"]["bytes"].as_u64()
            );
            assert_eq!(
                receipt_deployment["runtime"]["sha256"].as_str(),
                Some(find_known(RUNTIME_SHA256, chain_id, &address))
            );
            assert_eq!(
                receipt_deployment["runtime"]["keccak256"].as_str(),
                Some(find_known(RUNTIME_KECCAK256, chain_id, &address))
            );
            assert_eq!(
                deployment["evidence_block"]["number"].as_u64(),
                block["number"].as_u64()
            );
            assert_eq!(
                deployment["evidence_block"]["number_hex"].as_str(),
                block["number_hex"].as_str()
            );

            let observations = receipt_deployment["observations"]
                .as_array()
                .expect("RPC observations");
            assert_eq!(observations.len(), 2);
            let observation_endpoints: BTreeSet<_> = observations
                .iter()
                .map(|observation| required_str(observation, "endpoint"))
                .collect();
            assert_eq!(observation_endpoints, providers);
            let mut zero_slot_receipts = 0usize;
            for observation in observations {
                assert_eq!(observation["runtime_matches_archive"].as_bool(), Some(true));
                if let Some(slots) = observation["proxy_slot_results"].as_object() {
                    zero_slot_receipts += 1;
                    for slot in ["implementation", "admin", "beacon"] {
                        assert_eq!(slots[slot].as_str(), Some(ZERO_WORD));
                    }
                } else {
                    unavailable_slot_observations += 1;
                    assert_eq!(chain_id, 56);
                    assert_eq!(
                        observation["endpoint"].as_str(),
                        Some("https://bsc.meowrpc.com")
                    );
                    assert!(required_str(observation, "proxy_slot_error")
                        .contains("Historical eth_getStorageAt was unavailable"));
                }
            }
            assert!(
                zero_slot_receipts >= 1,
                "each deployment needs at least one fixed-block zero-slot receipt"
            );
        }
    }
    assert_eq!(receipt_deployments, expected_deployments);
    assert_eq!(unavailable_slot_observations, 1);

    let receipt_residuals = receipt["residuals"]
        .as_array()
        .expect("receipt residuals")
        .iter()
        .map(|residual| residual.as_str().expect("receipt residual"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(receipt_residuals.contains("bespoke proxy"));
    assert!(receipt_residuals.contains("historical fixed-block observations"));
    assert!(receipt_residuals.contains("not live monitoring"));
    assert!(
        required_str(&manifest["direct_contract_classification"], "residual")
            .contains("standard-slot zeros alone do not exclude every bespoke proxy")
    );
    assert!(required_str(&manifest, "boundary").contains("no live-state"));
    assert!(required_str(&manifest, "boundary").contains("blind-signing authority"));
}
