//! Strict, bounded verification of Ethereum EIP-1186 account and storage
//! proofs.
//!
//! The verifier treats the proof as an unordered witness set. Every supplied
//! hashed node must be consumed exactly once by the authenticated path; inline
//! children are consumed directly from their parent and must not be repeated in
//! the witness. This rejects duplicate and surplus nodes while remaining
//! independent of an RPC provider's array ordering.

use pqsigner_tx_core::{
    hash::keccak256,
    rlp::{self, Item},
};

// A 32-byte secure key has 64 nibbles. The pathological canonical path is one
// branch per nibble followed by an empty-path leaf: 65 nodes total.
const MAX_PROOF_NODES: usize = 65;
const MAX_PROOF_NODE_BYTES: usize = 1_024;
const MAX_TRIE_STEPS: usize = 65;
const MAX_INLINE_DEPTH: usize = 32;

/// The authenticated account fields needed to verify storage proofs and bind
/// an account to its deployed code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// Verify an account proof against `state_root`.
///
/// The state-trie key is `keccak256(address)`. `Ok(None)` is returned only for
/// an authenticated absence proof; malformed, incomplete, duplicate, and
/// surplus witnesses are errors.
pub fn verify_account_proof(
    state_root: [u8; 32],
    address: [u8; 20],
    proof: &[Vec<u8>],
) -> Result<Option<Account>, String> {
    let key = keccak256(&address);
    match trie_get(state_root, key, proof)? {
        Some(value) => decode_account(&value).map(Some),
        None => Ok(None),
    }
}

/// Verify a storage proof against an authenticated account storage root.
///
/// The storage-trie key is `keccak256(slot)`. An included value is returned as
/// its canonical, minimal big-endian scalar bytes. Ethereum deletes zero-valued
/// storage slots, so an encoded zero is rejected rather than confused with
/// authenticated absence.
pub fn verify_storage_proof(
    storage_root: [u8; 32],
    slot: [u8; 32],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, String> {
    let key = keccak256(&slot);
    match trie_get(storage_root, key, proof)? {
        Some(value) => decode_storage_scalar(&value).map(Some),
        None => Ok(None),
    }
}

fn trie_get(root: [u8; 32], key: [u8; 32], proof: &[Vec<u8>]) -> Result<Option<Vec<u8>>, String> {
    // An empty Ethereum trie is represented by keccak256(rlp("")); there is
    // no trie node to include in the proof.
    if root == keccak256(&[0x80]) {
        return if proof.is_empty() {
            Ok(None)
        } else {
            Err("proof contains nodes for the empty trie".into())
        };
    }

    let mut witness = ProofWitness::new(proof)?;
    let nibbles = key_nibbles(&key);
    let mut key_offset = 0usize;
    let mut source = NodeSource::Hash {
        hash: root,
        is_root: true,
    };
    let mut required_tag = None;

    for _ in 0..MAX_TRIE_STEPS {
        let raw = match source {
            NodeSource::Hash { hash, is_root } => witness.take(hash, is_root)?,
            NodeSource::Inline(raw) => raw,
        };
        let node = decode_node(raw, 0)?;

        if let Some(expected) = required_tag.take() {
            if node.tag() != expected {
                return Err("extension child is not a branch node".into());
            }
        }

        match node {
            DecodedNode::Branch { children } => {
                if key_offset >= nibbles.len() {
                    return Err("branch appears after the secure-trie key is exhausted".into());
                }
                let child = children[nibbles[key_offset] as usize].clone();
                key_offset += 1;
                match child {
                    ChildRef::Empty => return finish_lookup(witness, None),
                    ChildRef::Hash(hash) => {
                        source = NodeSource::Hash {
                            hash,
                            is_root: false,
                        };
                    }
                    ChildRef::Inline(raw) => source = NodeSource::Inline(raw),
                }
            }
            DecodedNode::Extension { path, child } => {
                let remaining = nibbles.len() - key_offset;
                // An extension must leave at least one key nibble for its
                // canonical branch child. Longer keys cannot exist in a
                // state/storage secure trie because all preimages are 32 bytes.
                if path.len() >= remaining {
                    return Err("extension path exceeds a fixed-length secure-trie key".into());
                }
                if nibbles[key_offset..key_offset + path.len()] != path {
                    return finish_lookup(witness, None);
                }
                key_offset += path.len();
                required_tag = Some(NodeTag::Branch);
                match child {
                    ChildRef::Empty => {
                        return Err("extension contains an empty child".into());
                    }
                    ChildRef::Hash(hash) => {
                        source = NodeSource::Hash {
                            hash,
                            is_root: false,
                        };
                    }
                    ChildRef::Inline(raw) => source = NodeSource::Inline(raw),
                }
            }
            DecodedNode::Leaf { path, value } => {
                let remaining = &nibbles[key_offset..];
                if remaining.len() != path.len() {
                    return Err("leaf path does not fill a fixed-length secure-trie key".into());
                }
                if remaining != path {
                    return finish_lookup(witness, None);
                }
                return finish_lookup(witness, Some(value.to_vec()));
            }
        }
    }

    Err("proof exceeds the secure-trie traversal bound".into())
}

fn finish_lookup(
    witness: ProofWitness<'_>,
    value: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, String> {
    witness.finish()?;
    Ok(value)
}

struct ProofWitness<'a> {
    proof: &'a [Vec<u8>],
    hashes: Vec<[u8; 32]>,
    used: Vec<bool>,
}

impl<'a> ProofWitness<'a> {
    fn new(proof: &'a [Vec<u8>]) -> Result<Self, String> {
        if proof.len() > MAX_PROOF_NODES {
            return Err(format!(
                "proof has {} nodes; maximum is {MAX_PROOF_NODES}",
                proof.len()
            ));
        }

        let mut hashes = Vec::with_capacity(proof.len());
        for (index, node) in proof.iter().enumerate() {
            if node.is_empty() {
                return Err(format!("proof node {index} is empty"));
            }
            if node.len() > MAX_PROOF_NODE_BYTES {
                return Err(format!(
                    "proof node {index} has {} bytes; maximum is {MAX_PROOF_NODE_BYTES}",
                    node.len()
                ));
            }
            let hash = keccak256(node);
            if hashes.contains(&hash) {
                return Err(format!("proof node {index} duplicates an earlier node"));
            }
            hashes.push(hash);
        }

        Ok(Self {
            proof,
            hashes,
            used: vec![false; proof.len()],
        })
    }

    fn take(&mut self, expected: [u8; 32], is_root: bool) -> Result<&'a [u8], String> {
        let index = self
            .hashes
            .iter()
            .position(|hash| *hash == expected)
            .ok_or_else(|| {
                if is_root {
                    "proof does not contain a node matching the trie root".to_owned()
                } else {
                    "proof is missing a referenced child node".to_owned()
                }
            })?;

        if self.used[index] {
            return Err("proof path reuses a previously consumed node".into());
        }
        let node = self.proof[index].as_slice();
        if !is_root && node.len() < 32 {
            return Err("hashed child reference targets a node shorter than 32 bytes".into());
        }
        self.used[index] = true;
        Ok(node)
    }

    fn finish(self) -> Result<(), String> {
        if let Some(index) = self.used.iter().position(|used| !*used) {
            return Err(format!("proof contains surplus node {index}"));
        }
        Ok(())
    }
}

#[derive(Clone)]
enum NodeSource<'a> {
    Hash { hash: [u8; 32], is_root: bool },
    Inline(&'a [u8]),
}

#[derive(Clone)]
enum ChildRef<'a> {
    Empty,
    Hash([u8; 32]),
    Inline(&'a [u8]),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum NodeTag {
    Branch,
    Extension,
    Leaf,
}

enum DecodedNode<'a> {
    Branch { children: Vec<ChildRef<'a>> },
    Extension { path: Vec<u8>, child: ChildRef<'a> },
    Leaf { path: Vec<u8>, value: &'a [u8] },
}

impl DecodedNode<'_> {
    const fn tag(&self) -> NodeTag {
        match self {
            Self::Branch { .. } => NodeTag::Branch,
            Self::Extension { .. } => NodeTag::Extension,
            Self::Leaf { .. } => NodeTag::Leaf,
        }
    }
}

#[derive(Copy, Clone)]
struct EncodedItem<'a> {
    item: Item<'a>,
    raw: &'a [u8],
}

fn decode_node(raw: &[u8], inline_depth: usize) -> Result<DecodedNode<'_>, String> {
    if inline_depth > MAX_INLINE_DEPTH {
        return Err("inline trie-node nesting exceeds its bound".into());
    }
    let (outer, used) = rlp::decode_item(raw).map_err(|err| rlp_error("trie node", err))?;
    if used != raw.len() {
        return Err("trie node has trailing bytes".into());
    }
    let Item::List(payload) = outer else {
        return Err("trie node is not an RLP list".into());
    };
    let items = decode_list_items(payload)?;

    match items.len() {
        17 => decode_branch(&items, inline_depth),
        2 => decode_short_node(&items, inline_depth),
        count => Err(format!("trie node has {count} fields; expected 2 or 17")),
    }
}

fn decode_branch<'a>(
    items: &[EncodedItem<'a>],
    inline_depth: usize,
) -> Result<DecodedNode<'a>, String> {
    let mut children = Vec::with_capacity(16);
    let mut occupied = 0usize;
    for item in &items[..16] {
        let child = decode_child_ref(*item, true)?;
        if !matches!(child, ChildRef::Empty) {
            occupied += 1;
        }
        if let ChildRef::Inline(raw) = child {
            decode_node(raw, inline_depth + 1)?;
        }
        children.push(child);
    }

    let Item::Bytes(value) = items[16].item else {
        return Err("branch value is not an RLP byte string".into());
    };
    if !value.is_empty() {
        return Err("secure-trie branch contains a prefix value".into());
    }
    if occupied < 2 {
        return Err("branch has fewer than two occupied entries".into());
    }

    Ok(DecodedNode::Branch { children })
}

fn decode_short_node<'a>(
    items: &[EncodedItem<'a>],
    inline_depth: usize,
) -> Result<DecodedNode<'a>, String> {
    let Item::Bytes(encoded_path) = items[0].item else {
        return Err("compact trie path is not an RLP byte string".into());
    };
    let (is_leaf, path) = decode_compact_path(encoded_path)?;

    if is_leaf {
        let Item::Bytes(value) = items[1].item else {
            return Err("leaf value is not an RLP byte string".into());
        };
        if value.is_empty() {
            return Err("leaf contains an empty value".into());
        }
        Ok(DecodedNode::Leaf { path, value })
    } else {
        if path.is_empty() {
            return Err("extension contains an empty path".into());
        }
        let child = decode_child_ref(items[1], false)?;
        if let ChildRef::Inline(raw) = child {
            let child_node = decode_node(raw, inline_depth + 1)?;
            if child_node.tag() != NodeTag::Branch {
                return Err("inline extension child is not a branch node".into());
            }
        }
        Ok(DecodedNode::Extension { path, child })
    }
}

fn decode_child_ref(encoded: EncodedItem<'_>, allow_empty: bool) -> Result<ChildRef<'_>, String> {
    match encoded.item {
        Item::Bytes(bytes) if bytes.is_empty() && allow_empty => Ok(ChildRef::Empty),
        Item::Bytes(bytes) if bytes.len() == 32 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            Ok(ChildRef::Hash(hash))
        }
        Item::Bytes([]) => Err("trie child reference is empty".into()),
        Item::Bytes(_) => Err("trie child reference is neither empty nor a 32-byte hash".into()),
        Item::List(_) if encoded.raw.len() < 32 => Ok(ChildRef::Inline(encoded.raw)),
        Item::List(_) => Err("inline trie child is 32 bytes or longer".into()),
    }
}

fn decode_list_items(mut payload: &[u8]) -> Result<Vec<EncodedItem<'_>>, String> {
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, used) =
            rlp::decode_item(payload).map_err(|err| rlp_error("trie-node field", err))?;
        items.push(EncodedItem {
            item,
            raw: &payload[..used],
        });
        payload = &payload[used..];
    }
    Ok(items)
}

fn decode_compact_path(encoded: &[u8]) -> Result<(bool, Vec<u8>), String> {
    let first = *encoded
        .first()
        .ok_or_else(|| "compact trie path is empty".to_owned())?;
    let flag = first >> 4;
    if flag > 3 {
        return Err("compact trie path has an invalid flag nibble".into());
    }
    let odd = flag & 1 == 1;
    if !odd && first & 0x0f != 0 {
        return Err("even compact trie path has a non-zero padding nibble".into());
    }

    let mut path = Vec::with_capacity(encoded.len() * 2);
    if odd {
        path.push(first & 0x0f);
    }
    for &byte in &encoded[1..] {
        path.push(byte >> 4);
        path.push(byte & 0x0f);
    }
    Ok((flag & 2 != 0, path))
}

fn key_nibbles(key: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (index, byte) in key.iter().copied().enumerate() {
        out[index * 2] = byte >> 4;
        out[index * 2 + 1] = byte & 0x0f;
    }
    out
}

fn decode_account(value: &[u8]) -> Result<Account, String> {
    let (outer, used) = rlp::decode_item(value).map_err(|err| rlp_error("account value", err))?;
    if used != value.len() {
        return Err("account value has trailing bytes".into());
    }
    let Item::List(payload) = outer else {
        return Err("account value is not an RLP list".into());
    };
    let fields = decode_list_items(payload)?;
    if fields.len() != 4 {
        return Err(format!(
            "account value has {} fields; expected exactly 4",
            fields.len()
        ));
    }

    let nonce = item_bytes(fields[0], "account nonce")?;
    rlp::bytes_to_u64(nonce).map_err(|err| rlp_error("account nonce", err))?;
    let balance = item_bytes(fields[1], "account balance")?;
    rlp::bytes_to_u256(balance).map_err(|err| rlp_error("account balance", err))?;
    let storage_root = exact_32(
        item_bytes(fields[2], "account storage root")?,
        "storage root",
    )?;
    let code_hash = exact_32(item_bytes(fields[3], "account code hash")?, "code hash")?;

    Ok(Account {
        storage_root,
        code_hash,
    })
}

fn decode_storage_scalar(value: &[u8]) -> Result<Vec<u8>, String> {
    let (item, used) = rlp::decode_item(value).map_err(|err| rlp_error("storage value", err))?;
    if used != value.len() {
        return Err("storage value has trailing bytes".into());
    }
    let Item::Bytes(bytes) = item else {
        return Err("storage value is not an RLP scalar".into());
    };
    if bytes.is_empty() {
        return Err("storage proof contains a zero-valued leaf".into());
    }
    rlp::bytes_to_u256(bytes).map_err(|err| rlp_error("storage scalar", err))?;
    Ok(bytes.to_vec())
}

fn item_bytes<'a>(item: EncodedItem<'a>, field: &str) -> Result<&'a [u8], String> {
    match item.item {
        Item::Bytes(bytes) => Ok(bytes),
        Item::List(_) => Err(format!("{field} is not an RLP byte string")),
    }
}

fn exact_32(bytes: &[u8], field: &str) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!("account {field} is not 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn rlp_error(context: &str, error: rlp::RlpError) -> String {
    format!("{context} has invalid RLP: {error:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn length_bytes(length: usize) -> Vec<u8> {
        let bytes = length.to_be_bytes();
        bytes[bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1)..]
            .to_vec()
    }

    fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] <= 0x7f {
            return bytes.to_vec();
        }
        let mut out = Vec::new();
        if bytes.len() <= 55 {
            out.push(0x80 + bytes.len() as u8);
        } else {
            let length = length_bytes(bytes.len());
            out.push(0xb7 + length.len() as u8);
            out.extend_from_slice(&length);
        }
        out.extend_from_slice(bytes);
        out
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.iter().flatten().copied().collect();
        let mut out = Vec::new();
        if payload.len() <= 55 {
            out.push(0xc0 + payload.len() as u8);
        } else {
            let length = length_bytes(payload.len());
            out.push(0xf7 + length.len() as u8);
            out.extend_from_slice(&length);
        }
        out.extend_from_slice(&payload);
        out
    }

    fn compact_path(path: &[u8], leaf: bool) -> Vec<u8> {
        assert!(path.iter().all(|nibble| *nibble < 16));
        let odd = path.len() % 2 == 1;
        let mut out = Vec::with_capacity(path.len() / 2 + 1);
        let flag = (u8::from(leaf) << 1) | u8::from(odd);
        let mut index = 0usize;
        if odd {
            out.push((flag << 4) | path[0]);
            index = 1;
        } else {
            out.push(flag << 4);
        }
        while index < path.len() {
            out.push((path[index] << 4) | path[index + 1]);
            index += 2;
        }
        out
    }

    fn leaf(path: &[u8], value: &[u8]) -> Vec<u8> {
        rlp_list(&[rlp_bytes(&compact_path(path, true)), rlp_bytes(value)])
    }

    fn extension(path: &[u8], child_hash: [u8; 32]) -> Vec<u8> {
        rlp_list(&[
            rlp_bytes(&compact_path(path, false)),
            rlp_bytes(&child_hash),
        ])
    }

    fn branch(children: Vec<Vec<u8>>) -> Vec<u8> {
        assert_eq!(children.len(), 16);
        let mut fields = children;
        fields.push(rlp_bytes(&[]));
        rlp_list(&fields)
    }

    fn empty_children() -> Vec<Vec<u8>> {
        (0..16).map(|_| rlp_bytes(&[])).collect()
    }

    fn account_value(storage_root: [u8; 32], code_hash: [u8; 32]) -> Vec<u8> {
        rlp_list(&[
            rlp_bytes(&[]),
            rlp_bytes(&[1]),
            rlp_bytes(&storage_root),
            rlp_bytes(&code_hash),
        ])
    }

    fn long_storage_leaf(value: u8) -> Vec<u8> {
        let scalar = [value; 32];
        leaf(&[], &rlp_bytes(&scalar))
    }

    #[test]
    fn verifies_account_leaf_and_exact_fields() {
        let address = [0x11; 20];
        let storage_root = [0x22; 32];
        let code_hash = [0x33; 32];
        let key = key_nibbles(&keccak256(&address));
        let node = leaf(&key, &account_value(storage_root, code_hash));
        let root = keccak256(&node);

        assert_eq!(
            verify_account_proof(root, address, &[node]).unwrap(),
            Some(Account {
                storage_root,
                code_hash
            })
        );

        let five_fields = rlp_list(&[
            rlp_bytes(&[]),
            rlp_bytes(&[1]),
            rlp_bytes(&storage_root),
            rlp_bytes(&code_hash),
            rlp_bytes(&[1]),
        ]);
        let malformed = leaf(&key, &five_fields);
        assert!(verify_account_proof(keccak256(&malformed), address, &[malformed]).is_err());
    }

    #[test]
    fn verifies_hashed_nodes_and_an_inline_leaf_in_any_proof_order() {
        let slot = [0x44; 32];
        let key = key_nibbles(&keccak256(&slot));
        let target_index = key[63] as usize;
        let sibling_index = (target_index + 1) % 16;

        let mut children = empty_children();
        children[target_index] = leaf(&[], &rlp_bytes(&[0x2a]));
        let sibling = long_storage_leaf(0x55);
        assert!(sibling.len() >= 32);
        children[sibling_index] = rlp_bytes(&keccak256(&sibling));
        let branch = branch(children);
        assert!(branch.len() >= 32);
        let extension = extension(&key[..63], keccak256(&branch));
        let root = keccak256(&extension);

        // Proof nodes are deliberately reversed. The inline leaf is not a
        // separate witness node and is consumed directly from the branch.
        assert_eq!(
            verify_storage_proof(root, slot, &[branch, extension]).unwrap(),
            Some(vec![0x2a])
        );
    }

    #[test]
    fn proves_absence_at_empty_branch_and_mismatching_leaf() {
        let slot = [0x66; 32];
        let key = key_nibbles(&keccak256(&slot));
        let target_index = key[63] as usize;
        let first = (target_index + 1) % 16;
        let second = (target_index + 2) % 16;
        let mut children = empty_children();
        children[first] = rlp_bytes(&keccak256(&long_storage_leaf(0x71)));
        children[second] = rlp_bytes(&keccak256(&long_storage_leaf(0x72)));
        let branch = branch(children);
        let extension = extension(&key[..63], keccak256(&branch));
        let root = keccak256(&extension);
        assert_eq!(
            verify_storage_proof(root, slot, &[extension, branch]).unwrap(),
            None
        );

        let mut wrong_path = key;
        wrong_path[0] ^= 1;
        let scalar = rlp_bytes(&[7]);
        let wrong_leaf = leaf(&wrong_path, &scalar);
        assert_eq!(
            verify_storage_proof(keccak256(&wrong_leaf), slot, &[wrong_leaf]).unwrap(),
            None
        );
    }

    #[test]
    fn rejects_tampered_root_path_value_and_malformed_node() {
        let slot = [0x77; 32];
        let key = key_nibbles(&keccak256(&slot));
        let node = leaf(&key, &rlp_bytes(&[9]));
        let root = keccak256(&node);

        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(verify_storage_proof(wrong_root, slot, std::slice::from_ref(&node)).is_err());

        let mut tampered_path = node.clone();
        tampered_path[3] ^= 1;
        assert!(verify_storage_proof(root, slot, &[tampered_path]).is_err());

        let mut tampered_value = node.clone();
        *tampered_value.last_mut().unwrap() ^= 1;
        assert!(verify_storage_proof(root, slot, &[tampered_value]).is_err());

        let malformed = vec![0xc1];
        assert!(verify_storage_proof(keccak256(&malformed), slot, &[malformed]).is_err());
    }

    #[test]
    fn rejects_duplicate_and_surplus_nodes() {
        let slot = [0x88; 32];
        let key = key_nibbles(&keccak256(&slot));
        let node = leaf(&key, &rlp_bytes(&[3]));
        let root = keccak256(&node);

        assert!(verify_storage_proof(root, slot, &[node.clone(), node.clone()]).is_err());

        let mut other_path = key;
        other_path[1] ^= 1;
        let surplus = leaf(&other_path, &rlp_bytes(&[4]));
        assert!(verify_storage_proof(root, slot, &[node, surplus]).is_err());
    }

    #[test]
    fn rejects_noncanonical_storage_scalars_and_hashed_short_nodes() {
        let slot = [0x99; 32];
        let key = key_nibbles(&keccak256(&slot));

        let leading_zero = rlp_bytes(&[0, 1]);
        let node = leaf(&key, &leading_zero);
        assert!(verify_storage_proof(keccak256(&node), slot, &[node]).is_err());

        let zero = rlp_bytes(&[]);
        let node = leaf(&key, &zero);
        assert!(verify_storage_proof(keccak256(&node), slot, &[node]).is_err());

        let target_index = key[63] as usize;
        let sibling_index = (target_index + 1) % 16;
        let short_leaf = leaf(&[], &rlp_bytes(&[5]));
        assert!(short_leaf.len() < 32);
        let sibling = long_storage_leaf(0xa5);
        let mut children = empty_children();
        children[target_index] = rlp_bytes(&keccak256(&short_leaf));
        children[sibling_index] = rlp_bytes(&keccak256(&sibling));
        let branch = branch(children);
        let extension = extension(&key[..63], keccak256(&branch));
        let root = keccak256(&extension);
        assert!(verify_storage_proof(root, slot, &[extension, branch, short_leaf]).is_err());
    }

    #[test]
    fn accepts_empty_trie_only_with_an_empty_proof() {
        let empty_root = keccak256(&[0x80]);
        assert_eq!(
            verify_storage_proof(empty_root, [0u8; 32], &[]).unwrap(),
            None
        );
        assert!(verify_storage_proof(empty_root, [0u8; 32], &[vec![0x80]]).is_err());
    }
}
