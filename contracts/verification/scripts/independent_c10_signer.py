#!/usr/bin/env python3
"""
independent_c10_signer.py — a clean-room SHA-256 SPHINCS+C10 signer.

PURPOSE (A3.1 independent-source KAT leg, work-todo #7). The existing 3-way
Lean↔Yul↔Rust differential is anchored on vectors produced by the ONE Rust
`sphincs-c10` signer — a single implementation. This module is a SECOND,
independent implementation of the SAME C10 spec, in a different language, written
from the scheme (the deployed `SPHINCsC10Asm.sol` verifier + the documented PRF
preimages), NOT transliterated from the Rust. Validated by reproducing a
known-good Rust-generated vector BYTE-FOR-BYTE (deterministic signing), it gives
implementation diversity for the oracle: a transcription/spec bug present in BOTH
the Rust signer and the verifiers but absent here (or vice-versa) now shows up.

HONEST SCOPE: this is implementation diversity over a SHARED SPEC (the C10 scheme
is non-standard — there is no second independent spec to test against). It does
NOT replace the kernel proof or the Halmos/KAT discharge; it strengthens the
empirical oracle backing the A3.1 axiom's transcription residual.

Scheme (C10): h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205, SHA-256, JARDIN ADRS.
All tweakable hashes truncate to N=16 bytes (top 16); H_msg + wots_digest are full
32 bytes. ADRS = layer(4)||tree(8)||type(4)||kp(4)||ci(4)||cp(4)||ha(4).

Run:  python3 independent_c10_signer.py            # self-test vs the known-good vector
"""

import hashlib

# ── params ─────────────────────────────────────────────────────────────────
N = 16
H, D, A, K, W, L = 18, 2, 11, 13, 8, 43
LOG_W, W_MASK, TARGET_SUM, SUBTREE_H = 3, 0x7, 205, 9
FORS_LEAVES = 1 << A          # 2048
SUBTREE_LEAVES = 1 << SUBTREE_H  # 512
ADRS_WOTS, ADRS_WOTS_PK, ADRS_TREE, ADRS_FORS_TREE, ADRS_FORS_ROOTS = 0, 1, 2, 3, 4


# ── primitives ─────────────────────────────────────────────────────────────
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def trunc16(d: bytes) -> bytes:
    return d[:N]


def pad16(v16: bytes) -> bytes:
    return v16 + b"\x00" * (32 - N)


def be(x: int, nbytes: int) -> bytes:
    return (x & ((1 << (8 * nbytes)) - 1)).to_bytes(nbytes, "big")


def make_adrs(layer, tree, atype, kp, ci, cp, ha) -> bytes:
    """JARDIN 32-byte ADRS: layer(4)||tree(8)||type(4)||kp(4)||ci(4)||cp(4)||ha(4)."""
    v = ((layer & 0xFFFFFFFF) << 224 | (tree & 0xFFFFFFFFFFFFFFFF) << 160 |
         (atype & 0xFFFFFFFF) << 128 | (kp & 0xFFFFFFFF) << 96 |
         (ci & 0xFFFFFFFF) << 64 | (cp & 0xFFFFFFFF) << 32 | (ha & 0xFFFFFFFF))
    return v.to_bytes(32, "big")


def set_ci(adrs: bytes, i: int) -> bytes:        # chain index lives in bytes [20..24)
    a = bytearray(adrs)
    a[20:24] = be(i, 4)
    return bytes(a)


# ── PRFs / tweakable hashes (preimages per sphincs-c10/src/hash.rs) ──────────
def wots_secret(sk_seed, layer, tree, kp, ci) -> bytes:
    # sha256(sk_seed || "wots" || be4(layer) || u64_b32(tree) || be4(kp) || be4(ci))
    tree_b32 = b"\x00" * 24 + be(tree, 8)
    return trunc16(sha256(sk_seed + b"wots" + be(layer, 4) + tree_b32 + be(kp, 4) + be(ci, 4)))


def fors_secret(sk_seed, ht_idx, tree_idx, leaf_idx) -> bytes:
    return trunc16(sha256(sk_seed + b"fors" + be(ht_idx, 4) + be(tree_idx, 4) + be(leaf_idx, 4)))


def th(seed32, adrs32, val32) -> bytes:
    return trunc16(sha256(seed32 + adrs32 + val32))


def th_pair(seed32, adrs32, l32, r32) -> bytes:
    return trunc16(sha256(seed32 + adrs32 + l32 + r32))


def th_multi(seed32, adrs32, vals16) -> bytes:
    return trunc16(sha256(seed32 + adrs32 + b"".join(pad16(v) for v in vals16)))


def h_msg(seed32, root32, r32, msg32) -> bytes:   # full 32-byte digest
    return sha256(seed32 + root32 + r32 + msg32 + b"\xff" * 32)


def wots_digest(seed32, wots_adrs32, msg32, count) -> bytes:   # full 32-byte digest
    return sha256(seed32 + wots_adrs32 + msg32 + (b"\x00" * 28 + be(count, 4)))


def chain_hash(seed32, base_adrs, val16, start, steps) -> bytes:
    cur = val16
    a = bytearray(base_adrs)
    for step in range(steps):
        a[24:28] = be(start + step, 4)          # chain position lives in bytes [24..28)
        cur = th(seed32, bytes(a), pad16(cur))
    return cur


# ── WOTS+C ──────────────────────────────────────────────────────────────────
def wots_keygen_pk(seed32, sk_seed, layer, tree, kp) -> bytes:
    base = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    pk = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        pk.append(chain_hash(seed32, set_ci(base, i), sk_i, 0, W - 1))
    return th_multi(seed32, make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0), pk)


def _digits(d32):
    Di = int.from_bytes(d32, "big")
    return [(Di >> (i * LOG_W)) & W_MASK for i in range(L)]


def wots_sign(seed32, sk_seed, layer, tree, kp, node16):
    msg = pad16(node16)
    base = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    count = 0
    while True:
        digits = _digits(wots_digest(seed32, base, msg, count))
        if sum(digits) == TARGET_SUM:
            break
        count += 1
    sigma = []
    for i in range(L):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        sigma.append(chain_hash(seed32, set_ci(base, i), sk_i, 0, digits[i]))
    return sigma, count


def wots_pk_from_sig(seed32, layer, tree, kp, node16, sigma, count) -> bytes:
    base = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    digits = _digits(wots_digest(seed32, base, pad16(node16), count))
    pk = [chain_hash(seed32, set_ci(base, i), sigma[i], digits[i], (W - 1) - digits[i]) for i in range(L)]
    return th_multi(seed32, make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0), pk)


# ── Merkle subtree ───────────────────────────────────────────────────────────
def build_subtree(seed32, sk_seed, layer, tree):
    nodes = [[wots_keygen_pk(seed32, sk_seed, layer, tree, kp) for kp in range(SUBTREE_LEAVES)]]
    for h in range(SUBTREE_H):
        prev = nodes[h]
        nodes.append([
            th_pair(seed32, make_adrs(layer, tree, ADRS_TREE, 0, 0, h + 1, j // 2),
                    pad16(prev[j]), pad16(prev[j + 1]))
            for j in range(0, len(prev), 2)
        ])
    return nodes


def merkle_auth(nodes, leaf_idx, height):
    path, idx = [], leaf_idx
    for h in range(height):
        path.append(nodes[h][idx ^ 1])
        idx >>= 1
    return path


def verify_auth_path(seed32, layer, tree, leaf16, leaf_idx, ap):
    node, idx = leaf16, leaf_idx
    for h in range(SUBTREE_H):
        adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, h + 1, idx >> 1)
        sib = ap[h]
        node = (th_pair(seed32, adrs, pad16(node), pad16(sib)) if idx & 1 == 0
                else th_pair(seed32, adrs, pad16(sib), pad16(node)))
        idx >>= 1
    return node


def compute_pk_root(sk_seed, pk_seed16) -> bytes:
    seed32 = pad16(pk_seed16)
    return build_subtree(seed32, sk_seed, 1, 0)[SUBTREE_H][0]


# ── FORS+C ────────────────────────────────────────────────────────────────────
def build_fors_tree(seed32, sk_seed, ht_idx, tree_idx):
    leaves = []
    for j in range(FORS_LEAVES):
        s = fors_secret(sk_seed, ht_idx, tree_idx, j)
        leaves.append(th(seed32, make_adrs(0, ht_idx, ADRS_FORS_TREE, tree_idx, 0, 0, j), pad16(s)))
    nodes = [leaves]
    for h in range(A):
        prev = nodes[h]
        nodes.append([
            th_pair(seed32, make_adrs(0, ht_idx, ADRS_FORS_TREE, tree_idx, 0, h + 1, j // 2),
                    pad16(prev[j]), pad16(prev[j + 1]))
            for j in range(0, len(prev), 2)
        ])
    return nodes


# ── full sign (deterministic R, opt_rand = None) ──────────────────────────────
def sign(sk_seed, pk_seed16, pk_root16, msg32):
    seed32 = pad16(pk_seed16)
    a_mask = (1 << A) - 1
    last_shift = (K - 1) * A          # 132
    # R-grind: deterministic, secret-keyed (sphincs-c10/src/fors.rs::grind_r, opt_rand=None)
    nonce = 0
    while True:
        R = trunc16(sha256(sk_seed + b"R_grind" + msg32 + (b"\x00" * 28 + be(nonce, 4))))
        digest = h_msg(seed32, pad16(pk_root16), pad16(R), msg32)
        Di = int.from_bytes(digest, "big")
        if (Di >> last_shift) & a_mask == 0:
            break
        nonce += 1
    fors_idx = [(Di >> (i * A)) & a_mask for i in range(K)]
    ht_idx = (Di >> (K * A)) & ((1 << H) - 1)
    assert fors_idx[K - 1] == 0

    # FORS: first K-1 trees → (leaf secret, auth path); last tree → root packed as "secret"
    secrets, roots, auths = [None] * K, [None] * K, [None] * (K - 1)
    for t in range(K - 1):
        nodes = build_fors_tree(seed32, sk_seed, ht_idx, t)
        secrets[t] = fors_secret(sk_seed, ht_idx, t, fors_idx[t])
        auths[t] = merkle_auth(nodes, fors_idx[t], A)
        roots[t] = nodes[A][0]
    last_root = build_fors_tree(seed32, sk_seed, ht_idx, K - 1)[A][0]
    secrets[K - 1] = last_root
    roots[K - 1] = th(seed32, make_adrs(0, ht_idx, ADRS_FORS_TREE, K - 1, 0, 0, 0), pad16(last_root))
    fors_pk = th_multi(seed32, make_adrs(0, ht_idx, ADRS_FORS_ROOTS, 0, 0, 0, 0), roots)

    sig = bytearray()
    sig += R
    for s in secrets:
        sig += s
    for t in range(K - 1):
        for node in auths[t]:
            sig += node

    # Hypertree: D=2 layers
    current, idx_tree = fors_pk, ht_idx
    for layer in range(D):
        idx_leaf = idx_tree & ((1 << SUBTREE_H) - 1)
        idx_tree >>= SUBTREE_H
        nodes = build_subtree(seed32, sk_seed, layer, idx_tree)
        ap = merkle_auth(nodes, idx_leaf, SUBTREE_H)
        sigma, count = wots_sign(seed32, sk_seed, layer, idx_tree, idx_leaf, current)
        for s in sigma:
            sig += s
        sig += be(count, 4)
        for node in ap:
            sig += node
        wpk = wots_pk_from_sig(seed32, layer, idx_tree, idx_leaf, current, sigma, count)
        current = verify_auth_path(seed32, layer, idx_tree, wpk, idx_leaf, ap)
    assert current == pk_root16, "self-verify: reconstructed root != pk_root"
    return bytes(sig)


# ── independent verifier (second implementation of the verify side) ───────────
def verify(pk_seed16, pk_root16, msg32, sig) -> bool:
    """Clean-room C10 verify — a SECOND verifier implementation. Used to round-trip
    fresh (non-KAT) messages from the independent signer."""
    if len(sig) != 4008:
        return False
    seed32 = pad16(pk_seed16)
    off = 0
    R = sig[off:off + N]; off += N
    digest = h_msg(seed32, pad16(pk_root16), pad16(R), msg32)
    Di = int.from_bytes(digest, "big")
    a_mask = (1 << A) - 1
    fors_idx = [(Di >> (i * A)) & a_mask for i in range(K)]
    if fors_idx[K - 1] != 0:
        return False
    ht_idx = (Di >> (K * A)) & ((1 << H) - 1)
    secrets = [sig[off + t * N:off + (t + 1) * N] for t in range(K)]; off += K * N
    auths = []
    for _t in range(K - 1):
        ap = [sig[off + h * N:off + (h + 1) * N] for h in range(A)]
        off += A * N
        auths.append(ap)
    roots = [None] * K
    for t in range(K - 1):
        node, idx = th(seed32, make_adrs(0, ht_idx, ADRS_FORS_TREE, t, 0, 0, fors_idx[t]),
                       pad16(secrets[t])), fors_idx[t]
        for h in range(A):
            adrs = make_adrs(0, ht_idx, ADRS_FORS_TREE, t, 0, h + 1, idx >> 1)
            sib = auths[t][h]
            node = (th_pair(seed32, adrs, pad16(node), pad16(sib)) if idx & 1 == 0
                    else th_pair(seed32, adrs, pad16(sib), pad16(node)))
            idx >>= 1
        roots[t] = node
    roots[K - 1] = th(seed32, make_adrs(0, ht_idx, ADRS_FORS_TREE, K - 1, 0, 0, 0),
                      pad16(secrets[K - 1]))
    current = th_multi(seed32, make_adrs(0, ht_idx, ADRS_FORS_ROOTS, 0, 0, 0, 0), roots)
    idx_tree = ht_idx
    for layer in range(D):
        idx_leaf = idx_tree & ((1 << SUBTREE_H) - 1)
        idx_tree >>= SUBTREE_H
        sigma = [sig[off + i * N:off + (i + 1) * N] for i in range(L)]; off += L * N
        count = int.from_bytes(sig[off:off + 4], "big"); off += 4
        ap = [sig[off + h * N:off + (h + 1) * N] for h in range(SUBTREE_H)]; off += SUBTREE_H * N
        wpk = wots_pk_from_sig(seed32, layer, idx_tree, idx_leaf, current, sigma, count)
        current = verify_auth_path(seed32, layer, idx_tree, wpk, idx_leaf, ap)
    return current == pk_root16


# ── self-test against the known-good Rust-generated vectors ───────────────────
# Deterministic keypair + valid-1 from sphincs-c10/tests/gen_test_vectors.rs.
_SK_SEED = bytes([
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
])
_PK_SEED = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99])
_EXPECTED_PK_ROOT = bytes.fromhex("acfe47c228cac51484de30c2f977cbd0")
_MSG = b"PQSigner OS C10 Foundry test vec"


def _load_valid_vectors():
    import json
    import os
    p = os.path.join(os.path.dirname(__file__), "..", "..",
                     "smart-wallet", "test", "c10_test_vectors.json")
    d = json.load(open(p))
    out = []
    for v in d["vectors"]:
        if v.get("expectValid"):
            out.append((v["label"], bytes.fromhex(v["message"][2:]),
                        bytes.fromhex(v["signature"][2:])))
    return out


def self_test() -> int:
    print("=== independent clean-room C10 signer — byte-equivalence self-test ===")
    pk_root = compute_pk_root(_SK_SEED, _PK_SEED)
    if pk_root != _EXPECTED_PK_ROOT:
        print(f"FAIL keygen: pk_root {pk_root.hex()} != {_EXPECTED_PK_ROOT.hex()}")
        return 1
    print(f"keygen pk_root : {pk_root.hex()}  OK (matches the Rust signer)")

    # (1) Reproduce EVERY valid KAT vector byte-for-byte. Each of these exact byte
    #     strings is independently accepted by the Rust + Yul + Lean verifiers in the
    #     existing suites, so byte-identity here ties this independent signer to all
    #     three verifiers — implementation diversity over the shared C10 spec.
    vectors = _load_valid_vectors()
    for label, msg, expected in vectors:
        sig = sign(_SK_SEED, _PK_SEED, pk_root, msg)
        if sig != expected:
            for i in range(min(len(sig), len(expected))):
                if sig[i] != expected[i]:
                    print(f"FAIL {label}: first diff at byte {i}: "
                          f"got {sig[i]:02x} expected {expected[i]:02x}")
                    break
            return 1
        print(f"sign {label:8s} : {len(sig)} bytes  BYTE-IDENTICAL to the Rust signer")

    # (2) Round-trip FRESH (non-KAT) messages through the independent verifier — proves
    #     the signer is faithful for arbitrary messages, not just the KAT (different
    #     digests exercise different FORS/HT index positions + count grinds).
    for tag in (b"independent oracle fresh message#", b"another fresh c10 differential!!",
                b"third fresh vector for coverage_"):
        msg = tag[:32].ljust(32, b"\x00")
        sig = sign(_SK_SEED, _PK_SEED, pk_root, msg)
        if not verify(_PK_SEED, pk_root, msg, sig):
            print(f"FAIL fresh round-trip: independent verify rejected {tag!r}")
            return 1
        print(f"fresh round-trip: {tag.decode(errors='replace')[:18]}…  sign+verify OK")

    print(f"OK: independent signer reproduces the Rust pk_root + ALL {len(vectors)} valid KAT "
          f"vectors byte-for-byte,")
    print("    and round-trips fresh messages. Two C10 implementations agree (oracle diversity).")
    return 0


def _emit(label: str, msg_hex: str):
    """Emit a fresh (msg, sig) vector as JSON line for the Rust cross-verifier test."""
    import json
    msg = bytes.fromhex(msg_hex[2:] if msg_hex.startswith("0x") else msg_hex)
    assert len(msg) == 32, "message must be 32 bytes"
    pk_root = compute_pk_root(_SK_SEED, _PK_SEED)
    sig = sign(_SK_SEED, _PK_SEED, pk_root, msg)
    assert verify(_PK_SEED, pk_root, msg, sig)
    print(json.dumps({
        "label": label,
        "pkSeed": "0x" + _PK_SEED.hex(),
        "pkRoot": "0x" + pk_root.hex(),
        "message": "0x" + msg.hex(),
        "signature": "0x" + sig.hex(),
    }))


def _emit_fields(msg_hex: str):
    """Emit `pkSeed pkRoot message signature` as 4 space-separated 0x-hex tokens
    (trivially parsable by the Rust cross-verifier test, no JSON dep)."""
    msg = bytes.fromhex(msg_hex[2:] if msg_hex.startswith("0x") else msg_hex)
    assert len(msg) == 32, "message must be 32 bytes"
    pk_root = compute_pk_root(_SK_SEED, _PK_SEED)
    sig = sign(_SK_SEED, _PK_SEED, pk_root, msg)
    print(f"0x{_PK_SEED.hex()} 0x{pk_root.hex()} 0x{msg.hex()} 0x{sig.hex()}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 4 and sys.argv[1] == "--emit":
        _emit(sys.argv[2], sys.argv[3])
        sys.exit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "--emit-fields":
        _emit_fields(sys.argv[2])
        sys.exit(0)
    sys.exit(self_test())
