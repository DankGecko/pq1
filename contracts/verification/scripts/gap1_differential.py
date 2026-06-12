#!/usr/bin/env python3
"""GAP-1 / A3.1 differential oracle.

Two byte-level Python replicas, traced and diffed per intermediate:

  * yul_verify  — exact transliteration of the deployed
    `SPHINCsC10Asm.verify` Yul body (SHA-256 = hashlib = FIPS 180-4 =
    the 0x02 precompile). Ground truth: the same 10 KAT vectors pass on
    the deployed bytecode (forge test_verifyAllKatVectors), so if this
    replica matches expectValid 10/10 it computes the bytecode function
    on the corpus.

  * lean_verify — exact replica of the CURRENT Lean
    `Spec.Signature.verify` (including any divergence, e.g. the
    chainHash chain-index/chain-pos field bug), used to locate the
    first diverging intermediate so the Lean fix is surgical.

Run:  python3 scripts/gap1_differential.py [--lean-fixed]
      --lean-fixed replays the lean replica WITH the proposed fix
      applied, to pre-validate the Lean patch before touching .lean.
"""
import json
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JSON = os.path.normpath(os.path.join(
    HERE, "../../smart-wallet/test/c10_test_vectors.json"))

# --- shared helpers ---------------------------------------------------------

def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def word(x: int) -> bytes:
    return x.to_bytes(32, "big")

def cdload(buf: bytes, off: int) -> bytes:
    """calldataload semantics: 32-byte read, zero-padded past the end."""
    w = buf[off:off + 32]
    return w + b"\x00" * (32 - len(w))

def mask16(w32: bytes) -> bytes:
    """and(x, N_MASK): keep top 16 bytes, zero bottom 16."""
    return w32[:16] + b"\x00" * 16

def hx(s: str) -> bytes:
    return bytes.fromhex(s[2:])


# --- replica 1: the deployed Yul -------------------------------------------

def yul_verify(pk_seed: bytes, pk_root: bytes, message: bytes, sig: bytes,
               trace=None):
    t = trace if trace is not None else (lambda *_: None)
    if len(sig) != 4008:
        return None  # revert "Invalid sig length"
    seed, root = pk_seed, pk_root

    R = mask16(cdload(sig, 0))
    digest = sha(seed + root + R + message + b"\xff" * 32)
    d_int = int.from_bytes(digest, "big")
    ht_idx = (d_int >> 143) & 0x3FFFF
    t("digest", digest.hex())
    t("htIdx", ht_idx)

    if (d_int >> 132) & 0x7FF:
        t("forcedZero", "VIOLATED -> revert")
        return None

    roots = []
    for i in range(12):
        tree_idx = (d_int >> (i * 11)) & 0x7FF
        secret = mask16(cdload(sig, 16 + 16 * i))
        leaf_adrs = (ht_idx << 160) | (3 << 128) | (i << 96) | tree_idx
        node = mask16(sha(seed + word(leaf_adrs) + secret))
        t(f"fors[{i}].leafIdx", tree_idx)
        t(f"fors[{i}].leaf", node[:16].hex())
        tree_adrs_base = (ht_idx << 160) | (3 << 128) | (i << 96)
        path_idx = tree_idx
        auth_ptr = 224 + i * 176
        for h in range(11):
            sibling = mask16(cdload(sig, auth_ptr + 16 * h))
            parent_idx = path_idx >> 1
            adrs = tree_adrs_base | ((h + 1) << 32) | parent_idx
            if path_idx & 1 == 0:
                node = mask16(sha(seed + word(adrs) + node + sibling))
            else:
                node = mask16(sha(seed + word(adrs) + sibling + node))
            path_idx = parent_idx
        roots.append(node)
        t(f"fors[{i}].root", node[:16].hex())

    last_secret = mask16(cdload(sig, 16 + 16 * 12))
    last_adrs = (ht_idx << 160) | (3 << 128) | (12 << 96)
    last_root = mask16(sha(seed + word(last_adrs) + last_secret))
    roots.append(last_root)
    t("fors[12].root", last_root[:16].hex())

    roots_adrs = (ht_idx << 160) | (4 << 128)
    fors_pk = mask16(sha(seed + word(roots_adrs) + b"".join(roots)))
    t("forsPk", fors_pk[:16].hex())

    current = fors_pk
    idx_tree = ht_idx
    sig_off = 2336
    CHAIN_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF
    KEEP_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000
    for layer in range(2):
        idx_leaf = idx_tree & 0x1FF
        idx_tree >>= 9
        wots_adrs = (layer << 224) | (idx_tree << 160) | (idx_leaf << 96)
        count_off = sig_off + 688
        count = int.from_bytes(cdload(sig, count_off)[:4], "big")
        d_full = sha(seed + word(wots_adrs) + current + word(count))
        dd = int.from_bytes(d_full, "big")
        digits = [(dd >> (3 * ii)) & 7 for ii in range(43)]
        dsum = sum(digits)
        t(f"L{layer}.wotsAdrs", word(wots_adrs).hex())
        t(f"L{layer}.count", count)
        t(f"L{layer}.wotsDigest", d_full.hex())
        t(f"L{layer}.digitSum", dsum)
        if dsum != 205:
            t(f"L{layer}.digitSum", "TARGET-SUM FAIL -> revert")
            return None

        endpoints = []
        wots_ptr = sig_off
        for i in range(43):
            digit = digits[i]
            steps = 7 - digit
            val = mask16(cdload(sig, wots_ptr + 16 * i))
            chain_base = (wots_adrs | (i << 64)) & CHAIN_MASK
            for step in range(steps):
                adrs = chain_base | ((digit + step) << 32)
                val = mask16(sha(seed + word(adrs) + val))
            endpoints.append(val)
        t(f"L{layer}.endpoint[0]", endpoints[0][:16].hex())

        pk_adrs = (layer << 224) | (idx_tree << 160) | (1 << 128) | (idx_leaf << 96)
        wots_pk = mask16(sha(seed + word(pk_adrs) + b"".join(endpoints)))
        t(f"L{layer}.wotsPk", wots_pk[:16].hex())

        auth_off = count_off + 4
        tree_adrs = (layer << 224) | (idx_tree << 160) | (2 << 128)
        m_node, m_idx = wots_pk, idx_leaf
        for h in range(9):
            sibling = mask16(cdload(sig, auth_off + 16 * h))
            parent = m_idx >> 1
            adrs = (tree_adrs & KEEP_MASK) | ((h + 1) << 32) | parent
            if m_idx & 1 == 0:
                m_node = mask16(sha(seed + word(adrs) + m_node + sibling))
            else:
                m_node = mask16(sha(seed + word(adrs) + sibling + m_node))
            m_idx = parent
        current = m_node
        t(f"L{layer}.subtreeRoot", current[:16].hex())
        sig_off = auth_off + 144

    valid = current == root
    t("finalRoot", current[:16].hex())
    t("valid", valid)
    return valid


# --- replica 2: the current Lean Spec.Signature.verify ----------------------

def make_adrs(layer, tree, atype, kp, ci, cp, ha):
    """Spec.Adrs.make — layer(4)|tree(8)|atype(4)|kp(4)|ci(4)|cp(4)|ha(4)."""
    return (layer.to_bytes(4, "big") + tree.to_bytes(8, "big") +
            atype.to_bytes(4, "big") + kp.to_bytes(4, "big") +
            ci.to_bytes(4, "big") + cp.to_bytes(4, "big") +
            ha.to_bytes(4, "big"))

def set_chain_index(adrs: bytes, idx: int) -> bytes:
    """Spec.Adrs.setChainIndex — bytes [20..24)."""
    return adrs[:20] + idx.to_bytes(4, "big") + adrs[24:]

def set_chain_pos(adrs: bytes, pos: int) -> bytes:
    """The FIXED field: bytes [24..28) (Rust chain_hash / Yul shl(32, pos))."""
    return adrs[:24] + pos.to_bytes(4, "big") + adrs[28:]

def th(seed, adrs, val32):
    return sha(seed + adrs + val32)[:16]

def th_pair(seed, adrs, l32, r32):
    return sha(seed + adrs + l32 + r32)[:16]

def th_multi(seed, adrs, vals16):
    return sha(seed + adrs + b"".join(v + b"\x00" * 16 for v in vals16))[:16]

def pad16(v16):
    return v16 + b"\x00" * 16

def lean_verify(pk_seed: bytes, pk_root: bytes, message: bytes, sig: bytes,
                fixed: bool, trace=None):
    t = trace if trace is not None else (lambda *_: None)
    seed = pk_seed  # pad16 (take 16) == the N-masked word
    # deserialise
    r16 = cdload(sig, 0)[:16]
    fors_secrets = [cdload(sig, 16 + 16 * i)[:16] for i in range(13)]
    fors_auth = [[cdload(sig, 224 + tr * 176 + 16 * h)[:16] for h in range(11)]
                 for tr in range(12)]
    layers = []
    for l in range(2):
        off = 2336 + l * 836
        chains = [cdload(sig, off + 16 * i)[:16] for i in range(43)]
        count = int.from_bytes(cdload(sig, off + 688)[:4], "big")
        auth = [cdload(sig, off + 692 + 16 * h)[:16] for h in range(9)]
        layers.append((chains, count, auth))

    # Hypertree.verify
    digest = sha(seed + pk_root + pad16(r16) + message + b"\xff" * 32)
    d_int = int.from_bytes(digest, "big")
    t("digest", digest.hex())
    indices = [(d_int >> (i * 11)) & 0x7FF for i in range(13)]
    ht_idx = (d_int >> 143) & 0x3FFFF
    t("htIdx", ht_idx)
    if indices[12] != 0:
        t("forcedZero", "VIOLATED -> false")
        return False

    # Fors.reconstructForsPk
    roots = []
    for tr in range(12):
        leaf_idx = indices[tr]
        leaf_adrs = make_adrs(0, ht_idx, 3, tr, 0, 0, leaf_idx)
        node = th(seed, leaf_adrs, pad16(fors_secrets[tr]))
        t(f"fors[{tr}].leafIdx", leaf_idx)
        t(f"fors[{tr}].leaf", node.hex())
        path_idx = leaf_idx
        for h in range(11):
            parent_idx = path_idx // 2
            adrs = make_adrs(0, ht_idx, 3, tr, 0, h + 1, parent_idx)
            sibling = fors_auth[tr][h]
            if path_idx % 2 == 0:
                node = th_pair(seed, adrs, pad16(node), pad16(sibling))
            else:
                node = th_pair(seed, adrs, pad16(sibling), pad16(node))
            path_idx = parent_idx
        roots.append(node)
        t(f"fors[{tr}].root", node.hex())
    last_adrs = make_adrs(0, ht_idx, 3, 12, 0, 0, 0)
    last_root = th(seed, last_adrs, pad16(fors_secrets[12]))
    roots.append(last_root)
    t("fors[12].root", last_root.hex())
    fors_pk = th_multi(seed, make_adrs(0, ht_idx, 4, 0, 0, 0, 0), roots)
    t("forsPk", fors_pk.hex())

    # verifyHypertree
    current = fors_pk
    idx_tree = ht_idx
    for layer in range(2):
        idx_leaf = idx_tree & 0x1FF
        idx_tree >>= 9
        chains, count, auth = layers[layer]
        # Wots.pkFromSig
        wots_adrs = make_adrs(layer, idx_tree, 0, idx_leaf, 0, 0, 0)
        d_full = sha(seed + wots_adrs + pad16(current) + word(count))
        dd = int.from_bytes(d_full, "big")
        digits = [(dd >> (3 * i)) & 7 for i in range(43)]
        dsum = sum(digits)
        t(f"L{layer}.wotsAdrs", wots_adrs.hex())
        t(f"L{layer}.count", count)
        t(f"L{layer}.wotsDigest", d_full.hex())
        t(f"L{layer}.digitSum", dsum)
        if dsum != 205:
            t(f"L{layer}.digitSum", "TARGET-SUM FAIL -> none -> false")
            return False
        endpoints = []
        for i in range(43):
            chain_adrs = set_chain_index(wots_adrs, i)
            digit = digits[i]
            val = chains[i]
            for step in range(7 - digit):
                pos = digit + step
                if fixed:
                    a = set_chain_pos(chain_adrs, pos)   # PROPOSED FIX
                else:
                    a = set_chain_index(chain_adrs, pos)  # CURRENT Lean bug
                val = th(seed, a, pad16(val))
            endpoints.append(val)
        t(f"L{layer}.endpoint[0]", endpoints[0].hex())
        pk_adrs = make_adrs(layer, idx_tree, 1, idx_leaf, 0, 0, 0)
        wots_pk = th_multi(seed, pk_adrs, endpoints)
        t(f"L{layer}.wotsPk", wots_pk.hex())
        # verifyAuthPath
        node, idx = wots_pk, idx_leaf
        for h in range(9):
            parent_idx = idx // 2
            adrs = make_adrs(layer, idx_tree, 2, 0, 0, h + 1, parent_idx)
            sibling = auth[h]
            if idx % 2 == 0:
                node = th_pair(seed, adrs, pad16(node), pad16(sibling))
            else:
                node = th_pair(seed, adrs, pad16(sibling), pad16(node))
            idx = parent_idx
        current = node
        t(f"L{layer}.subtreeRoot", current.hex())

    valid = pad16(current) == pk_root
    t("finalRoot", current.hex())
    t("valid", valid)
    return valid


# --- driver -----------------------------------------------------------------

def main():
    fixed = "--lean-fixed" in sys.argv
    data = json.load(open(JSON))
    vectors = data["vectors"]
    print(f"=== GAP-1 differential: Yul replica vs Lean replica"
          f" ({'FIXED' if fixed else 'current'}) ===\n")
    yul_ok = lean_ok = 0
    first_div_shown = False
    for v in vectors:
        pk_seed = hx(v["pkSeed"])
        pk_root = hx(v["pkRoot"])
        msg = hx(v["message"])
        sig = hx(v["signature"])
        expect = bool(v["expectValid"])

        ytrace, ltrace = [], []
        y = yul_verify(pk_seed, pk_root, msg, sig,
                       lambda k, val: ytrace.append((k, str(val))))
        l = lean_verify(pk_seed, pk_root, msg, sig, fixed,
                        lambda k, val: ltrace.append((k, str(val))))
        y_valid = (y is True)
        y_match = (y_valid == expect)
        l_match = (l == expect)
        yul_ok += y_match
        lean_ok += l_match
        print(f"{v['label']:<36} yul={'OK ' if y_match else 'FAIL'}"
              f"  lean={'OK ' if l_match else 'FAIL'}")

        if not l_match and not first_div_shown:
            first_div_shown = True
            print(f"\n  --- first diverging intermediates ({v['label']}) ---")
            ld = dict(ltrace)
            shown = 0
            for k, yval in ytrace:
                lval = ld.get(k)
                # normalise 16-byte-hex vs 32-hex-char comparisons
                if lval is not None and lval != yval:
                    print(f"  {k}:")
                    print(f"    yul : {yval}")
                    print(f"    lean: {lval}")
                    shown += 1
                    if shown >= 6:
                        break
            if shown == 0:
                print("  (no traced intermediate diverges — final compare only)")
            print()

    print(f"\nyul replica  : {yul_ok}/10 match expectValid"
          f"  (must be 10/10 — it IS the bytecode function on this corpus)")
    print(f"lean replica : {lean_ok}/10 match expectValid")
    return 0 if yul_ok == 10 else 1


if __name__ == "__main__":
    sys.exit(main())
