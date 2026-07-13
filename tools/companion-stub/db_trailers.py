#!/usr/bin/env python3
"""Companion-stub: build ERC-20 / address-name sign-input
bundles from the host-side DB blobs.

These DBs used to be baked into the firmware (`include_bytes!`'d
into the non-secure image). They now live entirely host-side, under
`tools/companion-stub/{erc20,names}_db.bin`, exactly like the
selectors and ERC-7730 DBs. The device ships only the 32-byte Merkle
roots (`ERC20_DB_ROOT` / `NAMES_DB_ROOT` in
`secure/src/db_roots.rs`) and Merkle-verifies every companion-supplied
bundle against them in the secure world before any byte reaches the
trusted UI.

This module is the reference implementation a real companion app
follows. It mirrors the firmware's `nonsecure/src/{erc20,names}_db.rs`
`build_bundle` functions byte-for-byte — the dbgen round-trip test
`companion_stub_*_verifies_against_on_device` feeds this script's output
back through the on-device verifier, so the two stay locked together.

A malicious companion cannot forge a bundle (the Merkle proof would
fail against the pinned root); withholding one only degrades the render
to a fail-safe (unknown token / raw-hex address / blind-sign).

Usage:

    # ERC-20 metadata trailer for (chain, token):
    python3 tools/companion-stub/db_trailers.py erc20 \\
        --chain 8453 --contract 0x09bE1692ca16e06f536F0038fF11D1dA8524aDB1

    # Address-name trailer (chain 0 = wildcard fallback handled internally):
    python3 tools/companion-stub/db_trailers.py names \\
        --chain 1 --contract 0xE592427A0AEce92De3Edee1F18E0157C05861564

    # List the entries in a blob:
    python3 tools/companion-stub/db_trailers.py erc20 --list

The script writes the *inner* bundle bytes (no length prefix) to stdout
(or --out). The caller wraps it as `len.to_bytes(2, 'big') + bundle`
when splicing into the positional trailer skeleton of a CMD_SIGN_USEROP
payload (ERC-20 is slot 1; names is the trailing count-prefixed slot —
see `nonsecure/src/usb/commands.rs::ensure_trailer_skeleton`).

All multi-byte integers in the blobs AND in the emitted bundles are
little-endian (matching `sphincs_tz_shared::db_format`), EXCEPT the
outer trailer length prefix the caller adds, which is big-endian.

Pure Python 3, stdlib only (hashlib for the names short-key).
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

# ── Shared constants (mirror sphincs_tz_shared::db_format) ─────────────
HEADER_LEN = 32  # identical for all three DBs

ERC20_MAGIC = b"ERC2"
ERC20_ENTRY_LEN = 40
ERC20_ENTRY_OFF_CHAIN_ID = 0
ERC20_ENTRY_OFF_CONTRACT = 8
ERC20_ENTRY_OFF_NAME_OFF = 28
ERC20_ENTRY_OFF_SYMBOL_OFF = 32
ERC20_ENTRY_OFF_DECIMALS = 36

NAMES_MAGIC = b"NAMS"
NAMES_ENTRY_LEN = 20
NAMES_ENTRY_OFF_SHORT_KEY = 0
NAMES_ENTRY_OFF_NAME_OFF = 16
NAMES_SHORT_KEY_TAG = b"pqsigner-name-key-v1"
NAMES_WILDCARD_CHAIN_ID = 0


def _parse_address(s: str) -> bytes:
    s = s.lower().strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 40:
        raise ValueError(f"bad address (expected 40 hex chars): {s!r}")
    return bytes.fromhex(s)


def _header(blob: bytes, magic: bytes, pool_off_at: int = 16) -> dict:
    """Parse the common 32-byte header. The pool-offset field is at
    offset 16 for the ERC-20 / Names DBs (`pool_off`). proof_depth (24)
    and proofs_off (28) are identical across the DBs."""
    if len(blob) < HEADER_LEN:
        raise ValueError(f"blob too short: {len(blob)} < {HEADER_LEN}")
    if blob[:4] != magic:
        raise ValueError(f"bad magic: {blob[:4]!r} != {magic!r}")
    (version,) = struct.unpack_from("<I", blob, 4)
    if version != 1:
        raise ValueError(f"unknown db version: {version}")
    (entry_cnt,) = struct.unpack_from("<I", blob, 12)
    (pool_off,) = struct.unpack_from("<I", blob, pool_off_at)
    (proof_depth,) = struct.unpack_from("<I", blob, 24)
    (proofs_off,) = struct.unpack_from("<I", blob, 28)
    return {
        "entry_cnt": entry_cnt,
        "pool_off": pool_off,
        "proof_depth": proof_depth,
        "proofs_off": proofs_off,
    }


def _read_pool_string(blob: bytes, at: int) -> bytes:
    n = blob[at]
    return bytes(blob[at + 1 : at + 1 + n])


def _proof(blob: bytes, hdr: dict, idx: int) -> bytes:
    depth = hdr["proof_depth"]
    base = hdr["proofs_off"] + idx * depth * 32
    p = bytes(blob[base : base + depth * 32])
    if len(p) != depth * 32:
        raise SystemExit(f"truncated blob: proof for leaf {idx}")
    return p


# ── ERC-20 ─────────────────────────────────────────────────────────────
def build_erc20_bundle(blob: bytes, chain_id: int, contract: bytes) -> bytes:
    hdr = _header(blob, ERC20_MAGIC)
    idx = None
    for i in range(hdr["entry_cnt"]):
        base = HEADER_LEN + i * ERC20_ENTRY_LEN
        (e_chain,) = struct.unpack_from("<Q", blob, base + ERC20_ENTRY_OFF_CHAIN_ID)
        e_contract = bytes(
            blob[base + ERC20_ENTRY_OFF_CONTRACT : base + ERC20_ENTRY_OFF_CONTRACT + 20]
        )
        if e_chain == chain_id and e_contract == contract:
            idx = i
            break
    if idx is None:
        raise SystemExit(f"no ERC-20 entry for chain={chain_id} contract=0x{contract.hex()}")

    base = HEADER_LEN + idx * ERC20_ENTRY_LEN
    (name_off,) = struct.unpack_from("<I", blob, base + ERC20_ENTRY_OFF_NAME_OFF)
    (symbol_off,) = struct.unpack_from("<I", blob, base + ERC20_ENTRY_OFF_SYMBOL_OFF)
    decimals = blob[base + ERC20_ENTRY_OFF_DECIMALS]
    name = _read_pool_string(blob, hdr["pool_off"] + name_off)
    symbol = _read_pool_string(blob, hdr["pool_off"] + symbol_off)

    out = bytearray()
    out += struct.pack("<Q", chain_id)
    out += contract
    out += bytes([decimals])
    out += bytes([len(name)]) + name
    out += bytes([len(symbol)]) + symbol
    out += struct.pack("<I", idx)
    out += struct.pack("<I", hdr["proof_depth"])
    out += _proof(blob, hdr, idx)
    return bytes(out)


# ── Names ────────────────────────────────────────────────────────────────
def _short_key(chain_id: int, address: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(NAMES_SHORT_KEY_TAG)
    h.update(struct.pack(">Q", chain_id))
    h.update(address)
    return h.digest()[:16]


def _names_find(blob: bytes, hdr: dict, key: bytes) -> int | None:
    for i in range(hdr["entry_cnt"]):
        base = HEADER_LEN + i * NAMES_ENTRY_LEN
        if bytes(blob[base : base + 16]) == key:
            return i
    return None


def build_names_bundle(blob: bytes, chain_id: int, address: bytes) -> bytes:
    hdr = _header(blob, NAMES_MAGIC)
    # Two-phase: exact (chain_id, addr) first, then wildcard (0, addr).
    idx = _names_find(blob, hdr, _short_key(chain_id, address))
    hit_chain = chain_id
    if idx is None and chain_id != NAMES_WILDCARD_CHAIN_ID:
        idx = _names_find(blob, hdr, _short_key(NAMES_WILDCARD_CHAIN_ID, address))
        hit_chain = NAMES_WILDCARD_CHAIN_ID
    if idx is None:
        raise SystemExit(f"no name for chain={chain_id} address=0x{address.hex()}")

    base = HEADER_LEN + idx * NAMES_ENTRY_LEN
    (name_off,) = struct.unpack_from("<I", blob, base + NAMES_ENTRY_OFF_NAME_OFF)
    name = _read_pool_string(blob, hdr["pool_off"] + name_off)

    out = bytearray()
    out += struct.pack("<Q", hit_chain)
    out += address
    out += bytes([len(name)]) + name
    out += struct.pack("<I", idx)
    out += struct.pack("<I", hdr["proof_depth"])
    out += _proof(blob, hdr, idx)
    return bytes(out)


_KINDS = {
    "erc20": (ERC20_MAGIC, ERC20_ENTRY_LEN, build_erc20_bundle, "erc20_db.bin"),
    "names": (NAMES_MAGIC, NAMES_ENTRY_LEN, build_names_bundle, "names_db.bin"),
}


def _list(kind: str, blob: bytes) -> None:
    magic, entry_len, _, _ = _KINDS[kind]
    hdr = _header(blob, magic)
    print(f"# {kind}: {hdr['entry_cnt']} entries, proof_depth={hdr['proof_depth']}")
    for i in range(hdr["entry_cnt"]):
        base = HEADER_LEN + i * entry_len
        if kind == "names":
            print(f"  [{i:4d}] short_key=0x{bytes(blob[base:base+16]).hex()}")
        else:
            (chain,) = struct.unpack_from("<Q", blob, base)
            contract = bytes(blob[base + 8 : base + 28]).hex()
            print(f"  [{i:4d}] chain={chain:>6} contract=0x{contract}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("kind", choices=sorted(_KINDS), help="which DB to query")
    ap.add_argument("--db", help="blob path (default tools/companion-stub/<kind>_db.bin)")
    ap.add_argument("--chain", type=int, help="EIP-155 chain id")
    ap.add_argument("--contract", help="0x-prefixed contract / token / address")
    ap.add_argument("--out", help="output file; default stdout (binary)")
    ap.add_argument("--list", action="store_true", help="list entries instead of emitting")
    args = ap.parse_args()

    _, _, builder, default_name = _KINDS[args.kind]
    db_path = args.db or f"tools/companion-stub/{default_name}"
    blob = Path(db_path).read_bytes()

    if args.list:
        _list(args.kind, blob)
        return 0

    if args.chain is None or args.contract is None:
        ap.error("--chain and --contract are required unless --list is given")
    contract = _parse_address(args.contract)
    bundle = builder(blob, args.chain, contract)

    if args.out:
        Path(args.out).write_bytes(bundle)
        print(
            f"wrote {len(bundle)} B {args.kind} bundle "
            f"(chain={args.chain} contract=0x{contract.hex()}) to {args.out}",
            file=sys.stderr,
        )
    else:
        sys.stdout.buffer.write(bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
