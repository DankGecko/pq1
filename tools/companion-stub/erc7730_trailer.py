#!/usr/bin/env python3
"""Companion-stub: build an ERC-7730 sign-input trailer from a
catalog blob (`tools/companion-stub/erc7730_db.bin`).

Usage:

    python3 tools/companion-stub/erc7730_trailer.py \\
        --db tools/companion-stub/erc7730_db.bin \\
        --chain 1 \\
        --contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 \\
        --out /tmp/usdt_mainnet_trailer.bin

For EIP-712, select the exact context and complete primary type hash. The
catalog entry's `primary_type_hash` is only a sorting/diagnostic hint (one IR
can contain several formats), so lookup parses the authenticated IR format
table and compares all 32 bytes:

    python3 tools/companion-stub/erc7730_trailer.py \\
        --db tools/companion-stub/erc7730_db.bin \\
        --chain 1 \\
        --contract 0x8236a87084f8b84306f72007f36f2618a5634494 \\
        --context eip712 \\
        --domain-separator \\
          0x2c437c69596d3cb0d046c1b65cd31dee6005447683107eb67b1cf385d850284f \\
        --primary-type-hash \\
          0x40ac9f6aa27075e64c1ed1ea2e831b20b8c25efdeb6b79fd0cf683c9a9c50725 \\
        --out /tmp/lbtc_network_fee_authorization.bin

Writes the byte-for-byte payload the secure-world dispatcher expects
inside the `[u16 BE len][payload]` trailer envelope on
`CMD_SIGN_USEROP` / `CMD_SIGN_USEROP_BATCH` / `CMD_SIGN_OFFCHAIN`.

The output buffer is the *inner* bundle (no length prefix). The
caller wraps it as `len.to_bytes(2, 'big') + payload` when splicing
into a sign-input wire payload.

Wire layout produced (matches `pqsigner_erc7730::bundle`):

    ir_len(2 BE) || ir || leaf_index(4 BE) || proof_depth(4 BE) || proof

Catalog blob layout (header is little-endian; entry array is sorted
by `(chain_id, contract, primary_type_hash, context_kind)` so binary
search works):

    "P730" || ver_le(4) || flags_le(4) || entry_cnt_le(4) ||
    ir_pool_off_le(4) || ir_pool_size_le(4) || proof_depth_le(4) ||
    proofs_off_le(4)
    [entries: each 72 B = chain_id_le(8) | contract(20) |
     primary_type_hash(32) | ctx_kind(1) | pad(3) | ir_off_le(4) |
     ir_len_le(4)]
    [ir_pool: concatenated IRs]
    [proofs: entry_cnt × proof_depth × 32 bytes]

Contract lookup defaults to exact `(context=Contract, chain_id, contract)` for
backward compatibility and rejects ambiguity. EIP-712 lookup additionally
requires the exact `--domain-separator` and `--primary-type-hash`; it validates
every IR's lookup-relevant header, layout, and complete format table, then
matches both authenticated values. Zero or multiple matches are errors. The
firmware remains authoritative for rendering-policy semantics after Merkle
verification.

Pure Python 3, no third-party deps — runs on any host the dev test
loop can already reach.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


HEADER_MAGIC = b"P730"
HEADER_LEN = 32
ENTRY_LEN = 72
IR_HEADER_LEN = 134
IR_SCHEMA_VERSION = 3
IR_MAX_LEN = 4096
IR_MAX_FORMATS = 32
IR_MAX_FIELDS = 24
CTX_CONTRACT = 1
CTX_EIP712 = 2


def _parse_address(s: str) -> bytes:
    s = s.lower().strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 40:
        raise ValueError(f"bad address (expected 40 hex chars): {s!r}")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"bad address hex: {s!r}") from exc


def _parse_hash32(s: str) -> bytes:
    original = s
    s = s.lower().strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64:
        raise argparse.ArgumentTypeError(
            f"bad 32-byte hash (expected 64 hex chars): {original!r}"
        )
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"bad 32-byte hash hex: {original!r}"
        ) from exc


def _slice(blob: bytes, start: int, length: int, label: str) -> bytes:
    end = start + length
    if start < 0 or length < 0 or end < start or end > len(blob):
        raise ValueError(
            f"truncated catalog: {label} [{start}:{end}] exceeds {len(blob)} bytes"
        )
    return bytes(blob[start:end])


def _read_header(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ValueError(f"catalog too short: {len(blob)} < {HEADER_LEN}")
    if blob[:4] != HEADER_MAGIC:
        raise ValueError(f"bad magic: {blob[:4]!r} != {HEADER_MAGIC!r}")
    (version,) = struct.unpack_from("<I", blob, 4)
    (flags,) = struct.unpack_from("<I", blob, 8)
    (entry_cnt,) = struct.unpack_from("<I", blob, 12)
    (ir_pool_off,) = struct.unpack_from("<I", blob, 16)
    (ir_pool_size,) = struct.unpack_from("<I", blob, 20)
    (proof_depth,) = struct.unpack_from("<I", blob, 24)
    (proofs_off,) = struct.unpack_from("<I", blob, 28)
    if version != 1:
        raise ValueError(f"unknown catalog version: {version}")
    if flags != 0:
        raise ValueError(f"unsupported catalog flags: 0x{flags:08x}")
    if entry_cnt == 0:
        raise ValueError("catalog contains no entries")
    entries_end = HEADER_LEN + entry_cnt * ENTRY_LEN
    if entries_end > len(blob):
        raise ValueError(
            f"entry table exceeds catalog: {entries_end} > {len(blob)}"
        )
    if ir_pool_off != entries_end:
        raise ValueError(
            f"non-canonical IR pool offset: {ir_pool_off} != {entries_end}"
        )
    ir_pool_end = ir_pool_off + ir_pool_size
    if ir_pool_end < ir_pool_off or ir_pool_end > len(blob):
        raise ValueError("IR pool exceeds catalog bounds")
    if proofs_off != ir_pool_end:
        raise ValueError(
            f"non-canonical proofs offset: {proofs_off} != {ir_pool_end}"
        )
    if proof_depth > 32:
        raise ValueError(f"proof depth exceeds firmware cap: {proof_depth} > 32")
    expected_end = proofs_off + entry_cnt * proof_depth * 32
    if expected_end != len(blob):
        raise ValueError(
            f"catalog proof region/trailing bytes mismatch: {expected_end} != {len(blob)}"
        )
    return {
        "version": version,
        "flags": flags,
        "entry_cnt": entry_cnt,
        "ir_pool_off": ir_pool_off,
        "ir_pool_size": ir_pool_size,
        "proof_depth": proof_depth,
        "proofs_off": proofs_off,
    }


def _entry(blob: bytes, i: int) -> dict:
    """Decode entry `i` from the catalog."""
    hdr = _read_header(blob)
    if i < 0 or i >= hdr["entry_cnt"]:
        raise ValueError(f"catalog entry index out of range: {i}")
    base = HEADER_LEN + i * ENTRY_LEN
    _slice(blob, base, ENTRY_LEN, f"entry {i}")
    (chain_id,) = struct.unpack_from("<Q", blob, base)
    contract = bytes(blob[base + 8 : base + 28])
    primary_type_hash = bytes(blob[base + 28 : base + 60])
    ctx_kind = blob[base + 60]
    if ctx_kind not in (CTX_CONTRACT, CTX_EIP712):
        raise ValueError(f"entry {i}: bad context kind {ctx_kind}")
    if blob[base + 61 : base + 64] != b"\x00\x00\x00":
        raise ValueError(f"entry {i}: non-zero reserved padding")
    (ir_off,) = struct.unpack_from("<I", blob, base + 64)
    (ir_len,) = struct.unpack_from("<I", blob, base + 68)
    if ir_len == 0 or ir_len > IR_MAX_LEN:
        raise ValueError(f"entry {i}: invalid IR length {ir_len}")
    if ir_off + ir_len < ir_off or ir_off + ir_len > hdr["ir_pool_size"]:
        raise ValueError(f"entry {i}: IR slice exceeds the declared IR pool")
    return {
        "leaf_index": i,
        "chain_id": chain_id,
        "contract": contract,
        "primary_type_hash": primary_type_hash,
        "ctx_kind": ctx_kind,
        "ir_off": ir_off,
        "ir_len": ir_len,
    }


def _parse_ir(ir: bytes) -> dict:
    """Parse and validate the complete authenticated IR format table."""
    if len(ir) < IR_HEADER_LEN or len(ir) > IR_MAX_LEN:
        raise ValueError(f"IR length outside [{IR_HEADER_LEN}, {IR_MAX_LEN}]: {len(ir)}")
    if ir[0] != IR_SCHEMA_VERSION:
        raise ValueError(f"unsupported IR schema version: {ir[0]}")
    context_kind = ir[1]
    if context_kind not in (CTX_CONTRACT, CTX_EIP712):
        raise ValueError(f"bad IR context kind: {context_kind}")
    chain_id = int.from_bytes(ir[2:10], "big")
    contract = bytes(ir[10:30])
    domain_separator = bytes(ir[62:94])
    if context_kind == CTX_CONTRACT and any(domain_separator):
        raise ValueError("contract-context IR carries a non-zero domain separator")

    metadata_off = int.from_bytes(ir[126:128], "big")
    formats_off = int.from_bytes(ir[128:130], "big")
    pool_len = int.from_bytes(ir[130:132], "big")
    formats_len = int.from_bytes(ir[132:134], "big")
    if metadata_off != IR_HEADER_LEN:
        raise ValueError(f"bad IR metadata offset: {metadata_off}")
    if formats_off != metadata_off + pool_len:
        raise ValueError("IR metadata and format regions overlap or have a gap")
    if formats_off + formats_len != len(ir):
        raise ValueError("IR format region does not consume the complete IR")
    pool = bytes(ir[metadata_off:formats_off])
    formats = bytes(ir[formats_off:])
    if not formats:
        return {
            "context_kind": context_kind,
            "chain_id": chain_id,
            "contract": contract,
            "domain_separator": domain_separator,
            "type_hashes": (),
        }

    count = formats[0]
    if count > IR_MAX_FORMATS:
        raise ValueError(f"IR format count exceeds cap: {count}")
    cursor = 1
    selectors: set[bytes] = set()
    type_hashes: list[bytes] = []
    for format_index in range(count):
        if cursor + 9 > len(formats):
            raise ValueError(f"IR format {format_index} header is truncated")
        selector = bytes(formats[cursor : cursor + 4])
        field_count = formats[cursor + 4]
        intent_len = formats[cursor + 5]
        if field_count > IR_MAX_FIELDS:
            raise ValueError(f"IR format {format_index} field count exceeds cap")
        cursor += 9  # selector, counts, static-head words, nested-descent count
        if cursor + intent_len > len(formats):
            raise ValueError(f"IR format {format_index} intent is truncated")
        intent = formats[cursor : cursor + intent_len]
        if any(b < 0x20 or b >= 0x7F for b in intent):
            raise ValueError(f"IR format {format_index} intent is not printable ASCII")
        cursor += intent_len

        if selector in selectors:
            raise ValueError(f"IR format {format_index} duplicates selector 0x{selector.hex()}")
        selectors.add(selector)
        if context_kind == CTX_EIP712:
            if cursor + 32 > len(formats):
                raise ValueError(f"IR format {format_index} type hash is truncated")
            type_hash = bytes(formats[cursor : cursor + 32])
            cursor += 32
            if selector != type_hash[:4]:
                raise ValueError(f"IR format {format_index} selector/type-hash mismatch")
            type_hashes.append(type_hash)

        for field_index in range(field_count):
            if cursor + 2 > len(formats):
                raise ValueError(
                    f"IR format {format_index} field {field_index} header is truncated"
                )
            format_op = formats[cursor]
            label_len = formats[cursor + 1]
            if not 0x01 <= format_op <= 0x0E:
                raise ValueError(
                    f"IR format {format_index} field {field_index} has bad format opcode"
                )
            cursor += 2
            if cursor + label_len + 4 > len(formats):
                raise ValueError(
                    f"IR format {format_index} field {field_index} is truncated"
                )
            label = formats[cursor : cursor + label_len]
            if any(b < 0x20 or b >= 0x7F for b in label):
                raise ValueError(
                    f"IR format {format_index} field {field_index} label is not printable ASCII"
                )
            cursor += label_len
            path_off = int.from_bytes(formats[cursor : cursor + 2], "big")
            param_off = int.from_bytes(formats[cursor + 2 : cursor + 4], "big")
            cursor += 4
            for offset, label_name in ((path_off, "path"), (param_off, "parameter")):
                if offset:
                    if offset >= len(pool):
                        raise ValueError(f"IR {label_name} offset is outside the pool")
                    payload_len = pool[offset]
                    if offset + 1 + payload_len > len(pool):
                        raise ValueError(f"IR {label_name} pool entry is truncated")

    if cursor != len(formats):
        raise ValueError(f"IR format table has {len(formats) - cursor} trailing bytes")
    return {
        "context_kind": context_kind,
        "chain_id": chain_id,
        "contract": contract,
        "domain_separator": domain_separator,
        "type_hashes": tuple(type_hashes),
    }


def _parsed_entry(blob: bytes, hdr: dict, i: int) -> tuple[dict, bytes, dict]:
    entry = _entry(blob, i)
    ir_start = hdr["ir_pool_off"] + entry["ir_off"]
    ir = _slice(blob, ir_start, entry["ir_len"], f"IR for leaf {i}")
    parsed = _parse_ir(ir)
    # These index fields are lookup accelerators only; the IR is the Merkle-
    # authenticated source of truth. A mismatch is malformed catalog data.
    if (
        entry["chain_id"] != parsed["chain_id"]
        or entry["contract"] != parsed["contract"]
        or entry["ctx_kind"] != parsed["context_kind"]
    ):
        raise ValueError(f"entry {i}: catalog index disagrees with authenticated IR")
    return entry, ir, parsed


def _select_entry(
    blob: bytes,
    hdr: dict,
    chain_id: int,
    contract: bytes,
    context: str,
    domain_separator: bytes | None,
    primary_type_hash: bytes | None,
) -> tuple[int, dict, bytes]:
    context_kind = {"contract": CTX_CONTRACT, "eip712": CTX_EIP712}[context]
    if context_kind == CTX_EIP712:
        if domain_separator is None:
            raise ValueError("--domain-separator is required for --context eip712")
        if primary_type_hash is None:
            raise ValueError("--primary-type-hash is required for --context eip712")
    elif domain_separator is not None or primary_type_hash is not None:
        raise ValueError(
            "--domain-separator and --primary-type-hash are only valid for --context eip712"
        )

    matches: list[tuple[int, dict, bytes]] = []
    for i in range(hdr["entry_cnt"]):
        entry, ir, parsed = _parsed_entry(blob, hdr, i)
        if (
            parsed["context_kind"] != context_kind
            or parsed["chain_id"] != chain_id
            or parsed["contract"] != contract
        ):
            continue
        if context_kind == CTX_EIP712:
            if parsed["domain_separator"] != domain_separator:
                continue
            if primary_type_hash not in parsed["type_hashes"]:
                continue
        matches.append((i, entry, ir))

    label = (
        f"EIP-712 descriptor for chain={chain_id} contract=0x{contract.hex()} "
        f"domainSeparator=0x{domain_separator.hex()} typeHash=0x{primary_type_hash.hex()}"
        if primary_type_hash is not None
        else f"contract descriptor for chain={chain_id} contract=0x{contract.hex()}"
    )
    if not matches:
        raise ValueError(f"no {label}")
    if len(matches) != 1:
        leaves = ", ".join(str(match[0]) for match in matches)
        raise ValueError(f"ambiguous {label}: matching leaves {leaves}")
    return matches[0]


def build_trailer(
    blob: bytes,
    chain_id: int,
    contract: bytes,
    *,
    context: str = "contract",
    domain_separator: bytes | None = None,
    primary_type_hash: bytes | None = None,
) -> bytes:
    """Produce one exact contract- or EIP-712-context trailer payload."""
    hdr = _read_header(blob)
    if context not in ("contract", "eip712"):
        raise ValueError(f"unknown lookup context: {context!r}")
    if primary_type_hash is not None and len(primary_type_hash) != 32:
        raise ValueError("primary_type_hash must be exactly 32 bytes")
    if domain_separator is not None and len(domain_separator) != 32:
        raise ValueError("domain_separator must be exactly 32 bytes")
    idx, entry, ir_bytes = _select_entry(
        blob,
        hdr,
        chain_id,
        contract,
        context,
        domain_separator,
        primary_type_hash,
    )
    proof_depth = hdr["proof_depth"]

    proof_base = hdr["proofs_off"] + idx * proof_depth * 32
    proof_bytes = _slice(blob, proof_base, proof_depth * 32, f"proof for leaf {idx}")

    out = bytearray()
    out += struct.pack(">H", len(ir_bytes))
    out += ir_bytes
    out += struct.pack(">I", idx)
    out += struct.pack(">I", proof_depth)
    out += proof_bytes
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--db",
        default="tools/companion-stub/erc7730_db.bin",
        help="path to the ERC-7730 catalog blob",
    )
    ap.add_argument("--chain", type=int, help="EIP-155 chain id")
    ap.add_argument("--contract", help="0x-prefixed contract address")
    ap.add_argument(
        "--context",
        choices=("contract", "eip712"),
        default="contract",
        help="exact descriptor context (default: contract)",
    )
    ap.add_argument(
        "--domain-separator",
        type=_parse_hash32,
        help="exact 32-byte EIP-712 domain separator; required for --context eip712",
    )
    ap.add_argument(
        "--primary-type-hash",
        type=_parse_hash32,
        help="full 32-byte hash; required for --context eip712",
    )
    ap.add_argument(
        "--out",
        help="optional output file; default stdout (binary)",
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="instead of emitting, print the (chain, contract) pairs in the catalog",
    )
    args = ap.parse_args()

    blob = Path(args.db).read_bytes()

    if args.list:
        hdr = _read_header(blob)
        print(
            f"# {hdr['entry_cnt']} entries, "
            f"proof_depth={hdr['proof_depth']}, "
            f"ir_pool={hdr['ir_pool_size']} B"
        )
        for i in range(hdr["entry_cnt"]):
            e, _ir, parsed = _parsed_entry(blob, hdr, i)
            ctx = {CTX_CONTRACT: "Contract", CTX_EIP712: "EIP712"}[
                parsed["context_kind"]
            ]
            hashes = ",".join(f"0x{h.hex()}" for h in parsed["type_hashes"])
            print(
                f"  [{i:3d}] chain={e['chain_id']:>5} "
                f"contract=0x{e['contract'].hex()} "
                f"ctx={ctx} ir_len={e['ir_len']}"
                + (
                    f" domain_separator=0x{parsed['domain_separator'].hex()}"
                    if parsed["context_kind"] == CTX_EIP712
                    else ""
                )
                + (f" type_hashes={hashes}" if hashes else "")
            )
        return 0

    if args.chain is None or args.contract is None:
        ap.error("--chain and --contract are required unless --list is given")
    contract = _parse_address(args.contract)
    try:
        trailer = build_trailer(
            blob,
            args.chain,
            contract,
            context=args.context,
            domain_separator=args.domain_separator,
            primary_type_hash=args.primary_type_hash,
        )
    except ValueError as exc:
        ap.error(str(exc))

    if args.out:
        Path(args.out).write_bytes(trailer)
        print(
            f"wrote {len(trailer)} B trailer (chain={args.chain} "
            f"contract=0x{contract.hex()} context={args.context}) to {args.out}",
            file=sys.stderr,
        )
    else:
        sys.stdout.buffer.write(trailer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
