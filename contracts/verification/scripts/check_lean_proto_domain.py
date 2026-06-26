#!/usr/bin/env python3
"""P7 CI gate: assert the Lean factory add-slot domain tag is byte-identical to
the canonical `proto::FACTORY_ADD_SLOT_DOMAIN`.

The squat-defence proof (invariant #6) binds `Factory.addSlot0Digest` to the
device/Solidity digest only if the Lean domain constant matches the one the
device actually signs. proto<->Solidity is already gated (proto/tests +
xtask gen-solidity-constants); the missing link this closes is Lean<->proto.
A future Lean-only mutation of `factoryAddSlotDomain` now fails CI instead of
silently re-introducing the P7 domain drift.

Parses both literals from source (no build) and compares the bytes.

Usage: check_lean_proto_domain.py [<repo-root>]
Exit 0 = bytes match. Exit 1 = mismatch or parse failure.
"""
import os
import re
import sys


def parse_proto(path: str) -> bytes:
    txt = open(path, "r", encoding="utf-8").read()
    # pub const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";
    m = re.search(r'FACTORY_ADD_SLOT_DOMAIN\s*:\s*&\[u8\]\s*=\s*b"([^"]*)"', txt)
    if not m:
        print(f"FAIL: could not find FACTORY_ADD_SLOT_DOMAIN byte-string in {path}", file=sys.stderr)
        sys.exit(1)
    return m.group(1).encode("latin-1")


def parse_lean(path: str) -> bytes:
    txt = open(path, "r", encoding="utf-8").read()
    # def factoryAddSlotDomain : ByteVec N := ⟨#[0x.., 0x.., ...], by decide⟩
    m = re.search(r'def\s+factoryAddSlotDomain\b.*?:=\s*⟨\s*#\[([^\]]*)\]', txt, re.DOTALL)
    if not m:
        print(f"FAIL: could not find factoryAddSlotDomain byte array in {path}", file=sys.stderr)
        sys.exit(1)
    body = m.group(1)
    nums = re.findall(r'0x[0-9a-fA-F]+|\d+', body)
    return bytes(int(n, 0) for n in nums)


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..")
    )
    proto_path = os.path.join(root, "proto", "src", "lib.rs")
    lean_path = os.path.join(
        root, "contracts", "verification", "lean",
        "SphincsCVerify", "Wallet", "Factory.lean",
    )
    proto_bytes = parse_proto(proto_path)
    lean_bytes = parse_lean(lean_path)

    if proto_bytes != lean_bytes:
        print("FAIL: Lean factoryAddSlotDomain != proto FACTORY_ADD_SLOT_DOMAIN (P7 domain drift)", file=sys.stderr)
        print(f"  proto ({len(proto_bytes)} B): {proto_bytes!r}", file=sys.stderr)
        print(f"  lean  ({len(lean_bytes)} B): {lean_bytes!r}", file=sys.stderr)
        return 1

    print(f"OK: Lean factoryAddSlotDomain == proto FACTORY_ADD_SLOT_DOMAIN "
          f"({len(proto_bytes)} B: {proto_bytes.decode('latin-1')!r}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
