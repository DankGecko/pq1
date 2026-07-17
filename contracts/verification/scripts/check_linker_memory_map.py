#!/usr/bin/env python3
"""P1.9 CI gate: bind the TrustZone memory-map region literals across ALL three
source-of-truth families to each other and to the Lean model, closing a confirmed
UNGUARDED drift.

Today the region numbers are triplicated by hand with NO cross-family gate:
  * `nonsecure/memory-stm32u585.x` + `secure/memory-stm32u585.x` (linker MEMORY),
  * `proto/src/lib.rs` (NS-pointer-validation windows + mailbox),
  * `secure/src/sau.rs` (SAU NS regions).
Editing a `.x` MEMORY number without updating `proto`/`sau.rs` silently overlaps
secure data into an SAU-NS region (a window-"valid" NS pointer resolving to a
SECURE byte), and nothing catches it. This gate does, and additionally binds the
`SphincsCVerify.Platform.MemoryMap` Lean literals to the source, so the Lean
`accept ⟹ ∉ secure` disjointness proof is about the REAL map, not a stale copy.

Scope: the shipping `stm32u585` target. Parses literals from source (no build).
Exit 0 = all bindings + disjointness hold. Exit 1 = drift / overlap / parse fail.
`--self-test` = negative control: a synthetic `.x` drift MUST be caught.

Usage: check_linker_memory_map.py [--self-test] [<repo-root>]
"""
import os
import re
import sys

# (base, end_exclusive) tuples throughout.


def _len_bytes(num: str, suffix: str) -> int:
    n = int(num)
    return n * (1024 if suffix == "K" else 1024 * 1024 if suffix == "M" else 1)


def parse_linker_x(path: str) -> dict:
    """{'FLASH': (base, end_excl), 'RAM': (base, end_excl)} from MEMORY{}."""
    txt = open(path, encoding="utf-8").read()
    out = {}
    for m in re.finditer(
        r"(\w+)\s*:\s*ORIGIN\s*=\s*(0x[0-9a-fA-F]+)\s*,\s*LENGTH\s*=\s*(\d+)\s*([KM]?)",
        txt,
    ):
        name, origin, length, suf = m.group(1), int(m.group(2), 16), m.group(3), m.group(4)
        out[name] = (origin, origin + _len_bytes(length, suf))
    return out


def _hex(v: str) -> int:
    return int(v.replace("_", ""), 16)


def parse_proto_stm(path: str) -> dict:
    """stm32u585 NS windows + mailbox from the cfg-gated `mod mem_layout`.
    proto END is already EXCLUSIVE. Returns exclusive (base, end)."""
    txt = open(path, encoding="utf-8").read()
    m = re.search(
        r'#\[cfg\(feature\s*=\s*"stm32u585"\)\]\s*mod\s+mem_layout\s*\{(.*?)\n\}',
        txt,
        re.DOTALL,
    )
    if not m:
        print(f"FAIL: no stm32u585 `mod mem_layout` in {path}", file=sys.stderr)
        sys.exit(1)
    body = m.group(1)
    c = {n: _hex(v) for n, v in re.findall(r"const\s+(\w+)\s*:\s*u32\s*=\s*(0x[0-9a-fA-F_]+)", body)}
    try:
        return {
            "NS_FLASH": (c["NS_FLASH_BASE"], c["NS_FLASH_END"]),
            "NS_SRAM": (c["NS_SRAM_BASE"], c["NS_SRAM_END"]),
            "MAILBOX": (c["SHARED_MAILBOX_BASE"], c["SHARED_MAILBOX_END"]),
        }
    except KeyError as e:
        print(f"FAIL: proto stm32u585 const {e} missing in {path}", file=sys.stderr)
        sys.exit(1)


def parse_sau_stm(path: str) -> dict:
    """stm32u585 SAU NS regions (per-const `#[cfg]`). sau END is INCLUSIVE →
    normalized to EXCLUSIVE (+1). Returns exclusive (base, end)."""
    txt = open(path, encoding="utf-8").read()
    c = {}
    for m in re.finditer(
        r'#\[cfg\(feature\s*=\s*"stm32u585"\)\]\s*const\s+(SAU_NS_\w+)\s*:\s*u32\s*=\s*(0x[0-9a-fA-F_]+)',
        txt,
    ):
        c[m.group(1)] = _hex(m.group(2))
    try:
        return {
            "SAU_NS_FLASH": (c["SAU_NS_FLASH_BASE"], c["SAU_NS_FLASH_END"] + 1),
            "SAU_NS_SRAM": (c["SAU_NS_SRAM_BASE"], c["SAU_NS_SRAM_END"] + 1),
        }
    except KeyError as e:
        print(f"FAIL: sau.rs stm32u585 const {e} missing in {path}", file=sys.stderr)
        sys.exit(1)


def parse_lean(path: str) -> dict:
    """{'nsFlashWindow': (base, end_excl), ...} from `def X : Region := ⟨_, _⟩`."""
    txt = open(path, encoding="utf-8").read()
    out = {}
    for m in re.finditer(
        r"def\s+(\w+)\s*:\s*Region\s*:=\s*⟨\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*⟩",
        txt,
    ):
        out[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))
    return out


def disjoint(a, b) -> bool:
    return a[1] <= b[0] or b[1] <= a[0]


def subset(a, b) -> bool:
    return b[0] <= a[0] and a[1] <= b[1]


def run_checks(sec_x, ns_x, proto, sau, lean) -> list:
    """Return a list of failure strings (empty = all bindings + disjointness hold)."""
    fails = []

    def eq(name, a, b):
        if a != b:
            fails.append(f"{name}: {tuple(hex(x) for x in a)} != {tuple(hex(x) for x in b)}")

    secF, secR = sec_x["FLASH"], sec_x["RAM"]

    # (1) DRIFT GUARD: linker .x NS regions == proto NS windows.
    eq("drift .x-NS-FLASH vs proto NS_FLASH", ns_x["FLASH"], proto["NS_FLASH"])
    eq("drift .x-NS-RAM vs proto NS_SRAM", ns_x["RAM"], proto["NS_SRAM"])

    # (2) SUBSET: proto NS windows ⊆ SAU NS regions (the sau.rs const-assert, cross-family).
    if not subset(proto["NS_FLASH"], sau["SAU_NS_FLASH"]):
        fails.append("proto NS_FLASH window escaped SAU_NS_FLASH")
    if not subset(proto["NS_SRAM"], sau["SAU_NS_SRAM"]):
        fails.append("proto NS_SRAM window escaped SAU_NS_SRAM")

    # (3) DISJOINT: SAU-NS ∩ secure = ∅, and proto NS windows ∩ secure = ∅.
    for nm, r in (("SAU_NS_FLASH", sau["SAU_NS_FLASH"]), ("SAU_NS_SRAM", sau["SAU_NS_SRAM"]),
                  ("proto NS_FLASH", proto["NS_FLASH"]), ("proto NS_SRAM", proto["NS_SRAM"]),
                  ("mailbox", proto["MAILBOX"])):
        if not disjoint(r, secF):
            fails.append(f"{nm} overlaps SECURE FLASH {tuple(hex(x) for x in secF)}")
        if not disjoint(r, secR):
            fails.append(f"{nm} overlaps SECURE RAM {tuple(hex(x) for x in secR)}")

    # (4) MAILBOX ⊆ NS-SRAM.
    if not subset(proto["MAILBOX"], proto["NS_SRAM"]):
        fails.append("mailbox escaped NS_SRAM")

    # (5) LEAN BIND: every Lean literal == its source-derived value.
    binds = {
        "nsFlashWindow": proto["NS_FLASH"], "nsSramWindow": proto["NS_SRAM"],
        "mailbox": proto["MAILBOX"],
        "sauNsFlash": sau["SAU_NS_FLASH"], "sauNsSram": sau["SAU_NS_SRAM"],
        "secureFlash": secF, "secureRam": secR,
        "linkerNsFlash": ns_x["FLASH"], "linkerNsRam": ns_x["RAM"],
    }
    for dname, src in binds.items():
        if dname not in lean:
            fails.append(f"Lean def `{dname}` missing in MemoryMap.lean")
        else:
            eq(f"Lean `{dname}` vs source", lean[dname], src)
    return fails


def load(root: str):
    return (
        parse_linker_x(os.path.join(root, "secure/memory-stm32u585.x")),
        parse_linker_x(os.path.join(root, "nonsecure/memory-stm32u585.x")),
        parse_proto_stm(os.path.join(root, "proto/src/lib.rs")),
        parse_sau_stm(os.path.join(root, "secure/src/sau.rs")),
        parse_lean(os.path.join(root, "contracts/verification/lean/SphincsCVerify/Platform/MemoryMap.lean")),
    )


def main():
    args = [a for a in sys.argv[1:] if a != "--self-test"]
    self_test = "--self-test" in sys.argv
    root = args[0] if args else os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    sec_x, ns_x, proto, sau, lean = load(root)

    if self_test:
        # NEGATIVE CONTROL: inject a `.x` NS-FLASH origin drift INTO the secure
        # region — the exact silent-overlap this gate exists to catch. The check
        # MUST report failures; if it does not, the gate is vacuous.
        bad_ns = dict(ns_x)
        bad_ns["FLASH"] = (sec_x["FLASH"][0], sec_x["FLASH"][0] + 0x1000)  # NS FLASH → inside secure FLASH
        fails = run_checks(sec_x, bad_ns, proto, sau, lean)
        if not fails:
            print("SELF-TEST FAIL: injected .x drift into secure region was NOT caught", file=sys.stderr)
            sys.exit(1)
        print(f"self-test OK: injected .x/secure overlap caught ({len(fails)} failures fired)")
        sys.exit(0)

    fails = run_checks(sec_x, ns_x, proto, sau, lean)
    if fails:
        print("FAIL: TrustZone memory-map drift/overlap:", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)
    print("OK: linker .x == proto == sau.rs == Lean MemoryMap; SAU-NS ∩ secure = ∅ (stm32u585).")
    sys.exit(0)


if __name__ == "__main__":
    main()
