#!/usr/bin/env python3
"""Key a CycloneDX dependency SBOM to the FSBL-measured firmware hash.

SOTA 2026-06 §8: an SBOM is only meaningful as a release artifact if it is
BOUND to a specific firmware build — `make sbom`'s per-crate dependency SBOM
answers "what deps does this crate pull", not "what deps went into THIS
firmware image". This post-processor runs `fwmeasure` over the built secure
ELF (the same SHA-256 the FSBL measures + the device shows at boot), and
stamps that hash + the 8 BIP-39 words into the SBOM's root
`metadata.component`, so the dependency manifest is provably the one that
produced this exact firmware.

Usage:
    tools/sbom_firmware.py <secure.elf> <input.cdx.json> <output.cdx.json> \
        [--flash-base=0xHEX] [--flash-end=0xHEX]

Reads the SHA-256 from `fwmeasure`'s stderr ("SHA-256: <hex>") and the 8
words from its stdout. Requires `fwmeasure` built (`cargo build -p fwmeasure`).
"""
import json
import re
import subprocess
import sys


def measure(elf: str, extra_args: list[str]) -> tuple[str, str]:
    """Return (sha256_hex, '1 word\\n2 word\\n...') for the firmware ELF."""
    exe = "target/release/fwmeasure"
    out = subprocess.run([exe, elf, *extra_args], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"fwmeasure failed: {out.stderr}")
    m = re.search(r"SHA-256:\s*([0-9a-fA-F]{64})", out.stderr)
    if not m:
        sys.exit(f"could not parse SHA-256 from fwmeasure stderr:\n{out.stderr}")
    return m.group(1).lower(), out.stdout.strip()


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    extra = [a for a in sys.argv[1:] if a.startswith("--")]
    if len(args) != 3:
        sys.exit(__doc__)
    elf, in_path, out_path = args

    sha, words = measure(elf, extra)
    word_list = [w.split(maxsplit=1)[1] for w in words.splitlines() if w.strip()]

    sbom = json.load(open(in_path))
    comp = sbom.setdefault("metadata", {}).setdefault("component", {})
    comp["type"] = "firmware"
    comp["name"] = "pqsigner-secure-world"
    comp["version"] = f"sha256:{sha}"
    # CycloneDX hash of the measured image — this is the binding to the build.
    comp["hashes"] = [{"alg": "SHA-256", "content": sha}]
    props = comp.setdefault("properties", [])
    props.append({"name": "pqsigner:fsbl-measurement-words", "value": " ".join(word_list)})
    props.append({"name": "pqsigner:measured-by", "value": "fwmeasure (FSBL-equivalent SHA-256)"})

    json.dump(sbom, open(out_path, "w"), indent=2)
    print(f"==> firmware-keyed SBOM: {out_path}")
    print(f"    measured SHA-256: {sha}")
    print(f"    FSBL words: {' '.join(word_list)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
