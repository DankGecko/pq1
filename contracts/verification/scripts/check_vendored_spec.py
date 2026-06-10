#!/usr/bin/env python3
"""§33 P1 — verify Extracted/SpecVendored.lean faithfully transcribes the
named ByteVec/Adrs definitions from the SphincsCVerify v4.22 source.

The version bridge's trust rests on the vendored copy being verbatim; this
catches drift if either side is edited."""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = [ROOT/"lean/SphincsCVerify/Spec/Bytes.lean",
       ROOT/"lean/SphincsCVerify/Spec/Adrs.lean"]
VEN = ROOT/"extracted/Extracted/SpecVendored.lean"
# definitions whose BODIES must match byte-for-byte (semantic content)
DEFS = ["def ofU32BE", "def ofU64BE", "def make\n", "def setChainIndex"]

def grab(text, marker):
    """Return the def's lines from `marker` until the next top-level def/end."""
    lines = text.split("\n")
    key = marker.rstrip("\n")
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith(key) and (marker.endswith("\n") and ln.strip()==key.strip() or not marker.endswith("\n") and key in ln):
            body=[ln]
            for nxt in lines[i+1:]:
                if re.match(r'^\s*(def |structure |theorem |instance |namespace |end |/-)', nxt) and nxt.strip():
                    break
                body.append(nxt)
            # strip comments + blank-trailing, normalize whitespace
            joined=' '.join(b.split('--')[0] for b in body)
            return re.sub(r'\s+',' ',joined).strip()
    return None

srctext = "\n".join(p.read_text() for p in SRC)
ventext = VEN.read_text()
ok = True
for d in DEFS:
    s, v = grab(srctext, d), grab(ventext, d)
    if s is None: print(f"MISSING in source: {d!r}"); ok=False; continue
    if v is None: print(f"MISSING in vendored: {d!r}"); ok=False; continue
    if s != v:
        print(f"DRIFT in {d!r}:\n  src: {s}\n  ven: {v}")
        ok=False
if ok: print("OK: vendored spec is a faithful copy of the SphincsCVerify source")
sys.exit(0 if ok else 1)
