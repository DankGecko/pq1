#!/usr/bin/env python3
"""Regenerate SphincsCVerify/KatVectors.lean from the shared KAT corpus.

Source of truth: contracts/smart-wallet/test/c10_test_vectors.json (the SAME
file the Solidity bytecode KAT test and the adversarial mutant screen read).

This embeds the 10 cross-validation vectors into a Lean module, together with
the OFFLINE-computed ground truth for the two verifier sub-layers that the
Lean spec models faithfully:

  * expectedDigestHex  — hMsg(seed16||0^16 ‖ root16||0^16 ‖ R16||0^16 ‖ msg ‖
                          0xFF*32) under FIPS-180-4 SHA-256 (hashlib);
  * expectedHtIdx      — (digest >> 143) & (2^18-1).

The Lean runner `verify-test-vectors` recomputes both from the spec and
asserts equality (a real Lean-sha256 ↔ FIPS differential), then runs the FULL
`Spec.Signature.verify` and reports the result honestly — see Main.lean for
why the full functional equivalence is currently a NAMED GAP, not a pass.
"""
import json
import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))
JSON = os.path.normpath(os.path.join(
    HERE, "../../../smart-wallet/test/c10_test_vectors.json"))
OUT = os.path.normpath(os.path.join(HERE, "../SphincsCVerify/KatVectors.lean"))


def hx(s):
    return bytes.fromhex(s[2:])


def digest_and_htidx(v):
    # N-mask: keep top 16 bytes, zero the bottom 16 (matches the deployed
    # verifier's `and(.., N_MASK)` and the Lean `pad16 (take 16 ..)`).
    seed = hx(v["pkSeed"])[:16] + b"\x00" * 16
    root = hx(v["pkRoot"])[:16] + b"\x00" * 16
    sig = hx(v["signature"])
    r = sig[:16] + b"\x00" * 16  # R = top 16 of the word at sig offset 0
    msg = hx(v["message"])
    dg = hashlib.sha256(seed + root + r + msg + b"\xff" * 32).digest()
    ht = (int.from_bytes(dg, "big") >> 143) & 0x3FFFF
    return dg.hex(), ht


def main():
    d = json.load(open(JSON))
    out = []
    out.append("/- AUTO-GENERATED from contracts/smart-wallet/test/c10_test_vectors.json.")
    out.append("   Do not edit by hand; regenerate via scripts/gen_kat_vectors.py. -/")
    out.append("namespace SphincsCVerify.KatVectors")
    out.append("")
    out.append("structure KatVector where")
    out.append("  label : String")
    out.append("  pkSeed : String")
    out.append("  pkRoot : String")
    out.append("  message : String")
    out.append("  signature : String")
    out.append("  expectValid : Bool")
    out.append("  /-- Ground-truth hMsg digest (FIPS SHA-256, computed offline). -/")
    out.append("  expectedDigestHex : String")
    out.append("  /-- Ground-truth extractHtIndex of the digest. -/")
    out.append("  expectedHtIdx : Nat")
    out.append("  deriving Inhabited")
    out.append("")
    out.append("def vectors : List KatVector := [")
    n = len(d["vectors"])
    for i, v in enumerate(d["vectors"]):
        dg, ht = digest_and_htidx(v)
        comma = "," if i < n - 1 else ""
        out.append("  { label := %s, pkSeed := %s, pkRoot := %s,"
                   % (json.dumps(v["label"]), json.dumps(v["pkSeed"]), json.dumps(v["pkRoot"])))
        out.append("    message := %s," % json.dumps(v["message"]))
        out.append("    signature := %s," % json.dumps(v["signature"]))
        out.append('    expectValid := %s, expectedDigestHex := "0x%s", expectedHtIdx := %d }%s'
                   % ("true" if v["expectValid"] else "false", dg, ht, comma))
    out.append("]")
    out.append("")
    out.append("end SphincsCVerify.KatVectors")
    open(OUT, "w").write("\n".join(out) + "\n")
    print("wrote %s (%d vectors)" % (OUT, n))


if __name__ == "__main__":
    main()
