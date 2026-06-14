#!/usr/bin/env python3
"""Embed contracts/verification/bulk_vectors.json into a Lean module for the
bulk executable-spec differential (A3.1 follow-up).

Source of truth: contracts/verification/bulk_vectors.json, produced by
`cargo test -p sphincs-c10 --test gen_bulk_vectors --release`. That generator
signs a broad random corpus (many keypairs × many messages) with the Rust
reference signer and self-verifies each, plus one single-byte mutation per
valid vector as a negative — exercising far more hypertree-leaf positions /
merkle-path lengths than the 10-vector KAT, including the offset-3992
boundary read that the 2026-06-13 `loadWord32` fix addressed.

Unlike KatVectors.lean this carries NO offline digest/htIdx ground truth: the
bulk runner only asserts the FULL `Spec.Signature.verify` matches the Rust
oracle's `expectValid`, so the embedded fields are just the raw bytes.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, "../../bulk_vectors.json"))
OUT = os.path.normpath(os.path.join(HERE, "../SphincsCVerify/BulkVectors.lean"))


def main() -> None:
    with open(SRC) as f:
        data = json.load(f)
    vecs = data["vectors"]

    lines = [
        "/- AUTO-GENERATED from contracts/verification/bulk_vectors.json.",
        "   Do not edit by hand; regenerate via:",
        "     cargo test -p sphincs-c10 --test gen_bulk_vectors --release",
        "     python3 scripts/gen_bulk_lean.py   (from contracts/verification/lean)",
        "   Then run `make verify-bulk` (in contracts/verification). -/",
        "namespace SphincsCVerify.BulkVectors",
        "",
        "structure BulkVector where",
        "  label : String",
        "  pkSeed : String",
        "  pkRoot : String",
        "  message : String",
        "  signature : String",
        "  expectValid : Bool",
        "  deriving Inhabited",
        "",
        "def vectors : List BulkVector := [",
    ]
    body = []
    for v in vecs:
        ev = "true" if v["expectValid"] else "false"
        body.append(
            '  { label := "%s", pkSeed := "%s", pkRoot := "%s",\n'
            '    message := "%s",\n'
            '    signature := "%s",\n'
            '    expectValid := %s }'
            % (v["label"], v["pkSeed"], v["pkRoot"], v["message"],
               v["signature"], ev)
        )
    lines.append(",\n".join(body))
    lines.append("]")
    lines.append("")
    lines.append("end SphincsCVerify.BulkVectors")
    lines.append("")

    with open(OUT, "w") as f:
        f.write("\n".join(lines))
    print(f"wrote {OUT} ({len(vecs)} vectors)")


if __name__ == "__main__":
    main()
