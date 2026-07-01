#!/usr/bin/env python3
"""ERC-8176 attestation coverage checker for the PQSigner ERC-7730 corpus.

Answers the one question that gates flipping `allow_unattested_dev_descriptors`
to `false`: *how many of our firmware-pinned descriptors carry a valid
ERC-8176 attestation from an auditor we trust?*

Each descriptor's ERC-8176 `descriptorHash` = keccak256(RFC-8785 JCS(resolved
descriptor)) is emitted by `dbgen` into `secure/data/erc7730.review.txt`
(`erc8176_hash=0x...` column; cross-validated against `cast keccak` + an
independent RFC-8785 canonicalizer). This tool reads those hashes and queries
the Ethereum Attestation Service (EAS) mainnet GraphQL API for attestations
under the ERC-8176 schema, then reports coverage.

No dependencies beyond `curl` + the Python stdlib. Read-only; no signing.

Usage:  python3 tools/erc8176_eas_coverage.py [--trusted 0xADDR ...] [--json]
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

# ERC-8176 canonical EAS schema (Ethereum mainnet), field `bytes32 descriptorHash`.
# https://easscan.org/schema/view/0xe023eef113c1670774801c34b377fdf612dd8a4d2fa92fe382e15bd91fafb5c2
ERC8176_SCHEMA_UID = "0xe023eef113c1670774801c34b377fdf612dd8a4d2fa92fe382e15bd91fafb5c2"
EAS_GRAPHQL = "https://easscan.org/graphql"

REVIEW = Path(__file__).resolve().parent.parent / "secure" / "data" / "erc7730.review.txt"


def our_descriptor_hashes():
    """Map erc8176 descriptorHash -> list of (contract, source) from the review file."""
    out = {}
    if not REVIEW.exists():
        sys.exit(f"review file not found: {REVIEW}\nrun `cargo run -p dbgen` first")
    for line in REVIEW.read_text().splitlines():
        if not line.startswith("["):
            continue
        fields = dict(
            tok.split("=", 1) for tok in line.split() if "=" in tok
        )
        h = fields.get("erc8176_hash")
        if not h:
            sys.exit(
                "review file has no `erc8176_hash` column — rebuild with the "
                "ERC-8176 dbgen change (`cargo run -p dbgen`)."
            )
        out.setdefault(h.lower(), []).append(
            (fields.get("contract", "?"), fields.get("source", "?"))
        )
    return out


def eas_attestations():
    """All non-revoked attestations under the ERC-8176 schema (mainnet)."""
    query = (
        "query{attestations(where:{schemaId:{equals:\"%s\"},revoked:{equals:false}}"
        "){attester decodedDataJson revoked time}}" % ERC8176_SCHEMA_UID
    )
    body = json.dumps({"query": query})
    try:
        res = subprocess.run(
            ["curl", "-sS", "-X", "POST", EAS_GRAPHQL,
             "-H", "Content-Type: application/json", "-d", body],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        sys.exit(f"EAS query failed (offline?): {e}")
    data = json.loads(res.stdout).get("data", {}).get("attestations", [])
    out = []  # (descriptorHash, attester)
    for a in data:
        try:
            dec = json.loads(a["decodedDataJson"])
            dh = dec[0]["value"]["value"].lower()
        except (KeyError, IndexError, json.JSONDecodeError):
            continue
        out.append((dh, a["attester"].lower()))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trusted", nargs="*", default=[],
                    help="attester addresses to count as trusted (default: none — reports all)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()
    trusted = {a.lower() for a in args.trusted}

    ours = our_descriptor_hashes()
    atts = eas_attestations()

    # Intersect: which of OUR descriptorHashes are attested on EAS?
    attested = {}  # hash -> set(attesters)
    for dh, attester in atts:
        if dh in ours:
            attested.setdefault(dh, set()).add(attester)

    n_desc = len(ours)
    n_attested = len(attested)
    n_trusted_attested = sum(
        1 for h, atsts in attested.items() if trusted & atsts
    ) if trusted else 0

    if args.json:
        print(json.dumps({
            "schema": ERC8176_SCHEMA_UID,
            "descriptors": n_desc,
            "eas_attestations_total": len(atts),
            "our_descriptors_attested": n_attested,
            "our_descriptors_trusted_attested": n_trusted_attested,
            "trusted_attesters": sorted(trusted),
        }, indent=2))
        return

    print(f"ERC-8176 attestation coverage (EAS schema {ERC8176_SCHEMA_UID[:10]}…, mainnet)")
    print(f"  our descriptors (unique descriptorHashes): {n_desc}")
    print(f"  total attestations under the schema:      {len(atts)}")
    print(f"  OUR descriptors with ANY attestation:     {n_attested}")
    if trusted:
        print(f"  OUR descriptors attested by a TRUSTED auditor ({len(trusted)} listed): {n_trusted_attested}")
    else:
        print("  (no --trusted auditors given; not counting trusted coverage)")
    if attested:
        print("\n  attested descriptors:")
        for h, atsts in sorted(attested.items()):
            contract, src = ours[h][0]
            mark = "TRUSTED" if (trusted & atsts) else "untrusted"
            print(f"    {h}  {src}  by {sorted(atsts)}  [{mark}]")
    print()
    # Flip-readiness verdict.
    if not trusted:
        print("VERDICT: give --trusted <auditor addrs> to assess production-flip readiness.")
    elif n_trusted_attested == n_desc:
        print("VERDICT: FULL trusted coverage — the production flip would keep every leaf. Safe to flip.")
    elif n_trusted_attested == 0:
        print("VERDICT: ZERO trusted coverage — flipping now drops the ENTIRE corpus to blind-sign. DO NOT flip.")
    else:
        pct = 100 * n_trusted_attested / n_desc
        print(f"VERDICT: PARTIAL trusted coverage ({n_trusted_attested}/{n_desc} = {pct:.1f}%). "
              f"Flipping now drops the un-attested remainder to blind-sign.")


if __name__ == "__main__":
    main()
