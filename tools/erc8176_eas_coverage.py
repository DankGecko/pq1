#!/usr/bin/env python3
"""ERC-8176 attestation coverage checker for the PQSigner ERC-7730 corpus.

Answers the one question that gates flipping `allow_unattested_dev_descriptors`
to `false`: *how many of our firmware-pinned descriptors carry the policy's
minimum number of distinct valid ERC-8176 attestations from auditors we trust?*

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
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path

# ERC-8176 canonical EAS schema (Ethereum mainnet), field `bytes32 descriptorHash`.
# https://easscan.org/schema/view/0xe023eef113c1670774801c34b377fdf612dd8a4d2fa92fe382e15bd91fafb5c2
ERC8176_SCHEMA_UID = "0xe023eef113c1670774801c34b377fdf612dd8a4d2fa92fe382e15bd91fafb5c2"
EAS_GRAPHQL = "https://easscan.org/graphql"

REVIEW = Path(__file__).resolve().parent.parent / "secure" / "data" / "erc7730.review.txt"
POLICY = Path(__file__).resolve().parent.parent / "secure" / "data" / "erc7730" / "policy.toml"

# ERC-8176 production readiness deliberately requires independent attesters.
# Even if a malformed or stale policy file says `1`, this reporting tripwire
# must never turn one-attester intersections into a "Safe to flip" verdict.
MIN_READINESS_ATTESTERS = 2


def policy_min_attesters(policy_path=POLICY):
    """Read and fail-closed validate the per-descriptor attester threshold."""
    try:
        policy = tomllib.loads(policy_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        sys.exit(f"cannot read ERC-8176 policy {policy_path}: {exc}")

    threshold = policy.get("min_attesters")
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        sys.exit(f"invalid min_attesters in {policy_path}: expected integer")
    if threshold < MIN_READINESS_ATTESTERS:
        sys.exit(
            f"unsafe min_attesters={threshold} in {policy_path}: readiness requires "
            f"at least {MIN_READINESS_ATTESTERS} distinct trusted attesters per descriptor"
        )
    return threshold


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


HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def parse_eas_attestations(records, as_of_unix):
    """Fail-closed parse of live EAS rows at an explicit report timestamp.

    Every row must carry the exact immutable ERC-8176 schema UID; the
    server-side GraphQL filter is not trusted as row identity evidence.
    `expirationTime == 0` means no expiry. Wrong-schema, revoked, expired,
    missing, or malformed rows never enter threshold arithmetic; counters keep
    the advisory report honest about what the indexer returned.
    """
    stats = {
        "records_returned": len(records),
        "records_eligible": 0,
        "records_expired": 0,
        "records_revoked": 0,
        "records_malformed": 0,
    }
    out = []
    for attestation in records:
        if not isinstance(attestation, dict):
            stats["records_malformed"] += 1
            continue
        if attestation.get("schemaId") != ERC8176_SCHEMA_UID:
            stats["records_malformed"] += 1
            continue
        if attestation.get("revoked") is not False:
            stats["records_revoked"] += 1
            continue

        expiration = attestation.get("expirationTime")
        if isinstance(expiration, bool):
            stats["records_malformed"] += 1
            continue
        if isinstance(expiration, str) and expiration.isascii() and expiration.isdigit():
            expiration = int(expiration)
        if not isinstance(expiration, int) or expiration < 0:
            stats["records_malformed"] += 1
            continue
        if expiration != 0 and expiration <= as_of_unix:
            stats["records_expired"] += 1
            continue

        attester = attestation.get("attester")
        if not isinstance(attester, str) or ADDRESS_RE.fullmatch(attester) is None:
            stats["records_malformed"] += 1
            continue
        try:
            decoded = json.loads(attestation["decodedDataJson"])
            if not isinstance(decoded, list) or len(decoded) != 1:
                raise ValueError("unexpected ERC-8176 field count")
            field = decoded[0]
            if not isinstance(field, dict):
                raise ValueError("malformed ERC-8176 field")
            if field.get("name") != "descriptorHash" or field.get("type") != "bytes32":
                raise ValueError("unexpected ERC-8176 field")
            value = field.get("value")
            if not isinstance(value, dict):
                raise ValueError("malformed ERC-8176 value")
            descriptor_hash = value.get("value")
            if not isinstance(descriptor_hash, str) or HEX32_RE.fullmatch(descriptor_hash) is None:
                raise ValueError("malformed descriptorHash")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            stats["records_malformed"] += 1
            continue

        out.append((descriptor_hash.lower(), attester.lower()))
        stats["records_eligible"] += 1
    return out, stats


def eas_attestations(as_of_unix):
    """Eligible, non-revoked, unexpired ERC-8176 rows plus parse counters."""
    query = (
        "query{attestations(where:{schemaId:{equals:\"%s\"}}"
        "){schemaId attester decodedDataJson revoked time expirationTime}}"
        % ERC8176_SCHEMA_UID
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
    try:
        response = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        sys.exit(f"EAS query returned malformed JSON: {exc}")
    if response.get("errors"):
        sys.exit(f"EAS query returned GraphQL errors: {response['errors']}")
    records = response.get("data", {}).get("attestations")
    if not isinstance(records, list):
        sys.exit("EAS query response has no attestations list")
    return parse_eas_attestations(records, as_of_unix)


def normalize_trusted_addresses(addresses):
    """Validate the advisory command-line trust set before counting it."""
    trusted = set()
    for address in addresses:
        if ADDRESS_RE.fullmatch(address) is None:
            sys.exit(f"invalid trusted attester address: {address!r}")
        trusted.add(address.lower())
    return trusted


def coverage_summary(ours, attestations, trusted, min_attesters, source_stats=None):
    """Return deterministic per-descriptor threshold coverage.

    EAS can contain duplicate records from the same address.  Sets make the
    production-relevant unit explicit: distinct trusted attester identities,
    counted independently for every descriptor hash.
    """
    if min_attesters < MIN_READINESS_ATTESTERS:
        raise ValueError(
            f"readiness requires at least {MIN_READINESS_ATTESTERS} attesters"
        )

    attested = {}
    for descriptor_hash, attester in attestations:
        descriptor_hash = descriptor_hash.lower()
        if descriptor_hash in ours:
            attested.setdefault(descriptor_hash, set()).add(attester.lower())

    details = []
    for descriptor_hash in sorted(ours):
        all_attesters = attested.get(descriptor_hash, set())
        trusted_attesters = sorted(all_attesters & trusted)
        found = len(trusted_attesters)
        details.append(
            {
                "descriptor_hash": descriptor_hash,
                "deployments": [
                    {"contract": contract, "source": source}
                    for contract, source in sorted(set(ours[descriptor_hash]))
                ],
                "all_attesters": sorted(all_attesters),
                "trusted_attesters": trusted_attesters,
                "trusted_attesters_found": found,
                "trusted_attesters_required": min_attesters,
                "shortfall": max(0, min_attesters - found),
                "meets_threshold": found >= min_attesters,
            }
        )

    threshold_met = sum(detail["meets_threshold"] for detail in details)
    with_any_trusted = sum(
        detail["trusted_attesters_found"] > 0 for detail in details
    )
    source_stats = source_stats or {
        "records_returned": len(attestations),
        "records_eligible": len(attestations),
        "records_expired": 0,
        "records_revoked": 0,
        "records_malformed": 0,
    }
    return {
        "descriptors": len(ours),
        "eas_attestations_total": source_stats["records_returned"],
        "eas_attestations_eligible": source_stats["records_eligible"],
        "eas_attestations_expired": source_stats["records_expired"],
        "eas_attestations_revoked": source_stats["records_revoked"],
        "eas_attestations_malformed": source_stats["records_malformed"],
        "our_descriptors_attested": len(attested),
        "our_descriptors_with_any_trusted_attestation": with_any_trusted,
        "our_descriptors_meeting_trusted_threshold": threshold_met,
        "min_attesters": min_attesters,
        "details": details,
        "descriptor_shortfalls": [
            detail for detail in details if not detail["meets_threshold"]
        ],
    }


def readiness_verdict(summary, trusted):
    """Return an advisory coverage verdict, never production authorization."""
    if not trusted:
        return "VERDICT: give --trusted <auditor addrs> to assess production-flip readiness."

    descriptors = summary["descriptors"]
    threshold_met = summary["our_descriptors_meeting_trusted_threshold"]
    min_attesters = summary["min_attesters"]
    if descriptors == 0:
        return "VERDICT: EMPTY corpus — no production-flip readiness claim is possible."
    if threshold_met == descriptors:
        return (
            "VERDICT: FULL trusted threshold coverage "
            f"(at least {min_attesters} distinct trusted attesters per descriptor) — "
            "the coverage prerequisite is met. DO NOT flip from this live-query report: "
            "the authenticated offline snapshot verifier and production provenance gate "
            "remain separate blockers."
        )
    if threshold_met == 0:
        return (
            "VERDICT: ZERO descriptors meet the trusted-attester threshold "
            f"({min_attesters} required per descriptor) — flipping now removes clear-sign "
            "coverage for the ENTIRE corpus, while filter-positive calls hard-refuse. "
            "DO NOT flip."
        )

    pct = 100 * threshold_met / descriptors
    return (
        "VERDICT: PARTIAL trusted threshold coverage "
        f"({threshold_met}/{descriptors} = {pct:.1f}%; {min_attesters} distinct trusted "
        "attesters required per descriptor). Flipping now removes clear-sign coverage "
        "for the below-threshold remainder; filter-positive calls hard-refuse."
    )


def json_report(summary, trusted, as_of_unix=None):
    """Build the stable machine-readable report without internal detail rows."""
    return {
        "schema": ERC8176_SCHEMA_UID,
        "descriptors": summary["descriptors"],
        "eas_attestations_total": summary["eas_attestations_total"],
        "eas_attestations_eligible": summary["eas_attestations_eligible"],
        "eas_attestations_expired": summary["eas_attestations_expired"],
        "eas_attestations_revoked": summary["eas_attestations_revoked"],
        "eas_attestations_malformed": summary["eas_attestations_malformed"],
        "report_as_of_unix": as_of_unix,
        "our_descriptors_attested": summary["our_descriptors_attested"],
        "our_descriptors_with_any_trusted_attestation": summary[
            "our_descriptors_with_any_trusted_attestation"
        ],
        # Keep the old key fail-closed for consumers: it now means the policy
        # threshold was met, not merely that one trusted address intersected.
        "our_descriptors_trusted_attested": summary[
            "our_descriptors_meeting_trusted_threshold"
        ],
        "our_descriptors_meeting_trusted_threshold": summary[
            "our_descriptors_meeting_trusted_threshold"
        ],
        "min_attesters": summary["min_attesters"],
        "trusted_attesters": sorted(trusted),
        "descriptor_shortfalls": summary["descriptor_shortfalls"],
        "production_flip_authorized": False,
        "trust_input": "command-line advisory set",
        "remaining_production_blockers": [
            "no owner-approved production auditor trust set and authenticated EAS "
            "snapshot configured",
            "production provenance gate has not accepted an erc8176-verified artifact",
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trusted", nargs="*", default=[],
                    help="attester addresses to count as trusted (default: none — reports all)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()
    trusted = normalize_trusted_addresses(args.trusted)
    min_attesters = policy_min_attesters()
    as_of_unix = int(time.time())

    ours = our_descriptor_hashes()
    atts, source_stats = eas_attestations(as_of_unix)
    summary = coverage_summary(
        ours,
        atts,
        trusted,
        min_attesters,
        source_stats=source_stats,
    )

    if args.json:
        print(json.dumps(json_report(summary, trusted, as_of_unix), indent=2))
        return

    print(
        f"ERC-8176 attestation coverage (EAS schema {ERC8176_SCHEMA_UID[:10]}…, "
        f"mainnet, as of Unix {as_of_unix})"
    )
    print(f"  our descriptors (unique descriptorHashes): {summary['descriptors']}")
    print(f"  records returned under the schema:        {summary['eas_attestations_total']}")
    print(f"  eligible (unrevoked and unexpired):        {summary['eas_attestations_eligible']}")
    print(f"  excluded expired:                          {summary['eas_attestations_expired']}")
    print(f"  excluded revoked/malformed:                "
          f"{summary['eas_attestations_revoked']}/{summary['eas_attestations_malformed']}")
    print(f"  OUR descriptors with ANY attestation:     {summary['our_descriptors_attested']}")
    if trusted:
        print(
            "  OUR descriptors meeting trusted threshold "
            f"({min_attesters} distinct required; {len(trusted)} listed): "
            f"{summary['our_descriptors_meeting_trusted_threshold']}"
        )
    else:
        print("  (no --trusted auditors given; not counting trusted coverage)")
    attested_details = [detail for detail in summary["details"] if detail["all_attesters"]]
    if attested_details:
        print("\n  attested descriptors:")
        for detail in attested_details:
            source = detail["deployments"][0]["source"]
            found = detail["trusted_attesters_found"]
            mark = "READY" if detail["meets_threshold"] else f"SHORT {found}/{min_attesters}"
            print(
                f"    {detail['descriptor_hash']}  {source}  "
                f"by {detail['all_attesters']}  [{mark}]"
            )
    print()
    print(readiness_verdict(summary, trusted))


if __name__ == "__main__":
    main()
