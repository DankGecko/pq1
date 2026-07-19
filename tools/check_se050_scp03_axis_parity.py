#!/usr/bin/env python3
"""Finding F7 — SE050 SCP03 key-derivation axis parity gate.

The per-device SCP03 `PUT KEY` rotation ceremony and the runtime-signing ship
image both derive their SE050 static SCP03 keys (S-ENC / S-MAC / DEK) from a
root that `hw::secret_keys::derive_into_bhk` selects at COMPILE TIME from the
feature set. If the ceremony installs keys derived on one axis (e.g. BHK) while
the ship image authenticates with keys derived on another (e.g. DHUK), the SCP03
EXTERNAL-AUTHENTICATE cryptogram mismatches, `establish()` fails closed (the
factory-key fallback is PROD_FORBIDDEN), and half_E becomes unrecoverable — a
persistent brick / loss of the SE050 entropy half.

This gate extracts the derivation axis from two Cargo feature strings and fails
if they differ, so ceremony and ship can never silently diverge.

    usage: check_se050_scp03_axis_parity.py "<ceremony-features>" "<ship-features>"

Owner decision (2026-07-14): keep the Tier-2 BHK split (SE050 SCP03 on BHK,
OPTIGA PBS on DHUK). The ceremony is therefore BHK while the ship image is still
DHUK until the phase-2B BHK provisioning lands and flips the ship image to BHK.
This gate is EXPECTED to fail today; it is the machine-checkable reminder that
the two must move to BHK in lockstep. See docs/archive/work-todo-retired-2026-07-19.md (phase-2B BHK).
"""
import sys


def axis(features):
    """Derivation axis id — precedence mirrors the cfg cascade in
    hw::secret_keys::derive_into_bhk -> derive_into (bhk-hardcoded > bhk >
    otp-hardcoded > saes-dhuk > legacy)."""
    if "bhk-hardcoded-master-key" in features:
        return "BHK-HARDCODED"
    if "bhk" in features:
        return "BHK"
    if "otp-hardcoded-master-key" in features:
        return "OTP-HARDCODED"
    if "saes-dhuk" in features:
        return "DHUK"
    return "OTP-LEGACY"


def parse(s):
    return {f.strip() for f in s.replace(" ", ",").split(",") if f.strip()}


def main(argv):
    if len(argv) != 3:
        print(
            "usage: check_se050_scp03_axis_parity.py <ceremony-features> <ship-features>",
            file=sys.stderr,
        )
        return 2
    ceremony = axis(parse(argv[1]))
    ship = axis(parse(argv[2]))
    print(f"SE050 SCP03 derivation axis: ceremony={ceremony}  ship={ship}")
    if ceremony != ship:
        print(
            f"FAIL (F7): axis mismatch — a chip rotated by the ceremony ({ceremony}) would\n"
            f"  fail SCP03 auth under the ship image ({ship}) and brick half_E. Align both\n"
            f"  axes before shipping. If this is the known BHK-vs-DHUK state pending phase-2B\n"
            f"  BHK provisioning, that is expected — see docs/archive/work-todo-retired-2026-07-19.md (phase-2B BHK).",
            file=sys.stderr,
        )
        return 1
    print("OK: ceremony and ship derive SE050 SCP03 keys on the same axis.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
