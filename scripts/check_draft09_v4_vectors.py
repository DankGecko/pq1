#!/usr/bin/env python3
"""Independent stdlib reproduction of Draft 0.9's frozen V4 vectors.

This is a nonshipping cross-language oracle for the Rust host model.  It does
not import repository code and performs no device, flash, TAMP, or OTP access.
"""

from __future__ import annotations

import hashlib
import json
import zlib

MANIFEST_SIZE = 8192
OFF_PENDING = 4192
OFF_CONFIRMED = 4208
OFF_TRAILING_RESERVED = 4224
OFF_CRC32 = 8188

PENDING = bytes.fromhex("123456789abcdef0edcba9876543210f")
CONFIRMED = bytes.fromhex("aa559966f00fc33c55aa66990ff03cc3")

SLOT = 1
RELEASE = 0x01020304
EPOCH = 0x05060708
TARGET = EPOCH - 1
SECURE_HASH = bytes(range(0x00, 0x20))
NONSECURE_HASH = bytes(range(0x20, 0x40))


def sha256(data: bytes | bytearray) -> bytes:
    return hashlib.sha256(data).digest()


def normalized_crc(page: bytes | bytearray) -> int:
    body = bytearray(page[:OFF_CRC32])
    body[OFF_PENDING:OFF_TRAILING_RESERVED] = b"\xff" * 32
    return zlib.crc32(body) & 0xFFFFFFFF


def page_fixture(journal: str, manifest_digest: bytes) -> bytes:
    page = bytearray(b"\xff" * MANIFEST_SIZE)
    page[0:4] = b"PQSF"
    page[4] = 4
    page[5] = SLOT
    page[6:8] = b"\x00\x00"
    page[8:12] = RELEASE.to_bytes(4, "big")
    page[12:16] = EPOCH.to_bytes(4, "big")
    page[16:20] = (0x1000).to_bytes(4, "big")
    page[20:24] = (0x2000).to_bytes(4, "big")
    page[24:56] = SECURE_HASH
    page[56:88] = NONSECURE_HASH
    page[88:120] = bytes(range(0x40, 0x60))
    page[120:152] = bytes(range(0x60, 0x80))
    page[152:184] = manifest_digest
    page[184:4192] = bytes(i & 0xFF for i in range(4008))
    if journal in ("pending", "confirmed"):
        page[OFF_PENDING:OFF_CONFIRMED] = PENDING
    if journal == "confirmed":
        page[OFF_CONFIRMED:OFF_TRAILING_RESERVED] = CONFIRMED
    page[OFF_CRC32:] = normalized_crc(page).to_bytes(4, "big")
    return bytes(page)


def main() -> None:
    preimage = (
        b"PQFW_V4"
        + bytes([SLOT])
        + RELEASE.to_bytes(4, "big")
        + EPOCH.to_bytes(4, "big")
        + SECURE_HASH
        + NONSECURE_HASH
    )
    manifest_digest = sha256(preimage)
    token_preimage = (
        b"PQFW_A1"
        + bytes([SLOT])
        + RELEASE.to_bytes(4, "big")
        + EPOCH.to_bytes(4, "big")
        + TARGET.to_bytes(4, "big")
        + manifest_digest
        + SECURE_HASH
        + NONSECURE_HASH
    )
    pages = {
        state: page_fixture(state, manifest_digest)
        for state in ("erased", "pending", "confirmed")
    }
    result = {
        "manifest_digest": manifest_digest.hex(),
        "token_digest": sha256(token_preimage).hex(),
        "normalized_crc": f"{normalized_crc(pages['erased']):08x}",
        "page_hashes": {state: sha256(page).hex() for state, page in pages.items()},
    }

    expected = {
        "manifest_digest": "b26491e86c8b97fe7e6bc3b67be73d1a6963ee4290c9fcaef5f2dad01f86461f",
        "token_digest": "167270423f35f16bcdecad4e9e19817ac87b06bb8838483be8b97636476c7b7a",
        "normalized_crc": "993615cd",
        "page_hashes": {
            "erased": "8e80b317a7a57a80136644339c6a10e340abf6c584fd73d58afedf3318875710",
            "pending": "0b2b7e22e23fa9c17a7a769a210354f711202273719e541695ff1c1c5fbd7847",
            "confirmed": "da4eec46baed2812be2af731bf76e319e1ca23137f4a117d7ba3ecedec0918f3",
        },
    }
    if result != expected:
        raise SystemExit(
            "Draft 0.9 V4 vector mismatch\n"
            + json.dumps({"actual": result, "expected": expected}, indent=2, sort_keys=True)
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
