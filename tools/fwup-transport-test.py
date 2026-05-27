#!/usr/bin/env python3
"""Over-USB FW-update transport e2e test (`make fwup-transport-hw`).

Drives the firmware's FW_BEGIN / FW_CHUNK / FW_COMMIT command sequence
over real USB HID against a device flashed with the `fwup-transport-e2e`
feature. The device runs the FULL state machine + `verify_manifest` +
`verify_images`, then stops at COMMIT *before* the OTP rollback-floor
bump + boot-state write + sys_reset (so the chip stays reflashable for
continued dev work — see secure/src/nsc/cmd_fw_commit.rs).

PASS criteria: every APDU response has SW=0x9000 (incl. the final
FW_COMMIT, which under the test feature returns Ok without committing).

Run directly with:
    tools/fwup-transport-test.py --fixture-dir target/fwup-test
or via:
    make fwup-transport-hw

No external Python dependencies — reads /dev/hidrawN directly (the
99-pqsigner.rules udev rule provides MODE=0666 for VID:PID 1209:7051,
so no root needed).
"""
from __future__ import annotations

import argparse
import glob
import os
import select
import struct
import sys

# ---------------------------------------------------------------------------
# Wire-format constants — mirror proto/src/lib.rs + tools/factory-prodtest-runner.py
# ---------------------------------------------------------------------------

VID = 0x1209
PID = 0x7051

APDU_CLA_V2 = 0xF0
HID_REPORT_SIZE = 64
HID_TAG_APDU = 0x05
HID_FIRST_DATA = HID_REPORT_SIZE - 7  # 57 B after [chan(2)|tag(1)|seq(2)|len(2)]
HID_CONT_DATA = HID_REPORT_SIZE - 5   # 59 B after [chan(2)|tag(1)|seq(2)]
CHANNEL_ID = 0x0001

# APDU chaining (docs/usb-protocol-v2.md "Command Chaining"):
#   P1=0x80 — more blocks follow
#   P1=0x00 — last (or only) block; triggers execute on the device.
P1_MORE = 0x80
P1_LAST = 0x00

# Status words.
SW_OK = 0x9000

# Pre-FW INS codes used as sanity probes.
INS_V2_GET_DEVICE_INFO = 0x01
INS_V2_GET_STATUS = 0x02

# FW-update INS codes (proto/src/lib.rs).
INS_V2_FW_BEGIN = 0x70
INS_V2_FW_CHUNK = 0x71
INS_V2_FW_COMMIT = 0x72

# FW_CHUNK payload layout (sphincs_tz_shared, secure/src/nsc/cmd_fw_chunk.rs):
#   [0..4]   u32 BE  chunk_offset
#   [4]      u8       image_kind (0=secure, 1=nonsecure)
#   [5]      u8       reserved (0)
#   [6..8]   u16 BE   chunk_len
#   [8..]    bytes    image data
FW_CHUNK_HEADER_LEN = 8
FW_IMAGE_KIND_SECURE = 0
FW_IMAGE_KIND_NONSECURE = 1

# Per-APDU bound is 255 (single-byte LC). Use 240 data bytes per chunk —
# QW-aligned (15 * 16) and well under LC=255 with the 8-byte header. The
# device caps at FW_MAX_CHUNK=1024 internally; the wire limit is what
# bounds us here.
MAX_CHUNK_DATA = 240


# ---------------------------------------------------------------------------
# /dev/hidrawN discovery + raw I/O
# ---------------------------------------------------------------------------

def find_hidraw() -> str | None:
    """Scan /sys/class/hidraw for the wallet (VID:PID match)."""
    needle_vid = f"{VID:04X}"
    needle_pid = f"{PID:04X}"
    for uevent in glob.glob("/sys/class/hidraw/hidraw*/device/uevent"):
        try:
            with open(uevent) as f:
                content = f.read().upper()
        except OSError:
            continue
        if needle_vid in content and needle_pid in content:
            # uevent path is .../hidraw/hidrawN/device/uevent;
            # the hidraw device node is /dev/hidrawN.
            hidraw_dir = os.path.dirname(os.path.dirname(uevent))
            return f"/dev/{os.path.basename(hidraw_dir)}"
    return None


class HidRaw:
    """Minimal /dev/hidrawN wrapper. One HID report per read/write."""

    def __init__(self, path: str, read_timeout_s: float = 30.0) -> None:
        self.fd = os.open(path, os.O_RDWR)
        self.read_timeout_s = read_timeout_s

    def write(self, frame: bytes) -> None:
        assert len(frame) == HID_REPORT_SIZE
        # Linux /dev/hidraw convention: even when the device's report
        # descriptor uses NO report IDs (as ours doesn't — see
        # nonsecure/src/usb/hid.rs:15 REPORT_DESCRIPTOR), every write
        # must prepend an implicit 0x00 byte. The kernel strips it
        # before delivering to the device.
        os.write(self.fd, b"\x00" + frame)

    def read_frame(self) -> bytes:
        rlist, _, _ = select.select([self.fd], [], [], self.read_timeout_s)
        if not rlist:
            raise TimeoutError(
                f"HID read timeout after {self.read_timeout_s}s — device hang?"
            )
        return os.read(self.fd, HID_REPORT_SIZE)

    def close(self) -> None:
        os.close(self.fd)


# ---------------------------------------------------------------------------
# HID frame fragmentation (mirrors tools/factory-prodtest-runner.py)
# ---------------------------------------------------------------------------

def frame_apdu(apdu: bytes) -> list[bytes]:
    """Split an APDU into 64-byte HID reports with sequence numbers."""
    chan = CHANNEL_ID
    frames: list[bytes] = []

    first = bytearray(HID_REPORT_SIZE)
    first[0] = (chan >> 8) & 0xFF
    first[1] = chan & 0xFF
    first[2] = HID_TAG_APDU
    first[3] = 0x00
    first[4] = 0x00
    first[5] = (len(apdu) >> 8) & 0xFF
    first[6] = len(apdu) & 0xFF
    first_chunk = min(HID_FIRST_DATA, len(apdu))
    first[7 : 7 + first_chunk] = apdu[:first_chunk]
    frames.append(bytes(first))

    off = first_chunk
    seq = 1
    while off < len(apdu):
        f = bytearray(HID_REPORT_SIZE)
        f[0] = (chan >> 8) & 0xFF
        f[1] = chan & 0xFF
        f[2] = HID_TAG_APDU
        f[3] = (seq >> 8) & 0xFF
        f[4] = seq & 0xFF
        c = min(HID_CONT_DATA, len(apdu) - off)
        f[5 : 5 + c] = apdu[off : off + c]
        frames.append(bytes(f))
        off += c
        seq += 1
    return frames


def read_response(hid: HidRaw) -> tuple[int, bytes]:
    """Reassemble one APDU response. Returns (sw, response_data)."""
    buf = bytearray()
    expected = 0
    seq = 0
    while True:
        frame = hid.read_frame()
        if len(frame) < 3 or frame[2] != HID_TAG_APDU:
            print(
                f"[hid] dropping non-APDU frame: tag=0x{frame[2] if len(frame)>2 else 0:02x}",
                file=sys.stderr,
            )
            continue
        r_seq = (frame[3] << 8) | frame[4]
        if r_seq != seq:
            raise IOError(f"HID seq mismatch: expected {seq}, got {r_seq}")
        if seq == 0:
            expected = (frame[5] << 8) | frame[6]
            payload_off = 7
            chunk = min(HID_FIRST_DATA, expected)
        else:
            payload_off = 5
            chunk = min(HID_CONT_DATA, expected - len(buf))
        buf.extend(frame[payload_off : payload_off + chunk])
        seq += 1
        if len(buf) >= expected:
            break
    resp = bytes(buf[:expected])
    if len(resp) < 2:
        raise IOError(f"APDU response too short ({len(resp)} bytes)")
    sw = (resp[-2] << 8) | resp[-1]
    return sw, resp[:-2]


def send_single_apdu(hid: HidRaw, ins: int, p1: int, data: bytes) -> tuple[int, bytes]:
    """Build one CLA INS P1 P2 LC Data APDU + send + read response."""
    assert len(data) <= 255, f"LC overflow: {len(data)} > 255"
    apdu = bytes([APDU_CLA_V2, ins, p1, 0x00, len(data)]) + data
    for frame in frame_apdu(apdu):
        hid.write(frame)
    return read_response(hid)


def send_apdu_chained(
    hid: HidRaw, ins: int, payload: bytes, per_apdu: int = 255
) -> tuple[int, bytes]:
    """Send `payload` chained across multiple APDUs (P1=0x80 ... P1=0x00).

    Empty payload becomes a single APDU with LC=0, P1=0x00.
    """
    if not payload:
        return send_single_apdu(hid, ins, P1_LAST, b"")
    off = 0
    while True:
        chunk = payload[off : off + per_apdu]
        more = off + len(chunk) < len(payload)
        p1 = P1_MORE if more else P1_LAST
        sw, resp = send_single_apdu(hid, ins, p1, chunk)
        off += len(chunk)
        if not more:
            return sw, resp
        if sw != SW_OK:
            # The device rejected an intermediate frame — stop.
            return sw, resp


# ---------------------------------------------------------------------------
# FW-update sequence
# ---------------------------------------------------------------------------

def send_image(hid: HidRaw, kind: int, image: bytes, label: str) -> None:
    """Stream `image` as a sequence of FW_CHUNK APDUs (one chunk per APDU)."""
    off = 0
    n_chunks = 0
    while off < len(image):
        chunk_len = min(MAX_CHUNK_DATA, len(image) - off)
        # Non-final chunks must be QW-aligned (multiple of 16); the
        # device's `write_chunk` only allows the *last* chunk to be a
        # short remainder. Round down for non-final chunks.
        if (off + chunk_len < len(image)) and (chunk_len & 0xF != 0):
            chunk_len &= ~0xF
        chunk_data = image[off : off + chunk_len]
        header = struct.pack(">IBBH", off, kind, 0, chunk_len)
        payload = header + chunk_data
        sw, _ = send_single_apdu(hid, INS_V2_FW_CHUNK, P1_LAST, payload)
        if sw != SW_OK:
            raise RuntimeError(
                f"FW_CHUNK ({label}) at offset {off} failed: SW=0x{sw:04X}"
            )
        off += chunk_len
        n_chunks += 1
    print(f"==> FW_CHUNK {label}: SW_OK ({n_chunks} chunks, {len(image)} bytes total)")


def run_e2e(fixture_dir: str) -> int:
    manifest = open(os.path.join(fixture_dir, "manifest.bin"), "rb").read()
    secure = open(os.path.join(fixture_dir, "secure.bin"), "rb").read()
    nonsecure = open(os.path.join(fixture_dir, "nonsecure.bin"), "rb").read()

    assert len(manifest) == 8192, f"manifest must be 8192 bytes, got {len(manifest)}"
    assert len(secure) % 16 == 0, (
        f"secure must be QW-aligned, got {len(secure)}"
    )
    assert len(nonsecure) % 16 == 0, (
        f"nonsecure must be QW-aligned, got {len(nonsecure)}"
    )

    path = find_hidraw()
    if path is None:
        print(
            f"ERROR: no /dev/hidraw* device for VID:PID {VID:04x}:{PID:04x} — "
            f"is the wallet flashed and enumerated?",
            file=sys.stderr,
        )
        return 1
    print(f"==> Using {path}")
    hid = HidRaw(path)
    try:
        # --- Sanity probe: GET_DEVICE_INFO (no PIN required) ---
        print("==> GET_DEVICE_INFO (sanity probe — no PIN required)...")
        sw, resp = send_single_apdu(hid, INS_V2_GET_DEVICE_INFO, P1_LAST, b"")
        if sw != SW_OK:
            print(
                f"GET_DEVICE_INFO failed: SW=0x{sw:04X} — basic HID transport is broken",
                file=sys.stderr,
            )
            return 1
        print(f"==> GET_DEVICE_INFO: SW_OK, {len(resp)} bytes")

        # --- Sanity probe: GET_STATUS (returns lock state; tells us if PIN is verified) ---
        print("==> GET_STATUS (lock-state probe)...")
        sw, resp = send_single_apdu(hid, INS_V2_GET_STATUS, P1_LAST, b"")
        if sw != SW_OK:
            print(
                f"GET_STATUS failed: SW=0x{sw:04X}",
                file=sys.stderr,
            )
            return 1
        print(f"==> GET_STATUS: SW_OK, payload={resp.hex()}")

        print(
            f"==> FW_BEGIN: sending {len(manifest)}-byte manifest as chained APDUs..."
        )
        sw, _ = send_apdu_chained(hid, INS_V2_FW_BEGIN, manifest)
        if sw != SW_OK:
            print(f"FW_BEGIN failed: SW=0x{sw:04X}", file=sys.stderr)
            # Post-failure GET_STATUS — did pin_verified get cleared during
            # the chained send?
            sw2, resp2 = send_single_apdu(hid, INS_V2_GET_STATUS, P1_LAST, b"")
            print(
                f"   post-fail GET_STATUS: SW=0x{sw2:04X} payload={resp2.hex()}",
                file=sys.stderr,
            )
            return 1
        print("==> FW_BEGIN: SW_OK")

        send_image(hid, FW_IMAGE_KIND_SECURE, secure, label="secure")
        send_image(hid, FW_IMAGE_KIND_NONSECURE, nonsecure, label="nonsecure")

        print("==> FW_COMMIT...")
        sw, _ = send_apdu_chained(hid, INS_V2_FW_COMMIT, b"")
        if sw != SW_OK:
            print(f"FW_COMMIT failed: SW=0x{sw:04X}", file=sys.stderr)
            return 1
        print("==> FW_COMMIT: SW_OK (test-mode — no OTP / no reset)")

        print()
        print(
            "=== PASS — FW-update transport e2e: BEGIN + CHUNKs + COMMIT all green ==="
        )
        return 0
    finally:
        hid.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--fixture-dir",
        default="target/fwup-test",
        help="Directory with manifest.bin / secure.bin / nonsecure.bin "
        "(generated by `cargo run -p fwsign -- gen-test-fixture`)",
    )
    args = ap.parse_args()
    return run_e2e(args.fixture_dir)


if __name__ == "__main__":
    sys.exit(main())
