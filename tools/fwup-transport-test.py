#!/usr/bin/env python3
"""Over-USB FW-update transport e2e test (`make fwup-transport-hw`).

Drives the firmware's FW_BEGIN / FW_CHUNK / FW_COMMIT command sequence
over real USB HID against a device flashed with the `fwup-transport-e2e`
feature. The device runs the FULL state machine + `verify_manifest` +
`verify_images`, then stops at COMMIT *before* the OTP rollback-floor
bump + boot-state write + sys_reset (so the chip stays reflashable for
continued dev work — see secure/src/nsc/cmd_fw_commit.rs).

Test phases:
  1. Sanity probes (GET_DEVICE_INFO, GET_STATUS).
  2. Happy path — BEGIN + CHUNKs + COMMIT all green.
  3. Failure paths — bad magic / bad CRC / bad signature / bad vendor
     fingerprint each rejected by the device with a non-OK SW, no link
     hang. A successful BEGIN between each failure resets the in-RAM
     verify-failure counter so phase 3 doesn't pre-trip phase 4.
  4. Wipe-on-repeated-failure trigger — 5 consecutive bad manifests.
     After the 5th, the device arms the admin-wipe flag and sys_resets
     (Finding B from docs/usb-fw-update-hardening.md). The test waits
     for the USB device to disappear from lsusb and re-enumerate, then
     verifies it's responsive again and runs one valid BEGIN to clear
     the flash-backed counter so the next run starts clean.

PASS criteria: every expected-SW_OK gets SW_OK, every expected-failure
gets a non-OK SW (clamped to SW_CONDITIONS_NOT_SATISFIED per Finding C),
the wipe-trigger run causes a real USB disconnect + re-enumerate, and
the post-wipe device is responsive.

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
import subprocess
import sys
import time
import zlib

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

# Manifest field offsets — mirror fw-manifest/src/lib.rs.
OFF_MAGIC = 0
OFF_VENDOR_FPR = 84
OFF_SIGNATURE = 180
OFF_CRC32 = 8192 - 4

# Verify-failure threshold (in-RAM, see secure/src/nsc/cmd_fw_begin.rs
# `FW_VERIFY_FAIL_THRESHOLD_RAM`). Hitting this count in a single
# power-cycle arms the admin wipe + sys_resets.
FW_VERIFY_FAIL_THRESHOLD_RAM = 5


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


def lsusb_has_device() -> bool:
    """Returns True iff lsusb shows our VID:PID."""
    needle = f"{VID:04x}:{PID:04x}"
    try:
        out = subprocess.check_output(["lsusb"], text=True, timeout=2)
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    return needle.lower() in out.lower()


def wait_for_disconnect(timeout_s: float = 10.0) -> bool:
    """Poll lsusb until the device disappears, or timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not lsusb_has_device():
            return True
        time.sleep(0.2)
    return False


def wait_for_enumerate(timeout_s: float = 30.0) -> bool:
    """Poll lsusb until the device re-appears, or timeout. Also waits a
    short settle period for /dev/hidrawN to be (re-)created by udev."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if lsusb_has_device():
            # Let udev create the /dev/hidrawN node.
            settle_deadline = time.monotonic() + 3.0
            while time.monotonic() < settle_deadline:
                if find_hidraw() is not None:
                    return True
                time.sleep(0.1)
            return find_hidraw() is not None
        time.sleep(0.2)
    return False


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
# Manifest mutations — patch a valid manifest in-memory to exercise each
# branch of the verify chain
# ---------------------------------------------------------------------------

def _recompute_crc(manifest: bytearray) -> None:
    """Rewrite the CRC32 trailer to match bytes [0..8188)."""
    new_crc = zlib.crc32(bytes(manifest[:OFF_CRC32])) & 0xFFFF_FFFF
    manifest[OFF_CRC32:OFF_CRC32 + 4] = new_crc.to_bytes(4, "big")


def mutate_bad_magic(manifest: bytes) -> bytes:
    """Flip the first MAGIC byte. Hits verify_structural → BadMagic."""
    m = bytearray(manifest)
    m[OFF_MAGIC] ^= 0xFF
    return bytes(m)


def mutate_bad_crc(manifest: bytes) -> bytes:
    """Flip a byte in the CRC trailer. Hits verify_crc → BadCrc."""
    m = bytearray(manifest)
    m[OFF_CRC32] ^= 0xFF
    return bytes(m)


def mutate_bad_signature(manifest: bytes) -> bytes:
    """Flip a byte in the SPHINCS+C10 signature field, then re-CRC so
    verify_crc passes and verify_signature is what fails."""
    m = bytearray(manifest)
    m[OFF_SIGNATURE + 7] ^= 0xFF
    _recompute_crc(m)
    return bytes(m)


def mutate_bad_vendor_fpr(manifest: bytes) -> bytes:
    """Flip a byte in the vendor fingerprint, then re-CRC. vendor_fpr is
    NOT part of the signed preimage, so verify_signature still passes;
    the failure mode is verify_vendor_fpr → WrongVendor."""
    m = bytearray(manifest)
    m[OFF_VENDOR_FPR] ^= 0xFF
    _recompute_crc(m)
    return bytes(m)


# ---------------------------------------------------------------------------
# FW-update sequence (happy path)
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


def happy_path(hid: HidRaw, manifest: bytes, secure: bytes, nonsecure: bytes) -> None:
    """BEGIN + CHUNK secure + CHUNK ns + COMMIT, all expected SW_OK."""
    print(
        f"==> [happy] FW_BEGIN: sending {len(manifest)}-byte manifest as chained APDUs..."
    )
    sw, _ = send_apdu_chained(hid, INS_V2_FW_BEGIN, manifest)
    if sw != SW_OK:
        raise RuntimeError(f"[happy] FW_BEGIN failed: SW=0x{sw:04X}")
    print("==> [happy] FW_BEGIN: SW_OK")

    send_image(hid, FW_IMAGE_KIND_SECURE, secure, label="[happy] secure")
    send_image(hid, FW_IMAGE_KIND_NONSECURE, nonsecure, label="[happy] nonsecure")

    print("==> [happy] FW_COMMIT...")
    sw, _ = send_apdu_chained(hid, INS_V2_FW_COMMIT, b"")
    if sw != SW_OK:
        raise RuntimeError(f"[happy] FW_COMMIT failed: SW=0x{sw:04X}")
    print("==> [happy] FW_COMMIT: SW_OK (test-mode — no OTP / no reset)")


def expect_bad_manifest(hid: HidRaw, manifest: bytes, label: str) -> None:
    """Send a mutated manifest via FW_BEGIN and expect a non-SW_OK
    response. Verifies the device cleanly rejects the manifest without
    hanging the link."""
    sw, _ = send_apdu_chained(hid, INS_V2_FW_BEGIN, manifest)
    if sw == SW_OK:
        raise RuntimeError(
            f"[failpath/{label}] expected rejection but device returned SW_OK"
        )
    print(f"==> [failpath/{label}] rejected as expected (SW=0x{sw:04X})")


def reset_fail_counter(hid: HidRaw, manifest: bytes) -> None:
    """Send a valid FW_BEGIN to trigger `record_verify_success()`, which
    zeroes both the in-RAM and the flash-backed verify-failure tallies.
    Used between failure tests so they don't pre-trip the wipe threshold."""
    sw, _ = send_apdu_chained(hid, INS_V2_FW_BEGIN, manifest)
    if sw != SW_OK:
        raise RuntimeError(f"reset BEGIN failed: SW=0x{sw:04X}")


# ---------------------------------------------------------------------------
# Test orchestration
# ---------------------------------------------------------------------------

def open_hid_or_die() -> HidRaw:
    path = find_hidraw()
    if path is None:
        print(
            f"ERROR: no /dev/hidraw* device for VID:PID {VID:04x}:{PID:04x} — "
            f"is the wallet flashed and enumerated?",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"==> Using {path}")
    return HidRaw(path)


def phase_sanity(hid: HidRaw) -> None:
    print("==> [sanity] GET_DEVICE_INFO (no PIN required)...")
    sw, resp = send_single_apdu(hid, INS_V2_GET_DEVICE_INFO, P1_LAST, b"")
    if sw != SW_OK:
        raise RuntimeError(
            f"GET_DEVICE_INFO failed: SW=0x{sw:04X} — basic HID transport broken"
        )
    print(f"==> [sanity] GET_DEVICE_INFO: SW_OK, {len(resp)} bytes")

    print("==> [sanity] GET_STATUS...")
    sw, resp = send_single_apdu(hid, INS_V2_GET_STATUS, P1_LAST, b"")
    if sw != SW_OK:
        raise RuntimeError(f"GET_STATUS failed: SW=0x{sw:04X}")
    print(f"==> [sanity] GET_STATUS: SW_OK, payload={resp.hex()}")


def phase_failure_paths(hid: HidRaw, manifest: bytes) -> None:
    """Exercise each branch of the verify chain.

    Between mutations a successful BEGIN resets both the in-RAM and the
    flash-backed verify-failure counters via `record_verify_success`,
    so this phase contributes at most one outstanding RAM-counter bump
    when it returns to the caller.
    """
    cases = [
        ("bad_magic", mutate_bad_magic),
        ("bad_crc", mutate_bad_crc),
        ("bad_signature", mutate_bad_signature),
        ("bad_vendor_fpr", mutate_bad_vendor_fpr),
    ]
    for label, mutate in cases:
        mutated = mutate(manifest)
        assert len(mutated) == 8192
        expect_bad_manifest(hid, mutated, label)
        # Successful BEGIN clears the failure tally — keeps phase 4
        # independent of how many mutations we run here.
        reset_fail_counter(hid, manifest)
        print(f"==> [failpath/{label}] counter reset via valid BEGIN")


def detach_probe_rs() -> None:
    """Kill any `probe-rs run` holding the SWD link and wait for the
    ST-LINK to actually release.

    Why: a firmware-initiated `sys_reset` while probe-rs is attached
    trips vector-catch — the core halts at the reset vector and USB
    never re-enumerates (memory `probe-rs-reset-halts-core`). For the
    wipe-trigger phase we need the device to actually re-boot itself,
    so we let probe-rs go. The Makefile target re-`pkill`s at the end
    of the test as a safety net.
    """
    print("==> [wipe] detaching probe-rs so sys_reset can boot cleanly")
    # Kill probe-rs AND the timeout(1) wrapper the Makefile uses.
    subprocess.run(["pkill", "-f", "probe-rs run"], check=False)
    subprocess.run(["pkill", "-f", "timeout 120 probe-rs"], check=False)

    # Wait until no `probe-rs` process is left. ST-LINK takes a moment
    # to release the SWD link once the host disconnects; 2 s is
    # empirically sufficient.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        rc = subprocess.run(
            ["pgrep", "-f", "probe-rs run"],
            capture_output=True,
            check=False,
        )
        if rc.returncode != 0:
            break
        time.sleep(0.2)
    time.sleep(2.0)


def phase_wipe_trigger(hid: HidRaw, manifest: bytes) -> HidRaw:
    """Drive `FW_VERIFY_FAIL_THRESHOLD_RAM` consecutive bad-manifest BEGINs.

    The 5th one tips the in-RAM counter to the threshold; the device
    arms the admin-wipe flag and `sys_reset`s. We then wait for USB
    disconnect, USB re-enumerate, and re-open hidraw. A final valid
    BEGIN clears the flash-backed counter so subsequent test runs
    start clean.

    Returns the re-opened HidRaw (the caller closes it).
    """
    bad = mutate_bad_signature(manifest)

    # First (threshold - 1) bad BEGINs must each return a non-OK SW
    # *and* the device must remain on the bus.
    for i in range(1, FW_VERIFY_FAIL_THRESHOLD_RAM):
        sw, _ = send_apdu_chained(hid, INS_V2_FW_BEGIN, bad)
        if sw == SW_OK:
            raise RuntimeError(
                f"[wipe] bad BEGIN #{i} returned SW_OK — verify_signature "
                f"didn't reject"
            )
        print(
            f"==> [wipe] bad BEGIN #{i}/{FW_VERIFY_FAIL_THRESHOLD_RAM} "
            f"rejected (SW=0x{sw:04X})"
        )

    # Drop the SWD attachment before the wipe trigger fires (otherwise
    # vector-catch holds the core halted post-reset and USB never
    # comes back).
    detach_probe_rs()

    # The threshold-th BEGIN should arm the wipe and sys_reset. The
    # device may or may not get a response frame out before the reset
    # fires, so we tolerate timeout/IOError here and pivot to checking
    # USB-bus state instead.
    print(
        f"==> [wipe] sending bad BEGIN #{FW_VERIFY_FAIL_THRESHOLD_RAM} "
        f"— expect device sys_reset"
    )
    hid.read_timeout_s = 8.0
    try:
        sw, _ = send_apdu_chained(hid, INS_V2_FW_BEGIN, bad)
        print(
            f"==> [wipe] device responded with SW=0x{sw:04X} before reset "
            f"(may still reset after)"
        )
    except (TimeoutError, IOError, OSError) as e:
        print(f"==> [wipe] expected error mid-reset: {type(e).__name__}: {e}")

    hid.close()

    print("==> [wipe] waiting for USB disconnect (required — proves "
          "sys_reset fired)...")
    if not wait_for_disconnect(timeout_s=10.0):
        raise RuntimeError(
            "[wipe] device did NOT disconnect within 10s — sys_reset did "
            "not fire after the 5th bad BEGIN"
        )
    print("==> [wipe] USB disconnect observed — wipe trigger fired ✓")

    # Firmware-driven re-enumeration (task #26): `cc_open_then_reset`
    # holds the USB-C CC lines open long enough for the host's typec
    # port controller to register a real detach, then sys_resets — so
    # the post-reset dead-battery Rd looks like a fresh attach and the
    # device re-enumerates with NO physical replug. End-to-end latency
    # is dominated by device boot (~15-25 s in this e2e build, which
    # re-provisions on every boot) + the host's typec/VBUS cycle.
    print("==> [wipe] waiting for firmware-driven USB re-enumerate "
          "(cc_open_then_reset, up to 90s)...")
    if not wait_for_enumerate(timeout_s=90.0):
        raise RuntimeError(
            "[wipe] device did NOT re-enumerate within 90s — the "
            "cc_open_then_reset re-attach path regressed (it has worked "
            "before: device comes back ~20-25s after the disconnect). "
            "Check VBUS/CC wiring + that the host typec subsystem is healthy."
        )
    print("==> [wipe] USB re-enumerated automatically (no replug) ✓")
    hid2 = open_hid_or_die()
    sw, _ = send_single_apdu(hid2, INS_V2_GET_DEVICE_INFO, P1_LAST, b"")
    if sw != SW_OK:
        raise RuntimeError(
            f"[wipe] post-reset GET_DEVICE_INFO failed: SW=0x{sw:04X}"
        )
    print("==> [wipe] post-reset device responsive (GET_DEVICE_INFO: SW_OK) ✓")

    # Best-effort flash-counter reset for the NEXT run's hygiene. This
    # is a heavy chained BEGIN (~33 APDUs) over a freshly-re-enumerated
    # link, which is the most transport-fragile op in the whole test —
    # if it hangs we don't fail the run (the re-enumeration itself is
    # the thing under test, and it already passed above). A stale flash
    # counter at worst trips the lifetime wipe a few runs sooner.
    try:
        reset_fail_counter(hid2, manifest)
        print("==> [wipe] flash-backed counter reset via post-recovery BEGIN ✓")
    except (TimeoutError, IOError, OSError) as e:
        print(
            f"==> [wipe] post-recovery counter-reset BEGIN did not complete "
            f"({type(e).__name__}) — non-fatal, re-enumeration already "
            f"validated. Flash counter may carry over to the next run."
        )
    return hid2


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

    hid = open_hid_or_die()
    try:
        phase_sanity(hid)
        happy_path(hid, manifest, secure, nonsecure)
        phase_failure_paths(hid, manifest)
        hid = phase_wipe_trigger(hid, manifest)

        print()
        print(
            "=== PASS — FW-update transport e2e: sanity + happy + 4 fail-paths "
            "+ wipe-trigger + recovery all green ==="
        )
        return 0
    finally:
        try:
            hid.close()
        except Exception:
            pass


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
