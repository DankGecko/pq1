# USB HID Setup Guide

> **🟠 Pre-cutover protocol details superseded (2026-04-30 audit).**
>
> The hardware setup, cabling, JP4 configuration, flashing, udev rules, and
> Chrome WebHID flow described below are still correct. The **APDU command set
> shown in §"USB Protocol"** is from the v1 era (CLA `0xE0`, SLH-DSA 17,088-byte
> signatures, INS 0x02/0x04/0x06/0x08/0x0C). It does **not** describe the
> shipping protocol.
>
> Current protocol after the all-C10 cutover is **CLA `0xF0`** with INS
> `0x01..0x74` (see proto/src/lib.rs `INS_V2_*`). Authoritative spec:
>
> - `docs/companion/usb-protocol-v2.md` — wire format, INS table, request/response layouts
> - `docs/companion/companion-app-integration.md` — full integration walkthrough
> - `proto/src/lib.rs` — `INS_V2_*` constants are source of truth
>
> The hardware-setup half of this doc (CN1/CN8/JP4/cables/udev) is preserved
> as-is for board bring-up.

USB HID transport for PQSigner on the B-U585I-IOT02A discovery board.

## Hardware Setup

### Board: B-U585I-IOT02A (MB1551)

**Jumper JP4** must be set to **5V_USB_STLK** (routes ST-LINK 5V to VDDUSB).
This powers the USB transceiver from the ST-LINK debugger connection.

**BT_PWR SELECT (SW5/SW6)**: Default positions (3V3 / USB) are fine.

### Cables

You need **two cables** connected simultaneously:

| Port | Cable | Purpose |
|------|-------|---------|
| **CN8** (micro-USB) | USB-A to micro-B | ST-LINK: flashing + debug + VDDUSB power |
| **CN1** (USB-C) | USB-C to USB-A **or** USB-C to USB-C | USB HID: host communication |

Both USB-A to USB-C and USB-C to USB-C cables are supported on CN1.
With JP4 on 5V_USB_STLK the ST-LINK provides VDDUSB power regardless
of cable type.

## Building

### Auto-provisioned test build (recommended for initial testing)

```bash
make build-hw-usb-test
```

This builds:
- **Secure world**: `mock-se` + `ui-noop` + `e2e-test` (auto-provisions, no interactive wizard)
- **Non-secure world**: `usb` feature (USB HID main loop)

No semihosting — runs standalone without debugger.

### Full build (with real UI/SE, for production)

```bash
make build-hw-usb
```

Requires OLED display + buttons for PIN entry / seed wizard.

## Flashing

```bash
# Flash both worlds
make flash-hw-usb-test

# Or manually:
probe-rs download --chip STM32U585AIIx target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure
probe-rs download --chip STM32U585AIIx target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure

# Configure TrustZone option bytes (one-time)
STM32_Programmer_CLI --connect port=SWD \
    --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
    SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000

# Reset
probe-rs reset --chip STM32U585AIIx
```

After flashing, **unplug and replug the USB-C cable** from CN1 to trigger
fresh USB enumeration.

## Linux: udev rules

Required for non-root access (WebHID, hidapi, etc.):

```bash
sudo cp tools/99-pqsigner.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
# Unplug and replug the USB-C cable
```

Verify:
```bash
lsusb | grep 1209
# Should show: ID 1209:7051 Generic PQSigner OS

ls -la /dev/hidraw*
# PQSigner's hidraw should show crw-rw-rw-
```

## Testing with WebHID (Chrome)

Open `tools/webhid_test.html` in Chrome:

```bash
google-chrome tools/webhid_test.html
```

1. Click **Connect to PQSigner**
2. Select "PQSigner OS" in the device picker
3. Try **GET_APP_CONF** — returns firmware version + device info
4. Try **GET_PUBLIC_KEY** — returns SLH-DSA verifying key (32 bytes)

## USB Protocol

The v1 APDU command set that previously lived here (CLA `0xE0`, the
0x02..0x0C INS table, and SLH-DSA 17,088-byte chunked responses) has been
**removed as superseded** — it does not describe the shipping firmware.

The current wire protocol is CLA `0xF0` with the `INS_V2_*` command set,
signing with SPHINCS+C10 (4008-byte signatures). See:

- `docs/companion/usb-protocol-v2.md` — wire format, INS table, request/response layouts
- `proto/src/lib.rs` — `APDU_CLA_V2` / `INS_V2_*` constants (source of truth)

## Architecture

```
Host PC (WebHID / node-hid / hidapi)
    |
    | USB Full-Speed (12 Mbps)
    |
[64-byte HID reports]           ← USB HID transport
    |
[APDU-over-HID framing]        ← Ledger-compatible
    |
[APDU Command Router]          ← nonsecure/src/usb/commands.rs
    |
[NSC Gateway]                   ← Shared-memory mailbox
    |
[Secure World]                  ← SPHINCS+C10 signing, PIN, ZK verify
```

USB runs entirely in the **non-secure TrustZone world**. The secure
world only handles cryptographic operations via the existing NSC gateway.

## Troubleshooting

**Device not appearing in `lsusb`**:
- Check JP4 is on 5V_USB_STLK
- Unplug and replug USB-C cable after flashing
- Verify ST-LINK micro-USB is also connected (powers VDDUSB)
- USB-C to USB-C: ensure the cable supports data (not charge-only)

**Chrome says "no compatible devices"**:
- Install udev rules and replug the cable
- Verify `ls -la /dev/hidraw*` shows `crw-rw-rw-` for PQSigner

**Device enumerates but doesn't respond**:
- The `e2e-test` build auto-provisions with a test mnemonic
- Without `e2e-test`, the device needs OLED + buttons for first-boot wizard
