#!/usr/bin/env python3
"""Push images / test patterns to a real NV3007 panel over a CH347 USB bridge.

Designer workflow:
  1. Wire the panel to the CH347 board (see README.md).
  2. python show.py test          # color bars + orientation 'F' -- sanity check
  3. Export your design as a PNG (ideally 428x142 landscape) from Figma/etc.
  4. python show.py watch mock.png # panel live-updates every time you re-export

Examples:
  python show.py test
  python show.py fill 00FF00
  python show.py image mock.png
  python show.py image mock.png --orient native --fit cover
  python show.py watch designs/        # watch a folder, show the newest PNG
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from PIL import Image

import nv3007
from image_convert import image_to_frame, orientation_test_image, LAND_W, LAND_H


def build_panel(args) -> nv3007.NV3007:
    """Open the CH347 bridge and return an initialised panel."""
    from ch347 import CH347Transport  # lazy: needs pyusb + libusb
    t = CH347Transport(freq_hz=args.freq, dc_gpio=args.dc_gpio, cs_gpio=args.cs_gpio)
    panel = nv3007.NV3007(t)
    if not args.no_init:
        print(f"[nv3007] init @ {args.freq/1e6:.1f} MHz SPI ...", flush=True)
        panel.init()
    return panel


def cmd_test(args) -> None:
    panel = build_panel(args)
    for name, color in (("GREEN", nv3007.GREEN), ("RED", nv3007.RED), ("BLUE", nv3007.BLUE)):
        print(f"[test] fill {name}")
        panel.fill(color)
        time.sleep(0.8)
    print("[test] orientation pattern -- a red 'F' + green arrow -> right.")
    print("       If it's mirrored/rotated, rerun 'image' with --flip-x/--flip-y "
          "or --orient to correct, then note the working combo.")
    frame = image_to_frame(orientation_test_image(), orient="wallet",
                           flip_x=args.flip_x, flip_y=args.flip_y)
    panel.blit_full(frame)


def cmd_fill(args) -> None:
    panel = build_panel(args)
    rgb = int(args.hexcolor, 16)
    r, g, b = (rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF
    c565 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
    print(f"[fill] #{args.hexcolor} -> RGB565 0x{c565:04X}")
    panel.fill(c565)


def _push_image(panel: nv3007.NV3007, path: str, args) -> None:
    img = Image.open(path)
    frame = image_to_frame(img, orient=args.orient, fit=args.fit,
                           flip_x=args.flip_x, flip_y=args.flip_y)
    panel.blit_full(frame)


def cmd_image(args) -> None:
    panel = build_panel(args)
    print(f"[image] {args.path}  orient={args.orient} fit={args.fit} "
          f"flip_x={args.flip_x} flip_y={args.flip_y}")
    _push_image(panel, args.path, args)


def _newest_png(path: str) -> str | None:
    if os.path.isfile(path):
        return path
    pngs = [os.path.join(path, f) for f in os.listdir(path)
            if f.lower().endswith((".png", ".jpg", ".jpeg", ".bmp"))]
    return max(pngs, key=os.path.getmtime) if pngs else None


def cmd_watch(args) -> None:
    panel = build_panel(args)
    print(f"[watch] {args.path} -- re-pushing on change. Ctrl-C to stop.")
    last_sig = None
    while True:
        target = _newest_png(args.path)
        if target:
            try:
                sig = (target, os.path.getmtime(target))
            except OSError:
                sig = None
            if sig and sig != last_sig:
                last_sig = sig
                try:
                    print(f"[watch] push {target}", flush=True)
                    _push_image(panel, target, args)
                except Exception as e:  # keep the loop alive on a mid-write file
                    print(f"[watch] skip ({e})", flush=True)
        time.sleep(args.interval)


def _add_common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--freq", type=float, default=15e6, help="SPI clock Hz (default 15e6)")
    ap.add_argument("--dc-gpio", type=int, default=None,
                    help="CH347 GPIO index wired to the panel DC line (default 6 / CTS)")
    ap.add_argument("--cs-gpio", type=int, default=None,
                    help="CH347 GPIO index for CS (omit to use the CH347 hardware SCS0)")
    ap.add_argument("--orient", choices=["wallet", "native"], default="wallet")
    ap.add_argument("--fit", choices=["contain", "cover", "stretch"], default="contain")
    ap.add_argument("--flip-x", dest="flip_x", action="store_true", default=True)
    ap.add_argument("--no-flip-x", dest="flip_x", action="store_false")
    ap.add_argument("--flip-y", dest="flip_y", action="store_true", default=False)
    ap.add_argument("--no-init", action="store_true", help="skip panel init (already initialised)")


def main() -> int:
    # Common flags live on a parent parser attached to every subcommand, so they
    # work in the natural position AFTER the subcommand:
    #   show.py image x.png --orient native --fit cover
    common = argparse.ArgumentParser(add_help=False)
    _add_common(common)

    p = argparse.ArgumentParser(description="Drive an NV3007 panel via a CH347 USB bridge.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test", parents=[common]).set_defaults(func=cmd_test)
    sp = sub.add_parser("fill", parents=[common]); sp.add_argument("hexcolor"); sp.set_defaults(func=cmd_fill)
    sp = sub.add_parser("image", parents=[common]); sp.add_argument("path"); sp.set_defaults(func=cmd_image)
    sp = sub.add_parser("watch", parents=[common]); sp.add_argument("path")
    sp.add_argument("--interval", type=float, default=0.3, help="watch poll seconds (default 0.3)")
    sp.set_defaults(func=cmd_watch)

    args = p.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[bye]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
