# PQ1 mainboard — PCB layer artwork

CAM plots for the PQ1 mainboard, revision **V10**, dated 2026-07-15 11:00
(vendor build code `AL_A66_MB_V10_20260715_1100`; `A66` is the ODM's internal
project code for the PQ1 mainboard). Received from the ODM 2026-07-24.

Six-layer stackup, one PDF per copper layer:

| File | Layer |
|------|-------|
| `AL_A66_MB_V10_20260715_1100-TOP.pdf` | L1 — top / component side |
| `AL_A66_MB_V10_20260715_1100-L2.pdf`  | L2 |
| `AL_A66_MB_V10_20260715_1100-L3.pdf`  | L3 |
| `AL_A66_MB_V10_20260715_1100-L4.pdf`  | L4 |
| `AL_A66_MB_V10_20260715_1100-L5.pdf`  | L5 |
| `AL_A66_MB_V10_20260715_1100-BOT.pdf` | L6 — bottom / solder side |

These are **layout artwork (copper plots), not schematics** — there is no
netlist, no reference-designator-to-net mapping, and no BOM here. Schematic
sheets and the BOM are tracked separately.

Scope notes:

- This is the EVT-era board revision. Cross-reference with
  [`../evt-silicon-validation.md`](../evt-silicon-validation.md) and
  [`../evt-debug-pins.md`](../evt-debug-pins.md) before probing anything; the
  debug-pin doc is the authority for which pads are safe to touch.
- Layer artwork is the ODM's output for fabrication. It is a record of what was
  built, not a design-review artifact — no signal-integrity, EMC, or
  tamper/side-channel review is implied by its presence in this repo.
- `*.pdf` is globally `.gitignore`d in this repo (vendor-copyrighted material
  was purged from history before open-sourcing). This directory is an explicit
  exception because the artwork is Freedom Factory IP.
