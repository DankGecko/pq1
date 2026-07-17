# FV pilot — directional PIN-rollback reconcile (P1.6) — 2026-07-17

> **Scope, first (F9).** A bounded TLA+/TLC model of the DEPLOYED
> `reconcile_pin_attempts` predicate (`secure/src/nsc/mod.rs`) over small
> counters — not the Rust, not the silicon. It checks the reconcile predicate’s
> reachable-state behaviour exhaustively at `Cap=3`; silicon counter/reset/ECC
> behaviour stays a hardware-receipt assumption, and three-way boot
> reconciliation is explicitly NOT modelled or claimed (SE050 is not a reconcile
> input in the shipping policy — invariant #2).

## The question (finding PM-1)

The existing Tamarin model `contracts/verification/tamarin/pin_lockstep.spthy`
proves a property of an **idealized SYMMETRIC** three-counter reconcile (wipe on
*any* disagreement), and its own README/caveat (finding PM-1, 2026-07-02) admits
it **overstates** the deployed check: the shipped reconcile is **directional**,
compares **ordered** counters, and catches *strictly less* than the symmetric
lemmas assert. The overstatement is partly an artifact of Tamarin’s weak
arithmetic — the model had to abstract each counter to a `fresh`/`zeroed`
**status** because Tamarin can’t compare ordered counters cleanly, and that
status-abstraction is exactly what forces the symmetric “any-disagreement-wipes”
idealization. P1.6 is to build the **faithful** directional model.

## The deployed predicate (what we model)

`reconcile_pin_attempts`, shipping dual-SE + `optiga-hw-counter` config:

```
mcu      = pin_attempts_read()          // MCU page-124 count
se_count = optiga E120 count            // SE050 read = None (policy SW=0x6986)
se_split = false                        // dead: needs BOTH legs readable
if se leg unavailable (None): return    // skip — NO wipe
tamper   = (se_count > mcu) || se_split  =  (se_count > mcu)
wipe iff tamper.
```

The directional `>` (not `!=`) relies on a **pre-commit invariant**:
`gated_unlock` precharges page-124 *before* the SE verify, so every benign state
has `mcu >= se_count` (`mcu == se` after both advance, `mcu == se+1` across a
power-cut in the sub-ms window). The model **derives** this rather than assuming
it: an honest wrong-PIN attempt is a **two-phase** bump (`mcu` then `se`), which
makes `mcu >= se` a theorem of honest dynamics and `se > mcu` provably
unreachable without an attack — that is what makes the directional `>` sound.

## The model

`contracts/verification/tla/PinReconcileDirectional.tla` (+ `pin_*.cfg`,
`run_pin.sh`). State = `(mcu, se, pendingSe, legUp, booted, wiped)` + ghosts
`(mcuReset, seReset)`. Two negative-control constants:

- `SymmetricReconcile` — `FALSE` = deployed directional (`se > mcu`); `TRUE` =
  the idealized symmetric variant (`se # mcu`), i.e. the `pin_lockstep.spthy`
  predicate, run as the **labelled negative control**.
- `EnableAttack` — `FALSE` = honest-only play; `TRUE` = the attacker may roll
  back page-124 (`ResetMcu`), reset the SE silicon counter (`ResetSe`), or glitch
  the OPTIGA leg down (`DisableLeg` → `se_used = None`).

## Result — the TWO-SIDED CROSSING (self-checked by `run_pin.sh`)

`Cap=3`. Reproduce: `TLA2TOOLS=/path/to/tla2tools.jar
contracts/verification/tla/run_pin.sh`.

| Check | Config | TLC | Meaning |
|---|---|---|---|
| `INV_BENIGN_MCU_LEADS` | directional, honest | **HOLD** | honest two-phase play keeps `mcu >= se` — the pre-commit invariant is derived, not assumed |
| `INV_ALIVE_NONVACUOUS` | directional, honest | **VIOLATED** | anti-vacuity: a surviving honest boot IS reachable (not trivially always-wipe) |
| `INV_ROLLBACK_DETECTED` | directional, attack | **HOLD** | **deployed positive guarantee**: leg up ∧ `se > mcu` (page-124 rollback) ⟹ WIPE — the property reconcile exists for |
| `INV_NO_LEG_BYPASS` | directional, attack | **VIOLATED** | **residual #2**: glitch the leg down ⟹ a real rollback goes undetected (skip on `None`) |
| `INV_NO_FALSE_WIPE` | **directional**, honest | **HOLD** | directional never false-wipes the benign `mcu == se+1` power-cut … |
| `INV_NO_FALSE_WIPE` | **symmetric**, honest | **VIOLATED** | … but symmetric **false-wipes** it — the availability cost of `!=` |
| `INV_CATCHES_RESET` | **directional**, attack | **VIOLATED** | directional does **not** catch an SE-silicon reset (`se ≤ mcu`) — **the residual** … |
| `INV_CATCHES_RESET` | **symmetric**, attack | **HOLD** | … but symmetric **does** catch it — the detection benefit of `!=` |

The last four rows are the finding: the deployed directional predicate and the
symmetric one are not weaker/stronger but **different points on an
availability-vs-detection trade**. Directional buys availability (never
false-wipes a power-cut) at the cost of not catching an SE-silicon reset;
symmetric buys reset-detection at the cost of false-wiping every power-cut.

## What this establishes (closes PM-1)

1. **The deployed positive guarantee is machine-checked.** `INV_ROLLBACK_DETECTED`
   holds: an MCU page-124 rollback that leaves `se_count > mcu`, with the leg
   readable, is always wiped. This is the real property reconcile provides —
   stated over the *ordered* predicate, not the symmetric idealization.

2. **The directionality is a deliberate design, not an oversight.** The crossing
   shows the symmetric alternative would be strictly worse for availability
   (false-wipes every benign power-cut) — which is *why* the shipped code compares
   `se > mcu` and not `se != mcu`. A one-sided “symmetric catches more” framing
   would miss this; the two-sided control explains the deployed choice.

3. **The two residuals are named precisely.**
   - **SE-silicon-reset residual** (`INV_CATCHES_RESET` VIOLATED, directional):
     an attacker who resets the OPTIGA E120 counter to `≤ mcu` is not caught by
     reconcile. **Severity (DiD framing, carried forward):** this requires the
     attacker to have *already defeated the primary per-SE silicon lockout* — the
     residual is “reconcile adds no DiD against an SE-silicon reset”, **not**
     “reconcile grants attempts”. The primary controls (per-SE silicon lockout +
     the FI-hardened page-124 pre-commit) still bound the attacker to
     `≤ MAX_ATTEMPTS`. No fund-drain.
   - **Leg-availability residual #2** (`INV_NO_LEG_BYPASS` VIOLATED): forcing the
     OPTIGA read to fail (`se_used = None`) makes reconcile skip, disabling the
     whole cross-check — and it defeats *both* predicates (it is orthogonal to the
     directional/symmetric choice, which is why `INV_CATCHES_RESET` is guarded by
     `legUp` to keep the crossing clean).

## Relationship to the Tamarin model

`pin_lockstep.spthy` is **retained as the idealized symmetric upper-bound
contrast** — its lemmas are honest statements about the symmetric idealization
and now serve as the labelled `SymmetricReconcile = TRUE` negative control here.
Its README + header are updated to cross-link this faithful model and mark the
PM-1 follow-up done. The directional arithmetic is deliberately **not** forced
into Tamarin: the status-abstraction its weak arithmetic requires is precisely
what produced the overstatement.

## Residual + out-of-frame (stated honestly)

- **Silicon**: real counter monotonicity, erase/ECC, and reset semantics are
  hardware-receipt assumptions; the model abstracts each counter to a bounded
  natural.
- **`se_split` future config**: the shipping model has `se_split` dead (SE050
  unreadable). A future backend where both legs are readable adds
  `se_split = (optiga != se050)` as a third tamper input — a documented extension
  (a second SE counter variable), not modelled here to keep the model
  deployed-faithful.
- **One boot per trace**: `Boot` is terminal (finite, decidable). Reconcile runs
  at every boot, so the per-boot guarantee proven here is the operative one.

## Files

- `contracts/verification/tla/PinReconcileDirectional.tla` — the faithful model.
- `contracts/verification/tla/pin_*.cfg` + `run_pin.sh` — the 8 pinned checks
  (self-asserting; the crossing + anti-vacuity + positive guarantee must match).
- `contracts/verification/tamarin/{pin_lockstep.spthy, README.md}` — updated to
  demote the symmetric model to a labelled contrast + cross-link (PM-1 closure).
