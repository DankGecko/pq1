# FV pilot — page-123 compaction crash-atomicity (TLA+/TLC) — 2026-07-16

> **Scope, first (FV-review F9 anti-over-claim).** This pilot verifies a **model**
> of the page-123 compaction *algorithm* under **stated assumptions**, with TLC
> **bounded** model-checking over small constants. It is **not** the Rust, **not**
> the silicon, and **not** a universal proof. `Model ≠ implementation ≠ hardware.`
> A green run means "no crash trace in this bounded model reaches the bad state",
> not "the firmware is crash-safe". This is the first pilot of the FV-surface
> expansion program (roadmap P1.1 / surface `durable-counter-crash-recovery`); it
> is a **new tool** for the project (TLA+/TLC), run as the sanctioned P2 "one
> finite durable-counter model" small pilot — not a monolithic lifecycle theorem.

- **Model:** `contracts/verification/tla/Page123Compaction.tla` (+ `.cfg`s, `run.sh`).
- **Models:** `secure/src/hw/flash.rs` `{compact_page, write_entry, scan_page_into_table, offchain_count_read, is_registered_*}` and `secure/src/offchain_state.rs`.
- **Method:** dual-perspective — my model + an independent GPT-5.6 model from the
  same `flash.rs`; both converged on the invariant, the crash model, and the
  negative control (see "Dual perspective" below).

## What the store does (the target)

Page 123 is a single-flash-page, append-only log of quad-word (QW) entries
`(slot_key, type, count)`, `type ∈ {SIGS = USEROP_SIGS, UO = USEROP, CNT = COUNT}`.
Readback **projects the MAX** count per `(slot, type)`; a slot is **registered**
iff ≥1 entry decodes for it. When the page fills, `compact_page` snapshots the
projection into SRAM, **erases** the page, then **replays** the survivors — a
single page with **no two-phase staging**, so a power loss during replay can tear
it. The shipped design (flash.rs F3 comment) replays **`USEROP_SIGS` first** per
slot, claiming this makes unreachable the dangerous state *"slot registered but
its few-time-key SIGS tally rolled back below its true durable high-water"*
(SIGS has no on-chain backstop, so a rollback re-opens the C10 few-time budget).

## The claim under test, and the negative control

- **Property (`INV_SIGS_COMPACTION_LOCAL`):** a compaction step never lowers a
  slot's SIGS **below the value it had entering that compaction** (a pre-erase
  snapshot). This isolates the *replay-ordering* property from the separate
  "input was already SIGS-less" issue.
- **Negative control** (per the review's own anti-vacuity discipline): the replay
  order is a **model parameter**. The **wrong** order (`SigsLast` = `UO,CNT,SIGS`,
  the pre-F3 order) **must** reproduce the rollback, or the model is vacuous and a
  green run is worthless. It does (see the matrix).
- **Hardware premise, also a parameter (`TornModel`):** a power-interrupted QW
  either reads back **undecodable and is skipped** (`Skip` — what the code assumes,
  matching `parse_entry`'s `Some((0,_,_))` branch) **or** may read back as an
  **arbitrary valid entry** (`MayValid` — there is no CRC / commit marker in the
  QW format, flagged by the independent model).

## Result matrix (TLC, `Slots={a,b}`, `MaxCount=2`, `PageCap=4`)

Reproduce: `TLA2TOOLS=/path/to/tla2tools.jar contracts/verification/tla/run.sh`

| Invariant | ReplayOrder | TornModel | TLC | Meaning |
|---|---|---|---|---|
| `INV_SIGS_COMPACTION_LOCAL` | **SigsFirst** | **Skip** | **PASS** (35 238 states; also **PASS at 1 033 535 states**, PageCap=5/MaxCount=3) | ✅ the shipped F3 ordering claim is **confirmed** under the code's HW premise |
| `INV_SIGS_COMPACTION_LOCAL` | SigsLast | Skip | VIOLATED | negative control fires ⇒ the PASS is **non-vacuous** |
| `INV_SIGS_COMPACTION_LOCAL` | SigsFirst | **MayValid** | **VIOLATED** | **Finding 1** — the QW format has no per-entry integrity tag; safety relies on the hardware giving "torn QW = undecodable" for free |
| `INV_SIGS_NO_ROLLBACK` (end-to-end) | SigsFirst | Skip | **VIOLATED** | **Finding 2** — the *local* tally can reset after a torn total-loss; the model confirms invariant #9 + the on-chain cap are the (load-bearing) backstops, not a hole |

The model encodes **invariant #9** (a bare `COUNT`/`USEROP` write requires the slot
to be already registered — faithful to `cmd_sign_offchain.rs:265`, which refuses an
unregistered slot; only a Type-2 SIGS bump may re-register a lost slot). Rows are
`Slots={a,b}, MaxCount=2, PageCap=4` unless noted.
| `INV_CNT_NO_ROLLBACK` | SigsFirst | Skip | VIOLATED | machine-confirms the **documented** SIGS-vs-COUNT asymmetry (also a non-vacuity check) |

## What is confirmed

Under the stated hardware premise (a torn QW is undecodable and skipped), the
**SIGS-first replay ordering does what the F3 comment claims**: no torn
compaction leaves a *SIGS-present* slot registered with a rolled-back SIGS —
it comes back either intact (SIGS at its pre-compaction value) or fully
unregistered. TLC checks this **exhaustively** over the model, and it holds at
both the default bound (35 238 distinct states) **and** a larger bound
(1 033 535 distinct states, PageCap=5/MaxCount=3), so the PASS is not a
tiny-bound artifact. The negative control (wrong order) reproduces the exact
rollback trace (`compact → erase → replay CNT/UO before SIGS → registered,
SIGS=0`), so the PASS is meaningful. The model also encodes invariant #9
(bare `COUNT`/`UO` writes require a registered slot, per
`cmd_sign_offchain.rs:265`), so it is faithful to how the firmware actually
gates the re-registration path.

## Findings (load-bearing premises the model localized)

**Finding 1 — the QW format has no per-entry integrity tag, so the ordering
guarantee inherits an unverified STM32U5 hardware premise.** This is **not** about
the replay order — under `MayValid` **both** SigsFirst and SigsLast violate
`INV_SIGS_COMPACTION_LOCAL`, for the *same* reason: with no CRC / commit marker, a
torn frontier QW can read back as **any** valid entry, and the adversary just
picks the worst one (TLC's witness: the torn QW meant to write `a.SIGS=2` reads
back as a valid `a.SIGS=0`, registering the slot with a rolled-back tally). Every
log-structured scheme without per-entry integrity has this property; SIGS-first is
not the weak link. What SIGS-first buys is real **only if** the hardware delivers
`Skip`-like behaviour (a torn QW is undecodable and skipped) for free.
`write_quadword_verified` verifies *after a clean write*; it does nothing on power
loss.
→ **Action:** pin the premise with silicon evidence — does a power-interrupted
quad-word program on STM32U5 flash read back as (a) an ECC-uncorrectable fault,
(b) undecodable bytes, or (c) possibly-valid partial bytes? If (c) is reachable,
add a per-entry integrity tag / commit marker or a two-phase commit. Either way,
record "torn QW ⇒ undecodable" as an explicit, named, unverified hardware premise.

**Finding 2 — a positive decomposition, not a hole: the model confirms invariant
#9 and the on-chain cap are load-bearing.** The end-to-end `INV_SIGS_NO_ROLLBACK`
(SIGS never below the **global** true high-water) is violated even by SigsFirst:
a torn compaction that crashes before a slot's SIGS is replayed loses the slot
entirely (unregistered), and the *local* few-time tally is **not recoverable from
flash** (projection resets to 0). The flash layer's guarantee is therefore exactly
the scoped `INV_SIGS_COMPACTION_LOCAL` (compaction is faithful for SIGS-present
slots) — **not** an end-to-end no-rollback. The end-to-end safety is provided,
outside the flash layer, by two mechanisms this pilot's dual-perspective + the code
read confirm are load-bearing:
- **Invariant #9** — `cmd_sign_offchain.rs:265` **refuses** an unregistered slot
  (except the deliberate, loudly-displayed ERC-6492 counterfactual slot-0 reset),
  so a lost slot cannot be silently re-registered by a bare counter write. The
  model **encodes** this guard; without it (an earlier, unfaithful variant) TLC
  reached the rollback via a bare `AppendCnt` — i.e. the model demonstrates the
  guard is not optional.
- **The on-chain combined cap** `slotUses[i] + offchainSigCount[i] < MAX_SLOT_USES`
  — monotonic and unresettable on-chain — is the authoritative backstop for the
  budget a re-registered (tally-reset) slot can spend. `cmd_sign_userop.rs`
  explicitly repairs a partial-compaction-lost `COUNT` up to the `last_userop`
  high-water (its on-chain-backed estimate) before signing.
So this is **not a latent vulnerability**: the local tally reset is real but
bounded by mechanisms the flash-only model cannot see.
→ **Action (follow-up, not a fix):** the P1.5 `query-budget-lifetime-cap` surface —
compose this store with the gateway + on-chain counters and *prove* the released
budget for a re-registered slot is bounded by the on-chain cap. Until then, that
composition bound is a **cited** premise, precisely localized by this pilot.

> **UPDATE 2026-07-17 — P1.5 landed (`fv-pilot-combined-budget-lifetime-2026-07-17.md`).**
> The composition model confirms: the on-chain combined cap **holds across torn
> resets** (`INV_ONCHAIN_CAP`), so **fund-moving / on-chain-landing** few-time-key
> usage is bounded by `MAX_SLOT_USES` regardless of resets — the backstop is real.
> The residual is narrower than "the flash layer doesn't bound it": it is the
> **view-only off-chain margin** (EIP-1271 sigs that never reach the chain), which
> a torn reset can erode past the cap (`INV_MARGIN_BOUNDED` violated ON, and the
> negative control holds OFF — so the reset is the cause). That erosion is bounded
> outside the model by the bootstrap re-registration budget + the physical
> torn-compaction rate, and the excess sigs do not validate on-chain.

**Confirmed residual — the SIGS-vs-COUNT asymmetry.** `INV_CNT_NO_ROLLBACK` is
violated under SigsFirst+Skip, machine-confirming the F3 comment's own honest
statement that a torn `COUNT`/`USEROP` roll-back is possible (bounded elsewhere by
`MAX_OFFCHAIN_GAP` + on-chain monotonicity). This is the "weaker property the
design knowingly accepts", and its reachability is what proves the SIGS PASS is
not vacuous.

## Dual perspective (independent modeling)

An independent GPT-5.6 model built from the same `flash.rs` (no sight of this
model) converged on: the same invariant (`Registered ⇒ Proj(SIGS) ≥ High`), the
same crash taxonomy (clean-between-QW vs torn-during-QW), the **same** negative
control (`UO→CNT→SIGS`), the same weaker-property failure (COUNT rollback, not
bounded at the page level), and — critically — the re-registration gap (Finding 2)
and the torn-decode-valid hazard (Finding 1). The two hazards this pilot reports
are therefore the *intersection* of two independent models, not one modeler's
artifact.

## Abstractions / threats to validity (do not over-read the PASS)

- **Bounded:** `2` slots, counts `0..2`, page cap `4`. TLC explores this finite
  model exhaustively; it is **not** a proof for the real 512-QW page / 7-byte
  counts / 128-slot cap. A larger instance could in principle reach a state this
  one cannot (mitigated by the smallness of the ordering argument, not eliminated).
- **Slot keys** are unique abstract atoms (assumes SHA-256-truncated collision
  freedom).
- **Appends are atomic** (verify-after-write); only compaction replay is torn.
  A torn *single* append is a separate, smaller surface not modeled here.
- **Fail-closed compaction overflow** (`> MAX_ACTIVE_SLOTS` refuses before erase)
  and the `MAX_DISTINCT_SLOTS = 128` un-wedgeable cap are **not** in this model —
  it assumes compaction proceeds; a separate check should cover the refuse path.
- `Model ≠ Rust ≠ silicon` — see the header. The Rust↔model correspondence is by
  inspection, not extraction.

## Files

- `contracts/verification/tla/Page123Compaction.tla` — the model.
- `contracts/verification/tla/*.cfg` — the 5 pinned configs (the matrix rows).
- `contracts/verification/tla/run.sh` — self-checking harness (asserts each of the
  5 expected outcomes; exits non-zero on any mismatch — the same anti-vacuity
  discipline as the repo's other gates). Needs `tla2tools.jar`.
