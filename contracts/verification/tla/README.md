# TLA+/TLC models (FV-surface expansion)

First pilot of the formal-verification-surface expansion program
(`docs/verification/fv-surface-expansion-inventory-2026-07-16.md`).

## `Page123Compaction.tla` — page-123 compaction crash-atomicity

Bounded TLA+/TLC model of the STM32U585 page-123 log-structured off-chain
signing-counter store (`secure/src/hw/flash.rs`). Tests the flash.rs F3
crash-atomicity claim that replaying `USEROP_SIGS` first per slot keeps a
torn compaction from rolling back a registered slot's few-time-key tally.

**Read the full report + scope caveats first:**
`docs/verification/fv-pilot-page123-crash-atomicity-2026-07-16.md`.
This is a **bounded model** of the algorithm under stated assumptions —
`model ≠ implementation ≠ hardware`, not a universal proof.

### Run

```sh
# fetch the checker once (single jar), then:
TLA2TOOLS=/path/to/tla2tools.jar ./run.sh
# (or drop tla2tools.jar in $HOME). https://github.com/tlaplus/tlaplus/releases
```

`run.sh` is a self-checking harness: it asserts each of the 5 pinned configs
produces its expected PASS/VIOLATED outcome and exits non-zero on any mismatch
(the same anti-vacuity discipline as the repo's other FV gates). The wrong
replay order (`sigslast_skip.cfg`) MUST reproduce the rollback, or the model is
vacuous.

| cfg | replay | torn model | invariant | expect |
|---|---|---|---|---|
| `sigsfirst_skip` | SigsFirst | Skip | `INV_SIGS_COMPACTION_LOCAL` | PASS — F3 claim confirmed |
| `sigslast_skip` | SigsLast | Skip | `INV_SIGS_COMPACTION_LOCAL` | VIOLATED — negative control |
| `sigsfirst_mayvalid` | SigsFirst | MayValid | `INV_SIGS_COMPACTION_LOCAL` | VIOLATED — no per-entry integrity tag (Finding 1) |
| `endtoend_sigsfirst_skip` | SigsFirst | Skip | `INV_SIGS_NO_ROLLBACK` | VIOLATED — local reset, backstopped by inv#9+on-chain (Finding 2) |
| `cnt_sigsfirst_skip` | SigsFirst | Skip | `INV_CNT_NO_ROLLBACK` | VIOLATED — documented residual |

Not CI-gated (needs a JVM + tla2tools.jar; TLA+ is a new, local tool for the
project). Treat like `verify-easycrypt` / `verify-kontrol`: a local gate.
