# A/B rollback FSBL resource map and simplification receipt

Date: 2026-07-11
Scope: Draft-0.8 software-only warning work; no production or hardware authority

This receipt remains frozen provenance for the isolated warning proxy.
Historical Draft 0.9 is bound to tag `rollback-architecture-v0.9` and SHA-256
`f38b90307f15b87a65e9dc9d69583a74775fe4f77385e8b3a84978c34a947336`;
it never turned this proxy into a combined implementation build. The live
[`a-b-firmware-rollback-architecture.md`](a-b-firmware-rollback-architecture.md)
is Draft 1.1 at SHA-256
`743bc156417ff84b5ac201996b07c97db1e53526e2f9a2f59e44a6681ce3d7ad`.
Draft 1.1 is an unapproved research candidate and does not retroactively raise
this receipt's authority.

## Outcome

The target-immutable FSBL warning proxy can be reduced from a 40,268-byte physical
FLASH span to 38,860 bytes while retaining the signature, signed
digest/image, rollback-admission/establishment, ECC, and final fresh-hash
gates. The 1,408-byte reduction puts the proxy only 52 bytes below Draft
0.8's 38,912-byte warning limit.

That result is **AMBER / conditional warning-proxy pass**, not GREEN. The
2 KiB FLASH and 512-byte RAM reservations stand in for interfaces whose final
implementations do not yet exist, and a 52-byte result is within LTO/toolchain
noise. It neither selects an OTP backend nor proves that Foundation A fits.

The corrected pessimistic RAM scenario is also AMBER. The original resource
receipt omitted the 176-byte `commit_confirmed_slot` frame from the deepest
C10 path. Before stack-shape simplification, provisional remaining RAM was
1,212 bytes in the low scenario and only 188 bytes in the high scenario.

## Frozen provenance

- Architecture: A/B rollback Draft 0.8, SHA-256
  `66b0bd6587b14d0f6d048aafff27d66532a7710070912ef2d7de02ef3f10d4b1`.
- Source base: `8d231c24c5bce05ed1b80c0b60eb4007ce6b25d6`.
- Preliminary warning report SHA-256:
  `06760d838cf8df8556b1e19c479eb6566ee5bbc0b56a65634346a2be9098f63d`.
- RAM-correction sidecar SHA-256:
  `09a08438038e4eb225bc8dc43b7d9300643780300cbfd5d648191783edc4a235`.
- Toolchain: `rustc 1.96.0-nightly (9602bda1d 2026-04-05)`, LLVM
  22.1.2, GNU Arm binutils 2.42; release `opt-level="s"`, LTO,
  `codegen-units=1`, overflow checks enabled.
- Link geometry: 40,960 bytes FLASH at `0x0C00_0000`; 16,384 bytes transient
  secure SRAM at `0x3000_0000`.
- The exact 32-byte development vendor key occupied the production-sized
  section, but provides no production-key assurance.

All experiments used the same nonshipping legacy stress source and changed
one cluster at a time. LTO makes the rebuilt delta—not symbol-size addition—
authoritative.

## Byte-level KEEP map

| Cluster | Linked envelope | Rationale |
|---|---:|---|
| Packed BIP-39 prefix table | 6,144 B rodata | Exact measured-boot format; independently saves 4,024 B net |
| Exact STM32U585 IRQ table | 504 B of 568-B vectors | Avoids 1,480 B generic-vector waste |
| SHA-256 and C10 verification | 12,156 B text | Immutable vendor-signature and image-hash root |
| Manifest trust-root FI wrappers | 810 B | Slot, digest, vendor key, signature, rollback admission |
| Image/hash/vector verification | 1,324 B | Rejects torn images and invalid handoff vectors |
| Measured-boot UI | at least 6,971 B explicit table/font/decoder | Trusted display is a product security property |
| Minimal ECC recovery | 104 B text + 2 B BSS currently named | Must grow to reviewed fresh-array ECCC attribution |
| Final fresh handoff validation | required | Exact vectors, bounds, image hash, and sentinel gate |
| Vendor public key | 32 B | Production-sized immutable trust root |

None of these is available as generic headroom.

## REPLACE map

| Rejected prototype cluster | Current envelope | Required replacement |
|---|---:|---|
| Single-QW OTP/MAC implementation | 6,254 B text + 110 B rodata | Typed `Steady/Recovering/Unknown`, replica groups, completion/recovery, fresh ECCC, selected durable stage |
| FI monomorphizations within it | 2,608 B | Only reviewed admission/establishment, close-to-store, and postcondition gates |
| MAC-only key reader/domain | 562 B + 83 B | Removed by plain family, or replaced by redundant reviewed key design |
| Legacy OTP record codec | 930 B | Antichain replica/group codec; not free space |
| Manifest-v3 three-QW decoder | 1,116 B | Manifest-v4 two-QW plus bound TAMP composite decoder |
| Legacy selector | 104 B plus inlining | Confirmed-preserving `(E,R,slot-A)` selector |
| Main-flash ATTEMPTED writer | about 760 B | Secure TAMP `ARM_READY -> ATTEMPTED` transition |
| Legacy journal constants | 32 B rodata | Frozen v4/TAMP domains and codewords |

The direct three-array journal match is especially expensive. The v4 decoder
should use a compact shared exact-equality accumulator and exhaustive
malformed/torn-state tests.

## DEFER map

- Broad complement/sentinel FI beyond the load-bearing boundary checks.
- Expanded reset/handoff assembly as an unreviewed way to solve remanence.
  The warning experiment may omit it for attribution, but production must
  retain or reintroduce an independently reviewed equivalent before claiming
  warm-reset remanence protection.
- DMA/TZSC expansion, production-profile rewrites, option-byte tooling, and
  unrelated factory changes from the research worktree.
- Any layout growth, four-character display change, or security-check removal
  used merely to force a fit.

## Corrected RAM path

The legacy padded path is:

```text
8       Cortex runtime main wrapper
1,296   FSBL main body
176     commit_confirmed_slot
56      filter_valid
32      signature FI wrapper
6,304   verify_signature
280     reconstruct_fors_root
296     sha256_bytes
104     SHA fixed-output finalizer
164     SHA-256 compression
-----
8,716   synchronous
52      alignment + exception/NMI allowance
-----
8,768   corrected known interruptible estimate
```

With the warning receipt's other provisional reservations unchanged:

```text
available     = 15,868 B
required_low  = 14,656 B
required_high = 15,680 B
remaining     = 1,212 B .. 188 B
```

The dominant avoidable cause was LTO inlining the 720-byte fingerprint grid
into `main`, keeping it live across C10 verification and floor establishment.

## Isolated experiments

All FLASH deltas are changes in the physical `PT_LOAD` span from the same
40,268-byte padded proxy.

| Experiment | FLASH delta | Stack/result | Disposition |
|---|---:|---|---|
| Force fingerprint renderer `#[inline(never)]` | -72 B | main 1,296 -> 536 B; render 936 B; deepest path -760 B | KEEP |
| Remove `require_confirmed` immediately before full commit revalidation | -312 B | no stack regression | KEEP in final design |
| Defer expanded SRAM/GPR/control scrub assembly | -64 B | auth unchanged; remanence defense lost | measurement-only; not a shipping deletion |
| Remove second metadata-only handoff sentinel; retain full fresh-hash sentinel | -144 B | full gate remains | KEEP |
| Consolidate two pre-commit binding sentinels | -272 B | two volatile reads/ECC probes and typed target remain | KEEP under single-fault model |
| Make early append target/record checks ordinary fail-closed checks | -280 B | close-to-store and post-scan sentinels remain | KEEP |
| Replace outer pre-store sentinel with an ordinary check | **+64 B** | LTO expanded code | DROP |
| Delete that outer gate entirely | -40 B | insufficient benefit for lost early reject | DROP |
| Compact handoff token while preserving complements for every assembly input | cumulative -304 B beyond prior subset | removes redundant slot guard and unused post-gate digest inverse | KEEP |

The one-at-a-time useful deltas do not add linearly under LTO.

## Cumulative warning candidate

The retained design-candidate subset, including the measurement-only scrub
deferral, linked as:

| Metric | Result |
|---|---:|
| Initialized bytes (`size -B` text+data) | 38,856 B |
| Physical FLASH span | **38,860 B** |
| Draft warning limit | 38,912 B |
| Warning-limit headroom | **52 B** |
| Immutable 40 KiB ceiling headroom | 2,100 B |
| Static RAM end | `0x30000204` |
| Main frame | 424 B |
| Renderer frame | 936 B |
| Commit frame | 176 B |
| Corrected interruptible known path | 7,896 B |
| Provisional RAM slack, low/high | 2,084 B / 1,060 B |

This is a compiler-specific measurement, not an interface guarantee. A final
backend, fresh-ECC primitive, durable stage, toolchain change, or legitimate
new check can consume more than 52 bytes.

## Security adjudication

The independent Opus pass returned **GO WITH RED-LINES** for retaining this as
the next design candidate. Review SHA-256:
`fa1959b1f3de36e8394078844768934b053870f2fca56efad3d8af5675c4c30e`.
Its RAM-arithmetic correction was accepted without changing the verdict;
correction SHA-256:
`e3cb2fb1995c52f91c3f6df1ff3425bd363028581c7416b6a6aa8f4a998b1616`.

The red-lines are:

1. The scrub omission is measurement-only. Restore it or an equivalent
   reviewed remanence defense before production.
2. Report the result as AMBER, never GREEN.
3. Record that pre-write CONFIRMED depth falls from three independent gates to
   one internally double-evaluated gate. This is sound for the stated
   single-fault model, but spends multi-fault margin.

The compact token remains fault-coded for `base`, `signed_len`, `MSP`, and
`reset`, the only values consumed after the final gate. The slot guard is
redundant with exact A/B base identity plus `base_inv`; `digest_inv` is
redundant because the digest is used only inside the double-evaluated fresh
hash gate and is not consumed by handoff assembly.

## Stop conditions

Stop and redesign rather than delete more checks if any final family:

- exceeds 38,912 bytes or the frozen RAM/stack envelope;
- cannot provide fresh per-QW ECC attribution;
- weakens vendor signature, digest/image binding, rollback
  admission/establishment, or final handoff;
- needs an unreviewed FLASH/SRAM enlargement or display-format change; or
- depends on an unproven placeholder to claim GREEN.

Sacrificial OTP/silicon work remains blocked until the owner names the exact
throwaway board and authorizes the irreversible cells separately.
