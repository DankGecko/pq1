# Draft 0.9 rollback host-model and resource-warning receipt

Date: 2026-07-13
Scope: isolated pre-silicon research only; no production-backend or hardware authority

## Authority boundary

The governing architecture is the historical object
`git show rollback-architecture-v0.9:docs/security/a-b-firmware-rollback-architecture.md`
(not the mutable repository path, which now contains Draft 1.1), SHA-256
`f38b90307f15b87a65e9dc9d69583a74775fe4f77385e8b3a84978c34a947336`,
preserved by annotated tag `rollback-architecture-v0.9`.

This receipt records executable host models and an early resource warning. It
does **not** approve a manifest parser, journal, floor codec, durable stage,
OTP key layout, physical QW allocation, TAMP representation, ECC primitive,
production implementation, or firmware release. `OPEN-JRN-HW-1`,
`OPEN-JRN-DUR-1`, `OPEN-ECC-1`, `OPEN-OTP-1..3`, `OPEN-RAM-1`,
`OPEN-HLT-1`, `OPEN-HLT-2`, `OPEN-TIME-1`, `OPEN-REL-1`, and `OPEN-C10-1`
remain open. No OTP, TAMP, option-byte, RDP, or hardware state was changed.

## Executable model surface

The nonshipping model set covers:

- exact Draft 0.9 manifest-v4 bytes, signed preimage, normalized CRC, three
  page fixtures, marker/token codewords, and `PQFW_A1` binding, with an
  independent Python standard-library oracle;
- typed journal observations and the composite logical state decoder;
- the confirmed-preserving two-slot selector, including malformed, attempted,
  nonqualifying pending, and two-confirmed ordering cases;
- checked `R/E/T/F` arithmetic, same-epoch zero-write classification, and the
  `Steady` / bound `Recovering` / `Unknown` stage boundary;
- candidate constant-weight antichain records, replica thresholds, global QW
  ownership, abstract durable-preclaim/replacement semantics, stale-token rejection, cuts,
  second cuts, ambiguous completion, quorum degradation, and illustrative
  capacity arithmetic; and
- checked FLASH/RAM envelope arithmetic with an explicit externally supplied
  provenance class. The arithmetic does not inspect an ELF deeply enough to
  prove that a caller's `CombinedDraft09` label is truthful; the final build
  and symbol/section receipt must establish that independently.

These models are specifications and adversarial test fixtures. They are kept
outside the production FSBL and firmware crates. Their physical encodings and
backend operations remain candidates until the architecture's open decisions
and silicon gates close.

The power-cut traces assume that an authoritative abstract stage survives and
can be decoded after the cut. They do not implement or prove torn body versus
activation writes, replicated erasable-journal recovery, erase-unit layout,
stage compaction, or post-`COMPLETE` compaction. Those are precisely the open
durable-stage construction and layout questions; an in-memory model cannot
close them.

In particular, the model's no-admit-after-`begin` guard and newest-committed
group witness are abstract `writer_may_have_begun` / committed-head states. If
a physical implementation allowed either authority to disappear or roll back
together with the state it protects, the model's safety argument would not
apply. This is not a viable route-1 journal construction or a durability proof;
the crash-consistent authenticated encoding remains `OPEN-OTP-3`.

The host codec model also treats current-boot freshness as abstract typestate,
not as a physical monotonic counter or a closed `OPEN-ECC-1` primitive. Every
modeled cut invalidates BASE0, active-clean, and committed-replica authority.
Restoration requires a receipt bound to the new boot epoch, an exact fresh
array read, clean ECC attribution, and the durable launch-time clean binding.
EOP is a launch-time diagnostic required before the abstract durable stage
records the clean transition; EOP itself is neither durable nor re-observable
after reset. Later boots rely on the authenticated logged clean transition
plus a fresh read. Saved receipts from an earlier boot cannot restore
authority.

No QEMU rollback run is claimed for this receipt. The executable QEMU firmware
still contains the quarantined legacy backend, so running it would validate
the wrong state machine and could only create misleading evidence. QEMU
power-cut traces become meaningful after a reviewed nonshipping Draft 0.9
candidate exists; that candidate does not yet exist.

## Early FLASH/RAM warning

At master `6aac004c83ce28deeb27ababe07b4df9832ccc0e`, the current legacy FSBL
was linked in release mode with a production-sized development vendor key and
the explicit `legacy-fw-rollback-unsafe` feature. The relevant command was:

```text
FSBL_ALLOW_DEV_KEY=1
RUSTFLAGS='-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x'
cargo build --locked --release --target thumbv8m.main-none-eabi \
  -p pqsigner-fsbl --features legacy-fw-rollback-unsafe
```

Toolchain: Rust `1.96.0-nightly (9602bda1d 2026-04-05)`, LLVM 22.1.2,
GNU Arm binutils 2.42.

| Metric | Legacy baseline result |
|---|---:|
| Non-empty `PT_LOAD` | `0x0C00_0000..0x0C00_6EA0` |
| Physical FLASH span | 28,320 B |
| Gap to the current legacy 32,768-B linker ceiling | 4,448 B |
| Arithmetic gap to 38,912-B warning target | 10,592 B |
| Arithmetic gap to immutable 40,960-B ceiling | 12,640 B |
| `__edata` / `__ebss` | `0x3000_0000` |
| `_stack_start` | `0x3000_4000` |
| Static-address gap | 16,384 B |

The current linker still encodes the quarantined 32-KiB FSBL / manifest-A at
`0x0C00_8000` geometry. Draft 0.9's coordinated 40-KiB geometry moves
manifest A to `0x0C00_A000` and removes the legacy boot-state page; that layout
is not implemented or validated by this baseline link.

This is **not usable headroom**. The linked image contains the quarantined
legacy manifest/journal/floor path and omits the Draft 0.9 V4 decoder, typed
composite journal, fresh per-QW ECC attribution, replica codec, durable stage,
completion/recovery, and their final FI boundary. The 16-KiB static-address
gap is likewise not a worst-case normal/recovery/ECC-NMI stack proof.

The earlier 38,860-byte Draft 0.8 warning proxy remains **AMBER** with only 52
bytes below the warning target. It uses placeholder reservations and is not a
combined Draft 0.9 candidate. Its frozen provenance remains in
[`fw-rollback-fsbl-resource-map-2026-07.md`](fw-rollback-fsbl-resource-map-2026-07.md).

Therefore the current resource conclusion is **AMBER / unresolved**: the
arithmetic and measurement method are ready, but no final candidate exists to
measure. A future combined candidate must report its physical load span,
authoritative static end, worst-case stack including recovery and ECC-NMI,
guard/margin policy, and pass the 38,912-byte warning limit without weakening
a security requirement.

## Capacity comparisons

For a hypothetical 26-QW allocation, the host model records the following
comparison arithmetic only:

| Family | Illustrative epoch commitments |
|---|---:|
| Single QW (rejected comparison) | 26 |
| Two QWs (not sufficient by itself) | 13 |
| Three clean replicas | 8 |
| Three replicas with two fixed recovery-margin QWs | 8 |
| Four QWs per epoch | 6 |
| Current host candidate: two planned attempts for each of three roles | 4 |

The eight-epoch three-replica row excludes replacement cells and therefore is
not the capacity of the current six-QW planned-map candidate. Even its
four-commitment figure is before stage-journal overhead and torn-write losses.
These numbers do not select replica count,
degraded threshold, preclaim storage, recovery reserve, MAC versus plain
records, key storage, or a physical QW map. Ordinary releases in the same
security epoch consume zero rollback-record writes; only a security-epoch bump
would consume a commitment.

## Host validation

The final pre-review host run produced:

| Surface | Debug | Release |
|---|---:|---:|
| Manifest-v4 vectors and structural model | 10 passed | 10 passed |
| Composite journal and selector model | 9 passed | 9 passed |
| Typed floor and stage boundary | 13 passed | 13 passed |
| Candidate codec, ownership, cuts, and boot-freshness model | 30 passed | 30 passed |
| Checked resource-envelope arithmetic | 6 passed | 6 passed |

The independent Python oracle reproduced the frozen manifest digest, token
digest, normalized CRC, and all three full-page hashes. Both model crates pass
targeted `clippy --no-deps` with warnings denied, and the touched Rust files
pass `rustfmt --check`. The complete `pqsigner-fsbl-tests` package reports 70
passed and three explicitly ignored QEMU-harness tests; those ignored tests are
not counted as rollback evidence. Diff hygiene is clean.

CI now enrolls the host-only journal, floor/stage, codec, and resource suites
by name. The manifest-v4 integration test remains covered by the existing
`fw-manifest --tests` host job. The real FSBL footprint test remains in its
existing package path and is not misrepresented as a combined Draft 0.9 link.

## Stop condition

The pre-silicon work stops after the host models, warning receipt, and two
independent adversarial model reviews. Section 13 sacrificial-silicon work
remains prohibited until the owner separately names the throwaway
B-U585I-IOT02A and authorizes exact QWs. No result in this receipt supplies
that authorization.
