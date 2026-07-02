# VULN — Flash page 126 double-ownership: FW-update COMMIT erases the BHK store → SE050 unpairing brick

- **Severity:** HIGH / CRITICAL (permanent brick), **latent** — dormant while `bhk` is off; detonates the moment `bhk` is enabled.
- **Class:** availability / brick, on the once-a-year firmware-update path.
- **Found:** 2026-07-02 reliability hunt (multi-agent workflow; the finder rated it HIGH, the first-pass verifier REFUTED it on "`bhk` is off by default." That refutation is true-today but dismisses a loaded gun — see below).
- **Status:** compile-time guard landed (`secure/src/hw/bhk.rs`); structural relocation still owed (owner decision).

## Mechanism

Flash **page 126** (`0x0C0F_C000`, bank-1, 8 KB) was the OPTIGA PBS seal page, freed by work-todo #24. It was then re-claimed by **two mutually-incompatible owners**:

1. `secure/src/hw/flash.rs:181` — `FW_FAIL_PAGE_ADDR = 0x0C0F_C000`, the firmware-update verify-failure counter. **Unconditional** (not feature-gated). `flash::fw_fail_reset()` (flash.rs:250) does `erase_secure_page(126)`.
2. `secure/src/hw/bhk.rs:78` — `BHK_PAGE_ADDR = 0x0C0F_C000`, the wrapped-BHK store, under `#[cfg(feature = "bhk")]`.

`fw_fail_reset()` runs on **every successful `CMD_FW_COMMIT`**:
`cmd_fw_commit.rs:290` → `cmd_fw_begin::reset_verify_failure_tally()` → `flash::fw_fail_reset()` → `erase_secure_page(126)`.

Under `bhk`, that erase wipes the wrapped BHK. The SE050 SCP03 session keys **and** the SE050 admin PIN are derived from the BHK (`bhk.rs:21`, `hw/secret_keys.rs`). With the BHK gone they can never be reconstructed → the SE050 is **permanently unpaired** → `half_E` is unreadable → the XOR-split seed is unrecoverable → **hard brick on every device**, triggered by the annual firmware update.

### Two conflicting assumptions, each locally reasonable

- `flash.rs:246-248`: *"the page is dedicated to this counter … so erasing it has no other side effects."*
- `bhk.rs:73-74`: *"Lives in bank 1 so the bank-2-only firmware-update path can never touch it."*

Both are false in each other's presence. The FW-fail counter **is** the FW-update path writing/erasing bank-1 page 126, so the BHK's "bank-2-only" safety assumption does not hold. `bhk.rs:40` even states the contract — *"firmware-update path MUST NOT touch page 126"* — which the FW-fail counter silently violated when it was added.

## Reachability / why it's dormant today

`bhk` is **not** in the production `RELEASE_FEATURES` (Makefile:2017). It is deliberately excluded — but for an **unrelated** reason (Makefile:2014-2016: "enabling it without the phase-2B silicon provisioning yields zero-keyed derivations"), **not** because of this collision. So:

- **Today (bhk off):** page 126 is owned solely by the FW-fail counter; erasing it at COMMIT is correct and harmless. No brick.
- **When phase-2B lands** and someone adds `bhk` to `RELEASE_FEATURES` (it is on the roadmap; `se050/mod.rs` calls a `bhk` build "the shipping target"): the first annual FW-update erases the BHK → brick. Nothing but a stale comment (`bhk.rs:40`) stood between the roadmap and a fleet-wide brick.

The only builds that enable `bhk` today are two dev/e2e bench targets (`Makefile:1190`, `dual-se-bhk-e2e` at `Makefile:2453`), both with `debug-log,e2e-test`. Neither exercises "provision a BHK **then** run a FW-COMMIT on the same device," which is why the collision has never manifested on the bench.

## Fix applied

Compile-time collision guard in `secure/src/hw/bhk.rs` (only compiled when `bhk` is on, so a no-op for today's production + host test suite):

```rust
const _: () = assert!(
    BHK_PAGE_ADDR != flash::FW_FAIL_PAGE_ADDR,
    "page-126 collision: the wrapped-BHK store and the FW-update verify-fail \
     counter both occupy 0x0C0F_C000; every FW-COMMIT erases it, wiping the \
     BHK and permanently unpairing the SE050 (brick on the annual update). \
     Relocate one owner to a free flash page before enabling `bhk`."
);
```

Verified: `cargo check … --features …,saes-dhuk,bhk` now fails with
`error[E0080]: evaluation panicked: page-126 collision …`. Non-`bhk` builds and the host test suite are unaffected (2065/0). This matches the codebase's existing `compile_error!` ship-blocker-fence pattern (`nsc/mod.rs`), and it **auto-clears** once the pages are separated.

## Remaining work (owner decision — NOT done here)

Relocate one owner to a free flash page so `bhk` is shippable. Bank-1 secure pages 123–127 are all claimed (123 offchain, 124 pin-attempts, 125 admin, 126 collision, 127 reserved key storage), so a genuinely-free page must be chosen from the full linker/WRP/FSBL map — hence deferred to the owner. The FW-fail counter is the simpler mover (an 8 KB tally page); BHK's whole lifecycle is documented around page 126. After relocation, the guard above passes automatically.
