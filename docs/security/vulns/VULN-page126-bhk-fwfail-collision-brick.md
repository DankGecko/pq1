# VULN — Flash page 126 double-ownership: FW-update COMMIT erases the BHK store → SE050 unpairing brick

- **Severity:** HIGH / CRITICAL (permanent brick), **latent** — dormant while `bhk` is off; detonates the moment `bhk` is enabled.
- **Class:** availability / brick, on the once-a-year firmware-update path.
- **Found:** 2026-07-02 reliability hunt (multi-agent workflow; the finder rated it HIGH, the first-pass verifier REFUTED it on "`bhk` is off by default." That refutation is true-today but dismisses a loaded gun — see below).
- **Status:** **RESOLVED in current code.** The persistent firmware-update
  verify-failure counter was removed; page 126 now has one owner, the wrapped
  SE050 BHK. The mechanism below is the historical as-found state and must not
  be read as a current page map.

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

## Reachability in the as-found tree

`bhk` was **not** in the production `RELEASE_FEATURES`. It was deliberately
excluded for an unrelated provisioning reason, not because of this collision.
At discovery time:

- **Then-current default (`bhk` off):** page 126 was owned solely by the
  FW-fail counter; erasing it at COMMIT was harmless in that build.
- **If phase-2B had landed without a fix:** adding `bhk` to
  `RELEASE_FEATURES` would have made the first firmware-update COMMIT erase the
  BHK and brick the device.

The only builds that enabled `bhk` in that snapshot were dev/e2e bench
targets. Neither exercised "provision a BHK **then** run a FW-COMMIT on the
same device," which is why the collision had not manifested on the bench.

## Initial containment (historical)

The first containment added this compile-time collision guard in
`secure/src/hw/bhk.rs`:

```rust
const _: () = assert!(
    BHK_PAGE_ADDR != flash::FW_FAIL_PAGE_ADDR,
    "page-126 collision: the wrapped-BHK store and the FW-update verify-fail \
     counter both occupy 0x0C0F_C000; every FW-COMMIT erases it, wiping the \
     BHK and permanently unpairing the SE050 (brick on the annual update). \
     Relocate one owner to a free flash page before enabling `bhk`."
);
```

At that stage, `cargo check … --features …,saes-dhuk,bhk` failed with
`error[E0080]: evaluation panicked: page-126 collision …`. Non-`bhk` builds and the host test suite are unaffected (2065/0). This matches the codebase's existing `compile_error!` ship-blocker-fence pattern (`nsc/mod.rs`), and it **auto-clears** once the pages are separated.

## Final resolution (current)

The persistent firmware-update verify-failure counter was removed rather than
relocated. Page 126 has one current owner: the DHUK-wrapped SE050 BHK when the
`bhk` feature is enabled. Firmware-update code does not write or erase that
page. The collision guard and prose above describe the historical containment,
not a current build failure or an open relocation task.
