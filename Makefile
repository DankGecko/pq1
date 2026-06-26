TARGET = thumbv8m.main-none-eabi
RUSTFLAGS_VAR = CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS
VENEERS = $(CURDIR)/target/veneers.o

# CMSE veneers only exist on the real STM32U585 build path (the QEMU
# `mps2-an505` transport uses a shared-memory mailbox instead). The
# linker rejects `--cmse-implib` if no `cmse-nonsecure-entry` symbols
# are present in the secure binary, so we only emit the implib when the
# `stm32u585` cargo feature is selected.
ifneq (,$(findstring stm32u585,$(FEATURES)))
SECURE_CMSE_FLAGS = -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)
NS_VENEERS_FLAG   = -C link-arg=$(VENEERS)
else
SECURE_CMSE_FLAGS =
NS_VENEERS_FLAG   =
endif

# Reproducible-build flags. Rebuilding the same commit on a different
# laptop (or inside CI) must produce byte-identical ELFs so that
# `make measure` yields the same 8 BIP-39 words. The flags below
# normalize three sources of build-host variance:
#
#   1. --remap-path-prefix rewrites any absolute file paths that end up
#      in panic messages / debug info / OUT_DIR references to a stable
#      prefix. Without this, two laptops with different $HOME values
#      produce different ELFs. The /nix/store rule covers the rustc
#      sysroot path embedded by `core` panic messages: under the
#      flake, rust-overlay downloads a per-host prebuilt rustc, so
#      the store hash differs between Linux x86_64 and macOS aarch64
#      and would otherwise leak into .rodata.
#   2. -Wl,--build-id=none strips the GNU build-id note, which is a
#      hash over the other note sections and shifts with any re-link.
#   3. -Wl,--no-insert-timestamp prevents the linker from stamping
#      build time into the PE-ish note sections (ld is usually quiet
#      about this on ELF, but we still pass the flag as a belt-and-
#      braces measure).
#
# SOURCE_DATE_EPOCH is exported for any build script that embeds a
# timestamp. When built from a git checkout it's the commit time
# (deterministic for a given commit); otherwise it falls back to the
# POSIX epoch.
REPRO_REMAP = --remap-path-prefix=$(HOME)/.cargo=/cargo \
              --remap-path-prefix=$(HOME)/.rustup=/rustup \
              --remap-path-prefix=/nix/store=/nix-store \
              --remap-path-prefix=$(CURDIR)=/pqsigner
# The Makefile invokes arm-none-eabi-ld directly (no gcc driver), so linker
# flags are passed bare — not wrapped in -Wl,. arm-none-eabi-ld has
# --build-id= but not --no-insert-timestamp (that one's PE-only).
REPRO_LINK  = -C link-arg=--build-id=none
REPRO_FLAGS = $(REPRO_REMAP) $(REPRO_LINK)

export SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)

# Factored RUSTFLAGS strings for the two firmware worlds. Every target
# that invokes cargo on the ARM tree uses one of these variables so
# reproducibility flags are applied consistently and can't drift.
# Cargo gives CARGO_TARGET_<TRIPLE>_RUSTFLAGS precedence over
# `.cargo/config.toml`, so that file is only a fallback for ad-hoc
# `cargo build` invocations — the canonical flags live here.
RUSTFLAGS_SECURE    = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) $(SECURE_CMSE_FLAGS)
RUSTFLAGS_NONSECURE = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) $(NS_VENEERS_FLAG)
# Variants for hardware targets that unconditionally emit CMSE veneers
# (independent of the $(FEATURES) content — used by the hw- targets).
RUSTFLAGS_SECURE_HW    = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)
RUSTFLAGS_NONSECURE_HW = -C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS) -C link-arg=$(VENEERS)

SECURE_ELF   = target/secure/$(TARGET)/release/sphincs-tz-secure
NONSECURE_ELF = target/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure
FSBL_ELF      = target/fsbl/$(TARGET)/release/pqsigner-fsbl

# Default: mock secure element + semihosting UI mock (no real hardware needed)
# debug-log enables semihosting output from the secure world.
# Remove it for production builds to eliminate all debug strings.
FEATURES ?= mock-se,debug-log,ui-semihosting

# Extract features relevant to the nonsecure crate (it doesn't know about
# mock-se, debug-log, ui-semihosting, etc. — only e2e-test and stm32u585).
NS_FEATURES_LIST := $(strip $(foreach f,stm32u585 e2e-test usb,$(if $(findstring $(f),$(FEATURES)),$(f))))
comma := ,
empty :=
space := $(empty) $(empty)
NS_FEATURES_ARG = $(if $(NS_FEATURES_LIST),--features $(subst $(space),$(comma),$(NS_FEATURES_LIST)),)

.PHONY: all clean secure nonsecure run play play-hw-display run-tropic01 run-hw setup-serial e2e e2e-hw e2e-erc7730-hw e2e-hw-display e2e-hw-dual-se build-hw flash-hw test test-unit test-solidity test-formal-verification verify-theft-free test-key-speed test-update-hw qr-screen measure factory-reset optiga-reset-oids flash-hw-optiga-reset verify-pins

# Supply-chain audit. Hard-fails if any dependency is not cryptographically
# pinned (Cargo.lock checksums, git rev= pins, foundry.lock matching
# checked-out submodules, circuits/package-lock.json SRI integrity,
# dated-nightly rust-toolchain). See tools/verify_pins.sh for the exact
# rules. Every release-path target below depends on this.
verify-pins:
	@tools/verify_pins.sh

all: verify-pins secure nonsecure

secure:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Secure world built (features: $(FEATURES))."

nonsecure: secure
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure $(NS_FEATURES_ARG)
	@echo "==> Non-secure world built."

# Run with mock SE (no real TROPIC01 chip needed).
# We attach semihosting to a dedicated stdio chardev so SYS_READC can read
# from the host terminal — this is what the secure UI mock uses to receive
# "button" input ('l'/'h' = short, 'L'/'H' = long).
run: all
	qemu-system-arm \
		-M mps2-an505 \
		-monitor null \
		-serial null \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF)

# Interactive two-button hardware-wallet emulation. Maps your laptop's
# arrow keys to the two physical buttons:
#   <-           Left button (back / scroll down)
#   ->           Right button (next / scroll up)
#   <- + ->      Confirm (press both arrows together within 150 ms)
#   Esc          Cancel / back
#   Ctrl-C       Quit
# tools/wallet_run.py spawns QEMU under the hood, owns the terminal in
# raw mode, and forwards button events through the existing semihosting
# single-char protocol.
play: all
	@python3 tools/wallet_run.py

# Interactive two-button wallet on real STM32U585 with SSD1306 OLED display.
# Same arrow-key mapping as `play` (QEMU version), but runs on real hardware.
# Display renders on the physical OLED; button input comes from your laptop
# keyboard via probe-rs semihosting READC.
# Requires: ST-LINK connected, SSD1306 OLED wired to PB8/PB9/3V3/GND.
play-hw-display:
	@echo "==> Building secure + nonsecure for interactive OLED play"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-oled,stm32u585,dev-testkey,gpio-buttons
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive wallet (Ctrl-C to quit)..."
	@python3 tools/wallet_run_hw.py

# Interactive two-button wallet on the NV3007 SPI LCD — the PRODUCTION display
# path (`ui-lcd` is the shipping backend as of 2026-06-09). Runs the FULL real
# wizard / PIN / confirm flow (no `lcd-test` short-circuit). Input from the
# physical gpio-buttons (LEFT=PC1/D8, RIGHT=PA8/D9). `ui-lcd` pulls in
# `gpio-buttons` + `spi1-arduino`. Requires: ST-LINK + the NV3007 wired per
# docs/hardware/nv3007-wiring.md (SPI on CN13 D10/D11/D13, DC=PE7/D4, RES→3V3, VCC+BLK→3V3,
# GND) + two buttons on the gpio-buttons pins. The OLED equivalent is
# `play-hw-display` (kept for SSD1306 dev boards).
play-hw-lcd:
	@echo "==> Building secure + nonsecure for interactive LCD play (NV3007)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-lcd,stm32u585,dev-testkey
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Drive the wizard with the physical buttons; streaming logs (Ctrl-C to quit)..."
	@python3 tools/wallet_run_hw.py

# §32 P4/P5 interactive UI test — drive JUST the duress-PIN setup dialogs
# on the real OLED. No SE, no provisioning (mock-se + duress-ui-test
# short-circuits into a dialog loop at boot). Driven by the PHYSICAL
# perfboard buttons (gpio-buttons: LEFT=PC1/D8, RIGHT=PA8/D9; both = OK,
# long-left = cancel) — same input path as `play-hw-display`, so no host
# key-forwarder is needed. wallet_run_hw.py still streams the OLED debug
# lines if you want them.
play-hw-duress-ui:
	@echo "==> Building §32 duress-PIN UI harness (mock-se, dialogs only)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-oled,stm32u585,dev-testkey,duress-ui-test,gpio-buttons
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive duress-UI harness (Ctrl-C to quit)..."
	@python3 tools/wallet_run_hw.py

# One-time chip hardening: set brown-out supervision + SRAM2 auto-erase
# option bytes. Run once per device during provisioning; no need to
# repeat unless the chip has been fully option-byte-reset.
#
# Changes:
#   BOR_LEV   = 3 (~2.7V)   — flash writes abort cleanly below this
#   SRAM2_RST = 0            — silicon erases SRAM2 on every reset
#                              (POR, BOR, SW, watchdog)
#
# Triggers an Option Byte Load (OBL_LAUNCH), which resets the chip.
# Expected side effects: next boot classifies as ResetCause::OptionByte
# in the semihosting log.
#
# After running this once, every subsequent reset hardware-zeroizes
# SRAM2 — put sensitive active-window state there (Stage 2 of the
# brownout hardening roadmap; see docs/security/brownout-hardening.md).
stm32-harden-opts:
	@echo "==> Configuring brown-out supervision + SRAM2 auto-erase"
	@echo "    BOR_LEV=3 (~2.7V), SRAM2_RST=0 (auto-erase on reset)"
	@echo "    This triggers an Option Byte Load — the chip will reset."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes BOR_LEV=3 SRAM2_RST=0
	@echo "==> Option bytes written. Reset triggered. Chip state: hardened."

# Configure /dev/ttyACM0 for TROPIC01 communication
setup-serial:
	@echo "Configuring /dev/ttyACM0 for TROPIC01..."
	stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb
	@echo "Serial port ready."

# Build + run with real TROPIC01 chip via semihosting SPI bridge.
# UI is still mocked over semihosting (the OLED + buttons live on real HW).
# Requires: TROPIC01 TS1302 devkit connected at /dev/ttyACM0
run-tropic01: setup-serial
	$(MAKE) FEATURES=tropic01-se,debug-log,ui-semihosting all
	qemu-system-arm \
		-M mps2-an505 \
		-monitor null \
		-serial null \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF)

# Real STM32U585 hardware build (full): real chip + real OLED + real buttons.
# This target only BUILDS — flashing is done with probe-rs / openocd / etc.
# It will not link until the ui-oled backend is fully wired up.
run-hw:
	$(MAKE) FEATURES=tropic01-se,ui-oled,pka-accel,consumption-mask,stm32u585 all

# Real STM32U585 hardware build (semihosting): mock SE + semihosting UI.
# Uses probe-rs semihosting for I/O — same interactive model as QEMU
# but running on the real Cortex-M33.
build-hw:
	$(MAKE) FEATURES=mock-se,debug-log,ui-semihosting,stm32u585 all

# Flash and run on real STM32U585 via probe-rs + OpenOCD.
# Requires: ST-LINK connected, openocd installed.
#
# Workflow:
#   1. Flash both ELFs via probe-rs (it may clear TZEN during flash)
#   2. (Re-)configure TrustZone option bytes via OpenOCD
#   3. Run the secure world with semihosting I/O
#
# The option byte setup (TZEN, SECWM, SECBOOTADD0) only needs to be done
# once after a chip erase. Subsequent flashes can skip step 2 if OBs are
# already configured.
flash-hw: build-hw
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# Non-interactive automated end-to-end test for the sign dispatch logic.
# Builds both worlds with the `e2e-test` cargo feature, runs them in QEMU
# with stdin closed (no semihosting input needed), captures stdout, and
# asserts that the secure-world dispatcher routed each scenario to the
# right TxKind variant + that every scenario returned NscStatus::Ok.
#
# Scenarios:
#   1. value_transfer   → ValueTransfer
#   2. erc20_known      → Erc20Known     (USDC mainnet, bundle from NS DB)
#   3. blind_sign       → ContractCall   (Uniswap router selector only)
#   4. zk_clear_sign    → ZkClearSign    (Aave V3 supply, VK bundle from NS DB)
#   5. cowswap_pre_sign → ZkClearSign    (GPv2Settlement.setPreSignature,
#                                         in-tree Circom circuit, VK bundle
#                                         from NS DB)
#   6. cowswap_eip712_order → ZkClearSignMsg
#                                       (CowSwap GPv2Order EIP-712 typed-data
#                                        message signing — M4. Native keccak
#                                        digest in the secure world, bound
#                                        to a Poseidon-hashed canonical
#                                        encoding via Groth16. No on-chain
#                                        tx envelope.)
#
# Pass → exits 0. Any missing assertion or non-zero status → exits 1.
e2e:
	@echo "==> Building secure + nonsecure with e2e-test feature (QEMU mailbox transport)"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test
	@echo "==> Running e2e suite under QEMU"
	@# Route semihosting output through a stdio chardev so we see live
	@# progress AND can grep for assertions. `chardev null` (the previous
	@# setting) silently discarded every `hprintln!` line, which masked
	@# real test failures and made hangs invisible. The NS panic handler
	@# uses panic-semihosting's `exit` feature (enabled via the
	@# `e2e-test` cargo feature) so a failed assertion terminates QEMU
	@# instead of looping forever — without that, this target would
	@# never return on any test bug.
	@log=$$(mktemp); \
	qemu-system-arm \
		-M mps2-an505 \
		-monitor null \
		-serial null \
		-nographic \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF) </dev/null 2>&1 | tee $$log; \
	echo "===================================="; \
	fail=0; \
	for line in \
		"\\[NS\\]\\[e2e\\] Scenario 1: register slot 1 on chain A" \
		"\\[NS\\]\\[e2e\\] Scenario 2: repeat sign on chain A slot 1" \
		"\\[NS\\]\\[e2e\\] Scenario 3: rotate to slot 2 on chain A" \
		"\\[NS\\]\\[e2e\\] Scenario 4: register slot 1 on chain B" \
		"\\[NS\\]\\[e2e\\] Scenario 5: Safe approveHash clear-sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5b: verified function-selector bundle" \
		"\\[NS\\]\\[e2e\\] Scenario 5c: cross-check rejects mismatched selector" \
		"\\[NS\\]\\[e2e\\] Scenario 5d: typed walker declines, blind-sign fallback" \
		"\\[NS\\]\\[e2e\\] Scenario 5e: atomic batch sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5f: degenerate 1-tx batch" \
		"\\[NS\\]\\[e2e\\] Scenario 5g: max-size batch" \
		"\\[NS\\]\\[e2e\\] Scenario 5h: empty batch is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5i: truncated inner-tx block is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5j: self-attest typed render" \
		"\\[NS\\]\\[e2e\\] Scenario 5k: self-attest keccak mismatch dropped" \
		"\\[NS\\]\\[e2e\\] Scenario 5l: both selector trailers refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5p: EIP-712 typed sign (kind=2) wire format" \
		"\\[NS\\]\\[e2e\\] Scenario 5q: Safe-wrapped CoW presign clear-sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5r: safe-wrapped presign without zk_v3 is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5s: multiSend (approve+presign) safe-wrapped CoW clear-sign" \
		"\\[NS\\]\\[e2e\\] Scenario 5t: multiSend with a delegatecall record is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 5u: multiSend presign without zk_v3 is refused" \
		"\\[NS\\]\\[e2e\\] Scenario 6: brute-force protection" \
		"\\[NS\\]\\[e2e\\] === All scenarios passed! ==="; do \
		if grep -q "$$line" $$log; then \
			echo "  PASS  $$line"; \
		else \
			echo "  MISS  $$line"; \
			fail=1; \
		fi; \
	done; \
	rm -f $$log; \
	if [ $$fail -eq 0 ]; then \
		echo "==> e2e: ALL ASSERTIONS PASSED"; \
		exit 0; \
	else \
		echo "==> e2e: ASSERTIONS FAILED"; \
		exit 1; \
	fi

# Fully-automated signing benchmark on real STM32U585.
#
# Clocks the MCU to 160 MHz (hw::rcc::init, the default for the stm32u585
# build path) and uses the DWT cycle counter (armed in secure main.rs
# before booting NS) to measure wall-clock time for:
#
#   A) first-sign on a fresh chain  — Type 1 (C11) + slot keygen + Type 2
#   B) 5 x subsequent signs on same chain — Type 2 only (slot cached)
#   C) first-sign on a second chain — another Type 1 data point
#
# The secure crate builds with `e2e-test` so the wallet auto-provisions
# a fixed mnemonic and pre-unlocks the gateway (no PIN UI).  The NS crate
# builds with `bench-key-speed`, which swaps main() for the bench runner
# in `nonsecure/src/bench_key_speed.rs`.
#
# Why this exists: motivates evaluating the SHA-256 hash variant (see
# `docs/SHA256_VARIANT.md`), where the STM32U585 HASH peripheral would
# accelerate signing ~10x vs software Keccak.  This target establishes
# the baseline number.
#
# Requires: ST-LINK connected, STM32_Programmer_CLI on PATH.
# Pass: exits 0 with "[NS][bench] === PASS ===" on stdout.
# Fail: exits 1 if any sign returns non-Ok or the PASS line is missing.
test-key-speed:
	@echo "==> Building secure (e2e-test auto-provision) + NS (bench-key-speed) + SHA-256 HW accel"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features bench-key-speed,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running key-speed bench on hardware (160 MHz)..."
	@echo "    (streaming semihosting output; each [NS][bench] line = one measurement)"
	@log=$$(mktemp -t test-key-speed.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	rc_file=$$(mktemp -t test-key-speed-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if [ "$$rc" != "0" ] && [ "$$rc" != "130" ]; then \
		echo "==> test-key-speed: FAIL (probe-rs exited $$rc)"; \
		exit 1; \
	fi; \
	if grep -q "\[NS\]\[bench\] === PASS ===" "$$log"; then \
		echo "==> test-key-speed: PASS"; \
		exit 0; \
	else \
		echo "==> test-key-speed: FAIL (missing PASS marker)"; \
		exit 1; \
	fi

# Automated, non-destructive test of the firmware-update (CMD_FW_*)
# logic on real STM32U585 hardware.  NS side runs `fwup_hw_test.rs`,
# which walks every FW_* command through its verify chain and rejects
# paths — including a full-chain "valid-but-rollback-rejected" manifest
# that proves structural + CRC + digest + vendor-fpr all work end-to-end.
#
# WHAT THIS DOES NOT DO (on purpose — both are irreversible / destructive
# to the currently-running firmware on the pre-A/B-split branch):
#
#   * Never calls CMD_FW_COMMIT → no OTP rollback bit is burned.
#     (1024 bits of OTP budget per device.  Each COMMIT burns at least
#      one bit, permanently.  This test burns zero.)
#   * Never lets CMD_FW_BEGIN reach `flash::erase_slot(inactive)`.  On
#     the current linker layout the inactive slot's manifest page (page
#     5 @ 0x0C00_A000) still sits inside the running secure firmware's
#     .text region — erasing it would hard-fault the CPU.  We craft the
#     happy-path test manifest with fw_version=0 so it exercises
#     structural / CRC / digest / fpr checks and then rejects at the
#     rollback-floor gate (fw_version > floor is strict, floor >= 0),
#     which is the last check before `erase_slot` would run.
#
# The only first-boot one-way side-effect is `otp::ensure_device_master`
# (burns the per-device OTP master key on first-boot of a blank MCU —
# this happens on every hardware boot of this firmware, not just this
# target, so there is nothing new here).
#
# Requires: ST-LINK connected, STM32_Programmer_CLI on PATH.
# Pass: exits 0 with "[NS][fwup-test] === PASS ===" on stdout.
# Fail: exits 1 if any test case fails or the PASS marker is missing.
test-update-hw:
	@echo "==> Building secure (e2e-test auto-unlock) + NS (fwup-hw-test) + SHA-256 HW accel"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,hw-sha256
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features fwup-hw-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running firmware-update logic test (safe mode)..."
	@echo "    (no COMMIT, no slot erase — nothing irreversible will happen)"
	@log=$$(mktemp -t test-update-hw.XXXXXX.log); \
	rc_file=$$(mktemp -t test-update-hw-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if [ "$$rc" != "0" ] && [ "$$rc" != "130" ]; then \
		echo "==> test-update-hw: FAIL (probe-rs exited $$rc)"; \
		exit 1; \
	fi; \
	if grep -q "\[NS\]\[fwup-test\] === PASS ===" "$$log"; then \
		echo "==> test-update-hw: PASS"; \
		exit 0; \
	else \
		echo "==> test-update-hw: FAIL (missing PASS marker)"; \
		exit 1; \
	fi

# Same e2e suite but on real STM32U585 hardware via probe-rs semihosting.
# Requires: ST-LINK connected, STM32_Programmer_CLI on PATH.
# Phase 5 item 8 — ERC-7730 e2e on real STM32U585 hardware. Drives the
# Scenario 5m + 5p clear-signing paths through probe-rs semihosting +
# arrow-key forwarder. Requires the same hardware bench as `e2e-hw`
# plus a UI device for descriptor confirmation. Stubbed — implementation
# defers to the Phase 5+ EIP-712 descriptor mirror landing first so
# Scenario 5p has a happy path to assert against.
e2e-erc7730-hw:
	@echo "HW required — run on STM32U585 host with probe-rs + ST-LINK +"
	@echo "  the Phase 5+ EIP-712 descriptor mirror landed (handoff item 2)."
	@echo "Until then this target fails by design so CI doesn't silently skip"
	@echo "  the hardware parity gate. See docs/archive/handoff-erc7730-phase5.md item 8."
	@false

e2e-hw:
	@echo "==> Building e2e + stm32u585"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,e2e-test,stm32u585
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running e2e on hardware (Ctrl-C to abort)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Same e2e suite on real STM32U585, but with OLED display output.
# The SSD1306 128x64 OLED is driven via I2C1 (PB8=SCL, PB9=SDA).
# Uses ui-oled instead of ui-semihosting so the UI renders on the
# physical display rather than the probe-rs console.
# Requires: ST-LINK connected, SSD1306 OLED wired to PB8/PB9/3V3/GND.
e2e-hw-display:
	@echo "==> Building e2e + stm32u585 + OLED display"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-oled,e2e-test,stm32u585
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running e2e on hardware with OLED display (Ctrl-C to abort)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Full sign e2e on real STM32U585 with *both* real SEs (OPTIGA
# Trust M + SE050, XOR-split entropy) driving the SSD1306 OLED.
#
# Exercises the post-cutover stateless-slot flow (Type 1 + Type 2,
# cross-chain slot rotation) end-to-end through real silicon:
#   * dual-se   — OPTIGA + SE050 XOR-split provision + unlock
#   * ui-oled   — status on the physical SSD1306 (PB8=SCL, PB9=SDA)
#   * e2e-test  — auto-provisions fixed mnemonic + PIN, pre-unlocks
#                 the gateway (probe-rs cannot serve SYS_READC)
#   * otp-hardcoded-master-key — avoids burning real OTP each run
#                                (same choice as dual-se-admin-wipe-e2e)
#
# Requires: ST-LINK, STM32_Programmer_CLI, OPTIGA Trust M + SE050 on
# the I2C bus, SSD1306 OLED wired to PB8/PB9/3V3/GND.
#
# Watch semihosting for "[NS][e2e] === All scenarios passed! ===".
# OLED will show "e2e Sign N/4" + "T1+T2"/"T2 only" on each sign.
e2e-hw-dual-se:
	@echo "==> Building e2e + stm32u585 + dual-SE (OPTIGA + SE050) + OLED"
	@echo "    WARNING: re-provisions wallet state on BOTH chips with the"
	@echo "    fixed e2e test mnemonic (abandon × 23 || art, PIN 00000000)."
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features dual-se,ui-oled,debug-log,e2e-test,e2e-skip-admin-wipe,stm32u585,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE e2e on hardware..."
	@echo "    (streaming semihosting; looks for 'All scenarios passed!'"
	@echo "     then exits — hit Ctrl-C if it hangs past 2 min)"
	@log=$$(mktemp -t e2e-hw-dual-se.XXXXXX.log); \
	rc_file=$$(mktemp -t e2e-hw-dual-se-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 300 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; \
	  echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if grep -q "All scenarios passed!" "$$log"; then \
		echo "==> e2e-hw-dual-se: PASS"; \
		exit 0; \
	elif grep -q "PANIC\|FAIL" "$$log"; then \
		echo "==> e2e-hw-dual-se: FAIL (see log above)"; \
		exit 1; \
	else \
		echo "==> e2e-hw-dual-se: FAIL (no PASS/FAIL marker; rc=$$rc)"; \
		exit 1; \
	fi

# GTZC1 TZSC + TZIC enforcement validation on real STM32U585 silicon.
#
# Production gate for invariant #4 ("all secrets live ONLY in TrustZone
# secure world"). NS probes each peripheral the secure-world boot path
# marked SECURE in `secure/src/sau.rs` (I2C1/2, AES, HASH, RNG, PKA,
# SAES) via its NS-aliased control register. Each access should be
# RAZ-gated by the AHB bridge and raise NVIC IRQ 8 (GTZC), bumping the
# secure-world `hw::tzic::VIOLATION_COUNT`. The NS driver reads the
# counter back via `nsc_tzic_status` CMSE veneer and asserts.
#
# Secure side:
#   mock-se          — skips dual-SE provisioning (we're not signing)
#   ui-semihosting   — secure-side `[S][TZIC]` lines come out on probe-rs
#   debug-log        — `secure_log!` enabled
#   e2e-test         — pre-unlock + exposes `nsc_tzic_status` veneer
#   stm32u585        — real GTZC1 (not the QEMU MPC fallback)
#   otp-hardcoded-master-key — stable OTP master across re-flashes
#
# NS side:
#   gtzc-test        — replaces interactive main() with probe + assert
#   stm32u585        — real hardware target
#
# Greps for `[NS][gtzc] === PASS ===` on stdout; missing marker = FAIL.
#
# Requires: ST-LINK on B-U585I-IOT02A. Non-destructive (no SE writes,
# no PIN attempts). Safe to re-run.
gtzc-enforcement-hw:
	@echo "==> Building GTZC1 enforcement test (secure + stm32u585 + e2e-test + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,ui-semihosting,debug-log,e2e-test,stm32u585,otp-hardcoded-master-key
	@echo "==> Building GTZC1 enforcement test (NS + gtzc-test + stm32u585)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features gtzc-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running GTZC enforcement validation on hardware..."
	@log=$$(mktemp -t gtzc-enforcement-hw.XXXXXX.log); \
	rc_file=$$(mktemp -t gtzc-enforcement-hw-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 120 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; \
	  echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if grep -q "\[NS\]\[gtzc\] === PASS ===" "$$log"; then \
		echo "==> gtzc-enforcement-hw: PASS — GTZC1 TZSC + TZIC enforcement confirmed"; \
		exit 0; \
	elif grep -q "\[NS\]\[gtzc\] === FAIL" "$$log"; then \
		echo "==> gtzc-enforcement-hw: FAIL — violation counter mismatch (see log above)"; \
		exit 1; \
	else \
		echo "==> gtzc-enforcement-hw: FAIL (no PASS/FAIL marker; rc=$$rc)"; \
		exit 1; \
	fi

# Slice 2 demo: GTZC1 illegal-access → wipe escalation on real
# STM32U585 silicon.
#
# Builds with `tzic-wipe` ON in the secure crate. NS does a single
# probe of HASH_CR's NS alias; the TZIC IRQ fires, runs
# `hw::tzic::trigger_tzic_wipe()` (zeroize SRAM → arm page-125 wipe
# flag → SCB::sys_reset). The NS driver never reaches its
# `SURVIVED` log line — its absence is the pass marker.
#
# probe-rs note: `probe-rs run` arms vector-catch-on-reset, so a
# successful `SCB::sys_reset` from the IRQ is intercepted and
# surfaces as "Firmware exited unexpectedly: Exception" rather
# than a clean reboot loop. That's the EXPECTED success state for
# this harness — the chip *did* reset, probe-rs just caught it.
# On stand-alone power-up the chip reboots normally and the boot-
# time wipe-resume path drives the full SE wipe.
#
# Pass criteria (host-side):
#   * `[NS][gtzc-wipe] probing`  appears exactly 1 time
#   * `[NS][gtzc-wipe] SURVIVED` appears 0 times (wipe preempted)
#
# Side-effect: leaves the page-125 wipe-armed flag set. Subsequent
# boots of a `se050` or `dual-se` build will finish the SE wipe on
# the next boot. Run `make wipe-for-wizard` to clear deliberately,
# or any normal e2e target that includes `factory_reset_admin`.
#
# Requires: ST-LINK on B-U585I-IOT02A.
tzic-wipe-hw:
	@echo "==> Building TZIC wipe demo (secure + stm32u585 + tzic-wipe + e2e-test + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,ui-semihosting,debug-log,e2e-test,stm32u585,otp-hardcoded-master-key,tzic-wipe
	@echo "==> Building TZIC wipe demo (NS + tzic-wipe-test + stm32u585)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features tzic-wipe-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running TZIC wipe demo on hardware (30 s probe-then-reset)..."
	@log=$$(mktemp -t tzic-wipe-hw.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	timeout 30 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1 | tee "$$log" || true; \
	probes=$$(grep -c '\[NS\]\[gtzc-wipe\] probing' "$$log" || true); \
	survived=$$(grep -c '\[NS\]\[gtzc-wipe\] SURVIVED' "$$log" || true); \
	reset_seen=$$(grep -c 'Exception\|Firmware exited' "$$log" || true); \
	echo "===================================="; \
	echo "==> Observed: probes=$$probes  survived=$$survived  reset_intercepted=$$reset_seen"; \
	if [ "$$survived" -gt 0 ]; then \
		echo "==> tzic-wipe-hw: FAIL — saw SURVIVED line; IRQ did not preempt"; \
		exit 1; \
	elif [ "$$probes" -ge 1 ] && [ "$$reset_seen" -ge 1 ]; then \
		echo "==> tzic-wipe-hw: PASS — TZIC IRQ ran wipe path and chip reset (probe-rs intercepted)"; \
		exit 0; \
	else \
		echo "==> tzic-wipe-hw: FAIL — probes=$$probes reset_seen=$$reset_seen"; \
		exit 1; \
	fi

# Real STM32U585 hardware build with USB HID host communication.
# Uses mock SE + semihosting debug output + USB transport.
build-hw-usb:
	$(MAKE) FEATURES=mock-se,debug-log,ui-semihosting,stm32u585,usb all

# USB build with auto-provisioning for standalone testing.
# No debug-log (semihosting BKPT faults without debugger attached).
# Secure world: e2e-test auto-provisions, ui-semihosting for compile compat.
# NS world: usb feature for USB HID main loop.
build-hw-usb-test:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,usb,e2e-test
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> USB test build ready (auto-provisioned, no semihosting)."

# Flash auto-provisioned USB build.
flash-hw-usb-test: build-hw-usb-test
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# mock-se USB build WITH debug-log — boot-trace the USB path over probe-rs
# semihosting (does boot reach USB init / does it fault?). Diagnostic only.
build-hw-usb-test-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,usb,e2e-test,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> mock-se USB test (debug) build ready."

# SE050 + USB build with auto-provisioning for testing.
# Secure world: se050 (real SE via I2C1), ui-noop, USB hardware init, e2e-test auto-provision.
# NS world: usb feature for USB HID main loop.
build-hw-se050-usb-test:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + USB test build ready."

flash-hw-se050-usb-test: build-hw-se050-usb-test
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# SE050 + USB test with semihosting debug output (requires probe-rs attach).
build-hw-se050-usb-test-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,ui-noop,stm32u585,usb,e2e-test,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + USB test (debug) build ready."

flash-hw-se050-usb-test-debug: build-hw-se050-usb-test-debug
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching with semihosting (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# Real SE050 + GPIO hardware buttons + semihosting display.
# The SE050 runs over I2C1 (PB8/PB9 on the Arduino shield), buttons on
# CN13 D8/D9 jumper wires, and the UI renders via probe-rs semihosting.
# Interactive: PIN entry, seed wizard, signing — all on real hardware.
flash-hw-se050-buttons:
	@echo "==> Building SE050 + GPIO buttons + semihosting UI"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,debug-log,ui-semihosting,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SE050 + buttons wallet (Ctrl-C to quit)..."
	@echo "    LEFT=CN13 pin1 (D8), RIGHT=CN13 pin2 (D9), GND=CN13 pin7"
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# GPIO button test: scan Arduino header pins, then test debounced events.
# Requires: jumper wires on CN14 (D8=LEFT, D9=RIGHT, pin7=GND).
button-test:
	@echo "==> Building GPIO button test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features button-test,debug-log,ui-semihosting
	@echo "==> Flashing button test firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running button test (Ctrl-C to quit)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Companion-app QR-code screen in isolation: flash a firmware that
# renders the QR + install URL on the OLED at boot and halts. Nothing
# else runs — no SEs, no PIN flow, no NS world. Power-cycle or press
# reset to re-run. Requires the SSD1306 OLED on I2C1 (PB8/PB9).
qr-screen:
	@echo "==> Building QR-screen test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features qr-screen-test,debug-log
	@echo "==> Flashing QR-screen firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running QR screen (Ctrl-C to quit; the OLED holds the image)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# STSAFE-A110 I2C2 bus probe: detect on-board secure element.
# Scans I2C2 (PH4/PH5) for the STSAFE-A110 at 0x20 and any other devices.
stsafe-probe:
	@echo "==> Building STSAFE-A110 I2C2 probe firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features stsafe-probe,debug-log,ui-semihosting
	@echo "==> Flashing probe firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running I2C2 bus scan (Ctrl-C to quit)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 factory reset: wipe all objects, then halt.
# Run this once to clear stale SE050 state, then flash normal firmware.
# Assumes the stale UserID is at 0x7B06_0000 or 0x7B00_2000 (legacy) and
# the PIN is one of: 00000000, 12345678, 11111111. Each wrong attempt
# consumes one of the SE050's 10 PIN tries against that UserID; a correct
# PIN auto-resets the counter. Status reported on OLED + semihosting:
# clean / wrong-PIN / blocked.
se050-reset:
	@echo "==> Building SE050 factory-reset firmware..."
	@echo "    Assumes dev PIN in {00000000, 12345678, 11111111}"
	@echo "    and stale UserID at 0x7B06_0000 or 0x7B00_2000."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-factory-reset,ui-noop,stm32u585,debug-log
	@echo "==> Flashing reset firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running factory reset (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Full device factory reset: wipe every piece of persistent state that
# accumulates during provisioning + signing, so the device returns to a
# fresh unprovisioned state (as if it had just come off the programming
# line).
#
# What gets wiped:
#   * SE050 data objects — entropy half_E, UserID/PIN, gated objects.
#     Reuses the se050-factory-reset firmware (assumes dev PIN in
#     {00000000, 12345678, 11111111}; a wrong guess consumes one of the
#     SE050's 10 PIN attempts).
#   * All STM32 secure flash — mass-erased via STM32_Programmer_CLI,
#     which clears:
#       - page 124 — MCU PIN-attempt counter (one programmed QW per
#                    attempt; capacity 32, lockout at 10)
#       - page 125 — SE050 admin PIN + crash-safety wipe flag
#       - page 126 — OPTIGA Trust M Platform Binding Secret
#       - page 127 — Tropic01 pairing key slot
#     plus all firmware code — so you WILL need to re-flash afterwards.
#
# What does NOT get wiped:
#   * OPTIGA Trust M internal objects (half_O, auth refs). The firmware
#     currently has no OPTIGA reset path. Losing the PBS on STM32 page
#     126 means the MCU can no longer open a Shielded Connection against
#     those objects, so in practice the OPTIGA side is inert after this
#     target runs, but its silicon still holds the entropy half.
#   * Option bytes (TZEN / SECWM / SECBOOTADD0). Those survive mass
#     erase and the normal flash-hw-* targets re-assert them anyway.
#
# Prompts for confirmation. Requires ST-LINK connected and
# STM32_Programmer_CLI on PATH.
factory-reset:
	@echo "==> FACTORY RESET"
	@echo "    Wipes: SE050 data objects + all STM32 flash (pages 123-127 + firmware)"
	@echo "    You MUST re-flash firmware afterwards — the chip will be blank."
	@printf "    Proceed? [y/N] "; \
		read ans; \
		[ "$$ans" = "y" ] || [ "$$ans" = "Y" ] || { echo "    Aborted."; exit 1; }
	@echo ""
	@echo "==> Step 1/2: building + running SE050 factory-reset firmware"
	@echo "    (20s timeout — proceeds even if SE050 isn't attached)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features se050-factory-reset,ui-noop,stm32u585,debug-log
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	-@timeout 20 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) || true
	@echo ""
	@echo "==> Step 2/2: STM32 mass-erase (wipes all flash pages + firmware)"
	@STM32_Programmer_CLI --connect port=SWD mode=UR -e all
	@echo ""
	@echo "==> Factory reset complete. Chip is blank."
	@echo "    Re-flash firmware to use the device again, e.g.:"
	@echo "      make flash-hw-se050-oled-standalone   # SE050 + OLED, production"
	@echo "      make flash-hw-optiga-oled-standalone  # OPTIGA Trust M + OLED (LcsO=Creation)"
	@echo "      make optiga-factory-reset-hw          # OPTIGA wipe -> next boot = fresh wizard"
	@echo "      make optiga-preprovision-hw           # OPTIGA pre-provisioned w/ PIN=00000000"
	@echo "      make flash-hw-se050-usb-test          # SE050 + USB, auto-provisioned test"

# SE050 factory-reset roundtrip e2e test on real hardware.
# Provisions a fresh test UserID + 2 gated data objects, exercises
# user_factory_reset, then verifies all three objects are gone.
# Uses test object IDs (0x7B07_xxxx) so it doesn't touch any real
# wallet provisioning. Repeatable on the same chip.
# Watch semihosting for "[E2E] FACTORY-RESET ROUNDTRIP: PASS"/"FAIL".
se050-reset-e2e:
	@echo "==> Building SE050 reset-roundtrip e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-reset-e2e,ui-noop,stm32u585,debug-log
	@echo "==> Flashing e2e firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running e2e (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 crash-safety (power-loss mid-wipe) e2e test.
# Two-phase: phase 1 provisions test objects at 0x7B0A_xxxx, writes a
# test admin PIN to flash page 125, arms the wipe flag, deletes ONLY
# the data object, halts. User/Makefile resets the board, simulating
# power loss. Phase 2 boots, detects armed flag, verifies expected
# mid-wipe state, finishes the wipe, erases page 125, reports PASS.
# WARNING: overwrites flash page 125 admin PIN. Only run on a chip
# that hasn't been through first-boot wizard on production firmware.
# Watch semihosting for "PHASE 2 — CRASH-SAFETY RESUME: PASS"/"FAIL".
se050-crash-safety-e2e:
	@echo "==> Building SE050 crash-safety e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-crash-safety-e2e,ui-noop,stm32u585,debug-log
	@echo "==> Flashing crash-safety firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo ""
	@echo "==> PHASE 1: provision + partial wipe + halt"
	@echo "    (Watching for 'PHASE 1 COMPLETE' — 30s timeout)..."
	-timeout 30 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) || true
	@echo ""
	@echo "==> Resetting board (simulated power cycle)..."
	probe-rs reset --chip STM32U585AIIx
	@echo ""
	@echo "==> PHASE 2: boot-time resume"
	@echo "    (Watching for 'CRASH-SAFETY RESUME: PASS' — 30s timeout)..."
	-timeout 30 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) || true

# SE050 admin-auth wipe e2e test.
# Exercises the exact path PIN-lockout factory reset uses: admin UserID
# auth deleting user-gated objects without knowing the user PIN. Uses
# OID range 0x7B09_xxxx so it doesn't touch real provisioning or the
# user-reset e2e range (0x7B07_xxxx). Repeatable on the same chip.
# Watch semihosting for "[E2E-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS"/"FAIL".
se050-admin-wipe-e2e:
	@echo "==> Building SE050 admin-wipe e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050-admin-wipe-e2e,ui-noop,stm32u585,debug-log,e2e-test
	@echo "==> Flashing admin-wipe e2e firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running admin-wipe e2e (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# ---------------------------------------------------------------------------
# SE050 on-silicon stress-test harness — `make se050-stress*`
# ---------------------------------------------------------------------------
# Catalog-driven runner that exercises the SE050 driver against real
# silicon. Tests live under `secure/src/se050_stress/tests/*.rs`;
# adding one is a function + a `stress_test!` macro line + a one-row
# append to `secure/src/se050_stress/tests/mod.rs::ALL_TESTS`. No
# Cargo.toml / Makefile edits per test.
#
# Output channel: `secure_log!` semihosting (probe-rs stdout). The
# recipes scrape the log for `=== SUMMARY: P PASS / F FAIL / S SKIP ===`
# and exit 0 only when F=0.
#
# Carve-out OIDs `0x7B5F_*`; production `0x7B10_*` is never touched.
# Prereq: board has been through `make flash-hw-dual-se-oled-standalone`
# at least once so TrustZone option bytes are set. The recipes below
# do NOT reconfigure them.
#
# `make se050-stress`              — run all Tier::Safe tests
# `make se050-stress-destructive`  — Safe + Destructive (drives UserID
#                                    attempt counters to lockout)
# `make se050-stress-only-<name>`  — single test by name (rebuilt with
#                                    SE050_STRESS_ONLY filter)
# `make se050-stress-list`         — host-side catalog dump (no flash)

SE050_STRESS_FEATURES = se050-stress,ui-oled,stm32u585,debug-log,e2e-test,otp-hardcoded-master-key,usb

# Cache-bust the secure-crate build whenever the SE050_STRESS_* env vars
# change. cargo doesn't include env vars in its fingerprint, so without
# this a re-run with a different filter would silently reuse the prior
# binary. `date +%s` makes every invocation a distinct cfg flag.
#
# Name-only cfg (no `=value`): rustc nightly (≥2026-04 verified) rejects
# `--cfg=name=value` unless the value is a quoted string, and the double
# quotes get stripped by the shell when the variable is interpolated
# inside the recipe's `RUSTFLAGS="..."` assignment. A name-only cfg
# avoids the quoting tangle entirely while still being a unique-per-
# second cargo fingerprint input — the cfg name itself is never queried
# in source code, it just exists to invalidate the build cache.
SE050_STRESS_RUSTFLAGS = $(RUSTFLAGS_SECURE_HW) --cfg=stress_build_$(shell date +%s)

.PHONY: se050-stress se050-stress-destructive se050-stress-list

# Common pass/fail scrape — runs probe-rs, captures stdout, returns
# 0 iff `=== SUMMARY:` appears AND the FAIL count is 0. Parameterised
# so all three recipes share the same shell logic.
#  $(1) = display label
define SE050_STRESS_RUN
	@log=$$(mktemp); rc_file=$$(mktemp); \
	{ timeout 1200 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	if ! grep -q "=== SUMMARY:" "$$log"; then \
		echo "==> $(1): FAIL (no SUMMARY line, probe-rs rc=$$rc, log=$$log)"; exit 1; \
	fi; \
	fail_count=$$(grep "=== SUMMARY:" "$$log" | head -1 | sed -E 's/.* ([0-9]+) FAIL .*/\1/'); \
	if [ "$$fail_count" = "0" ]; then \
		echo "==> $(1): PASS"; rm -f "$$log" "$$rc_file"; exit 0; \
	fi; \
	echo "==> $(1): FAIL ($$fail_count test failures, probe-rs rc=$$rc, log=$$log)"; exit 1
endef

# Run the full Tier::Safe catalog.
se050-stress:
	@echo "==> Building SE050 stress firmware (Tier::Safe)..."
	$(RUSTFLAGS_VAR)="$(SE050_STRESS_RUSTFLAGS)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(SE050_STRESS_FEATURES)
	@echo "==> Flashing stress firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running stress catalog (watch semihosting output)..."
	$(call SE050_STRESS_RUN,se050-stress)

# Run Safe + Destructive tiers (includes UserID-lockout tests).
se050-stress-destructive:
	@echo "==> Building SE050 stress firmware (Safe + Destructive)..."
	SE050_STRESS_TIER=destructive \
	$(RUSTFLAGS_VAR)="$(SE050_STRESS_RUSTFLAGS)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(SE050_STRESS_FEATURES)
	@echo "==> Flashing stress firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running stress catalog (Safe + Destructive)..."
	$(call SE050_STRESS_RUN,se050-stress-destructive)

# Single-test runner — pattern target. Usage:
#   make se050-stress-only-scp03_response_encryption_verify
# Selection happens at build time via `SE050_STRESS_ONLY=<name>`,
# baked into the firmware through `option_env!`. The Tier filter is
# also disabled (`all`) so destructive single-test runs work without
# the user remembering to flip a second flag.
se050-stress-only-%:
	@echo "==> Building SE050 stress firmware (single: $*)..."
	SE050_STRESS_ONLY="$*" SE050_STRESS_TIER=all \
	$(RUSTFLAGS_VAR)="$(SE050_STRESS_RUSTFLAGS)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(SE050_STRESS_FEATURES)
	@echo "==> Flashing stress firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running stress test '$*' (watch semihosting output)..."
	$(call SE050_STRESS_RUN,se050-stress-only-$*)

# Host-side catalog listing — no hardware, no flash. Greps the seed
# catalog files for `stress_test!(IDENT, "name", Tier::X, …)` lines
# and prints them as "[tier] name".
se050-stress-list:
	@echo "==> SE050 stress catalog:"
	@grep -hE '^[[:space:]]*stress_test!\(' secure/src/se050_stress/tests/*.rs 2>/dev/null \
		| sed -E 's/^[[:space:]]*stress_test!\([A-Z0-9_]+,[[:space:]]*"([^"]+)",[[:space:]]*Tier::([A-Za-z]+).*/[\2]\t\1/' \
		| sort -k1,1 -k2,2 \
		| awk -F'\t' '{printf "  %-14s %s\n", $$1, $$2}' \
		|| echo "  (no tests found)"

# SE050 SCP03 platform-key rotation ceremony (work-todo #20 Stage B).
#
# *** IRREVERSIBLE — DO NOT RUN ON A WORKING BENCH SE050 ***
# One-shot GP PUT KEY: replaces SCP03 keyset 0x0B in place with this
# device's derived keys (secret_keys::se050_scp03_*_key, BHK-rooted), then
# halts. The published AN12436 factory keys are GONE after this — the chip
# only opens with firmware that re-derives the matching keys, so:
#  - on a board that ever gets RDP-regressed, the BHK is mass-erased => dead
#    SE050 => half_E unrecoverable. PRODUCTION-PROVISIONING ONLY (RDP2 has no
#    regression path); never flash this to a board you still RDP-bounce.
#  - the PUT KEY APDU framing in scp03::build_put_key_apdu is best-effort
#    from GP 2.3 / AN12436 -- VALIDATE ON SACRIFICIAL PARTS before any real
#    provisioning run (the chip recomputes the KCV/fields and rejects on
#    mismatch, so a rehearsal that returns SW=0x9000 is the real proof).
# Pre-conditions: RDP already at >=1 (so the BHK is its final per-die-DHUK
# value), BHK provisioned, chip factory-fresh. See docs/production-todo.md
# §"SE050 - SCP03 + ADMIN provisioning" + docs/work-todo.md #20.
# Watch the OLED / semihosting for "[SCP03-ROTATE] PUT KEY OK" / "FAIL".
flash-hw-se050-rotate-scp03:
	@echo "==> *** IRREVERSIBLE SCP03 KEY ROTATION -- Ctrl-C now if this is your working bench SE050 ***"
	@echo "==> Building SE050 SCP03-rotation ceremony firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features se050-rotate-scp03,bhk,stm32u585,ui-oled,debug-log,e2e-test
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SCP03 rotation ceremony (watch for [SCP03-ROTATE] PUT KEY OK)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 admin-extract-attempt e2e — NEGATIVE security test.
# Falsifies the load-bearing claim that the two-entry TAG_POLICY (user →
# READ|WRITE|DELETE, admin → DELETE only) is silicon-enforced. Provisions
# a 32-B sentinel on isolated OID range 0x7B0B_xxxx under user-PIN gating,
# then:
#   step 3: user-auth READ must return the sentinel (test setup valid)
#   step 4: admin-auth READ must be REFUSED  ← the security property
#   step 5: same admin session DELETEs all 3 objects (proves admin was real)
# PASS = chip silicon enforced the read deny. FAIL = security regression
# (admin extracted a user-PIN-gated secret — would mean a DHUK/BHK leak
# could drain funds, contrary to the threat model in CLAUDE.md §"Hardware
# PIN gating, three-way lockstep").
# Watch semihosting for "[E2E-EXTRACT] ADMIN-EXTRACT ATTEMPT: PASS"/"FAIL".
# Repeatable on the same chip (step 1 cleans up prior residue).
se050-admin-extract-attempt-e2e:
	@echo "==> Building SE050 admin-extract-attempt e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features se050-admin-extract-attempt-e2e,ui-noop,stm32u585,debug-log,e2e-test,otp-hardcoded-master-key
	@echo "==> Flashing admin-extract-attempt e2e firmware..."
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running admin-extract-attempt e2e (watch semihosting output)..."
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# SE050 + OLED interactive build (real SE050, real OLED display, real buttons).
# Full first-boot wizard: user enters PIN and creates/restores mnemonic.
# Both the SSD1306 OLED and SE050 share I2C1 (PB8/PB9) at 400 kHz.
build-hw-se050-oled:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-oled,stm32u585,usb,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> SE050 + OLED interactive build ready."

# Standalone build: no debug-log, no semihosting. Safe to run with only
# USB-C power and no debugger attached. BKPT-free.
build-hw-se050-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,ui-oled,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Standalone build ready (no semihosting, USB-C only)."

flash-hw-se050-oled-standalone: build-hw-se050-oled-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# Dual-SE + OLED standalone — production-shape dual-chip build (OPTIGA
# Trust M + SE050, XOR entropy split across both). Mirrors the
# `wipe-for-wizard` feature set so the admin PIN is derived from the
# same OTP source and wipe-for-wizard can delete what this target
# provisioned (and vice versa). No semihosting, no debug-log — safe to
# run on USB-C power alone with no debugger attached.
#
# Feature set: `dual-se` (= optiga-trust-m + se050), `optiga-hw-counter`
# (OPTIGA E120 for the PIN-attempt counter), `dev-testkey` (stable OTP
# master across flashes so the derived SE050 admin PIN matches what
# wipe-for-wizard derives), `ui-oled`, `gpio-buttons`, `stm32u585`,
# `usb`. Deliberately DOES NOT include `optiga-lock-operational`;
# every OPTIGA user OID stays at LcsO=Creation through provisioning.
#
# Invariants respected:
#   #1 dual-chip seed split (half_O on OPTIGA, half_E on SE050).
#   #2 hardware-level PIN gating (OPTIGA auth-ref + SE050 UserID).
#   #3 E2E encrypted tunnels (Shielded Connection + SCP03) — STRUCTURE only on
#      this BENCH target: `dev-testkey` roots the OPTIGA PBS in a compile-time
#      constant and `se050-derived-scp03` is OFF, so the SE050 SCP03 channel runs
#      on the PUBLISHED AN12436 factory keys. Both are bus-sniffable here — fine
#      for bench (dev-testkey is a non-shipping marker), NOT confidential. A
#      SHIPPING build must add `se050-derived-scp03` (+ saes-dhuk/bhk PBS) and a
#      rotated chip; the `nsc/mod.rs` HIGH-1 fence enforces the build side.
#   #4/#5/#6/#7/#8 — all in force; this is just a feature-set wrapper.
#
# Intended workflow for bench iteration:
#   1. `make wipe-for-wizard`   — nukes OPTIGA F1Dx/E1Ex + SE050
#                                 user+admin+canary objects, halts.
#   2. Disconnect ST-LINK and USB-C, reconnect USB-C only.
#   3. `make flash-hw-dual-se-oled-standalone` (this target) — flashes
#      the standalone firmware. First boot: chip is unprovisioned, OLED
#      shows the first-boot wizard, user enters a mnemonic + PIN,
#      firmware provisions both chips with the XOR-split entropy.
#      Subsequent boots: OLED shows the unlock dialog.
#   4. Use the wallet via USB HID from the companion app.
build-hw-dual-se-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-oled,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Dual-SE standalone build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-dual-se-oled-standalone: build-hw-dual-se-oled-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# Same full standalone firmware as `flash-hw-dual-se-oled-standalone`,
# but on the NV3007 SPI LCD (`ui-lcd` — the shipping display backend as
# of 2026-06-09) instead of the OLED. `ui-lcd` pulls in `gpio-buttons`
# + `spi1-arduino`. Requires the NV3007 wired per docs/hardware/nv3007-wiring.md.
# All the caveats on the OLED target (bench-only #3 tunnel keys via
# dev-testkey, LcsO=Creation, wipe-for-wizard workflow) apply unchanged.
build-hw-dual-se-lcd-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,ui-lcd,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Dual-SE LCD standalone build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-dual-se-lcd-standalone: build-hw-dual-se-lcd-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# Same build as `flash-hw-dual-se-lcd-standalone` PLUS `debug-log`,
# attached over the ST-LINK micro-USB (`probe-rs run` at the end keeps
# the debugger connected and streams every secure-world log line to
# this terminal). Board powers from the programmer — no USB-C needed.
# NOT for production: `debug-log` leaks device-internal state (the
# wizard prints mnemonic words) over semihosting.
build-hw-dual-se-lcd-standalone-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,ui-lcd,stm32u585,usb,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Dual-SE LCD standalone DEBUG build ready (debug-log ON, ST-LINK powered)."

flash-hw-dual-se-lcd-standalone-debug: build-hw-dual-se-lcd-standalone-debug
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Attaching probe-rs run — semihosting stream follows. Ctrl-C to detach."
	@echo "    Wizard + PIN entry are driven by the physical buttons as usual;"
	@echo "    probe-rs only captures stdout."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Same build as `flash-hw-dual-se-oled-standalone` PLUS `debug-log`, so
# `secure_log!` / `hprintln!` output streams over the ST-LINK SWO/SWD
# semihosting channel. Flashes with `probe-rs run` at the end — that
# command keeps the debugger attached and forwards every secure-world
# log line to this terminal, so you can cold-power-cycle the board
# (long-press RESET or pull+reinsert VCC) while watching the host
# stdout to see exactly which branch of `is_provisioned()` / wizard /
# unlock path fires.
#
# Use this to diagnose the "wizard re-runs after a successful setup"
# class of bug: on the second boot, look for one of:
#   [S] Device already provisioned — requesting PIN unlock
#   [S] Unprovisioned — running first-boot wizard
# and the `[OPTIGA] Init: ...` + `[SE050] Init: ...` breadcrumbs above
# it to see whether one of the SE `init()` calls is timing out on cold
# boot.
#
# NOT for production — `debug-log` leaks device-internal state over
# semihosting (mnemonic words are printed when the wizard runs, per
# `main.rs`'s debug-only log block). Keep ST-LINK attached throughout;
# disconnecting kills the semihosting channel but the device will
# continue to run. Safe against the `probe-rs` `SYS_READC` gap (see
# CLAUDE.md "Hardware testing under probe-rs") because this build uses
# `gpio-buttons` + `ui-oled` — PIN / mnemonic entry goes through real
# button presses, not semihosting input.
build-hw-dual-se-oled-standalone-debug:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-oled,stm32u585,usb,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Dual-SE standalone DEBUG build ready (debug-log ON, USB-C + ST-LINK)."

flash-hw-dual-se-oled-standalone-debug: build-hw-dual-se-oled-standalone-debug
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Attaching probe-rs run — semihosting stream follows. Ctrl-C to detach."
	@echo "    Power-cycle the board (pull+replug USB-C, or press the B2 RESET button)"
	@echo "    to see the full boot sequence. Wizard + PIN entry are driven by the"
	@echo "    physical buttons as usual; probe-rs only captures stdout."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# OPTIGA Trust M + OLED standalone — single-SE variant of the SE050
# standalone target above. Uses Infineon OPTIGA Trust M V3 on I2C1
# (TRUSTMV3SHIELDTOBO1 on Arduino R3 headers). No semihosting, USB-C
# only. Deliberately does NOT include `optiga-lock-operational`, so
# every user OID (E140, F1D0..F1D4, F1E1) stays at LcsO=Creation
# throughout provisioning — metadata remains mutable, data rewriteable,
# no irreversible LcsO=Operational bump. This build is intended for
# bench/dev use; see docs/secure-elements/optiga-brick-postmortem.md §5 + §7 before
# adding `optiga-lock-operational` for a real production unit.
#
# NOTE: this target violates invariant #1 (dual-chip seed split) — the
# full entropy lives on OPTIGA alone. It is the single-SE OPTIGA twin of
# `flash-hw-se050-oled-standalone`, not a production dual-SE build.
build-hw-optiga-oled-standalone:
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features optiga-trust-m,gpio-buttons,ui-oled,stm32u585,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Standalone OPTIGA build ready (no semihosting, USB-C only, LcsO=Creation)."

flash-hw-optiga-oled-standalone: build-hw-optiga-oled-standalone
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Flashed and reset. Disconnect ST-LINK, connect only USB-C if desired."
	@echo "    Set JP4 to 5V_UCPD for USB-C power (or keep 5V_USB_STLK if using both cables)."

# ---------------------------------------------------------------------------
# OPTIGA Trust M dev-convenience helpers for the standalone target.
#
# Both targets assume the same hardware shape as `flash-hw-optiga-oled-
# standalone`: STM32U585 + OPTIGA Trust M V3 on I2C1 + SSD1306 OLED +
# GPIO buttons. Neither target uses `otp-hardcoded-master-key`, so OTP is
# burned from TRNG on first boot and every subsequent reflash (including
# back to the real standalone target) derives the same PBS from the same
# OTP master — i.e. shield handshake and PIN auth remain consistent
# across reflashes.
#
# LcsO-safety: neither target includes `optiga-lock-operational`. Every
# OID stays at LcsO=Creation; nothing is ratcheted to Operational.
# ---------------------------------------------------------------------------

# Factory-reset the connected board's OPTIGA chip so the next standalone
# boot sees it as never-provisioned. Reuses the `optiga-admin-wipe-e2e`
# exercise, which provisions throwaway test data, verifies unlock, then
# calls `factory_reset` — ending with F1D5 = RESET_SENTINEL (0xFF) and
# F1D0..F1D4 blanked. Post-state: `check_provisioned()` returns false →
# first-boot wizard runs on the next `flash-hw-optiga-oled-standalone`.
#
# Typical usage after the wizard got into a bad state:
#   make optiga-factory-reset-hw            # wipes OPTIGA, watch OLED
#   make flash-hw-optiga-oled-standalone    # reflash; wizard runs fresh
#
# Runs non-interactively: `probe-rs reset` starts the firmware, OLED
# shows "OPTIGA wipe: running..." → "OPTIGA wipe: PASS" (or FAIL), then
# the device halts in `wfi`. The STM32_Programmer_CLI call re-asserts the
# TZ option bytes (safe to repeat; ST-LINK may reset them between runs).
optiga-factory-reset-hw:
	@echo "==> Building OPTIGA factory-reset firmware (nuclear path)..."
	@echo "    Writes 0xFF to F1E1 (counter sentinel) via plaintext APDUs."
	@echo "    Skips OTP burn, PBS derivation, shielded connection, and"
	@echo "    the provision-first dance — so it works on boards where"
	@echo "    the OTP master can't be programmed."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-nuclear-reset,stm32u585,ui-oled,gpio-buttons,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting attached. Watch for:"
	@echo "      [OPTIGA/prov] step: ..."
	@echo "      [OPTIGA-E2E-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS/FAIL"
	@echo "    Ctrl+C to detach once PASS/FAIL lines appear."
	@echo ""
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Pre-provision the connected board's OPTIGA chip with a known mnemonic
# + PIN, skipping the interactive wizard. Uses the `e2e-test` fast-path
# (fixed test mnemonic + PIN baked into `secure/src/main.rs`) plus
# `e2e-skip-unlock`, which halts right after `provision_from_mnemonic`
# returns so the gateway never auto-unlocks.
#
# Bake-in credentials:
#   PIN:      00000000  (type "0" eight times in the PIN UI)
#   Mnemonic: abandon x23 + "art"  (standard BIP-39 test vector)
#
# After this target runs, the OPTIGA chip is in the same state a real
# user would leave it in by typing those credentials into the wizard.
# Reflash `flash-hw-optiga-oled-standalone` and the next boot skips the
# wizard, prompts "Enter PIN", and accepts 00000000.
#
# Typical usage to skip the wizard on a fresh board:
#   make optiga-preprovision-hw             # provisions OPTIGA, halts
#   make flash-hw-optiga-oled-standalone    # reflash
#   <type 00000000 at the PIN prompt>       # device unlocks
#
# OTP handling: no `otp-hardcoded-master-key`, so OTP burns real TRNG on
# first boot. The standalone build reflashed afterwards reads the same
# OTP key and derives the same PBS — shield handshake and PIN-derived
# auth secret stay consistent across the reflash.
optiga-preprovision-hw:
	@echo "==> Building OPTIGA pre-provision firmware (testkey PBS)..."
	@echo "    Adds otp-hardcoded-master-key so provisioning works on boards"
	@echo "    where OTP burn is blocked. Must be paired with the testkey"
	@echo "    standalone variant below so both firmwares derive the same PBS."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-oled,gpio-buttons,e2e-test,e2e-skip-unlock,otp-hardcoded-master-key,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,e2e-test
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting — watch for PBS fingerprint + provision OK."
	@echo "    Ctrl+C once you see '[OPTIGA] Provisioning complete' + halt."
	@echo ""
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Testkey standalone build — byte-for-byte the interactive
# `flash-hw-optiga-oled-standalone` flow, with the single difference
# that `otp-hardcoded-master-key` replaces the per-device OTP master
# with a compile-time constant so the PBS derives without needing OTP
# to be programmable. The dev-testkey feature is the explicit opt-out
# from the `nsc/mod.rs` production guard that would otherwise refuse
# to compile `otp-hardcoded-master-key` in a non-e2e-test release.
#
# Interactive: first boot runs the seed wizard (PIN + mnemonic),
# subsequent boots prompt "Enter PIN" like the real standalone build.
# No auto-provision, no auto-unlock.
#
# Use this on boards where OTP writes fail (WRPERR at 0x0BFA_0080)
# so the normal OTP-burn path can't run. PBS is the shared test
# constant across every dev board built with this feature — NEVER
# promote this target into production.
flash-hw-optiga-oled-standalone-testkey:
	@echo "==> Building OPTIGA standalone w/ dev-testkey (interactive, hardcoded PBS)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,gpio-buttons,ui-oled,stm32u585,usb,dev-testkey,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Flashed. Interactive first-boot wizard runs on a blank chip."
	@echo "    PBS is the shared dev-testkey constant (NOT device-unique)."
	@echo "    To wipe wallet state:           make optiga-factory-reset-hw"
	@echo "    To see semihosting output:      probe-rs run --chip STM32U585AIIx $(SECURE_ELF)"

# Same interactive dev-testkey build as above, but flashes and then
# stays attached via `probe-rs run` so semihosting (`secure_log!`,
# debug-log prints) streams live to the terminal while the firmware
# executes. Hardware buttons (PC1/PA8) still drive the UI — the
# semihosting channel is read-only for logs, not for input.
#
# Use when you need to watch the boot flow during bench iteration.
# Ctrl+C to detach (leaves firmware running on-device).
flash-hw-optiga-oled-testkey:
	@echo "==> Building OPTIGA dev-testkey (interactive, hardcoded PBS, debug-log)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,gpio-buttons,ui-oled,stm32u585,usb,dev-testkey,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@echo "==> Running with semihosting attached. Ctrl+C to detach."
	@echo "    Hardware buttons (PC1 LEFT / PA8 RIGHT) drive the UI."
	@echo ""
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

flash-hw-se050-oled: build-hw-se050-oled
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Starting interactive SE050 wallet (Ctrl-C to quit)..."
	@echo "    Button input via keyboard: h/l=short left/right, H/L=long left/right"
	@python3 tools/wallet_run_hw.py

# Flash USB-enabled build to real STM32U585.
flash-hw-usb: build-hw-usb
	probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching (Ctrl-C to quit)..."
	probe-rs reset --chip STM32U585AIIx
	probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# Run all three test layers: Rust unit tests, Foundry Solidity tests, and
# the full e2e suite under QEMU.
test: test-unit test-solidity e2e
	@echo "==> ALL TEST LAYERS PASSED"

# Host-side Rust unit tests for pure logic (aa, tx modules).
#
# Explicit `--no-default-features --features ...` because the secure crate
# now defaults to no features (Phase-2 of the modularity refactor). Without
# an explicit feature set, dead-code warnings on unreachable feature-gated
# modules would either litter the output or, under `-D warnings`, fail the
# build outright.
test-unit:
	@echo "==> Running Rust unit tests (host)"
	@cargo test --locked -p sphincs-tz-secure \
	    --no-default-features \
	    --features mock-se,debug-log,ui-semihosting
	@echo "==> Running pqsigner-tx-core unit tests (host)"
	@cargo test --locked -p pqsigner-tx-core --lib
	@echo "==> Running pqsigner-aa unit tests (host)"
	@cargo test --locked -p pqsigner-aa --lib
	@echo "==> Running pqsigner-domain unit tests (host)"
	@cargo test --locked -p pqsigner-domain --lib
	@echo "==> Running pqsigner-tx unit tests (host)"
	@cargo test --locked -p pqsigner-tx --lib
	@echo "==> Running pqsigner-erc7730 unit tests (host)"
	@cargo test --locked -p pqsigner-erc7730 --lib
	@echo "==> Running dbgen ERC-7730 round-trip integration tests (host)"
	@cargo test --locked -p dbgen --test erc7730_roundtrip

# CI gate: every checked-in generated artifact must round-trip
# byte-for-byte. New artifacts get a parallel diff target here so a
# stale `dbgen` / `xtask` run can't slip past review.
#
# Mirrors the existing `gen-solidity-constants --check` pattern: each
# subcommand rebuilds its outputs in-memory and exits non-zero on drift.
#
# Run manually:
#   make check-codegen
#
# Or as part of `make prod-check` (Phase 2 onwards).
.PHONY: check-codegen check-erc7730-descriptors
check-codegen: check-erc7730-descriptors
	@echo "==> codegen artifacts in sync"

check-erc7730-descriptors:
	@echo "==> Checking ERC-7730 descriptor catalog (xtask --check)"
	@cargo run --locked -q -p pqsigner-xtask -- gen-erc7730-descriptors --check

# Foundry tests for the PQ smart-wallet contracts.
test-solidity:
	@echo "==> Running Foundry tests"
	@cd contracts/smart-wallet && forge test

# Lean 4 formal verification — type-checks the SphincsCVerify project.
# See contracts/verification/README.md for what this proves and what it
# leaves to the TCB.
test-formal-verification:
	@echo "==> Building SphincsCVerify Lean project"
	@$(MAKE) -C contracts/verification verify
	@echo "==> Auditing axioms + sorry inventory"
	@$(MAKE) -C contracts/verification verify-audit

# `verify-theft-free` — end-to-end machine check of the headline theorem
# `SphincsCVerify.Spec.Theorems.theft_free`, plus an HONEST per-axiom
# discharge-status report.
#
# Pipeline:
#   1. Install the pinned Lean toolchain (idempotent; elan caches it).
#   2. `lake build` — the kernel re-checks every closed theorem in the
#      SphincsCVerify project, including `Spec.Theorems.theft_free` and
#      wallet invariants I-1..I-8.
#   3. Audit the axiom dependency closure of `theft_free` and diff it
#      against the expected set. Any drift fails the target.
#   4. Run `lint_axioms.sh` — fails on any newly-introduced `True`-typed
#      axiom or `True := trivial` placeholder theorem outside the
#      allowlists in `contracts/verification/scripts/`.
#   5. Print the per-axiom status table sourced from
#      `contracts/verification/docs/AXIOM_STATUS.json`. The previous
#      headline "An adversary cannot cause ... balance to decrease" line
#      overclaimed: three of the bridge axioms have type `True` and do
#      not constrain the deployed bytecode. The status table tells you
#      WHICH axioms are placeholders vs cited-TCB vs discharged.
#
# See `contracts/verification/docs/DISCHARGE_PLAN.md` for the tiered
# plan to turn placeholders into discharged content.
# Trust boundary: contracts/verification/docs/TRUST_ASSUMPTIONS.md.
.PHONY: verify-theft-free
verify-theft-free: export PATH := $(HOME)/.elan/bin:$(PATH)
verify-theft-free:
	@command -v elan >/dev/null || { \
	  echo "ERROR: elan not found. Install with:"; \
	  echo "  curl https://elan.lean-lang.org/elan-init.sh -sSf | sh -s -- -y"; \
	  exit 1; \
	}
	@echo "==> [1/5] Pinning Lean toolchain"
	@cd contracts/verification/lean && elan toolchain install "$$(cat lean-toolchain)" >/dev/null 2>&1 || true
	@echo "==> [2/5] lake build (kernel-checks every closed theorem)"
	@$(MAKE) -s -C contracts/verification verify-build
	@echo "==> [3/5] Auditing axiom closure of theft_free"
	@cd contracts/verification/lean && \
	  lake env lean scripts/dump_axioms.lean 2>/dev/null > /tmp/theft_free_axioms.txt
	@awk "/^'SphincsCVerify\\.Spec\\.Theorems\\.theft_free' depends on axioms:/{flag=1} flag{print} flag&&/\\]/{exit}" \
	    /tmp/theft_free_axioms.txt \
	  | tr -d ' \n' \
	  | sed -e 's/.*\[//' -e 's/\]$$//' \
	  | tr ',' '\n' \
	  | sort -u > /tmp/theft_free_seen.txt
	@printf '%s\n' \
	    Classical.choice \
	    Quot.sound \
	    SphincsCVerify.Bridge.EntryPoint.entrypoint_honest \
	    SphincsCVerify.Bridge.evm_bytecode_executes_correctly \
	    SphincsCVerify.Bridge.precompile_0x02_is_FIPS_180_4 \
	    SphincsCVerify.Bridge.solidityVerifier_compiles_correctly \
	    SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC \
	    SphincsCVerify.Crypto.ITSR_F \
	    SphincsCVerify.Crypto.SM_DT_TCR_F \
	    SphincsCVerify.Crypto.hMsg_random_oracle \
	    propext \
	  | sort -u > /tmp/theft_free_expected.txt
	@if ! diff -u /tmp/theft_free_expected.txt /tmp/theft_free_seen.txt; then \
	  echo ""; \
	  echo "FAIL: theft_free's axiom closure drifted from the expected set."; \
	  echo "Full dump: /tmp/theft_free_axioms.txt"; \
	  echo "If you intentionally added/removed an axiom, update BOTH the"; \
	  echo "expected list in this Makefile target AND the corresponding"; \
	  echo "entry in contracts/verification/docs/AXIOM_STATUS.json."; \
	  exit 1; \
	fi
	@echo "    closure matches the documented set (A1..A5 + Lean kernel built-ins)"
	@echo "==> [4/5] Linting for placeholder axioms / True := trivial theorems"
	@bash contracts/verification/scripts/lint_axioms.sh
	@echo "==> [5/5] Honest per-axiom discharge status"
	@python3 contracts/verification/scripts/format_axiom_status.py

# `test-all` — run every host-runnable test suite in the repo with one
# command. Streams one progress line per suite (suite name, then
# PASS/FAIL with test count when it finishes), keeps going past
# failures, and exits non-zero with a per-suite summary at the end if
# anything broke. Per-suite output is captured to
# `/tmp/test-all.<suite>.log` and the log path is shown for any FAIL.
#
# Covers (no opt-in needed):
#   1. Pure-logic workspace crates (`cargo test --workspace`, minus the
#      firmware-only bins that don't link on host).
#   2. `sphincs-tz-secure` host-testable subset behind `--features mock-se`.
#   3. Standalone `fuzz/` workspace (harness + structure tests).
#   4. Solidity contracts under `contracts/smart-wallet` via `forge test`
#      (auto-skipped with a SKIP line if `forge` is not on PATH).
#
# NOT included (these are slow QEMU/HW integration tests, not unit tests):
#   make e2e, make e2e-hw, make play, make run, make test-key-speed,
#   make pin-gate-*-hw, make optiga-hw-counter-e2e, ...
.PHONY: test-all
test-all: SHELL := /usr/bin/env bash
test-all:
	@set -uo pipefail; \
	pass=0; fail=0; failed=(); idx=0; \
	run() { \
	  idx=$$((idx+1)); \
	  local name="$$1"; shift; \
	  local slug=$$(echo "$$name" | tr ' /()' '____'); \
	  local log="/tmp/test-all.$$slug.log"; \
	  printf "[%2d] %-46s " "$$idx" "$$name"; \
	  if "$$@" >"$$log" 2>&1; then \
	    local n; n=$$(grep -E '^(test|Suite) result' "$$log" | awk '{tot+=$$4} END {print tot+0}'); \
	    [ -z "$$n" ] && n="?"; \
	    printf "PASS  (%s tests)\n" "$$n"; \
	    pass=$$((pass+1)); \
	    rm -f "$$log"; \
	  else \
	    printf "FAIL  (log: %s)\n" "$$log"; \
	    fail=$$((fail+1)); \
	    failed+=("$$name -> $$log"); \
	  fi; \
	}; \
	echo "=== running all host-runnable test suites ==="; \
	run "workspace host crates" cargo test --workspace --tests --no-fail-fast --quiet \
	    --exclude sphincs-tz-secure --exclude sphincs-tz-nonsecure --exclude pqsigner-fsbl; \
	run "sphincs-tz-secure --features mock-se" cargo test -p sphincs-tz-secure --tests \
	    --features mock-se --no-fail-fast --quiet; \
	run "fuzz workspace" bash -c "cd fuzz && cargo test --tests --no-fail-fast --quiet"; \
	if command -v forge >/dev/null 2>&1; then \
	  run "contracts/smart-wallet forge" bash -c "cd contracts/smart-wallet && forge test"; \
	else \
	  idx=$$((idx+1)); \
	  printf "[%2d] %-46s SKIP  (forge not on PATH)\n" "$$idx" "contracts/smart-wallet forge"; \
	fi; \
	echo; \
	if [ "$$fail" -eq 0 ]; then \
	  echo "==== ALL $$pass SUITES PASSED ===="; \
	else \
	  echo "==== $$fail / $$((pass+fail)) SUITE(S) FAILED ===="; \
	  for s in "$${failed[@]}"; do echo "  FAIL  $$s"; done; \
	  exit 1; \
	fi

# Compute firmware measurement words from the secure ELF.
# Displays the same 8 BIP-39 words the device shows at boot.
#
# Uses the same secure-world build as `flash-hw-dual-se-oled-standalone`
# (features: dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-oled,
# stm32u585,usb), so the words printed here match what the OLED shows
# after that flash target runs. To measure a different feature matrix
# (e.g. the production set without `dev-testkey`), use `make release`
# instead — it runs `verify-repro` and prints both secure + nonsecure
# measurements from the verified ELFs.
measure: build-hw-dual-se-oled-standalone
	cargo run --locked -p fwmeasure -- $(SECURE_ELF)

# Build the first-stage bootloader for real STM32U585 hardware.
#
# FSBL_VENDOR_PUBKEY: path to the 32-byte vendor pubkey (`pk_seed[16]
# || pk_root[16]`, produced by `fwsign pubkey`). If unset, a fixed dev
# fixture key is derived inline by fsbl/build.rs — the resulting FSBL
# is for development use only and will not accept production-signed
# firmware, and vice versa.
#
# Budget: 32 KB at 0x0C00_0000 (pages 0–3 of bank 1). Current footprint
# is ~18 KB with software SHA-256.
.PHONY: fsbl
fsbl:
	@echo "==> Building FSBL (FSBL_VENDOR_PUBKEY=$${FSBL_VENDOR_PUBKEY:-<dev fixture>})"
	@# FSBL_ALLOW_DEV_KEY opts this dev target into fsbl/build.rs's committed
	@# dev vendor key when FSBL_VENDOR_PUBKEY is unset (finding F2). A bare
	@# `cargo build -p pqsigner-fsbl` without either env var now fails the
	@# build instead of silently embedding the public dev key; `fsbl-release`
	@# sets neither and supplies a real pubkey via FSBL_VENDOR_PUBKEY.
	@FSBL_ALLOW_DEV_KEY=1 $(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/fsbl -p pqsigner-fsbl
	@echo "==> FSBL built: $(FSBL_ELF)"
	@size $(FSBL_ELF) 2>/dev/null || arm-none-eabi-size $(FSBL_ELF)

# Production-only: refuse to build the FSBL without FSBL_VENDOR_PUBKEY.
# Use this in the release pipeline.
.PHONY: fsbl-release
fsbl-release:
	@if [ -z "$${FSBL_VENDOR_PUBKEY}" ]; then \
		echo "ERROR: fsbl-release requires FSBL_VENDOR_PUBKEY=path/to/pubkey.bin"; \
		echo "       Use 'make fsbl' for dev builds with the built-in fixture."; \
		exit 1; \
	fi
	@$(MAKE) fsbl

# Verify byte-for-byte reproducibility of the secure + nonsecure ELFs.
#
# Builds each world twice in isolated target directories with the same
# FEATURES + toolchain, then diffs the resulting ELFs. Any divergence
# means some source of non-determinism has leaked into the build — the
# release is not safe to ship because an independent rebuild would
# produce different measurement words than the vendor publishes.
#
# This target is the canonical reproducibility gate. The nightly CI
# workflow runs it (.github/workflows/nightly.yml, the `verify-repro`
# job); the release pipeline runs it before signing. It is NOT a
# per-PR gate — two full release cross-builds are too slow for that.
#
# Two builds share the same VENEERS path (build A writes it, build B
# links against the identical file), which is fine: linking the same
# implib into identical NS crates yields an identical NS ELF, so the
# whole reproducibility story holds.
.PHONY: verify-repro
verify-repro:
	@echo "==> Reproducibility check (FEATURES=$(FEATURES))"
	@rm -rf target/repro-a target/repro-b
	@$(MAKE) --no-print-directory _repro_one \
		OUT=target/repro-a VENEERS=$(CURDIR)/target/repro-a/veneers.o FEATURES="$(FEATURES)"
	@$(MAKE) --no-print-directory _repro_one \
		OUT=target/repro-b VENEERS=$(CURDIR)/target/repro-b/veneers.o FEATURES="$(FEATURES)"
	@echo "==> Comparing ELFs"
	@if cmp -s target/repro-a/secure/$(TARGET)/release/sphincs-tz-secure \
	           target/repro-b/secure/$(TARGET)/release/sphincs-tz-secure; then \
		echo "    secure.elf:    IDENTICAL"; \
	else \
		echo "    secure.elf:    DIFFERS — reproducibility broken"; \
		echo "    Re-run with VERBOSE=1 and inspect with diffoscope"; \
		exit 1; \
	fi
	@if cmp -s target/repro-a/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure \
	           target/repro-b/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure; then \
		echo "    nonsecure.elf: IDENTICAL"; \
	else \
		echo "    nonsecure.elf: DIFFERS — reproducibility broken"; \
		exit 1; \
	fi
	@echo "==> verify-repro: PASS"

# Internal helper — one end-to-end build into $(OUT). Invoked twice by
# verify-repro with different OUT dirs and different VENEERS paths.
# Reuses the canonical RUSTFLAGS_SECURE / RUSTFLAGS_NONSECURE variables
# (which honour the $(FEATURES) gate that decides whether --cmse-implib
# is emitted), so we implicitly get correct behaviour for both QEMU
# and STM32U585 feature sets.
.PHONY: _repro_one
_repro_one:
	@mkdir -p $(OUT)
	@echo "==> Build $(OUT): secure"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE)" \
		cargo build --locked --release --target $(TARGET) --target-dir $(OUT)/secure \
			-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Build $(OUT): nonsecure"
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE)" \
		cargo build --locked --release --target $(TARGET) --target-dir $(OUT)/nonsecure \
			-p sphincs-tz-nonsecure $(NS_FEATURES_ARG)

# Release build: reproducibility-verified secure + nonsecure ELFs plus
# their measurement words. This is what the vendor's release-signing
# pipeline consumes as input. Writes artifacts to target/release/.
#
# Note: --features are taken from $(RELEASE_FEATURES); the default is
# the production feature set (no debug-log, no e2e-test, no mock-se).
# Pass RELEASE_FEATURES=... on the command line to override.
#
# Tier-1 channel-key roots (finding F8c): `saes-dhuk` routes
# hw::secret_keys::derive_into through SAES-CMAC(DHUK) instead of the legacy
# OTP-master + HKDF arm, and `se050-derived-scp03` makes SE050 SCP03 use
# per-device derived keys instead of the published AN12436 factory constants.
# Without these a default `make release` shipped non-Tier-1 roots, contrary to
# invariant #3; the nsc/mod.rs require-fence now makes that a build error.
# `bhk` (Tier-2 SE050 split) is deliberately NOT added — enabling it without
# the phase-2B silicon provisioning yields zero-keyed derivations (see
# secure/Cargo.toml); it remains a tracked follow-up.
RELEASE_FEATURES ?= stm32u585,se050,optiga-trust-m,dual-se,ui-lcd,saes-dhuk,se050-derived-scp03

# MED-2 ship gate (audits/tz-tamper-debug-20260611). Resolve the ACTUAL feature
# set cargo would compile for the shipping image and fail if any never-ship
# feature is active — including TRANSITIVELY (ui-capture→debug-log,
# dev-testkey→otp-hardcoded-master-key). `cargo tree --depth 0 -f "{f}"` prints
# the secure crate's fully-resolved feature list; we scan it against the
# forbidden set. Independent of the `mode-production` compile fences in
# nsc/mod.rs: this also catches a release built as `stm32u585,…` WITHOUT
# mode-production. `make release` depends on it; CI runs it as a fast gate.
PROD_FORBIDDEN = e2e-test dev-testkey mock-se debug-log otp-hardcoded-master-key \
                 ui-capture ui-mirror bhk-hardcoded-master-key uart-console \
                 boot-pulse sca-trigger erc7730-dev-unattested optiga-reset-oids \
                 fw-rollback-e2e fwup-transport-e2e se050-scp03-allow-factory-fallback
.PHONY: prod-check
prod-check:
	@echo "==> prod-check (MED-2): resolving shipping feature set"
	@echo "    RELEASE_FEATURES = $(RELEASE_FEATURES)"
	@feats=$$(cargo tree -p sphincs-tz-secure --no-default-features \
		--features "$(RELEASE_FEATURES)" --target $(TARGET) \
		-e features -f "{f}" --depth 0 2>/dev/null | tr ',' '\n' | tr -d ' ' | sort -u); \
	bad=""; \
	for f in $(PROD_FORBIDDEN); do \
		echo "$$feats" | grep -qx "$$f" && bad="$$bad $$f"; \
	done; \
	if [ -n "$$bad" ]; then \
		echo "==> prod-check: FAIL — shipping build enables never-ship feature(s):$$bad"; \
		echo "    forbidden set: $(PROD_FORBIDDEN)"; \
		exit 1; \
	fi; \
	echo "==> prod-check: PASS — no never-ship feature in the resolved set"

.PHONY: release
release: prod-check
	@echo "==> Release build (features: $(RELEASE_FEATURES))"
	@echo "==> SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)"
	@$(MAKE) verify-repro FEATURES=$(RELEASE_FEATURES)
	@mkdir -p target/release
	@cp target/repro-a/secure/$(TARGET)/release/sphincs-tz-secure \
	    target/release/secure.elf
	@cp target/repro-a/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure \
	    target/release/nonsecure.elf
	@echo ""
	@echo "==> Secure measurement:"
	@cargo run --locked -q -p fwmeasure -- target/release/secure.elf 2>/dev/null | sed 's/^/    /'
	@echo ""
	@echo "==> Nonsecure measurement:"
	@cargo run --locked -q -p fwmeasure -- target/release/nonsecure.elf 2>/dev/null | sed 's/^/    /'
	@echo ""
	@echo "==> Release artifacts in target/release/"
	@echo "    Next: fwsign sign --key vendor-key.enc --version N ..."

# Hardware bring-up test for the OTP-derived OPTIGA Shielded Connection
# path landed in work-todo #24.
#
# Build config:
#   - optiga-trust-m + stm32u585   : real chip over I2C1 (no SE050 needed)
#   - otp-hardcoded-master-key     : PBS derives from the fixed ASCII
#                                    constant, no real OTP is burned — the
#                                    chip can be re-paired across multiple
#                                    reflashes with a *stable* PBS. This is
#                                    the test we couldn't run before #24.
#   - e2e-test                     : pre-provisions the test mnemonic +
#                                    auto-verifies the PIN, so the OPTIGA
#                                    provisioning pipeline runs end-to-end
#                                    without interactive input.
#   - optiga-lock-operational      : deliberately NOT set. E140 stays at
#                                    LcsO=Creation so the chip is rewriteable
#                                    if anything in the derivation needs
#                                    iterating.
#
# What to watch for on the probe-rs semihosting stream:
#   [OPTIGA] PBS derived from OTP master and loaded
#   [OPTIGA/prov] step 1: setup_pbs_no_handshake
#   [OPTIGA/prov] E140 LcsO bump SKIPPED (optiga-lock-operational OFF; ...)
#   [OPTIGA/shield] establish: start
#   [OPTIGA/shield] sending MasterHello
#   [OPTIGA/shield] MasterHello response n=38
#   [OPTIGA/shield] PRL handshake OK — encrypted I2C active
#   [OPTIGA] Provisioning complete (6 OIDs written + locked)
#   [S][e2e] gateway pre-unlocked, ready for tests
#
# Rebuild-stability test: after the first successful run, edit any comment
# in the source, rerun `make flash-hw-optiga-bringup`, and confirm the
# same markers appear again. The chip still holds the PBS from the first
# run; the MCU re-derives the same 32 bytes from the hardcoded master;
# the handshake succeeds with the existing chip-side pairing state.
# That's the concrete proof that the firmware_hash-in-wrap-key brick
# class is gone.
flash-hw-optiga-bringup:
	@echo "==> Building OPTIGA Stage-1 bring-up test (Phase B: full PRL)"
	@echo "    (optiga-trust-m + otp-hardcoded-master-key + e2e-test)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — watch for PRL handshake markers."
	@echo "    (Ctrl-C to abort; rerun the target after a code change to"
	@echo "     prove the PBS is stable across rebuilds.)"
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Phase A of the OPTIGA Stage-1 hardware validation.
#
# Same build as `flash-hw-optiga-bringup` PLUS `e2e-skip-unlock`, which
# halts the boot flow immediately after `provision_from_mnemonic` returns
# and BEFORE `SE.unlock` runs. The practical effect:
#
#   - `setup_pbs_no_handshake` WRITES the 64-byte PBS to OID E140 via
#     plaintext APDU. The chip records it at LcsO=Creation (rewriteable).
#   - Each user OID (F1D0..F1E1) is provisioned plaintext, LcsO=Creation.
#   - `authenticate_and_read` / `ensure_shield` / `shield.establish` are
#     NEVER called, so `ensure_pbs_lcso_operational` cannot bump E140 to
#     LcsO=Operational. The chip remains fully recoverable.
#
# If the write succeeds, we see `[OPTIGA] PBS provisioned (handshake
# deferred)` followed by `[S][e2e] e2e-skip-unlock active: halting after
# provisioning`. At that point the chip holds our PBS but is still rewrite-
# able via plaintext I2C (LcsO<op), so Phase B's PRL test can commit it
# properly, or a re-run with a different PBS can overwrite it.
#
# If the write FAILS (e.g., the chip refuses the 64-byte size, or some
# APDU-level error), we see a `set_data_object FAILED` line and Phase B
# is definitively off the table until the root cause is understood.
flash-hw-optiga-bringup-write-only:
	@echo "==> Building OPTIGA Stage-1 bring-up test (Phase A: write + halt)"
	@echo "    (optiga-trust-m + otp-hardcoded-master-key + e2e-test + e2e-skip-unlock)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key,e2e-skip-unlock
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — Phase-A validation (no LcsO=op bump)."
	@echo "    Watch for the PBS fingerprint + '[OPTIGA] PBS provisioned'"
	@echo "    followed by 'e2e-skip-unlock active: halting after provisioning'."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Full unlock test: provision + verify_pin + read all secrets through
# the Shielded Connection. Identical features to
# `flash-hw-optiga-bringup-write-only` minus `e2e-skip-unlock` so the
# e2e runner falls through to `SE.unlock(pin)`, which exercises:
#   - `ensure_shield` (handshake / re-handshake)
#   - counter bump + readback (F1E1, data only)
#   - GetRandom → DecryptSym HMAC-verify against F1D0 (silicon PIN gate)
#   - Auto(F1D0)-gated reads of F1D1..F1D4
#   - counter reset to 0 on success
# Critically: `optiga-lock-operational` stays OUT of the feature set,
# so `lock_oid` is a no-op and nothing bumps any OID to Operational.
# No `set_metadata` call is reachable on this path either.
flash-hw-optiga-unlock-test:
	@echo "==> Building OPTIGA unlock test (provision → verify_pin → read secrets)"
	@echo "    Features match bringup-write-only MINUS e2e-skip-unlock."
	@echo "    LcsO on every OID stays at whatever it was on entry."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — expect 'gateway pre-unlocked, ready for tests'"
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# OPTIGA factory_reset roundtrip e2e. Exercises `factory_reset` end-to-end
# on the real chip: provision F1D0..F1D4 + F1E1 with known test vectors,
# unlock, factory_reset, then verify the counter == RESET_SENTINEL + unlock
# returns NotProvisioned + check_provisioned() == false.
#
# !!! WARNING: this target DESTROYS any wallet state on the chip !!!
# `factory_reset` hardcodes the production OIDs (F1D0..F1D4 + F1E1), so
# the test wipes them. Re-run `make flash-hw-optiga-unlock-test` or the
# real first-boot wizard afterwards to restore. Safe to run on any dev
# bench chip; idempotent across repeated runs.
#
# Scope: exercises the factory_reset PRIMITIVE, NOT the PIN-lockout→wipe
# integration path (that's a separate deferred test).
#
# LcsO-safety: deliberately does NOT include `optiga-lock-operational`.
# Every metadata write in the provisioning step goes via
# `build_metadata_auth_ref` / `build_metadata_user_oid` /
# `build_metadata_counter` (no LCS tag), and `lock_oid` is a no-op. No
# OID is promoted to LcsO=Operational by running this target.
#
# `e2e-test` is required because `otp-hardcoded-master-key` trips the
# production guard in nsc/mod.rs unless the unambiguous "not-shippable"
# marker is set. The e2e-test fast-path itself is dead code here — our
# dispatcher at main.rs halts before the fast-path ever runs.
#
# Watch semihosting for "[E2E-OPTIGA-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS"/"FAIL".
optiga-hw-counter-e2e:
	@echo "==> Building OPTIGA hardware PIN counter (E120 + LUC) e2e firmware..."
	@echo "    This rewrites F1D0 metadata to the LUC-binding variant and"
	@echo "    provisions E120 as the silicon PIN counter. LcsO stays at"
	@echo "    Creation on every touched OID (optiga-lock-operational OFF)."
	@echo "    If F1D0 is somehow already at LcsO=Operational with legacy"
	@echo "    non-LUC metadata the firmware aborts loudly (Status 0xE0) —"
	@echo "    run optiga-reset-oids first in that case."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-hw-counter-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running hw-counter e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

optiga-admin-wipe-e2e:
	@echo "==> Building OPTIGA factory_reset roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE any wallet state on the target chip."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running admin-wipe e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Dual-SE (OPTIGA + SE050) admin-wipe roundtrip e2e. Exercises
# `DualSecureElement::provision` + `DualSecureElement::unlock` end-to-end:
# pre-clean both chips (tolerates prior test contamination via a
# three-stage cascade: admin-PIN → user-PIN candidates → unauthenticated
# sweep), provision fresh test entropy XOR-split across the two,
# unlock and verify the master_secret reconstructs byte-exact.
#
# !!! WARNING: this target DESTROYS wallet state on BOTH chips !!!
# Pre-clean wipes OPTIGA F1D0..F1D4 + F1E1 and every deletable SE050
# object in the 0x7B0E_xxxx (v5) range. Re-run the normal first-boot wizard
# afterwards to restore. Idempotent across repeated runs on the same
# chip (pre-clean handles each re-invocation).
#
# Scope: exercises the XOR entropy reconstruction — the unique dual-SE
# value-add not covered by either single-SE test. Does NOT exercise
# `factory_reset_admin`; see `make optiga-admin-wipe-e2e` +
# `make se050-admin-wipe-e2e` for those primitives individually, and
# note that the full dual-SE admin-wipe integration is intentionally
# DEFERRED (requires a fresh SE050 whose admin UserID PIN matches
# page-125 flash; cross-test contamination on dev chips desyncs the
# two and makes the test unrunnable without fresh silicon).
#
# LcsO-safety: `optiga-lock-operational` deliberately NOT included.
# OPTIGA stays at Creation throughout. SE050 has no LcsO concept. The
# only "slot commitments" on SE050 are policy installs on freshly-
# created objects within the 0x7B0E_xxxx (v5) range; `store_objects`
# skips creation if objects already exist, so repeat runs don't write
# new policies. Stuck SE050 objects outside 0x7B0E_xxxx (v3 + older)
# are not touched.
#
# `e2e-test` is required because `otp-hardcoded-master-key` trips the
# production guard in nsc/mod.rs. The e2e-test fast-path itself is
# dead code here — our dispatcher halts before it runs.
#
# Watch semihosting for "[E2E-DUAL-ADMIN] DUAL-WIPE ROUNDTRIP: PASS"/"FAIL".
# Multi-unlock / cross-reboot validation for the SE050-corruption fix.
# First cold boot: provisions both chips with a fixed test mnemonic+PIN,
# then does 5 consecutive unlock+XOR-reconstruct+verify cycles.
# Subsequent cold boots: detects the provisioned state, skips
# re-provisioning, does another 5 unlocks. Across the 3 runs below =
# 15 unlocks spread over 3 full power-cycle equivalents (probe-rs reset
# + run). PASS on all three proves SE050 ENTROPY_OBJ survives the full
# provisioning pulse sequence AND stays stable across reboots — the
# exact "works once, fails on reboot" scenario from the old cross-
# coupling bug. Use `make dual-se-multi-unlock-e2e`.
dual-se-multi-unlock-e2e:
	@echo "==> Building dual-SE multi-unlock / reboot e2e firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se-multi-unlock-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo ""
	@for n in 1 2 3; do \
		echo "==> Boot $$n/3..."; \
		log=$$(mktemp -t dual-se-multi-b$$n.XXXXXX.log); \
		probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1 | tee "$$log"; \
		sleep 3; \
		if grep -q "MULTI-UNLOCK ROUNDTRIP: PASS" "$$log"; then \
			echo "==> Boot $$n PASS"; \
			rm -f "$$log"; \
		else \
			echo "==> Boot $$n FAIL"; rm -f "$$log"; exit 1; \
		fi; \
		echo ""; \
	done
	@echo "==> ALL 3 BOOTS PASS — 15 unlocks across 3 cold reboots"
	@echo ""
	@echo "==> ALL 3 BOOTS PASS — 15 unlocks across 3 cold reboots, master_secret reproduces every time"

dual-se-admin-wipe-e2e:
	@echo "==> Building dual-SE unlock roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE wallet state on BOTH chips."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE unlock e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Tier-2 silicon-root variant of dual-se-admin-wipe-e2e: exercises the
# SAME dual-SE unlock roundtrip + admin-wipe cascade, but with the real
# hardware HUK roots — `saes-dhuk` (OPTIGA PBS over SAES-CMAC(DHUK)) and
# `bhk` (SE050 SCP03 + admin PIN over SAES-CMAC(BHK)). No hardcoded test
# keys: `otp-hardcoded-master-key` and `bhk-hardcoded-master-key` are
# BOTH off, so this is the closest thing to the shipping derivation we
# can run on the bench.
#
# What it does on first boot:
#   - `[S] SAES initialised (Tier-1 DHUK path)`
#   - if flash page 126 is blank: `[S] BHK provisioned (first boot)` —
#     generates 32 TRNG bytes, DHUK-ECB-wraps them, writes page 126.
#     REVERSIBLE: page 126 is mass-erasable (RDP regression / explicit
#     `flash::erase_secure_page(126)`); an RDP regression on a bhk-active
#     device just means the SE050 needs re-pairing afterward (OPTIGA's
#     PBS is on DHUK directly and survives). No OTP is touched — with
#     `saes-dhuk` on, `secret_keys::derive_into` routes to SAES-CMAC,
#     never `otp::ensure_device_master` (pre-flight audit confirmed).
#   - else: `[S] BHK loaded + BHKLOCK set` — unwraps page 126 into
#     TAMP BKP0R..7R, sets BHKLOCK.
#   - then the usual pre-clean cascade (`se050.factory_reset_admin()`
#     re-derives the admin PIN via the real BHK), fresh provision, and
#     the dual-SE unlock roundtrip.
#
# WIPES wallet state on BOTH chips (same as dual-se-admin-wipe-e2e).
# Watch semihosting for the dual-SE PASS line.
dual-se-bhk-e2e:
	@echo "==> Building dual-SE Tier-2 (real DHUK+BHK) unlock roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE wallet state on BOTH chips,"
	@echo "             and (on first boot) provision a DHUK-wrapped BHK to flash page 126."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,saes-dhuk,bhk
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running dual-SE Tier-2 e2e (watch semihosting for SAES/BHK init lines + PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# PIN-gate roundtrip e2e. Direct non-interactive test of the MCU-side
# PIN attempt counter at flash page 126 + the `nsc::gated_unlock`
# pre-commit pattern. No buttons, no USB — hardcoded right/wrong PINs
# + semihosting PASS/FAIL.
#
# Validates work-todo #4 Phase 1 (dual-SE PIN lockout sync): counter
# bumps on wrong PIN, counter resets to 0 on correct PIN, cycle is
# repeatable. Does not test the PinLocked path (would burn SE050's
# silicon retry counter and brick the v5 UserID for an otherwise-
# provable inspection-only check).
#
# Destroys any wallet state on both chips (the initial factory_reset_
# admin + fresh provision with a test PIN). Re-run the normal first-
# boot wizard afterwards to restore.
#
# Watch semihosting for "[E2E-PIN-GATE] PIN-GATE ROUNDTRIP: PASS".
# §32 duress-PIN feasibility probe. Provisions a SECOND OPTIGA AuthRef
# (F1D8, Execute=ALW / no E120 binding) + a SECOND SE050 UserID
# (max_attempts=0) alongside the real credentials, and asserts they
# coexist AND that the duress OPTIGA auth leaves E120 untouched. Stays
# LcsO=Creation on every OID (never locks → fully recoverable).
# Reprovisions the bench chips with test data, like the other SE e2es.
#
# Pass: semihosting ends with "DURESS COEXISTENCE PROBE: PASS".
# §32 timing-channel measurement (decides the P3 drift fix). Same
# firmware as duress-probe-hw but built WITHOUT debug-log so the
# measured SE verifies run at production speed (no per-I²C-transaction
# semihosting). The coexistence steps run silently; the
# [DURESS-TIMING] lines print via unconditional hprintln!. Watch for
# the OPTIGA/SE050 per-verify latency + the "EXTRA real-verify cost".
duress-timing-hw:
	@echo "==> Building §32 timing-channel measurement firmware (no debug-log → production-speed verifies)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features duress-probe-e2e,stm32u585,ui-oled,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running timing measurement (watch for [DURESS-TIMING] lines)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

duress-probe-hw:
	@echo "==> Building §32 duress-PIN coexistence probe firmware..."
	@echo "    Adds a 2nd OPTIGA AuthRef (F1D8, no E120) + 2nd SE050 UserID"
	@echo "    (unlimited) next to the real credentials. NEVER locks an OID;"
	@echo "    every credential stays LcsO=Creation / re-writable."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features duress-probe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running duress-PIN coexistence probe (watch for DURESS COEXISTENCE PROBE: PASS)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

duress-provision-hw:
	@echo "==> Building §32 P2 full provision_duress silicon-validation firmware..."
	@echo "    Provisions a real wallet + an independent decoy via the PRODUCTION"
	@echo "    provision/provision_duress path, then reads both decoy halves and"
	@echo "    asserts half_o XOR half_e == the known decoy entropy + E121-only bump"
	@echo "    + real wallet still unlocks. Stays LcsO=Creation (never locks)."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features duress-provision-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running duress provision validation (watch for DURESS PROVISION VALIDATION: PASS)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

pin-gate-hw-counter-e2e:
	@echo "==> Building combined sync + desync recovery e2e firmware..."
	@echo "    Exercises MCU page-124 + OPTIGA E120 + SE050 UserID counters"
	@echo "    together under dual-se + optiga-hw-counter. WIPES wallet state"
	@echo "    on BOTH chips. Does NOT bump any OID to LcsO=Operational."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-hw-counter-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running combined sync + desync e2e (watch for SYNC+DESYNC ROUNDTRIP: PASS)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

pin-gate-wipe-e2e:
	@echo "==> Building MCU-MAX-ATTEMPTS lockout-wipe dispatch e2e firmware..."
	@echo "    DESTRUCTIVE: burns 10 wrong PINs → SE050 UserID silicon-locks,"
	@echo "    MCU counter saturates, E120 LUC at 10. Then fires"
	@echo "    factory_reset_admin + pin_attempts_reset to prove the lockout-"
	@echo "    wipe dispatch path end-to-end. Re-provisions at the end to"
	@echo "    prove recovery. Does NOT bump any OID to LcsO=Operational."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running wipe dispatch e2e (watch for WIPE+RECOVERY ROUNDTRIP: PASS)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Re-run the currently-flashed wipe-for-wizard firmware under probe-rs
# with semihosting, WITHOUT rebuilding, re-downloading non-secure, or
# re-configuring TrustZone option bytes. The normal `make wipe-for-
# wizard` flow detaches probe-rs right after the "WIPED — power-cycle
# me" halt, so the subsequent physical power-cycle boots blind — there
# is no semihosting sink attached to capture the wizard path's output.
#
# This target re-enters the flow by issuing an SWD reset through
# probe-rs and streaming the new boot's logs. Functionally equivalent
# to a physical power-cycle with the probe still attached. The secure
# ELF is re-downloaded (same image — effectively a no-op) so we can
# piggyback `probe-rs run`'s built-in reset + attach sequence; the
# non-secure ELF stays whatever was last flashed by `wipe-for-wizard`.
#
# Pre-req: a prior `make wipe-for-wizard` (or any target that flashed
# both secure + non-secure ELFs and set TZEN/SECBOOTADD0). Use this
# when you see a successful wipe halt but nothing visible on the next
# boot — the semihosting trace will show whether the chip is in the
# "nothing to wipe → fall through to wizard" branch or failing earlier.
wipe-for-wizard-rerun:
	@echo "==> Re-running already-flashed wipe-for-wizard firmware under probe-rs semihosting..."
	@echo "    (no rebuild, no NS re-flash, no TZ option-byte rewrite)"
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

wipe-for-wizard:
	@echo "==> Building dev wipe-for-wizard firmware..."
	@echo "    DESTRUCTIVE (wallet state): wipes OPTIGA user OIDs,"
	@echo "    SE050 user objects + admin UserID, MCU page 124."
	@echo "    PRESERVES: STM32 OTP master, OPTIGA E140 PBS, all OID"
	@echo "    metadata (LcsO stays at Creation), resident firmware."
	@echo "    Boot 1: wipes + halts on 'WIPED — power-cycle me'."
	@echo "    Boot 2 (after power-cycle): drops into interactive"
	@echo "    first-boot wizard for fresh mnemonic + PIN entry."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features wipe-for-wizard,stm32u585,debug-log
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running wipe (watch OLED for 'WIPED — power-cycle me')..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# One-shot D6 pin-identification diagnostic.
# Builds a minimal secure-world firmware that runs `pin_diag::run()`
# at the top of `main()` (pulsing PA4/PD5/PE0/PE4/PE5/PB6 with
# distinct widths) and then parks the CPU in `wfe`. No provisioning,
# no SE init beyond the GPIO toggling — safe to flash over any
# existing state.
# Workflow:
#   1. `sigrok-cli --driver kingst-la2016 --channels CH3 --time 5000 \
#          --config samplerate=1m -o /tmp/d6.sr` in one terminal
#   2. `make pin-diag-boot-hw` in another (flashes + runs)
#   3. The width visible on CH3 identifies the STM32 pin on D6.
pin-diag-boot-hw:
	@echo "==> Building pin-diag-boot firmware (one-shot D6 finder)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-diag-boot,debug-log,ui-noop
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running (pulses fire once, then CPU halts in wfe)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# One-shot SAES self-test on real silicon. Boots the firmware just far
# enough to init SAES (Tier 1 of work-todo #7), runs the software-key
# round-trip + DHUK-vs-SW domain-separation + DHUK round-trip self-
# tests, prints an 8-byte DHUK fingerprint, then exits cleanly via
# SYS_EXIT. No OTP burn, no flash writes, no TAMP access, no SE I/O.
# Cross-boot check: run this twice on the same board — the DHUK
# fingerprint must be byte-identical across reboots. Running on
# different boards should yield different fingerprints.
# Masked-SHA-256 overhead bench (work-todo §18 SHAKE-vs-SHA2 #2
# measurement). Builds the bench firmware, flashes, configures TZ,
# streams the DWT-timed results over semihosting. Reports the
# projected masked-SHA-256-block slowdown vs the HASH peripheral.
#
# `e2e-test` escapes the production fence + permits `mock-se` (the
# bench short-circuits before any SE access). `ui-noop` is headless.
# `bench-masked-sha` implies stm32u585 (→ hw-sha256), so the
# HASH-peripheral baseline is real silicon, not software.
#
# NOTE: deliberately NO `debug-log`. `hw::rng::fill` emits a
# `secure_log!("[S] rng::fill entry ...")` on EVERY call when debug-log
# is on; the bench draws the TRNG hundreds of thousands of times, so
# debug-log floods the semihosting channel (one slow probe round-trip
# per draw) and the bench crawls. The bench prints its results via
# unconditional `hprintln!`, which works under probe-rs regardless of
# debug-log — so dropping it keeps the results AND kills the flood.
#
# Pass: streams `[BENCH] ...` lines ending in
#       `=== masked-sha2 bench complete ===`, then SYS_EXITs.
bench-masked-sha-hw:
	@echo "==> Building masked-SHA-256 overhead bench firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features bench-masked-sha,ui-noop,e2e-test,mock-se
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running masked-SHA-256 bench (streaming results)..."
	@log=$$(mktemp -t bench-masked-sha.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1 | tee "$$log"; \
	echo "===================================="; \
	if grep -q "=== masked-sha2 bench complete ===" "$$log"; then \
		echo "==> bench-masked-sha: DONE"; exit 0; \
	else \
		echo "==> bench-masked-sha: FAIL (missing completion marker)"; exit 1; \
	fi

saes-self-test-hw:
	@echo "==> Building SAES Tier-1 self-test firmware..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features saes-self-test,debug-log,ui-noop,e2e-test,mock-se
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running SAES self-test..."
	@log=$$(mktemp -t saes-self-test.XXXXXX.log); \
	trap 'rm -f "$$log"' EXIT; \
	probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1 | tee "$$log"; \
	echo "===================================="; \
	if grep -q "=== self_test PASS ===" "$$log"; then \
		echo "==> saes-self-test: PASS"; exit 0; \
	else \
		echo "==> saes-self-test: FAIL (missing PASS marker)"; exit 1; \
	fi

# RDP1 variant of the SAES self-test — captures the REAL per-die DHUK
# fingerprint by stepping the chip to RDP1 (where ST activates the real
# DHUK, instead of the RDP0 placeholder constant shared across every
# STM32U585). Because RDP1 disables SWD debug, semihosting / probe-rs
# can't see the output — we route the PASS line over USART1 → ST-LINK
# VCP instead. The ST-LINK's VCP is a feature of the on-board debugger
# MCU and works independently of the target's RDP level.
#
# Flow:
#   1. Build firmware with `uart-console` so the fp goes out PA9.
#   2. Flash firmware at RDP0 (the only RDP where flash-via-SWD works
#      without OEM keys).
#   3. Start capturing /dev/serial/by-id/*STLINK* in the background.
#   4. Program RDP=0xBB to step to RDP1 — the chip resets, firmware
#      re-runs with the real per-die DHUK.
#   5. Wait ~5 seconds for the fp line, then kill capture.
#   6. Grep for the PASS line + extract the fingerprint.
#
# IMPORTANT: run `make saes-self-test-hw-rdp0-regress` afterward to
# restore the board to RDP0 for normal dev iteration. Leaving a board
# at RDP1 is fine (reversible), but you can't re-flash via probe-rs
# until you regress.
saes-self-test-hw-rdp1:
	@echo "==> Building SAES Tier-1 self-test firmware (UART console)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features saes-self-test,uart-console,debug-log,ui-noop,e2e-test,mock-se
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing at RDP0..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Ensuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@set -e; \
	vcp=$$(ls /dev/serial/by-id/*STLINK*-if02* 2>/dev/null | head -1); \
	if [ -z "$$vcp" ]; then \
		vcp=$$(ls /dev/serial/by-id/*STLINK* 2>/dev/null | head -1); \
	fi; \
	if [ -z "$$vcp" ]; then \
		echo "==> saes-self-test-hw-rdp1: FAIL — no ST-LINK VCP at /dev/serial/by-id/*STLINK*"; \
		exit 1; \
	fi; \
	echo "==> Using ST-LINK VCP: $$vcp"; \
	stty -F "$$vcp" 115200 cs8 -cstopb -parenb raw -echo -ixon -ixoff 2>/dev/null || true; \
	log=$$(mktemp -t saes-rdp1.XXXXXX.log); \
	timeout 8 cat "$$vcp" > "$$log" 2>&1 & \
	cat_pid=$$!; \
	sleep 0.3; \
	echo "==> Stepping chip to RDP1 (RDP=0xBB) — chip resets + firmware runs at RDP1..."; \
	STM32_Programmer_CLI --connect port=SWD mode=UR --optionbytes RDP=0xBB || \
		STM32_Programmer_CLI --connect port=SWD mode=HotPlug --optionbytes RDP=0xBB || true; \
	wait $$cat_pid 2>/dev/null || true; \
	echo "===================================="; \
	echo "==> ST-LINK VCP capture:"; \
	cat "$$log"; \
	echo "===================================="; \
	ret=1; \
	if grep -q "self_test PASS" "$$log"; then \
		fp=$$(grep "DHUK(fp)=" "$$log" | head -1 | sed 's/.*DHUK(fp)=//;s/[^0-9a-f].*//'); \
		echo "==> saes-self-test-hw-rdp1: PASS"; \
		echo "==> RDP1 DHUK fingerprint: $$fp"; \
		echo "==> Board is now at RDP1. Run 'make saes-self-test-hw-rdp0-regress' to return to RDP0."; \
		ret=0; \
	else \
		echo "==> saes-self-test-hw-rdp1: FAIL — no PASS line captured on VCP."; \
		echo "==> Chip may be at RDP1 now; 'make saes-self-test-hw-rdp0-regress' will recover."; \
	fi; \
	rm -f "$$log"; \
	exit $$ret

# Regress a board from RDP1 (or above, with OEM2 password) back to RDP0.
# Mirrors ST's own `Projects/B-U585I-IOT02A/Applications/SBSFU/SBSFU_Boot/
# STM32CubeIDE/regression.sh` pattern: writes RDP=0xAA, strips WRP1/WRP2
# + SECWM, forces an `-e all` mass erase, and restores default option
# bytes. ST's OpenBootloader source confirms: "Going from RDP level 1 to
# RDP level 0 erase all the flash" (Middlewares/ST/OpenBootloader/
# Modules/I2C/openbl_i2c_cmd.c:399).
#
# Caveats:
#   - Mass-erases both flash banks. MCU-side wallet state (pages 123-125)
#     is wiped; OTP survives (OTP is silicon-level one-way, not tied to
#     RDP). SE050 / OPTIGA NVM is untouched (separate chips).
#   - No OEM2 password is set or expected. If you've ever burnt one, you
#     need to add `--readunprotect <password>` or similar to the CLI call.
#   - Does NOT step RDP2 → RDP1 (RDP2 is permanent). Only RDP1 → RDP0.
saes-self-test-hw-rdp0-regress:
	@echo "==> Regressing RDP1 → RDP0 (mass-erase will wipe flash banks 1+2)..."
	@echo "    Note: OTP survives; SE050 / OPTIGA NVM are separate chips and unaffected."
	@STM32_Programmer_CLI --connect port=SWD mode=UR --optionbytes RDP=0xAA \
		UNLOCK_1A=1 UNLOCK_1B=1 UNLOCK_2A=1 UNLOCK_2B=1 || \
		STM32_Programmer_CLI --connect port=SWD mode=HotPlug --optionbytes RDP=0xAA \
			UNLOCK_1A=1 UNLOCK_1B=1 UNLOCK_2A=1 UNLOCK_2B=1
	@echo "==> Stripping write-protect + secure watermarks..."
	@STM32_Programmer_CLI --connect port=SWD --optionbytes \
		WRP1A_PSTRT=0x7F WRP1A_PEND=0x0 WRP1B_PSTRT=0x7F WRP1B_PEND=0x0 \
		WRP2A_PSTRT=0x7F WRP2A_PEND=0x0 WRP2B_PSTRT=0x7F WRP2B_PEND=0x0 \
		SECWM1_PSTRT=0x7F SECWM1_PEND=0x0 SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 || true
	@echo "==> Mass-erase both banks..."
	@STM32_Programmer_CLI --connect port=SWD -e all
	@echo "==> Restoring default option bytes (TZEN=1 + full-secure banks + SECBOOTADD0)..."
	@STM32_Programmer_CLI --connect port=SWD --optionbytes \
		TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Regression complete — board is back at RDP0."

pin-gate-e2e:
	@echo "==> Building PIN-gate roundtrip e2e firmware..."
	@echo "    WARNING: this build will WIPE wallet state on BOTH chips."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features pin-gate-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running PIN-gate e2e (watch semihosting for PASS/FAIL)..."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Shield-handshake-only test. Skips `provision_from_mnemonic` entirely
# and runs `init` → `load_pbs_from_otp` → `ensure_shield` against an
# already-provisioned chip. Use this to validate the Shielded Connection
# handshake in isolation without re-writing any F1Dx state. The chip's
# E140 must already have the OTP-derived PBS from a prior run of
# `flash-hw-optiga-bringup-write-only`; the PBS itself is reproduced
# deterministically from the STM32U585's OTP master on every boot.
flash-hw-optiga-shield-handshake-only:
	@echo "==> Building OPTIGA shield-handshake-only test"
	@echo "    (e2e-skip-provision: reuses existing E140 PBS, tests PRL only)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features optiga-trust-m,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key,e2e-skip-unlock,e2e-skip-provision
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features e2e-test,stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting and attaching — expect '[S][e2e] SHIELD UP — PRL handshake succeeded'."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# One-shot OPTIGA Trust M OID recovery. Regenerates reset manifests from
# the Infineon protected_update_data_set tool, builds firmware with the
# optiga-reset-oids feature, flashes the STM32U585, and attaches probe-rs
# so the reset log is visible. Drop the feature from the regular flash
# targets after the chip reports all OIDs reset OK.
optiga-reset-oids:
	@echo "==> Regenerating reset manifests (requires built tool)"
	@test -x /home/nicola/repos/optiga-trust-m/examples/tools/protected_update_data_set/bin/protected_update_data_set \
		|| (echo "Build the tool first: make -C /home/nicola/repos/optiga-trust-m/examples/tools/protected_update_data_set" && exit 1)
	@python3 tools/optiga_reset/gen_reset_manifests.py

flash-hw-optiga-reset: optiga-reset-oids
	@echo "==> Building firmware with optiga-reset-oids"
	@echo ""
	@echo "    ### DOES NOT WORK ON TRUSTMV3SHIELDTOBO1 ###"
	@echo "    Verified 2026-04-22: all 17 target OIDs return Status(0xFF)"
	@echo "    because E0E3 on this shield is Infineon's device cert slot"
	@echo "    (DataType 0x12), not a mutable Trust Anchor slot (0x11)."
	@echo "    SetDataObject accepts our TA cert bytes but the chip does"
	@echo "    not promote the slot to act as a TA, so every subsequent"
	@echo "    SetObjectProtected manifest fails signature verification."
	@echo "    See memory/project_optiga_reset_oids.md for full trace."
	@echo ""
	@echo "    Continue only if you have a DIFFERENT OPTIGA chip where"
	@echo "    E0E3 is known-blank (fresh engineering samples). Ctrl-C"
	@echo "    now to abort."
	@echo ""
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW) -C debug-assertions=on" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features dual-se,optiga-reset-oids,stm32u585,ui-oled,debug-log,usb
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Attaching probe-rs so the reset log is visible (Ctrl-C to quit)..."
	@probe-rs reset --chip STM32U585AIIx
	@probe-rs attach --chip STM32U585AIIx $(SECURE_ELF)

# Coverage-guided libFuzzer harnesses (`fuzz/`, kept as a standalone
# workspace since cargo-fuzz needs nightly + libFuzzer + sanitizers).
# Pure-logic parsers only — the proptest sibling that always runs is
# in `secure/src/fuzz_props.rs`. See `fuzz/README.md` for setup and
# `docs/architecture/trezor-comparison.md §2.4` for the rationale.
#
# Usage:
#   make fuzz-list                 -- list available targets
#   make fuzz-aa-userop-parse [TIME=600]
#   make fuzz-rlp-decode-item [TIME=600]
#   make fuzz-eip1559-parse [TIME=600]
#   make fuzz-erc20-calldata [TIME=600]
#   make fuzz-erc20-bundle [TIME=600]
#   make fuzz-apdu-parse-header [TIME=600]
#   make fuzz-hid-frame-assembler [TIME=600]
#
# TIME (seconds) bounds the libFuzzer run; omit for unbounded.
FUZZ_TIME ?= $(TIME)
FUZZ_LIBFUZZER_ARGS = $(if $(FUZZ_TIME),-- -max_total_time=$(FUZZ_TIME),)

# On a nix-based toolchain the libFuzzer binary can't find libstdc++ at runtime
# (the system libstdc++ is GLIBC-incompatible with the nix-built cargo-fuzz).
# Auto-prepend the nix gcc-lib dir if present; empty on a standard glibc env
# (where the binaries link the system libstdc++ and just run).
FUZZ_LD := $(shell ls -d /nix/store/*gcc-1[45]*-lib/lib 2>/dev/null | head -1)
FUZZ_ENV := $(if $(FUZZ_LD),LD_LIBRARY_PATH=$(FUZZ_LD),)

# Net-isolation (SOTA 2026-06 §7 egress discipline): the fuzzer RUN phase has no
# business reaching the network, so wrap it in tools/sca/run-isolated.sh
# (bwrap --unshare-net, fails closed). The BUILD stays networked (it's not
# wrapped). Composed via `env` so it coexists with the optional FUZZ_ENV LD
# prefix. Override with `make fuzz-all FUZZ_ISOLATE=` to disable (e.g. a host
# without bwrap, or inside a CI container that already drops the network).
FUZZ_ISOLATE ?= $(CURDIR)/tools/sca/run-isolated.sh

.PHONY: fuzz-list fuzz-all fuzz-aa-userop-parse fuzz-rlp-decode-item fuzz-eip1559-parse fuzz-erc20-calldata fuzz-erc20-bundle fuzz-apdu-parse-header fuzz-hid-frame-assembler

# Smoke the whole adversarial parse surface: run every target for FUZZ_TIME
# seconds (default 30) against its seed corpus. Coverage-guided libFuzzer; a
# crash drops an artifact under fuzz/artifacts/<target>/ to triage (these parsers
# are Kani-proven panic-free on bounded input, so a crash = a real unbounded-path
# bug OR a harness artifact — decide which before "fixing"). Last full run
# (2026-06-17): all 11 targets non-vacuous (cov 23-133), 0 crashes.
fuzz-all:
	@cd fuzz && cargo +nightly fuzz build
	@cd fuzz && for t in $$(cargo +nightly fuzz list); do \
	  echo "==> fuzz $$t ($(or $(FUZZ_TIME),30)s)"; \
	  mkdir -p corpus/$$t artifacts/$$t; \
	  $(FUZZ_ISOLATE) env $(FUZZ_ENV) target/x86_64-unknown-linux-gnu/release/$$t corpus/$$t \
	    -max_total_time=$(or $(FUZZ_TIME),30) -rss_limit_mb=2048 -artifact_prefix=artifacts/$$t/ \
	    2>&1 | grep -E "DONE|cov: [0-9]+ ft:|crash|deadly signal|SUMMARY" | tail -2; \
	done; \
	c=$$(find artifacts -type f \( -name 'crash-*' -o -name 'oom-*' \) 2>/dev/null | wc -l); \
	echo "==> fuzz-all done; crash artifacts: $$c (triage any under fuzz/artifacts/)"

fuzz-list:
	@echo "Available fuzz targets (see fuzz/README.md):"
	@cd fuzz && cargo +nightly fuzz list 2>/dev/null || \
		(echo "  cargo-fuzz not installed. Install with:"; \
		 echo "    cargo install cargo-fuzz"; \
		 echo "    rustup install nightly"; \
		 echo "  Then re-run \`make fuzz-list\`."; exit 1)

fuzz-aa-userop-parse:
	cd fuzz && cargo +nightly fuzz run aa_userop_parse_header $(FUZZ_LIBFUZZER_ARGS)

fuzz-rlp-decode-item:
	cd fuzz && cargo +nightly fuzz run tx_core_rlp_decode_item $(FUZZ_LIBFUZZER_ARGS)

fuzz-eip1559-parse:
	cd fuzz && cargo +nightly fuzz run tx_core_eip1559_parse $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc20-calldata:
	cd fuzz && cargo +nightly fuzz run tx_erc20_parse_calldata $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc20-bundle:
	cd fuzz && cargo +nightly fuzz run tx_erc20_verify_bundle $(FUZZ_LIBFUZZER_ARGS)

fuzz-apdu-parse-header:
	cd fuzz && cargo +nightly fuzz run apdu_parse_header $(FUZZ_LIBFUZZER_ARGS)

fuzz-hid-frame-assembler:
	cd fuzz && cargo +nightly fuzz run hid_frame_assembler $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc7730-verify-bundle:
	cd fuzz && cargo +nightly fuzz run erc7730_verify_bundle $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc7730-ir-parse:
	cd fuzz && cargo +nightly fuzz run erc7730_ir_parse $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc7730-walker:
	cd fuzz && cargo +nightly fuzz run erc7730_walker $(FUZZ_LIBFUZZER_ARGS)

fuzz-erc7730-render-dispatch:
	cd fuzz && cargo +nightly fuzz run erc7730_render_dispatch $(FUZZ_LIBFUZZER_ARGS)

# F-24 stage E Phase 1 — hardware flicker validation harness for the
# decoy-mnemonic-frame defense. Builds a minimal secure firmware that
# short-circuits `main()` into `ui::seed_wizard::decoy_flicker_test_loop`
# (renders page 0 of a fixed test mnemonic interleaved with 4 fixed
# decoys at the production 5:1 = 200ms:40ms cadence, forever). No
# wizard, no buttons, no SE access. A bench user stares at the OLED
# and reports whether the cadence is visually readable.
#
# Expected screen: row 0 = "Phrase 1/8" title, rows 1-3 = three words
# from the test mnemonic (varying every ~240 ms cycle between real
# and one of 4 decoys). If the flicker is acceptable, ship as-is. If
# distracting, bump REAL_FRAME_HOLD_MS in
# `secure/src/ui/seed_wizard.rs:129` to 400-500 (smooths visual at
# cost of decoy coverage).
decoy-flicker-hw:
	@echo "==> Building decoy-flicker-test firmware..."
	@echo "    Renders page 0 forever with 5:1 real:decoy cadence."
	@echo "    No buttons, no wizard, no SE — just OLED rendering."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features decoy-flicker-test,mock-se,debug-log,ui-oled,stm32u585,dev-testkey
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running — watch the OLED. Ctrl-C to detach."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Decoy-flicker test on the NV3007 LCD (Phase D — F-24 stage E sub-channel 4).
# Same harness as decoy-flicker-hw but `ui-lcd`. The LCD's slow-response pixels
# (Tr+Tf ~35 ms) are the whole point: a decoy painted briefly then overwritten
# by the next real frame may never fully transition (subliminal to the eye)
# while the SPI bus still carries it (the defense). The loop SWEEPS DECOY_HOLD =
# 40/25/15/8/3/0 ms (~4-5 s each, logged) so you can find the subliminal
# threshold. Builds + flashes; then run + watch the panel:
#   probe-rs run --chip STM32U585AIIx $(SECURE_ELF)
# Requires the NV3007 wired per docs/hardware/nv3007-wiring.md.
decoy-flicker-lcd-hw:
	@echo "==> Building decoy-flicker-test firmware for the NV3007 LCD..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features decoy-flicker-test,mock-se,debug-log,ui-lcd,stm32u585,dev-testkey,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Flashed. Run + watch the LCD (log prints the active DECOY_HOLD):"
	@echo "    probe-rs run --chip STM32U585AIIx $(SECURE_ELF)"

# Factory production-line test (prodtest) firmware. Single-purpose
# build that the factory operator flashes BEFORE the
# factory_provisioning ceremony. Sits in WFI after boot, waiting for
# the factory fixture to drive each component test via USB. See
# `docs/provisioning/factory-prodtest.md` for the command reference + fixture
# integration guide.
#
# Phase A (landed 2026-05-19): CMD_PRODTEST_GET_ID +
#                              CMD_PRODTEST_DISPLAY_PATTERN
# Phase B (landed 2026-05-19): CMD_PRODTEST_{SAES,BHK}_SELFTEST,
#                              CMD_PRODTEST_FLASH_RW (stub),
#                              CMD_PRODTEST_TRNG_SAMPLE
# Phase C-G (deferred to work-todo §30): communication tests
#                              (OPTIGA/SE050 handshakes), button
#                              test, host-side fixture runner.
#
# Use this target to validate the prodtest build compiles cleanly;
# silicon validation is Phase B work in work-todo §30.
build-hw-prodtest:
	@echo "==> Building prodtest firmware..."
	@echo "    Boot sequence:"
	@echo "      1. Normal STM32 + SE + button + USB init"
	@echo "      2. Display 'PRODTEST READY' on OLED"
	@echo "      3. Launch NS world (USB stack)"
	@echo "      4. Wait for USB INSes (INS_V2_PRODTEST_* 0x80-0x89)"
	@echo "    Factory fixture drives the test sequence via USB HID."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features prodtest,dev-testkey
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb,prodtest
	@echo "==> Prodtest build ready."
	@echo "    Host fixture runner at tools/factory-prodtest-runner.py"

# Factory provisioning firmware. Single-purpose build the factory
# operator flashes to a fresh device. Runs the
# `factory_provisioning::run_and_halt` state machine — validates
# hardware, provisions OPTIGA + SE050 infrastructure, wipes the
# dummy user state, cross-validates, and halts on a "FACTORY OK"
# or "FACTORY FAIL @ STEP X" OLED panel.
#
# Build profile:
#   - dual-se (required): both SEs must be alive to be provisioned.
#   - stm32u585 (required): real silicon target.
#   - ui-oled (required): the operator needs the OLED panel.
#   - dev-testkey: factory uses the deterministic OTP-master constant
#     during bring-up of this target. **REMOVE for real production**
#     once the OTP-burn-from-TRNG path has been bench-validated.
#   - NO debug-log: production-fence-compatible, no semihosting leaks.
#   - NO e2e-test: ceremony runs the real provision path.
#
# After flashing, the factory operator:
#   1. Power-cycles the device.
#   2. Watches the OLED panel.
#   3. Reports the displayed status (success or numbered fail).
#
# Error code lookup table + operator manual:
#   docs/provisioning/factory-provisioning.md
#
# Currently TARGETED but NOT YET VALIDATED on real silicon — this
# builds a buildable factory image; bench-validation is a follow-up.
build-hw-factory-provisioning:
	@echo "==> Building factory provisioning firmware..."
	@echo "    Output: $(SECURE_ELF)"
	@echo "    The factory operator flashes this + power-cycles."
	@echo "    OLED shows step progress + halts on OK/FAIL."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features factory-provisioning,dev-testkey
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Factory provisioning build ready."
	@echo "    To flash + run the ceremony:"
	@echo "        make flash-hw-factory-provisioning"
	@echo "    To check the result + optionally bump RDP2:"
	@echo "        tools/factory-provisioning-verify.sh [--bump-rdp2]"

# Flash the production factory-provisioning firmware + configure
# TZ option bytes + reset + verify the OTP sentinel via probe-rs.
# Does NOT bump RDP2 — that's a separate deliberate step. Operator
# (or the factory's automated fixture) inspects the verifier
# output, then runs the bump target only when confident.
#
# This is the "happy path" target the factory's fixture script will
# call after probe-rs download of any per-device data. Untested on
# real silicon — Phase A is the "ready to send" milestone, Phase B
# is the actual silicon trial.
flash-hw-factory-provisioning: build-hw-factory-provisioning
	@echo "==> Downloading factory firmware to STM32..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes (NOT RDP)..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target — chip runs the ceremony autonomously..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Polling OTP sentinel for ceremony completion..."
	@tools/factory-provisioning-verify.sh

# Same as flash-hw-factory-provisioning but uses the rehearsal build.
# Steps 4-6 SKIP their destructive calls; OTP sentinel records
# BIT_REHEARSAL (not BIT_PRODUCTION). Useful for OLED panel layout
# iteration without burning SE-side state on dev chips.
flash-hw-factory-provisioning-rehearsal: build-hw-factory-provisioning-rehearsal
	@echo "==> Downloading REHEARSAL firmware to STM32..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes (NOT RDP)..."
	@STM32_Programmer_CLI --connect port=SWD \
		--optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
		SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Resetting target — chip runs the REHEARSAL ceremony..."
	@probe-rs reset --chip STM32U585AIIx
	@echo "==> Polling OTP sentinel for ceremony completion..."
	@tools/factory-provisioning-verify.sh

# IRREVERSIBLE: bumps STM32 RDP option byte to Level 2 after
# verifying the OTP factory sentinel says the chip is production-
# ready. Refuses if the sentinel is not RDP2-eligible. Requires the
# operator to type "BUMP RDP2" at the interactive prompt as a final
# confirmation.
#
# After this target completes:
#   - SWD / JTAG is permanently denied
#   - probe-rs read/write no longer works
#   - semihosting/UART are dead
#   - the only post-RDP2 diagnostic surface is OLED + USB behavior
#   - the only "recovery" is mass-erase via STM32_Programmer_CLI
#     --regression, which wipes every secret on the chip
#
# Run ONLY after `make flash-hw-factory-provisioning` has reported
# PRODUCTION_OK or BOTH_OK.
bump-rdp2-after-factory:
	@echo "==> RDP2 bump — IRREVERSIBLE."
	@echo "    Verifying OTP sentinel before proceeding..."
	@tools/factory-provisioning-verify.sh --bump-rdp2

# Read-only inspection target: report the OTP factory sentinel
# state without flashing anything. Useful to check a chip's
# current factory state mid-iteration.
factory-status-hw:
	@tools/factory-provisioning-verify.sh

# Factory provisioning REHEARSAL build. Identical state machine to
# the production target above, except steps 4 (DualSeProvision), 5
# (WipeUserState), and 6 (PostWipeValidation) SKIP their destructive
# calls. The OLED still cycles through all 7 panels; the OTP
# sentinel still gets written, but with BIT_REHEARSAL set instead of
# BIT_PRODUCTION, so the host fixture refuses to bump RDP2 on a
# rehearsal-only chip.
#
# Use this for OLED panel layout iteration without burning chip-side
# state. Safe to run repeatedly on your dev chips.
#
# After running, the OLED reads "REHEARSAL OK" / "SE NOT changed" /
# "NOT for ship!" — distinct from production's "FACTORY OK" /
# "READY TO SHIP".
build-hw-factory-provisioning-rehearsal:
	@echo "==> Building factory provisioning REHEARSAL firmware..."
	@echo "    Steps 4-6 SKIP their destructive calls."
	@echo "    OLED shows 'REHEARSAL OK' on success."
	@echo "    OTP sentinel records BIT_REHEARSAL (not BIT_PRODUCTION)."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features factory-provisioning,factory-provisioning-rehearsal,dev-testkey
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Rehearsal build ready (safe to flash on dev chips)."

# LCD bring-up — Phase A check. Compiles the secure-world firmware
# with the `ui-lcd` feature enabled so the NV3007 SPI LCD driver
# (`secure/src/hw/lcd_nv3007.rs`) lands in the binary. The wizard UI
# still runs over the existing `ui-noop` Display backend (Phase C
# will wire the LCD into the Display trait); for Phase B bring-up
# you'd call `hw::lcd_nv3007::init()` + `fill_screen(0x07E0)` (green)
# from `main()` to verify SPI signalling + reset timing on the bench.
#
# Pin wiring (B-U585I-IOT02A → ZT165M017AT FPC):
#   PE12 → CS    (Arduino D10)
#   PE13 → SCL   (Arduino D13, AF5)
#   PE15 → SDA   (Arduino D11, AF5)
#   PE3  → D/CX  (jumper, free GPIO)
#   PE1  → RES   (jumper, free GPIO)
#   3V3  → VCC_2V8 + VLED+
#   GND  → GND   + VLED-
#
# Use this target to verify the firmware compiles cleanly; the actual
# LCD init/fill sanity check needs a Phase B short-circuit in main.rs
# (analogous to `decoy-flicker-hw`).
build-hw-lcd-bringup:
	@echo "==> Building secure firmware with ui-lcd driver (Phase A scaffold)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features ui-lcd,ui-noop,mock-se,debug-log,stm32u585,dev-testkey
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585
	@echo "==> LCD bring-up build ready (Phase A — no init call site yet)."
	@echo "    Next: add a hw::lcd_nv3007::init() + fill_screen() call"
	@echo "    in main.rs behind a lcd-test feature gate, mirror"
	@echo "    decoy-flicker-hw's short-circuit pattern."

# Phase-B LCD bring-up (NV3007). Flashes a firmware that short-circuits
# main() into hw::lcd_nv3007::lcd_test_loop — the screen cycles
# green -> red -> blue (~1 s each) forever. First on-silicon confirmation
# that the wiring + the ported init sequence work. Wiring: docs/hardware/nv3007-wiring.md
# (SPI on CN13 D10/D11/D13, DC=PE7/D4, RES=PD15/D2, VCC+BLK=3V3, GND).
# Assumes TZ option bytes are already set (run any *-hw target once first).
lcd-test-hw:
	@echo "==> Building LCD UI bring-up test (NV3007 ui::Display 16x4 text)..."
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features lcd-test,mock-se,debug-log,stm32u585,dev-testkey,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running — watch the LCD: green -> red -> blue cycling. Ctrl-C to detach."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

# Animated splash-screen preview (NV3007). Flashes a firmware that short-circuits
# main() into ui::splash_test::run — the three assets/splash-1{6,7,8}-*.html
# revisions (hyperspace -> horizon -> nebula), ported to no_std, cycle on the
# LCD ~12 s each forever so you can judge how each looks on the real panel.
# Same wiring as lcd-test-hw (docs/hardware/nv3007-wiring.md): SPI on CN13 D10/D11/D13,
# DC=PE7/D4, RES=3V3, VCC+BLK=3V3, GND. Assumes TZ option bytes are already set
# (run any *-hw target once first). The first build pulls `micromath` into
# Cargo.lock (cached locally, so it resolves offline).
splash-test-hw:
	@echo "==> Building animated splash preview (NV3007: hyperspace/horizon/nebula)..."
	@echo "    (with hardware FPU: -C target-feature=+fp-armv8d16sp; CPACR enabled at runtime)"
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW) -C target-feature=+fp-armv8d16sp" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features \
		--features splash-test,mock-se,debug-log,stm32u585,dev-testkey,usb
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure \
		-p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Running — watch the LCD cycle the 3 splash revisions. Ctrl-C to detach."
	@probe-rs run --chip STM32U585AIIx $(SECURE_ELF)

clean:
	rm -rf target/secure target/nonsecure target/veneers.o


# Firmware anti-rollback test on real STM32U585 silicon — REVERSIBLE.
#
# Proves downgrade rejection (v1 install OK; v2 update OK; v2->v1 downgrade
# REJECTED; same-version reinstall REJECTED; forward v3 OK; forged signature
# REJECTED) by driving the REAL fw_update::verify_manifest chain (the exact
# function CMD_FW_BEGIN runs: structural -> CRC -> digest -> vendor-fpr ->
# FI-hardened SPHINCS+C10 signature -> rollback floor) with dev-key-signed
# manifests against literal test floors passed as a function argument.
#
# REVERSIBLE — burns NOTHING: no OTP rollback-floor bump, no flash erase, no
# boot-state write, no reboot, no USB. The chip stays fully reflashable.
# (Production OTP-burn FW-update validation is deferred to dedicated HW.)
#
# Greps for `[S][fwrb] === PASS ===`. Requires ST-LINK on B-U585I-IOT02A.
# Uses `probe-rs run` (NOT reset — reset leaves the core halted on this setup).
fw-rollback-hw: dev-pubkey-fixture
	@echo "==> Building FW anti-rollback test (secure + stm32u585 + fw-rollback-e2e + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/secure \
	  -p sphincs-tz-secure --no-default-features --features mock-se,ui-noop,stm32u585,fw-rollback-e2e
	@echo "==> Building minimal NS image (stm32u585; not reached, flashed for layout)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
	  -p sphincs-tz-nonsecure --features stm32u585
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
	  --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
	  SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> Running FW anti-rollback test on hardware (~10s; signs 4 manifests)..."
	@log=$$(mktemp -t fw-rollback-hw.XXXXXX.log); \
	rc_file=$$(mktemp -t fw-rollback-hw-rc.XXXXXX); \
	trap 'rm -f "$$log" "$$rc_file"' EXIT; \
	{ timeout 120 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) 2>&1; \
	  echo $$? >"$$rc_file"; } | tee "$$log"; \
	rc=$$(cat "$$rc_file"); \
	echo "===================================="; \
	if grep -q "\[S\]\[fwrb\] === PASS ===" "$$log"; then \
	  echo "==> fw-rollback-hw: PASS — downgrade rejected, forward allowed, forged sig rejected"; \
	  exit 0; \
	elif grep -q "\[S\]\[fwrb\] === FAIL ===" "$$log"; then \
	  echo "==> fw-rollback-hw: FAIL — an anti-rollback assertion mismatched (see log)"; \
	  exit 1; \
	else \
	  echo "==> fw-rollback-hw: FAIL (no PASS/FAIL marker; rc=$$rc)"; \
	  exit 1; \
	fi

# DEV vendor pubkey fixture (32 bytes = pk_seed[16] || pk_root[16]) derived
# from the built-in dev seed via `fwsign dev-pubkey`. The secure crate has no
# sphincs-c10 build-dep (feature unification would leak host features into
# the firmware target), so `secure/build.rs` cannot compute this itself — it
# reads `FSBL_VENDOR_PUBKEY` instead. This target writes the dev pubkey to a
# stable path the test/dev builds can point at. Byte-identical to the key
# `fsbl/build.rs` falls back to when `FSBL_VENDOR_PUBKEY` is unset.
DEV_VENDOR_PUBKEY := $(CURDIR)/target/dev_vendor_pubkey.bin

dev-pubkey-fixture: $(DEV_VENDOR_PUBKEY)

$(DEV_VENDOR_PUBKEY):
	@mkdir -p $(@D)
	@cargo run --release -p fwsign --quiet -- dev-pubkey --out $@

# Fuzz the fw-manifest verify chain (the trust decision the USB FW-update
# path makes at CMD_FW_BEGIN). Standalone cargo-fuzz workspace under
# `fw-manifest/fuzz/`. Requires:
#   rustup toolchain install nightly
#   cargo install cargo-fuzz
# Then:
#   make fuzz-manifest                 # full verify-chain fuzz (slower)
#   make fuzz-manifest-crc             # structural+CRC only (faster)
# Or build-check only (CI-friendly, no nightly required if libfuzzer-sys
# can be compiled with stable; otherwise needs nightly):
#   make fuzz-manifest-build
fuzz-manifest:
	cd fw-manifest && cargo +nightly fuzz run fuzz_target_verify_manifest

fuzz-manifest-crc:
	cd fw-manifest && cargo +nightly fuzz run fuzz_target_structural_crc

fuzz-manifest-build:
	cd fw-manifest/fuzz && cargo +nightly build --release

# Over-USB FW-update transport e2e test on real STM32U585 silicon —
# REVERSIBLE (no OTP burn, no reset; chip stays reflashable).
#
# The host driver (tools/fwup-transport-test.py) sends a dev-signed
# v1 manifest + small QW-aligned image chunks + FW_COMMIT over real
# USB HID. The device runs the FULL state machine + verify_manifest +
# verify_images, then STOPS at COMMIT before OTP/boot-state/sys_reset
# under the `fwup-transport-e2e` feature.
#
# Catches transport-layer bugs (APDU chaining, HID framing, chunk
# header parsing, BEGIN -> CHUNK -> COMMIT ordering) that the device-
# side make-fw-rollback-hw test can't see (because that one bypasses
# the gateway and calls verify_manifest directly).
#
# Requires:
#   * ST-LINK + USB-C cable both connected (see USB-C enumeration
#     work — `5V_UCPD` jumper is OK; ST-LINK provides probe-rs access).
#   * udev rule installed for 1209:7051 (tools/99-pqsigner.rules) so
#     /dev/hidrawN is rw-accessible without root.
#   * `make dev-pubkey-fixture` populated (target/dev_vendor_pubkey.bin).
#
# Build features:
#   secure: mock-se,ui-noop,stm32u585,usb,fwup-transport-e2e
#     (fwup-transport-e2e implies e2e-test — auto-provision + skip PIN;
#      deliberately does NOT imply debug-log because semihosting BKPTs
#      under probe-rs run break USB timing — see the USB-C enumeration
#      lesson + the reference_probe_rs_reset_halts_core memory.)
#   NS: stm32u585,usb (the standard USB-HID host-facing build).
FWUP_FIXTURE_DIR := $(CURDIR)/target/fwup-test
FWUP_FIXTURE_FILES := $(FWUP_FIXTURE_DIR)/manifest.bin $(FWUP_FIXTURE_DIR)/secure.bin $(FWUP_FIXTURE_DIR)/nonsecure.bin

fwup-transport-fixture: $(FWUP_FIXTURE_FILES)

$(FWUP_FIXTURE_FILES) &:
	@mkdir -p $(FWUP_FIXTURE_DIR)
	@cargo run --release -p fwsign --quiet -- gen-test-fixture \
	  --version 1 --secure-len 240 --nonsecure-len 240 \
	  --out-dir $(FWUP_FIXTURE_DIR)

fwup-transport-hw: dev-pubkey-fixture fwup-transport-fixture
	@echo "==> Building secure (fwup-transport-e2e + usb + mock-se)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/secure \
	    -p sphincs-tz-secure --no-default-features \
	    --features mock-se,ui-noop,stm32u585,usb,fwup-transport-e2e
	@echo "==> Building NS (usb)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
	    -p sphincs-tz-nonsecure --features stm32u585,usb
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
	  --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
	  SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> probe-rs run (background) — letting the device boot + USB enumerate..."
	@(timeout 120 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) > /tmp/fwup-transport-run.log 2>&1 &)
	@for i in $$(seq 1 25); do \
	  if lsusb 2>/dev/null | grep -qi '1209:7051'; then echo "==> Enumerated (~$${i}s)"; break; fi; \
	  sleep 1; \
	done
	@if ! lsusb 2>/dev/null | grep -qi '1209:7051'; then \
	  echo "ERROR: 1209:7051 did not enumerate within 25s — is the USB-C cable plugged into the host?"; \
	  pkill -f "probe-rs run --chip STM32U585AIIx" 2>/dev/null; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi
	@echo "==> Running transport e2e test (tools/fwup-transport-test.py)..."
	@rc=0; python3 tools/fwup-transport-test.py --fixture-dir $(FWUP_FIXTURE_DIR) || rc=$$?; \
	pkill -f "probe-rs run --chip STM32U585AIIx" 2>/dev/null || true; \
	echo "===================================="; \
	if [ $$rc -eq 0 ]; then \
	  echo "==> fwup-transport-hw: PASS — full BEGIN+CHUNK+COMMIT round-trip green"; \
	  exit 0; \
	else \
	  echo "==> fwup-transport-hw: FAIL (python rc=$$rc)"; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi

# IWDG validation variant of fwup-transport-hw. Same flow but builds
# BOTH worlds with the `iwdg` feature ON, and inserts a 12 s idle-
# survival check before the transport test. This is the on-silicon
# proof that the USB-path watchdog:
#   * does NOT false-fire during normal idle (the device stays
#     enumerated through the 12 s window — NS heartbeat keeps the IWDG
#     fed), and
#   * does NOT false-fire during the multi-second BEGIN erase or the
#     wipe-halt (handler_is_busy() keeps it fed) — the full
#     BEGIN+CHUNK+COMMIT+failpath+wipe-trigger sequence stays green.
# (Deliberately reuses fwup-transport-e2e on the secure side so the
#  device auto-provisions + enumerates; iwdg is added on TOP of it
#  purely for this validation — production ships iwdg WITHOUT e2e.)
fwup-transport-hw-iwdg: dev-pubkey-fixture fwup-transport-fixture
	@echo "==> Building secure (fwup-transport-e2e + usb + mock-se + IWDG)"
	@FSBL_VENDOR_PUBKEY=$(DEV_VENDOR_PUBKEY) $(RUSTFLAGS_VAR)="$(RUSTFLAGS_SECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/secure \
	    -p sphincs-tz-secure --no-default-features \
	    --features mock-se,ui-noop,stm32u585,usb,fwup-transport-e2e,iwdg
	@echo "==> Building NS (usb + IWDG)"
	@rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
	@$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" \
	  cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
	    -p sphincs-tz-nonsecure --features stm32u585,usb,iwdg
	@echo "==> Flashing..."
	@probe-rs download --chip STM32U585AIIx $(NONSECURE_ELF)
	@probe-rs download --chip STM32U585AIIx $(SECURE_ELF)
	@echo "==> Configuring TrustZone option bytes..."
	@STM32_Programmer_CLI --connect port=SWD \
	  --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
	  SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000
	@echo "==> probe-rs run (background) — letting the device boot + USB enumerate..."
	@(timeout 120 probe-rs run --chip STM32U585AIIx $(SECURE_ELF) > /tmp/fwup-transport-run.log 2>&1 &)
	@for i in $$(seq 1 25); do \
	  if lsusb 2>/dev/null | grep -qi '1209:7051'; then echo "==> Enumerated (~$${i}s)"; break; fi; \
	  sleep 1; \
	done
	@if ! lsusb 2>/dev/null | grep -qi '1209:7051'; then \
	  echo "ERROR: 1209:7051 did not enumerate within 25s"; \
	  pkill -f "probe-rs run --chip STM32U585AIIx" 2>/dev/null; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi
	@echo "==> IWDG idle-survival: device must stay enumerated for 12 s (no watchdog false-fire while idle)..."
	@sleep 12
	@if ! lsusb 2>/dev/null | grep -qi '1209:7051'; then \
	  echo "==> fwup-transport-hw-iwdg: FAIL — device dropped off USB during idle (IWDG false-fired)"; \
	  pkill -f "probe-rs run --chip STM32U585AIIx" 2>/dev/null; \
	  exit 1; \
	fi
	@echo "==> Still enumerated after 12 s idle — no false-fire ✓"
	@echo "==> Running transport e2e test (tools/fwup-transport-test.py)..."
	@rc=0; python3 tools/fwup-transport-test.py --fixture-dir $(FWUP_FIXTURE_DIR) || rc=$$?; \
	pkill -f "probe-rs run --chip STM32U585AIIx" 2>/dev/null || true; \
	echo "===================================="; \
	if [ $$rc -eq 0 ]; then \
	  echo "==> fwup-transport-hw-iwdg: PASS — idle-survival + full round-trip green with IWDG ON"; \
	  exit 0; \
	else \
	  echo "==> fwup-transport-hw-iwdg: FAIL (python rc=$$rc)"; \
	  cat /tmp/fwup-transport-run.log | tail -20; \
	  exit 1; \
	fi

# ── Invariant gates: machine-enforce CLAUDE.md non-negotiable invariants ──
# #5 one PQ signer · #6 immutable bootstrap keys · #7 monotonic unresettable caps.
# Deps gated by cargo-deny [bans]; source gated by .semgrep/pqsigner-invariants.yml.
.PHONY: invariant-gates
SEMGREP ?= $(shell command -v semgrep 2>/dev/null || echo $(HOME)/.venvs/semgrep/bin/semgrep)
invariant-gates:
	@echo "==> [1/3] supply-chain (deps): cargo deny check advisories bans sources"
	@echo "    bans=invariant #5 (no classical signer); advisories=real CVEs"
	@echo "    (unmaintained is workspace-scoped); sources=registry/remote guard."
	cargo deny check advisories bans sources
	@command -v "$(SEMGREP)" >/dev/null 2>&1 || { echo "ERROR: semgrep not found ($(SEMGREP)). Install: python3 -m venv ~/.venvs/semgrep && ~/.venvs/semgrep/bin/pip install semgrep"; exit 1; }
	@echo "==> [2/3] invariants #5/#6/#7 (source, ERROR-level fails the build):"
	"$(SEMGREP)" --config .semgrep/pqsigner-invariants.yml --severity ERROR --error --metrics off --quiet
	@echo "==> [3/3] advisory warnings (non-blocking):"
	-@"$(SEMGREP)" --config .semgrep/pqsigner-invariants.yml --severity WARNING --metrics off --quiet
	@echo "==> invariant-gates: PASS"

# cargo-vet: dependency audit-ATTESTATION gate (SOTA §8 — complements cargo-deny's
# bans/advisories/sources). Every dep must be either trusted-audited (we import
# the Mozilla / Google / Bytecode-Alliance / Embark audit sets, pinned in
# supply-chain/imports.lock) or explicitly exempted in supply-chain/config.toml,
# so a NEW transitive dep forces an audit-or-exempt decision in a reviewable diff.
# Audit down the exemption list over time: `cargo vet certify <crate> <ver>`.
.PHONY: vet
vet:
	@command -v cargo-vet >/dev/null 2>&1 || { echo "ERROR: cargo-vet not found. Install: cargo install --locked cargo-vet"; exit 1; }
	cargo vet --locked

# Supply-chain SBOM (CycloneDX) — a release SIDECAR capturing the full dep tree
# + licenses. NOT embedded in firmware (the secure-world binary is size-critical;
# pair an external SBOM with the FSBL-measured hash, per the SOTA report §8).
# Licenses are RECORDED here, not gated (a license gate is a compliance tripwire,
# not a security property — see deny.toml). Output `*.cdx.json` is gitignored.
.PHONY: sbom
sbom:
	@command -v cargo-cyclonedx >/dev/null 2>&1 || { echo "ERROR: cargo-cyclonedx not found. Install: cargo install cargo-cyclonedx"; exit 1; }
	cargo cyclonedx --format json --all
	@echo "==> sbom: wrote <crate>.cdx.json per workspace member (release sidecars)"

# ---------------------------------------------------------------------------
# Host Rust formal verification (SOTA 2026-06 §1 adopt-now; work-todo §34).
#   kani = bounded model-checking (panic / arithmetic-overflow / slice-OOB
#          freedom) of the untrusted-companion-bytes parse surface.
#   miri = UB detection on the host-reachable `unsafe` (the FI volatile
#          helpers + the decoders).
# SCOPE: host toolchain over HOST-REACHABLE logic. The CMSE veneers, raw
# MMIO, and NS-pointer deref are thumbv8m/hardware-cfg'd OUT of the host
# build, so these do NOT cover those — see work-todo §34.
# ---------------------------------------------------------------------------
.PHONY: kani miri ui-golden
kani:
	@command -v cargo-kani >/dev/null 2>&1 || { echo "ERROR: cargo-kani not found. Install: cargo install --locked kani-verifier && cargo kani setup"; exit 1; }
	@echo "==> Kani: tx-core RLP parsers (decode_item used<=len, bytes_to_u256)"
	cargo kani -p pqsigner-tx-core
	@echo "==> Kani: domain recovery parser (deserialize_pin_state)"
	cargo kani -p pqsigner-domain --harness deserialize_pin_state_panic_free
	@echo "==> Kani: ERC-20 calldata decoder (panic-free + transfer no-misdecode)"
	cargo kani -p pqsigner-tx
	@echo "==> Kani: ERC-7730 IR header parser (offset-bounds safety)"
	cargo kani -p pqsigner-erc7730 --harness erc7730_ir_parse_panic_free
	@echo "==> kani: PASS"

miri:
	@rustup component list --toolchain nightly --installed 2>/dev/null | grep -q '^miri' || rustup component add miri --toolchain nightly
	@echo "==> Miri: FI volatile helpers"
	MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p pqsigner-fi
	@echo "==> Miri: tx-core decoders (RLP / EIP-1559 / keccak)"
	MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p pqsigner-tx-core
	@echo "==> Miri: secure-world NS-pointer deref + validation (the genuine host-reachable unsafe)"
	@# permissive-provenance: the NS-ptr boundary is a legitimate int->ptr cast.
	MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-permissive-provenance" cargo +nightly miri test -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting -- ns_ptr ptr_validate
	@echo "==> miri: PASS"

# UI golden-screenshot gate (Trezor-port, SOTA 2026-06 §6). Builds the e2e
# suite with the `ui-capture` feature so every secure-world Display::flush()
# emits a `[UI-FP] <idx> <sha256>` line (secure/src/ui/capture.rs), runs it
# under QEMU, and diffs the captured per-frame fingerprints against the
# committed tests/ui_fixtures.json. A render regression (layout / text /
# byte drift) flips a hash → tools/ui_fixture.py exits 1. Same trust
# boundary as the display: the fingerprint is produced INSIDE the secure
# world, so it hashes exactly what the trusted UI rendered.
#
#   make ui-golden                          # check against committed fixtures
#   make ui-golden GOLDEN_MODE=--regenerate # re-baseline after an intentional UI change
#
# LOCAL / MANUAL gate (not in CI). ROOT CAUSE (measured 2026-06-18): the
# slowness is NOT the frame emit — it's that this captures frames WHILE running
# the full 24-scenario sign-e2e, and each scenario's SPHINCS+C10 sign over
# QEMU's SOFTWARE SHA-256 is seconds-to-minutes. A 150s bounded run reached
# only Scenario 1 (≈ a full run would be ~60 min). The CI-viable redesign is a
# dedicated RENDER-ONLY harness: render a curated set of representative screens
# (measured-boot fingerprint + a handful of confirm dialogs) directly via the
# display renderers, with NO signing — fast because it skips the C10 signs.
# That harness (~a new `ui-golden`-mode entry that constructs representative
# display inputs + flushes) is the unfinished piece; until then this target
# runs the slow full-e2e capture and is local/manual only. Regenerate fixtures
# only from a clean, intentional render.
GOLDEN_MODE ?= --check
ui-golden:
	@echo "==> Building e2e suite with ui-capture (frame-fingerprint emitter)"
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/secure \
			-p sphincs-tz-secure --no-default-features \
			--features mock-se,debug-log,ui-semihosting,ui-capture,e2e-test
	@$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $(REPRO_FLAGS)" \
		cargo build --locked --release --target $(TARGET) --target-dir target/nonsecure \
			-p sphincs-tz-nonsecure --features e2e-test
	@echo "==> Running e2e under QEMU, capturing [UI-FP] frame fingerprints"
	@log=$$(mktemp); \
	qemu-system-arm \
		-M mps2-an505 -monitor null -serial null -nographic \
		-chardev stdio,id=hostio \
		-semihosting-config enable=on,target=native,chardev=hostio \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF) </dev/null 2>&1 | tee $$log >/dev/null; \
	echo "==> ui-golden ($(GOLDEN_MODE)) vs tests/ui_fixtures.json"; \
	rc=0; python3 tools/ui_fixture.py $(GOLDEN_MODE) tests/ui_fixtures.json < $$log || rc=$$?; \
	rm -f $$log; \
	if [ $$rc -eq 0 ]; then echo "==> ui-golden: PASS"; else echo "==> ui-golden: FAIL (rc=$$rc)"; fi; \
	exit $$rc

# Symbolic-model (ProVerif, Dolev-Yao) proof of the dual-SE seed-unlock protocol:
# seed secrecy under partial compromise (Claims 1/2) + the PIN-gate authentication
# + the anti-vacuity positive control. See contracts/verification/proverif/README.md.
.PHONY: proverif
proverif:
	@command -v proverif >/dev/null 2>&1 || { echo "ERROR: proverif not found. Install: opam install --assume-depexts proverif (CLI build needs no GTK)"; exit 1; }
	@echo "==> ProVerif: dual-SE seed-unlock (secrecy + PIN-gate auth)"
	proverif contracts/verification/proverif/dual_se_unlock.pv
	@echo "==> ProVerif: SE050 SCP03 handshake (session-key secrecy + mutual auth + static-leak residual)"
	proverif contracts/verification/proverif/scp03_handshake.pv
	@echo "==> ProVerif: OPTIGA Shielded Connection handshake (half_O secrecy + mutual auth + PBS-leak residual)"
	proverif contracts/verification/proverif/optiga_shield_handshake.pv
	@echo "==> ProVerif: SCP03 within-session no-forgery (companion to the Tamarin no-replay)"
	proverif contracts/verification/proverif/scp03_replay.pv
	@echo "==> ProVerif: firmware-update authenticity (vendor-signed manifest, domain-separated)"
	proverif contracts/verification/proverif/fw_update_authenticity.pv

# Stateful symbolic model (Tamarin) of the three-way PIN-attempt lockstep:
# a single-counter reset is always caught by the boot reconcile (CORE), an
# all-three reset is the documented residual. Companion to the ProVerif secrecy
# model. See contracts/verification/tamarin/README.md.
.PHONY: tamarin
tamarin:
	@command -v tamarin-prover >/dev/null 2>&1 || { echo "ERROR: tamarin-prover not found. Install the prebuilt linux64 binary + the maude backend (both need no sudo/GHC; see contracts/verification/tamarin/README.md)"; exit 1; }
	@echo "==> Tamarin: three-way PIN-attempt lockstep reconcile"
	tamarin-prover --prove contracts/verification/tamarin/pin_lockstep.spthy
	@echo "==> Tamarin: SCP03 within-session no-replay (counter)"
	tamarin-prover --prove contracts/verification/tamarin/scp03_replay.spthy
	@echo "==> Tamarin: dual-SE XOR seed-split secrecy (one-time-pad, info-theoretic)"
	tamarin-prover --prove contracts/verification/tamarin/seed_split_xor.spthy

# ---------------------------------------------------------------------------
# Discoverability wrappers for the off-Makefile verification tools (SOTA
# 2026-06 §1/§4; docs/tooling-and-systems.md §B). These four were installed
# but had NO root make target, so an agent inventorying `make` targets missed
# them. Each delegates to the canonical runner / vendored harness — the runner
# scripts + tools/sca/DONJON-RUST-TOOLING.md remain the source of truth.
#   halmos  = symbolic EVM execution of the deployed wallet bytecode (A3.* bridge)
#   kontrol = KEVM proofs of the bootstrap-unremovable / owner-table invariants
#   checkct = binsec relational CT proof of the secret primitives on thumbv8m
#   muscat  = Donjon SCA (Welch-T TVLA / CPA) over the rainbow shuffle traces
# ---------------------------------------------------------------------------
.PHONY: halmos kontrol checkct muscat

halmos:
	$(MAKE) -C contracts/verification verify-halmos

kontrol:
	$(MAKE) -C contracts/verification verify-kontrol

# binsec is OCaml + a local opam switch; ~/checkct_env.sh sets the nix PATH,
# OPAMROOT, the `checkct` switch + gmp store paths (DONJON-RUST-TOOLING §1).
# cargo-checkct lives in ~/repos/cargo-checkct (not on PATH). The kdf/fors/th
# drivers prove SECURE; the `driver` (fisher_yates shuffle) is INSECURE BY
# DESIGN (address-channel + statistical misalignment, not bitwise CT) so the
# suite exits non-zero — the three green drivers are the signal, not the exit.
checkct:
	@test -f $(HOME)/checkct_env.sh || { echo "ERROR: ~/checkct_env.sh not found — see tools/sca/DONJON-RUST-TOOLING.md §1 (install binsec + the opam switch)"; exit 1; }
	@test -x $(HOME)/repos/cargo-checkct/target/release/cargo-checkct || { echo "ERROR: cargo-checkct not built — git clone https://github.com/Ledger-Donjon/cargo-checkct ~/repos/cargo-checkct && cargo build --release"; exit 1; }
	@echo "==> cargo-checkct: relational CT proof of kdf/fors/th (+ by-design-INSECURE fisher_yates shuffle) on thumbv8m"
	@bash -c 'source $(HOME)/checkct_env.sh && export PATH="$(HOME)/repos/cargo-checkct/target/release:$(HOME)/.cargo/bin:$$PATH" && cargo-checkct run --dir tools/sca --timeout 300'

# Muscat (Donjon SCA, successor to lascar): Welch-T TVLA + CPA. With TRACES_DIR
# set, runs over those real .npy traces (see DONJON-RUST-TOOLING §2 for the
# f9_traces.npz -> .npy pipeline). With no TRACES_DIR, generates the synthetic
# self-test (ground-truth leaky S-box: TVLA fires, CPA recovers KEY[0]=0x2b) —
# a standalone CI smoke that needs no rainbow run. Override the repo with
# MUSCAT_DIR=...; first run builds the example (~10s).
MUSCAT_DIR ?= $(HOME)/repos/muscat
muscat:
	@test -f $(MUSCAT_DIR)/examples/pqsigner_tvla_cpa.rs || { echo "ERROR: muscat harness missing at $(MUSCAT_DIR) — git clone https://github.com/Ledger-Donjon/muscat ~/repos/muscat && cp tools/sca/muscat/pqsigner_tvla_cpa.rs $(MUSCAT_DIR)/examples/ (+ the [[example]] stanza)"; exit 1; }
ifeq ($(TRACES_DIR),)
	@echo "==> Muscat: no TRACES_DIR — synthetic self-test (ground-truth leaky S-box)"
	@rm -rf /tmp/pq1-muscat-selftest && mkdir -p /tmp/pq1-muscat-selftest/muscat_demo
	cd /tmp/pq1-muscat-selftest && python3 $(CURDIR)/tools/sca/muscat/gen_pqsigner_shape.py
	cd $(MUSCAT_DIR) && TRACES_DIR=/tmp/pq1-muscat-selftest/muscat_demo cargo run --release --example pqsigner_tvla_cpa
else
	@echo "==> Muscat: Welch-T TVLA + CPA over $(TRACES_DIR)"
	cd $(MUSCAT_DIR) && TRACES_DIR=$(TRACES_DIR) cargo run --release --example pqsigner_tvla_cpa
endif
