TARGET = thumbv8m.main-none-eabi
RUSTFLAGS_VAR = CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS
VENEERS = $(CURDIR)/target/veneers.o

SECURE_ELF   = target/secure/$(TARGET)/release/sphincs-tz-secure
NONSECURE_ELF = target/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure

# Default: mock secure element (no real chip needed)
# debug-log enables semihosting output from the secure world.
# Remove it for production builds to eliminate all debug strings.
FEATURES ?= mock-se,debug-log

.PHONY: all clean secure nonsecure run run-tropic01 setup-serial

all: secure nonsecure

secure:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure \
		-p sphincs-tz-secure --no-default-features --features $(FEATURES)
	@echo "==> Secure world built (features: $(FEATURES)). Veneers: $(VENEERS)"

nonsecure: secure
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure
	@echo "==> Non-secure world built."

# Run with mock SE (no real TROPIC01 chip needed)
run: all
	qemu-system-arm \
		-M mps2-an505 \
		-nographic \
		-semihosting-config enable=on,target=native \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF)

# Configure /dev/ttyACM0 for TROPIC01 communication
setup-serial:
	@echo "Configuring /dev/ttyACM0 for TROPIC01..."
	stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb
	@echo "Serial port ready."

# Build + run with real TROPIC01 chip via semihosting SPI bridge
# Requires: TROPIC01 TS1302 devkit connected at /dev/ttyACM0
run-tropic01: setup-serial
	$(MAKE) FEATURES=tropic01-se,debug-log all
	qemu-system-arm \
		-M mps2-an505 \
		-nographic \
		-semihosting-config enable=on,target=native \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF)

clean:
	rm -rf target/secure target/nonsecure target/veneers.o
