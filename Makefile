TARGET = thumbv8m.main-none-eabi
RUSTFLAGS_VAR = CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS
VENEERS = $(CURDIR)/target/veneers.o

SECURE_ELF   = target/secure/$(TARGET)/release/sphincs-tz-secure
NONSECURE_ELF = target/nonsecure/$(TARGET)/release/sphincs-tz-nonsecure

.PHONY: all clean secure nonsecure run

all: secure nonsecure

secure:
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/secure -p sphincs-tz-secure
	@echo "==> Secure world built. Veneers: $(VENEERS)"

nonsecure: secure
	$(RUSTFLAGS_VAR)="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=$(VENEERS)" \
	cargo build --release --target $(TARGET) --target-dir target/nonsecure -p sphincs-tz-nonsecure
	@echo "==> Non-secure world built."

run: all
	qemu-system-arm \
		-M mps2-an505 \
		-nographic \
		-semihosting-config enable=on,target=native \
		-kernel $(SECURE_ELF) \
		-device loader,file=$(NONSECURE_ELF)

clean:
	rm -rf target/secure target/nonsecure target/veneers.o
