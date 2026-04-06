/* Secure world linker script for QEMU mps2-an505 (Cortex-M33 TrustZone)
 *
 * cortex-m-rt's link.x INCLUDEs this file.
 *
 * QEMU 8.2.2 workaround: SG instruction verification reads through the
 * NS alias, so the MPC block containing the veneers must be marked NS.
 * We place the NSC veneers at SSRAM-0 offset 0x3FC000 (block ~4080,
 * in NS MPC territory) via a separate NSC memory region.
 */

MEMORY
{
    /* Secure flash: SSRAM-0 S alias, first ~2MB (MPC blocks 0-63 = secure) */
    FLASH : ORIGIN = 0x10000000, LENGTH = 256K

    /* NSC region: SSRAM-0 S alias at offset 0x3FF000 (near end of 4MB).
     * Must be in NS MPC blocks (64+) so QEMU's SG check can read via NS alias.
     * Offset 0x3FF000 = block 4092 = LUT word 127, well into NS territory.
     * NS flash is at offset 0x200000-0x23FFFF, so no collision. */
    NSC   : ORIGIN = 0x103FF000, LENGTH = 4K

    /* Secure SRAM: SSRAM-1 S alias */
    RAM   : ORIGIN = 0x38000000, LENGTH = 128K
}

/* Stack grows downward from top of secure SRAM */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
