/* Non-secure world linker script for QEMU mps2-an505 */

MEMORY
{
    /* Non-secure flash: NS alias of SSRAM-0 (offset 0x200000) */
    FLASH : ORIGIN = 0x00200000, LENGTH = 256K

    /* Non-secure SRAM: mps2-an505 SSRAM-1 NS alias, offset 128KB
     * (first 128KB reserved for secure world stack via S alias 0x38000000) */
    RAM   : ORIGIN = 0x28020000, LENGTH = 128K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
