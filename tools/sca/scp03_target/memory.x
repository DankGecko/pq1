/* Conventional layout — exact addresses are irrelevant to the FI/leakage
   logic; rainbow maps whatever PT_LOAD segments the ELF declares. This just
   satisfies cortex-m-rt's link.x. */
MEMORY
{
    FLASH : ORIGIN = 0x08000000, LENGTH = 512K
    RAM   : ORIGIN = 0x20000000, LENGTH = 128K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
