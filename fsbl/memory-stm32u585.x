/* First-stage bootloader linker script for STM32U585.
 *
 * Legacy bench layout: the FSBL occupies the first 32 KB of bank 1
 * (pages 0–3). This file is not production geometry or factory authority.
 * Draft 1.1 proposes a different envelope and keeps FLASH/RAM/factory gates
 * open; do not derive WRP or irreversible operations from this linker script.
 *
 * Flash layout (bank 1, secure alias):
 *   0x0C00_0000  FSBL           32 KB   (legacy bench pages 0–3)
 *   0x0C00_8000  Manifest A      8 KB   (page 4)
 *   0x0C00_A000  Manifest B      8 KB   (page 5)
 *   0x0C00_C000  Boot state      8 KB   (page 6)
 *   0x0C00_E000  Slot A secure 464 KB   (pages 7–64)
 *   0x0C08_2000  Slot B secure 464 KB   (pages 65–122)
 *   0x0C0F_A000  Reserved (admin/wipe state, wrapped BHK, etc.; no PBS storage)
 *
 * RAM: the first 16 KB of SRAM1 (0x3000_0000) is reserved for the
 * FSBL's stack. The runtime slot reuses the full SRAM1 from 0x0 on
 * branch (FSBL clears its own stack + variables before leaving).
 */

MEMORY
{
    FLASH : ORIGIN = 0x0C000000, LENGTH = 32K
    RAM   : ORIGIN = 0x30000000, LENGTH = 16K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
