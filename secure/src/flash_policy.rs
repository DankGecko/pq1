//! Pure policy for generic secure-bank flash mutations.
//!
//! Bank-1 page 127 is exclusively owned by the append-only first-boot
//! provisioning journal.  Generic flash callers must not be able to erase it
//! or program a quad-word that overlaps it.  Keeping the policy free of MMIO
//! makes the exact boundary and overflow behaviour executable on the host;
//! the hardware driver consumes the validated address/page capabilities.

/// Secure alias of STM32U585 flash bank 1.
pub(crate) const BANK1_BASE: u32 = 0x0C00_0000;
/// Bank-1 page size.
pub(crate) const PAGE_BYTES: u32 = 0x2000;
/// Number of pages in bank 1.
const PAGE_COUNT: u32 = 128;
/// First byte after secure flash bank 1.
const BANK1_END: u32 = BANK1_BASE + PAGE_COUNT * PAGE_BYTES;
/// Page reserved exclusively for the first-boot provisioning journal.
pub(crate) const FIRST_BOOT_JOURNAL_PAGE: u32 = 127;
/// First byte of the first-boot provisioning journal.
pub(crate) const FIRST_BOOT_JOURNAL_ADDR: u32 = BANK1_BASE + FIRST_BOOT_JOURNAL_PAGE * PAGE_BYTES;
/// First byte after the first-boot provisioning journal.
const FIRST_BOOT_JOURNAL_END: u32 = FIRST_BOOT_JOURNAL_ADDR + PAGE_BYTES;
const QUADWORD_BYTES: u32 = 16;

/// A quad-word address proven to be aligned, in bank 1, and disjoint from
/// the first-boot journal.
pub(crate) struct GenericSecureQwAddr(u32);

impl GenericSecureQwAddr {
    /// Validate an address for the generic secure-bank programming API.
    pub(crate) const fn new(addr: u32) -> Option<Self> {
        if addr % QUADWORD_BYTES != 0 {
            return None;
        }
        let end = match addr.checked_add(QUADWORD_BYTES) {
            Some(end) => end,
            None => return None,
        };
        if addr < BANK1_BASE || end > BANK1_END {
            return None;
        }
        if addr < FIRST_BOOT_JOURNAL_END && end > FIRST_BOOT_JOURNAL_ADDR {
            return None;
        }
        Some(Self(addr))
    }

    /// Recover the validated address for the MMIO driver.
    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

/// A bank-1 page proven erasable through the generic erase API.
pub(crate) struct GenericSecurePage(u32);

impl GenericSecurePage {
    /// Validate a page number and exclude the journal-owned page 127.
    pub(crate) const fn new(page: u32) -> Option<Self> {
        if page < FIRST_BOOT_JOURNAL_PAGE {
            Some(Self(page))
        } else {
            None
        }
    }

    /// Recover the validated page number for the MMIO driver.
    pub(crate) const fn get(&self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_quadword_policy_excludes_every_journal_boundary_case() {
        assert_eq!(
            GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR - 16).map(|a| a.get()),
            Some(FIRST_BOOT_JOURNAL_ADDR - 16)
        );

        // Crossing from below, exactly at the start, wholly inside, and the
        // final aligned QW are all journal-owned.
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR - 8).is_none());
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR).is_none());
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_ADDR + 16).is_none());
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_END - 16).is_none());

        // There is no generic bank-1 address above page 127.
        assert!(GenericSecureQwAddr::new(FIRST_BOOT_JOURNAL_END).is_none());
    }

    #[test]
    fn generic_quadword_policy_rejects_misalignment_range_errors_and_overflow() {
        assert!(GenericSecureQwAddr::new(BANK1_BASE).is_some());
        assert!(GenericSecureQwAddr::new(BANK1_BASE + 1).is_none());
        assert!(GenericSecureQwAddr::new(BANK1_BASE - 16).is_none());
        assert!(GenericSecureQwAddr::new(u32::MAX - 15).is_none());
        assert!(GenericSecureQwAddr::new(u32::MAX).is_none());
    }

    #[test]
    fn generic_erase_policy_rejects_journal_and_out_of_range_pages() {
        assert_eq!(GenericSecurePage::new(0).map(|p| p.get()), Some(0));
        assert_eq!(GenericSecurePage::new(126).map(|p| p.get()), Some(126));
        assert!(GenericSecurePage::new(127).is_none());
        assert!(GenericSecurePage::new(128).is_none());
        assert!(GenericSecurePage::new(u32::MAX).is_none());
    }
}
