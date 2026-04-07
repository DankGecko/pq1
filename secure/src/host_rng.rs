//! QEMU-only host randomness via ARM semihosting `/dev/urandom`.
//!
//! Used by:
//! * BIP-39 mnemonic generation in `crypto::provision_with_mnemonic`
//! * The ephemeral X25519 keypair for each TROPIC01 e2e session
//!   (`tropic01_se::generate_ephemeral`)
//! * Spot-check word index selection in the seed-phrase wizard
//!
//! On real STM32U585 hardware this module will be replaced by an embassy
//! `Rng` driver. The semihosting backend is fine for QEMU because the
//! "device" is the host kernel CSPRNG.
//!
//! See `docs/architecture.md` "Porting to STM32U585" for the migration plan.

use cortex_m_semihosting::nr;

/// Fill `buf` with random bytes from the host kernel via semihosting.
/// Returns `Err(())` if the semihosting OPEN/READ fails.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    let path = b"/dev/urandom\0";
    let fd = unsafe {
        cortex_m_semihosting::syscall!(OPEN, path.as_ptr(), nr::open::R_BINARY, path.len() - 1)
    };
    if fd as isize == -1 {
        return Err(());
    }
    let not_read = unsafe {
        cortex_m_semihosting::syscall!(READ, fd, buf.as_mut_ptr(), buf.len())
    };
    unsafe { cortex_m_semihosting::syscall!(CLOSE, fd) };
    if not_read != 0 {
        return Err(());
    }
    Ok(())
}

/// One-shot single-byte helper. Panics if `fill` fails because the
/// callers (wizard spot-check, fallback paths) cannot proceed without it.
pub fn byte() -> u8 {
    let mut b = [0u8; 1];
    fill(&mut b).expect("host_rng: semihosting /dev/urandom failed");
    b[0]
}
