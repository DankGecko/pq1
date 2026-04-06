/// SPI-over-USB transport using ARM semihosting file I/O.
///
/// This is a no_std port of desktop/src/usb_dongle.rs. It opens the host's
/// /dev/ttyACM0 via semihosting SYS_OPEN and speaks the same hex-encoded
/// SPI protocol as the TS1302 USB dongle.
///
/// The host must pre-configure the serial port before launching QEMU:
///   stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb

use cortex_m_semihosting::nr;
use embedded_hal::spi::{self, Operation};

// Max SPI frame size (L2_MAX_FRAME_SIZE + overhead)
const MAX_FRAME: usize = 300;
// Hex-encoded frame buffer: 2 chars per byte + "x\n" + margin
const HEX_BUF_SIZE: usize = MAX_FRAME * 2 + 4;
// Read line buffer
const READ_BUF_SIZE: usize = MAX_FRAME * 2 + 16;

#[derive(Debug)]
pub enum SpiError {
    OpenFailed,
    WriteFailed,
    ReadFailed,
    ProtocolError,
    HexParseError,
}

impl spi::Error for SpiError {
    fn kind(&self) -> spi::ErrorKind {
        spi::ErrorKind::Other
    }
}

pub struct SemihostingSpi {
    fd: usize,
}

impl SemihostingSpi {
    /// Open the USB dongle serial port via semihosting.
    /// `path` must be a null-terminated device path (e.g., b"/dev/ttyACM0\0").
    pub fn open(path: &[u8]) -> Result<Self, SpiError> {
        let fd = unsafe {
            cortex_m_semihosting::syscall!(OPEN, path.as_ptr(), nr::open::RW_BINARY, path.len() - 1)
        };
        if fd as isize == -1 {
            return Err(SpiError::OpenFailed);
        }
        Ok(Self { fd })
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<(), SpiError> {
        let mut offset = 0;
        while offset < data.len() {
            let remaining = &data[offset..];
            let not_written = unsafe {
                cortex_m_semihosting::syscall!(WRITE, self.fd, remaining.as_ptr(), remaining.len())
            };
            if not_written > remaining.len() {
                return Err(SpiError::WriteFailed);
            }
            offset += remaining.len() - not_written;
        }
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8, SpiError> {
        let mut buf = [0u8; 1];
        // Retry loop — semihosting read may return 0 bytes initially
        for _ in 0..100_000 {
            let not_read = unsafe {
                cortex_m_semihosting::syscall!(READ, self.fd, buf.as_mut_ptr(), 1usize)
            };
            if not_read == 0 {
                return Ok(buf[0]);
            }
        }
        Err(SpiError::ReadFailed)
    }

    fn read_line(&mut self, buf: &mut [u8]) -> Result<usize, SpiError> {
        let mut idx = 0;
        loop {
            let b = self.read_byte()?;
            if idx < buf.len() {
                buf[idx] = b;
                idx += 1;
            }
            if b == b'\n' {
                return Ok(idx);
            }
        }
    }

    /// Perform an SPI transfer using the USB dongle hex protocol.
    /// Sends hex-encoded data + "x\n", receives hex-encoded response.
    fn spi_transfer(&mut self, data: &mut [u8]) -> Result<(), SpiError> {
        // Encode TX bytes as hex + "x\n"
        let mut tx_buf = [0u8; HEX_BUF_SIZE];
        let mut tx_len = 0;
        for &b in data.iter() {
            tx_buf[tx_len] = hex_nibble(b >> 4);
            tx_buf[tx_len + 1] = hex_nibble(b & 0x0F);
            tx_len += 2;
        }
        tx_buf[tx_len] = b'x';
        tx_buf[tx_len + 1] = b'\n';
        tx_len += 2;

        self.write_bytes(&tx_buf[..tx_len])?;

        // Small delay for chip processing
        for _ in 0..50_000 {
            cortex_m::asm::nop();
        }

        // Read hex response line
        let mut rx_buf = [0u8; READ_BUF_SIZE];
        let rx_len = self.read_line(&mut rx_buf)?;

        // Trim trailing \r\n or \n
        let mut end = rx_len;
        while end > 0 && (rx_buf[end - 1] == b'\n' || rx_buf[end - 1] == b'\r') {
            end -= 1;
        }

        // Validate response length (2 hex chars per byte)
        if end != data.len() * 2 {
            return Err(SpiError::ProtocolError);
        }

        // Decode hex response into data buffer
        for i in 0..data.len() {
            let hi = parse_hex_nibble(rx_buf[i * 2])?;
            let lo = parse_hex_nibble(rx_buf[i * 2 + 1])?;
            data[i] = (hi << 4) | lo;
        }

        Ok(())
    }

    /// Deassert CS: send "CS=0\n", expect "OK\r\n"
    fn cs_deassert(&mut self) -> Result<(), SpiError> {
        self.write_bytes(b"CS=0\n")?;

        let mut buf = [0u8; 4];
        for i in 0..4 {
            buf[i] = self.read_byte()?;
        }
        if &buf != b"OK\r\n" {
            return Err(SpiError::ProtocolError);
        }
        Ok(())
    }
}

impl spi::ErrorType for SemihostingSpi {
    type Error = SpiError;
}

impl spi::SpiDevice for SemihostingSpi {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let mut had_transfer = false;
        for op in operations {
            match op {
                Operation::TransferInPlace(data) => {
                    self.spi_transfer(data)?;
                    had_transfer = true;
                }
                Operation::Read(buf) => {
                    buf.fill(0x00);
                    self.spi_transfer(buf)?;
                    had_transfer = true;
                }
                Operation::Transfer(read, write) => {
                    read[..write.len()].copy_from_slice(write);
                    self.spi_transfer(read)?;
                    had_transfer = true;
                }
                Operation::Write(data) => {
                    let mut tmp = [0u8; MAX_FRAME];
                    let len = data.len().min(MAX_FRAME);
                    tmp[..len].copy_from_slice(&data[..len]);
                    self.spi_transfer(&mut tmp[..len])?;
                    had_transfer = true;
                }
                Operation::DelayNs(ns) => {
                    let iters = (*ns as u64) / 100;
                    for _ in 0..iters {
                        cortex_m::asm::nop();
                    }
                }
            }
        }
        if had_transfer {
            self.cs_deassert()?;
        }
        Ok(())
    }
}

fn hex_nibble(n: u8) -> u8 {
    match n & 0x0F {
        0..=9 => b'0' + n,
        _ => b'A' + (n - 10),
    }
}

fn parse_hex_nibble(c: u8) -> Result<u8, SpiError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(SpiError::HexParseError),
    }
}
