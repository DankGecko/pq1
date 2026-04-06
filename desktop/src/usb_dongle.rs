// USB dongle SPI transport for the TROPIC01 TS1302 devkit.
// Based on the libtropic-rs example (BSD-3-Clause-Clear license, Filancore GmbH).

use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

use embedded_hal::spi::{self, Operation};
use log::debug;
use serialport::SerialPort;

#[derive(Debug)]
pub enum UsbDongleError {
    Io(std::io::Error),
    Protocol(String),
}

impl std::fmt::Display for UsbDongleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "USB dongle I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "USB dongle protocol error: {msg}"),
        }
    }
}

impl std::error::Error for UsbDongleError {}

impl spi::Error for UsbDongleError {
    fn kind(&self) -> spi::ErrorKind {
        spi::ErrorKind::Other
    }
}

impl From<std::io::Error> for UsbDongleError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serialport::Error> for UsbDongleError {
    fn from(e: serialport::Error) -> Self {
        Self::Protocol(e.to_string())
    }
}

pub struct UsbDongle {
    port: Box<dyn SerialPort>,
}

impl UsbDongle {
    pub fn new(path: &str, baud_rate: u32) -> Result<Self, UsbDongleError> {
        let port = serialport::new(path, baud_rate)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(Duration::from_millis(100))
            .open()?;

        Ok(Self { port })
    }

    fn spi_transfer(&mut self, data: &mut [u8]) -> Result<(), UsbDongleError> {
        debug!("SPI TX ({} bytes): {:02X?}", data.len(), data);

        let hex_tx: String = data.iter().map(|b| format!("{b:02X}")).collect();
        let cmd = format!("{hex_tx}x\n");
        self.port.write_all(cmd.as_bytes())?;
        self.port.flush()?;

        thread::sleep(Duration::from_millis(10));

        let response = self.read_line()?;
        let response = response.trim_end_matches("\r\n").trim_end_matches('\n');
        debug!("SPI RX raw: {:?}", response);

        if response.len() != data.len() * 2 {
            return Err(UsbDongleError::Protocol(format!(
                "expected {} hex chars, got {}",
                data.len() * 2,
                response.len()
            )));
        }

        for (i, chunk) in response.as_bytes().chunks(2).enumerate() {
            let hex_str =
                std::str::from_utf8(chunk).map_err(|e| UsbDongleError::Protocol(e.to_string()))?;
            data[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|e| UsbDongleError::Protocol(format!("invalid hex '{hex_str}': {e}")))?;
        }

        debug!("SPI RX ({} bytes): {:02X?}", data.len(), data);
        Ok(())
    }

    fn cs_deassert(&mut self) -> Result<(), UsbDongleError> {
        self.port.write_all(b"CS=0\n")?;
        self.port.flush()?;

        let mut buf = [0u8; 4];
        self.port.read_exact(&mut buf)?;
        if &buf != b"OK\r\n" {
            return Err(UsbDongleError::Protocol(format!(
                "expected 'OK\\r\\n' after CS=0, got {:?}",
                String::from_utf8_lossy(&buf)
            )));
        }

        Ok(())
    }

    fn read_line(&mut self) -> Result<String, UsbDongleError> {
        let mut result = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            self.port.read_exact(&mut byte)?;
            result.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        String::from_utf8(result).map_err(|e| UsbDongleError::Protocol(e.to_string()))
    }
}

impl spi::ErrorType for UsbDongle {
    type Error = UsbDongleError;
}

impl spi::SpiDevice for UsbDongle {
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
                    read.copy_from_slice(write);
                    self.spi_transfer(read)?;
                    had_transfer = true;
                }
                Operation::Write(data) => {
                    let mut tmp = data.to_vec();
                    self.spi_transfer(&mut tmp)?;
                    had_transfer = true;
                }
                Operation::DelayNs(ns) => {
                    thread::sleep(Duration::from_nanos(u64::from(*ns)));
                }
            }
        }

        if had_transfer {
            self.cs_deassert()?;
        }

        Ok(())
    }
}
