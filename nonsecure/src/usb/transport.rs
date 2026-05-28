//! Ledger-compatible APDU-over-HID transport.
//!
//! Fragments/reassembles APDUs into 64-byte HID reports using the
//! standard hardware-wallet framing protocol (Ledger/Keycard Shell).
//!
//! Response flow for large data (e.g. 17 KB signatures):
//! 1. Command handler returns first APDU response (≤255 bytes) with
//!    SW=0x61XX indicating more data available.
//! 2. Host sends GET_RESPONSE (INS 0xC0) APDUs to drain remaining data.
//! 3. Each response APDU is individually HID-framed (fragmented into
//!    64-byte HID reports).

use sphincs_tz_shared::{HID_REPORT_SIZE, HID_TAG_APDU};
use sphincs_tz_shared::apdu_framing::{
    FrameOutcome, HidFrameAssembler, HID_CONT_DATA, HID_FIRST_DATA, MAX_APDU_RX,
};
use super::hid::PqSignerHid;
use super::UsbBusType;

/// APDU-over-HID transport state machine.
///
/// RX framing logic — `HidFrameAssembler` — lives in the `shared` crate
/// so the production path here and the proptest harness in
/// `shared/src/apdu_framing.rs::fuzz_props` exercise byte-identical
/// state-machine code. Adding a new edge case there immediately covers
/// this transport too.
pub struct Transport {
    pub hid: PqSignerHid<'static, UsbBusType>,

    // RX state: bookkeeping (channel/seq/expected) lives in the
    // assembler; the actual reassembly buffer is owned here.
    rx: HidFrameAssembler,
    rx_buf: [u8; MAX_APDU_RX],

    // USB frame number (OTG_DSTS.FNSOF) captured when a multi-frame
    // reassembly began, or `None` when idle. Drives the 5 s reassembly
    // timeout in `check_rx_timeout`. `Some` precisely while the
    // assembler is mid-APDU (between a seq=0 NeedMore and the matching
    // ApduComplete/Dropped).
    rx_start_frame: Option<u16>,

    // TX state: fragment one response APDU into multiple HID frames.
    // `channel_id` is captured from the most recent successfully
    // reassembled RX so outgoing frames carry the matching id.
    channel_id: u16,
    tx_buf: [u8; 256],   // response APDU (max 255 bytes, fits any single APDU)
    tx_len: usize,
    tx_pos: usize,
    tx_seq: u16,
    tx_active: bool,
}

/// 5 s reassembly timeout in USB frames (1 frame = 1 ms SOF). Below
/// the 14-bit `OTG_DSTS.FNSOF` wrap (16.384 s) so wrap-aware
/// subtraction stays unambiguous. §19 P0 "Bounded APDU reassembly".
pub const RX_REASSEMBLY_TIMEOUT_FRAMES: u16 = 5000;

impl Transport {
    pub fn new(hid: PqSignerHid<'static, UsbBusType>) -> Self {
        Self {
            hid,
            rx: HidFrameAssembler::new(),
            rx_buf: [0u8; MAX_APDU_RX],
            rx_start_frame: None,
            channel_id: 0,
            tx_buf: [0u8; 256],
            tx_len: 0,
            tx_pos: 0,
            tx_seq: 0,
            tx_active: false,
        }
    }

    /// Try to receive a complete APDU from the host.
    /// Returns `Some(slice)` when a full APDU has been reassembled
    /// from one or more HID frames.
    ///
    /// `now_frame` is the current `OTG_DSTS.FNSOF` (see
    /// `usb::usb_frame_number`); it stamps the reassembly start so
    /// `check_rx_timeout` can bound how long a partial APDU may sit
    /// half-assembled.
    pub fn try_receive(&mut self, now_frame: u16) -> Option<&[u8]> {
        let mut report = [0u8; HID_REPORT_SIZE];
        let n = self.hid.read_report(&mut report)?;

        match self.rx.process_frame(&report, n, &mut self.rx_buf) {
            FrameOutcome::ApduComplete(len) => {
                self.channel_id = self.rx.channel_id();
                self.rx_start_frame = None;
                Some(&self.rx_buf[..len])
            }
            FrameOutcome::PingEcho => {
                self.hid.write_report(&report);
                None
            }
            FrameOutcome::NeedMore => {
                // Reassembly in progress — stamp the start frame on the
                // transition from idle so the total-reassembly clock
                // runs from the first chunk, not the latest.
                if self.rx_start_frame.is_none() {
                    self.rx_start_frame = Some(now_frame);
                }
                None
            }
            FrameOutcome::Dropped => {
                self.rx_start_frame = None;
                None
            }
        }
    }

    /// Enforce the reassembly timeout. Call once per main-loop
    /// iteration with the current `OTG_DSTS.FNSOF`. If a partial APDU
    /// has been sitting half-assembled longer than
    /// `RX_REASSEMBLY_TIMEOUT_FRAMES`, scrub the reassembly buffer +
    /// reset the assembler and return `true`.
    ///
    /// Why: a host that sends a seq=0 (declaring a large APDU) and
    /// then stalls would otherwise pin a partial secret-bearing buffer
    /// indefinitely. The frame clock only advances while the host is
    /// sending SOFs, so a genuinely-idle (suspended/unplugged) link
    /// won't false-trip this.
    pub fn check_rx_timeout(&mut self, now_frame: u16) -> bool {
        let Some(start) = self.rx_start_frame else {
            return false;
        };
        // Wrap-aware elapsed over the 14-bit frame counter.
        let elapsed = now_frame.wrapping_sub(start) & 0x3FFF;
        if elapsed >= RX_REASSEMBLY_TIMEOUT_FRAMES {
            self.rx_buf.fill(0);
            self.rx.reset();
            self.rx_start_frame = None;
            return true;
        }
        false
    }

    /// Queue a response APDU for HID-framed transmission.
    ///
    /// The response data at `ptr` of `len` bytes (including 2-byte SW)
    /// is copied into an internal buffer and fragmented into 64-byte
    /// HID reports by `poll_tx()`.
    ///
    /// # Safety
    /// `ptr` must be valid for `len` bytes.
    pub unsafe fn queue_response(&mut self, ptr: *const u8, len: usize) {
        // FI-hardened length clamp — the secure-side `len` flows
        // directly into a `copy_nonoverlapping`, so an EMFI-glitch on
        // the `min` here would let a stale-or-faulted `len` punch past
        // `tx_buf` end. `pqsigner_fi::fi_min` recomputes via the
        // opposite branch if the result fails the post-condition.
        let copy_len = pqsigner_fi::fi_min(len, self.tx_buf.len());
        core::ptr::copy_nonoverlapping(ptr, self.tx_buf.as_mut_ptr(), copy_len);
        self.tx_len = copy_len;
        self.tx_pos = 0;
        self.tx_seq = 0;
        self.tx_active = true;
    }

    /// Send pending HID frames for the current response APDU.
    /// Returns true if a frame was sent.
    pub fn poll_tx(&mut self) -> bool {
        if !self.tx_active {
            return false;
        }

        let mut frame = [0u8; HID_REPORT_SIZE];
        frame[0..2].copy_from_slice(&self.channel_id.to_be_bytes());
        frame[2] = HID_TAG_APDU;
        frame[3..5].copy_from_slice(&self.tx_seq.to_be_bytes());

        if self.tx_seq == 0 {
            // First HID frame: includes data length
            frame[5..7].copy_from_slice(&(self.tx_len as u16).to_be_bytes());
            let remaining = self.tx_len - self.tx_pos;
            let chunk = core::cmp::min(HID_FIRST_DATA, remaining);
            frame[7..7 + chunk].copy_from_slice(&self.tx_buf[self.tx_pos..self.tx_pos + chunk]);
            if !self.hid.write_report(&frame) {
                return false;
            }
            self.tx_pos += chunk;
            self.tx_seq += 1;
        } else {
            // Continuation HID frame
            let remaining = self.tx_len - self.tx_pos;
            let chunk = core::cmp::min(HID_CONT_DATA, remaining);
            frame[5..5 + chunk].copy_from_slice(&self.tx_buf[self.tx_pos..self.tx_pos + chunk]);
            if !self.hid.write_report(&frame) {
                return false;
            }
            self.tx_pos += chunk;
            self.tx_seq += 1;
        }

        if self.tx_pos >= self.tx_len {
            self.tx_active = false;
        }
        true
    }

    pub fn is_tx_active(&self) -> bool {
        self.tx_active
    }
}
