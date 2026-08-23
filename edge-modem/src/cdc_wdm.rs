use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::io::AsRawFd,
    path::Path,
    time::{Duration, Instant},
};

use crate::SessionError;

const QMUX_INTERFACE_TYPE: u8 = 0x01;
const CONTROL_INDICATION_KIND: u8 = 0x02;
const SERVICE_INDICATION_KIND: u8 = 0x04;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);

/// Linux `cdc-wdm` character device. One file is bound to one modem control
/// channel; the caller must not share it across devices.
pub struct CdcWdmDevice {
    file: File,
    timeout: Duration,
    /// The node this was opened on, carried so an error can name the module
    /// it is about. A bench with three of these produces three identical
    /// messages otherwise, and the one that matters is whichever one just
    /// left the bus.
    device: String,
}

impl CdcWdmDevice {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SessionError> {
        Self::open_with_timeout(path, DEFAULT_TIMEOUT)
    }

    pub fn open_with_timeout(
        path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self, SessionError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                SessionError::transport(format!("open {}: {error}", path.display()))
            })?;
        Ok(Self {
            file,
            timeout,
            device: path.display().to_string(),
        })
    }
}

impl crate::QmiTransport for CdcWdmDevice {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.file
            .write_all(request)
            .map_err(|error| self.io_error("write cdc-wdm request", &error, false))?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SessionError::transport(
                    "timed out waiting for QMI response",
                ));
            }
            wait_readable(&self.file, &self.device, remaining)?;
            let frame = read_qmux_frame(&mut self.file, &self.device)?;
            if is_indication(&frame) {
                continue;
            }
            // Only the answer to the request just written. Anything else on
            // this node is a leftover, and taking a leftover as the answer is
            // how one lost transaction becomes a permanent fault: the session
            // layer rejects the mismatch, the real answer stays unread, and
            // every transaction after it is one frame behind for as long as
            // the modem is up. Seen on the bench as
            // `poll /dev/cdc-wdm1 FAIL response has no pending service 0x00
            // client 0x00 transaction 0x0002`, repeating until the module was
            // power-cycled -- a module that answers everything correctly and
            // is nonetheless reported as unreachable.
            if !answers(request, &frame) {
                continue;
            }
            return Ok(frame);
        }
    }
}

/// Whether `frame` is the response to `request`.
///
/// Addressed by service, client and transaction, which is the whole of what
/// QMUX gives a caller to match on. Frames too short to carry an address
/// cannot be anybody's answer and are dropped by the same rule.
fn answers(request: &[u8], frame: &[u8]) -> bool {
    match (address_of(request), address_of(frame)) {
        (Some(wanted), Some(got)) => wanted == got,
        _ => false,
    }
}

/// `(service, client, transaction)` of a QMUX frame, request or response.
///
/// The control service numbers its transactions in one byte and every other
/// service in two, so the transaction cannot be read without first knowing
/// which service the frame belongs to.
fn address_of(frame: &[u8]) -> Option<(u8, u8, u16)> {
    if frame.len() < 8 {
        return None;
    }
    let service = frame[4];
    let client = frame[5];
    let transaction = if service == 0 {
        u16::from(frame[7])
    } else {
        if frame.len() < 9 {
            return None;
        }
        u16::from_le_bytes([frame[7], frame[8]])
    };
    Some((service, client, transaction))
}

impl CdcWdmDevice {
    /// Classifies an `io::Error` from the node. Everything here happens with
    /// the request already written, except the write itself.
    fn io_error(&self, what: &str, error: &std::io::Error, awaiting_response: bool) -> SessionError {
        if is_gone(error) {
            return SessionError::Disconnected {
                device: self.device.clone(),
                awaiting_response,
            };
        }
        SessionError::transport(format!("{what}: {error}"))
    }

}

/// Whether an `io::Error` means the character device no longer has a modem
/// behind it, as opposed to a transfer that failed while it still did.
fn is_gone(error: &std::io::Error) -> bool {
    // ENODEV, ENXIO and ESHUTDOWN are what a `cdc-wdm` node returns once its
    // USB device has been unbound. On this bench that is a routine event: the
    // modules arrive over USB/IP and a module that stalls its QMI interrupt
    // endpoint takes its whole USB/IP session down with it.
    matches!(
        error.raw_os_error(),
        Some(libc::ENODEV) | Some(libc::ENXIO) | Some(libc::ESHUTDOWN)
    ) || error.kind() == std::io::ErrorKind::UnexpectedEof
}

fn wait_readable(file: &File, device: &str, timeout: Duration) -> Result<(), SessionError> {
    let mut pollfd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let n = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    if n < 0 {
        return Err(SessionError::transport("poll cdc-wdm failed"));
    }
    if n == 0 {
        return Err(SessionError::transport(
            "timed out waiting for QMI response",
        ));
    }
    classify_revents(device, pollfd.revents)
}

/// What `poll` on a `cdc-wdm` node means for a request already written to it.
///
/// `POLLHUP` is not a variation on "transport error": it says the node the
/// request went to has no modem behind it any more. The distinction is the
/// whole difference between "the module refused this send" and "the module
/// took this send and then left the bus", and only the second one must not be
/// retried -- the submit may already be on its way, and the SIM's own MO
/// reference counter shows it usually is.
///
/// Reported as `cdc-wdm poll revents 0x18` this reads like a parser fault. It
/// is `POLLERR|POLLHUP`, which the kernel's `cdc-wdm` driver returns for one
/// reason only: the device is disconnecting.
pub(crate) fn classify_revents(device: &str, revents: libc::c_short) -> Result<(), SessionError> {
    // Data first. A device can be on its way out with a complete frame still
    // buffered, and that frame is the answer we are waiting for.
    if revents & libc::POLLIN != 0 {
        return Ok(());
    }
    if revents & (libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(SessionError::Disconnected {
            device: device.to_string(),
            awaiting_response: true,
        });
    }
    if revents & libc::POLLERR != 0 {
        return Err(SessionError::transport(format!(
            "{device} reported a transfer error (POLLERR) with no response to read"
        )));
    }
    Err(SessionError::transport(format!(
        "cdc-wdm poll revents 0x{revents:x} on {device}"
    )))
}

fn is_indication(frame: &[u8]) -> bool {
    if frame.len() < 7 {
        return false;
    }
    let service = frame[4];
    let kind = frame[6];
    if service == 0 {
        kind == CONTROL_INDICATION_KIND
    } else {
        kind == SERVICE_INDICATION_KIND
    }
}

fn read_qmux_frame(file: &mut File, device: &str) -> Result<Vec<u8>, SessionError> {
    let mut header = [0u8; 3];
    file.read_exact(&mut header)
        .map_err(|error| read_error(device, "header", &error))?;
    if header[0] != QMUX_INTERFACE_TYPE {
        return Err(SessionError::transport(format!(
            "cdc-wdm interface type 0x{:02x}",
            header[0]
        )));
    }

    let rest = u16::from_le_bytes([header[1], header[2]]) as usize;
    let mut frame = vec![0u8; 1 + rest];
    frame[..3].copy_from_slice(&header);
    if rest > 2 {
        file.read_exact(&mut frame[3..])
            .map_err(|error| read_error(device, "payload", &error))?;
    }
    Ok(frame)
}

/// A read that failed on a node whose device may have gone away underneath it.
fn read_error(device: &str, part: &str, error: &std::io::Error) -> SessionError {
    if is_gone(error) {
        return SessionError::Disconnected {
            device: device.to_string(),
            awaiting_response: true,
        };
    }
    SessionError::transport(format!("read cdc-wdm {part} on {device}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "/dev/cdc-wdm2";

    /// The failure this whole classification exists for.
    ///
    /// `0x18` is `POLLERR|POLLHUP`, which is what a send on IMEI
    /// 867018069509705 returns on this bench: the module stalls its QMI
    /// interrupt endpoint, the USB/IP session is torn down, and the node the
    /// request went to stops having a modem behind it. Calling that a
    /// "transport error" hides the one fact the caller needs -- the request
    /// was already handed over.
    #[test]
    fn pollerr_with_pollhup_is_a_disconnect_not_a_transport_error() {
        let error = classify_revents(DEVICE, libc::POLLERR | libc::POLLHUP)
            .expect_err("0x18 must not read as success");
        assert!(
            matches!(
                &error,
                SessionError::Disconnected {
                    device,
                    awaiting_response: true
                } if device == DEVICE
            ),
            "expected a named disconnect, got {error:?}"
        );
        assert!(
            error.left_the_bus_after_the_request(),
            "a send must be able to tell this apart from a refusal"
        );
    }

    /// A latched transfer error with no hangup is a different thing: the
    /// device is still there. Reporting it as a disconnect would tell a
    /// caller not to retry something that never left.
    #[test]
    fn pollerr_alone_is_not_a_disconnect() {
        let error = classify_revents(DEVICE, libc::POLLERR).expect_err("POLLERR is not success");
        assert!(!error.left_the_bus_after_the_request());
        assert!(
            error.to_string().contains("POLLERR"),
            "the operator has to be able to tell which of the two happened: {error}"
        );
    }

    /// A module can be on its way out with the answer already buffered.
    /// Throwing that frame away loses the one authoritative record of what
    /// the modem did with the request.
    #[test]
    fn a_readable_frame_wins_over_a_pending_hangup() {
        classify_revents(DEVICE, libc::POLLIN | libc::POLLHUP).expect("read the buffered frame");
    }

    #[test]
    fn an_unrecognised_mask_still_reports_its_bits() {
        let error = classify_revents(DEVICE, libc::POLLOUT).expect_err("no readable data");
        assert!(error.to_string().contains("0x4"), "{error}");
        assert!(error.to_string().contains(DEVICE), "{error}");
    }

    /// `ENODEV` is what the node returns once its USB device is unbound, and
    /// it reaches the caller as an ordinary `io::Error` rather than through
    /// `poll`. Both routes have to end at the same conclusion.
    #[test]
    fn an_unbound_node_reads_as_gone() {
        assert!(is_gone(&std::io::Error::from_raw_os_error(libc::ENODEV)));
        assert!(is_gone(&std::io::Error::from_raw_os_error(libc::ENXIO)));
        assert!(!is_gone(&std::io::Error::from_raw_os_error(libc::EAGAIN)));
    }

    /// One CTL request and the response to it, byte for byte off the bench.
    fn ctl_sync_request() -> Vec<u8> {
        hex("010b00000000000127000000")
    }

    fn ctl_sync_response() -> Vec<u8> {
        hex("01120080000001012700070002040000000000")
    }

    /// The frame that was still in flight from the previous cycle: a CTL
    /// response to transaction 2, arriving while transaction 1 is awaited.
    fn stale_ctl_response() -> Vec<u8> {
        hex("011700800000010222000c00020400000000000102000501")
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The fault that took IMEI 862547055142811 out of the fleet.
    ///
    /// A transaction that timed out leaves its answer on the wire. The next
    /// request reads that answer, and if the transport hands it up as the
    /// response the session layer rejects it -- while the answer that was
    /// actually asked for stays unread and becomes the next request's
    /// leftover. The module answers everything correctly and is reported
    /// unreachable for as long as it stays powered.
    #[test]
    fn a_leftover_from_a_previous_transaction_is_not_the_answer() {
        assert!(
            !answers(&ctl_sync_request(), &stale_ctl_response()),
            "transaction 2's answer must not settle transaction 1"
        );
        assert!(
            answers(&ctl_sync_request(), &ctl_sync_response()),
            "the real answer must still be recognised"
        );
    }

    /// Same transaction number, different service: WMS transaction 1 is not
    /// the answer to CTL transaction 1.
    #[test]
    fn a_matching_transaction_on_another_service_is_not_the_answer() {
        let wms_request = hex("011e0000050100010020001200010f00060c0000212c05810180f600000132");
        assert!(!answers(&ctl_sync_request(), &wms_request));
        assert_eq!(address_of(&wms_request), Some((0x05, 0x01, 1)));
        // CTL numbers transactions in one byte; a service uses two, and
        // reading a service frame the control way finds the wrong number.
        assert_eq!(address_of(&ctl_sync_request()), Some((0x00, 0x00, 1)));
    }

    #[test]
    fn a_frame_too_short_to_carry_an_address_answers_nothing() {
        assert_eq!(address_of(&[0x01, 0x02, 0x00]), None);
        assert!(!answers(&ctl_sync_request(), &[0x01, 0x02, 0x00]));
    }

    /// The skip has to happen in the transport, where the next frame can
    /// still be read. Driven over a socket pair, which like the device is
    /// read/write on one descriptor and readable only while something is
    /// queued, so `poll` decides the same way it does on the bench.
    #[test]
    fn transact_reads_past_a_leftover_to_the_real_answer() {
        use crate::QmiTransport;
        use std::os::unix::io::FromRawFd;

        let mut fds = [0 as libc::c_int; 2];
        let made = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(made, 0, "socketpair");
        let mut modem = unsafe { File::from_raw_fd(fds[1]) };
        // Queued in the order the modem delivered them: the previous
        // transaction's answer first, then this one's.
        modem.write_all(&stale_ctl_response()).expect("leftover");
        modem.write_all(&ctl_sync_response()).expect("answer");

        let mut device = CdcWdmDevice {
            file: unsafe { File::from_raw_fd(fds[0]) },
            timeout: Duration::from_secs(2),
            device: "/dev/cdc-wdm-test".into(),
        };
        let frame = device
            .transact(&ctl_sync_request())
            .expect("the answer is on the wire, one leftover behind");
        assert_eq!(frame, ctl_sync_response());
    }
}
