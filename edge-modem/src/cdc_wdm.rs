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
        Ok(Self { file, timeout })
    }
}

impl crate::QmiTransport for CdcWdmDevice {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.file.write_all(request).map_err(|error| {
            SessionError::transport(format!("write cdc-wdm request: {error}"))
        })?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SessionError::transport(
                    "timed out waiting for QMI response",
                ));
            }
            wait_readable(&self.file, remaining)?;
            let frame = read_qmux_frame(&mut self.file)?;
            if is_indication(&frame) {
                continue;
            }
            return Ok(frame);
        }
    }
}

fn wait_readable(file: &File, timeout: Duration) -> Result<(), SessionError> {
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
    if pollfd.revents & libc::POLLIN == 0 {
        return Err(SessionError::transport(format!(
            "cdc-wdm poll revents 0x{:x}",
            pollfd.revents
        )));
    }
    Ok(())
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

fn read_qmux_frame(file: &mut File) -> Result<Vec<u8>, SessionError> {
    let mut header = [0u8; 3];
    file.read_exact(&mut header)
        .map_err(|error| SessionError::transport(format!("read cdc-wdm header: {error}")))?;
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
        file.read_exact(&mut frame[3..]).map_err(|error| {
            SessionError::transport(format!("read cdc-wdm payload: {error}"))
        })?;
    }
    Ok(frame)
}
