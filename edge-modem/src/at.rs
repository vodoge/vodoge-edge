//! AT command channel over a Quectel serial interface.
//!
//! QMI covers the structured operations this agent performs in normal service.
//! Diagnosis is a different job: an operator debugging a stuck module needs to
//! issue arbitrary vendor commands and read exactly what the module answered,
//! including the vendor extensions (`AT+QGMR`, `AT+QMBNCFG`, `AT+QCFG`) that
//! have no QMI equivalent at all. This module exists for that path only.
//!
//! An EC20-class module exposes four serial interfaces. Interface `1.2` is the
//! AT control port and `1.3` is the modem/PPP port. Both answer `AT`, but the
//! modem port is where a data session lives, so control traffic belongs on
//! `1.2` and this module never picks `1.3` on its own.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Serial interface number carrying the AT control port on Quectel modules.
pub const AT_CONTROL_INTERFACE: &str = "1.2";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 512;

/// Failures from opening or talking to an AT port.
#[derive(Debug)]
pub enum AtError {
    Open { path: PathBuf, reason: String },
    Io(String),
    Timeout { command: String, elapsed: Duration },
    /// The module answered, but with a terminal error result code.
    Rejected { command: String, response: String },
}

impl std::fmt::Display for AtError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, reason } => write!(formatter, "open {}: {reason}", path.display()),
            Self::Io(reason) => formatter.write_str(reason),
            Self::Timeout { command, elapsed } => write!(
                formatter,
                "{command} did not terminate within {}ms",
                elapsed.as_millis()
            ),
            Self::Rejected { command, response } => {
                write!(formatter, "{command} rejected: {response}")
            }
        }
    }
}

impl std::error::Error for AtError {}

/// One AT command and everything the module said in reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtExchange {
    pub command: String,
    /// Response lines with the echoed command and the final result code
    /// removed, in the order the module produced them.
    pub lines: Vec<String>,
    /// The terminal result code, e.g. `OK` or `+CME ERROR: 10`.
    pub terminator: String,
    pub elapsed: Duration,
}

impl AtExchange {
    pub fn succeeded(&self) -> bool {
        self.terminator == "OK"
    }

    /// Full text as it appeared on the wire, for a console transcript.
    pub fn transcript(&self) -> String {
        let mut out = self.lines.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&self.terminator);
        out
    }
}

/// An open AT control port.
pub struct AtPort {
    file: File,
    path: PathBuf,
    timeout: Duration,
}

impl AtPort {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AtError> {
        Self::open_with_timeout(path, DEFAULT_TIMEOUT)
    }

    pub fn open_with_timeout(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, AtError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| AtError::Open {
                path: path.clone(),
                reason: error.to_string(),
            })?;
        configure_raw(&file).map_err(|reason| AtError::Open {
            path: path.clone(),
            reason,
        })?;
        let mut port = Self {
            file,
            path,
            timeout,
        };
        port.drain();
        Ok(port)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run one command and read until a terminal result code.
    ///
    /// A rejection is returned as a successful exchange carrying the error
    /// terminator, not as `Err`. A console has to show `+CME ERROR: 10` as the
    /// module's answer; only losing the port is a transport failure.
    pub fn command(&mut self, command: &str) -> Result<AtExchange, AtError> {
        let command = command.trim();
        self.drain();
        let started = Instant::now();
        self.file
            .write_all(format!("{command}\r").as_bytes())
            .map_err(|error| AtError::Io(format!("write {command}: {error}")))?;
        self.file
            .flush()
            .map_err(|error| AtError::Io(format!("flush {command}: {error}")))?;

        let mut buffer = String::new();
        loop {
            if started.elapsed() >= self.timeout {
                return Err(AtError::Timeout {
                    command: command.to_string(),
                    elapsed: started.elapsed(),
                });
            }
            let remaining = self.timeout.saturating_sub(started.elapsed());
            if !wait_readable(&self.file, remaining)? {
                continue;
            }
            let mut chunk = [0u8; READ_CHUNK];
            let read = self
                .file
                .read(&mut chunk)
                .map_err(|error| AtError::Io(format!("read {command}: {error}")))?;
            if read == 0 {
                continue;
            }
            buffer.push_str(&String::from_utf8_lossy(&chunk[..read]));
            if let Some(terminator) = terminal_code(&buffer) {
                let lines = response_lines(&buffer, command, &terminator);
                return Ok(AtExchange {
                    command: command.to_string(),
                    lines,
                    terminator,
                    elapsed: started.elapsed(),
                });
            }
        }
    }

    /// Discard unsolicited output left over from a previous session, so it does
    /// not get attributed to the next command.
    fn drain(&mut self) {
        let mut chunk = [0u8; READ_CHUNK];
        while matches!(wait_readable(&self.file, Duration::from_millis(0)), Ok(true)) {
            match self.file.read(&mut chunk) {
                Ok(n) if n > 0 => continue,
                _ => break,
            }
        }
    }
}

/// Serial interface path that carries the AT control port for the USB device
/// backing `qmi_path`.
///
/// The pairing goes through sysfs rather than an index guess: `/dev/ttyUSB2`
/// only belongs to the same module as `/dev/cdc-wdm0` because they hang off the
/// same USB device, and that stops being true the moment a stick is unplugged.
pub fn at_port_for_qmi(qmi_path: &Path) -> Option<PathBuf> {
    let name = qmi_path.file_name()?.to_str()?;
    let usb = usb_device_of(&PathBuf::from(format!("/sys/class/usbmisc/{name}/device")))?;
    for entry in std::fs::read_dir("/sys/class/tty").ok()? {
        let entry = entry.ok()?;
        let tty = entry.file_name();
        let tty = tty.to_str()?;
        if !tty.starts_with("ttyUSB") {
            continue;
        }
        let link = PathBuf::from(format!("/sys/class/tty/{tty}/device"));
        let Some(candidate) = usb_device_of(&link) else {
            continue;
        };
        if candidate != usb {
            continue;
        }
        if interface_of(&link).as_deref() == Some(AT_CONTROL_INTERFACE) {
            return Some(PathBuf::from(format!("/dev/{tty}")));
        }
    }
    None
}

/// USB device identifier, e.g. `2-4.1`, from a sysfs device link.
fn usb_device_of(link: &Path) -> Option<String> {
    let resolved = std::fs::canonicalize(link).ok()?;
    let text = resolved.to_str()?;
    // The interface directory is `<usb-device>:<config>.<interface>`; the part
    // before the colon names the device the interface belongs to.
    text.rsplit('/')
        .find_map(|segment| segment.split_once(':').map(|(device, _)| device.to_string()))
}

/// Interface number, e.g. `1.2`, from a sysfs device link.
fn interface_of(link: &Path) -> Option<String> {
    let resolved = std::fs::canonicalize(link).ok()?;
    let text = resolved.to_str()?;
    text.rsplit('/')
        .find_map(|segment| segment.split_once(':').map(|(_, interface)| interface.to_string()))
}

/// Put the tty in raw mode at 115200 8N1 with no flow control.
///
/// Without this the line discipline echoes input and buffers by line, which
/// corrupts multi-line responses such as `AT+COPS=?`.
#[cfg(target_os = "linux")]
fn configure_raw(file: &File) -> Result<(), String> {
    let fd = file.as_raw_fd();
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err("tcgetattr failed".into());
    }
    unsafe { libc::cfmakeraw(&mut termios) };
    termios.c_cflag |= libc::CLOCAL | libc::CREAD;
    termios.c_cflag &= !libc::CRTSCTS;
    // Reads are driven by poll(), so the driver itself must never block.
    termios.c_cc[libc::VMIN] = 0;
    termios.c_cc[libc::VTIME] = 0;
    unsafe {
        libc::cfsetispeed(&mut termios, libc::B115200);
        libc::cfsetospeed(&mut termios, libc::B115200);
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err("tcsetattr failed".into());
    }
    unsafe { libc::tcflush(fd, libc::TCIOFLUSH) };
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_raw(_file: &File) -> Result<(), String> {
    Err("AT ports are only supported on Linux".into())
}

#[cfg(target_os = "linux")]
fn wait_readable(file: &File, timeout: Duration) -> Result<bool, AtError> {
    let mut pollfd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let n = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    if n < 0 {
        return Err(AtError::Io("poll AT port failed".into()));
    }
    Ok(n > 0 && pollfd.revents & libc::POLLIN != 0)
}

#[cfg(not(target_os = "linux"))]
fn wait_readable(_file: &File, _timeout: Duration) -> Result<bool, AtError> {
    Err(AtError::Io("AT ports are only supported on Linux".into()))
}

/// Terminal result code present in `buffer`, if the response is complete.
fn terminal_code(buffer: &str) -> Option<String> {
    for line in buffer.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "OK" || line == "ERROR" || line == "NO CARRIER" || line == "ABORTED" {
            return Some(line.to_string());
        }
        if line.starts_with("+CME ERROR:") || line.starts_with("+CMS ERROR:") {
            return Some(line.to_string());
        }
        // A prompt means the module wants payload rather than a result code.
        if line == ">" {
            return Some(line.to_string());
        }
    }
    None
}

/// Response body with the echoed command and terminator removed.
fn response_lines(buffer: &str, command: &str, terminator: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut skipped_echo = false;
    for line in buffer.lines() {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        if !skipped_echo && line.eq_ignore_ascii_case(command) {
            skipped_echo = true;
            continue;
        }
        if line == terminator {
            continue;
        }
        lines.push(line.to_string());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_terminates_a_response() {
        assert_eq!(terminal_code("AT\r\r\nOK\r\n").as_deref(), Some("OK"));
    }

    #[test]
    fn partial_response_has_no_terminator() {
        assert_eq!(terminal_code("AT+CSQ\r\r\n+CSQ: 24,99\r\n"), None);
    }

    #[test]
    fn cme_error_terminates_a_response() {
        assert_eq!(
            terminal_code("AT+CPIN?\r\r\n+CME ERROR: 10\r\n").as_deref(),
            Some("+CME ERROR: 10")
        );
    }

    #[test]
    fn echo_and_terminator_are_stripped() {
        let buffer = "AT+CSQ\r\r\n+CSQ: 24,99\r\n\r\nOK\r\n";
        assert_eq!(
            response_lines(buffer, "AT+CSQ", "OK"),
            vec!["+CSQ: 24,99".to_string()]
        );
    }

    #[test]
    fn multi_line_response_keeps_order() {
        let buffer = "AT+COPS=?\r\r\n+COPS: (2,\"A\"),(1,\"B\")\r\n+COPS: (0-4)\r\n\r\nOK\r\n";
        assert_eq!(
            response_lines(buffer, "AT+COPS=?", "OK"),
            vec![
                "+COPS: (2,\"A\"),(1,\"B\")".to_string(),
                "+COPS: (0-4)".to_string(),
            ]
        );
    }

    #[test]
    fn transcript_reassembles_the_exchange() {
        let exchange = AtExchange {
            command: "AT+CSQ".into(),
            lines: vec!["+CSQ: 24,99".into()],
            terminator: "OK".into(),
            elapsed: Duration::from_millis(12),
        };
        assert_eq!(exchange.transcript(), "+CSQ: 24,99\nOK");
        assert!(exchange.succeeded());
    }

    #[test]
    fn rejection_is_not_success() {
        let exchange = AtExchange {
            command: "AT+CPIN?".into(),
            lines: Vec::new(),
            terminator: "+CME ERROR: 10".into(),
            elapsed: Duration::from_millis(4),
        };
        assert!(!exchange.succeeded());
        assert_eq!(exchange.transcript(), "+CME ERROR: 10");
    }
}
