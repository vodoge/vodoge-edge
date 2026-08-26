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

    /// The call-progress code this exchange ended on, if it ended on one.
    ///
    /// `BUSY`, `NO ANSWER`, `NO DIALTONE` and `NO CARRIER` are four different
    /// answers — the far end is engaged, it rang out, the module never got a
    /// line, the call is gone — and each asks for something different of the
    /// caller. Folding them into one generic failure throws away the only
    /// part that says what to do next, so every code is handed back as
    /// itself.
    pub fn call_progress(&self) -> Option<&'static str> {
        CALL_PROGRESS_CODES
            .iter()
            .copied()
            .find(|code| *code == self.terminator)
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
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        // O_NOCTTY, and it is not optional.
        //
        // A systemd service runs as a session leader with no controlling
        // terminal, so the first tty it opens without this flag becomes one.
        // That tty is a USB serial port: when the stick re-enumerates, the
        // kernel hangs up the terminal and SIGHUPs the session, and the daemon
        // dies. Nothing explains it afterwards either — systemd counts SIGHUP
        // as a clean exit, so the journal says "Deactivated successfully" and
        // no more. Seen on the bench: ttyUSB8-11 disconnected at 03:57:33 and
        // the agent was gone in the same second, with no other trace.
        //
        // Latent for as long as the agent only ran AT commands rarely. Driving
        // them from the console makes opening this port ordinary.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOCTTY);
        }
        let file = options.open(&path).map_err(|error| AtError::Open {
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

    /// Run one command with a timeout that overrides the port default.
    ///
    /// A network scan keeps the module busy far longer than any query: the
    /// radio has to sweep every band. Applying the ordinary budget to it
    /// reports a timeout for a command that was working correctly.
    pub fn command_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<AtExchange, AtError> {
        let previous = self.timeout;
        self.timeout = timeout;
        let result = self.command(command);
        self.timeout = previous;
        result
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

    /// Wait for an unsolicited line beginning with `prefix`.
    ///
    /// Some operations answer twice. `AT+CUSD=1,...` returns `OK` as soon as
    /// the request is accepted and the network's reply arrives seconds later as
    /// a `+CUSD:` report, so treating the `OK` as the answer returns an empty
    /// result for a command that worked. This must not drain first: the report
    /// can arrive between the `OK` and this call.
    pub fn wait_for_urc(
        &mut self,
        prefix: &str,
        timeout: Duration,
    ) -> Result<Option<String>, AtError> {
        self.wait_for_any_urc(&[prefix], timeout)
    }

    /// Wait for the first unsolicited line matching any of `prefixes`.
    ///
    /// An operation that reports asynchronously can also fail asynchronously.
    /// A USSD request the network rejects produces `+CME ERROR: 100` about a
    /// second after the command's own `OK`; waiting only for the success
    /// prefix spends the whole timeout and then reports no answer, when the
    /// module had already said exactly what went wrong.
    pub fn wait_for_any_urc(
        &mut self,
        prefixes: &[&str],
        timeout: Duration,
    ) -> Result<Option<String>, AtError> {
        let started = Instant::now();
        let mut buffer = String::new();
        loop {
            if let Some(line) = buffer
                .lines()
                .map(|line| line.trim())
                .find(|line| prefixes.iter().any(|prefix| line.starts_with(prefix)))
            {
                return Ok(Some(line.to_string()));
            }
            if started.elapsed() >= timeout {
                return Ok(None);
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if !wait_readable(&self.file, remaining)? {
                continue;
            }
            let mut chunk = [0u8; READ_CHUNK];
            let read = self
                .file
                .read(&mut chunk)
                .map_err(|error| AtError::Io(format!("read report: {error}")))?;
            if read == 0 {
                continue;
            }
            buffer.push_str(&String::from_utf8_lossy(&chunk[..read]));
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

/// Every serial port that is a module's AT control port, sorted.
///
/// One per module, found the same way as `at_port_for_qmi` but without
/// starting from a QMI port — because sometimes there is no QMI port to start
/// from. A module in a usbnet mode other than rmnet exposes no `cdc-wdm` at
/// all, and the agent indexes modules by exactly that, so switching one out
/// of rmnet would otherwise put it beyond reach of the thing that switched
/// it. The same gap swallows every command issued in the seconds after a
/// restart, before the first poll has built the index.
///
/// Only the control interface is listed. The DM, NMEA and PPP interfaces
/// belong to the same module and would answer to nothing useful, and the PPP
/// one may be carrying a session that an `AT` written into it would corrupt.
pub fn at_control_ports() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/sys/class/tty") else {
        return Vec::new();
    };
    let mut ports = Vec::new();
    for entry in entries.flatten() {
        let tty = entry.file_name();
        let Some(tty) = tty.to_str() else { continue };
        if !tty.starts_with("ttyUSB") {
            continue;
        }
        let link = PathBuf::from(format!("/sys/class/tty/{tty}/device"));
        if interface_of(&link).as_deref() == Some(AT_CONTROL_INTERFACE) {
            ports.push(PathBuf::from(format!("/dev/{tty}")));
        }
    }
    ports.sort();
    ports
}

/// USB device identifier, e.g. `2-4.1`, backing an AT control port.
///
/// The counterpart to `usb_device_of_qmi`, and the join key between the two
/// ways the agent finds a module. A stick that answers over QMI is also
/// listed by `at_control_ports`, so without a shared identity the poll would
/// report it twice -- once as a managed module and once as an unmanaged one
/// with the same IMEI.
pub fn usb_device_of_at(at_path: &Path) -> Option<String> {
    let tty = at_path.file_name()?.to_str()?;
    usb_device_of(&PathBuf::from(format!("/sys/class/tty/{tty}/device")))
}

/// The first response line that is nothing but digits.
///
/// `AT+CGSN` and `AT+CIMI` answer with a bare value and no `+CMD:` prefix, so
/// there is no key to search for. Echo suppression is not guaranteed on a
/// port the agent did not configure, and a stray `AT+CGSN` echo would
/// otherwise be returned as the IMEI of a module that never reported one.
pub fn first_bare_digits(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .map(|line| line.trim())
        .find(|line| !line.is_empty() && line.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_string)
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

/// Result codes that end a call-originating command instead of `OK`.
///
/// These are terminators, not status lines: a module that answers `BUSY` says
/// nothing more, so a reader that does not know the word waits out the entire
/// port timeout and then reports the command as hung. That shape is much
/// harder to diagnose than a rejection — nothing in the log says the module
/// answered at all — which is why these belong here even though no code path
/// in this agent dials yet.
///
/// `RING`, `RDY`, `SMS Ready`, `Call Ready` and `NORMAL POWER DOWN` are
/// deliberately absent. Those are unsolicited, and a call arriving while an
/// unrelated command is in flight must not cut that command's answer short.
///
/// The same caveat applies in reverse to the four below, and it is a trade
/// rather than a free win: a voice dial on these modules is `ATD<number>;`,
/// which answers `OK` immediately and reports the outcome later as an
/// unsolicited line, so these words can also land in the middle of some other
/// exchange and end it early. A truncated answer is at least visible in the
/// transcript; a timeout tells the operator nothing.
const CALL_PROGRESS_CODES: [&str; 4] = ["NO CARRIER", "BUSY", "NO ANSWER", "NO DIALTONE"];

/// Terminal result code present in `buffer`, if the response is complete.
///
/// `None` is not a neutral outcome. It sends `command()` back to waiting on
/// the port, so an unrecognised terminator costs the full timeout and is then
/// reported as `AtError::Timeout`. Keeping the two paths straight matters:
/// what is matched here ends the exchange at once and is carried in
/// `AtExchange::terminator`; everything else is treated as more response
/// still on its way.
fn terminal_code(buffer: &str) -> Option<String> {
    for line in buffer.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "OK" || line == "ERROR" || line == "ABORTED" {
            return Some(line.to_string());
        }
        if CALL_PROGRESS_CODES.contains(&line) {
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
    fn busy_terminates_a_dial() {
        assert_eq!(
            terminal_code("ATD10086;\r\r\nBUSY\r\n").as_deref(),
            Some("BUSY")
        );
    }

    #[test]
    fn no_answer_terminates_a_dial() {
        assert_eq!(
            terminal_code("ATD10086;\r\r\nNO ANSWER\r\n").as_deref(),
            Some("NO ANSWER")
        );
    }

    #[test]
    fn no_dialtone_terminates_a_dial() {
        assert_eq!(
            terminal_code("ATD10086;\r\r\nNO DIALTONE\r\n").as_deref(),
            Some("NO DIALTONE")
        );
    }

    #[test]
    fn no_carrier_and_aborted_still_terminate() {
        assert_eq!(
            terminal_code("ATD10086;\r\r\nNO CARRIER\r\n").as_deref(),
            Some("NO CARRIER")
        );
        assert_eq!(
            terminal_code("AT+COPS=?\r\r\nABORTED\r\n").as_deref(),
            Some("ABORTED")
        );
    }

    #[test]
    fn an_unsolicited_ring_leaves_the_read_waiting() {
        // A call arriving while another command is in flight must not end that
        // command: its own result code has not been sent yet, so this input
        // takes the same path as any partial response.
        assert_eq!(terminal_code("AT+CSQ\r\r\nRING\r\n"), None);
    }

    #[test]
    fn a_call_progress_word_inside_a_line_leaves_the_read_waiting() {
        // Matching is on the whole line. Text that merely contains the words —
        // here a network's USSD reply — is response body, not a terminator.
        assert_eq!(
            terminal_code("AT+CUSD=1\r\r\n+CUSD: 0,\"NO ANSWER FROM 10086\",15\r\n"),
            None
        );
    }

    #[test]
    fn each_call_progress_code_reaches_the_caller_as_itself() {
        for code in ["NO CARRIER", "BUSY", "NO ANSWER", "NO DIALTONE"] {
            let exchange = AtExchange {
                command: "ATD10086;".to_string(),
                lines: Vec::new(),
                terminator: code.to_string(),
                elapsed: Duration::from_millis(1),
            };
            assert!(!exchange.succeeded(), "{code} is not a success");
            assert_eq!(exchange.call_progress(), Some(code));
        }
    }

    #[test]
    fn a_rejection_is_not_call_progress() {
        let exchange = AtExchange {
            command: "AT+CPIN?".to_string(),
            lines: Vec::new(),
            terminator: "+CME ERROR: 10".to_string(),
            elapsed: Duration::from_millis(1),
        };
        assert_eq!(exchange.call_progress(), None);
        let ok = AtExchange {
            command: "AT".to_string(),
            lines: Vec::new(),
            terminator: "OK".to_string(),
            elapsed: Duration::from_millis(1),
        };
        assert_eq!(ok.call_progress(), None);
    }

    #[test]
    fn a_failed_dial_keeps_its_code_out_of_the_body() {
        let buffer = "ATD10086;\r\r\nNO ANSWER\r\n";
        assert_eq!(
            response_lines(buffer, "ATD10086;", "NO ANSWER"),
            Vec::<String>::new()
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

    #[test]
    fn bare_digits_skip_a_command_echo() {
        let lines = vec!["AT+CGSN".to_string(), "867018069509705".to_string()];
        assert_eq!(
            first_bare_digits(&lines),
            Some("867018069509705".to_string())
        );
    }

    #[test]
    fn bare_digits_ignore_blank_lines_and_prefixed_answers() {
        let lines = vec![String::new(), "+CME ERROR: 10".to_string()];
        assert_eq!(first_bare_digits(&lines), None);
    }
}

// ---------------------------------------------------------------------------
// Modem arbitration and the local AT lease
// ---------------------------------------------------------------------------
//
// The AT port is a single serial line and the module answers one command at a
// time. That was already true, and one mutex around every AT and QMI exchange
// was already enough — while the only thing asking was this daemon.
//
// It stops being enough once the tunnel stack is a second process. Its AKA
// challenges are not background work: each one sits inside a timed, blocking
// exchange with somebody else's server (IKE_AUTH once, the IMS REGISTER 401
// challenge once, E911 entitlement up to five rounds, EAP re-authentication
// once). A plain mutex would let a band scan or an ES10 sequence hold the
// module past the peer's patience, and the tunnel would then fail for a
// reason nothing in the logs connects to a queue. So the arbiter is
// priority-aware: an AKA request goes ahead of anything merely waiting.
//
// The lease itself is a Unix socket and nothing else, on purpose. It runs
// arbitrary AT commands, which is complete control of the module — the SIM,
// the radio, the firmware. A loopback TCP port would still be reachable by
// every process and container on the host, and by anything that can persuade
// this host to forward to it; a socket file is reachable by whoever the
// filesystem says, and it is created 0600.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::aka::{decode_hex, hex_upper, AkaError, AkaOutcome, AUTN_BYTES, RAND_BYTES};

/// Who is asking for the module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModemPriority {
    /// Console commands, the poll loop, eUICC profile management.
    Normal,
    /// A USIM authentication on a timed protocol path. Overtakes anything
    /// that is only queued; it cannot interrupt work already running, because
    /// half an ES10 sequence is worse than a late challenge.
    Aka,
}

impl ModemPriority {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Aka => "aka",
        }
    }
}

#[derive(Default)]
struct ArbiterState {
    held: bool,
    waiting_normal: usize,
    waiting_aka: usize,
}

/// Serialises every conversation with one module, with AKA jumping the queue.
///
/// Deliberately not a `Mutex<()>`: the point is that the waiters are not
/// equal, and an arbitrary wake order is exactly what this replaces.
#[derive(Default)]
pub struct ModemArbiter {
    state: Mutex<ArbiterState>,
    changed: Condvar,
}

/// How many callers are queued, for tests and for a status page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArbiterWaiting {
    pub normal: usize,
    pub aka: usize,
    pub held: bool,
}

impl ModemArbiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Blocks until the module is ours.
    ///
    /// An AKA caller waits only for the current holder. A normal caller also
    /// waits for every queued AKA caller, which is the whole mechanism. AKA
    /// work is bounded — one APDU pair per challenge, a handful of challenges
    /// per session — so this cannot starve the console in practice, and what
    /// it replaces is a timed protocol exchange losing to the follow-up work
    /// of a three-minute band scan.
    pub fn acquire(&self, priority: ModemPriority) -> ModemLease<'_> {
        let mut state = self.state.lock().expect("modem arbiter");
        match priority {
            ModemPriority::Aka => {
                state.waiting_aka += 1;
                while state.held {
                    state = self.changed.wait(state).expect("modem arbiter");
                }
                state.waiting_aka -= 1;
            }
            ModemPriority::Normal => {
                state.waiting_normal += 1;
                while state.held || state.waiting_aka > 0 {
                    state = self.changed.wait(state).expect("modem arbiter");
                }
                state.waiting_normal -= 1;
            }
        }
        state.held = true;
        drop(state);
        ModemLease { arbiter: self }
    }

    pub fn waiting(&self) -> ArbiterWaiting {
        let state = self.state.lock().expect("modem arbiter");
        ArbiterWaiting {
            normal: state.waiting_normal,
            aka: state.waiting_aka,
            held: state.held,
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("modem arbiter");
        state.held = false;
        drop(state);
        self.changed.notify_all();
    }
}

/// Holds the module until dropped, including on a panic path.
pub struct ModemLease<'a> {
    arbiter: &'a ModemArbiter,
}

impl Drop for ModemLease<'_> {
    fn drop(&mut self) {
        self.arbiter.release();
    }
}

/// A refusal the lease reports to its client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseFailure {
    pub code: String,
    pub message: String,
}

impl LeaseFailure {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl From<AkaError> for LeaseFailure {
    fn from(error: AkaError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

/// What the daemon lets a local process do with a module.
///
/// Two operations rather than one. `execute` is the general lease the Go
/// tunnel process needs; `authenticate` exists as well because an AKA
/// challenge is the one thing that must be able to overtake the queue, and
/// because the status-word classification belongs on this side of the
/// boundary — the caller learns "the card rejected this", not `9862`.
pub trait AtLease: Send + Sync {
    fn execute(
        &self,
        imei: Option<&str>,
        command: &str,
        timeout: Duration,
        priority: ModemPriority,
    ) -> Result<AtExchange, LeaseFailure>;

    fn authenticate(
        &self,
        imei: Option<&str>,
        rand16: &[u8],
        autn16: &[u8],
    ) -> Result<AkaOutcome, LeaseFailure>;
}

/// Longest command budget a client may ask for.
///
/// A band scan legitimately runs past a minute, so the ceiling is generous;
/// it exists so that one request cannot pin the module forever.
pub const MAX_LEASE_TIMEOUT: Duration = Duration::from_secs(300);
/// Used when a request does not say.
pub const DEFAULT_LEASE_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent clients. The arbiter serialises them anyway; this only stops a
/// misbehaving peer from spawning threads without bound.
pub const MAX_LEASE_CLIENTS: usize = 8;

/// Handle one request line and produce the response line.
///
/// Split out from the socket so the protocol is testable without one, which
/// also means a change to the wire format cannot be verified only against
/// itself.
pub fn handle_lease_request(lease: &dyn AtLease, line: &str) -> String {
    let request: serde_json::Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => return failure_json("bad_request", &format!("not JSON: {error}")),
    };
    let imei = request
        .get("imei")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match request.get("op").and_then(|value| value.as_str()) {
        Some("execute_at") => {
            let Some(command) = request.get("command").and_then(|value| value.as_str()) else {
                return failure_json("bad_request", "execute_at needs a command");
            };
            let timeout = match request.get("timeout_ms") {
                None => DEFAULT_LEASE_TIMEOUT,
                Some(value) => match value.as_u64() {
                    Some(millis) if millis > 0 => {
                        Duration::from_millis(millis).min(MAX_LEASE_TIMEOUT)
                    }
                    _ => {
                        return failure_json("bad_request", "timeout_ms must be a positive integer")
                    }
                },
            };
            let priority = match request.get("priority").and_then(|value| value.as_str()) {
                None | Some("normal") => ModemPriority::Normal,
                Some("aka") => ModemPriority::Aka,
                Some(other) => {
                    return failure_json("bad_request", &format!("unknown priority {other:?}"))
                }
            };
            match lease.execute(imei, command, timeout, priority) {
                Ok(exchange) => serde_json::json!({
                    "ok": true,
                    "op": "execute_at",
                    "succeeded": exchange.succeeded(),
                    "response": exchange.transcript(),
                    "lines": exchange.lines,
                    "terminator": exchange.terminator,
                    "elapsed_ms": exchange.elapsed.as_millis() as u64,
                })
                .to_string(),
                Err(failure) => failure_json(&failure.code, &failure.message),
            }
        }
        Some("authenticate") => {
            let rand = match hex_field(&request, "rand", RAND_BYTES) {
                Ok(bytes) => bytes,
                Err(message) => return failure_json("bad_request", &message),
            };
            let autn = match hex_field(&request, "autn", AUTN_BYTES) {
                Ok(bytes) => bytes,
                Err(message) => return failure_json("bad_request", &message),
            };
            match lease.authenticate(imei, &rand, &autn) {
                Ok(outcome) => outcome_json(&outcome),
                Err(failure) => failure_json(&failure.code, &failure.message),
            }
        }
        Some(other) => failure_json("bad_request", &format!("unknown op {other:?}")),
        None => failure_json("bad_request", "missing op"),
    }
}

fn hex_field(request: &serde_json::Value, name: &str, expected: usize) -> Result<Vec<u8>, String> {
    let text = request
        .get(name)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("authenticate needs {name} as a hex string"))?;
    let bytes = decode_hex(text).ok_or_else(|| format!("{name} is not hex"))?;
    if bytes.len() != expected {
        return Err(format!(
            "{name} must be {expected} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn outcome_json(outcome: &AkaOutcome) -> String {
    let mut body = serde_json::json!({
        "ok": true,
        "op": "authenticate",
        "outcome": outcome.label(),
    });
    let map = body.as_object_mut().expect("object");
    match outcome {
        AkaOutcome::Success { res, ck, ik, kc } => {
            map.insert("res".into(), hex_upper(res).into());
            map.insert("ck".into(), hex_upper(ck).into());
            map.insert("ik".into(), hex_upper(ik).into());
            if let Some(kc) = kc {
                map.insert("kc".into(), hex_upper(kc).into());
            }
        }
        AkaOutcome::SyncFailure { auts } => {
            map.insert("auts".into(), hex_upper(auts).into());
        }
        AkaOutcome::AuthenticationFailure { sw1, sw2, detail } => {
            map.insert("sw".into(), format!("{sw1:02X}{sw2:02X}").into());
            map.insert("detail".into(), (*detail).into());
        }
    }
    body.to_string()
}

fn failure_json(code: &str, message: &str) -> String {
    serde_json::json!({ "ok": false, "error": code, "message": message }).to_string()
}

/// Default socket path. Under `/run` because the socket is per-boot state and
/// a stale one left in a data directory is a confusing thing to find.
pub const DEFAULT_LEASE_SOCKET: &str = "/run/vodoge-edge/at-lease.sock";
/// Environment variable that overrides it.
pub const LEASE_SOCKET_ENV: &str = "VODOGE_AT_LEASE_SOCKET";

/// Where the lease socket should live for this process.
pub fn lease_socket_path() -> PathBuf {
    std::env::var_os(LEASE_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LEASE_SOCKET))
}

#[cfg(unix)]
mod unix_lease {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};

    /// Bind the lease socket, replacing a stale one from a previous run.
    ///
    /// Permissions are set before anything can connect, and a leftover path is
    /// only removed when it is actually a socket — deleting whatever happens
    /// to be at a configured path would be a fine way to lose a file somebody
    /// meant to keep.
    pub fn bind_lease_socket(path: &Path) -> Result<UnixListener, AtError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| AtError::Open {
                path: parent.to_path_buf(),
                reason: error.to_string(),
            })?;
        }
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                let _ = std::fs::remove_file(path);
            }
            Ok(_) => {
                return Err(AtError::Open {
                    path: path.to_path_buf(),
                    reason: "exists and is not a socket".into(),
                })
            }
            Err(_) => {}
        }
        let listener = UnixListener::bind(path).map_err(|error| AtError::Open {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
            AtError::Open {
                path: path.to_path_buf(),
                reason: format!("chmod 0600: {error}"),
            }
        })?;
        Ok(listener)
    }

    /// Serve the lease until the listener fails.
    ///
    /// One thread per connection because the Go side keeps a connection open
    /// across a whole tunnel session, and an AKA challenge must not wait
    /// behind another client's band scan at the socket layer — the arbiter
    /// decides that ordering, not the accept loop.
    pub fn serve_lease<L: AtLease + 'static>(listener: UnixListener, lease: Arc<L>) {
        let clients = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            if clients.load(Ordering::SeqCst) >= MAX_LEASE_CLIENTS {
                let mut stream = stream;
                let _ = writeln!(
                    stream,
                    "{}",
                    failure_json("too_many_clients", "AT lease is at its connection limit")
                );
                continue;
            }
            clients.fetch_add(1, Ordering::SeqCst);
            let lease = Arc::clone(&lease);
            let clients = Arc::clone(&clients);
            std::thread::spawn(move || {
                serve_connection(stream, lease.as_ref());
                clients.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    /// One request per line, one response per line, until the peer hangs up.
    pub fn serve_connection(stream: UnixStream, lease: &dyn AtLease) {
        let Ok(mut writer) = stream.try_clone() else {
            return;
        };
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            let Ok(line) = line else { return };
            if line.trim().is_empty() {
                continue;
            }
            let response = handle_lease_request(lease, &line);
            if writeln!(writer, "{response}").is_err() || writer.flush().is_err() {
                return;
            }
        }
    }
}

#[cfg(unix)]
pub use unix_lease::{bind_lease_socket, serve_connection, serve_lease};

#[cfg(test)]
mod lease_tests {
    use super::*;
    use std::sync::mpsc::channel;

    struct RecordingLease {
        answers: Mutex<Vec<String>>,
    }

    impl AtLease for RecordingLease {
        fn execute(
            &self,
            _imei: Option<&str>,
            command: &str,
            timeout: Duration,
            priority: ModemPriority,
        ) -> Result<AtExchange, LeaseFailure> {
            self.answers.lock().expect("answers").push(format!(
                "{command}|{}|{}",
                timeout.as_millis(),
                priority.label()
            ));
            Ok(AtExchange {
                command: command.to_string(),
                lines: vec!["EC20CEHCLGR06A08M1G".into()],
                terminator: "OK".into(),
                elapsed: Duration::from_millis(7),
            })
        }

        fn authenticate(
            &self,
            _imei: Option<&str>,
            _rand16: &[u8],
            _autn16: &[u8],
        ) -> Result<AkaOutcome, LeaseFailure> {
            Ok(AkaOutcome::AuthenticationFailure {
                sw1: 0x98,
                sw2: 0x62,
                detail: "card rejected the challenge: incorrect MAC (SW 9862)",
            })
        }
    }

    fn lease() -> RecordingLease {
        RecordingLease {
            answers: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn execute_at_returns_the_transcript() {
        let lease = lease();
        let response = handle_lease_request(
            &lease,
            "{\"op\":\"execute_at\",\"command\":\"ATI\",\"timeout_ms\":2000}",
        );
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(
            value["response"],
            serde_json::json!("EC20CEHCLGR06A08M1G\nOK")
        );
        assert_eq!(
            lease.answers.lock().expect("answers").as_slice(),
            ["ATI|2000|normal".to_string()]
        );
    }

    #[test]
    fn a_lease_client_may_ask_for_aka_priority() {
        let lease = lease();
        handle_lease_request(
            &lease,
            "{\"op\":\"execute_at\",\"command\":\"AT+CSIM=10,\\\"00F2000000\\\"\",\"priority\":\"aka\"}",
        );
        let recorded = lease.answers.lock().expect("answers")[0].clone();
        assert!(recorded.ends_with("|10000|aka"), "{recorded}");
        assert!(recorded.starts_with("AT+CSIM=10,\"00F2000000\""), "{recorded}");
    }

    #[test]
    fn authenticate_reports_a_named_rejection() {
        let response = handle_lease_request(
            &lease(),
            &format!(
                "{{\"op\":\"authenticate\",\"rand\":\"{}\",\"autn\":\"{}\"}}",
                "11".repeat(16),
                "22".repeat(16)
            ),
        );
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        assert_eq!(
            value["outcome"],
            serde_json::json!("authentication_failure")
        );
        assert_eq!(value["sw"], serde_json::json!("9862"));
    }

    #[test]
    fn a_short_rand_is_refused_before_the_module_is_touched() {
        let lease = lease();
        let response = handle_lease_request(
            &lease,
            "{\"op\":\"authenticate\",\"rand\":\"1122\",\"autn\":\"33\"}",
        );
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        assert_eq!(value["ok"], serde_json::json!(false));
        assert_eq!(value["error"], serde_json::json!("bad_request"));
        assert!(lease.answers.lock().expect("answers").is_empty());
    }

    #[test]
    fn aka_overtakes_a_queued_normal_caller() {
        let arbiter = Arc::new(ModemArbiter::new());
        let (order, arrivals) = channel::<&'static str>();

        let held = arbiter.acquire(ModemPriority::Normal);

        let normal = {
            let arbiter = Arc::clone(&arbiter);
            let order = order.clone();
            std::thread::spawn(move || {
                let _lease = arbiter.acquire(ModemPriority::Normal);
                order.send("normal").expect("send");
            })
        };
        wait_until(&arbiter, |waiting| waiting.normal == 1);

        let aka = {
            let arbiter = Arc::clone(&arbiter);
            std::thread::spawn(move || {
                let _lease = arbiter.acquire(ModemPriority::Aka);
                order.send("aka").expect("send");
            })
        };
        wait_until(&arbiter, |waiting| waiting.aka == 1);

        drop(held);
        aka.join().expect("aka thread");
        normal.join().expect("normal thread");

        assert_eq!(arrivals.recv().expect("first"), "aka");
        assert_eq!(arrivals.recv().expect("second"), "normal");
    }

    #[test]
    fn the_arbiter_serialises_holders() {
        let arbiter = Arc::new(ModemArbiter::new());
        let overlaps = Arc::new(AtomicUsize::new(0));
        let inside = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for index in 0..8 {
            let arbiter = Arc::clone(&arbiter);
            let overlaps = Arc::clone(&overlaps);
            let inside = Arc::clone(&inside);
            let priority = if index % 2 == 0 {
                ModemPriority::Normal
            } else {
                ModemPriority::Aka
            };
            threads.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let _lease = arbiter.acquire(priority);
                    if inside.fetch_add(1, Ordering::SeqCst) != 0 {
                        overlaps.fetch_add(1, Ordering::SeqCst);
                    }
                    inside.fetch_sub(1, Ordering::SeqCst);
                }
            }));
        }
        for thread in threads {
            thread.join().expect("worker");
        }
        assert_eq!(overlaps.load(Ordering::SeqCst), 0);
        assert_eq!(
            arbiter.waiting(),
            ArbiterWaiting {
                normal: 0,
                aka: 0,
                held: false
            }
        );
    }

    fn wait_until(arbiter: &ModemArbiter, ready: impl Fn(ArbiterWaiting) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if ready(arbiter.waiting()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!(
            "arbiter never reached the expected state: {:?}",
            arbiter.waiting()
        );
    }
}
