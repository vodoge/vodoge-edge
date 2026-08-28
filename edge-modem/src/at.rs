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
//! `1.2` and this module never picks `1.3` on its own. Other modules use CDC
//! ACM, Qualcomm high-speed serial, a different configuration number, or a
//! vendor-labelled AT port; discovery therefore treats `1.2` as a preference,
//! not as a universal truth.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Legacy Quectel USB interface preferred for an AT control port.
///
/// This remains a preference for the EC20-style layout. Newer USB
/// compositions are selected from their sysfs interface metadata instead of
/// being rejected because they are not exactly `1.2`.
pub const AT_CONTROL_INTERFACE: &str = "1.2";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 512;

/// Serial transport exposed by a possible modem control channel.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AtPortKind {
    /// A vendor USB serial port such as Quectel `option` or Qualcomm
    /// `qcserial`.
    Usb,
    /// USB CDC ACM.
    Acm,
    /// Qualcomm high-speed serial. These can be platform-attached instead of
    /// hanging directly below a USB interface.
    HighSpeed,
}

/// Whether the agent may send its identifying AT probe to a serial candidate.
///
/// `Manual` candidates are deliberately returned to callers so an operator can
/// see a newly attached module and choose a profile for it. They are not sent
/// `AT+CGSN` by the background poller: a generic USB serial adapter can expose
/// the same kernel node names and its traffic must not be treated as modem AT
/// traffic merely because it is a tty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtProbePolicy {
    Automatic,
    Manual,
}

/// A serial port that could belong to a modem.
///
/// `usb_device` is the stable sysfs topology key when the port is USB-backed.
/// It is absent for platform-attached high-speed serial, where no USB reset or
/// QMI pairing can be inferred from the tty alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtPortCandidate {
    pub path: PathBuf,
    pub kind: AtPortKind,
    pub usb_device: Option<String>,
    /// USB configuration and interface number, for example `1.2`.
    pub interface: Option<String>,
    /// USB interface string, when the firmware provides one.
    pub interface_label: Option<String>,
    /// Kernel driver bound to the USB interface or high-speed tty.
    pub driver: Option<String>,
    /// USB vendor ID from the parent device, normalized as lowercase hex.
    pub vendor_id: Option<String>,
    /// USB product ID from the parent device, normalized as lowercase hex.
    pub product_id: Option<String>,
    pub policy: AtProbePolicy,
}

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
/// It accepts USB serial and CDC ACM candidates; a QMI path cannot be paired to
/// a platform-only `ttyHS` node because there is no shared USB topology key.
pub fn at_port_for_qmi(qmi_path: &Path) -> Option<PathBuf> {
    let name = qmi_path.file_name()?.to_str()?;
    let usb = usb_device_of(&PathBuf::from(format!("/sys/class/usbmisc/{name}/device")))?;
    select_control_ports(
        at_port_candidates()
            .into_iter()
            .filter(|candidate| candidate.usb_device.as_deref() == Some(usb.as_str()))
            .collect(),
    )
    .into_iter()
    .next()
}

/// Every modem-shaped serial candidate visible in sysfs, sorted by device path.
///
/// This deliberately has a wider surface than [`at_control_ports`]. A modem
/// may use `ttyUSB`, `ttyACM`, or `ttyHS`, and a new USB composition does not
/// deserve to disappear merely because it is not the EC20 `1.2` layout. The
/// [`AtProbePolicy`] tells a caller whether discovery has enough evidence to
/// issue an automatic identifying AT command. `Manual` candidates are for a
/// panel or operator to inspect and explicitly claim.
pub fn at_port_candidates() -> Vec<AtPortCandidate> {
    at_port_candidates_in(Path::new("/sys/class/tty"), Path::new("/dev"))
}

/// Every serial port safe for the background poller to identify, sorted.
///
/// One control candidate is chosen for each physical USB device. A module in a
/// usbnet mode without `cdc-wdm` therefore remains discoverable, while its DM,
/// NMEA and PPP siblings are not all probed. A generic USB serial adapter is
/// preserved as a `Manual` candidate by [`at_port_candidates`] and never lands
/// here.
pub fn at_control_ports() -> Vec<PathBuf> {
    select_control_ports(at_port_candidates())
}

fn at_port_candidates_in(tty_root: &Path, dev_root: &Path) -> Vec<AtPortCandidate> {
    let Ok(entries) = std::fs::read_dir(tty_root) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(kind) = AtPortKind::from_tty_name(name) else {
            continue;
        };
        let link = entry.path().join("device");
        let Ok(resolved) = std::fs::canonicalize(&link) else {
            continue;
        };
        let interface_path = usb_interface_path(&resolved);
        let interface = interface_path
            .as_deref()
            .and_then(interface_name_of_path)
            .map(str::to_string);
        let usb_device = interface_path
            .as_deref()
            .and_then(usb_device_name_of_path)
            .map(str::to_string);
        let usb_parent = interface_path.as_deref().and_then(Path::parent);
        let vendor_id = usb_parent
            .and_then(|path| read_trimmed(&path.join("idVendor")))
            .map(|value| value.to_ascii_lowercase());
        let product_id = usb_parent
            .and_then(|path| read_trimmed(&path.join("idProduct")))
            .map(|value| value.to_ascii_lowercase());
        let interface_label = interface_path
            .as_deref()
            .and_then(|path| read_trimmed(&path.join("interface")));
        let driver = interface_path
            .as_deref()
            .and_then(driver_name_at)
            .or_else(|| driver_name_at_or_above(&resolved));
        candidates.push(candidate_from_parts(
            dev_root.join(name),
            kind,
            usb_device,
            interface,
            interface_label,
            driver,
            vendor_id,
            product_id,
        ));
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    candidates
}

impl AtPortKind {
    fn from_tty_name(name: &str) -> Option<Self> {
        if numbered_tty(name, "ttyUSB") {
            Some(Self::Usb)
        } else if numbered_tty(name, "ttyACM") {
            Some(Self::Acm)
        } else if numbered_tty(name, "ttyHS") {
            Some(Self::HighSpeed)
        } else {
            None
        }
    }
}

fn numbered_tty(name: &str, prefix: &str) -> bool {
    let Some(number) = name.strip_prefix(prefix) else {
        return false;
    };
    !number.is_empty() && number.chars().all(|character| character.is_ascii_digit())
}

fn candidate_from_parts(
    path: PathBuf,
    kind: AtPortKind,
    usb_device: Option<String>,
    interface: Option<String>,
    interface_label: Option<String>,
    driver: Option<String>,
    vendor_id: Option<String>,
    product_id: Option<String>,
) -> AtPortCandidate {
    let policy = automatic_probe_policy(
        kind,
        interface.as_deref(),
        interface_label.as_deref(),
        driver.as_deref(),
    );
    AtPortCandidate {
        path,
        kind,
        usb_device,
        interface,
        interface_label,
        driver,
        vendor_id,
        product_id,
        policy,
    }
}

/// Select exactly one automatic control port per USB device. The rank is
/// deliberately based on sysfs meaning rather than tty number: tty numbers are
/// recycled every time a USB serial driver rebinds.
fn select_control_ports(candidates: Vec<AtPortCandidate>) -> Vec<PathBuf> {
    let mut usb_ports = BTreeMap::<String, AtPortCandidate>::new();
    let mut non_usb_ports = Vec::new();
    for candidate in candidates
        .into_iter()
        .filter(|candidate| candidate.policy == AtProbePolicy::Automatic)
    {
        match candidate.usb_device.clone() {
            Some(usb) => match usb_ports.get(&usb) {
                Some(previous) if control_rank(previous) <= control_rank(&candidate) => {}
                _ => {
                    usb_ports.insert(usb, candidate);
                }
            },
            None => non_usb_ports.push(candidate),
        }
    }
    let mut ports: Vec<_> = usb_ports
        .into_values()
        .chain(non_usb_ports)
        .map(|candidate| candidate.path)
        .collect();
    ports.sort();
    ports.dedup();
    ports
}

fn control_rank(candidate: &AtPortCandidate) -> u8 {
    if is_explicit_at_label(candidate.interface_label.as_deref()) {
        0
    } else if candidate.interface.as_deref() == Some(AT_CONTROL_INTERFACE) {
        1
    } else if is_control_interface(candidate.interface.as_deref()) {
        2
    } else {
        match candidate.kind {
            AtPortKind::HighSpeed => 3,
            AtPortKind::Acm => 4,
            AtPortKind::Usb => 5,
        }
    }
}

fn automatic_probe_policy(
    kind: AtPortKind,
    interface: Option<&str>,
    interface_label: Option<&str>,
    driver: Option<&str>,
) -> AtProbePolicy {
    let explicit_control = is_explicit_at_label(interface_label);
    let conventional_control = is_control_interface(interface);
    let modem_driver = is_modem_serial_driver(driver);
    let high_speed_driver = is_high_speed_modem_driver(driver);
    let policy = match kind {
        // A vendor serial driver plus interface ordinal 2 is the portable
        // version of the old `1.2` rule: it survives a configuration number
        // change but still avoids probing every sibling serial endpoint.
        AtPortKind::Usb => explicit_control || (conventional_control && modem_driver),
        // CDC ACM is also used by development boards and instruments. Its
        // firmware must call the interface an AT/modem port before polling it.
        AtPortKind::Acm => explicit_control,
        // `ttyHS` is a Qualcomm modem-specific kernel naming convention only
        // when the backing high-speed driver confirms it. A stray similarly
        // named tty remains visible for manual confirmation.
        AtPortKind::HighSpeed => explicit_control || high_speed_driver,
    };
    if policy {
        AtProbePolicy::Automatic
    } else {
        AtProbePolicy::Manual
    }
}

fn is_control_interface(interface: Option<&str>) -> bool {
    interface
        .and_then(|interface| interface.rsplit_once('.').map(|(_, number)| number))
        == Some("2")
}

fn is_explicit_at_label(label: Option<&str>) -> bool {
    let Some(label) = label else { return false };
    let label = label.trim().to_ascii_uppercase();
    label == "AT"
        || label.contains("AT PORT")
        || label.contains("AT COMMAND")
        || label.contains("MODEM")
}

fn is_modem_serial_driver(driver: Option<&str>) -> bool {
    matches!(
        driver.map(|driver| driver.to_ascii_lowercase()),
        Some(driver)
            if matches!(
                driver.as_str(),
                "option"
                    | "option1"
                    | "qcserial"
                    | "qcaux"
                    | "sierra"
                    | "hso"
                    | "usb_wwan"
            )
    )
}

fn is_high_speed_modem_driver(driver: Option<&str>) -> bool {
    matches!(
        driver.map(|driver| driver.to_ascii_lowercase()),
        Some(driver)
            if matches!(
                driver.as_str(),
                "msm_serial_hs" | "msm_serial_hsl" | "hsuart"
            )
    )
}

fn read_trimmed(path: &Path) -> Option<String> {
    let value = std::fs::read_to_string(path).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn driver_name_at(path: &Path) -> Option<String> {
    std::fs::read_link(path.join("driver"))
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_string)
}

fn driver_name_at_or_above(path: &Path) -> Option<String> {
    path.ancestors().find_map(driver_name_at)
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
    usb_interface_path(&resolved)
        .as_deref()
        .and_then(usb_device_name_of_path)
        .map(str::to_string)
}

/// Find the USB interface ancestor of a tty sysfs target.
///
/// A broad `split_once(':')` is not enough here: PCI and platform path
/// components contain colons too. A USB interface has the exact
/// `<usb-device>:<configuration>.<interface>` suffix, both numeric.
fn usb_interface_path(resolved: &Path) -> Option<PathBuf> {
    resolved
        .ancestors()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(usb_interface_parts)
                .is_some()
        })
        .map(Path::to_path_buf)
}

fn usb_device_name_of_path(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let (device, _) = usb_interface_parts(name)?;
    Some(device)
}

fn interface_name_of_path(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let (_, interface) = usb_interface_parts(name)?;
    Some(interface)
}

fn usb_interface_parts(name: &str) -> Option<(&str, &str)> {
    let (device, interface) = name.split_once(':')?;
    let (configuration, number) = interface.split_once('.')?;
    if device.is_empty()
        || configuration.is_empty()
        || number.is_empty()
        || !configuration.chars().all(|character| character.is_ascii_digit())
        || !number.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    Some((device, interface))
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

    fn serial_candidate(
        name: &str,
        kind: AtPortKind,
        usb_device: Option<&str>,
        interface: Option<&str>,
        label: Option<&str>,
        driver: Option<&str>,
    ) -> AtPortCandidate {
        candidate_from_parts(
            PathBuf::from(format!("/dev/{name}")),
            kind,
            usb_device.map(str::to_string),
            interface.map(str::to_string),
            label.map(str::to_string),
            driver.map(str::to_string),
            Some("2c7c".into()),
            Some("0125".into()),
        )
    }

    #[test]
    fn usb_interface_parser_ignores_pci_colons() {
        assert_eq!(usb_interface_parts("2-4.2:1.2"), Some(("2-4.2", "1.2")));
        assert_eq!(usb_interface_parts("4-1:2.2"), Some(("4-1", "2.2")));
        assert_eq!(usb_interface_parts("0000:00:16.0"), None);
        assert_eq!(usb_interface_parts("platform:serial"), None);
    }

    #[test]
    fn a_different_usb_configuration_keeps_the_control_port_automatic() {
        let candidate = serial_candidate(
            "ttyUSB8",
            AtPortKind::Usb,
            Some("2-4.2"),
            Some("2.2"),
            None,
            Some("option"),
        );
        assert_eq!(candidate.policy, AtProbePolicy::Automatic);
        assert_eq!(candidate.vendor_id.as_deref(), Some("2c7c"));
        assert_eq!(candidate.product_id.as_deref(), Some("0125"));
        assert_eq!(select_control_ports(vec![candidate]), vec![PathBuf::from("/dev/ttyUSB8")]);
    }

    #[test]
    fn cdc_acm_needs_an_explicit_modem_label_before_polling() {
        let at_port = serial_candidate(
            "ttyACM0",
            AtPortKind::Acm,
            Some("1-3"),
            Some("1.0"),
            Some("USB AT Port"),
            Some("cdc_acm"),
        );
        let generic_serial = serial_candidate(
            "ttyACM1",
            AtPortKind::Acm,
            Some("1-4"),
            Some("1.0"),
            Some("Debug Console"),
            Some("cdc_acm"),
        );
        assert_eq!(at_port.policy, AtProbePolicy::Automatic);
        assert_eq!(generic_serial.policy, AtProbePolicy::Manual);
        assert_eq!(
            select_control_ports(vec![at_port, generic_serial]),
            vec![PathBuf::from("/dev/ttyACM0")]
        );
    }

    #[test]
    fn high_speed_serial_requires_a_modem_driver_or_explicit_label() {
        let modem = serial_candidate(
            "ttyHS0",
            AtPortKind::HighSpeed,
            None,
            None,
            None,
            Some("msm_serial_hs"),
        );
        let unknown = serial_candidate(
            "ttyHS1",
            AtPortKind::HighSpeed,
            None,
            None,
            None,
            Some("serial"),
        );
        assert_eq!(modem.policy, AtProbePolicy::Automatic);
        assert_eq!(unknown.policy, AtProbePolicy::Manual);
        assert_eq!(
            select_control_ports(vec![modem, unknown]),
            vec![PathBuf::from("/dev/ttyHS0")]
        );
    }

    #[test]
    fn one_physical_modem_gets_one_preferred_control_port() {
        let declared_control = serial_candidate(
            "ttyUSB10",
            AtPortKind::Usb,
            Some("2-4.2"),
            Some("1.1"),
            Some("USB AT Port"),
            Some("option"),
        );
        let standard = serial_candidate(
            "ttyUSB8",
            AtPortKind::Usb,
            Some("2-4.2"),
            Some("1.2"),
            None,
            Some("option"),
        );
        let ppp = serial_candidate(
            "ttyUSB9",
            AtPortKind::Usb,
            Some("2-4.2"),
            Some("1.3"),
            None,
            Some("option"),
        );
        assert_eq!(standard.policy, AtProbePolicy::Automatic);
        assert_eq!(ppp.policy, AtProbePolicy::Manual);
        assert_eq!(
            select_control_ports(vec![ppp, declared_control, standard]),
            vec![PathBuf::from("/dev/ttyUSB10")]
        );
    }

    #[test]
    fn only_known_serial_naming_conventions_become_candidates() {
        assert_eq!(AtPortKind::from_tty_name("ttyUSB12"), Some(AtPortKind::Usb));
        assert_eq!(AtPortKind::from_tty_name("ttyACM0"), Some(AtPortKind::Acm));
        assert_eq!(AtPortKind::from_tty_name("ttyHS1"), Some(AtPortKind::HighSpeed));
        assert_eq!(AtPortKind::from_tty_name("ttyS0"), None);
        assert_eq!(AtPortKind::from_tty_name("ttyUSBdebug"), None);
    }

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
