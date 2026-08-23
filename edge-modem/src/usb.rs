//! USB-level recovery for a modem that stopped answering QMI.
//!
//! A Quectel QMI stack can desync so that every request comes back as
//! `response has no pending service 0x00 client 0x00`: the module is replying
//! to a transaction from a previous session. Nothing on the QMI channel
//! recovers that, because allocating a client ID is itself a QMI request, and
//! `AT` on the control port cannot reach the QMI stack at all. The interface
//! also reports `endpoint hangup` once the state is deep enough.
//!
//! # Why `USBDEVFS_RESET` is not enough here
//!
//! These modules reach the host over USB/IP, so their bus is `vhci_hcd` and
//! not a real controller. `USBDEVFS_RESET` asks the hub for a port reset, and
//! `vhci_hcd` answers a port reset **locally**: it times a 50ms window in the
//! virtual root hub and marks the port enabled again. Nothing is sent to the
//! server, so the module never sees a reset. That is exactly what the bench
//! showed on 2026-08-23: a `USBDEVFS_RESET` on USB `4-2` logged
//! `reset high-speed USB device number 49`, kept device number 49, and left
//! QMI just as desynced as before. The same stick recovered forty minutes
//! later when it genuinely disconnected and came back as device number 67.
//!
//! So the recovery here writes the device's `authorized` attribute instead.
//! De-authorising runs `usb_set_configuration(dev, -1)`, which unbinds every
//! interface driver — `qmi_wwan`, `option`, `cdc_wdm` — and puts
//! `SET_CONFIGURATION 0` **on the wire as a control transfer**. Control
//! transfers are ordinary URBs, so `vhci_hcd` forwards them to the server and
//! they reach the module. Re-authorising re-reads the descriptors and sets a
//! configuration again, which recreates `cdc-wdm` and the `ttyUSB` nodes.
//! It is the strongest thing available from inside the guest that does not
//! require someone to physically pull the stick, or a USB/IP detach on the
//! host that no one can undo remotely if it fails to come back.
//!
//! `USBDEVFS_RESET` is kept as the lighter tier, used only when `authorized`
//! cannot be written at all. It is never used as a silent substitute: the
//! result says which of the two ran.

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// `_IO('U', 20)` — re-enumerate the device behind an open usbfs handle.
#[cfg(target_os = "linux")]
const USBDEVFS_RESET: libc::c_ulong = 0x5514;

/// Where the kernel lists USB devices by bus topology.
const SYSFS_USB_DEVICES: &str = "/sys/bus/usb/devices";

/// How long the module is left de-authorised before it is brought back.
///
/// Long enough for the `SET_CONFIGURATION 0` to have travelled the USB/IP
/// link and been acted on; short enough that the window in which the stick is
/// deliberately absent stays small.
const DEAUTHORIZE_SETTLE: Duration = Duration::from_millis(1_500);

/// How many times re-authorising is retried before it is called a failure.
///
/// Only the second half of the cycle retries. Failing to bring a device back
/// is the one outcome that must not be shrugged off: it leaves the module
/// unusable in a way an operator cannot fix without physical access.
const REAUTHORIZE_ATTEMPTS: u32 = 5;

/// Gap between re-authorise attempts.
const REAUTHORIZE_RETRY: Duration = Duration::from_millis(400);

/// How long the device is given to expose interfaces again.
///
/// USB enumeration is sub-second when it works; this is generous so that a
/// slow module is not reported as lost, and bounded so that a module that
/// really did not come back is reported straight away rather than left for
/// somebody to notice.
const RETURN_TIMEOUT: Duration = Duration::from_secs(20);

/// Poll interval while waiting for the device to come back.
const RETURN_POLL: Duration = Duration::from_millis(250);

/// Failures while locating or recovering a USB device.
#[derive(Debug)]
pub enum UsbError {
    NotFound(PathBuf),
    /// No USB device sits at this bus topology position.
    UnknownDevice(String),
    Open { path: PathBuf, reason: String },
    Ioctl(String),
    /// The device was taken down and did not come back. Deliberately its own
    /// variant: it is the only failure here that leaves the bench worse than
    /// it was found.
    DidNotReturn { device: String, waited: Duration },
    Unsupported,
}

impl std::fmt::Display for UsbError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(path) => {
                write!(formatter, "no USB device behind {}", path.display())
            }
            Self::UnknownDevice(device) => {
                write!(formatter, "no USB device at {device}")
            }
            Self::Open { path, reason } => write!(formatter, "open {}: {reason}", path.display()),
            Self::Ioctl(reason) => formatter.write_str(reason),
            Self::DidNotReturn { device, waited } => write!(
                formatter,
                "USB device {device} was de-authorised and had not come back after {}s",
                waited.as_secs()
            ),
            Self::Unsupported => formatter.write_str("USB recovery is only supported on Linux"),
        }
    }
}

impl std::error::Error for UsbError {}

/// What a USB device says it is, read from sysfs rather than remembered.
///
/// The bench sticks report no `iSerial` at all and share one vendor/product
/// pair, so this cannot tell two of them apart. What it can do is tell a
/// modem from whatever else might occupy the same bus position later, which
/// is the question a recorded position has to survive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsbIdentity {
    pub vendor: String,
    pub product: String,
}

impl std::fmt::Display for UsbIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.vendor, self.product)
    }
}

/// Which of the two recovery tiers actually ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbRecovery {
    /// `authorized` written `0` then `1`: every interface driver is unbound
    /// and the module is unconfigured and reconfigured over the wire.
    Reauthorized,
    /// `USBDEVFS_RESET`: a port reset, which a USB/IP bus answers locally.
    /// Only used when `authorized` could not be written.
    PortReset,
}

impl UsbRecovery {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Reauthorized => "reauthorize",
            Self::PortReset => "port_reset",
        }
    }
}

/// Where a recovery landed, so an operator can tell which stick moved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsbReset {
    /// USB device identifier, e.g. `4-3`.
    pub device: String,
    /// The file the recovery was issued through — the `authorized` attribute
    /// or the usbfs node, depending on which tier ran.
    pub node: PathBuf,
    pub recovery: UsbRecovery,
    /// Bus address before and after. On a USB/IP bus neither tier reassigns
    /// it, so this is reported rather than asserted on: it is evidence about
    /// what happened, not the definition of success.
    pub devnum_before: Option<u32>,
    pub devnum_after: Option<u32>,
    /// How long the device took to expose interfaces again.
    pub returned_after_ms: u64,
}

/// sysfs directory of a USB device identifier.
fn sysfs_device(device: &str) -> PathBuf {
    PathBuf::from(SYSFS_USB_DEVICES).join(device)
}

/// Reset the USB device that provides `qmi_path`.
///
/// Kept for callers that only hold a `cdc-wdm` path. Anything that has to be
/// sure *which* stick it is touching should resolve the device identifier
/// first and call [`recover_usb_device`]: a `cdc-wdm` number is reassigned on
/// re-enumeration and a bus position is not.
///
/// The character device disappears and comes back during re-enumeration, so
/// the caller must rediscover it rather than reuse an open handle.
pub fn reset_for_qmi(qmi_path: &Path) -> Result<UsbReset, UsbError> {
    let device = usb_device_of_qmi(qmi_path).ok_or_else(|| UsbError::NotFound(qmi_path.into()))?;
    recover_usb_device(&device)
}

/// USB device identifier backing a `cdc-wdm` character device.
pub fn usb_device_of_qmi(qmi_path: &Path) -> Option<String> {
    let name = qmi_path.file_name()?.to_str()?;
    let link = PathBuf::from(format!("/sys/class/usbmisc/{name}/device"));
    let resolved = std::fs::canonicalize(link).ok()?;
    let text = resolved.to_str()?;
    text.rsplit('/')
        .find_map(|segment| segment.split_once(':').map(|(device, _)| device.to_string()))
}

/// Vendor and product of the device at a bus position, read now.
pub fn usb_identity(device: &str) -> Option<UsbIdentity> {
    identity_in(&sysfs_device(device))
}

/// Bus address of the device at a bus position, read now.
pub fn usb_devnum(device: &str) -> Option<u32> {
    read_number(&sysfs_device(device).join("devnum"))
}

fn identity_in(base: &Path) -> Option<UsbIdentity> {
    let vendor = std::fs::read_to_string(base.join("idVendor")).ok()?;
    let product = std::fs::read_to_string(base.join("idProduct")).ok()?;
    Some(UsbIdentity {
        vendor: vendor.trim().to_string(),
        product: product.trim().to_string(),
    })
}

fn read_number(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Whether the kernel has bound interfaces to this device.
///
/// An interface directory is named `<device>:<config>.<interface>`, and none
/// exist while the device is de-authorised. Their return is what says the
/// module answered the descriptor reads and took a configuration.
fn has_interfaces_in(base: &Path, device: &str) -> bool {
    let prefix = format!("{device}:");
    let Ok(entries) = std::fs::read_dir(base) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .map(|name| name.starts_with(&prefix))
            .unwrap_or(false)
    })
}

/// Take a module down to nothing and bring it back.
///
/// Targeted by bus position, never by `cdc-wdm` number: the number moves
/// across a re-enumeration and the position does not, and this is a
/// destructive operation aimed at hardware that cannot say who it is.
pub fn recover_usb_device(device: &str) -> Result<UsbReset, UsbError> {
    let base = sysfs_device(device);
    let Some(_identity) = identity_in(&base) else {
        return Err(UsbError::UnknownDevice(device.to_string()));
    };
    let devnum_before = read_number(&base.join("devnum"));
    let authorized = base.join("authorized");

    let started = Instant::now();
    let recovery = match deauthorize(&authorized) {
        Ok(()) => {
            std::thread::sleep(DEAUTHORIZE_SETTLE);
            // From here the module is deliberately absent. Every failure is
            // reported rather than retried into something else: falling back
            // to a port reset now would be issuing a second recovery against
            // a device that is already down.
            reauthorize(&authorized, device)?;
            UsbRecovery::Reauthorized
        }
        // Nothing was disturbed, so the lighter tier is still open. It is
        // weaker on a USB/IP bus, and the caller is told which one ran.
        Err(_) => {
            let node = usbfs_node(device).ok_or_else(|| UsbError::UnknownDevice(device.into()))?;
            issue_reset(&node)?;
            return Ok(UsbReset {
                device: device.to_string(),
                node,
                recovery: UsbRecovery::PortReset,
                devnum_before,
                devnum_after: read_number(&base.join("devnum")),
                returned_after_ms: started.elapsed().as_millis() as u64,
            });
        }
    };

    let deadline = Instant::now() + RETURN_TIMEOUT;
    while !has_interfaces_in(&base, device) {
        if Instant::now() >= deadline {
            return Err(UsbError::DidNotReturn {
                device: device.to_string(),
                waited: RETURN_TIMEOUT,
            });
        }
        std::thread::sleep(RETURN_POLL);
    }

    Ok(UsbReset {
        device: device.to_string(),
        node: authorized,
        recovery,
        devnum_before,
        devnum_after: read_number(&base.join("devnum")),
        returned_after_ms: started.elapsed().as_millis() as u64,
    })
}

fn deauthorize(authorized: &Path) -> Result<(), UsbError> {
    std::fs::write(authorized, b"0").map_err(|error| UsbError::Open {
        path: authorized.to_path_buf(),
        reason: error.to_string(),
    })
}

fn reauthorize(authorized: &Path, device: &str) -> Result<(), UsbError> {
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..REAUTHORIZE_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(REAUTHORIZE_RETRY);
        }
        match std::fs::write(authorized, b"1") {
            Ok(()) => return Ok(()),
            Err(error) => last = Some(error),
        }
    }
    Err(UsbError::Ioctl(format!(
        "USB device {device} stayed de-authorised: {}",
        last.map(|error| error.to_string())
            .unwrap_or_else(|| "no reason reported".into())
    )))
}

/// usbfs node for a USB device identifier, read from sysfs rather than guessed:
/// bus and device numbers change on every re-enumeration.
fn usbfs_node(device: &str) -> Option<PathBuf> {
    let base = sysfs_device(device);
    let bus = read_number(&base.join("busnum"))?;
    let address = read_number(&base.join("devnum"))?;
    Some(PathBuf::from(format!(
        "/dev/bus/usb/{bus:03}/{address:03}"
    )))
}

#[cfg(target_os = "linux")]
fn issue_reset(node: &Path) -> Result<(), UsbError> {
    use std::os::unix::io::AsRawFd;

    let file = OpenOptions::new()
        .write(true)
        .open(node)
        .map_err(|error| UsbError::Open {
            path: node.to_path_buf(),
            reason: error.to_string(),
        })?;
    if unsafe { libc::ioctl(file.as_raw_fd(), USBDEVFS_RESET, 0) } != 0 {
        return Err(UsbError::Ioctl(format!(
            "USBDEVFS_RESET on {} failed: {}",
            node.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn issue_reset(_node: &Path) -> Result<(), UsbError> {
    Err(UsbError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch sysfs tree, so the readers can be exercised without a bus.
    struct Sysfs(PathBuf);

    impl Sysfs {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!("vodoge-usb-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("scratch sysfs");
            Self(root)
        }

        fn device(&self, device: &str) -> PathBuf {
            let base = self.0.join(device);
            std::fs::create_dir_all(&base).expect("device dir");
            base
        }
    }

    impl Drop for Sysfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_device_is_reported_with_its_path() {
        let error = UsbError::NotFound(PathBuf::from("/dev/cdc-wdm9"));
        assert_eq!(error.to_string(), "no USB device behind /dev/cdc-wdm9");
    }

    #[test]
    fn unknown_qmi_node_has_no_usb_device() {
        assert_eq!(
            usb_device_of_qmi(Path::new("/dev/cdc-wdm-does-not-exist")),
            None
        );
    }

    #[test]
    fn usbfs_node_is_absent_for_an_unknown_device() {
        assert_eq!(usbfs_node("99-99"), None);
    }

    #[test]
    fn an_absent_device_has_no_identity() {
        assert_eq!(usb_identity("99-99"), None);
        assert_eq!(usb_devnum("99-99"), None);
    }

    #[test]
    fn identity_is_read_from_the_device_directory() {
        let sysfs = Sysfs::new("identity");
        let base = sysfs.device("4-3");
        // Trailing newlines are how sysfs actually answers.
        std::fs::write(base.join("idVendor"), "2c7c\n").expect("vendor");
        std::fs::write(base.join("idProduct"), "0125\n").expect("product");
        assert_eq!(
            identity_in(&base),
            Some(UsbIdentity {
                vendor: "2c7c".into(),
                product: "0125".into(),
            })
        );
        assert_eq!(identity_in(&base).expect("identity").to_string(), "2c7c:0125");
    }

    /// A de-authorised device keeps its directory and loses its interfaces,
    /// which is the difference the return wait is watching for.
    #[test]
    fn interfaces_are_what_says_a_device_came_back() {
        let sysfs = Sysfs::new("interfaces");
        let base = sysfs.device("4-3");
        std::fs::write(base.join("idVendor"), "2c7c\n").expect("vendor");
        assert!(!has_interfaces_in(&base, "4-3"));
        std::fs::create_dir_all(base.join("4-3:1.0")).expect("interface");
        assert!(has_interfaces_in(&base, "4-3"));
    }

    /// The colon is load-bearing. A device directory also holds the devices
    /// plugged in below it — `4-3.1` sits inside `4-3` — and those keep their
    /// directories while `4-3` itself is de-authorised. Matching on the bare
    /// name would read a downstream device as proof that this one came back.
    #[test]
    fn a_downstream_device_is_not_an_interface() {
        let sysfs = Sysfs::new("downstream");
        let base = sysfs.device("4-3");
        std::fs::create_dir_all(base.join("4-3.1")).expect("downstream device");
        assert!(!has_interfaces_in(&base, "4-3"));
        std::fs::create_dir_all(base.join("4-3:1.0")).expect("interface");
        assert!(has_interfaces_in(&base, "4-3"));
    }

    #[test]
    fn recovery_tiers_spell_themselves_for_the_receipt() {
        assert_eq!(UsbRecovery::Reauthorized.wire(), "reauthorize");
        assert_eq!(UsbRecovery::PortReset.wire(), "port_reset");
    }

    #[test]
    fn a_device_that_never_came_back_says_so() {
        let error = UsbError::DidNotReturn {
            device: "4-3".into(),
            waited: Duration::from_secs(20),
        };
        assert_eq!(
            error.to_string(),
            "USB device 4-3 was de-authorised and had not come back after 20s"
        );
    }

    #[test]
    fn recovering_a_position_with_nothing_on_it_is_refused() {
        match recover_usb_device("99-99") {
            Err(UsbError::UnknownDevice(device)) => assert_eq!(device, "99-99"),
            other => panic!("expected UnknownDevice, got {other:?}"),
        }
    }
}
