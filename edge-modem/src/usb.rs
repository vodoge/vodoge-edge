//! USB port-level reset for a modem that stopped answering QMI.
//!
//! A Quectel QMI stack can desync so that every request comes back as
//! `response has no pending service 0x00 client 0x00`: the module is replying
//! to a transaction from a previous session. Nothing on the QMI channel
//! recovers that, because allocating a client ID is itself a QMI request, and
//! `AT` on the control port cannot reach the QMI stack at all. The interface
//! also reports `endpoint hangup` once the state is deep enough.
//!
//! `USBDEVFS_RESET` re-enumerates the device, which reloads the driver and
//! clears the module's client-ID table. It is the only recovery that does not
//! require someone to physically pull the stick.

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// `_IO('U', 20)` — re-enumerate the device behind an open usbfs handle.
#[cfg(target_os = "linux")]
const USBDEVFS_RESET: libc::c_ulong = 0x5514;

/// Failures while locating or resetting a USB device.
#[derive(Debug)]
pub enum UsbError {
    NotFound(PathBuf),
    Open { path: PathBuf, reason: String },
    Ioctl(String),
    Unsupported,
}

impl std::fmt::Display for UsbError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(path) => {
                write!(formatter, "no USB device behind {}", path.display())
            }
            Self::Open { path, reason } => write!(formatter, "open {}: {reason}", path.display()),
            Self::Ioctl(reason) => formatter.write_str(reason),
            Self::Unsupported => formatter.write_str("USB reset is only supported on Linux"),
        }
    }
}

impl std::error::Error for UsbError {}

/// Where a reset landed, so an operator can tell which stick moved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsbReset {
    /// USB device identifier, e.g. `2-4.1`.
    pub device: String,
    /// usbfs node the ioctl was issued against.
    pub node: PathBuf,
}

/// Reset the USB device that provides `qmi_path`.
///
/// The character device disappears and comes back during re-enumeration, so the
/// caller must rediscover it rather than reuse an open handle.
pub fn reset_for_qmi(qmi_path: &Path) -> Result<UsbReset, UsbError> {
    let device = usb_device_of_qmi(qmi_path).ok_or_else(|| UsbError::NotFound(qmi_path.into()))?;
    let node = usbfs_node(&device).ok_or_else(|| UsbError::NotFound(qmi_path.into()))?;
    issue_reset(&node)?;
    Ok(UsbReset { device, node })
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

/// usbfs node for a USB device identifier, read from sysfs rather than guessed:
/// bus and device numbers change on every re-enumeration.
fn usbfs_node(device: &str) -> Option<PathBuf> {
    let base = PathBuf::from("/sys/bus/usb/devices").join(device);
    let bus: u16 = std::fs::read_to_string(base.join("busnum"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let address: u16 = std::fs::read_to_string(base.join("devnum"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
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
}
