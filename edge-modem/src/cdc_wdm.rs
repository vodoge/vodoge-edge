use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use crate::SessionError;

const QMUX_INTERFACE_TYPE: u8 = 0x01;

/// Linux `cdc-wdm` character device. One file is bound to one modem control
/// channel; the caller must not share it across devices.
pub struct CdcWdmDevice {
    file: File,
}

impl CdcWdmDevice {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SessionError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                SessionError::transport(format!("open {}: {error}", path.display()))
            })?;
        Ok(Self { file })
    }
}

impl crate::QmiTransport for CdcWdmDevice {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.file.write_all(request).map_err(|error| {
            SessionError::transport(format!("write cdc-wdm request: {error}"))
        })?;
        read_qmux_frame(&mut self.file)
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
