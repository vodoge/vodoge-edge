//! Making a connection leave over a chosen network interface.
//!
//! This is the part of the proxy that cannot be tested on a workstation, and
//! the part everything else exists to serve: without it the packets take the
//! box's default route and a proxy "bound to a SIM" is a fiction.
//!
//! Linux offers `SO_BINDTODEVICE`, which pins a socket to an interface by name
//! regardless of the routing table. It needs CAP_NET_RAW, which the edge
//! service is granted for exactly this.

use std::io;

use tokio::net::TcpStream;

/// Connects to `address`, leaving over `interface` when one is given.
///
/// On a platform without interface binding the interface is refused rather
/// than ignored. A connection that silently took the default route would be
/// indistinguishable from a correct one until someone read the exit IP.
pub async fn connect_via(address: &str, interface: Option<&str>) -> io::Result<TcpStream> {
    match interface {
        None => TcpStream::connect(address).await,
        Some(name) => connect_bound(address, name).await,
    }
}

#[cfg(target_os = "linux")]
async fn connect_bound(address: &str, interface: &str) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    use std::os::fd::AsRawFd;

    use tokio::net::TcpSocket;

    // Resolution happens here, on the box, using its resolver. A domain that
    // resolves differently per network is a real situation, and this is the
    // point at which the choice of interface is already known.
    let resolved = {
        let address = address.to_string();
        tokio::task::spawn_blocking(move || {
            address
                .to_socket_addrs()
                .map(|mut addresses| addresses.next())
        })
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))??
    };
    let resolved = resolved.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {address}"))
    })?;

    let socket = if resolved.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    // SO_BINDTODEVICE takes the interface name as bytes, not a NUL-terminated
    // string, and the length must include no terminator.
    let name = interface.as_bytes();
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        // Worth naming the interface: the usual causes are that it has gone
        // away with the modem, or that the process lost CAP_NET_RAW.
        return Err(io::Error::new(
            error.kind(),
            format!("cannot bind to interface {interface}: {error}"),
        ));
    }
    socket.connect(resolved).await
}

#[cfg(not(target_os = "linux"))]
async fn connect_bound(_address: &str, interface: &str) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("binding a connection to interface {interface} needs Linux"),
    ))
}

/// Finds the network interface a modem's data session is using, by walking
/// sysfs from the USB device the QMI node belongs to.
///
/// The name is not stable across re-enumeration — a modem that resets can come
/// back as a different `wwan`— so it is resolved when a listener starts rather
/// than remembered.
#[cfg(target_os = "linux")]
pub fn interface_for_usb_device(usb_path: &std::path::Path) -> Option<String> {
    let entries = std::fs::read_dir(usb_path.join("net")).ok()?;
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            return Some(name.to_string());
        }
    }
    None
}
