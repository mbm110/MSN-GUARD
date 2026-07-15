#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};

#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::error::{AetherError, Result};

/// Bridges Android's packet TUN file descriptor with Aether's raw-IP tunnel.
#[cfg(unix)]
pub async fn bridge(
    tun_fd: i32,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    // Duplicate fd: Java owns original ParcelFileDescriptor lifetime.
    let fd = unsafe { libc::dup(tun_fd) };
    if fd < 0 {
        return Err(AetherError::Io(io::Error::last_os_error()));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(AetherError::Io(error));
    }

    // SAFETY: `fd` is successful duplicate, now owned by File.
    let tun = AsyncFd::new(unsafe { File::from_raw_fd(fd) })?;
    let mut packet = vec![0u8; 65_535];

    loop {
        tokio::select! {
            tunnel_packet = inbound_rx.recv() => match tunnel_packet {
                Some(packet) => write_packet(&tun, &packet).await?,
                None => return Ok(()),
            },
            read = read_packet(&tun, &mut packet) => {
                let length = read?;
                if length == 0 {
                    return Ok(());
                }
                outbound_tx.send(packet[..length].to_vec()).await
                    .map_err(|_| AetherError::Other("tunnel outbound channel closed".into()))?;
            },
        }
    }
}

#[cfg(unix)]
async fn read_packet(tun: &AsyncFd<File>, packet: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = tun.readable().await?;
        match ready.try_io(|file| {
            let length = unsafe {
                libc::read(
                    file.get_ref().as_raw_fd(),
                    packet.as_mut_ptr().cast(),
                    packet.len(),
                )
            };
            if length < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(length as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

#[cfg(unix)]
async fn write_packet(tun: &AsyncFd<File>, packet: &[u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < packet.len() {
        let mut ready = tun.writable().await?;
        match ready.try_io(|file| {
            let length = unsafe {
                libc::write(
                    file.get_ref().as_raw_fd(),
                    packet[offset..].as_ptr().cast(),
                    packet.len() - offset,
                )
            };
            if length < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(length as usize)
            }
        }) {
            Ok(Ok(length)) => offset += length,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn bridge(
    _tun_fd: i32,
    _inbound_rx: mpsc::Receiver<Vec<u8>>,
    _outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    Err(AetherError::Other("TUN mode requires a Unix platform".into()))
}
