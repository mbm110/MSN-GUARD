use std::io;
use std::sync::RwLock;

pub type SocketProtector = unsafe extern "C" fn(fd: i32) -> i32;

static SOCKET_PROTECTOR: RwLock<Option<SocketProtector>> = RwLock::new(None);

pub fn set_socket_protector(protector: Option<SocketProtector>) {
    *SOCKET_PROTECTOR.write().unwrap() = protector;
}

#[cfg(unix)]
pub(crate) fn protect_socket<T: std::os::fd::AsRawFd>(socket: &T) -> io::Result<()> {
    let Some(protector) = *SOCKET_PROTECTOR.read().unwrap() else {
        return Ok(());
    };

    // SAFETY: caller registered this function pointer and it remains valid until replaced.
    let protected = unsafe { protector(socket.as_raw_fd()) };
    if protected != 0 {
        Ok(())
    } else {
        Err(io::Error::other("Android VPN socket protection failed"))
    }
}

#[cfg(not(unix))]
pub(crate) fn protect_socket<T>(_socket: &T) -> io::Result<()> {
    Ok(())
}
