//! Rootless Linux network-namespace bridge for CDM's trusted HTTP(S) proxy.
//!
//! A helper inside the empty network namespace accepts only loopback TCP.
//! Accepted TCP descriptors cross a private AF_UNIX control channel with
//! SCM_RIGHTS; the trusted host broker connects each descriptor to CDM's
//! existing loopback proxy. No routable interface enters the namespace.

use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(test)]
use std::io::Read;

pub const BRIDGE_SOCKET_NAME: &str = "bridge.sock";
const BRIDGE_RECORD: u8 = 0xc1;
const MAX_FORWARDERS: usize = 128;

pub struct ProxyBridge {
    socket_path: PathBuf,
    root: PathBuf,
    stop: Arc<AtomicBool>,
    broker: Option<JoinHandle<io::Result<()>>>,
    forwarders: Arc<Mutex<Vec<JoinHandle<io::Result<()>>>>>,
}

impl ProxyBridge {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn start(runtime_root: &Path, upstream_port: u16) -> io::Result<Self> {
        Self::start_with_ports(runtime_root, upstream_port, upstream_port)
    }

    fn start_with_ports(
        runtime_root: &Path,
        upstream_port: u16,
        accepted_port: u16,
    ) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        // The invocation runtime is already private and unique. Keep the
        // additional bridge path short enough for sockaddr_un::sun_path even
        // when the host supplies a long temporary-directory prefix.
        let root = runtime_root.join("proxy-bridge");
        std::fs::create_dir(&root)?;
        let mut setup = BridgeSetupCleanup::new(root.clone());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let socket_path = root.join(BRIDGE_SOCKET_NAME);
        let listener = UnixListener::bind(&socket_path)?;
        setup.socket_path = Some(socket_path.clone());
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let forwarders = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_forwarders = Arc::clone(&forwarders);
        let broker = thread::Builder::new()
            .name("cdm-linux-proxy-bridge".into())
            .spawn(move || {
                broker_loop(
                    listener,
                    upstream_port,
                    accepted_port,
                    &thread_stop,
                    &thread_forwarders,
                )
            })?;
        let bridge = Self {
            socket_path,
            root,
            stop,
            broker: Some(broker),
            forwarders,
        };
        setup.disarm();
        Ok(bridge)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[cfg(target_os = "linux")]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stop(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.socket_path);
        let mut failure = None;
        if let Some(thread) = self.broker.take() {
            let result = thread
                .join()
                .map_err(|_| io::Error::other("proxy bridge broker panicked"))
                .and_then(|result| result);
            record_cleanup_failure(&mut failure, result);
        }
        let forwarders = match self.forwarders.lock() {
            Ok(mut forwarders) => std::mem::take(&mut *forwarders),
            Err(_) => {
                record_cleanup_failure(
                    &mut failure,
                    Err(io::Error::other("proxy bridge lock poisoned")),
                );
                Vec::new()
            }
        };
        for forwarder in forwarders {
            let result = forwarder
                .join()
                .map_err(|_| io::Error::other("proxy bridge forwarder panicked"))
                .and_then(|result| result);
            record_cleanup_failure(&mut failure, result);
        }
        record_cleanup_failure(&mut failure, remove_if_present(&self.socket_path));
        record_cleanup_failure(&mut failure, remove_dir_if_present(&self.root));
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for ProxyBridge {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn broker_loop(
    listener: UnixListener,
    upstream_port: u16,
    accepted_port: u16,
    stop: &AtomicBool,
    forwarders: &Mutex<Vec<JoinHandle<io::Result<()>>>>,
) -> io::Result<()> {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                verify_bridge_peer(&stream)?;
                if let Some(path) = listener.local_addr()?.as_pathname() {
                    remove_if_present(path)?;
                }
                stream.set_read_timeout(Some(Duration::from_millis(100)))?;
                while !stop.load(Ordering::Acquire) {
                    match receive_fd(&stream) {
                        Ok(Some(fd)) => {
                            validate_loopback_tcp(fd.as_raw_fd(), accepted_port)?;
                            reap_finished_forwarders(forwarders)?;
                            if forwarders
                                .lock()
                                .map_err(|_| io::Error::other("proxy bridge lock poisoned"))?
                                .len()
                                >= MAX_FORWARDERS
                            {
                                return Err(io::Error::other(
                                    "proxy bridge concurrent connection limit exceeded",
                                ));
                            }
                            let handle = thread::Builder::new()
                                .name("cdm-proxy-forward".into())
                                .spawn(move || forward_fd(fd, upstream_port))?;
                            forwarders
                                .lock()
                                .map_err(|_| io::Error::other("proxy bridge lock poisoned"))?
                                .push(handle);
                        }
                        Ok(None) => return Ok(()),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(error) => return Err(error),
                    }
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn reap_finished_forwarders(forwarders: &Mutex<Vec<JoinHandle<io::Result<()>>>>) -> io::Result<()> {
    let finished = {
        let mut handles = forwarders
            .lock()
            .map_err(|_| io::Error::other("proxy bridge lock poisoned"))?;
        let mut finished = Vec::new();
        let mut index = 0;
        while index < handles.len() {
            if handles[index].is_finished() {
                finished.push(handles.swap_remove(index));
            } else {
                index += 1;
            }
        }
        finished
    };
    for handle in finished {
        handle
            .join()
            .map_err(|_| io::Error::other("proxy bridge forwarder panicked"))??;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_bridge_peer(stream: &UnixStream) -> io::Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if credentials.uid != unsafe { libc::getuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Linux proxy bridge peer uid does not match the invoking user",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_bridge_peer(_stream: &UnixStream) -> io::Result<()> {
    Ok(())
}

fn forward_fd(fd: OwnedFd, upstream_port: u16) -> io::Result<()> {
    let mut client = TcpStream::from(fd);
    let mut upstream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], upstream_port)))?;
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let outbound = thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let inbound = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let outbound = outbound
        .join()
        .map_err(|_| io::Error::other("proxy bridge copy thread panicked"))?;
    inbound.and(outbound).map(|_| ())
}

pub fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    send_fd_record(stream, fd, BRIDGE_RECORD)
}

fn send_fd_record(stream: &UnixStream, fd: RawFd, record: u8) -> io::Result<()> {
    let mut byte = [record];
    let mut iovec = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize }];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        if cmsg.is_null() {
            return Err(io::Error::other("SCM_RIGHTS control buffer is invalid"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;
        std::ptr::copy_nonoverlapping(
            (&fd as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
        message.msg_controllen = (*cmsg).cmsg_len;
        if libc::sendmsg(stream.as_raw_fd(), &message, 0) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn receive_fd(stream: &UnixStream) -> io::Result<Option<OwnedFd>> {
    let mut byte = [0u8];
    let mut iovec = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize }];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, flags) };
    if received == 0 {
        return Ok(None);
    }
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&message);
        let mut received_fd = None;
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
            && (*cmsg).cmsg_len as usize
                >= libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize
        {
            let mut raw = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                (&mut raw as *mut RawFd).cast::<u8>(),
                std::mem::size_of::<RawFd>(),
            );
            if raw >= 0 {
                received_fd = Some(OwnedFd::from_raw_fd(raw));
            }
        }
        let exact_rights_record = byte[0] == BRIDGE_RECORD
            && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0
            && !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
            && (*cmsg).cmsg_len as usize
                == libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize;
        if !cmsg.is_null() {
            cmsg = libc::CMSG_NXTHDR(&message, cmsg);
        }
        if !exact_rights_record || !cmsg.is_null() || received_fd.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy bridge message did not contain one TCP descriptor",
            ));
        }
        Ok(received_fd)
    }
}

fn validate_loopback_tcp(fd: RawFd, accepted_port: u16) -> io::Result<()> {
    let mut socket_type: libc::c_int = 0;
    let mut socket_type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_len,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy bridge accepts only TCP stream descriptors",
        ));
    }
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    let local = stream.local_addr();
    let peer = stream.peer_addr();
    std::mem::forget(stream);
    let local = local?;
    let peer = peer?;
    if !is_loopback(local.ip()) || !is_loopback(peer.ip()) || local.port() != accepted_port {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy bridge accepts only loopback TCP descriptors",
        ));
    }
    Ok(())
}

struct BridgeSetupCleanup {
    root: Option<PathBuf>,
    socket_path: Option<PathBuf>,
}

impl BridgeSetupCleanup {
    fn new(root: PathBuf) -> Self {
        Self {
            root: Some(root),
            socket_path: None,
        }
    }

    fn disarm(&mut self) {
        self.socket_path = None;
        self.root = None;
    }
}

impl Drop for BridgeSetupCleanup {
    fn drop(&mut self) {
        if let Some(socket_path) = self.socket_path.take() {
            let _ = remove_if_present(&socket_path);
        }
        if let Some(root) = self.root.take() {
            let _ = std::fs::remove_dir(&root);
        }
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_dir_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn record_cleanup_failure(failure: &mut Option<io::Error>, result: io::Result<()>) {
    if let Err(error) = result {
        if let Some(first) = failure.take() {
            *failure = Some(io::Error::new(
                first.kind(),
                format!("{first}; additional cleanup failure: {error}"),
            ));
        } else {
            *failure = Some(error);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn run_namespace_helper(
    bridge_path: &Path,
    port: u16,
    command: &[std::ffi::OsString],
) -> io::Result<i32> {
    if command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux proxy helper command is missing",
        ));
    }
    let bridge = UnixStream::connect(bridge_path)?;
    if unsafe { libc::fcntl(bridge.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))?;
    listener.set_nonblocking(true)?;
    install_unix_socket_filter()?;
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    let mut child = std::process::Command::new(&command[0])
        .args(&command[1..])
        .spawn()?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let acceptor = thread::spawn(move || -> io::Result<()> {
        while !thread_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((client, _)) => send_fd(&bridge, client.as_raw_fd())?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    let status = child.wait()?;
    stop.store(true, Ordering::Release);
    acceptor
        .join()
        .map_err(|_| io::Error::other("Linux proxy acceptor panicked"))??;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(libc::SIGKILL)))
}

#[cfg(target_os = "linux")]
fn install_unix_socket_filter() -> io::Result<()> {
    let mut filter = unix_socket_filter();
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            )
        } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub struct SeccompProgram {
    fd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl SeccompProgram {
    pub fn deny_host_socket_deputies() -> io::Result<Self> {
        use std::ffi::CString;
        use std::os::fd::IntoRawFd;
        let name = CString::new("cdm-seccomp")?;
        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let filter = unix_socket_filter();
        let bytes = unsafe {
            std::slice::from_raw_parts(
                filter.as_ptr().cast::<u8>(),
                filter.len() * std::mem::size_of::<libc::sock_filter>(),
            )
        };
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)?;
        file.flush()?;
        let fd = file.into_raw_fd();
        if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0
            || unsafe {
                libc::fcntl(
                    fd,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_SEAL
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_WRITE,
                )
            } < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0
        {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
fn unix_socket_filter() -> Vec<libc::sock_filter> {
    use std::mem::offset_of;
    const ALLOW: u32 = 0x7fff_0000;
    const ERRNO: u32 = 0x0005_0000;
    const KILL: u32 = 0x8000_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    let mut filter = vec![
        stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            offset_of!(libc::seccomp_data, arch) as u32,
        ),
        jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            AUDIT_ARCH,
            1,
            0,
        ),
        stmt((libc::BPF_RET | libc::BPF_K) as u16, KILL),
        stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            offset_of!(libc::seccomp_data, nr) as u32,
        ),
    ];
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_ptrace,
        libc::SYS_bpf,
    ] {
        filter.push(jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            syscall as u32,
            0,
            1,
        ));
        filter.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            ERRNO | libc::EACCES as u32,
        ));
    }
    filter.extend([
        jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            libc::SYS_socket as u32,
            0,
            3,
        ),
        stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            offset_of!(libc::seccomp_data, args) as u32,
        ),
        jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            libc::AF_UNIX as u32,
            0,
            1,
        ),
        stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            ERRNO | libc::EACCES as u32,
        ),
        stmt((libc::BPF_RET | libc::BPF_K) as u16, ALLOW),
    ]);
    filter
}

#[cfg(target_os = "linux")]
const fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_os = "linux")]
const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex as TestMutex, OnceLock};

    fn bridge_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<TestMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| TestMutex::new(())).lock().unwrap()
    }

    #[test]
    fn descriptor_bridge_forwards_only_loopback_tcp() {
        let _guard = bridge_test_lock();
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut input = [0u8; 4];
            stream.read_exact(&mut input).unwrap();
            assert_eq!(&input, b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let root = PathBuf::from("target").join(format!(
            "cpb-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let local = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut bridge =
            ProxyBridge::start_with_ports(&root, upstream_port, local.local_addr().unwrap().port())
                .unwrap();
        let control = UnixStream::connect(bridge.socket_path()).unwrap();
        let mut client = TcpStream::connect(local.local_addr().unwrap()).unwrap();
        let (accepted, _) = local.accept().unwrap();
        send_fd(&control, accepted.as_raw_fd()).unwrap();
        drop(accepted);
        client.write_all(b"ping").unwrap();
        let mut output = [0u8; 4];
        client.read_exact(&mut output).unwrap();
        assert_eq!(&output, b"pong");
        drop(client);
        drop(control);
        bridge.stop().unwrap();
        upstream_thread.join().unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_non_tcp_descriptor() {
        let _guard = bridge_test_lock();
        let (left, right) = UnixStream::pair().unwrap();
        let raw = right.as_raw_fd();
        let error = validate_loopback_tcp(raw, 1234).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::NotConnected | io::ErrorKind::InvalidInput
        ));
        drop(left);
    }

    #[test]
    fn rejects_unknown_bridge_record_without_leaking_the_descriptor() {
        let _guard = bridge_test_lock();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        send_fd_record(&sender, file.as_raw_fd(), BRIDGE_RECORD.wrapping_add(1)).unwrap();
        let error = receive_fd(&receiver).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn accepts_exactly_one_descriptor_record() {
        let _guard = bridge_test_lock();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        send_fd(&sender, file.as_raw_fd()).unwrap();
        assert!(receive_fd(&receiver).unwrap().is_some());
    }

    #[test]
    fn bridge_socket_fits_beneath_a_long_runtime_path() {
        use std::os::unix::ffi::OsStrExt;

        let mut component = format!("cdm-pb-{}-", std::process::id());
        component.push_str(&"x".repeat(64 - component.len()));
        let runtime = PathBuf::from("/tmp").join(component);
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut bridge = ProxyBridge::start_with_ports(&runtime, 1, 1).unwrap();
        assert!(bridge.socket_path().as_os_str().as_bytes().len() < 104);
        bridge.stop().unwrap();
        std::fs::remove_dir(runtime).unwrap();
    }
}
