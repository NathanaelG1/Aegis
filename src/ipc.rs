//! Experimental same-account Unix transport. Peer UID is NOT human presence/containment.
use crate::{protocol, AgentClient, ErrorCode};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub const MAX_CONNECTIONS: usize = 8;
pub const FRAME_READ_SECONDS: u64 = 1;
/// Conservative complete socket-path byte limit for this Unix workflow.
pub const MAX_SOCKET_PATH_BYTES: usize = 100;

// A socket timeout bounds one read syscall. A frame deadline must also bound
// peers that continually provide a few bytes before that timeout elapses.
struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn new(stream: UnixStream, duration: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + duration,
        }
    }
    fn begin_frame(&mut self, duration: Duration) {
        self.deadline = Instant::now() + duration;
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "frame deadline"))?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
fn uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

pub fn authenticate_peer(stream: &UnixStream) -> Result<(), ErrorCode> {
    #[cfg(target_os = "macos")]
    let peer = nix::unistd::getpeereid(stream)
        .map_err(|_| ErrorCode::PrincipalMismatch)?
        .0
        .as_raw();
    #[cfg(target_os = "linux")]
    let peer = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|_| ErrorCode::PrincipalMismatch)?
        .uid();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(ErrorCode::BrokerUnavailable);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if peer == uid() {
        Ok(())
    } else {
        Err(ErrorCode::PrincipalMismatch)
    }
}

fn no_symlink_components(path: &Path) -> Result<(), ErrorCode> {
    if !path.is_absolute() {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir | Component::Normal(_) => current.push(part),
            _ => return Err(ErrorCode::InvalidRequest),
        }
        let metadata =
            std::fs::symlink_metadata(&current).map_err(|_| ErrorCode::InvalidRequest)?;
        if metadata.file_type().is_symlink() {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    Ok(())
}

/// Owns only a newly created directory and socket; never replaces an existing path.
pub struct Endpoint {
    listener: UnixListener,
    directory: PathBuf,
    socket: PathBuf,
    epoch: String,
}
impl Endpoint {
    pub fn create(directory: &Path) -> Result<Self, ErrorCode> {
        if directory
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(u8::is_ascii_control)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut epoch = [0u8; 16];
        getrandom::getrandom(&mut epoch).map_err(|_| ErrorCode::BrokerUnavailable)?;
        let epoch = epoch.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let parent = directory.parent().ok_or(ErrorCode::InvalidRequest)?;
        no_symlink_components(parent)?;
        if !matches!(
            directory.components().next_back(),
            Some(Component::Normal(_))
        ) {
            return Err(ErrorCode::InvalidRequest);
        }
        let socket = directory.join("agent.sock");
        if socket.as_os_str().as_encoded_bytes().len() > MAX_SOCKET_PATH_BYTES {
            return Err(ErrorCode::InvalidRequest);
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(_) => {
                let _ = std::fs::remove_dir(directory);
                return Err(ErrorCode::BrokerUnavailable);
            }
        };
        listener
            .set_nonblocking(true)
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        Ok(Self {
            listener,
            directory: directory.to_path_buf(),
            socket,
            epoch,
        })
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }
    /// Bound per-connection I/O and connection count; no control methods on this endpoint.
    pub fn accept_available(
        &self,
        client: &AgentClient,
        active: Arc<AtomicUsize>,
    ) -> Result<(), ErrorCode> {
        for _ in 0..MAX_CONNECTIONS * 2 {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(ErrorCode::BrokerUnavailable),
            };
            if authenticate_peer(&stream).is_err() {
                continue;
            }
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let client = client.clone();
            let count = active.clone();
            let epoch = self.epoch.clone();
            std::thread::spawn(move || {
                struct Guard(Arc<AtomicUsize>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                let _guard = Guard(count);
                if stream.set_nonblocking(false).is_err() {
                    return;
                }
                if stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .is_err()
                    || stream
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .is_err()
                {
                    return;
                }
                if let Ok(mut writer) = stream.try_clone() {
                    let greeting = serde_json::json!({"version":protocol::PROTOCOL_VERSION,"session_epoch":epoch});
                    if serde_json::to_writer(&mut writer, &greeting).is_err()
                        || writer.write_all(b"\n").is_err()
                    {
                        return;
                    }
                    let input = BufReader::new(DeadlineStream::new(
                        stream,
                        Duration::from_secs(FRAME_READ_SECONDS),
                    ));
                    let _ = protocol::serve_frames(input, writer, &client, |reader| {
                        reader
                            .get_mut()
                            .begin_frame(Duration::from_secs(FRAME_READ_SECONDS));
                    });
                }
            });
        }
        Ok(())
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn validate_endpoint(socket: &Path) -> Result<(), ErrorCode> {
    no_symlink_components(socket)?;
    let parent = socket.parent().ok_or(ErrorCode::InvalidRequest)?;
    let directory = std::fs::symlink_metadata(parent).map_err(|_| ErrorCode::BrokerUnavailable)?;
    let metadata = std::fs::symlink_metadata(socket).map_err(|_| ErrorCode::BrokerUnavailable)?;
    if !directory.is_dir()
        || directory.uid() != uid()
        || directory.mode() & 0o777 != 0o700
        || !metadata.file_type().is_socket()
        || metadata.uid() != uid()
    {
        return Err(ErrorCode::PrincipalMismatch);
    }
    Ok(())
}

pub struct SocketBridge {
    socket: PathBuf,
    epoch: String,
}
impl SocketBridge {
    pub fn connect(socket: &Path) -> Result<Self, ErrorCode> {
        let (_, epoch) = open_connection(socket)?;
        Ok(Self {
            socket: socket.to_path_buf(),
            epoch,
        })
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Greeting {
    version: u32,
    session_epoch: String,
}
fn open_connection(socket: &Path) -> Result<(BufReader<DeadlineStream>, String), ErrorCode> {
    validate_endpoint(socket)?;
    let stream = UnixStream::connect(socket).map_err(|_| ErrorCode::BrokerUnavailable)?;
    authenticate_peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    let mut reader = BufReader::new(DeadlineStream::new(stream, Duration::from_secs(2)));
    let mut frame = Vec::new();
    std::io::Read::take(&mut reader, 257)
        .read_until(b'\n', &mut frame)
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    if frame.len() > 256 || frame.last() != Some(&b'\n') {
        return Err(ErrorCode::InvalidProviderResult);
    }
    let greeting: Greeting =
        serde_json::from_slice(&frame).map_err(|_| ErrorCode::InvalidProviderResult)?;
    if greeting.version != protocol::PROTOCOL_VERSION
        || greeting.session_epoch.len() != 32
        || !greeting
            .session_epoch
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(ErrorCode::InvalidProviderResult);
    }
    Ok((reader, greeting.session_epoch))
}
impl crate::mcp::Bridge for SocketBridge {
    fn exchange(&mut self, request: &serde_json::Value) -> protocol::Response {
        let result = (|| {
            let (mut reader, epoch) = open_connection(&self.socket)?;
            if epoch != self.epoch {
                return Err(ErrorCode::PrincipalMismatch);
            }
            serde_json::to_writer(reader.get_mut(), request)
                .map_err(|_| ErrorCode::InvalidRequest)?;
            reader
                .get_mut()
                .write_all(b"\n")
                .map_err(|_| ErrorCode::BrokerUnavailable)?;
            let mut frame = Vec::new();
            reader.get_mut().begin_frame(Duration::from_secs(2));
            std::io::Read::take(&mut reader, (protocol::MAX_FRAME_BYTES + 1) as u64)
                .read_until(b'\n', &mut frame)
                .map_err(|_| ErrorCode::BrokerUnavailable)?;
            if frame.len() > protocol::MAX_FRAME_BYTES || frame.last() != Some(&b'\n') {
                return Err(ErrorCode::InvalidProviderResult);
            }
            let response: protocol::Response =
                serde_json::from_slice(&frame).map_err(|_| ErrorCode::InvalidProviderResult)?;
            if response.version != protocol::PROTOCOL_VERSION
                || response.error.is_some() == response.result.is_some()
            {
                return Err(ErrorCode::InvalidProviderResult);
            }
            Ok(response)
        })();
        result.unwrap_or_else(protocol::Response::failure)
    }
}
