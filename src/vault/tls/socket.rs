//! Bounded inherited-socket driver for disposable, separately loaded TLS roles.
//!
//! These private factories accept only already-owned sockets. They do not create
//! listeners, select destinations, enroll operational identities, or certify custody.
use super::*;
use crate::vault::{crypto, store};
use serde::Deserialize;
use std::{net::Shutdown, os::unix::net::UnixStream};

const SCHEMA: u16 = 1;
const DOCUMENT: &str = "tls.json";
const MAX_DOCUMENT: usize = 24 * 1024;
const MAX_CERT: usize = 4096;
const MAX_RECORD: usize = 16 * 1024 + 2048;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerDocument {
    schema: u16,
    kind: String,
    root: String,
    certificate: String,
    key: String,
    agent_pin: String,
    admin_pin: String,
}
impl Drop for ServerDocument {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientDocument {
    schema: u16,
    kind: String,
    root: String,
    certificate: String,
    key: String,
    server_pin: String,
}
impl Drop for ClientDocument {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
fn write_document(path: &Path, document: &impl Serialize) -> std::result::Result<(), ErrorCode> {
    store::new_directory(path)?;
    let bytes =
        PrivateBytes(serde_json::to_vec(document).map_err(|_| ErrorCode::PersistenceUnavailable)?);
    if bytes.0.len() > MAX_DOCUMENT {
        return Err(ErrorCode::CapacityExceeded);
    }
    store::write_new(&path.join(DOCUMENT), &bytes.0)?;
    store::sync_directory(path)
}
fn read_document<T: DeserializeOwned>(path: &Path) -> std::result::Result<T, ErrorCode> {
    store::safe_directory(path)?;
    let bytes = PrivateBytes(store::read_file(&path.join(DOCUMENT), MAX_DOCUMENT)?);
    serde_json::from_slice(&bytes.0).map_err(|_| ErrorCode::PersistenceUnavailable)
}
fn certificate(value: &str) -> std::result::Result<CertificateDer<'static>, ErrorCode> {
    let mut bytes = crypto::decode(value, MAX_CERT)?;
    if bytes.0.is_empty() {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(CertificateDer::from(std::mem::take(&mut bytes.0)))
}
fn identity(cert: &str, key: &str) -> std::result::Result<Identity, ErrorCode> {
    let mut bytes = crypto::decode(key, MAX_CERT)?;
    if bytes.0.is_empty() {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(Identity {
        cert: certificate(cert)?,
        key: Zeroizing::new(PrivatePkcs8KeyDer::from(std::mem::take(&mut bytes.0)).into()),
    })
}
fn unavailable(_: Failure) -> ErrorCode {
    ErrorCode::BrokerUnavailable
}

// Only the disposable bootstrap calls Fixtures::new. The server loader below
// has neither a client-private field nor a client-private document read.
pub(in crate::vault) fn bootstrap_fixture(path: &Path) -> std::result::Result<(), ErrorCode> {
    store::new_directory(path)?;
    let fixture = Fixtures::new().map_err(unavailable)?;
    write_document(
        &path.join("broker"),
        &ServerDocument {
            schema: SCHEMA,
            kind: "aegis.synthetic.tls.broker.v1".into(),
            root: crypto::encode(fixture.ca.der()),
            certificate: crypto::encode(&fixture.server.cert),
            key: crypto::encode(fixture.server.key.secret_der()),
            agent_pin: crypto::encode(&fixture.agent.cert),
            admin_pin: crypto::encode(&fixture.admin.cert),
        },
    )?;
    for (name, role) in [("agent", Role::Agent), ("admin", Role::Admin)] {
        let id = fixture.identity(role);
        write_document(
            &path.join(name),
            &ClientDocument {
                schema: SCHEMA,
                kind: client_kind(role).into(),
                root: crypto::encode(fixture.ca.der()),
                certificate: crypto::encode(&id.cert),
                key: crypto::encode(id.key.secret_der()),
                server_pin: crypto::encode(&fixture.server.cert),
            },
        )?;
    }
    store::sync_directory(path)
}
fn client_kind(role: Role) -> &'static str {
    match role {
        Role::Agent => "aegis.synthetic.tls.agent.v1",
        Role::Admin => "aegis.synthetic.tls.admin.v1",
        Role::Recipient => "aegis.synthetic.tls.recipient.v1",
    }
}

pub(in crate::vault) struct ClientFactory {
    config: Arc<ClientConfig>,
    enrollment: Enrollment,
}
impl ClientFactory {
    pub(in crate::vault) fn agent(path: &Path) -> std::result::Result<Self, ErrorCode> {
        Self::open(path, Role::Agent)
    }
    pub(in crate::vault) fn admin(path: &Path) -> std::result::Result<Self, ErrorCode> {
        Self::open(path, Role::Admin)
    }
    fn open(path: &Path, role: Role) -> std::result::Result<Self, ErrorCode> {
        let d: ClientDocument = read_document(path)?;
        if d.schema != SCHEMA || d.kind != client_kind(role) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let id = identity(&d.certificate, &d.key)?;
        Ok(Self {
            config: client_config(&certificate(&d.root)?, Some(&id), role).map_err(unavailable)?,
            enrollment: Enrollment {
                role,
                client_pin: id.cert,
                server_pin: certificate(&d.server_pin)?,
            },
        })
    }
    pub(in crate::vault) fn connect(
        &self,
        stream: UnixStream,
    ) -> std::result::Result<SocketClient, ErrorCode> {
        let name = ServerName::try_from(SERVER_NAME).map_err(|_| ErrorCode::BrokerUnavailable)?;
        let tls = Connection::Client(
            ClientConnection::new(self.config.clone(), name)
                .map_err(|_| ErrorCode::BrokerUnavailable)?,
        );
        Ok(SocketClient {
            connection: SocketConnection::establish(stream, tls, &self.enrollment, true)
                .map_err(unavailable)?,
        })
    }
}

#[derive(Clone)]
pub(in crate::vault) struct ServerMaterial {
    agent: Arc<ServerConfig>,
    admin: Arc<ServerConfig>,
    agent_enrollment: Enrollment,
    admin_enrollment: Enrollment,
}
impl ServerMaterial {
    pub(in crate::vault) fn open(path: &Path) -> std::result::Result<Self, ErrorCode> {
        let d: ServerDocument = read_document(path)?;
        if d.schema != SCHEMA || d.kind != "aegis.synthetic.tls.broker.v1" {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let root = certificate(&d.root)?;
        let id = identity(&d.certificate, &d.key)?;
        let agent_pin = certificate(&d.agent_pin)?;
        let admin_pin = certificate(&d.admin_pin)?;
        if agent_pin == admin_pin || agent_pin == id.cert || admin_pin == id.cert {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        Ok(Self {
            agent: server_config(&root, &id, Role::Agent).map_err(unavailable)?,
            admin: server_config(&root, &id, Role::Admin).map_err(unavailable)?,
            agent_enrollment: Enrollment {
                role: Role::Agent,
                client_pin: agent_pin,
                server_pin: id.cert.clone(),
            },
            admin_enrollment: Enrollment {
                role: Role::Admin,
                client_pin: admin_pin,
                server_pin: id.cert,
            },
        })
    }
    pub(in crate::vault) fn agent(
        &self,
        stream: UnixStream,
        endpoint: AgentEndpoint,
    ) -> std::result::Result<SocketServer, ErrorCode> {
        self.connect(
            stream,
            Endpoint::Agent(endpoint),
            &self.agent,
            &self.agent_enrollment,
        )
    }
    pub(in crate::vault) fn admin(
        &self,
        stream: UnixStream,
        endpoint: AdminEndpoint,
    ) -> std::result::Result<SocketServer, ErrorCode> {
        self.connect(
            stream,
            Endpoint::Admin(endpoint),
            &self.admin,
            &self.admin_enrollment,
        )
    }
    fn connect(
        &self,
        stream: UnixStream,
        endpoint: Endpoint,
        config: &Arc<ServerConfig>,
        enrollment: &Enrollment,
    ) -> std::result::Result<SocketServer, ErrorCode> {
        let tls = Connection::Server(
            ServerConnection::new(config.clone()).map_err(|_| ErrorCode::BrokerUnavailable)?,
        );
        let connection =
            SocketConnection::establish(stream, tls, enrollment, false).map_err(unavailable)?;
        if connection.channel.binding.role != endpoint.role() {
            return Err(ErrorCode::BrokerUnavailable);
        }
        Ok(SocketServer {
            connection,
            endpoint: Some(endpoint),
            #[cfg(test)]
            discard_response: false,
        })
    }
}

// Absolute deadlines are rechecked before and after every OS operation, including
// the final successful byte. EINTR spends work budget and never resets time.
fn remaining(deadline: Instant, now: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or(Failure::Deadline)
}
fn io_failure(error: io::Error) -> Failure {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Failure::Deadline,
        _ => Failure::Closed,
    }
}
struct SocketIo {
    stream: Option<UnixStream>,
    deadline: Instant,
    budget: Budget,
}
impl SocketIo {
    fn new(stream: UnixStream) -> Result<Self> {
        stream.set_nonblocking(false).map_err(io_failure)?;
        let budget = Budget::new(CHANNEL_TIME);
        Ok(Self {
            stream: Some(stream),
            deadline: budget.start + CHANNEL_TIME,
            budget,
        })
    }
    fn operation_deadline(&self, duration: Duration) -> Instant {
        (Instant::now() + duration).min(self.deadline)
    }
    fn check(&mut self, deadline: Instant, bytes: usize, now: Instant) -> Result<()> {
        remaining(deadline.min(self.deadline), now)?;
        self.budget.charge(bytes, now)
    }
    fn write_all(&mut self, bytes: &[u8], deadline: Instant) -> Result<()> {
        self.write_clock(bytes, deadline, Instant::now)
    }
    fn write_clock(
        &mut self,
        mut bytes: &[u8],
        deadline: Instant,
        mut now: impl FnMut() -> Instant,
    ) -> Result<()> {
        while !bytes.is_empty() {
            let start = now();
            self.check(deadline, 0, start)?;
            let stream = self.stream.as_mut().ok_or(Failure::Closed)?;
            stream
                .set_write_timeout(Some(remaining(deadline.min(self.deadline), start)?))
                .map_err(io_failure)?;
            match stream.write(bytes) {
                Ok(0) => return Err(Failure::Closed),
                Ok(count) => {
                    self.check(deadline, count, now())?;
                    bytes = &bytes[count..];
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(io_failure(e)),
            }
        }
        self.check(deadline, 0, now())
    }
    fn read_exact(&mut self, bytes: &mut [u8], deadline: Instant) -> Result<()> {
        self.read_clock(bytes, deadline, Instant::now)
    }
    fn read_clock(
        &mut self,
        mut bytes: &mut [u8],
        deadline: Instant,
        mut now: impl FnMut() -> Instant,
    ) -> Result<()> {
        while !bytes.is_empty() {
            let start = now();
            self.check(deadline, 0, start)?;
            let stream = self.stream.as_mut().ok_or(Failure::Closed)?;
            stream
                .set_read_timeout(Some(remaining(deadline.min(self.deadline), start)?))
                .map_err(io_failure)?;
            match stream.read(bytes) {
                Ok(0) => return Err(Failure::Truncated),
                Ok(count) => {
                    self.check(deadline, count, now())?;
                    bytes = &mut bytes[count..];
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(io_failure(e)),
            }
        }
        self.check(deadline, 0, now())
    }
    fn record(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        // Read exactly one bounded TLS record, so a completed handshake never
        // consumes a following application record before peer pin verification.
        // Rustls remains responsible for all record and cryptographic validation.
        let mut header = [0; 5];
        self.read_exact(&mut header, deadline)?;
        let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if size == 0 || size > MAX_RECORD {
            return Err(Failure::Limit);
        }
        let mut wire = vec![0; 5 + size];
        wire[..5].copy_from_slice(&header);
        self.read_exact(&mut wire[5..], deadline)?;
        self.check(deadline, 0, Instant::now())?;
        Ok(wire)
    }
    fn stop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}
impl Drop for SocketIo {
    fn drop(&mut self) {
        self.stop();
    }
}
struct SocketConnection {
    io: SocketIo,
    channel: Channel,
}
impl SocketConnection {
    fn establish(
        stream: UnixStream,
        mut tls: Connection,
        enrollment: &Enrollment,
        client: bool,
    ) -> Result<Self> {
        let mut io = SocketIo::new(stream)?;
        let deadline = io.operation_deadline(HANDSHAKE_TIME);
        let mut budget = Budget::new(HANDSHAKE_TIME);
        tls.set_buffer_limit(Some(MAX_BODY + HEADER + 4096));
        loop {
            io.check(deadline, 0, Instant::now())?;
            let wire = drain_tls(&mut tls, &mut budget)?;
            io.write_all(&wire, deadline)?;
            if !tls.is_handshaking() && !tls.wants_write() {
                break;
            }
            let wire = io.record(deadline)?;
            feed_handshake(&mut tls, &wire, &mut budget)?;
        }
        let channel = Channel::authenticate(tls, enrollment, client)?;
        io.check(deadline, 0, Instant::now())?;
        Ok(Self { io, channel })
    }
    fn stop(&mut self) {
        self.channel.close();
        self.io.stop();
    }
    fn send(&mut self, body: &[u8], deadline: Instant) -> Result<()> {
        self.io.check(deadline, 0, Instant::now())?;
        let wire = self.channel.send(body)?;
        self.io.write_all(&wire, deadline)
    }
    fn receive(&mut self, deadline: Instant) -> Result<Option<PrivateBytes>> {
        loop {
            let wire = self.io.record(deadline)?;
            let (mut bodies, closed) =
                self.channel
                    .receive_records_at(&wire, Instant::now(), true)?;
            self.io.check(deadline, 0, Instant::now())?;
            if closed {
                return Ok(None);
            }
            if !bodies.is_empty() {
                if bodies.len() != 1 || self.channel.decoder.pending() {
                    return Err(Failure::Protocol);
                }
                return Ok(bodies.pop());
            }
            // Key updates may generate control records; they share this read's
            // fixed deadline and lifetime/work/byte budget.
            let tls = self.channel.tls.as_mut().ok_or(Failure::Closed)?;
            let wire = drain_tls(tls, &mut self.channel.budget)?;
            self.io.write_all(&wire, deadline)?;
        }
    }
    fn close(&mut self) -> Result<()> {
        let result = (|| {
            let deadline = self.io.operation_deadline(FRAME_TIME);
            let tls = self.channel.tls.as_mut().ok_or(Failure::Closed)?;
            tls.send_close_notify();
            let wire = drain_tls(tls, &mut self.channel.budget)?;
            self.io.write_all(&wire, deadline)
        })();
        self.stop();
        result
    }
}
impl Drop for SocketConnection {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(in crate::vault) struct SocketClient {
    connection: SocketConnection,
}
impl SocketClient {
    pub(in crate::vault) fn exchange(
        &mut self,
        body: &[u8],
    ) -> std::result::Result<PrivateBytes, ErrorCode> {
        let result = (|| {
            // One deadline covers request writing, waiting, and the last response
            // byte. A timeout after dispatch never repeats the request.
            let deadline = self.connection.io.operation_deadline(FRAME_TIME);
            self.connection.send(body, deadline)?;
            self.connection.receive(deadline)?.ok_or(Failure::Closed)
        })();
        if result.is_err() {
            self.connection.stop();
        }
        result.map_err(unavailable)
    }
    pub(in crate::vault) fn close(&mut self) -> std::result::Result<(), ErrorCode> {
        self.connection.close().map_err(unavailable)
    }
}

pub(in crate::vault) struct SocketServer {
    connection: SocketConnection,
    endpoint: Option<Endpoint>,
    #[cfg(test)]
    discard_response: bool,
}
impl SocketServer {
    pub(in crate::vault) fn serve_one(&mut self) -> std::result::Result<bool, ErrorCode> {
        let result = (|| {
            if self.endpoint.is_none() {
                return Err(Failure::Closed);
            }
            let deadline = self.connection.io.operation_deadline(FRAME_TIME);
            let Some(body) = self.connection.receive(deadline)? else {
                self.stop();
                return Ok(false);
            };
            self.connection.io.check(deadline, 0, Instant::now())?;
            let endpoint = self.endpoint.as_ref().ok_or(Failure::Closed)?;
            let response = bounded_json(&endpoint.handle(&body.0))?;
            #[cfg(test)]
            if self.discard_response {
                return Err(Failure::Closed);
            }
            // The completed read's deadline does not become a fresh receive
            // allowance. The response has its own absolute write bound, capped
            // by the connection lifetime; dispatch is never automatically retried.
            let deadline = self.connection.io.operation_deadline(FRAME_TIME);
            self.connection.send(&response.0, deadline)?;
            Ok(true)
        })();
        if result.is_err() {
            self.stop();
        }
        result.map_err(unavailable)
    }
    fn stop(&mut self) {
        self.endpoint = None;
        self.connection.stop();
    }
    #[cfg(test)]
    fn close(&mut self) -> std::result::Result<(), ErrorCode> {
        self.endpoint = None;
        self.connection.close().map_err(unavailable)
    }
    #[cfg(test)]
    pub(in crate::vault) fn discard_next_response_for_test(&mut self) {
        self.discard_response = true;
    }
}
impl Drop for SocketServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests;
