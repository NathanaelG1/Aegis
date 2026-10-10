//! TLS 1.3 mutual authentication and exporter-bound framing, with ephemeral fixtures.
//!
//! The public surface accepts no keys, certificates, addresses or payloads. There
//! is no listener or live-secret entry. The standalone drill keeps both peers in
//! one process; the crate-private fixture driver uses inherited sockets between
//! disposable processes. Neither establishes independent custody or human presence.
//!
//! ```compile_fail
//! use aegis::vault::tls::Channel;
//! ```
//! ```compile_fail
//! use aegis::vault::tls::Enrollment;
//! ```
pub(super) mod socket;

use super::{
    auth::Actors,
    crypto::PrivateBytes,
    protocol::{self, AdminEndpoint, AgentEndpoint, ProtocolResponse, SyntheticProtocol},
    store::Kit,
};
use crate::{
    ErrorCode, Lifecycle, ManualClock, OperationIntent, OperationPrepareInput, ProfileId, RequestId,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
    ClientConfig, ClientConnection, Connection, HandshakeKind, ProtocolVersion, RootCertStore,
    ServerConfig, ServerConnection,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::{self, Cursor, Read, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const SERVER_NAME: &str = "broker.aegis.invalid";
const EXPORT_LABEL: &[u8] = b"EXPORTER-Aegis-fixture-channel-v1";
const HEADER: usize = 52;
const MAX_BODY: usize = protocol::MAX_FRAME_BYTES;
const MAX_FRAMES: u64 = 32;
const MAX_FLIGHT: usize = 64 * 1024;
const MAX_WIRE: usize = 256 * 1024;
const MAX_STEPS: usize = 4096;
const HANDSHAKE_TIME: Duration = Duration::from_secs(2);
const CHANNEL_TIME: Duration = Duration::from_secs(30);
const FRAME_TIME: Duration = Duration::from_secs(1);
const CANARY: &[u8] = b"aegis-disposable-tls-canary-not-a-real-secret";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Configuration,
    Tls,
    Peer,
    Protocol,
    Closed,
    Limit,
    Deadline,
    Binding,
    Sequence,
    Truncated,
}
type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum Role {
    Agent = 1,
    Admin = 2,
    Recipient = 3,
}
impl Role {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::Agent => b"aegis-agent/1",
            Self::Admin => b"aegis-admin/1",
            Self::Recipient => b"aegis-recipient/1",
        }
    }
    fn peer(self) -> u8 {
        self as u8
    }
}
// rcgen exposes an explicit zeroize operation, not a zeroizing Drop.
struct FixtureKey(KeyPair);
impl Drop for FixtureKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl rcgen::PublicKeyData for FixtureKey {
    fn der_bytes(&self) -> &[u8] {
        self.0.der_bytes()
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.0.algorithm()
    }
}
impl rcgen::SigningKey for FixtureKey {
    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        self.0.sign(msg)
    }
}
struct Identity {
    cert: CertificateDer<'static>,
    key: Zeroizing<PrivateKeyDer<'static>>,
}
impl Identity {
    fn issue(ca: &CertifiedIssuer<'_, FixtureKey>, name: &str, server: bool) -> Result<Self> {
        let key = FixtureKey(KeyPair::generate().map_err(|_| Failure::Configuration)?);
        let mut params =
            CertificateParams::new(vec![name.into()]).map_err(|_| Failure::Configuration)?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![if server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        let cert = params
            .signed_by(&key, ca)
            .map_err(|_| Failure::Configuration)?;
        Ok(Self {
            cert: cert.der().clone(),
            key: Zeroizing::new(PrivatePkcs8KeyDer::from(key.0.serialize_der()).into()),
        })
    }
}
struct Fixtures {
    ca: CertifiedIssuer<'static, FixtureKey>,
    server: Identity,
    agent: Identity,
    admin: Identity,
    recipient: Identity,
}
impl Fixtures {
    fn new() -> Result<Self> {
        let mut params = CertificateParams::new(vec!["ca.aegis.invalid".into()])
            .map_err(|_| Failure::Configuration)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(
            params,
            FixtureKey(KeyPair::generate().map_err(|_| Failure::Configuration)?),
        )
        .map_err(|_| Failure::Configuration)?;
        Ok(Self {
            server: Identity::issue(&ca, SERVER_NAME, true)?,
            agent: Identity::issue(&ca, "agent.aegis.invalid", false)?,
            admin: Identity::issue(&ca, "admin.aegis.invalid", false)?,
            recipient: Identity::issue(&ca, "recipient.aegis.invalid", false)?,
            ca,
        })
    }
    fn identity(&self, role: Role) -> &Identity {
        match role {
            Role::Agent => &self.agent,
            Role::Admin => &self.admin,
            Role::Recipient => &self.recipient,
        }
    }
    fn enrollment(&self, role: Role) -> Enrollment {
        Enrollment {
            role,
            client_pin: self.identity(role).cert.clone(),
            server_pin: self.server.cert.clone(),
        }
    }
    fn pair(&self, role: Role) -> Result<(Channel, Channel)> {
        let enrollment = self.enrollment(role);
        let (client, server) =
            configs(self.ca.der(), &self.server, Some(self.identity(role)), role)?;
        establish(client, server, SERVER_NAME, &enrollment)
    }
}
// Protected setup, not certificate subject strings or request fields, owns roles.
// Exact leaf DER pinning is additional to standard path/EKU/time/name validation.
#[derive(Clone)]
struct Enrollment {
    role: Role,
    client_pin: CertificateDer<'static>,
    server_pin: CertificateDer<'static>,
}
fn configs(
    root: &CertificateDer<'static>,
    server: &Identity,
    client: Option<&Identity>,
    role: Role,
) -> Result<(Arc<ClientConfig>, Arc<ServerConfig>)> {
    Ok((
        client_config(root, client, role)?,
        server_config(root, server, role)?,
    ))
}
fn roots(root: &CertificateDer<'static>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(root.clone())
        .map_err(|_| Failure::Configuration)?;
    Ok(roots)
}
fn client_config(
    root: &CertificateDer<'static>,
    client: Option<&Identity>,
    role: Role,
) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Failure::Configuration)?
        .with_root_certificates(roots(root)?);
    let mut config = match client {
        Some(id) => builder
            .with_client_auth_cert(vec![id.cert.clone()], id.key.clone_key())
            .map_err(|_| Failure::Configuration)?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![role.alpn().to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.max_fragment_size = Some(4096);
    Ok(Arc::new(config))
}
fn server_config(
    root: &CertificateDer<'static>,
    server: &Identity,
    role: Role,
) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(root)?), provider.clone())
            .build()
            .map_err(|_| Failure::Configuration)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Failure::Configuration)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server.cert.clone()], server.key.clone_key())
        .map_err(|_| Failure::Configuration)?;
    config.alpn_protocols = vec![role.alpn().to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.max_fragment_size = Some(4096);
    // Standard verifiers only: no system roots, proxies, DNS, or key logging.
    Ok(Arc::new(config))
}

struct Budget {
    start: Instant,
    duration: Duration,
    bytes: usize,
    steps: usize,
}
impl Budget {
    fn new(duration: Duration) -> Self {
        Self {
            start: Instant::now(),
            duration,
            bytes: 0,
            steps: 0,
        }
    }
    fn charge(&mut self, bytes: usize, now: Instant) -> Result<()> {
        if now
            .checked_duration_since(self.start)
            .ok_or(Failure::Deadline)?
            >= self.duration
        {
            return Err(Failure::Deadline);
        }
        self.bytes = self.bytes.checked_add(bytes).ok_or(Failure::Limit)?;
        self.steps = self.steps.checked_add(1).ok_or(Failure::Limit)?;
        if self.bytes > MAX_WIRE || self.steps > MAX_STEPS {
            return Err(Failure::Limit);
        }
        Ok(())
    }
}
struct Flight(Vec<u8>);
impl Write for Flight {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FLIGHT - self.0.len() {
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn drain_tls(tls: &mut Connection, budget: &mut Budget) -> Result<Vec<u8>> {
    let mut flight = Flight(Vec::new());
    while tls.wants_write() {
        budget.charge(0, Instant::now())?;
        let count = tls.write_tls(&mut flight).map_err(|_| Failure::Tls)?;
        if count == 0 {
            return Err(Failure::Closed);
        }
        budget.charge(count, Instant::now())?;
    }
    Ok(flight.0)
}
fn feed_handshake(tls: &mut Connection, wire: &[u8], budget: &mut Budget) -> Result<()> {
    // Fragment the actual TLS record stream; there is no shortcut into plaintext.
    for chunk in wire.chunks(2048) {
        let mut input = Cursor::new(chunk);
        while input.position() < chunk.len() as u64 {
            budget.charge(chunk.len(), Instant::now())?;
            if tls.read_tls(&mut input).map_err(|_| Failure::Tls)? == 0 {
                return Err(Failure::Closed);
            }
            let state = tls.process_new_packets().map_err(|_| Failure::Tls)?;
            if state.plaintext_bytes_to_read() != 0 || state.peer_has_closed() {
                return Err(Failure::Protocol);
            }
        }
    }
    Ok(())
}
fn establish(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
    enrollment: &Enrollment,
) -> Result<(Channel, Channel)> {
    let name = ServerName::try_from(name.to_owned()).map_err(|_| Failure::Configuration)?;
    let mut client = Connection::Client(
        ClientConnection::new(client, name).map_err(|_| Failure::Configuration)?,
    );
    let mut server =
        Connection::Server(ServerConnection::new(server).map_err(|_| Failure::Configuration)?);
    client.set_buffer_limit(Some(MAX_BODY + HEADER + 4096));
    server.set_buffer_limit(Some(MAX_BODY + HEADER + 4096));
    let mut budget = Budget::new(HANDSHAKE_TIME);
    loop {
        budget.charge(0, Instant::now())?;
        let to_server = drain_tls(&mut client, &mut budget)?;
        feed_handshake(&mut server, &to_server, &mut budget)?;
        let to_client = drain_tls(&mut server, &mut budget)?;
        feed_handshake(&mut client, &to_client, &mut budget)?;
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            break;
        }
        if to_server.is_empty() && to_client.is_empty() {
            return Err(Failure::Closed);
        }
    }
    budget.charge(0, Instant::now())?;
    Ok((
        Channel::authenticate(client, enrollment, true)?,
        Channel::authenticate(server, enrollment, false)?,
    ))
}
#[derive(Clone, Copy)]
struct Binding {
    role: Role,
    exporter: [u8; 32],
}
impl Binding {
    fn header(self, direction: u8, sequence: u64, size: usize) -> [u8; HEADER] {
        let mut h = [0; HEADER];
        h[..4].copy_from_slice(b"ATL1");
        h[4] = self.role as u8;
        h[5] = self.role.peer();
        h[6] = direction;
        h[8..40].copy_from_slice(&self.exporter);
        h[40..48].copy_from_slice(&sequence.to_be_bytes());
        h[48..].copy_from_slice(&(size as u32).to_be_bytes());
        h
    }
}
struct Decoder {
    binding: Binding,
    direction: u8,
    header: [u8; HEADER],
    used: usize,
    body: PrivateBytes,
    size: Option<usize>,
    sequence: u64,
    started: Option<Instant>,
}
impl Decoder {
    fn new(binding: Binding, direction: u8) -> Self {
        Self {
            binding,
            direction,
            header: [0; HEADER],
            used: 0,
            body: PrivateBytes(Vec::new()),
            size: None,
            sequence: 0,
            started: None,
        }
    }
    fn check_time(&self, now: Instant) -> Result<()> {
        if let Some(start) = self.started {
            if now.checked_duration_since(start).ok_or(Failure::Deadline)? >= FRAME_TIME {
                return Err(Failure::Deadline);
            }
        }
        Ok(())
    }
    fn receive(
        &mut self,
        mut input: &[u8],
        now: Instant,
        output: &mut Vec<PrivateBytes>,
    ) -> Result<()> {
        self.check_time(now)?;
        while !input.is_empty() {
            if self.sequence >= MAX_FRAMES {
                return Err(Failure::Limit);
            }
            self.started.get_or_insert(now);
            let take = (HEADER - self.used).min(input.len());
            self.header[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            input = &input[take..];
            if self.used < HEADER {
                return Ok(());
            }
            if self.size.is_none() {
                let h = &self.header;
                if h[..4] != *b"ATL1" || h[7] != 0 {
                    return Err(Failure::Protocol);
                }
                if h[4] != self.binding.role as u8
                    || h[5] != self.binding.role.peer()
                    || h[6] != self.direction
                    || h[8..40] != self.binding.exporter
                {
                    return Err(Failure::Binding);
                }
                let seq = u64::from_be_bytes(h[40..48].try_into().map_err(|_| Failure::Protocol)?);
                if seq != self.sequence {
                    return Err(Failure::Sequence);
                }
                let size =
                    u32::from_be_bytes(h[48..].try_into().map_err(|_| Failure::Protocol)?) as usize;
                if size == 0 || size > MAX_BODY {
                    return Err(Failure::Limit);
                }
                self.body = PrivateBytes(Vec::with_capacity(size));
                self.size = Some(size);
            }
            let size = self.size.ok_or(Failure::Protocol)?;
            let take = (size - self.body.0.len()).min(input.len());
            self.body.0.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.body.0.len() == size {
                output.push(PrivateBytes(std::mem::take(&mut self.body.0)));
                self.sequence += 1;
                self.used = 0;
                self.size = None;
                self.started = None;
                self.header.zeroize();
            }
        }
        Ok(())
    }
    fn clear(&mut self) {
        self.header.zeroize();
        self.body.0.zeroize();
        self.binding.exporter.zeroize();
    }
    fn pending(&self) -> bool {
        self.used != 0 || self.size.is_some()
    }
}
impl Drop for Decoder {
    fn drop(&mut self) {
        self.clear();
    }
}
struct Channel {
    tls: Option<Connection>,
    binding: Binding,
    outgoing: u8,
    sequence: u64,
    decoder: Decoder,
    budget: Budget,
    receive_started: Option<Instant>,
}
impl Channel {
    fn authenticate(tls: Connection, enrollment: &Enrollment, client: bool) -> Result<Self> {
        if tls.is_handshaking()
            || tls.protocol_version() != Some(ProtocolVersion::TLSv1_3)
            || tls.handshake_kind() != Some(HandshakeKind::Full)
            || tls.alpn_protocol() != Some(enrollment.role.alpn())
        {
            return Err(Failure::Protocol);
        }
        let pin = if client {
            &enrollment.server_pin
        } else {
            &enrollment.client_pin
        };
        let certs = tls.peer_certificates().ok_or(Failure::Peer)?;
        if certs.len() != 1 || certs[0].len() > 4096 || certs[0] != *pin {
            return Err(Failure::Peer);
        }
        let exporter = tls
            .export_keying_material([0; 32], EXPORT_LABEL, Some(enrollment.role.alpn()))
            .map_err(|_| Failure::Tls)?;
        let binding = Binding {
            role: enrollment.role,
            exporter,
        };
        let outgoing = if client { 1 } else { 2 };
        Ok(Self {
            tls: Some(tls),
            binding,
            outgoing,
            sequence: 0,
            decoder: Decoder::new(binding, 3 - outgoing),
            budget: Budget::new(CHANNEL_TIME),
            receive_started: None,
        })
    }
    fn close(&mut self) {
        self.tls = None;
        self.binding.exporter.zeroize();
        self.decoder.clear();
    }
    fn send(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let result = (|| {
            let tls = self.tls.as_mut().ok_or(Failure::Closed)?;
            self.budget.charge(0, Instant::now())?;
            if body.is_empty() || body.len() > MAX_BODY || self.sequence >= MAX_FRAMES {
                return Err(Failure::Limit);
            }
            let header = Zeroizing::new(self.binding.header(
                self.outgoing,
                self.sequence,
                body.len(),
            ));
            tls.writer()
                .write_all(header.as_ref())
                .map_err(|_| Failure::Tls)?;
            tls.writer().write_all(body).map_err(|_| Failure::Tls)?;
            let wire = drain_tls(tls, &mut self.budget)?;
            self.sequence += 1;
            Ok(wire)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn receive(&mut self, wire: &[u8]) -> Result<Vec<PrivateBytes>> {
        self.receive_at(wire, Instant::now())
    }
    fn receive_at(&mut self, wire: &[u8], now: Instant) -> Result<Vec<PrivateBytes>> {
        self.receive_records_at(wire, now, false)
            .map(|(bodies, _)| bodies)
    }
    fn receive_records_at(
        &mut self,
        wire: &[u8],
        now: Instant,
        allow_clean_close: bool,
    ) -> Result<(Vec<PrivateBytes>, bool)> {
        let result = (|| {
            let tls = self.tls.as_mut().ok_or(Failure::Closed)?;
            self.budget.charge(wire.len(), now)?;
            self.decoder.check_time(now)?;
            if !wire.is_empty() {
                self.receive_started.get_or_insert(now);
            }
            if let Some(start) = self.receive_started {
                if now.checked_duration_since(start).ok_or(Failure::Deadline)? >= FRAME_TIME {
                    return Err(Failure::Deadline);
                }
            }
            if wire.len() > MAX_FLIGHT {
                return Err(Failure::Limit);
            }
            let mut output = Vec::new();
            let mut input = Cursor::new(wire);
            let mut clear = Zeroizing::new([0; 1024]);
            while input.position() < wire.len() as u64 {
                self.budget.charge(0, now)?;
                if tls.read_tls(&mut input).map_err(|_| Failure::Tls)? == 0 {
                    return Err(Failure::Truncated);
                }
                let state = tls.process_new_packets().map_err(|_| Failure::Tls)?;
                if state.peer_has_closed() {
                    if allow_clean_close
                        && state.plaintext_bytes_to_read() == 0
                        && !self.decoder.pending()
                        && output.is_empty()
                        && input.position() == wire.len() as u64
                    {
                        self.budget.charge(0, Instant::now())?;
                        return Ok((output, true));
                    }
                    return Err(Failure::Closed);
                }
                loop {
                    self.budget.charge(0, now)?;
                    match tls.reader().read(clear.as_mut()) {
                        Ok(0) => return Err(Failure::Closed),
                        Ok(n) => {
                            self.decoder.receive(&clear[..n], now, &mut output)?;
                            clear.zeroize();
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => return Err(Failure::Tls),
                    }
                }
            }
            self.budget.charge(0, Instant::now())?;
            if !output.is_empty() && !self.decoder.pending() {
                self.receive_started = None;
            }
            Ok((output, false))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn eof(&mut self) -> Result<()> {
        self.close();
        Err(Failure::Truncated)
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.close();
    }
}

/// Safe evidence from actual TLS handshakes and encrypted in-memory record IO.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyntheticTlsReport {
    pub synthetic_only: bool,
    pub authenticated_role_channels: usize,
    pub tls13_mutual_authentication_verified: bool,
    pub encrypted_roundtrip_verified: bool,
    pub wrong_ca_denied: bool,
    pub wrong_name_denied: bool,
    pub missing_client_certificate_denied: bool,
    pub wrong_peer_denied: bool,
    pub wrong_role_denied: bool,
    pub wrong_alpn_denied: bool,
    pub application_replay_denied: bool,
    pub cross_channel_frame_denied: bool,
    pub ciphertext_tampering_denied: bool,
    pub protocol_delivery_verified: bool,
    pub unauthenticated_agent_denied: bool,
    pub unauthenticated_admin_denied: bool,
    pub wrong_role_proof_denied: bool,
    pub agent_admin_method_denied: bool,
    pub completed_deliveries: usize,
    pub consumed_uses: usize,
    pub recipient_generation: u64,
    pub revoked: bool,
    pub agent_transcript_contains_canary: bool,
    pub independent_key_custody_verified: bool,
    pub independent_human_presence_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}
/// Creates only new fixed-canary fixture paths and ephemeral TLS identities,
/// performs a reviewed delivery through mutually authenticated agent/admin channels,
/// then revokes. No socket, caller-supplied secret, certificate or route is accepted.
pub fn run_synthetic_tls_drill(
    root: &Path,
    kit: &Path,
    recipient: &Path,
) -> std::result::Result<SyntheticTlsReport, ErrorCode> {
    let mut report = drill().map_err(|_| ErrorCode::BrokerUnavailable)?;
    protocol_drill(root, kit, recipient, &mut report)?;
    Ok(report)
}
fn drill() -> Result<SyntheticTlsReport> {
    let fixtures = Fixtures::new()?;
    for role in [Role::Agent, Role::Admin, Role::Recipient] {
        let (mut client, mut server) = fixtures.pair(role)?;
        if client.binding.exporter != server.binding.exporter {
            return Err(Failure::Binding);
        }
        let wire = client.send(CANARY)?;
        if wire.windows(CANARY.len()).any(|w| w == CANARY) {
            return Err(Failure::Tls);
        }
        let bodies = server.receive(&wire)?;
        if bodies.len() != 1 || bodies[0].0 != CANARY {
            return Err(Failure::Protocol);
        }
        let reply = server.send(b"dummy-accepted")?;
        let bodies = client.receive(&reply)?;
        if bodies.len() != 1 || bodies[0].0 != b"dummy-accepted" {
            return Err(Failure::Protocol);
        }
    }
    let enrollment = fixtures.enrollment(Role::Agent);
    let foreign = Fixtures::new()?;
    let (c, s) = configs(
        foreign.ca.der(),
        &fixtures.server,
        Some(&fixtures.agent),
        Role::Agent,
    )?;
    let wrong_ca_denied = establish(c, s, SERVER_NAME, &enrollment).is_err();
    let (c, s) = configs(
        fixtures.ca.der(),
        &fixtures.server,
        Some(&fixtures.agent),
        Role::Agent,
    )?;
    let wrong_name_denied = establish(c, s, "wrong.aegis.invalid", &enrollment).is_err();
    let (c, s) = configs(fixtures.ca.der(), &fixtures.server, None, Role::Agent)?;
    let missing_client_certificate_denied = establish(c, s, SERVER_NAME, &enrollment).is_err();
    let stranger = Identity::issue(&fixtures.ca, "stranger.aegis.invalid", false)?;
    let (c, s) = configs(
        fixtures.ca.der(),
        &fixtures.server,
        Some(&stranger),
        Role::Agent,
    )?;
    let wrong_peer_denied = matches!(
        establish(c, s, SERVER_NAME, &enrollment),
        Err(Failure::Peer)
    );
    let (c, s) = configs(
        fixtures.ca.der(),
        &fixtures.server,
        Some(&fixtures.admin),
        Role::Agent,
    )?;
    let wrong_role_denied = matches!(
        establish(c, s, SERVER_NAME, &enrollment),
        Err(Failure::Peer)
    );
    let (mut c, s) = configs(
        fixtures.ca.der(),
        &fixtures.server,
        Some(&fixtures.agent),
        Role::Agent,
    )?;
    Arc::get_mut(&mut c)
        .ok_or(Failure::Configuration)?
        .alpn_protocols = vec![b"wrong/1".to_vec()];
    let wrong_alpn_denied = establish(c, s, SERVER_NAME, &enrollment).is_err();
    let (mut c, mut s) = fixtures.pair(Role::Agent)?;
    let mut replay = Zeroizing::new(c.binding.header(1, 0, CANARY.len()).to_vec());
    replay.extend_from_slice(CANARY);
    let wire = c.send(CANARY)?;
    s.receive(&wire)?;
    c.tls
        .as_mut()
        .ok_or(Failure::Closed)?
        .writer()
        .write_all(&replay)
        .map_err(|_| Failure::Tls)?;
    let wire = drain_tls(c.tls.as_mut().ok_or(Failure::Closed)?, &mut c.budget)?;
    let application_replay_denied = matches!(s.receive(&wire), Err(Failure::Sequence));
    let (mut other_c, mut other_s) = fixtures.pair(Role::Agent)?;
    other_c
        .tls
        .as_mut()
        .ok_or(Failure::Closed)?
        .writer()
        .write_all(&replay)
        .map_err(|_| Failure::Tls)?;
    let wire = drain_tls(
        other_c.tls.as_mut().ok_or(Failure::Closed)?,
        &mut other_c.budget,
    )?;
    let cross_channel_frame_denied = matches!(other_s.receive(&wire), Err(Failure::Binding));
    let (mut c, mut s) = fixtures.pair(Role::Recipient)?;
    let mut wire = c.send(CANARY)?;
    *wire.last_mut().ok_or(Failure::Tls)? ^= 1;
    let ciphertext_tampering_denied = matches!(s.receive(&wire), Err(Failure::Tls));
    // A truncated peer must leave no reusable authenticated channel.
    if !matches!(c.eof(), Err(Failure::Truncated))
        || !matches!(c.send(CANARY), Err(Failure::Closed))
    {
        return Err(Failure::Closed);
    }
    if ![
        wrong_ca_denied,
        wrong_name_denied,
        missing_client_certificate_denied,
        wrong_peer_denied,
        wrong_role_denied,
        wrong_alpn_denied,
        application_replay_denied,
        cross_channel_frame_denied,
        ciphertext_tampering_denied,
    ]
    .into_iter()
    .all(|v| v)
    {
        return Err(Failure::Protocol);
    }
    Ok(SyntheticTlsReport {
        synthetic_only: true,
        authenticated_role_channels: 3,
        tls13_mutual_authentication_verified: true,
        encrypted_roundtrip_verified: true,
        wrong_ca_denied,
        wrong_name_denied,
        missing_client_certificate_denied,
        wrong_peer_denied,
        wrong_role_denied,
        wrong_alpn_denied,
        application_replay_denied,
        cross_channel_frame_denied,
        ciphertext_tampering_denied,
        protocol_delivery_verified: false,
        unauthenticated_agent_denied: false,
        unauthenticated_admin_denied: false,
        wrong_role_proof_denied: false,
        agent_admin_method_denied: false,
        completed_deliveries: 0,
        consumed_uses: 0,
        recipient_generation: 0,
        revoked: false,
        agent_transcript_contains_canary: false,
        independent_key_custody_verified: false,
        independent_human_presence_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

// This owning dispatcher is private. Its endpoint is selected only after the
// enrolled leaf certificate has authenticated; no request field is a selector.
enum Endpoint {
    Agent(AgentEndpoint),
    Admin(AdminEndpoint),
}
impl Endpoint {
    fn role(&self) -> Role {
        match self {
            Self::Agent(_) => Role::Agent,
            Self::Admin(_) => Role::Admin,
        }
    }
    fn handle(&self, body: &[u8]) -> ProtocolResponse {
        match self {
            Self::Agent(e) => e.handle(body),
            Self::Admin(e) => e.handle(body),
        }
    }
}
struct EndpointChannel {
    client: Channel,
    server: Channel,
    endpoint: Option<Endpoint>,
    transcript_contains_canary: bool,
}
impl EndpointChannel {
    fn new(fixtures: &Fixtures, endpoint: Endpoint) -> Result<Self> {
        let (client, server) = fixtures.pair(endpoint.role())?;
        if server.binding.role != endpoint.role() || server.outgoing != 2 {
            return Err(Failure::Peer);
        }
        Ok(Self {
            client,
            server,
            endpoint: Some(endpoint),
            transcript_contains_canary: false,
        })
    }
    fn close(&mut self) {
        self.endpoint = None;
        self.client.close();
        self.server.close();
    }
    fn respond(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        let result = (|| {
            let endpoint = self.endpoint.as_ref().ok_or(Failure::Closed)?;
            let body = receive_message(&mut self.server, wire)?;
            let response = bounded_json(&endpoint.handle(&body.0))?;
            if endpoint.role() == Role::Agent {
                self.transcript_contains_canary |=
                    [super::store::CANARY_ONE, super::store::CANARY_TWO]
                        .iter()
                        .any(|s| response.0.windows(s.len()).any(|w| w == s.as_bytes()));
            }
            self.server.send(&response.0)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn exchange(&mut self, body: &[u8]) -> Result<PrivateBytes> {
        let result = (|| {
            let wire = self.client.send(body)?;
            let response = self.respond(&wire)?;
            receive_message(&mut self.client, &response)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl Drop for EndpointChannel {
    fn drop(&mut self) {
        self.close();
    }
}

fn receive_message(channel: &mut Channel, wire: &[u8]) -> Result<PrivateBytes> {
    // One request/response at a time; no pipelined dispatch or hidden response queue.
    let mut budget = Budget::new(FRAME_TIME);
    let mut output = None;
    for fragment in wire.chunks(257) {
        budget.charge(fragment.len(), Instant::now())?;
        for body in channel.receive(fragment)? {
            if output.replace(body).is_some() {
                return Err(Failure::Protocol);
            }
        }
    }
    budget.charge(0, Instant::now())?;
    if channel.decoder.pending() {
        return Err(Failure::Truncated);
    }
    output.ok_or(Failure::Truncated)
}

struct BoundedBody(PrivateBytes);
impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BODY - self.0 .0.len() {
            return Err(io::Error::other("synthetic TLS frame limit"));
        }
        self.0 .0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_json(value: &impl Serialize) -> Result<PrivateBytes> {
    let mut output = BoundedBody(PrivateBytes(Vec::new()));
    serde_json::to_writer(&mut output, value).map_err(|_| Failure::Limit)?;
    Ok(output.0)
}

#[derive(Serialize)]
struct Action<'a, T> {
    method: &'a str,
    params: T,
}
#[derive(Serialize)]
struct Request<'a, T> {
    protocol: &'static str,
    version: u32,
    action: Action<'a, T>,
}
#[derive(Serialize)]
struct Proof<'a> {
    assertion: &'a str,
}
#[derive(Serialize)]
struct Handle {
    prepared_request_id: u64,
}
#[derive(Serialize)]
struct Empty {}
fn request(method: &str, params: impl Serialize) -> std::result::Result<PrivateBytes, ErrorCode> {
    bounded_json(&Request {
        protocol: protocol::PROTOCOL,
        version: protocol::VERSION,
        action: Action { method, params },
    })
    .map_err(|_| ErrorCode::BrokerUnavailable)
}

fn exchange(
    connection: &mut EndpointChannel,
    method: &str,
    params: impl Serialize,
) -> std::result::Result<serde_json::Value, ErrorCode> {
    let request = request(method, params)?;
    let response = connection
        .exchange(&request.0)
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    serde_json::from_slice(&response.0).map_err(|_| ErrorCode::BrokerUnavailable)
}
fn value<T: DeserializeOwned>(
    reply: serde_json::Value,
    kind: &str,
) -> std::result::Result<T, ErrorCode> {
    if reply["error"].is_null() && reply["result"]["kind"] == kind {
        serde_json::from_value(reply["result"]["value"].clone())
            .map_err(|_| ErrorCode::BrokerUnavailable)
    } else {
        Err(ErrorCode::BrokerUnavailable)
    }
}
fn is_kind(reply: &serde_json::Value, kind: &str) -> bool {
    reply["error"].is_null() && reply["result"]["kind"] == kind
}
fn is_error(reply: &serde_json::Value, error: ErrorCode) -> bool {
    reply["result"].is_null()
        && matches!(serde_json::from_value::<ErrorCode>(reply["error"].clone()), Ok(found) if found == error)
}
fn sign(
    actors: &Actors,
    challenge: &protocol::ProofChallenge,
) -> std::result::Result<super::crypto::Signed, ErrorCode> {
    actors.sign(challenge)
}
fn proof(signed: &super::crypto::Signed) -> std::result::Result<Proof<'_>, ErrorCode> {
    Ok(Proof {
        assertion: std::str::from_utf8(signed.bytes()).map_err(|_| ErrorCode::BrokerUnavailable)?,
    })
}

fn protocol_drill(
    root: &Path,
    kit: &Path,
    recipient: &Path,
    report: &mut SyntheticTlsReport,
) -> std::result::Result<(), ErrorCode> {
    let protocol =
        SyntheticProtocol::create(root, kit, recipient, Arc::new(ManualClock::default()))?;
    let actors = Kit::open(kit)?;
    let fixtures = Fixtures::new().map_err(|_| ErrorCode::BrokerUnavailable)?;
    let mut agent = EndpointChannel::new(&fixtures, Endpoint::Agent(protocol.agent))
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    let mut admin = EndpointChannel::new(&fixtures, Endpoint::Admin(protocol.admin))
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    let unauthenticated_agent_denied = is_error(
        &exchange(&mut agent, "discover_operations", Empty {})?,
        ErrorCode::AuthenticationRequired,
    );
    let unauthenticated_admin_denied = is_error(
        &exchange(&mut admin, "revoke_challenge", Empty {})?,
        ErrorCode::AuthenticationRequired,
    );
    let challenge: protocol::ProofChallenge = value(
        exchange(&mut agent, "connect_challenge", Empty {})?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    let wrong_role_proof_denied = is_error(
        &exchange(&mut admin, "connect", proof(&signed)?)?,
        ErrorCode::AuthenticationRequired,
    );
    if !is_kind(
        &exchange(&mut agent, "connect", proof(&signed)?)?,
        "connected",
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let challenge = value(
        exchange(&mut admin, "connect_challenge", Empty {})?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    if !is_kind(
        &exchange(&mut admin, "connect", proof(&signed)?)?,
        "connected",
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let agent_admin_method_denied = is_error(
        &exchange(&mut agent, "revoke_challenge", Empty {})?,
        ErrorCode::InvalidRequest,
    );
    let prepared: crate::OperationRunView = value(
        exchange(
            &mut agent,
            "prepare_operation",
            OperationPrepareInput {
                request_id: RequestId::new("tls-canary-one")?,
                profile_id: ProfileId::new("vault-delivery")?,
                operation: OperationIntent::Delivery(super::DeliveryParameters::fixture(1)),
            },
        )?,
        "run",
    )?;
    let id = prepared.prepared_request_id;
    let awaiting: crate::OperationRunView = value(
        exchange(
            &mut agent,
            "request_approval",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "run",
    )?;
    if awaiting.state != Lifecycle::AwaitingApproval {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let expected: protocol::ReviewPlan = value(
        exchange(
            &mut admin,
            "inspect_review",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "review",
    )?;
    let challenge = value(
        exchange(&mut admin, "approval_challenge", &expected)?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    #[derive(Serialize)]
    struct Approval<'a> {
        expected: &'a protocol::ReviewPlan,
        proof: Proof<'a>,
    }
    let approved: crate::OperationRunView = value(
        exchange(
            &mut admin,
            "approve",
            Approval {
                expected: &expected,
                proof: proof(&signed)?,
            },
        )?,
        "run",
    )?;
    if approved.state != Lifecycle::Approved {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let challenge = value(
        exchange(
            &mut agent,
            "invocation_challenge",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    #[derive(Serialize)]
    struct Invocation<'a> {
        prepared_request_id: u64,
        proof: Proof<'a>,
    }
    let response = exchange(
        &mut agent,
        "invoke_approved",
        Invocation {
            prepared_request_id: id,
            proof: proof(&signed)?,
        },
    )?;
    let run: crate::OperationRunView = value(response, "run")?;
    if run.state != Lifecycle::Succeeded {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let challenge = value(
        exchange(&mut admin, "revoke_challenge", Empty {})?,
        "challenge",
    )?;
    let signed = sign(&actors.actors, &challenge)?;
    if !is_kind(&exchange(&mut admin, "revoke", proof(&signed)?)?, "revoked") {
        return Err(ErrorCode::BrokerUnavailable);
    }

    let agent_transcript_contains_canary = agent.transcript_contains_canary;
    drop((agent, admin, actors));
    let inspected = super::inspect_synthetic_vault(root, kit, recipient)?;
    if !(unauthenticated_agent_denied
        && unauthenticated_admin_denied
        && wrong_role_proof_denied
        && agent_admin_method_denied
        && inspected.consumed_uses == 1
        && inspected.recipient_generation == 1
        && inspected.revoked
        && !agent_transcript_contains_canary)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    report.protocol_delivery_verified = true;
    report.unauthenticated_agent_denied = unauthenticated_agent_denied;
    report.unauthenticated_admin_denied = unauthenticated_admin_denied;
    report.wrong_role_proof_denied = wrong_role_proof_denied;
    report.agent_admin_method_denied = agent_admin_method_denied;
    report.completed_deliveries = 1;
    report.consumed_uses = inspected.consumed_uses;
    report.recipient_generation = inspected.recipient_generation;
    report.revoked = inspected.revoked;
    report.agent_transcript_contains_canary = agent_transcript_contains_canary;
    Ok(())
}

// The composed fixture supplies its already-assembled broker and process-only
// recipient. There is no constructor here that can replace it with a local one.
struct ComposedChannels {
    agent: EndpointChannel,
    admin: EndpointChannel,
    agent_actor: super::custody::ActorRole,
    admin_actor: super::custody::ActorRole,
}
pub(super) struct ComposedRound {
    pub(super) run: crate::OperationRunView,
    pub(super) duplicate_reused: bool,
    pub(super) unauthenticated_agent_denied: bool,
    pub(super) unauthenticated_admin_denied: bool,
    pub(super) agent_transcript_contains_canary: bool,
}
impl ComposedChannels {
    fn new(
        protocol: SyntheticProtocol,
        custody: &Path,
        vault_id: &str,
    ) -> std::result::Result<Self, ErrorCode> {
        let fixtures = Fixtures::new().map_err(|_| ErrorCode::BrokerUnavailable)?;
        Ok(Self {
            agent: EndpointChannel::new(&fixtures, Endpoint::Agent(protocol.agent))
                .map_err(|_| ErrorCode::BrokerUnavailable)?,
            admin: EndpointChannel::new(&fixtures, Endpoint::Admin(protocol.admin))
                .map_err(|_| ErrorCode::BrokerUnavailable)?,
            agent_actor: super::custody::ActorRole::agent(custody, vault_id)?,
            admin_actor: super::custody::ActorRole::admin(custody, vault_id)?,
        })
    }
    fn connect(&mut self) -> std::result::Result<(bool, bool), ErrorCode> {
        let agent_denied = is_error(
            &exchange(&mut self.agent, "discover_operations", Empty {})?,
            ErrorCode::AuthenticationRequired,
        );
        let admin_denied = is_error(
            &exchange(&mut self.admin, "revoke_challenge", Empty {})?,
            ErrorCode::AuthenticationRequired,
        );
        let challenge = value(
            exchange(&mut self.agent, "connect_challenge", Empty {})?,
            "challenge",
        )?;
        let proof = self.agent_actor.proof(&challenge)?;
        if !is_error(
            &exchange(&mut self.admin, "connect", &proof)?,
            ErrorCode::AuthenticationRequired,
        ) || !is_kind(&exchange(&mut self.agent, "connect", proof)?, "connected")
        {
            return Err(ErrorCode::BrokerUnavailable);
        }
        let challenge = value(
            exchange(&mut self.admin, "connect_challenge", Empty {})?,
            "challenge",
        )?;
        if !is_kind(
            &exchange(
                &mut self.admin,
                "connect",
                self.admin_actor.proof(&challenge)?,
            )?,
            "connected",
        ) || !is_error(
            &exchange(&mut self.agent, "revoke_challenge", Empty {})?,
            ErrorCode::InvalidRequest,
        ) {
            return Err(ErrorCode::BrokerUnavailable);
        }
        Ok((agent_denied, admin_denied))
    }
}

pub(super) fn composed_round(
    protocol: SyntheticProtocol,
    custody: &Path,
    vault_id: &str,
) -> std::result::Result<ComposedRound, ErrorCode> {
    let mut channels = ComposedChannels::new(protocol, custody, vault_id)?;
    let (agent_denied, admin_denied) = channels.connect()?;
    let prepared: crate::OperationRunView = value(
        exchange(
            &mut channels.agent,
            "prepare_operation",
            OperationPrepareInput {
                request_id: RequestId::new("composed-import-one")?,
                profile_id: ProfileId::new("vault-delivery")?,
                operation: OperationIntent::Delivery(super::DeliveryParameters::fixture(1)),
            },
        )?,
        "run",
    )?;
    let id = prepared.prepared_request_id;
    let awaiting: crate::OperationRunView = value(
        exchange(
            &mut channels.agent,
            "request_approval",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "run",
    )?;
    if awaiting.state != Lifecycle::AwaitingApproval {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let expected: protocol::ReviewPlan = value(
        exchange(
            &mut channels.admin,
            "inspect_review",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "review",
    )?;
    // The simulated signer checks the complete broker-resolved profile and exact
    // delivery parameters, in addition to binding the proof to its review digest.
    if expected.profile != super::DeliveryProfile::fixture(1)
        || expected.operation != super::DeliveryParameters::fixture(1)
    {
        return Err(ErrorCode::PolicyChanged);
    }
    let challenge = value(
        exchange(&mut channels.admin, "approval_challenge", &expected)?,
        "challenge",
    )?;
    let reviewed_proof = channels.admin_actor.reviewed_proof(&challenge, &expected)?;
    let approved: crate::OperationRunView = value(
        exchange(
            &mut channels.admin,
            "approve",
            serde_json::json!({"expected":expected,"proof":reviewed_proof}),
        )?,
        "run",
    )?;
    if approved.state != Lifecycle::Approved {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let challenge = value(
        exchange(
            &mut channels.agent,
            "invocation_challenge",
            Handle {
                prepared_request_id: id,
            },
        )?,
        "challenge",
    )?;
    let invocation = serde_json::json!({"prepared_request_id":id,"proof":channels.agent_actor.proof(&challenge)?});
    let run: crate::OperationRunView = value(
        exchange(&mut channels.agent, "invoke_approved", &invocation)?,
        "run",
    )?;
    let duplicate: crate::OperationRunView = value(
        exchange(&mut channels.agent, "invoke_approved", &invocation)?,
        "run",
    )?;
    Ok(ComposedRound {
        duplicate_reused: run == duplicate,
        run,
        unauthenticated_agent_denied: agent_denied,
        unauthenticated_admin_denied: admin_denied,
        agent_transcript_contains_canary: channels.agent.transcript_contains_canary,
    })
}

pub(super) fn composed_revoke_after_restart(
    protocol: SyntheticProtocol,
    custody: &Path,
    vault_id: &str,
) -> std::result::Result<bool, ErrorCode> {
    let mut channels = ComposedChannels::new(protocol, custody, vault_id)?;
    let (agent_denied, admin_denied) = channels.connect()?;
    let challenge = value(
        exchange(&mut channels.admin, "revoke_challenge", Empty {})?,
        "challenge",
    )?;
    if !is_kind(
        &exchange(
            &mut channels.admin,
            "revoke",
            channels.admin_actor.proof(&challenge)?,
        )?,
        "revoked",
    ) {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(agent_denied && admin_denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Paths(PathBuf);
    impl Paths {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "aegis-tls-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn protocol(&self) -> SyntheticProtocol {
            SyntheticProtocol::create(
                &self.0.join("vault"),
                &self.0.join("kit"),
                &self.0.join("recipient"),
                Arc::new(ManualClock::default()),
            )
            .unwrap()
        }
    }
    impl Drop for Paths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn failed<T>(result: Result<T>, expected: Failure) {
        assert!(matches!(result, Err(actual) if actual == expected));
    }
    fn binding() -> Binding {
        Binding {
            role: Role::Agent,
            exporter: [7; 32],
        }
    }
    fn frame(binding: Binding, direction: u8, sequence: u64, body: &[u8]) -> PrivateBytes {
        let mut bytes = binding.header(direction, sequence, body.len()).to_vec();
        bytes.extend_from_slice(body);
        PrivateBytes(bytes)
    }
    fn encrypted_plaintext(client: &mut Channel, clear: &[u8]) -> Vec<u8> {
        let tls = client.tls.as_mut().unwrap();
        tls.writer().write_all(clear).unwrap();
        drain_tls(tls, &mut client.budget).unwrap()
    }

    #[test]
    fn actual_mtls_drill_delivers_via_protocol_without_opening_deployment() {
        let paths = Paths::new();
        let report = run_synthetic_tls_drill(
            &paths.0.join("vault"),
            &paths.0.join("kit"),
            &paths.0.join("recipient"),
        )
        .unwrap();
        assert!(report.tls13_mutual_authentication_verified && report.encrypted_roundtrip_verified);
        assert!(
            report.wrong_ca_denied
                && report.wrong_name_denied
                && report.missing_client_certificate_denied
        );
        assert!(report.wrong_peer_denied && report.wrong_role_denied && report.wrong_alpn_denied);
        assert!(
            report.application_replay_denied
                && report.cross_channel_frame_denied
                && report.ciphertext_tampering_denied
        );
        assert!(
            report.protocol_delivery_verified
                && report.unauthenticated_agent_denied
                && report.unauthenticated_admin_denied
        );
        assert!(
            report.wrong_role_proof_denied && report.agent_admin_method_denied && report.revoked
        );
        assert_eq!(
            (
                report.completed_deliveries,
                report.consumed_uses,
                report.recipient_generation
            ),
            (1, 1, 1)
        );
        assert!(
            !report.agent_transcript_contains_canary && !report.independent_key_custody_verified
        );
        assert!(
            !report.independent_human_presence_verified
                && !report.protected_deployment_verified
                && !report.ready_for_real_keys
        );
        let output = serde_json::to_string(&report).unwrap();
        for marker in [
            super::super::store::CANARY_ONE,
            super::super::store::CANARY_TWO,
            "PRIVATE KEY",
            "assertion",
            "exporter",
        ] {
            assert!(!output.contains(marker));
        }
        assert_eq!(
            super::super::require_live_deployment(),
            Err(ErrorCode::UnsupportedDeployment)
        );
    }

    #[test]
    fn full_handshakes_never_resume_and_exporters_are_unique_and_role_bound() {
        let fixtures = Fixtures::new().unwrap();
        for role in [Role::Agent, Role::Admin, Role::Recipient] {
            let (c, s) = configs(
                fixtures.ca.der(),
                &fixtures.server,
                Some(fixtures.identity(role)),
                role,
            )
            .unwrap();
            assert!(!c.enable_early_data);
            assert_eq!(
                (
                    s.send_tls13_tickets,
                    s.max_tls13_tickets,
                    s.max_early_data_size
                ),
                (0, 0, 0)
            );
            let enrollment = fixtures.enrollment(role);
            let (first, peer) = establish(c.clone(), s.clone(), SERVER_NAME, &enrollment).unwrap();
            let (second, _) = establish(c, s, SERVER_NAME, &enrollment).unwrap();
            assert!(first.binding.exporter == peer.binding.exporter);
            assert!(first.binding.exporter != second.binding.exporter);
            assert_eq!(
                first.tls.as_ref().unwrap().handshake_kind(),
                Some(HandshakeKind::Full)
            );
            assert_eq!(
                second.tls.as_ref().unwrap().handshake_kind(),
                Some(HandshakeKind::Full)
            );
        }
    }

    #[test]
    fn wrong_client_ca_server_pin_eku_and_expired_certificates_are_refused() {
        let fixtures = Fixtures::new().unwrap();
        let foreign = Fixtures::new().unwrap();
        let enrollment = fixtures.enrollment(Role::Agent);
        let (c, s) = configs(
            fixtures.ca.der(),
            &fixtures.server,
            Some(&foreign.agent),
            Role::Agent,
        )
        .unwrap();
        assert!(establish(c, s, SERVER_NAME, &enrollment).is_err());
        let impostor_server = Identity::issue(&fixtures.ca, SERVER_NAME, true).unwrap();
        let (c, s) = configs(
            fixtures.ca.der(),
            &impostor_server,
            Some(&fixtures.agent),
            Role::Agent,
        )
        .unwrap();
        failed(establish(c, s, SERVER_NAME, &enrollment), Failure::Peer);
        let wrong_eku = Identity::issue(&fixtures.ca, "agent.aegis.invalid", true).unwrap();
        let (c, s) = configs(
            fixtures.ca.der(),
            &fixtures.server,
            Some(&wrong_eku),
            Role::Agent,
        )
        .unwrap();
        assert!(establish(c, s, SERVER_NAME, &enrollment).is_err());
        let key = FixtureKey(KeyPair::generate().unwrap());
        let mut params = CertificateParams::new(vec![SERVER_NAME.into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let expired = Identity {
            cert: params.signed_by(&key, &fixtures.ca).unwrap().der().clone(),
            key: Zeroizing::new(PrivatePkcs8KeyDer::from(key.0.serialize_der()).into()),
        };
        let (c, s) = configs(
            fixtures.ca.der(),
            &expired,
            Some(&fixtures.agent),
            Role::Agent,
        )
        .unwrap();
        assert!(establish(c, s, SERVER_NAME, &enrollment).is_err());
    }

    #[test]
    fn every_plaintext_split_and_one_byte_tls_fragments_reassemble() {
        let body = b"bounded dummy message";
        let bytes = frame(binding(), 1, 0, body);
        for split in 0..=bytes.0.len() {
            let mut d = Decoder::new(binding(), 1);
            let mut out = Vec::new();
            d.receive(&bytes.0[..split], Instant::now(), &mut out)
                .unwrap();
            d.receive(&bytes.0[split..], Instant::now(), &mut out)
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(&out[0].0, body);
            assert!(!d.pending());
        }
        let fixtures = Fixtures::new().unwrap();
        let (mut c, mut s) = fixtures.pair(Role::Agent).unwrap();
        let wire = c.send(body).unwrap();
        let mut out = Vec::new();
        for byte in wire {
            out.extend(s.receive(&[byte]).unwrap());
        }
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].0, body);
    }

    #[test]
    fn frame_bounds_are_checked_before_body_allocation_and_largest_body_roundtrips() {
        for size in [0, MAX_BODY + 1, u32::MAX as usize] {
            let mut d = Decoder::new(binding(), 1);
            failed(
                d.receive(
                    &binding().header(1, 0, size),
                    Instant::now(),
                    &mut Vec::new(),
                ),
                Failure::Limit,
            );
            assert_eq!(d.body.0.capacity(), 0);
        }
        let fixtures = Fixtures::new().unwrap();
        let (mut c, mut s) = fixtures.pair(Role::Agent).unwrap();
        let body = vec![42; MAX_BODY];
        let wire = c.send(&body).unwrap();
        let out = receive_message(&mut s, &wire).unwrap();
        assert!(out.0 == body);
        failed(c.send(&vec![0; MAX_BODY + 1]), Failure::Limit);
        failed(c.send(b"again"), Failure::Closed);
        failed(bounded_json(&"x".repeat(MAX_BODY)), Failure::Limit);
    }

    #[test]
    fn immutable_header_bindings_direction_magic_and_sequences_reject_changes() {
        for (offset, expected) in [
            (0, Failure::Protocol),
            (4, Failure::Binding),
            (5, Failure::Binding),
            (6, Failure::Binding),
            (7, Failure::Protocol),
            (8, Failure::Binding),
            (47, Failure::Sequence),
        ] {
            let mut bytes = frame(binding(), 1, 0, b"x");
            bytes.0[offset] ^= 1;
            failed(
                Decoder::new(binding(), 1).receive(&bytes.0, Instant::now(), &mut Vec::new()),
                expected,
            );
        }
        let mut d = Decoder::new(binding(), 1);
        let bytes = frame(binding(), 1, 0, b"x");
        d.receive(&bytes.0, Instant::now(), &mut Vec::new())
            .unwrap();
        failed(
            d.receive(&bytes.0, Instant::now(), &mut Vec::new()),
            Failure::Sequence,
        );
    }

    #[test]
    fn frame_count_byte_work_and_absolute_time_caps_are_enforced() {
        let mut d = Decoder::new(binding(), 1);
        for sequence in 0..MAX_FRAMES {
            d.receive(
                &frame(binding(), 1, sequence, b"x").0,
                Instant::now(),
                &mut Vec::new(),
            )
            .unwrap();
        }
        failed(
            d.receive(
                &frame(binding(), 1, MAX_FRAMES, b"x").0,
                Instant::now(),
                &mut Vec::new(),
            ),
            Failure::Limit,
        );
        let mut b = Budget::new(CHANNEL_TIME);
        failed(b.charge(MAX_WIRE + 1, Instant::now()), Failure::Limit);
        let mut b = Budget::new(CHANNEL_TIME);
        for _ in 0..MAX_STEPS {
            b.charge(0, Instant::now()).unwrap();
        }
        failed(b.charge(0, Instant::now()), Failure::Limit);
        let mut b = Budget::new(HANDSHAKE_TIME);
        failed(b.charge(0, b.start + HANDSHAKE_TIME), Failure::Deadline);
        let fixtures = Fixtures::new().unwrap();
        let (mut c, mut s) = fixtures.pair(Role::Agent).unwrap();
        let wire = c.send(b"x").unwrap();
        let start = Instant::now();
        assert!(s.receive_at(&wire[..1], start).unwrap().is_empty());
        failed(
            s.receive_at(&wire[1..], start + FRAME_TIME),
            Failure::Deadline,
        );
        failed(s.receive(&wire), Failure::Closed);
        let (_, mut s) = fixtures.pair(Role::Agent).unwrap();
        failed(
            s.receive_at(&[], s.budget.start + CHANNEL_TIME),
            Failure::Deadline,
        );
        let mut d = Decoder::new(binding(), 1);
        d.receive(
            &frame(binding(), 1, 0, b"xx").0[..HEADER + 1],
            start,
            &mut Vec::new(),
        )
        .unwrap();
        failed(
            d.receive(b"x", start + FRAME_TIME, &mut Vec::new()),
            Failure::Deadline,
        );
        let mut b = Budget::new(HANDSHAKE_TIME);
        failed(
            b.charge(0, b.start - Duration::from_nanos(1)),
            Failure::Deadline,
        );
    }

    #[test]
    fn ciphertext_replay_cross_channel_and_truncation_leave_no_reusable_channel() {
        let fixtures = Fixtures::new().unwrap();
        let (mut c, mut s) = fixtures.pair(Role::Agent).unwrap();
        let wire = c.send(b"x").unwrap();
        s.receive(&wire).unwrap();
        failed(s.receive(&wire), Failure::Tls);
        failed(s.receive(&wire), Failure::Closed);
        let (_, mut other) = fixtures.pair(Role::Agent).unwrap();
        failed(other.receive(&wire), Failure::Tls);
        for split in [1, 4, wire.len() - 1] {
            let (mut c, mut s) = fixtures.pair(Role::Agent).unwrap();
            let wire = c.send(b"x").unwrap();
            assert!(s.receive(&wire[..split]).unwrap().is_empty());
            failed(s.eof(), Failure::Truncated);
            failed(s.receive(&wire[split..]), Failure::Closed);
        }
    }

    #[test]
    fn dispatcher_denials_stay_bounded_and_terminal_transport_failure_drops_endpoint() {
        let paths = Paths::new();
        let protocol = paths.protocol();
        let fixtures = Fixtures::new().unwrap();
        let mut channel = EndpointChannel::new(&fixtures, Endpoint::Agent(protocol.agent)).unwrap();
        let response = channel.exchange(b"{}").unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response.0).unwrap();
        assert!(is_error(&response, ErrorCode::InvalidRequest));
        assert!(channel.endpoint.is_some());
        let bad = frame(channel.client.binding, 2, channel.client.sequence, b"{}");
        let wire = encrypted_plaintext(&mut channel.client, &bad.0);
        failed(channel.respond(&wire), Failure::Binding);
        assert!(channel.endpoint.is_none());
        failed(channel.exchange(b"{}"), Failure::Closed);
    }

    #[test]
    fn pipelined_requests_are_rejected_before_dispatch() {
        let paths = Paths::new();
        let protocol = paths.protocol();
        let fixtures = Fixtures::new().unwrap();
        let mut channel = EndpointChannel::new(&fixtures, Endpoint::Agent(protocol.agent)).unwrap();
        let first = frame(channel.client.binding, 1, 0, b"{}");
        let second = frame(channel.client.binding, 1, 1, b"{}");
        let mut plain = PrivateBytes(first.0.clone());
        plain.0.extend_from_slice(&second.0);
        let wire = encrypted_plaintext(&mut channel.client, &plain.0);
        failed(channel.respond(&wire), Failure::Protocol);
        assert!(channel.endpoint.is_none());
    }
}
