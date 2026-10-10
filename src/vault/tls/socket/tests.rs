use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "aegis-socket-tls-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        bootstrap_fixture(&path.join("tls")).unwrap();
        Self(path)
    }
    fn server(&self) -> ServerMaterial {
        ServerMaterial::open(&self.0.join("tls/broker")).unwrap()
    }
    fn factory(&self, role: Role) -> ClientFactory {
        match role {
            Role::Agent => ClientFactory::agent(&self.0.join("tls/agent")).unwrap(),
            Role::Admin => ClientFactory::admin(&self.0.join("tls/admin")).unwrap(),
            Role::Recipient => unreachable!(),
        }
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
    fn pair(&self, endpoint: Endpoint) -> (SocketClient, SocketServer) {
        let factory = self.factory(endpoint.role());
        let server = self.server();
        let (client_socket, server_socket) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || match endpoint {
            Endpoint::Agent(e) => server.agent(server_socket, e),
            Endpoint::Admin(e) => server.admin(server_socket, e),
        });
        let client = factory.connect(client_socket).unwrap();
        (client, worker.join().unwrap().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn inherited_socket_roles_exchange_protocol_and_close_without_endpoint_reuse() {
    let f = Fixture::new();
    let p = f.protocol();
    let agent = f.pair(Endpoint::Agent(p.agent));
    let admin = f.pair(Endpoint::Admin(p.admin));
    for ((mut client, mut server), method) in
        [(agent, "discover_operations"), (admin, "revoke_challenge")]
    {
        let worker = thread::spawn(move || {
            assert!(server.serve_one().unwrap());
            assert!(!server.serve_one().unwrap());
            assert!(server.endpoint.is_none());
            assert_eq!(server.serve_one(), Err(ErrorCode::BrokerUnavailable));
        });
        let body = request(method, Empty {}).unwrap();
        let reply: serde_json::Value =
            serde_json::from_slice(&client.exchange(&body.0).unwrap().0).unwrap();
        assert!(is_error(&reply, ErrorCode::AuthenticationRequired));
        client.close().unwrap();
        assert!(client.exchange(&body.0).is_err());
        worker.join().unwrap();
    }
}

#[test]
fn runtime_role_documents_are_separate_strict_and_bound_to_role() {
    let f = Fixture::new();
    let server: ServerDocument = read_document(&f.0.join("tls/broker")).unwrap();
    let agent: ClientDocument = read_document(&f.0.join("tls/agent")).unwrap();
    let admin: ClientDocument = read_document(&f.0.join("tls/admin")).unwrap();
    assert!(server.key != agent.key && server.key != admin.key && agent.key != admin.key);
    let bytes = fs::read(f.0.join("tls/broker/tls.json")).unwrap();
    assert!(!bytes
        .windows(agent.key.len())
        .any(|w| w == agent.key.as_bytes()));
    assert!(!bytes
        .windows(admin.key.len())
        .any(|w| w == admin.key.as_bytes()));
    assert!(ClientFactory::agent(&f.0.join("tls/admin")).is_err());
    assert!(ClientFactory::admin(&f.0.join("tls/agent")).is_err());
    assert!(bootstrap_fixture(&f.0.join("tls")).is_err());
    let mut parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    parsed["client_key"] = serde_json::Value::String(agent.key.clone());
    assert!(serde_json::from_value::<ServerDocument>(parsed).is_err());
    fs::remove_file(f.0.join("tls/agent/tls.json")).unwrap();
    fs::remove_file(f.0.join("tls/admin/tls.json")).unwrap();
    assert!(ServerMaterial::open(&f.0.join("tls/broker")).is_ok());
}

#[test]
fn socket_mtls_rejects_the_other_role_and_fresh_certificate_set() {
    let f = Fixture::new();
    let foreign = Fixture::new();
    for factory in [f.factory(Role::Admin), foreign.factory(Role::Agent)] {
        let server = f.server();
        let p = f.protocol();
        let (client_socket, server_socket) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || server.agent(server_socket, p.agent));
        let mut client = factory.connect(client_socket);
        if let Ok(client) = &mut client {
            assert!(client
                .exchange(&request("discover_operations", Empty {}).unwrap().0)
                .is_err());
        }
        assert!(worker.join().unwrap().is_err());
        // This fixture's protocol paths are create-new, including when loading
        // multiple independent denied TLS peers in the same test.
        for name in ["vault", "kit", "recipient"] {
            fs::remove_dir_all(f.0.join(name)).unwrap();
        }
    }
}

#[test]
fn absolute_os_deadlines_reject_even_the_last_successful_byte() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let mut io = SocketIo::new(socket).unwrap();
    let before = Instant::now();
    let deadline = before + Duration::from_secs(1);
    let mut observations = [before, deadline].into_iter();
    assert_eq!(
        io.write_clock(b"x", deadline, || observations.next().unwrap()),
        Err(Failure::Deadline)
    );
    let mut observed = [0];
    peer.read_exact(&mut observed).unwrap();
    assert_eq!(observed, [b'x']);
    peer.write_all(b"y").unwrap();
    let mut observations = [before, deadline].into_iter();
    assert_eq!(
        io.read_clock(&mut observed, deadline, || observations.next().unwrap()),
        Err(Failure::Deadline)
    );
    assert_eq!(observed, [b'y']);
}

#[test]
fn stalled_record_reads_and_backpressure_obey_one_absolute_deadline() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let mut io = SocketIo::new(socket).unwrap();
    // A prefix cannot extend the deadline for the remaining TLS record bytes.
    peer.write_all(&[23, 3, 3, 0, 8, 1]).unwrap();
    let start = Instant::now();
    let deadline = start + Duration::from_millis(40);
    assert_eq!(io.record(deadline), Err(Failure::Deadline));
    assert!(start.elapsed() < Duration::from_secs(1));
    let (socket, _peer) = UnixStream::pair().unwrap();
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::SndBuf, &4096).unwrap();
    let mut io = SocketIo::new(socket).unwrap();
    let start = Instant::now();
    let deadline = start + Duration::from_millis(40);
    let result = io.write_all(&vec![0; MAX_WIRE], deadline);
    assert_eq!(result, Err(Failure::Deadline));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn handshake_stall_and_eof_cannot_create_a_channel() {
    let f = Fixture::new();
    let (socket, peer) = UnixStream::pair().unwrap();
    drop(peer);
    assert!(f.factory(Role::Agent).connect(socket).is_err());
    let (socket, _peer) = UnixStream::pair().unwrap();
    let start = Instant::now();
    assert!(f.factory(Role::Agent).connect(socket).is_err());
    assert!(start.elapsed() >= HANDSHAKE_TIME);
    assert!(start.elapsed() < HANDSHAKE_TIME + Duration::from_secs(1));
}

#[test]
fn lifetime_frame_stall_and_abrupt_eof_drop_the_owned_endpoint() {
    for mode in 0..3 {
        let f = Fixture::new();
        let (mut client, mut server) = f.pair(Endpoint::Agent(f.protocol().agent));
        match mode {
            0 => server.connection.io.deadline = Instant::now(),
            1 => {
                // A complete TLS record with an incomplete app header must not
                // dispatch an endpoint operation or leave a reusable endpoint.
                let c = &mut client.connection;
                c.channel
                    .tls
                    .as_mut()
                    .unwrap()
                    .writer()
                    .write_all(b"ATL")
                    .unwrap();
                let wire =
                    drain_tls(c.channel.tls.as_mut().unwrap(), &mut c.channel.budget).unwrap();
                let deadline = c.io.operation_deadline(FRAME_TIME);
                c.io.write_all(&wire, deadline).unwrap();
            }
            _ => client.connection.stop(),
        }
        assert_eq!(server.serve_one(), Err(ErrorCode::BrokerUnavailable));
        assert!(server.endpoint.is_none());
        assert_eq!(server.serve_one(), Err(ErrorCode::BrokerUnavailable));
    }
}

#[test]
fn largest_frame_and_bounded_dispatch_count_share_the_existing_decoder() {
    let f = Fixture::new();
    let (mut client, mut server) = f.pair(Endpoint::Agent(f.protocol().agent));
    let worker = thread::spawn(move || {
        for _ in 0..MAX_FRAMES {
            assert!(server.serve_one().unwrap());
        }
        assert!(!server.serve_one().unwrap());
    });
    for index in 0..MAX_FRAMES {
        let body = if index == 0 {
            vec![b'x'; MAX_BODY]
        } else {
            b"invalid-json".to_vec()
        };
        let response: serde_json::Value =
            serde_json::from_slice(&client.exchange(&body).unwrap().0).unwrap();
        assert!(!response["error"].is_null());
    }
    client.close().unwrap();
    worker.join().unwrap();
}

#[test]
fn lost_response_is_terminal_and_server_close_is_authenticated() {
    let f = Fixture::new();
    let (mut client, mut server) = f.pair(Endpoint::Agent(f.protocol().agent));
    server.discard_next_response_for_test();
    let worker = thread::spawn(move || {
        assert_eq!(server.serve_one(), Err(ErrorCode::BrokerUnavailable));
        assert!(server.endpoint.is_none());
    });
    let request = request("discover_operations", Empty {}).unwrap();
    assert!(client.exchange(&request.0).is_err());
    assert!(client.exchange(&request.0).is_err());
    worker.join().unwrap();
    let f = Fixture::new();
    let (mut client, mut server) = f.pair(Endpoint::Agent(f.protocol().agent));
    server.close().unwrap();
    assert!(server.endpoint.is_none());
    assert!(client.exchange(&request.0).is_err());
}
