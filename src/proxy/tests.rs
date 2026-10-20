use super::*;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    thread,
};

const CANARY: &str = "DISPOSABLE_proxy_test_key_47ad8789";
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("aegis-proxy-{}", random().unwrap()));
        Broker::initialize(&root).unwrap();
        Self(root)
    }
    fn broker(&self) -> Broker {
        Broker::open(&self.0).unwrap()
    }
    fn token(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(format!("{name}.token"))).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn policy(url: String) -> Policy {
    serde_json::from_value(json!({"allowed_secrets":["provider-key"],"max_calls":10,"operations":{
        "send":{"url":url,"method":"POST","secrets":{"provider-key":{"header":"Authorization","prefix":"Bearer "}},
        "response_fields":{"id":"/id"}}}})).unwrap()
}
fn request(id: &str) -> Request {
    serde_json::from_value(json!({"request_id":id,"operation":"send","inject":["provider-key"],"body":{"message":"test"}})).unwrap()
}
fn upstream(response: String) -> (String, rustls::RootCertStore, thread::JoinHandle<Vec<u8>>) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = generated.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://localhost:{}/v1/send",
        listener.local_addr().unwrap().port()
    );
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            tcp,
        );
        let mut input = Vec::new();
        let mut byte = [0u8; 1];
        while !input.ends_with(b"\r\n\r\n") && input.len() < 32768 {
            if stream.read_exact(&mut byte).is_err() {
                return input;
            }
            input.push(byte[0]);
        }
        let length = String::from_utf8_lossy(&input)
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        if stream.read_exact(&mut body).is_ok() {
            input.extend(body);
        }
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        input
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    (url, roots, handle)
}
fn response(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}
fn trust(broker: &mut Broker, roots: rustls::RootCertStore) {
    broker.client.tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
}

#[test]
fn encrypted_storage_rotation_permissions_and_tampering() {
    let f = Fixture::new();
    let b = f.broker();
    b.put_secret("provider-key", CANARY.into()).unwrap();
    assert!(!fs::read(f.0.join("vault.age"))
        .unwrap()
        .windows(CANARY.len())
        .any(|w| w == CANARY.as_bytes()));
    assert!(!b.status().unwrap().to_string().contains(CANARY));
    b.put_secret("provider-key", "replacement_value_987654321".into())
        .unwrap();
    assert_eq!(
        b.store.load().unwrap().secrets["provider-key"].value,
        "replacement_value_987654321"
    );
    b.delete_secret("provider-key").unwrap();
    assert!(b.store.load().unwrap().secrets.is_empty());
    assert!(Broker::initialize(&f.0).is_err());
    fs::set_permissions(f.0.join("identity.key"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(b.status().is_err());
    fs::set_permissions(f.0.join("identity.key"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = fs::read(f.0.join("vault.age")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(f.0.join("vault.age"), bytes).unwrap();
    assert!(b.status().is_err());
}
#[test]
fn rejects_links_and_invalid_permissions() {
    let f = Fixture::new();
    let link = f.0.with_extension("link");
    symlink(&f.0, &link).unwrap();
    assert!(Broker::open(&link).is_err());
    fs::remove_file(link).unwrap();
    fs::rename(f.0.join("identity.key"), f.0.join("original.key")).unwrap();
    symlink(f.0.join("original.key"), f.0.join("identity.key")).unwrap();
    assert!(f.broker().status().is_err());
    fs::remove_file(f.0.join("identity.key")).unwrap();
    fs::hard_link(f.0.join("original.key"), f.0.join("identity.key")).unwrap();
    assert!(f.broker().status().is_err());
}
#[test]
fn permissions_and_destinations_fail_closed() {
    let f = Fixture::new();
    let b = f.broker();
    b.put_secret("provider-key", CANARY.into()).unwrap();
    for url in [
        "http://example.com/a",
        "https://user:password@example.com/a",
        "https://example.com/a#fragment",
    ] {
        assert!(b.add_service("app", policy(url.into())).is_err());
    }
    for header in [
        "Host",
        "Transfer-Encoding",
        "Content-Length",
        "Connection",
        "Upgrade",
        "Proxy-Authorization",
        "bad\r\nheader",
    ] {
        let mut p = policy("https://example.com/a".into());
        p.operations
            .get_mut("send")
            .unwrap()
            .secrets
            .get_mut("provider-key")
            .unwrap()
            .header = header.into();
        assert!(b.add_service("app", p).is_err());
    }
    let mut p = policy("https://example.com/a".into());
    p.allowed_secrets.clear();
    assert!(b.add_service("app", p).is_err());
    for field in ["url", "headers", "secret_value", "owner", "exec"] {
        let mut v = serde_json::to_value(request("a")).unwrap();
        v[field] = json!("unauthorized");
        assert!(serde_json::from_value::<Request>(v).is_err());
    }
    b.add_service("app", policy("https://example.com/a".into()))
        .unwrap();
    assert!(b.invoke(&"0".repeat(64), request("a")).is_err());
    let mut wrong = request("a");
    wrong.inject.insert("other-key".into());
    assert!(b.invoke(&f.token("app"), wrong).is_err());
    let mut wrong = request("a");
    wrong.operation = "exec".into();
    assert!(b.invoke(&f.token("app"), wrong).is_err());
    assert_eq!(b.status().unwrap()["retained_requests"], 0);
}
#[test]
fn real_tls_injection_projection_replay_and_restart() {
    let f = Fixture::new();
    let mut b = f.broker();
    let (url, roots, server) = upstream(response(&format!(
        r#"{{"id":"accepted","unexpected_secret":"{CANARY}"}}"#
    )));
    trust(&mut b, roots);
    b.put_secret("provider-key", CANARY.into()).unwrap();
    b.add_service("app", policy(url)).unwrap();
    let token = f.token("app");
    let result = b.invoke(&token, request("once")).unwrap();
    assert_eq!(result, json!({"status":200,"fields":{"id":"accepted"}}));
    let wire = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(wire.contains(&format!("Bearer {CANARY}")));
    assert!(!wire.contains(&token));
    let reopened = f.broker();
    assert_eq!(reopened.invoke(&token, request("once")).unwrap(), result);
    let mut conflict = request("once");
    conflict.body = Some(json!({"message":"different"}));
    assert!(reopened.invoke(&token, conflict).is_err());
    assert_eq!(reopened.status().unwrap()["services"][0]["used"], 1);
    reopened.control("app", Some(false), false).unwrap();
    assert!(reopened.invoke(&token, request("once")).is_err());
    reopened.control("app", Some(true), true).unwrap();
    assert!(reopened.invoke(&token, request("once")).is_err());
    assert_eq!(
        reopened.invoke(&f.token("app"), request("once")).unwrap(),
        result
    );
}
#[test]
fn echo_responses_and_redirects_are_withheld() {
    for body in [CANARY.to_owned(), STANDARD.encode(CANARY)] {
        let f = Fixture::new();
        let mut b = f.broker();
        let (url, roots, server) = upstream(response(&json!({"id":body}).to_string()));
        trust(&mut b, roots);
        b.put_secret("provider-key", CANARY.into()).unwrap();
        b.add_service("app", policy(url)).unwrap();
        let result = b.invoke(&f.token("app"), request("echo")).unwrap();
        assert_eq!(result, json!({"error":"upstream_response_withheld"}));
        server.join().unwrap();
    }
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let f = Fixture::new();
    let mut b = f.broker();
    let (url, roots, server) = upstream(format!(
        "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:{}/steal\r\nContent-Length: 0\r\n\r\n",
        target.local_addr().unwrap().port()
    ));
    trust(&mut b, roots);
    b.put_secret("provider-key", CANARY.into()).unwrap();
    b.add_service("app", policy(url)).unwrap();
    assert_eq!(
        b.invoke(&f.token("app"), request("redirect")).unwrap(),
        json!({"status":302})
    );
    server.join().unwrap();
    assert!(target.accept().is_err());
}
#[test]
fn unknown_outcome_is_durable_and_never_retried() {
    let f = Fixture::new();
    let mut b = f.broker();
    let (url, roots, server) = upstream(String::new());
    trust(&mut b, roots);
    b.put_secret("provider-key", CANARY.into()).unwrap();
    b.add_service("app", policy(url)).unwrap();
    let result = b.invoke(&f.token("app"), request("lost")).unwrap();
    server.join().unwrap();
    assert_eq!(
        result["error"],
        "upstream_outcome_unknown_do_not_retry_with_new_id"
    );
    assert_eq!(
        f.broker().invoke(&f.token("app"), request("lost")).unwrap(),
        result
    );
    assert_eq!(b.status().unwrap()["services"][0]["used"], 1);
}
#[test]
fn untrusted_tls_and_missing_secrets_never_dispatch_plaintext() {
    let f = Fixture::new();
    let b = f.broker();
    let (url, _, server) = upstream(response("{}"));
    b.put_secret("provider-key", CANARY.into()).unwrap();
    b.add_service("app", policy(url)).unwrap();
    assert!(b
        .invoke(&f.token("app"), request("untrusted"))
        .unwrap()
        .get("error")
        .is_some());
    assert!(server.join().unwrap().is_empty());
    b.delete_secret("provider-key").unwrap();
    assert!(b.invoke(&f.token("app"), request("missing")).is_err());
}

#[test]
fn concurrent_retries_consume_once_and_policy_changes_keep_budget() {
    let f = Fixture::new();
    let mut b = f.broker();
    let (url, roots, server) = upstream(response(r#"{"id":"one"}"#));
    trust(&mut b, roots);
    b.put_secret("provider-key", CANARY.into()).unwrap();
    let mut p = policy(url);
    p.max_calls = 1;
    b.add_service("app", p.clone()).unwrap();
    b.put_secret("separate-key", "separate_disposable_value".into())
        .unwrap();
    let mut other = p.clone();
    other.allowed_secrets = BTreeSet::from(["separate-key".into()]);
    other.operations.get_mut("send").unwrap().secrets = BTreeMap::from([(
        "separate-key".into(),
        Injection {
            header: "Authorization".into(),
            prefix: "Bearer ".into(),
        },
    )]);
    b.add_service("other", other).unwrap();
    assert_eq!(
        b.invoke(&f.token("other"), request("once")).unwrap_err(),
        Error::Denied
    );
    let b = Arc::new(b);
    let start = Arc::new(std::sync::Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let b = b.clone();
            let start = start.clone();
            let token = f.token("app");
            thread::spawn(move || {
                start.wait();
                b.invoke(&token, request("once"))
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(results
        .iter()
        .any(|r| r.as_ref().is_ok_and(|v| v["fields"]["id"] == "one")));
    assert!(results
        .iter()
        .all(|r| r.as_ref().is_ok_and(|v| v["fields"]["id"] == "one")
            || *r == Err(Error::OutcomeUnknown)));
    server.join().unwrap();
    assert_eq!(
        b.invoke(&f.token("app"), request("new")).unwrap_err(),
        Error::Capacity
    );
    b.set_policy("app", p).unwrap();
    assert_eq!(
        b.invoke(&f.token("app"), request("new")).unwrap_err(),
        Error::Capacity
    );
    assert_eq!(b.store.load().unwrap().services["app"].used, 1);
    assert_eq!(b.store.load().unwrap().services["other"].used, 0);
}

#[test]
fn http_boundary_rejects_ambient_authority_and_returns_only_projection() {
    let f = Fixture::new();
    let mut b = f.broker();
    let (url, roots, upstream) = upstream(response(r#"{"id":"http-result"}"#));
    trust(&mut b, roots);
    b.put_secret("provider-key", CANARY.into()).unwrap();
    b.add_service("app", policy(url)).unwrap();
    let token = f.token("app");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let app = Router::new()
                .route("/v1/proxy", post(handle))
                .with_state(HttpState {
                    broker: Arc::new(b),
                    slots: Arc::new(tokio::sync::Semaphore::new(8)),
                });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
    });
    let call = |path: &str, authorization: &str, body: &str, extra: &str| {
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        write!(stream, "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\n{authorization}{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert!(!output.contains(CANARY));
        assert!(!output.contains(&token));
        output
    };
    let body = serde_json::to_string(&request("http")).unwrap();
    let auth = format!("Authorization: Bearer {token}\r\n");
    for (path, credential, extra) in [
        ("/v1/proxy", "", ""),
        ("/v1/proxy?token=ignored", auth.as_str(), ""),
        (
            "/v1/proxy",
            auth.as_str(),
            "Origin: https://example.invalid\r\n",
        ),
        ("/v1/proxy", auth.as_str(), auth.as_str()),
    ] {
        assert!(call(path, credential, &body, extra).starts_with("HTTP/1.1 403"));
    }
    for invalid in [
        "{}".to_string(),
        "x".repeat(65537),
        body.replace(
            "\"request_id\":",
            "\"request_id\":\"duplicate\",\"request_id\":",
        ),
    ] {
        assert!(call("/v1/proxy", &auth, &invalid, "").starts_with("HTTP/1.1 400"));
    }
    let output = call("/v1/proxy", &auth, &body, "");
    assert!(output.starts_with("HTTP/1.1 200"));
    assert!(output.contains("cache-control: no-store"));
    assert!(output.contains("http-result"));
    upstream.join().unwrap();
    stop.send(()).unwrap();
    server.join().unwrap();
}
