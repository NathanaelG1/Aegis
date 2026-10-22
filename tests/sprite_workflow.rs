#![cfg(all(feature = "proxy", unix))]
//! Native HTTP/process/MCP coverage; every credential is a disposable fixture.
use aegis::sprite_client::SpriteClient;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
struct Fixture {
    path: PathBuf,
    server: Option<Child>,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "aegis-native-sprite-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { path, server: None }
    }
    fn state(&self) -> PathBuf {
        self.path.join("state")
    }
    fn start(&mut self) -> String {
        if let Some(mut child) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_aegis"))
            .args(["sprite-demo-serve", "--state-dir"])
            .arg(self.state())
            .args(["--listen", "127.0.0.1:0"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut ready = String::new();
            let _ = reader.read_line(&mut ready);
            let _ = tx.send(ready);
            // Keep consuming audit output until the child exits.
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        self.server = Some(child);
        let ready = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(ready.starts_with("sprite_demo_ready "));
        format!("http://{}", ready.split_whitespace().nth(1).unwrap())
    }
    fn client(&self, url: &str, role: &str, instance: Option<String>) -> SpriteClient {
        SpriteClient::new(
            url,
            &self.state().join(format!("{role}.key")),
            role,
            instance,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn raw(url: &str, token: Option<&str>, path: &str, body: &str, extra: &str) -> u16 {
    let address = url.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(stream, "POST {path} HTTP/1.1\r\nHost: {address}\r\n{auth}{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}
#[test]
fn authenticated_http_and_separate_mcp_agent_workflow() {
    let mut f = Fixture::new();
    aegis::sprite::initialize(&f.state()).unwrap();
    assert!(aegis::sprite::initialize(&f.state()).is_err());
    let owner_token = fs::read_to_string(f.state().join("owner.key")).unwrap();
    let agent_token = fs::read_to_string(f.state().join("agent.key")).unwrap();
    let fake = fs::read_to_string(f.state().join("fake-secret.key")).unwrap();
    assert_ne!(owner_token, agent_token);
    assert!(fake.starts_with("AEGIS_FAKE_ONLY_"));
    assert!(SpriteClient::new(
        "http://example.invalid",
        &f.state().join("agent.key"),
        "agent",
        None
    )
    .is_err());
    let url = f.start();
    let mut agent = f.client(&url, "agent", None);
    let instance = agent.session().unwrap()["instance_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let owner = f.client(&url, "owner", Some(instance.clone()));
    for (token, route) in [
        (None, "/v1/agent"),
        (Some("invalid"), "/v1/agent"),
        (Some(agent_token.trim()), "/v1/owner"),
        (Some(owner_token.trim()), "/v1/agent"),
    ] {
        assert_eq!(raw(&url, token, route, "{}", ""), 401);
    }
    assert_eq!(
        raw(
            &url,
            Some(agent_token.trim()),
            "/v1/agent",
            "{}",
            &format!("Authorization: Bearer {}\r\n", owner_token.trim())
        ),
        401
    );
    assert_eq!(
        raw(
            &url,
            Some(agent_token.trim()),
            "/v1/agent",
            "{}",
            "Origin: https://example.invalid\r\n"
        ),
        400
    );
    assert_eq!(
        raw(
            &url,
            Some(agent_token.trim()),
            "/v1/agent?token=x",
            "{}",
            ""
        ),
        400
    );
    assert_eq!(
        raw(
            &url,
            Some(agent_token.trim()),
            "/v1/agent",
            &"x".repeat(16385),
            ""
        ),
        400
    );
    for route in [
        "/get_secret",
        "/secrets",
        "/files",
        "/debug",
        "/env",
        "/metrics",
    ] {
        assert_eq!(raw(&url, Some(agent_token.trim()), route, "{}", ""), 404);
    }
    for method in ["get_secret", "approve", "export", "exec", "read_file"] {
        let body =
            json!({"instance_id":instance,"request":{"version":1,"action":{"method":method}}});
        assert_eq!(
            raw(
                &url,
                Some(agent_token.trim()),
                "/v1/agent",
                &body.to_string(),
                ""
            ),
            400
        );
    }
    let duplicate = format!(
        r#"{{"instance_id":"{instance}","instance_id":"other","request":{{"version":1,"action":{{"method":"discover_operations"}}}}}}"#
    );
    assert_eq!(
        raw(&url, Some(agent_token.trim()), "/v1/agent", &duplicate, ""),
        400
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .args(["sprite-client", "--url", &url, "--token-file"])
        .arg(f.state().join("agent.key"))
        .args(["--role", "agent", "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut captures = Vec::new();
    let mut rpc = |id: u32, method: &str, params: Value| -> Value {
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
        )
        .unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        captures.push(line.clone());
        serde_json::from_str(&line).unwrap()
    };
    assert!(rpc(1, "initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}})).get("result").is_some());
    assert_eq!(
        rpc(2, "tools/list", json!({}))["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert!(
        rpc(3, "tools/call", json!({"name":"approve","arguments":{}}))
            .get("error")
            .is_some()
    );
    let prepared = agent.call("prepare_operation", Some(json!({"request_id":"main","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7}}))).unwrap();
    let handle = json!({"prepared_request_id":prepared["result"]["prepared_request_id"]});
    assert_eq!(
        agent.call("invoke_approved", Some(handle.clone())).unwrap()["error"],
        "approval_required"
    );
    assert_eq!(
        agent
            .call("request_approval", Some(handle.clone()))
            .unwrap()["result"]["state"],
        "awaiting_approval"
    );
    assert_eq!(
        owner.call("pending", None).unwrap()["result"][0]["prepared_request_id"],
        handle["prepared_request_id"]
    );
    assert_eq!(
        owner
            .call("approve", Some(json!({"review_id":"unknown"})))
            .unwrap()["error"],
        "approval_required"
    );
    let review = owner.call("inspect", Some(handle.clone())).unwrap();
    assert_eq!(
        review["result"]["plan"]["parameters"],
        json!({"repository_id":4242,"issue_number":7})
    );
    let receipt = json!({"review_id":review["result"]["review_id"]});
    assert_eq!(
        owner.call("approve", Some(receipt.clone())).unwrap()["result"]["state"],
        "approved"
    );
    assert_eq!(
        owner.call("approve", Some(receipt)).unwrap()["error"],
        "approval_required"
    );
    let success = rpc(
        4,
        "tools/call",
        json!({"name":"invoke_approved","arguments":handle}),
    );
    let success: Value =
        serde_json::from_str(success["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        success["result"]["result"],
        json!({"repository_id":4242,"issue_number":7,"state":"open"})
    );
    drop(stdin);
    assert!(child.wait().unwrap().success());
    let mut retries = Vec::new();
    for _ in 0..4 {
        let client = f.client(&url, "agent", Some(instance.clone()));
        let handle = handle.clone();
        retries.push(std::thread::spawn(move || {
            client.call("invoke_approved", Some(handle)).unwrap()
        }));
    }
    for retry in retries {
        let result = retry.join().unwrap();
        assert_eq!(result["result"], success["result"]);
        captures.push(result.to_string());
    }
    assert_eq!(
        owner.call("evidence", None).unwrap()["result"]["provider_authenticated_calls"],
        1
    );
    assert_eq!(agent.call("prepare_operation", Some(json!({"request_id":"wrong","profile_id":"issue-status","parameters":{"repository_id":9999,"issue_number":7}}))).unwrap()["error"], "scope_denied");
    assert_eq!(agent.call("prepare_operation", Some(json!({"request_id":"main","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":8}}))).unwrap()["error"], "request_id_conflict");
    let prepared = agent.call("prepare_operation", Some(json!({"request_id":"cancel","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7}}))).unwrap();
    let cancel = json!({"prepared_request_id":prepared["result"]["prepared_request_id"]});
    agent
        .call("request_approval", Some(cancel.clone()))
        .unwrap();
    let review = owner.call("inspect", Some(cancel.clone())).unwrap();
    owner.call("cancel", Some(cancel.clone())).unwrap();
    assert_eq!(
        owner
            .call(
                "approve",
                Some(json!({"review_id":review["result"]["review_id"]}))
            )
            .unwrap()["error"],
        "request_canceled"
    );
    assert_eq!(
        agent.call("invoke_approved", Some(cancel)).unwrap()["result"]["state"],
        "canceled"
    );
    owner.call("revoke", None).unwrap();
    assert_eq!(agent.call("prepare_operation", Some(json!({"request_id":"revoked","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7}}))).unwrap()["error"], "grant_revoked");
    let url = f.start();
    let mut fresh = f.client(&url, "agent", None);
    assert_ne!(fresh.session().unwrap()["instance_id"], instance);
    assert!(f
        .client(&url, "agent", Some(instance))
        .call("invoke_approved", Some(handle))
        .is_err());
    for capture in captures {
        for secret in [fake.trim(), owner_token.trim(), agent_token.trim()] {
            assert!(!capture.contains(secret), "credential disclosure");
        }
    }
}
