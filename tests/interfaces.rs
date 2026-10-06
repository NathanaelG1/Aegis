//! Actual synthetic subprocess and same-account Unix transport evidence.
//! Automating the test control pipe demonstrates the portable workflow's
//! same-account exclusion; it is deliberately not proof of human presence.
#![cfg(any(target_os = "macos", target_os = "linux"))]

use aegis::fake::SYNTHETIC_CANARY;
use aegis::ipc::{authenticate_peer, Endpoint, SocketBridge};
use aegis::mcp::{Bridge, MCP_VERSION};
use aegis::protocol::{Response, PROTOCOL_VERSION};
use aegis::{ErrorCode, Lifecycle, RunView};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        // macOS /tmp and /var can be symlinks. Exercise supported canonical
        // paths, with short names below the Unix sockaddr path-length limit.
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let path = parent.join(format!("ae-{:x}-{sequence:x}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create dedicated test directory: {error}"),
            }
        }
        panic!("cannot select a new dedicated test directory");
    }

    fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

type Lines = Arc<Mutex<Vec<String>>>;

fn capture(
    reader: impl std::io::Read + Send + 'static,
) -> (mpsc::Receiver<String>, mpsc::Receiver<()>, Lines) {
    let (sender, receiver) = mpsc::channel();
    let (completed, completion) = mpsc::channel();
    let log = Arc::new(Mutex::new(Vec::new()));
    let output = log.clone();
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut frame = Vec::new();
            // A broken child cannot allocate an unbounded line in the test.
            match std::io::Read::take(&mut reader, 32 * 1024).read_until(b'\n', &mut frame) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8(frame).expect("child output must be UTF-8");
                    output.lock().unwrap().push(line.clone());
                    let _ = sender.send(line);
                }
            }
        }
        let _ = completed.send(());
    });
    (receiver, completion, log)
}

struct ProcessOutput {
    status: ExitStatus,
    stdout: Vec<String>,
    stderr: Vec<String>,
}

impl ProcessOutput {
    fn assert_no_canary(&self) {
        assert!(!self.stdout.join("").contains(SYNTHETIC_CANARY));
        assert!(!self.stderr.join("").contains(SYNTHETIC_CANARY));
    }

    fn assert_json_stdout(&self) {
        for line in &self.stdout {
            let value: Value =
                serde_json::from_str(line).expect("MCP stdout must contain JSON only");
            assert_eq!(value["jsonrpc"], "2.0");
            assert!(value.get("id").is_some());
            assert_ne!(value.get("result").is_some(), value.get("error").is_some());
        }
    }
}

/// Every blocking read has a timeout; dropping a failed test kills its child.
struct Process {
    child: Child,
    input: Option<ChildStdin>,
    stdout: mpsc::Receiver<String>,
    stderr: mpsc::Receiver<String>,
    stdout_done: mpsc::Receiver<()>,
    stderr_done: mpsc::Receiver<()>,
    stdout_log: Lines,
    stderr_log: Lines,
}

impl Process {
    fn spawn(arguments: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_aegis"))
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let (stdout, stdout_done, stdout_log) = capture(child.stdout.take().unwrap());
        let (stderr, stderr_done, stderr_log) = capture(child.stderr.take().unwrap());
        Self {
            child,
            input,
            stdout,
            stderr,
            stdout_done,
            stderr_done,
            stdout_log,
            stderr_log,
        }
    }

    fn send(&mut self, line: &str) {
        let input = self.input.as_mut().expect("child stdin must still be open");
        input.write_all(line.as_bytes()).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }

    fn stdout_json(&self) -> Value {
        let line = self
            .stdout
            .recv_timeout(WAIT)
            .expect("MCP must reply within the test bound");
        assert!(!line.contains(SYNTHETIC_CANARY));
        serde_json::from_str(&line).expect("MCP stdout must be JSON")
    }

    fn stderr_line(&self) -> String {
        let line = self
            .stderr
            .recv_timeout(WAIT)
            .expect("control must reply within the test bound");
        assert!(!line.contains(SYNTHETIC_CANARY));
        line.trim_end().to_string()
    }

    fn finish(mut self) -> ProcessOutput {
        self.input.take();
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit within the test bound"
            );
            thread::sleep(Duration::from_millis(10));
        };
        self.stdout_done
            .recv_timeout(WAIT)
            .expect("stdout capture must finish");
        self.stderr_done
            .recv_timeout(WAIT)
            .expect("stderr capture must finish");
        ProcessOutput {
            status,
            stdout: self.stdout_log.lock().unwrap().clone(),
            stderr: self.stderr_log.lock().unwrap().clone(),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.input.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Broker {
    process: Process,
    directory: PathBuf,
    socket: PathBuf,
}

impl Broker {
    fn start(directory: PathBuf) -> Self {
        let process = Process::spawn(&[
            "synthetic-broker",
            "--socket-dir",
            directory.to_str().unwrap(),
            "--synthetic-control-pipe",
        ]);
        let socket = directory.join("agent.sock");
        assert_eq!(
            process.stderr_line(),
            format!("synthetic_broker_ready {}", socket.display())
        );
        assert!(process
            .stderr_line()
            .contains("same-account code can automate control"));
        assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(&directory).unwrap().uid(),
            nix::unistd::geteuid().as_raw()
        );
        assert_eq!(
            fs::metadata(&socket).unwrap().uid(),
            nix::unistd::geteuid().as_raw()
        );
        Self {
            process,
            directory,
            socket,
        }
    }

    fn control(&mut self, command: &str) -> String {
        self.process.send(command);
        self.process.stderr_line()
    }

    fn inspect(&mut self, id: u64) -> String {
        let canonical = self.control(&format!("inspect {id}"));
        assert!(canonical.starts_with("Resolved synthetic request: principal=local-uid-"));
        assert!(canonical.contains("mode=portable-workflow"));
        assert!(canonical.contains("credential=synthetic-fixture credential_version=1"));
        assert!(
            canonical.contains("effects=synthetic-read output=repository_id,issue_number,state")
        );
        assert_eq!(self.process.stderr_line(), "synthetic_control_ok");
        canonical
    }

    fn inspect_and_approve(&mut self, id: u64) {
        self.inspect(id);
        assert_eq!(
            self.control(&format!("approve {id}")),
            "synthetic_control_ok"
        );
    }

    fn stop(mut self) -> ProcessOutput {
        self.process.send("stop");
        let output = self.process.finish();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        output.assert_no_canary();
        assert!(
            !self.socket.exists(),
            "graceful stop must remove the owned socket"
        );
        assert!(
            !self.directory.exists(),
            "graceful stop must remove the owned directory"
        );
        output
    }
}

struct Mcp {
    process: Process,
    next_id: u64,
}

impl Mcp {
    fn start(socket: &Path) -> Self {
        let process = Process::spawn(&["mcp", "--socket", socket.to_str().unwrap()]);
        Self {
            process,
            next_id: 1,
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.process
            .send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string());
        let response = self.process.stdout_json();
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], id);
        response
    }

    fn initialize(&mut self) {
        let response = self.rpc(
            "initialize",
            json!({
                "protocolVersion":MCP_VERSION,
                "capabilities":{},
                // This misleading display label must never confer principal authority.
                "clientInfo":{"name":"human-approval-authority","version":"synthetic-test"}
            }),
        );
        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["protocolVersion"], MCP_VERSION);
        self.process
            .send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string());
    }

    fn call(&mut self, name: &str, arguments: Value) -> Response {
        let rpc = self.rpc("tools/call", json!({"name":name,"arguments":arguments}));
        assert!(rpc.get("error").is_none(), "expected a tool result: {rpc}");
        let text = rpc["result"]["content"][0]["text"].as_str().unwrap();
        let response: Response = serde_json::from_str(text).unwrap();
        assert_eq!(response.version, PROTOCOL_VERSION);
        assert_eq!(rpc["result"]["isError"], response.error.is_some());
        assert_ne!(response.result.is_some(), response.error.is_some());
        response
    }

    fn prepare(&mut self, request_id: &str, repository_id: u64, issue_number: u32) -> Response {
        self.call(
            "prepare_operation",
            json!({
                "request_id":request_id,"profile_id":"issue-status",
                "parameters":{"repository_id":repository_id,"issue_number":issue_number}
            }),
        )
    }

    fn handle(&mut self, method: &str, id: u64) -> Response {
        self.call(method, json!({"prepared_request_id":id}))
    }

    fn finish(self) -> ProcessOutput {
        let output = self.process.finish();
        assert!(output.status.success());
        output.assert_json_stdout();
        output.assert_no_canary();
        assert!(
            output.stderr.is_empty(),
            "MCP stderr must contain no workflow output"
        );
        output
    }
}

fn run_view(response: Response) -> RunView {
    assert_eq!(response.error, None);
    serde_json::from_value(response.result.unwrap()).unwrap()
}

fn envelope(method: &str, params: Value) -> Value {
    json!({"version":PROTOCOL_VERSION,"action":{"method":method,"params":params}})
}

fn prepared_envelope(request_id: &str) -> Value {
    envelope(
        "prepare_operation",
        json!({"request_id":request_id,"profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7}}),
    )
}

fn assert_bridge_error<T>(result: Result<T, ErrorCode>, expected: ErrorCode) {
    match result {
        Ok(_) => panic!("expected stable error {expected}"),
        Err(error) => assert_eq!(error, expected),
    }
}

#[test]
fn actual_mcp_subprocess_pauses_for_separate_control_review_then_resumes() {
    let root = TestDirectory::new();
    let mut broker = Broker::start(root.child("b"));
    let mut mcp = Mcp::start(&broker.socket);
    let before_initialize = mcp.rpc("tools/list", json!({}));
    assert_eq!(
        before_initialize["error"]["message"],
        "interaction_required"
    );
    mcp.initialize();
    let listed = mcp.rpc("tools/list", json!({}));
    let names: Vec<_> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "discover_operations",
            "prepare_operation",
            "request_approval",
            "invoke_approved",
            "get_run_status",
            "cancel"
        ]
    );
    let catalog = mcp.call("discover_operations", json!({}));
    assert_eq!(catalog.result.unwrap()["verified"], false);

    let prepared = run_view(mcp.prepare("subprocess-approved", 4242, 7));
    assert_eq!(prepared.prepared_request_id, 1);
    assert_eq!(prepared.state, Lifecycle::Prepared);
    assert_eq!(
        mcp.handle("invoke_approved", 1).error,
        Some(ErrorCode::ApprovalRequired)
    );
    assert_eq!(
        run_view(mcp.handle("request_approval", 1)).state,
        Lifecycle::AwaitingApproval
    );

    // Neither the agent's display label nor an agent-facing approval request is
    // a control decision. The only approving input below is broker stdin.
    let forged_control = mcp.rpc(
        "tools/call",
        json!({"name":"approve","arguments":{"prepared_request_id":1}}),
    );
    assert_eq!(forged_control["error"]["message"], "scope_denied");
    assert_eq!(broker.control("approve 1"), "approval_required");
    let canonical = broker.inspect(1);
    assert!(canonical.contains("resource=4242 issue=7 profile_revision=1"));
    assert!(canonical.contains("remaining_uses=20"));
    assert_eq!(broker.control("approve 1"), "synthetic_control_ok");
    let completed = run_view(mcp.handle("invoke_approved", 1));
    assert_eq!(completed.state, Lifecycle::Succeeded);
    assert_eq!(completed.result.as_ref().unwrap().repository_id, 4242);
    assert_eq!(completed.result.as_ref().unwrap().issue_number, 7);
    assert_eq!(run_view(mcp.handle("invoke_approved", 1)), completed);
    assert_eq!(
        run_view(mcp.prepare("subprocess-approved", 4242, 7)),
        completed
    );
    assert_eq!(
        mcp.prepare("subprocess-approved", 4242, 8).error,
        Some(ErrorCode::RequestIdConflict)
    );
    assert_eq!(
        mcp.prepare("subprocess-denied", 9000, 7).error,
        Some(ErrorCode::ScopeDenied)
    );
    assert_eq!(run_view(mcp.handle("get_run_status", 1)), completed);
    mcp.finish();
    broker.stop();
}

#[test]
fn canonical_review_must_be_repeated_when_the_available_budget_changes() {
    let root = TestDirectory::new();
    let mut broker = Broker::start(root.child("b"));
    let mut mcp = Mcp::start(&broker.socket);
    mcp.initialize();
    let first = run_view(mcp.prepare("review-first", 4242, 7)).prepared_request_id;
    let second = run_view(mcp.prepare("review-second", 4242, 8)).prepared_request_id;
    mcp.handle("request_approval", first);
    mcp.handle("request_approval", second);
    broker.inspect_and_approve(first);
    let review = broker.inspect(second);
    assert!(review.contains("remaining_uses=20"));
    assert_eq!(
        run_view(mcp.handle("invoke_approved", first)).state,
        Lifecycle::Succeeded
    );
    assert_eq!(
        broker.control(&format!("approve {second}")),
        "approval_required"
    );
    assert_eq!(
        run_view(mcp.handle("get_run_status", second)).state,
        Lifecycle::AwaitingApproval
    );
    assert!(broker.inspect(second).contains("remaining_uses=19"));
    assert_eq!(
        broker.control(&format!("approve {second}")),
        "synthetic_control_ok"
    );
    assert_eq!(
        run_view(mcp.handle("invoke_approved", second)).state,
        Lifecycle::Succeeded
    );
    mcp.finish();
    broker.stop();
}

#[test]
fn agent_socket_cannot_accept_approval_booleans_or_forged_principals() {
    let root = TestDirectory::new();
    let broker = Broker::start(root.child("b"));
    let mut bridge = SocketBridge::connect(&broker.socket).unwrap();
    let prepared = run_view(bridge.exchange(&prepared_envelope("forgery")));
    for action in [
        json!({"method":"approve","params":{"prepared_request_id":prepared.prepared_request_id}}),
        json!({"method":"prepare_operation","params":{"request_id":"forged-approved","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7},"approved":true}}),
        json!({"method":"prepare_operation","params":{"request_id":"forged-principal","profile_id":"issue-status","parameters":{"repository_id":4242,"issue_number":7},"principal":"human"}}),
    ] {
        let response = bridge.exchange(&json!({"version":PROTOCOL_VERSION,"action":action}));
        assert_eq!(response.error, Some(ErrorCode::InvalidRequest));
        assert_eq!(response.result, None);
    }
    assert_eq!(
        bridge
            .exchange(&envelope(
                "invoke_approved",
                json!({"prepared_request_id":prepared.prepared_request_id})
            ))
            .error,
        Some(ErrorCode::ApprovalRequired)
    );
    broker.stop();
}

#[test]
fn broker_restart_invalidates_old_socket_bridge_and_long_lived_mcp_authority() {
    let root = TestDirectory::new();
    let directory = root.child("b");
    let mut original = Broker::start(directory.clone());
    let mut bridge = SocketBridge::connect(&original.socket).unwrap();
    let mut mcp = Mcp::start(&original.socket);
    mcp.initialize();
    let id = run_view(mcp.prepare("restart-request", 4242, 7)).prepared_request_id;
    mcp.handle("request_approval", id);
    original.inspect_and_approve(id);
    original.stop();

    let restarted = Broker::start(directory);
    let old_run = envelope("invoke_approved", json!({"prepared_request_id":id}));
    assert_eq!(
        bridge.exchange(&old_run).error,
        Some(ErrorCode::PrincipalMismatch)
    );
    assert_eq!(
        mcp.handle("invoke_approved", id).error,
        Some(ErrorCode::PrincipalMismatch)
    );
    let mut fresh = SocketBridge::connect(&restarted.socket).unwrap();
    assert_eq!(fresh.exchange(&old_run).error, Some(ErrorCode::NotFound));
    let new_prepared = run_view(fresh.exchange(&prepared_envelope("restart-request")));
    assert_eq!(new_prepared.prepared_request_id, id);
    assert_eq!(new_prepared.state, Lifecycle::Prepared);
    assert_eq!(
        fresh.exchange(&old_run).error,
        Some(ErrorCode::ApprovalRequired)
    );
    mcp.finish();
    restarted.stop();
}

#[test]
fn headless_broker_without_explicit_synthetic_control_pipe_refuses_interaction() {
    let root = TestDirectory::new();
    let directory = root.child("b");
    let output = Process::spawn(&[
        "synthetic-broker",
        "--socket-dir",
        directory.to_str().unwrap(),
    ])
    .finish();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr.join(""), "interaction_required\n");
    output.assert_no_canary();
    assert!(!directory.exists());
}

#[test]
fn closing_synthetic_control_stdin_stops_broker_and_cleans_its_new_endpoint() {
    let root = TestDirectory::new();
    let broker = Broker::start(root.child("b"));
    let socket = broker.socket.clone();
    let directory = broker.directory.clone();
    let output = broker.process.finish();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    output.assert_no_canary();
    assert!(!socket.exists());
    assert!(!directory.exists());
}

fn assert_destination_refused(directory: &Path) {
    let output = Process::spawn(&[
        "synthetic-broker",
        "--socket-dir",
        directory.to_str().unwrap(),
        "--synthetic-control-pipe",
    ])
    .finish();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr.join(""), "invalid_request\n");
    output.assert_no_canary();
}

#[test]
fn existing_directory_is_preserved_instead_of_reused_or_overwritten() {
    let root = TestDirectory::new();
    let directory = root.child("existing");
    fs::create_dir(&directory).unwrap();
    let sentinel = directory.join("keep");
    fs::write(&sentinel, b"unrelated synthetic fixture").unwrap();
    assert_destination_refused(&directory);
    assert_eq!(fs::read(&sentinel).unwrap(), b"unrelated synthetic fixture");
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
}

#[test]
fn existing_file_is_preserved_instead_of_replaced_by_a_socket_directory() {
    let root = TestDirectory::new();
    let destination = root.child("file");
    fs::write(&destination, b"preserved synthetic fixture").unwrap();
    assert_destination_refused(&destination);
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"preserved synthetic fixture"
    );
}

#[test]
fn symlink_destination_and_symlink_ancestor_are_rejected_without_following_them() {
    let root = TestDirectory::new();
    let target = root.child("target");
    fs::create_dir(&target).unwrap();
    let sentinel = target.join("keep");
    fs::write(&sentinel, b"preserved synthetic target").unwrap();
    let link = root.child("link");
    symlink(&target, &link).unwrap();
    assert_destination_refused(&link);
    assert_destination_refused(&link.join("new"));
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserved synthetic target");
    assert!(!target.join("new").exists());
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn client_rejects_a_symlink_socket_before_connecting() {
    let root = TestDirectory::new();
    let broker = Broker::start(root.child("b"));
    let alias = broker.directory.join("alias.sock");
    symlink(&broker.socket, &alias).unwrap();
    assert_bridge_error(SocketBridge::connect(&alias), ErrorCode::InvalidRequest);
    fs::remove_file(alias).unwrap();
    broker.stop();
}

#[test]
fn client_rejects_a_socket_in_a_nonprivate_directory() {
    let root = TestDirectory::new();
    let directory = root.child("unprivate");
    fs::create_dir(&directory).unwrap();
    // Only a newly owned test fixture is changed; no operational permissions.
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    let socket = directory.join("agent.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    assert_bridge_error(SocketBridge::connect(&socket), ErrorCode::PrincipalMismatch);
}

#[test]
fn endpoint_creation_is_exclusive_private_and_cleanup_is_owned() {
    let root = TestDirectory::new();
    let directory = root.child("b");
    let endpoint = Endpoint::create(&directory).unwrap();
    let socket = endpoint.socket_path().to_path_buf();
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(&directory).unwrap().uid(),
        nix::unistd::geteuid().as_raw()
    );
    assert_bridge_error(Endpoint::create(&directory), ErrorCode::InvalidRequest);
    assert!(socket.exists());
    drop(endpoint);
    assert!(!socket.exists());
    assert!(!directory.exists());
    assert!(root.0.exists());
}

#[test]
fn both_sides_of_a_same_uid_socket_pair_authenticate_with_kernel_peer_identity() {
    let (first, second) = UnixStream::pair().unwrap();
    assert_eq!(authenticate_peer(&first), Ok(()));
    assert_eq!(authenticate_peer(&second), Ok(()));
    // A different-UID refusal requires a separate-identity platform harness.
    // These same-account tests intentionally make no containment claim.
}

#[test]
fn raw_socket_frames_use_the_same_operation_protocol_as_the_stdio_fixture() {
    let root = TestDirectory::new();
    let broker = Broker::start(root.child("b"));
    let stream = UnixStream::connect(&broker.socket).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    authenticate_peer(&stream).unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).unwrap();
    let greeting: Value = serde_json::from_str(&greeting).unwrap();
    assert_eq!(greeting["version"], PROTOCOL_VERSION);
    let mut frame = serde_json::to_vec(&prepared_envelope("raw-socket")).unwrap();
    frame.push(b'\n');
    reader.get_mut().write_all(&frame).unwrap();
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    let response: Response = serde_json::from_str(&response).unwrap();
    assert_eq!(run_view(response).state, Lifecycle::Prepared);
    drop(reader);
    broker.stop();
}

#[test]
fn relative_and_parent_traversal_endpoint_paths_are_rejected() {
    let root = TestDirectory::new();
    let child = root.child("existing");
    fs::create_dir(&child).unwrap();
    assert_bridge_error(
        Endpoint::create(Path::new("relative-aegis-test")),
        ErrorCode::InvalidRequest,
    );
    let traversal = child.join("..").join("escape");
    assert_bridge_error(Endpoint::create(&traversal), ErrorCode::InvalidRequest);
    assert!(!root.child("escape").exists());
}

#[test]
fn incomplete_socket_frame_at_eof_cannot_prepare_a_request() {
    let root = TestDirectory::new();
    let broker = Broker::start(root.child("b"));
    let stream = UnixStream::connect(&broker.socket).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).unwrap();
    reader
        .get_mut()
        .write_all(&serde_json::to_vec(&prepared_envelope("partial-eof")).unwrap())
        .unwrap();
    reader
        .get_mut()
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    let response: Response = serde_json::from_str(&response).unwrap();
    assert_eq!(response.error, Some(ErrorCode::InvalidRequest));
    let mut bridge = SocketBridge::connect(&broker.socket).unwrap();
    let response = bridge.exchange(&json!({"version":1,"action":{"method":"get_run_status","params":{"prepared_request_id":1}}}));
    assert_eq!(response.error, Some(ErrorCode::NotFound));
    drop(reader);
    broker.stop();
}

#[test]
fn trickling_partial_frames_release_all_connection_slots_at_the_frame_deadline() {
    let root = TestDirectory::new();
    let broker = Broker::start(root.child("b"));
    let mut held = Vec::new();
    for _ in 0..aegis::ipc::MAX_CONNECTIONS {
        let stream = UnixStream::connect(&broker.socket).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        let mut reader = BufReader::new(stream);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).unwrap();
        held.push(reader);
    }
    // Bytes arrive more often than the old syscall timeout. That must not
    // extend the absolute frame deadline or indefinitely occupy all slots.
    for _ in 0..10 {
        for reader in &mut held {
            let _ = reader.get_mut().write_all(b" ");
        }
        thread::sleep(Duration::from_millis(200));
    }
    for reader in &mut held {
        let mut byte = [0];
        match std::io::Read::read(reader, &mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("incomplete frame should have closed: {other:?}"),
        }
    }
    let mut bridge = SocketBridge::connect(&broker.socket).unwrap();
    assert!(bridge
        .exchange(&json!({"version":1,"action":{"method":"discover_operations"}}))
        .result
        .is_some());
    drop(held);
    broker.stop();
}

#[test]
fn overlong_socket_path_is_rejected_before_creating_its_directory() {
    let root = TestDirectory::new();
    let directory = root.child(&"x".repeat(aegis::ipc::MAX_SOCKET_PATH_BYTES));
    assert_bridge_error(Endpoint::create(&directory), ErrorCode::InvalidRequest);
    assert!(!directory.exists());
}

#[test]
fn bridge_rejects_an_unterminated_greeting() {
    let root = TestDirectory::new();
    let directory = root.child("b");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .write_all(br#"{"version":1,"session_epoch":"00000000000000000000000000000000"}"#)
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let _ = std::io::Read::read(&mut stream, &mut [0]);
    });
    assert_bridge_error(
        SocketBridge::connect(&socket),
        ErrorCode::InvalidProviderResult,
    );
    worker.join().unwrap();
}

#[test]
fn bridge_rejects_an_unterminated_broker_response() {
    let root = TestDirectory::new();
    let directory = root.child("b");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        for connection in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            stream
                .write_all(
                    b"{\"version\":1,\"session_epoch\":\"00000000000000000000000000000000\"}\n",
                )
                .unwrap();
            if connection == 1 {
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                reader
                    .get_mut()
                    .write_all(br#"{"version":1,"result":{},"error":null}"#)
                    .unwrap();
                reader
                    .get_mut()
                    .shutdown(std::net::Shutdown::Write)
                    .unwrap();
                let _ = std::io::Read::read(&mut reader, &mut [0]);
            } else {
                stream.shutdown(std::net::Shutdown::Write).unwrap();
                let _ = std::io::Read::read(&mut stream, &mut [0]);
            }
        }
    });
    let mut bridge = SocketBridge::connect(&socket).unwrap();
    assert_eq!(
        bridge
            .exchange(&json!({"version":1,"action":{"method":"discover_operations"}}))
            .error,
        Some(ErrorCode::InvalidProviderResult)
    );
    worker.join().unwrap();
}

#[test]
fn unterminated_control_command_at_eof_cannot_approve() {
    let root = TestDirectory::new();
    let mut broker = Broker::start(root.child("b"));
    let mut bridge = SocketBridge::connect(&broker.socket).unwrap();
    let id = run_view(bridge.exchange(&prepared_envelope("control-eof"))).prepared_request_id;
    bridge.exchange(&json!({"version":1,"action":{"method":"request_approval","params":{"prepared_request_id":id}}}));
    broker.inspect(id);
    let mut input = broker.process.input.take().unwrap();
    input.write_all(format!("approve {id}").as_bytes()).unwrap();
    input.flush().unwrap();
    drop(input);
    let output = broker.process.finish();
    assert!(output.status.success());
    assert_eq!(
        output
            .stderr
            .iter()
            .filter(|line| line.trim() == "synthetic_control_ok")
            .count(),
        1
    );
    output.assert_no_canary();
    assert!(!broker.socket.exists());
    assert!(!broker.directory.exists());
}
