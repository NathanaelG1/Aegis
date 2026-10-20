#![cfg(all(feature = "proxy", unix))]
//! Drive the actual executable through a pseudo-terminal, with disposable keys only.
use aegis::proxy::Broker;
use nix::{
    pty::{openpty, Winsize},
    sys::termios,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
struct Console {
    root: PathBuf,
    child: Child,
    input: File,
    slave: File,
    saved: termios::Termios,
    output: Receiver<Vec<u8>>,
    captured: Vec<u8>,
}
impl Console {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "aegis-tui-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let pty = openpty(
            Some(&Winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            None,
        )
        .unwrap();
        let input = File::from(pty.master);
        let slave = File::from(pty.slave);
        let saved = termios::tcgetattr(&slave).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_aegis"))
            .args(["tui", "--state-dir"])
            .arg(root.join("state"))
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let mut reader = input.try_clone().unwrap();
        let (tx, output) = mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = [0; 8192];
            while let Ok(n) = reader.read(&mut bytes) {
                if n == 0 || tx.send(bytes[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            root,
            child,
            input,
            slave,
            saved,
            output,
            captured: Vec::new(),
        }
    }
    fn wait(&mut self, text: &str) {
        let until = Instant::now() + Duration::from_secs(8);
        let mut recent = String::new();
        while Instant::now() < until {
            if let Ok(bytes) = self.output.recv_timeout(Duration::from_millis(100)) {
                recent.push_str(&String::from_utf8_lossy(&bytes));
                self.captured.extend(bytes);
                if recent.contains(text) {
                    return;
                }
            }
        }
        panic!("terminal did not reach {text:?}; last view: {recent}");
    }
    fn key(&mut self, text: &str) {
        self.input.write_all(text.as_bytes()).unwrap();
        self.input.flush().unwrap();
    }
    fn fill(&mut self, text: &str) {
        self.key(&format!("\u{15}\u{1b}[200~{text}\u{1b}[201~\r"));
    }
    fn initialize(&mut self) {
        self.wait("Welcome to Aegis");
        self.key("\r");
        self.wait("Create your vault");
        self.key("j\r");
        self.wait("Your vault is ready");
        self.key("\r");
        self.wait("Your workspace");
    }
    fn exit(&mut self) {
        self.key("\u{3}");
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < until, "TUI did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
        while let Ok(bytes) = self.output.try_recv() {
            self.captured.extend(bytes);
        }
        let restored = termios::tcgetattr(&self.slave).unwrap();
        let modes = termios::LocalFlags::ECHO
            | termios::LocalFlags::ICANON
            | termios::LocalFlags::ISIG
            | termios::LocalFlags::IEXTEN;
        assert_eq!(restored.local_flags & modes, self.saved.local_flags & modes);
        assert_eq!(restored.input_flags, self.saved.input_flags);
        assert_eq!(restored.output_flags, self.saved.output_flags);
        assert!(String::from_utf8_lossy(&self.captured).contains("\u{1b}[?1049l"));
    }
}
impl Drop for Console {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn guided_setup_persists_real_policy_without_displaying_secret() {
    let mut ui = Console::new();
    ui.initialize();
    ui.key("\r");
    ui.wait("Name your secret");
    ui.fill("provider-key");
    ui.wait("Enter secret value");
    let canary = "DISPOSABLE_TUI_CANARY_9327";
    ui.fill(canary);
    ui.wait("Secret saved");
    ui.key("\r");
    ui.wait("Your workspace");
    ui.key("jj\r");
    ui.wait("Name your service");
    ui.fill("worker");
    ui.wait("Policy for worker");
    ui.key("\r");
    ui.wait("Operation name");
    ui.fill("send");
    ui.wait("Approved HTTPS endpoint");
    ui.fill("https://example.invalid/v1/messages");
    ui.wait("HTTP method");
    ui.key("j\r");
    ui.wait("Choose a secret");
    ui.key("\r");
    ui.wait("How does the API accept");
    ui.key("\r");
    ui.wait("Configure send");
    ui.key("\r");
    ui.wait("Policy for worker");
    ui.key("jjjj\r");
    ui.wait("Review service access");
    ui.key("\r");
    ui.wait("Save this policy?");
    ui.key("j\r");
    ui.wait("Service ready");
    ui.key("\r");
    ui.wait("Connect your application");
    ui.key("\r");
    ui.wait("Your workspace");
    let status = Broker::open(&ui.root.join("state"))
        .unwrap()
        .status()
        .unwrap();
    assert_eq!(status["services"][0]["name"], "worker");
    assert_eq!(
        status["services"][0]["policy"]["operations"]["send"]["method"],
        "POST"
    );
    assert_eq!(
        status["services"][0]["policy"]["operations"]["send"]["secrets"]["provider-key"]["prefix"],
        "Bearer "
    );
    // The actual endpoint is persisted; the UI never contacted it.
    assert_eq!(status["services"][0]["used"], 0);
    // Reopen an existing POST operation and accept its defaults: editing must
    // preserve the method and permissions, rather than silently selecting GET.
    ui.key("jjj\r");
    ui.wait("Your services");
    ui.key("\r");
    ui.wait("Manage permissions");
    ui.key("\r");
    ui.wait("Policy for worker");
    ui.key("j\r");
    ui.wait("Edit operation");
    ui.key("\r");
    ui.wait("Operation name");
    ui.key("\r");
    ui.wait("Approved HTTPS endpoint");
    ui.key("\r");
    ui.wait("HTTP method");
    ui.key("\r");
    ui.wait("Configure send");
    ui.key("\r");
    ui.wait("Policy for worker");
    ui.key("jjjj\r");
    ui.wait("Review service access");
    ui.key("\r");
    ui.wait("Save this policy?");
    ui.key("j\r");
    ui.wait("Service ready");
    ui.key("\r");
    ui.wait("Connect your application");
    ui.key("\r");
    ui.wait("Your workspace");
    assert_eq!(
        Broker::open(&ui.root.join("state"))
            .unwrap()
            .status()
            .unwrap(),
        status
    );
    let token = fs::read_to_string(ui.root.join("state/worker.token")).unwrap();
    ui.exit();
    let capture = String::from_utf8_lossy(&ui.captured);
    assert!(!capture.contains(canary));
    assert!(!capture.contains(&token));
    assert!(!fs::read(ui.root.join("state/vault.age"))
        .unwrap()
        .windows(canary.len())
        .any(|w| w == canary.as_bytes()));
}
#[test]
fn cancellation_pasted_newlines_resize_and_terminal_restoration() {
    let mut ui = Console::new();
    ui.initialize();
    ui.key("\r");
    ui.wait("Name your secret");
    ui.fill("cancel-me");
    ui.wait("Enter secret value");
    ui.key("\u{1b}[200~DISPOSABLE_CANCELLED_VALUE\njjjj\n\u{1b}[201~");
    ui.wait("value entered - hidden");
    ui.key("\u{3}");
    ui.wait("Your workspace");
    assert_eq!(
        Broker::open(&ui.root.join("state"))
            .unwrap()
            .status()
            .unwrap()["secrets"],
        serde_json::json!([])
    );
    ui.key("\u{1b}[16;40R");
    ui.wait("A E G I S");
    ui.exit();
    assert!(!String::from_utf8_lossy(&ui.captured).contains("DISPOSABLE_CANCELLED_VALUE"));
}
#[test]
fn explicit_ui_fails_without_terminal_and_default_output_remains_scriptable() {
    let result = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .arg("tui")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!result.stdout.contains(&27));
    let help = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(!help.stdout.contains(&27));
}

#[test]
fn proxy_started_by_console_stops_when_owner_exits() {
    let mut ui = Console::new();
    ui.initialize();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    ui.key("jjjj\r");
    ui.wait("Start local proxy");
    ui.fill(&address.port().to_string());
    ui.wait("Proxy is running");
    ui.key("\r");
    ui.wait("Your workspace");
    assert!(std::net::TcpStream::connect(address).is_ok());
    ui.key("\u{3}");
    ui.wait("Stop proxy and exit?");
    ui.key("j\r");
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if ui.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(std::net::TcpStream::connect(address).is_err());
    let restored = termios::tcgetattr(&ui.slave).unwrap();
    assert!(restored
        .local_flags
        .contains(termios::LocalFlags::ECHO | termios::LocalFlags::ICANON));
}

#[test]
fn overlong_secret_paste_is_rejected_instead_of_silently_truncated() {
    let mut ui = Console::new();
    ui.initialize();
    ui.key("\r");
    ui.wait("Name your secret");
    ui.fill("too-long");
    ui.wait("Enter secret value");
    ui.fill(&"x".repeat(4100));
    ui.wait("Input is too long");
    assert_eq!(
        Broker::open(&ui.root.join("state"))
            .unwrap()
            .status()
            .unwrap()["secrets"],
        serde_json::json!([])
    );
    ui.key("\u{3}");
    ui.wait("Your workspace");
    ui.exit();
}
