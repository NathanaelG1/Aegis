//! Ordinary functional acceptance checks for the fixed composed canary drill.
//! These neither resume an independent review nor establish protected custody,
//! independent human presence, same-UID isolation, or readiness for real keys.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 8 * 1024;
const WAIT: Duration = Duration::from_secs(30);
const INPUT_MARKER: &str = "AEGIS_TEST_UNUSED_INPUT_NOT_A_CREDENTIAL";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        // Resolve the platform's temporary directory before using the fixture's
        // normalized, absolute, no-symlink destination contract.
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let path = parent.join(format!(
                "aegis-composed-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("cannot create composed acceptance fixture directory"),
            }
        }
        panic!("cannot allocate a fresh composed acceptance fixture directory");
    }

    fn root(&self) -> PathBuf {
        self.0.join("fixture")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-composed-canary"));
        command.current_dir(&self.0);
        command
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn capture(reader: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if reader
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .is_ok()
        {
            let _ = sender.send(bytes);
        }
    });
    receiver
}

fn run(command: &mut Command, input: Option<&[u8]>) -> Output {
    command
        .env_clear()
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = Running(command.spawn().expect("cannot start fixture binary"));
    let stdout = capture(process.0.stdout.take().unwrap());
    let stderr = capture(process.0.stderr.take().unwrap());
    if let Some(bytes) = input {
        // Small synthetic input only; the public drill has no stdin input API.
        // BrokenPipe is also acceptable if the child has already refused it.
        let result = process.0.stdin.take().unwrap().write_all(bytes);
        assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::BrokenPipe);
    }
    let deadline = Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "fixture process did not finish");
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout
        .recv_timeout(Duration::from_secs(1))
        .expect("fixture stdout did not close");
    let stderr = stderr
        .recv_timeout(Duration::from_secs(1))
        .expect("fixture stderr did not close");
    assert!(
        stdout.len() <= MAX_OUTPUT,
        "fixture stdout exceeded its bound"
    );
    assert!(
        stderr.len() <= MAX_OUTPUT,
        "fixture stderr exceeded its bound"
    );
    Output {
        status,
        stdout,
        stderr,
    }
}

fn contains(bytes: &[u8], value: &[u8]) -> bool {
    bytes.windows(value.len()).any(|window| window == value)
}

fn assert_no_canary(bytes: &[u8]) {
    for forbidden in [
        "AEGIS_DISPOSABLE_PROTECTED_ENTRY_CANARY",
        "AEGIS_SYNTHETIC_DELIVERY_CANARY",
        "aegis-disposable-tls-canary-not-a-real-secret",
        INPUT_MARKER,
    ] {
        assert!(
            !contains(bytes, forbidden.as_bytes()),
            "fixture data escaped into an observable output"
        );
    }
}

fn assert_safe_output(output: &Output, root: &Path) {
    for bytes in [&output.stdout, &output.stderr] {
        assert_no_canary(bytes);
        for forbidden in [
            "AGE-SECRET-KEY",
            "BEGIN PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
        ] {
            assert!(
                !contains(bytes, forbidden.as_bytes()),
                "private key material escaped into process output"
            );
        }
        assert!(
            !contains(bytes, root.to_str().unwrap().as_bytes()),
            "process output included the fixture path"
        );
    }
}

fn assert_refused(output: &Output, root: &Path) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert_safe_output(output, root);
}

#[test]
fn main_cli_has_no_composed_or_secret_input_command() {
    let directory = Directory::new();
    for verb in ["composed-canary", "import-secret"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis"));
        command
            .current_dir(&directory.0)
            .arg(verb)
            .arg(directory.root());
        assert_refused(
            &run(&mut command, Some(INPUT_MARKER.as_bytes())),
            &directory.root(),
        );
        assert!(!directory.root().exists());
    }
}

#[cfg(not(all(unix, feature = "vault-spike")))]
#[test]
fn composed_drill_refuses_without_unix_vault_feature() {
    let directory = Directory::new();
    for inspect in [false, true] {
        let mut command = directory.command();
        if inspect {
            command.arg("inspect");
        }
        command.arg(directory.root());
        let output = run(&mut command, Some(INPUT_MARKER.as_bytes()));
        assert_eq!(output.status.code(), Some(2));
        assert_refused(&output, &directory.root());
        assert!(!directory.root().exists());
    }
}

#[cfg(all(unix, feature = "vault-spike"))]
mod unix {
    use super::*;
    use serde_json::{json, Value};
    use std::{collections::BTreeMap, ffi::OsString, os::unix::fs::symlink};

    #[derive(Debug, Eq, PartialEq)]
    enum Entry {
        Directory,
        File(Vec<u8>),
    }

    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
            assert!(entries.len() < 64, "fixture exceeded its file count bound");
            let metadata = fs::symlink_metadata(path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if metadata.is_dir() {
                entries.insert(relative, Entry::Directory);
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), entries);
                }
            } else {
                assert!(metadata.is_file(), "fixture produced a non-file artifact");
                assert!(
                    metadata.len() <= 2 * 1024 * 1024,
                    "fixture file is unbounded"
                );
                entries.insert(relative, Entry::File(fs::read(path).unwrap()));
            }
        }
        let mut entries = BTreeMap::new();
        visit(root, root, &mut entries);
        entries
    }

    fn report(output: &Output, root: &Path) -> Value {
        assert_safe_output(output, root);
        assert!(output.status.success(), "composed fixture failed");
        assert!(output.stderr.is_empty());
        serde_json::from_slice(&output.stdout).expect("fixture must emit exactly one JSON report")
    }

    fn assert_read_only_inspection(directory: &Directory) {
        let root = directory.root();
        let before = snapshot(&root);
        let output = run(directory.command().arg("inspect").arg(&root), None);
        assert_eq!(
            report(&output, &root),
            json!({
                "synthetic_only": true,
                "input_import_bound": true,
                "consumed_uses": 1,
                "incomplete_deliveries": 0,
                "unknown_deliveries": 0,
                "remaining_uses": 3,
                "recipient_generation": 1,
                "revoked": true,
                "restored_sessions": 0,
                "automatic_retry_allowed": false,
                "workflow_mode": "UNISOLATED",
                "protected_custody_verified": false,
                "protected_deployment_verified": false,
                "ready_for_real_keys": false
            })
        );
        assert_eq!(snapshot(&root), before, "inspection changed fixture files");
        assert_no_recipient_process(&root);
    }

    #[cfg(target_os = "linux")]
    fn assert_no_recipient_process(root: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let executable = fs::canonicalize(env!("CARGO_BIN_EXE_aegis-composed-canary")).unwrap();
        for entry in fs::read_dir("/proc").unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().parse::<u32>().is_err()
                || fs::read_link(entry.path().join("exe")).ok().as_ref() != Some(&executable)
            {
                continue;
            }
            if let Ok(command) = fs::read(entry.path().join("cmdline")) {
                assert!(
                    !contains(&command, root.as_os_str().as_bytes()),
                    "a composed fixture process survived completion"
                );
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn assert_no_recipient_process(_: &Path) {}

    #[test]
    fn imported_ciphertext_reaches_child_through_approved_tls_flow() {
        let directory = Directory::new();
        let root = directory.root();
        let output = run(
            directory.command().arg(&root),
            Some(INPUT_MARKER.as_bytes()),
        );
        assert_eq!(
            report(&output, &root),
            json!({
                "synthetic_only": true,
                "input_import_bound": true,
                "authenticated_role_channels": 2,
                "tls13_mutual_authentication_verified": true,
                "separate_recipient_process": true,
                "bootstrap_in_child": true,
                "broker_loaded_recipient_private_keys": false,
                "unauthenticated_agent_denied": true,
                "unauthenticated_admin_denied": true,
                "completed_deliveries": 1,
                "consumed_uses": 1,
                "remaining_uses": 3,
                "recipient_generation": 1,
                "duplicate_reused": true,
                "cold_start_required_authentication": true,
                "revocation_survived_restart": true,
                "revoked": true,
                "agent_transcript_contains_canary": false,
                "restored_sessions": 0,
                "automatic_retry_allowed": false,
                "workflow_mode": "UNISOLATED",
                "independent_human_presence_verified": false,
                "protected_custody_verified": false,
                "protected_deployment_verified": false,
                "ready_for_real_keys": false
            })
        );
        let imported = fs::read(root.join("input/record.age")).unwrap();
        assert!(imported.starts_with(b"age-encryption.org/v1\n"));
        assert_eq!(imported, fs::read(root.join("vault/secret-1.age")).unwrap());
        assert!(!root.join("vault/secret-2.age").exists());
        assert!(!root.join("input/record.pending").exists());
        assert!(!root.join("custody/fixture-keys.json").exists());
        assert!(!fs::read(root.join("recipient/accepted.jws"))
            .unwrap()
            .is_empty());
        let before = snapshot(&root);
        for entry in before.values() {
            if let Entry::File(bytes) = entry {
                // Disposable role keys are intentionally persisted by custody;
                // this checks the imported value, not a protected key store.
                assert_no_canary(bytes);
            }
        }
        assert_no_recipient_process(&root);
        // This invokes the actual executable again, after the drill process and
        // all its in-memory sessions have terminated.
        assert_read_only_inspection(&directory);

        let repeated = run(directory.command().arg(&root), None);
        assert_eq!(repeated.status.code(), Some(2));
        assert_refused(&repeated, &root);
        assert_eq!(
            snapshot(&root),
            before,
            "retry changed retained fixture data"
        );
        assert_no_recipient_process(&root);
    }

    #[test]
    fn cold_inspection_refuses_missing_or_corrupt_imported_ciphertext() {
        let directory = Directory::new();
        let root = directory.root();
        report(&run(directory.command().arg(&root), None), &root);
        let original = snapshot(&root);
        for relative in ["input/record.age", "vault/secret-1.age"] {
            let file = root.join(relative);
            let saved = directory.0.join("saved-ciphertext");
            let bytes = fs::read(&file).unwrap();
            // Removing either side is an ordinary interrupted/missing-artifact
            // case at the supported read-only inspection stage.
            fs::rename(&file, &saved).unwrap();
            let missing = snapshot(&root);
            let output = run(directory.command().arg("inspect").arg(&root), None);
            assert_eq!(output.status.code(), Some(2));
            assert_refused(&output, &root);
            assert_eq!(snapshot(&root), missing);
            assert_no_recipient_process(&root);
            fs::rename(&saved, &file).unwrap();

            let mut corrupted = bytes.clone();
            corrupted[0] ^= 1;
            fs::write(&file, &corrupted).unwrap();
            let damaged = snapshot(&root);
            let output = run(directory.command().arg("inspect").arg(&root), None);
            assert_eq!(output.status.code(), Some(2));
            assert_refused(&output, &root);
            assert_eq!(snapshot(&root), damaged);
            assert_no_recipient_process(&root);
            fs::write(&file, &bytes).unwrap();
            assert_eq!(snapshot(&root), original);
            assert_read_only_inspection(&directory);
        }
    }

    #[test]
    fn inspection_of_absent_fixture_creates_nothing() {
        let directory = Directory::new();
        let root = directory.root();
        let output = run(directory.command().arg("inspect").arg(&root), None);
        assert_eq!(output.status.code(), Some(2));
        assert_refused(&output, &root);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
        assert_no_recipient_process(&root);
    }

    #[test]
    fn malformed_arguments_refuse_without_creating_fixture_or_echoing_input() {
        let directory = Directory::new();
        let root = directory.root();
        let root_arg = root.as_os_str().to_owned();
        let cases: Vec<Vec<OsString>> = vec![
            vec![],
            vec![root_arg.clone(), INPUT_MARKER.into()],
            vec!["--secret".into(), INPUT_MARKER.into()],
            vec!["deliver".into(), root_arg.clone()],
            vec!["inspect".into()],
            vec!["inspect".into(), root_arg, INPUT_MARKER.into()],
            vec!["relative-root".into()],
        ];
        for args in cases {
            let output = run(
                directory.command().args(args),
                Some(INPUT_MARKER.as_bytes()),
            );
            assert_eq!(output.status.code(), Some(2));
            assert_refused(&output, &root);
            assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
        }
    }

    #[test]
    fn existing_file_directory_and_symlink_are_never_overwritten() {
        let directory = Directory::new();
        let file = directory.0.join("existing-file");
        fs::write(&file, b"keep existing fixture file").unwrap();
        let occupied = directory.0.join("existing-directory");
        fs::create_dir(&occupied).unwrap();
        fs::write(
            occupied.join("sentinel"),
            b"keep existing fixture directory",
        )
        .unwrap();
        let empty = directory.0.join("empty-directory");
        fs::create_dir(&empty).unwrap();
        let link = directory.0.join("linked-directory");
        symlink(&occupied, &link).unwrap();
        let before = fs::read(occupied.join("sentinel")).unwrap();
        for root in [&file, &occupied, &empty, &link] {
            let output = run(directory.command().arg(root), None);
            assert_eq!(output.status.code(), Some(2));
            assert_refused(&output, root);
            assert_eq!(fs::read(&file).unwrap(), b"keep existing fixture file");
            assert_eq!(fs::read(occupied.join("sentinel")).unwrap(), before);
            assert_eq!(fs::read_dir(&occupied).unwrap().count(), 1);
            assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
            assert_eq!(fs::read_link(&link).unwrap(), occupied);
            assert_no_recipient_process(root);
        }
    }
}
