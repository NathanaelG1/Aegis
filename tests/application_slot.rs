//! Ordinary functional acceptance checks for the fixed dummy application slot.
//! These neither resume an independent review nor establish protected custody,
//! independent human presence, same-UID isolation, or readiness for real keys.
//! Plaintext installation into the one dummy application file is intentional;
//! encrypted recipient acceptance alone does not satisfy these checks.

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
const WAIT: Duration = Duration::from_secs(60);
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
                "aegis-application-slot-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("cannot create application slot acceptance fixture directory"),
            }
        }
        panic!("cannot allocate a fresh application slot acceptance fixture directory");
    }

    fn root(&self) -> PathBuf {
        self.0.join("fixture")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-application-slot"));
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
fn main_cli_has_no_application_slot_or_secret_input_command() {
    let directory = Directory::new();
    for verb in ["application-slot", "import-secret"] {
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

#[cfg(not(all(unix, feature = "application-slot")))]
#[test]
fn application_slot_refuses_without_unix_application_slot_feature() {
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

#[test]
fn malformed_arguments_refuse_without_creating_fixture_or_echoing_input() {
    use std::ffi::OsString;
    let directory = Directory::new();
    let root = directory.root();
    let root_arg = root.as_os_str().to_owned();
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec![root_arg.clone(), INPUT_MARKER.into()],
        vec!["--secret".into(), INPUT_MARKER.into()],
        vec!["--slot".into(), INPUT_MARKER.into()],
        vec!["--path".into(), INPUT_MARKER.into()],
        vec!["--executable".into(), INPUT_MARKER.into()],
        vec!["--command".into(), INPUT_MARKER.into()],
        vec!["--listen".into(), INPUT_MARKER.into()],
        vec!["--fault".into(), INPUT_MARKER.into()],
        vec!["--ready-for-real-keys".into(), root_arg.clone()],
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

#[cfg(all(unix, feature = "application-slot"))]
mod unix {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::{json, Value};
    use std::{
        collections::BTreeMap,
        os::unix::fs::{symlink, MetadataExt},
    };

    const SLOT: &str = "application/provider-auth";
    const RECEIPTS: &str = "application/installation.jws";
    const STAGE: &str = "application/.provider-auth.stage";

    #[derive(Eq, PartialEq)]
    struct Entry {
        // Ignore access time: inspection necessarily reads these artifacts.
        device: u64,
        inode: u64,
        mode: u32,
        modified: (i64, i64),
        bytes: Option<Vec<u8>>,
    }

    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
            assert!(entries.len() < 128, "fixture exceeded its file count bound");
            let metadata = fs::symlink_metadata(path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let bytes = if metadata.is_dir() {
                None
            } else {
                assert!(metadata.is_file(), "fixture produced a non-file artifact");
                assert!(
                    metadata.len() <= 2 * 1024 * 1024,
                    "fixture file is unbounded"
                );
                Some(fs::read(path).unwrap())
            };
            entries.insert(
                relative,
                Entry {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    mode: metadata.mode(),
                    modified: (metadata.mtime(), metadata.mtime_nsec()),
                    bytes,
                },
            );
            if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), entries);
                }
            }
        }
        let mut entries = BTreeMap::new();
        visit(root, root, &mut entries);
        entries
    }

    fn report(output: &Output, root: &Path) -> Value {
        assert_safe_output(output, root);
        assert!(output.status.success(), "application slot fixture failed");
        assert!(output.stderr.is_empty());
        serde_json::from_slice(&output.stdout).expect("fixture must emit exactly one JSON report")
    }

    fn signed_payload(token: &str) -> Value {
        // Decode public evidence to check its meaning. This is not signature
        // verification; the fresh-process inspector must authenticate it.
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "evidence is not compact JWS");
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({"alg": "RS256", "typ": "JWT"}));
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 256);
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        assert_no_canary(&payload);
        serde_json::from_slice(&payload).unwrap()
    }

    fn digest(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD
            .encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref())
    }

    fn installation_records(root: &Path) -> Vec<String> {
        let journal = fs::read_to_string(root.join(RECEIPTS)).unwrap();
        assert!(
            journal.ends_with('\n'),
            "installation journal has a partial record"
        );
        let lines: Vec<String> = journal.lines().map(str::to_owned).collect();
        assert_eq!(
            lines.len(),
            3,
            "duplicate delivery added installation journal records"
        );
        lines
    }

    fn assert_installation_tuple(root: &Path) {
        let lines = installation_records(root);
        let records: Vec<_> = lines.iter().map(|line| signed_payload(line)).collect();
        let application = fs::metadata(root.join("application")).unwrap();
        let manifest = signed_payload(
            fs::read_to_string(root.join("vault/manifest.jws"))
                .unwrap()
                .trim(),
        );
        for (index, (record, event)) in records
            .iter()
            .zip(["genesis", "intent", "complete"])
            .enumerate()
        {
            assert_eq!(record["schema"], 1);
            assert_eq!(
                record["kind"],
                "aegis.synthetic.application-slot.journal.v1"
            );
            assert_eq!(record["slot"], "provider-auth");
            assert_eq!(record["vault_id"], manifest["vault_id"]);
            assert_eq!(record["directory_device"], application.dev());
            assert_eq!(record["directory_inode"], application.ino());
            assert_eq!(record["event"]["type"], event);
            if index > 0 {
                assert_eq!(
                    record["sequence"].as_u64().unwrap(),
                    records[index - 1]["sequence"].as_u64().unwrap() + 1
                );
                assert_eq!(record["previous"], digest(lines[index - 1].as_bytes()));
            }
        }
        let receipt = signed_payload(records[2]["event"]["receipt"].as_str().unwrap());
        let ack = &receipt["ack"];
        assert_eq!(ack["schema"], 1);
        assert_eq!(ack["kind"], "aegis.synthetic.application-slot.installed.v1");
        assert_eq!(ack["vault_id"], manifest["vault_id"]);
        assert!(!ack["delivery_id"].as_str().unwrap().is_empty());
        assert_eq!(ack["version"], 1);
        assert_eq!(ack["generation"], 1);
        assert_eq!(
            ack["recipient"],
            json!({
                "id": "synthetic-recipient",
                "revision": 1,
                "configuration_revision": 1,
                "slot": "provider-auth"
            })
        );
        assert_eq!(ack["recipient"], receipt["profile"]["recipient"]);
        assert_eq!(
            receipt["profile"]["secret"],
            json!({"id": "synthetic-provider-key", "version": 1})
        );
        assert_eq!(receipt["profile"]["repository_id"], 4242);
        assert_eq!(receipt["prior_generation"], 0);
        assert_eq!(receipt["slot_filename"], "provider-auth");
        assert_eq!(
            receipt["file_digest"],
            digest(&fs::read(root.join(SLOT)).unwrap())
        );
        assert_eq!(receipt["directory_device"], application.dev());
        assert_eq!(receipt["directory_inode"], application.ino());
        assert_eq!(receipt["durability"], "file-sync-rename-directory-sync-v1");
    }

    fn assert_closed_report(value: &Value) {
        for field in [
            "synthetic_only",
            "input_import_bound",
            "installation_receipt_verified",
            "handle_relative_operations",
            "revoked",
        ] {
            assert_eq!(value[field], true, "{field}");
        }
        for field in [
            "automatic_retry_allowed",
            "protected_custody_verified",
            "protected_deployment_verified",
            "ready_for_real_keys",
        ] {
            assert_eq!(value[field], false, "{field}");
        }
        for (field, expected) in [
            ("completed_installations", 1),
            ("consumed_uses", 1),
            ("remaining_uses", 3),
            ("recipient_generation", 1),
            ("installed_version", 1),
            ("incomplete_installations", 0),
            ("restored_sessions", 0),
        ] {
            assert_eq!(value[field], expected, "{field}");
        }
        assert_eq!(value["application_slot"], "provider-auth");
        assert_eq!(value["workflow_mode"], "UNISOLATED");
    }

    fn assert_read_only_inspection(directory: &Directory) {
        let root = directory.root();
        let before = snapshot(&root);
        // Every call starts a fresh executable after the previous fixture's
        // broker, recipient and in-memory authority have exited.
        let output = run(directory.command().arg("inspect").arg(&root), None);
        let value = report(&output, &root);
        assert_closed_report(&value);
        assert_eq!(value["incomplete_deliveries"], 0);
        assert_eq!(value["unknown_deliveries"], 0);
        assert!(
            snapshot(&root) == before,
            "inspection changed fixture bytes or metadata"
        );
        assert_no_fixture_process(&root);
    }

    fn assert_read_only_refusal(directory: &Directory) {
        let root = directory.root();
        let before = snapshot(&root);
        let output = run(directory.command().arg("inspect").arg(&root), None);
        assert_eq!(output.status.code(), Some(2));
        assert_refused(&output, &root);
        assert!(
            snapshot(&root) == before,
            "failed inspection changed fixture bytes or metadata"
        );
        assert_no_fixture_process(&root);
    }

    #[test]
    fn compiled_canary_is_installed_and_retained_after_revoke() {
        let directory = Directory::new();
        let root = directory.root();
        let output = run(
            directory.command().arg(&root),
            Some(INPUT_MARKER.as_bytes()),
        );
        let value = report(&output, &root);
        assert_closed_report(&value);
        for field in [
            "duplicate_reused",
            "cold_start_required_authentication",
            "revocation_survived_restart",
        ] {
            assert_eq!(value[field], true, "{field}");
        }
        assert_eq!(value["agent_transcript_contains_canary"], false);

        // Success means the fixed dummy application actually receives these
        // compiled bytes. An encrypted capsule/acceptance record is insufficient.
        assert!(
            fs::read(root.join(SLOT)).unwrap()
                == b"AEGIS_SYNTHETIC_DELIVERY_CANARY_VERSION_ONE_NOT_VALID"
        );
        assert!(!root.join(STAGE).exists());
        assert_installation_tuple(&root);
        let imported = fs::read(root.join("input/record.age")).unwrap();
        assert!(imported.starts_with(b"age-encryption.org/v1\n"));
        assert!(imported == fs::read(root.join("vault/secret-1.age")).unwrap());
        assert!(!root.join("vault/secret-2.age").exists());
        assert!(!root.join("input/record.pending").exists());
        assert!(!root.join("custody/fixture-keys.json").exists());
        assert!(!root.join("vault/reservation.guard").exists());
        assert!(!root.join("vault/revocation.guard").exists());
        let before = snapshot(&root);
        for (relative, entry) in &before {
            if relative != Path::new(SLOT) {
                if let Some(bytes) = &entry.bytes {
                    // Disposable role keys remain in their fixture custody
                    // files. Only the fixed application slot may hold canary
                    // plaintext, which revocation intentionally does not erase.
                    assert_no_canary(bytes);
                }
            }
        }
        assert_no_fixture_process(&root);
        assert_read_only_inspection(&directory);
        assert_read_only_inspection(&directory);

        let repeated = run(directory.command().arg(&root), None);
        assert_eq!(repeated.status.code(), Some(2));
        assert_refused(&repeated, &root);
        assert!(
            snapshot(&root) == before,
            "rerun rewrote retained installation evidence"
        );
        assert_no_fixture_process(&root);
    }

    #[test]
    fn wrong_installed_generation_is_refused_without_repair() {
        let directory = Directory::new();
        let root = directory.root();
        assert_closed_report(&report(&run(directory.command().arg(&root), None), &root));
        assert_installation_tuple(&root);
        let original = fs::read(root.join(SLOT)).unwrap();
        let version_two = b"AEGIS_SYNTHETIC_DELIVERY_CANARY_VERSION_TWO_NOT_VALID";
        assert_eq!(original.len(), version_two.len());
        // Keep the genuine signed version-one receipt unchanged while the
        // actual installed bytes claim the other supported fixture generation.
        // This is more than a damaged or invalidly signed receipt check.
        fs::write(root.join(SLOT), version_two).unwrap();
        assert_read_only_refusal(&directory);
        fs::write(root.join(SLOT), original).unwrap();
        assert_read_only_inspection(&directory);
    }

    #[test]
    fn encrypted_recipient_acceptance_is_not_application_installation() {
        let directory = Directory::new();
        let root = directory.root();
        let mut legacy = Command::new(env!("CARGO_BIN_EXE_aegis-process-service"));
        legacy.current_dir(&directory.0).arg(&root);
        let output = run(&mut legacy, None);
        let legacy_report = report(&output, &root);
        assert_eq!(legacy_report["recipient_generation"], 1);
        assert!(root.join("recipient/accepted.jws").is_file());
        assert!(!root.join("application").exists());
        assert_read_only_refusal(&directory);

        // Even copying that acceptance evidence beside the expected plaintext
        // does not turn a legacy delivery receipt into an installation receipt.
        fs::create_dir(root.join("application")).unwrap();
        fs::copy(root.join("recipient/accepted.jws"), root.join(RECEIPTS)).unwrap();
        fs::write(
            root.join(SLOT),
            b"AEGIS_SYNTHETIC_DELIVERY_CANARY_VERSION_ONE_NOT_VALID",
        )
        .unwrap();
        assert_read_only_refusal(&directory);
    }

    #[test]
    fn fresh_inspection_refuses_missing_or_corrupt_evidence_without_repair() {
        let directory = Directory::new();
        let root = directory.root();
        assert_closed_report(&report(&run(directory.command().arg(&root), None), &root));
        for relative in [
            SLOT,
            RECEIPTS,
            "input/record.age",
            "vault/secret-1.age",
            "vault/manifest.jws",
            "vault/journal.jws",
            "custody/broker/custody.json",
        ] {
            let file = root.join(relative);
            let saved = directory.0.join("saved-artifact");
            let bytes = fs::read(&file).unwrap();
            assert!(!bytes.is_empty());
            fs::rename(&file, &saved).unwrap();
            assert_read_only_refusal(&directory);
            fs::rename(&saved, &file).unwrap();

            let mut corrupted = bytes.clone();
            corrupted[0] ^= 1;
            fs::write(&file, &corrupted).unwrap();
            assert_read_only_refusal(&directory);
            fs::write(&file, &bytes).unwrap();
            assert_read_only_inspection(&directory);
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_no_fixture_process(root: &Path) {
        // Root-scoped completion observation only, not a process-isolation or
        // supervisor-crash guarantee. Fixed children reexecute this binary.
        use std::os::unix::ffi::OsStrExt;
        let executable = fs::canonicalize(env!("CARGO_BIN_EXE_aegis-application-slot")).unwrap();
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
                    "an application slot fixture process survived completion"
                );
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn assert_no_fixture_process(_: &Path) {}

    #[test]
    fn inspection_of_absent_fixture_creates_nothing() {
        let directory = Directory::new();
        let root = directory.root();
        let output = run(directory.command().arg("inspect").arg(&root), None);
        assert_eq!(output.status.code(), Some(2));
        assert_refused(&output, &root);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
        assert_no_fixture_process(&root);
    }

    #[test]
    fn existing_paths_are_never_overwritten() {
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
        let linked_child = link.join("new-root");
        let before = snapshot(&occupied);
        for root in [&file, &occupied, &empty, &link, &linked_child] {
            let output = run(directory.command().arg(root), None);
            assert_eq!(output.status.code(), Some(2));
            assert_refused(&output, root);
            assert_eq!(fs::read(&file).unwrap(), b"keep existing fixture file");
            assert!(
                snapshot(&occupied) == before,
                "occupied directory was changed"
            );
            assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
            assert_eq!(fs::read_link(&link).unwrap(), occupied);
            assert_no_fixture_process(root);
        }
    }
}
