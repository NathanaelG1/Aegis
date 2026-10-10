//! Ordinary functional acceptance for the fixed two-import process composition.
//! These checks do not establish protected custody, human presence, isolation or
//! real-key readiness, and do not resume the stopped independent review.
//! The fixed application file intentionally contains a public canary.

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
const INPUT_MARKER: &str = "AEGIS_TEST_UNUSED_ROTATION_INPUT_NOT_A_CREDENTIAL";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let path = parent.join(format!(
                "aegis-application-rotation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("cannot create rotation acceptance fixture directory"),
            }
        }
        panic!("cannot allocate a fresh rotation acceptance fixture directory");
    }
    fn root(&self) -> PathBuf {
        self.0.join("fixture")
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-application-rotation"));
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
fn run(command: &mut Command) -> Output {
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = Running(
        command
            .spawn()
            .expect("cannot start rotation fixture binary"),
    );
    let stdout = capture(process.0.stdout.take().unwrap());
    let stderr = capture(process.0.stderr.take().unwrap());
    // The closed drill must ignore stdin, even on its successful path.
    let written = process
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(INPUT_MARKER.as_bytes());
    assert!(written.is_ok() || written.unwrap_err().kind() == std::io::ErrorKind::BrokenPipe);
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "rotation fixture did not finish");
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout
        .recv_timeout(Duration::from_secs(1))
        .expect("fixture stdout did not close");
    let stderr = stderr
        .recv_timeout(Duration::from_secs(1))
        .expect("fixture stderr did not close");
    assert!(
        stdout.len() <= MAX_OUTPUT && stderr.len() <= MAX_OUTPUT,
        "fixture output exceeded its bound"
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
            "fixture input appeared outside the intentional application slot"
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
            root.to_str().unwrap(),
        ] {
            assert!(
                !contains(bytes, forbidden.as_bytes()),
                "fixture output exposed private material or a path"
            );
        }
    }
}
fn assert_refused(output: &Output, root: &Path) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && !output.stderr.is_empty());
    assert_safe_output(output, root);
}

#[test]
fn main_cli_does_not_expose_rotation_or_arbitrary_import() {
    let directory = Directory::new();
    for verb in ["application-rotation", "import-secret"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis"));
        command
            .current_dir(&directory.0)
            .arg(verb)
            .arg(directory.root());
        let output = run(&mut command);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty() && !output.stderr.is_empty());
        assert_safe_output(&output, &directory.root());
        assert!(!directory.root().exists());
    }
}

#[cfg(not(all(unix, feature = "application-slot")))]
#[test]
fn rotation_requires_unix_and_the_application_slot_feature() {
    let directory = Directory::new();
    for inspect in [false, true] {
        let mut command = directory.command();
        if inspect {
            command.arg("inspect");
        }
        assert_refused(&run(command.arg(directory.root())), &directory.root());
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }
}

#[test]
fn malformed_arguments_and_absent_inspection_create_nothing() {
    use std::ffi::OsString;
    let directory = Directory::new();
    let root = directory.root();
    let root_arg = root.as_os_str().to_owned();
    let cases: Vec<Vec<OsString>> = vec![
        vec![],
        vec![root_arg.clone(), INPUT_MARKER.into()],
        vec!["--secret".into(), INPUT_MARKER.into()],
        vec!["--version".into(), "2".into()],
        vec!["--slot".into(), INPUT_MARKER.into()],
        vec!["--path".into(), INPUT_MARKER.into()],
        vec!["--executable".into(), INPUT_MARKER.into()],
        vec!["--command".into(), INPUT_MARKER.into()],
        vec!["--listen".into(), INPUT_MARKER.into()],
        vec!["--fault".into(), INPUT_MARKER.into()],
        vec!["--ready-for-real-keys".into(), root_arg.clone()],
        vec!["deliver".into(), root_arg.clone()],
        vec!["rotate".into(), root_arg.clone()],
        vec!["inspect".into()],
        vec!["inspect".into(), root_arg.clone(), INPUT_MARKER.into()],
        vec!["inspect".into(), root_arg],
        vec!["relative-root".into()],
    ];
    for args in cases {
        assert_refused(&run(directory.command().args(args)), &root);
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
    const CANARIES: [&[u8]; 2] = [
        b"AEGIS_SYNTHETIC_DELIVERY_CANARY_VERSION_ONE_NOT_VALID",
        b"AEGIS_SYNTHETIC_DELIVERY_CANARY_VERSION_TWO_NOT_VALID",
    ];
    #[derive(Eq, PartialEq)]
    struct Entry {
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
            let bytes = if metadata.is_dir() {
                None
            } else {
                assert!(
                    metadata.is_file() && metadata.len() <= 2 * 1024 * 1024,
                    "unexpected or unbounded fixture artifact"
                );
                Some(fs::read(path).unwrap())
            };
            entries.insert(
                path.strip_prefix(root).unwrap().into(),
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
    fn report(output: Output, root: &Path) -> Value {
        assert_safe_output(&output, root);
        assert!(output.status.success(), "rotation fixture failed");
        assert!(output.stderr.is_empty());
        serde_json::from_slice(&output.stdout).expect("fixture must emit exactly one JSON report")
    }
    fn assert_closed_report(value: &Value) {
        for field in [
            "synthetic_only",
            "input_import_bound",
            "separate_broker_process",
            "separate_recipient_process",
            "broker_and_recipient_reaped",
            "installation_receipt_verified",
            "handle_relative_operations",
            "revoked",
            "exact_import_ciphertexts_verified",
            "distinct_import_bindings_verified",
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
            ("completed_installations", 2),
            ("consumed_uses", 2),
            ("remaining_uses", 2),
            ("recipient_generation", 2),
            ("installed_version", 2),
            ("incomplete_installations", 0),
            ("restored_sessions", 0),
        ] {
            assert_eq!(value[field], expected, "{field}");
        }
        assert_eq!(value["imported_versions"], json!([1, 2]));
        assert_eq!(value["application_slot"], "provider-auth");
        assert_eq!(value["workflow_mode"], "UNISOLATED");
    }
    fn inspect(directory: &Directory, successful: bool) {
        let root = directory.root();
        let before = snapshot(&root);
        let output = run(directory.command().arg("inspect").arg(&root));
        if successful {
            let value = report(output, &root);
            assert_closed_report(&value);
            assert_eq!(value["incomplete_deliveries"], 0);
            assert_eq!(value["unknown_deliveries"], 0);
        } else {
            assert_refused(&output, &root);
        }
        // Access times are excluded because inspection reads all evidence.
        assert!(
            snapshot(&root) == before,
            "inspection changed bytes, inode, mode or modification time"
        );
        assert_no_fixture_process(&root);
    }
    fn create(directory: &Directory) -> Value {
        let value = report(
            run(directory.command().arg(directory.root())),
            &directory.root(),
        );
        assert_closed_report(&value);
        assert_no_fixture_process(&directory.root());
        value
    }
    fn signed_payload(token: &str) -> Value {
        // Decoding establishes tuple meaning, not authenticity. Fresh-process
        // inspection below must validate the actual signatures and installed file.
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, json!({"alg":"RS256", "typ":"JWT"}));
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 256);
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        assert_no_canary(&payload);
        serde_json::from_slice(&payload).unwrap()
    }
    fn digest(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD
            .encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref())
    }
    fn journal(root: &Path, name: &str, expected: usize) -> (Vec<String>, Vec<Value>) {
        let content = fs::read_to_string(root.join(name)).unwrap();
        assert!(content.ends_with('\n'));
        let tokens: Vec<_> = content.lines().map(str::to_owned).collect();
        assert_eq!(
            tokens.len(),
            expected,
            "duplicates must not append another effect"
        );
        let records: Vec<_> = tokens.iter().map(|token| signed_payload(token)).collect();
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record["sequence"], index + 1);
            assert_eq!(
                record["previous"],
                if index == 0 {
                    String::new()
                } else {
                    digest(tokens[index - 1].as_bytes())
                }
            );
        }
        (tokens, records)
    }
    fn assert_two_import_histories(root: &Path) {
        let manifest_token = fs::read_to_string(root.join("vault/manifest.jws")).unwrap();
        let manifest = signed_payload(manifest_token.trim());
        assert_eq!(manifest["receipt_contract"], "installation");
        assert_eq!(manifest["records"].as_array().unwrap().len(), 2);
        assert_eq!(manifest["acl"].as_array().unwrap().len(), 2);
        assert_ne!(
            manifest["records"][0]["import_metadata_digest"],
            manifest["records"][1]["import_metadata_digest"]
        );
        let application = fs::metadata(root.join("application")).unwrap();
        let (_, installations) = journal(root, RECEIPTS, 5);
        let (_, broker) = journal(root, "vault/journal.jws", 10);
        for record in installations.iter().chain(&broker) {
            assert_eq!(record["schema"], 1);
            assert_eq!(record["vault_id"], manifest["vault_id"]);
        }
        for record in &broker {
            assert_eq!(record["kind"], "aegis.synthetic.vault.journal.v1");
        }
        for (record, event) in installations
            .iter()
            .zip(["genesis", "intent", "complete", "intent", "complete"])
        {
            assert_eq!(
                record["kind"],
                "aegis.synthetic.application-slot.journal.v1"
            );
            assert_eq!(record["slot"], "provider-auth");
            assert_eq!(record["directory_device"], application.dev());
            assert_eq!(record["directory_inode"], application.ino());
            assert_eq!(record["event"]["type"], event);
        }
        assert_eq!(broker[0]["event"]["event"], "Genesis");
        assert_eq!(broker[0]["event"]["budget"], 4);
        assert_eq!(
            broker[0]["event"]["manifest_digest"],
            digest(manifest_token.trim().as_bytes())
        );
        assert_eq!(broker[9]["event"]["event"], "Revoke");
        let mut request_ids = Vec::new();
        for index in 0..2 {
            let version = index + 1;
            let ciphertext = fs::read(root.join(format!("input-{version}/record.age"))).unwrap();
            assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
            assert!(
                ciphertext == fs::read(root.join(format!("vault/secret-{version}.age"))).unwrap()
            );
            let record = &manifest["records"][index];
            assert_eq!(
                record["reference"],
                json!({"id":"synthetic-provider-key", "version":version})
            );
            assert_eq!(record["ciphertext_digest"], digest(&ciphertext));
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(record["import_metadata_digest"].as_str().unwrap())
                    .unwrap()
                    .len(),
                32
            );
            let intent = &installations[1 + 2 * index]["event"]["intent"];
            let capsule_token = intent["capsule"].as_str().unwrap();
            let capsule = signed_payload(capsule_token);
            let receipt_token = installations[2 + 2 * index]["event"]["receipt"]
                .as_str()
                .unwrap();
            let receipt = signed_payload(receipt_token);
            let ack = &receipt["ack"];
            let profile = &receipt["profile"];
            let recipient = json!({"id":"synthetic-recipient", "revision":1, "configuration_revision":1, "slot":"provider-auth"});
            assert_eq!(
                capsule["kind"],
                "aegis.synthetic.application-slot.capsule.v1"
            );
            assert_eq!(capsule["vault_id"], manifest["vault_id"]);
            assert_eq!(capsule["expected_generation"], index);
            assert_eq!(intent["prior_generation"], index);
            assert_eq!(intent["next_generation"], version);
            assert_eq!(intent["capsule_digest"], digest(capsule_token.as_bytes()));
            assert_eq!(intent["file_digest"], digest(CANARIES[index]));
            assert_eq!(ack["schema"], 1);
            assert_eq!(ack["kind"], "aegis.synthetic.application-slot.installed.v1");
            assert_eq!(ack["vault_id"], manifest["vault_id"]);
            assert_eq!(ack["delivery_id"], capsule["delivery_id"]);
            assert_eq!(ack["capsule_digest"], intent["capsule_digest"]);
            assert_eq!(ack["version"], version);
            assert_eq!(ack["generation"], version);
            assert_eq!(ack["recipient"], recipient);
            assert_eq!(profile, &capsule["profile"]);
            assert_eq!(profile["recipient"], recipient);
            assert_eq!(profile["secret"], record["reference"]);
            assert_eq!(profile["id"], "vault-delivery");
            assert_eq!(profile["revision"], version);
            assert_eq!(profile["acl_revision"], 1);
            assert_eq!(profile["repository_id"], 4242);
            assert_eq!(profile["adapter_contract"], 2);
            assert_eq!(profile["output_contract"], 2);
            assert_eq!(&manifest["acl"][index]["profile"], profile);
            assert_eq!(receipt["prior_generation"], index);
            assert_eq!(receipt["slot_filename"], "provider-auth");
            assert_eq!(receipt["file_digest"], intent["file_digest"]);
            assert_eq!(receipt["directory_device"], application.dev());
            assert_eq!(receipt["directory_inode"], application.ino());
            assert_eq!(receipt["durability"], "file-sync-rename-directory-sync-v1");
            let events: Vec<_> = broker[1 + 4 * index..5 + 4 * index]
                .iter()
                .map(|frame| &frame["event"])
                .collect();
            for (event, name) in
                events
                    .iter()
                    .zip(["Approval", "Reservation", "Handoff", "Complete"])
            {
                assert_eq!(event["event"], name);
            }
            let review = &events[0]["review"];
            assert_eq!(&events[1]["review"], review);
            assert_eq!(&review["profile"], profile);
            assert_eq!(review["request_id"], ack["delivery_id"]);
            assert_eq!(review["operation"]["secret"], record["reference"]);
            assert_eq!(review["operation"]["recipient"], recipient);
            assert_eq!(review["operation"]["expected_generation"], index);
            assert_eq!(events[1]["remaining_before"], 4 - index);
            assert_eq!(
                events[1]["admin_challenge"],
                events[0]["proof"]["challenge"]
            );
            assert_eq!(events[2]["request_id"], ack["delivery_id"]);
            assert_eq!(events[2]["capsule_digest"], ack["capsule_digest"]);
            assert_eq!(events[3]["request_id"], ack["delivery_id"]);
            assert_eq!(events[3]["outcome"], "delivered");
            assert_eq!(events[3]["ack"], receipt_token);
            request_ids.push(ack["delivery_id"].as_str().unwrap().to_owned());
        }
        assert_ne!(request_ids[0], request_ids[1]);
        assert_eq!(installations[4]["event"]["type"], "complete");
    }

    #[test]
    fn both_imports_reach_the_actual_fixed_file_and_survive_restart_and_revoke() {
        let directory = Directory::new();
        let root = directory.root();
        let value = create(&directory);
        for field in [
            "tls13_mutual_authentication_verified",
            "unauthenticated_agent_denied",
            "unauthenticated_admin_denied",
            "duplicate_reused",
            "cold_start_required_authentication",
            "revocation_survived_restart",
            "exact_approvals_verified",
            "old_version_rollback_prevented",
            "fresh_authentication_between_versions",
        ] {
            assert_eq!(value[field], true, "{field}");
        }
        assert_eq!(value["authenticated_role_channels"], 2);
        assert_eq!(value["delivery_broker_phases"], 2);
        assert_eq!(value["retained_duplicate_outcomes"], 2);
        assert_eq!(value["completed_installation_generations"], json!([1, 2]));
        assert_eq!(value["independent_human_presence_verified"], false);
        assert_eq!(value["agent_transcript_contains_canary"], false);
        assert!(fs::read(root.join(SLOT)).unwrap() == CANARIES[1]);
        assert_two_import_histories(&root);
        for relative in [
            "application/.provider-auth.stage",
            "input-1/record.pending",
            "input-2/record.pending",
            "vault/secret-3.age",
            "custody/fixture-keys.json",
            "vault/reservation.guard",
            "vault/revocation.guard",
        ] {
            assert!(!root.join(relative).exists());
        }
        let before = snapshot(&root);
        for (relative, entry) in &before {
            if relative != Path::new(SLOT) {
                if let Some(bytes) = &entry.bytes {
                    assert_no_canary(bytes);
                }
            }
        }
        inspect(&directory, true);
        inspect(&directory, true);
        let mut single_import = Command::new(env!("CARGO_BIN_EXE_aegis-application-slot"));
        single_import
            .current_dir(&directory.0)
            .arg("inspect")
            .arg(&root);
        assert_refused(&run(&mut single_import), &root);
        assert_refused(&run(directory.command().arg(&root)), &root);
        assert!(
            snapshot(&root) == before,
            "rerun changed retained rotation evidence"
        );
        assert!(fs::read(root.join(SLOT)).unwrap() == CANARIES[1]);
        assert_no_fixture_process(&root);
    }

    #[test]
    fn missing_corrupt_and_invalidly_signed_evidence_refuses_without_repair() {
        let directory = Directory::new();
        create(&directory);
        let root = directory.root();
        for relative in [
            SLOT,
            RECEIPTS,
            "input-1/record.age",
            "input-2/record.age",
            "vault/secret-1.age",
            "vault/secret-2.age",
            "vault/manifest.jws",
            "vault/journal.jws",
            "custody/broker/custody.json",
        ] {
            let path = root.join(relative);
            let saved = directory.0.join("saved-artifact");
            let original = fs::read(&path).unwrap();
            fs::rename(&path, &saved).unwrap();
            inspect(&directory, false);
            fs::rename(&saved, &path).unwrap();
            let mut damaged = original.clone();
            damaged[0] ^= 1;
            fs::write(&path, &damaged).unwrap();
            inspect(&directory, false);
            fs::write(&path, original).unwrap();
        }
        // Keep valid compact JWS syntax and exactly the same payload. Only the
        // RSA signature changes, so a parser-only inspector cannot pass this.
        for relative in ["vault/manifest.jws", RECEIPTS, "vault/journal.jws"] {
            let path = root.join(relative);
            let original = fs::read_to_string(&path).unwrap();
            let token = original.lines().last().unwrap();
            let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
            let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
            signature[0] ^= 1;
            parts[2] = URL_SAFE_NO_PAD.encode(signature);
            let changed = original.replacen(token, &parts.join("."), 1);
            fs::write(&path, changed).unwrap();
            inspect(&directory, false);
            fs::write(&path, original).unwrap();
        }
        inspect(&directory, true);
    }

    #[test]
    fn mixed_versions_and_old_canary_refuse_without_rollback_or_repair() {
        let directory = Directory::new();
        create(&directory);
        let root = directory.root();
        for (target, source) in [
            ("input-2/record.age", "input-1/record.age"),
            ("vault/secret-2.age", "vault/secret-1.age"),
        ] {
            let path = root.join(target);
            let original = fs::read(&path).unwrap();
            fs::write(&path, fs::read(root.join(source)).unwrap()).unwrap();
            inspect(&directory, false);
            fs::write(&path, original).unwrap();
        }
        // Genuine version-two signed receipts cannot validate the other allowed
        // canary; inspection must compare the actual file, not just its syntax.
        fs::write(root.join(SLOT), CANARIES[0]).unwrap();
        inspect(&directory, false);
        fs::write(root.join(SLOT), CANARIES[1]).unwrap();
        inspect(&directory, true);
    }

    #[test]
    fn a_single_import_fixture_is_not_composed_rotation() {
        let directory = Directory::new();
        let root = directory.root();
        let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-application-slot"));
        command.current_dir(&directory.0).arg(&root);
        let value = report(run(&mut command), &root);
        assert_eq!(value["completed_installations"], 1);
        assert!(fs::read(root.join(SLOT)).unwrap() == CANARIES[0]);
        inspect(&directory, false);
    }

    #[test]
    fn existing_paths_and_symlink_ancestors_are_never_overwritten() {
        let directory = Directory::new();
        let file = directory.0.join("existing-file");
        let occupied = directory.0.join("existing-directory");
        let empty = directory.0.join("empty-directory");
        let link = directory.0.join("linked-directory");
        fs::write(&file, b"keep file").unwrap();
        fs::create_dir(&occupied).unwrap();
        fs::write(occupied.join("sentinel"), b"keep directory").unwrap();
        fs::create_dir(&empty).unwrap();
        symlink(&occupied, &link).unwrap();
        let child = link.join("new-root");
        let before = snapshot(&occupied);
        for root in [&file, &occupied, &empty, &link, &child] {
            assert_refused(&run(directory.command().arg(root)), root);
            assert!(snapshot(&occupied) == before);
            assert_eq!(fs::read(&file).unwrap(), b"keep file");
            assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
            assert_eq!(fs::read_link(&link).unwrap(), occupied);
            assert_no_fixture_process(root);
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_no_fixture_process(root: &Path) {
        // Completion observation scoped to this fixture, not a claim about
        // isolation or cleanup after the supervisor itself crashes.
        use std::os::unix::ffi::OsStrExt;
        let executable =
            fs::canonicalize(env!("CARGO_BIN_EXE_aegis-application-rotation")).unwrap();
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
                    "a root-scoped rotation child survived completion"
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    fn assert_no_fixture_process(_: &Path) {}
}
