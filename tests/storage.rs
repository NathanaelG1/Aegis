#![cfg(feature = "storage-spike")]

use aegis::storage::{
    encrypt_synthetic_fixture, validate_synthetic_restore, SpikeError, SyntheticKey,
    MAX_CIPHERTEXT_BYTES,
};
#[cfg(unix)]
use aegis::storage::{RecoverySummary, MAX_PLAINTEXT_BYTES};
use std::io::Write;

const CANARY: &str = "AEGIS_SYNTHETIC_RECOVERY_CANARY_NO_REAL_CREDENTIAL";

// Arbitrary encrypted adversarial input exists only in this test harness. The shipped
// storage API accepts no plaintext fixture or credential values from its caller.
#[cfg(unix)]
fn hostile_ciphertext(plaintext: &[u8], key: &age::x25519::Identity) -> Vec<u8> {
    let recipient = key.to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    ciphertext
}

#[cfg(unix)]
fn fixed_fixture() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "kind": "aegis.synthetic.recovery.v1",
        "vault_id": "aegis-synthetic-vault-v1",
        "generation": 1,
        "credentials": [{"id":"synthetic-status", "version":1, "canary":CANARY}],
        "profiles": [{"id":"synthetic-issue-status", "revision":1,
            "credential_id":"synthetic-status", "credential_version":1,
            "operation":"fake.issue-status.v1", "resource":"synthetic/project-a",
            "output_contract":"issue-status.v1"}],
        "grants": [{"id":"synthetic-grant", "profile_id":"synthetic-issue-status",
            "profile_revision":1, "enabled":true, "remaining_uses":1}],
        "sessions": ["synthetic-session"]
    })
}

#[cfg(unix)]
fn check_hostile_fixture(plaintext: &[u8]) -> Result<RecoverySummary, SpikeError> {
    // A saved kit makes the external age identity available to the bounded API;
    // the in-memory SyntheticKey deliberately has no private-key import/accessor.
    #[cfg(unix)]
    {
        use aegis::storage::recover_saved_synthetic_drill;
        use age::secrecy::ExposeSecret;
        let directory = unix::TemporaryDirectory::new();
        let snapshot = directory.path.join("snapshot");
        let kit = directory.path.join("kit");
        std::fs::create_dir(&snapshot).unwrap();
        std::fs::create_dir(&kit).unwrap();
        let identity = age::x25519::Identity::generate();
        let ciphertext = hostile_ciphertext(plaintext, &identity);
        std::fs::write(snapshot.join("snapshot.age"), ciphertext).unwrap();
        std::fs::write(
            kit.join("recovery-key.txt"),
            identity.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        let result =
            recover_saved_synthetic_drill(&snapshot, &kit, &directory.path.join("restored"));
        if result.is_err() {
            assert!(!directory.path.join("restored").exists());
        }
        result
    }
    #[cfg(not(unix))]
    {
        let _ = plaintext;
        Err(SpikeError::UnsupportedPlatform)
    }
}

#[test]
fn independent_local_and_recovery_recipients_validate_without_plaintext_release() {
    let local = SyntheticKey::generate();
    let recovery = SyntheticKey::generate();
    let ciphertext = encrypt_synthetic_fixture(&local, &recovery).unwrap();
    assert!(!ciphertext
        .windows(CANARY.len())
        .any(|part| part == CANARY.as_bytes()));
    let summary = validate_synthetic_restore(&ciphertext, &local).unwrap();
    assert_eq!(
        summary,
        validate_synthetic_restore(&ciphertext, &recovery).unwrap()
    );
    assert_eq!(summary.disabled_grants, 1);
    assert_eq!(summary.enabled_grants, 0);
    assert_eq!(summary.restored_sessions, 0);
    assert!(!format!("{summary:?}").contains(CANARY));
    assert_eq!(
        encrypt_synthetic_fixture(&local, &local),
        Err(SpikeError::FixtureMismatch)
    );
}

#[test]
fn wrong_key_truncated_payload_and_corruption_fail_closed() {
    let local = SyntheticKey::generate();
    let recovery = SyntheticKey::generate();
    let unrelated = SyntheticKey::generate();
    let ciphertext = encrypt_synthetic_fixture(&local, &recovery).unwrap();
    assert_eq!(
        validate_synthetic_restore(&ciphertext, &unrelated),
        Err(SpikeError::DecryptionFailed)
    );
    for removed in 1..=32 {
        assert!(
            validate_synthetic_restore(&ciphertext[..ciphertext.len() - removed], &recovery)
                .is_err()
        );
    }
    for length in [0, 1, 20, 100] {
        assert!(validate_synthetic_restore(&ciphertext[..length], &recovery).is_err());
    }
    let mut payload_corrupted = ciphertext.clone();
    *payload_corrupted.last_mut().unwrap() ^= 1;
    assert_eq!(
        validate_synthetic_restore(&payload_corrupted, &recovery),
        Err(SpikeError::DecryptionFailed)
    );
    let mut header_corrupted = ciphertext;
    header_corrupted[0] ^= 1;
    assert_eq!(
        validate_synthetic_restore(&header_corrupted, &recovery),
        Err(SpikeError::InvalidCiphertext)
    );
}

#[test]
fn ciphertext_bound_applies_before_age_parsing() {
    assert_eq!(
        validate_synthetic_restore(
            &vec![0; MAX_CIPHERTEXT_BYTES + 1],
            &SyntheticKey::generate()
        ),
        Err(SpikeError::CiphertextTooLarge)
    );
}

#[test]
fn passphrase_payload_is_rejected_without_scrypt_decryption() {
    let mut recipient = age::scrypt::Recipient::new(age::secrecy::SecretString::from(
        "synthetic test only".to_owned(),
    ));
    recipient.set_work_factor(1);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(b"synthetic").unwrap();
    writer.finish().unwrap();
    assert_eq!(
        validate_synthetic_restore(&ciphertext, &SyntheticKey::generate()),
        Err(SpikeError::UnsupportedEncryption)
    );
}

#[cfg(unix)]
#[test]
fn plaintext_bound_applies_before_snapshot_parsing_or_destination_creation() {
    assert_eq!(
        check_hostile_fixture(&vec![b' '; MAX_PLAINTEXT_BYTES + 1]),
        Err(SpikeError::PlaintextTooLarge)
    );
}

#[cfg(unix)]
#[test]
fn unsupported_schema_and_unknown_or_duplicate_fields_fail_closed() {
    let mut fixture = fixed_fixture();
    fixture["schema_version"] = serde_json::json!(2);
    assert_eq!(
        check_hostile_fixture(&serde_json::to_vec(&fixture).unwrap()),
        Err(SpikeError::UnsupportedSchema)
    );
    fixture = fixed_fixture();
    fixture["approved"] = serde_json::json!(true);
    assert_eq!(
        check_hostile_fixture(&serde_json::to_vec(&fixture).unwrap()),
        Err(SpikeError::InvalidSnapshot)
    );
    let duplicate =
        serde_json::to_string(&fixed_fixture())
            .unwrap()
            .replacen("{", "{\"schema_version\":1,", 1);
    assert_eq!(
        check_hostile_fixture(duplicate.as_bytes()),
        Err(SpikeError::InvalidSnapshot)
    );
    assert_eq!(
        check_hostile_fixture(b"{\"schema_version\":1}"),
        Err(SpikeError::InvalidSnapshot)
    );
    assert_eq!(
        check_hostile_fixture(b"[[[[[[[[[[[[]]]]]]]]]]]]"),
        Err(SpikeError::InvalidSnapshot)
    );
    let mut trailing = serde_json::to_vec(&fixed_fixture()).unwrap();
    trailing.extend_from_slice(b" {\"approved\":true}");
    assert_eq!(
        check_hostile_fixture(&trailing),
        Err(SpikeError::InvalidSnapshot)
    );
}

#[cfg(unix)]
#[test]
fn every_synthetic_binding_and_record_shape_is_validated() {
    let changes = [
        ("/kind", serde_json::json!("production")),
        ("/vault_id", serde_json::json!("other-vault")),
        ("/generation", serde_json::json!(2)),
        ("/credentials/0/id", serde_json::json!("other-credential")),
        ("/credentials/0/version", serde_json::json!(2)),
        (
            "/credentials/0/canary",
            serde_json::json!("arbitrary value rejected"),
        ),
        ("/profiles/0/id", serde_json::json!("other-profile")),
        ("/profiles/0/revision", serde_json::json!(2)),
        (
            "/profiles/0/credential_id",
            serde_json::json!("other-credential"),
        ),
        ("/profiles/0/credential_version", serde_json::json!(2)),
        ("/profiles/0/operation", serde_json::json!("generic.exec")),
        (
            "/profiles/0/resource",
            serde_json::json!("synthetic/project-b"),
        ),
        ("/profiles/0/output_contract", serde_json::json!("raw-body")),
        ("/grants/0/id", serde_json::json!("other-grant")),
        ("/grants/0/profile_id", serde_json::json!("other-profile")),
        ("/grants/0/profile_revision", serde_json::json!(2)),
        ("/grants/0/remaining_uses", serde_json::json!(2)),
        ("/sessions/0", serde_json::json!("forged-session")),
        ("/credentials", serde_json::json!([])),
        ("/profiles", serde_json::json!([])),
        ("/grants", serde_json::json!([])),
        ("/sessions", serde_json::json!([])),
    ];
    for (pointer, value) in changes {
        let mut fixture = fixed_fixture();
        *fixture.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            check_hostile_fixture(&serde_json::to_vec(&fixture).unwrap()),
            Err(SpikeError::FixtureMismatch),
            "field {pointer}"
        );
    }
    for collection in ["credentials", "profiles", "grants", "sessions"] {
        let mut fixture = fixed_fixture();
        let values = fixture[collection].as_array_mut().unwrap();
        values.push(values[0].clone());
        assert_eq!(
            check_hostile_fixture(&serde_json::to_vec(&fixture).unwrap()),
            Err(SpikeError::FixtureMismatch)
        );
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use aegis::storage::{create_saved_synthetic_drill, recover_saved_synthetic_drill};
    use age::secrecy::ExposeSecret;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub(super) struct TemporaryDirectory {
        pub(super) path: PathBuf,
    }

    impl TemporaryDirectory {
        pub(super) fn new() -> Self {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "aegis-storage-spike-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    #[test]
    fn restrictive_new_files_and_disabled_restored_snapshot() {
        let root = TemporaryDirectory::new();
        let snapshot = root.path.join("snapshot");
        let kit = root.path.join("separate-kit");
        let restored = root.path.join("restored");
        create_saved_synthetic_drill(&snapshot, &kit).unwrap();
        for directory in [&snapshot, &kit] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for file in [snapshot.join("snapshot.age"), kit.join("recovery-key.txt")] {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let summary = recover_saved_synthetic_drill(&snapshot, &kit, &restored).unwrap();
        assert_eq!(summary.enabled_grants, 0);
        assert_eq!(summary.restored_sessions, 0);
        assert_eq!(
            fs::metadata(restored.join("snapshot.age"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let key = fs::read_to_string(kit.join("recovery-key.txt")).unwrap();
        let identity: age::x25519::Identity = key.parse().unwrap();
        let encrypted = fs::read(restored.join("snapshot.age")).unwrap();
        let decryptor = age::Decryptor::new(encrypted.as_slice()).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).unwrap();
        let fixture: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(fixture["grants"][0]["enabled"], false);
        assert_eq!(fixture["sessions"], serde_json::json!([]));
        // The actual persisted disabled fixture can be recovered again without reactivation.
        assert_eq!(
            recover_saved_synthetic_drill(&restored, &kit, &root.path.join("again")).unwrap(),
            summary
        );
    }

    #[test]
    fn existing_destinations_and_permissions_are_preserved() {
        let root = TemporaryDirectory::new();
        let existing = root.path.join("existing");
        fs::DirBuilder::new().mode(0o750).create(&existing).unwrap();
        let marker_path = existing.join("marker");
        let mut marker = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&marker_path)
            .unwrap();
        marker.write_all(b"preserve-me").unwrap();
        let directory_mode = fs::metadata(&existing).unwrap().permissions().mode();
        let file_mode = fs::metadata(&marker_path).unwrap().permissions().mode();
        let kit = root.path.join("kit");
        assert_eq!(
            create_saved_synthetic_drill(&existing, &kit),
            Err(SpikeError::DestinationExists)
        );
        assert!(!kit.exists());
        let snapshot = root.path.join("snapshot");
        create_saved_synthetic_drill(&snapshot, &kit).unwrap();
        assert_eq!(
            recover_saved_synthetic_drill(&snapshot, &kit, &existing),
            Err(SpikeError::DestinationExists)
        );
        assert_eq!(fs::read(&marker_path).unwrap(), b"preserve-me");
        assert_eq!(
            fs::metadata(&existing).unwrap().permissions().mode(),
            directory_mode
        );
        assert_eq!(
            fs::metadata(marker_path).unwrap().permissions().mode(),
            file_mode
        );
        assert_eq!(fs::read_dir(existing).unwrap().count(), 1);
    }

    #[test]
    fn relative_nested_and_symlink_destinations_are_rejected() {
        let root = TemporaryDirectory::new();
        assert_eq!(
            create_saved_synthetic_drill(std::path::Path::new("relative"), &root.path.join("kit")),
            Err(SpikeError::InvalidPath)
        );
        let alias = root.path.join("alias");
        symlink(&root.path, &alias).unwrap();
        assert_eq!(
            create_saved_synthetic_drill(&alias.join("snapshot"), &root.path.join("kit")),
            Err(SpikeError::UnsafeFile)
        );
        assert!(!root.path.join("snapshot").exists());
        assert_eq!(
            create_saved_synthetic_drill(&root.path.join("same"), &root.path.join("same")),
            Err(SpikeError::InvalidPath)
        );
    }

    #[test]
    fn malformed_wrong_and_symlinked_saved_kits_do_not_create_restore_destination() {
        let root = TemporaryDirectory::new();
        let snapshot = root.path.join("snapshot");
        let kit = root.path.join("kit");
        create_saved_synthetic_drill(&snapshot, &kit).unwrap();
        let wrong = root.path.join("wrong-kit");
        fs::create_dir(&wrong).unwrap();
        let unrelated = age::x25519::Identity::generate();
        fs::write(
            wrong.join("recovery-key.txt"),
            unrelated.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        let destination = root.path.join("restored");
        assert_eq!(
            recover_saved_synthetic_drill(&snapshot, &wrong, &destination),
            Err(SpikeError::DecryptionFailed)
        );
        fs::write(wrong.join("recovery-key.txt"), vec![b'X'; 257]).unwrap();
        assert_eq!(
            recover_saved_synthetic_drill(&snapshot, &wrong, &destination),
            Err(SpikeError::InvalidRecoveryKey)
        );
        fs::remove_file(wrong.join("recovery-key.txt")).unwrap();
        symlink(kit.join("recovery-key.txt"), wrong.join("recovery-key.txt")).unwrap();
        assert_eq!(
            recover_saved_synthetic_drill(&snapshot, &wrong, &destination),
            Err(SpikeError::UnsafeFile)
        );
        assert!(!destination.exists());
    }

    #[test]
    fn nonregular_saved_key_is_rejected_before_destination_creation() {
        let root = TemporaryDirectory::new();
        let snapshot = root.path.join("snapshot");
        let kit = root.path.join("kit");
        create_saved_synthetic_drill(&snapshot, &kit).unwrap();
        let malformed_kit = root.path.join("nonregular-kit");
        fs::create_dir(&malformed_kit).unwrap();
        fs::create_dir(malformed_kit.join("recovery-key.txt")).unwrap();
        let destination = root.path.join("restored");
        assert_eq!(
            recover_saved_synthetic_drill(&snapshot, &malformed_kit, &destination),
            Err(SpikeError::UnsafeFile)
        );
        assert!(!destination.exists());
    }

    #[test]
    fn saved_kit_recovery_occurs_after_setup_process_exits() {
        let root = TemporaryDirectory::new();
        for mode in ["create", "recover"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "unix::separate_process_worker", "--nocapture"])
                .env("AEGIS_SYNTHETIC_SPIKE_WORKER", mode)
                .env("AEGIS_SYNTHETIC_SPIKE_DIRECTORY", &root.path)
                .output()
                .unwrap();
            assert!(output.status.success(), "synthetic {mode} worker failed");
            for stream in [output.stdout, output.stderr] {
                assert!(!stream
                    .windows(CANARY.len())
                    .any(|part| part == CANARY.as_bytes()));
                assert!(!stream.windows(15).any(|part| part == b"AGE-SECRET-KEY-"));
            }
        }
        assert!(root.path.join("restored/snapshot.age").is_file());
    }

    #[test]
    fn separate_process_worker() {
        let Ok(mode) = std::env::var("AEGIS_SYNTHETIC_SPIKE_WORKER") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("AEGIS_SYNTHETIC_SPIKE_DIRECTORY").unwrap());
        match mode.as_str() {
            "create" => {
                create_saved_synthetic_drill(&root.join("snapshot"), &root.join("kit")).unwrap()
            }
            "recover" => {
                let summary = recover_saved_synthetic_drill(
                    &root.join("snapshot"),
                    &root.join("kit"),
                    &root.join("restored"),
                )
                .unwrap();
                assert_eq!(summary.enabled_grants, 0);
                assert_eq!(summary.restored_sessions, 0);
            }
            _ => panic!("unknown synthetic worker mode"),
        }
    }
}
