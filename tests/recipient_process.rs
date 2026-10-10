use std::process::Command;

#[cfg(not(all(unix, feature = "vault-spike")))]
#[test]
fn process_drill_is_unavailable_by_default() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegis-recipient-process"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[cfg(all(unix, feature = "vault-spike"))]
mod unix {
    use super::*;
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        process::Stdio,
        sync::atomic::{AtomicUsize, Ordering},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Paths(PathBuf);
    impl Paths {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aegis-process-integration-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn command(&self) -> Command {
            let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-recipient-process"));
            command
                .arg(self.0.join("vault"))
                .arg(self.0.join("custody"))
                .arg(self.0.join("recipient"));
            command
        }
    }
    impl Drop for Paths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn assert_safe(bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for forbidden in [
            "AEGIS_SYNTHETIC_DELIVERY_CANARY",
            "AGE-SECRET-KEY",
            "assertion",
            "capsule",
            "BEGIN PRIVATE KEY",
        ] {
            assert!(!text.contains(forbidden), "unexpected private content");
        }
    }
    #[test]
    fn real_child_delivery_rotation_cold_reopen_and_revoke_are_closed_and_unisolated() {
        let paths = Paths::new();
        let output = paths.command().output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert_safe(&output.stdout);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for field in [
            "synthetic_only",
            "separate_recipient_process",
            "bootstrap_in_child",
            "duplicate_reused",
            "cold_start_required_authentication",
            "revocation_survived_restart",
        ] {
            assert_eq!(report[field], true, "{field}");
        }
        for field in [
            "broker_loaded_recipient_private_keys",
            "delivery_responses_contain_canary",
            "automatic_retry_allowed",
            "independent_human_presence_verified",
            "protected_custody_verified",
            "protected_deployment_verified",
            "ready_for_real_keys",
        ] {
            assert_eq!(report[field], false, "{field}");
        }
        assert_eq!(report["completed_deliveries"], 2);
        assert_eq!(report["consumed_uses"], 2);
        assert_eq!(report["remaining_uses"], 2);
        assert_eq!(report["recipient_generation"], 2);
        assert_eq!(report["restored_sessions"], 0);
        assert_eq!(report["workflow_mode"], "UNISOLATED");
        assert!(paths.0.join("recipient/accepted.jws").is_file());
        assert!(!paths.0.join("custody/fixture-keys.json").exists());
        let before = fs::read(paths.0.join("recipient/accepted.jws")).unwrap();
        let repeated = paths.command().output().unwrap();
        assert!(!repeated.status.success());
        assert!(repeated.stdout.is_empty());
        assert_safe(&repeated.stderr);
        assert_eq!(
            fs::read(paths.0.join("recipient/accepted.jws")).unwrap(),
            before
        );
    }

    #[test]
    fn child_rejects_invalid_frames_without_installation_or_raw_errors() {
        let paths = Paths::new();
        aegis::vault::custody::bootstrap_synthetic_custody(&paths.0.join("custody")).unwrap();
        let requests = [
            vec![],
            vec![0, 0],
            vec![0, 0, 0, 7, b'{'],
            vec![0, 0, 0, 0],
            vec![0, 1, 0, 1],
            {
                let body = br#"{"method":"status","nonce":"bad","secret":"CANARY"}"#;
                let mut frame = (body.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(body);
                frame
            },
        ];
        for (index, request) in requests.into_iter().enumerate() {
            let state = paths.0.join(format!("recipient-{index}"));
            let mut child = Command::new(env!("CARGO_BIN_EXE_aegis-recipient-process"))
                .arg("--aegis-synthetic-recipient-child-v1")
                .arg("create")
                .arg(paths.0.join("custody/recipient"))
                .arg(&state)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&request).unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
            assert!(fs::read(state.join("accepted.jws")).unwrap().is_empty());
        }
    }
}
