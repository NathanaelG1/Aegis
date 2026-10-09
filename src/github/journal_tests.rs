use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aegis-intent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn journal(&self) -> PathBuf {
        self.0.join("journal")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn id(value: &str) -> RequestId {
    RequestId::new(value).unwrap()
}
fn start() -> Event {
    Event::Start {
        kind: KIND.into(),
        instance: [7; 16],
        enrollment: Enrollment::fixture(),
        maximum_reservations: MAX_RECORDS,
    }
}
fn reserve(value: &str) -> Event {
    Event::Reserve {
        intent: Intent {
            request_id: id(value),
            instance: [7; 16],
            enrollment: Enrollment::fixture(),
            approval_revision: 1,
            reserved_at: Moment {
                unix: 1000,
                elapsed: 0,
            },
            approval_expires_elapsed: 30,
        },
    }
}
fn encoded(events: &[Event]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, event) in events.iter().enumerate() {
        serde_json::to_writer(
            &mut bytes,
            &Frame {
                schema_version: SCHEMA,
                sequence: index + 1,
                event: event.clone(),
            },
        )
        .unwrap();
        bytes.push(b'\n');
    }
    bytes
}
fn successful_events() -> Vec<Event> {
    vec![
        start(),
        reserve("first"),
        Event::MintIntent {
            request_id: id("first"),
        },
        Event::TokenReceived {
            request_id: id("first"),
            reported_expires_at: 4600,
        },
        Event::TokenValidated {
            request_id: id("first"),
        },
        Event::ReadIntent {
            request_id: id("first"),
            mint_request_id: id("first"),
        },
        Event::Complete {
            request_id: id("first"),
            outcome: Terminal::Succeeded,
            blocks_new_requests: false,
        },
    ]
}
#[test]
fn replay_classifies_every_pre_effect_and_post_effect_boundary_without_authority() {
    let events = successful_events();
    for length in 1..=events.len() {
        let report = parse(&encoded(&events[..length])).unwrap().recovery();
        assert_eq!(report.reservations_consumed, usize::from(length > 1));
        assert_eq!(report.restored_grants, 0);
        assert_eq!(report.restored_sessions, 0);
        assert!(!report.automatic_retry_allowed);
        assert_eq!(
            report.incomplete_operations,
            usize::from((2..7).contains(&length))
        );
        assert_eq!(report.uncertain_mints, usize::from(length == 3));
        assert_eq!(report.unresolved_tokens, usize::from(length >= 4));
        assert_eq!(
            report.unknown_operations,
            usize::from((3..7).contains(&length))
        );
    }
}
#[test]
fn completed_read_does_not_reconcile_a_token_and_revocation_has_distinct_stages() {
    let mut events = successful_events();
    assert!(
        parse(&encoded(&events))
            .unwrap()
            .recovery()
            .reconciliation_required
    );
    events.push(Event::RevokeAuthority {});
    events.push(Event::RevokeIntent {
        mint_request_id: id("first"),
    });
    let report = parse(&encoded(&events)).unwrap().recovery();
    assert!(report.local_authority_revoked);
    assert_eq!(report.uncertain_revocations, 1);
    events.push(Event::RevokeComplete {
        mint_request_id: id("first"),
        confirmed: false,
    });
    assert_eq!(
        parse(&encoded(&events))
            .unwrap()
            .recovery()
            .uncertain_revocations,
        1
    );
    events.pop();
    events.push(Event::RevokeComplete {
        mint_request_id: id("first"),
        confirmed: true,
    });
    let report = parse(&encoded(&events)).unwrap().recovery();
    assert_eq!(report.unresolved_tokens, 0);
    assert!(!report.reconciliation_required);
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.restored_sessions, 0);
}
#[test]
fn unknown_mint_is_not_cleared_by_revoking_older_known_tokens() {
    let mut events = successful_events();
    events.extend([
        reserve("second"),
        Event::MintIntent {
            request_id: id("second"),
        },
        Event::Complete {
            request_id: id("second"),
            outcome: Terminal::Unknown,
            blocks_new_requests: true,
        },
        Event::RevokeAuthority {},
        Event::RevokeIntent {
            mint_request_id: id("first"),
        },
        Event::RevokeComplete {
            mint_request_id: id("first"),
            confirmed: true,
        },
    ]);
    let report = parse(&encoded(&events)).unwrap().recovery();
    assert_eq!(report.reservations_consumed, 2);
    assert_eq!(report.uncertain_mints, 1);
    assert_eq!(report.unresolved_tokens, 0);
    assert!(report.reconciliation_required);
}
#[test]
fn known_rejection_consumes_reservation_without_claiming_a_token() {
    let events = [
        start(),
        reserve("rejected"),
        Event::MintIntent {
            request_id: id("rejected"),
        },
        Event::Complete {
            request_id: id("rejected"),
            outcome: Terminal::Failed,
            blocks_new_requests: false,
        },
    ];
    let report = parse(&encoded(&events)).unwrap().recovery();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.uncertain_mints, 0);
    assert_eq!(report.restored_grants, 0);
}
#[test]
fn strict_state_machine_rejects_reordering_duplicates_or_cross_issuance_references() {
    for events in [
        vec![reserve("first")],
        vec![start(), start()],
        vec![start(), reserve("first"), reserve("first")],
        vec![start(), reserve("first"), reserve("second")],
        vec![
            start(),
            reserve("first"),
            Event::TokenReceived {
                request_id: id("first"),
                reported_expires_at: 4600,
            },
        ],
        vec![
            start(),
            reserve("first"),
            Event::Complete {
                request_id: id("first"),
                outcome: Terminal::Succeeded,
                blocks_new_requests: false,
            },
        ],
        vec![start(), Event::RevokeAuthority {}, reserve("first")],
        vec![
            start(),
            reserve("first"),
            Event::ReadIntent {
                request_id: id("first"),
                mint_request_id: id("unknown"),
            },
        ],
        vec![
            start(),
            Event::RevokeComplete {
                mint_request_id: id("unknown"),
                confirmed: true,
            },
        ],
    ] {
        assert!(matches!(
            parse(&encoded(&events)),
            Err(JournalError::InvalidJournal)
        ));
    }
    let mut events = successful_events();
    events.push(Event::Complete {
        request_id: id("first"),
        outcome: Terminal::Failed,
        blocks_new_requests: false,
    });
    assert!(parse(&encoded(&events)).is_err());
    events = successful_events();
    events.push(Event::RevokeIntent {
        mint_request_id: id("first"),
    });
    assert!(parse(&encoded(&events)).is_err());
}
#[test]
fn every_fixed_authority_binding_is_validated_and_not_restored() {
    let original = serde_json::to_value(start()).unwrap();
    for (field, bad) in [
        ("app_id", serde_json::json!(999)),
        ("client_id", serde_json::json!("other")),
        ("installation_id", serde_json::json!(999)),
        ("account_id", serde_json::json!(999)),
        ("login", serde_json::json!("Other")),
        ("account_kind", serde_json::json!("Organization")),
        ("selection", serde_json::json!("all")),
        ("repository_id", serde_json::json!(999)),
        ("repository_name", serde_json::json!("Another")),
        ("repository_owner_id", serde_json::json!(999)),
        ("signer_id", serde_json::json!("other-key")),
        ("signer_version", serde_json::json!(2)),
        ("binding_revision", serde_json::json!(2)),
        ("contents_ceiling", serde_json::json!("read")),
        ("metadata_ceiling", serde_json::json!("write")),
        ("requested_metadata", serde_json::json!("write")),
        ("operation", serde_json::json!("write")),
        ("output_revision", serde_json::json!(2)),
    ] {
        let mut changed = original.clone();
        changed["enrollment"][field] = bad;
        let event: Event = serde_json::from_value(changed).unwrap();
        assert!(parse(&encoded(&[event])).is_err());
    }
    for (field, bad) in [
        ("approval_revision", serde_json::json!(2)),
        ("approval_expires_elapsed", serde_json::json!(0)),
        ("instance", serde_json::json!(vec![8; 16])),
    ] {
        let mut value = serde_json::to_value(reserve("first")).unwrap();
        value["intent"][field] = bad;
        let event = serde_json::from_value(value).unwrap();
        assert!(parse(&encoded(&[start(), event])).is_err());
    }
}
#[test]
fn schema_sequence_unknown_and_duplicate_fields_fail_closed() {
    let bytes = encoded(&[start()]);
    let line = String::from_utf8(bytes).unwrap();
    for altered in [
        line.replace("\"schema_version\":1", "\"schema_version\":3"),
        line.replace("\"sequence\":1", "\"sequence\":2"),
        line.replace("\"sequence\":1", "\"sequence\":1,\"sequence\":1"),
        line.replace("\"sequence\":1", "\"sequence\":1,\"approved\":true"),
        line.replace("\"app_id\":101", "\"app_id\":101,\"app_id\":101"),
        line.replace("\"app_id\":101", "\"app_id\":101,\"secret\":\"bad\""),
        line.replace(
            "\"type\":\"start\"",
            "\"type\":\"start\",\"type\":\"start\"",
        ),
    ] {
        assert!(parse(altered.as_bytes()).is_err());
    }
    let unsupported = line.replace("\"schema_version\":1", "\"schema_version\":3");
    assert!(matches!(
        parse(unsupported.as_bytes()),
        Err(JournalError::UnsupportedSchema)
    ));
}
#[test]
fn partial_records_fail_closed_but_complete_prefixes_remain_conservative() {
    let bytes = encoded(&successful_events());
    for end in 0..bytes.len() {
        let result = parse(&bytes[..end]);
        if end > 0 && bytes[end - 1] == b'\n' {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
    let mut extra = bytes.clone();
    extra.push(b'\n');
    assert!(parse(&extra).is_err());
    assert!(parse(&vec![b'x'; MAX_BYTES + 1]).is_err());
    let oversized = format!("{}\n", " ".repeat(MAX_LINE));
    assert!(parse(oversized.as_bytes()).is_err());
}
#[test]
fn new_directory_file_lock_and_read_only_inspection_preserve_state() {
    let directory = Directory::new();
    let path = directory.journal();
    let journal = Journal::create(&path, [7; 16]).unwrap();
    assert!(matches!(inspect(&path), Err(JournalError::Busy)));
    assert!(matches!(
        Journal::create(&path, [8; 16]),
        Err(JournalError::DestinationExists)
    ));
    journal.append(reserve("first")).unwrap();
    drop(journal);
    let before = fs::read(path.join(FILE_NAME)).unwrap();
    let report = inspect(&path).unwrap();
    assert_eq!(report.reservations_consumed, 1);
    assert_eq!(report.restored_grants, 0);
    assert_eq!(fs::read(path.join(FILE_NAME)).unwrap(), before);
}
#[test]
fn symlink_hardlink_nonregular_and_nonprivate_inputs_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let directory = Directory::new();
    let path = directory.journal();
    let journal = Journal::create(&path, [7; 16]).unwrap();
    drop(journal);
    let link = directory.0.join("link");
    symlink(&path, &link).unwrap();
    assert_eq!(inspect(&link), Err(JournalError::UnsafeFile));
    fs::hard_link(path.join(FILE_NAME), directory.0.join("hardlink")).unwrap();
    assert_eq!(inspect(&path), Err(JournalError::UnsafeFile));
    fs::remove_file(directory.0.join("hardlink")).unwrap();
    fs::set_permissions(path.join(FILE_NAME), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(inspect(&path), Err(JournalError::UnsafeFile));
    fs::remove_file(path.join(FILE_NAME)).unwrap();
    fs::create_dir(path.join(FILE_NAME)).unwrap();
    assert_eq!(inspect(&path), Err(JournalError::UnsafeFile));
    assert!(matches!(
        Journal::create(Path::new("relative"), [7; 16]),
        Err(JournalError::InvalidPath)
    ));
}
#[test]
fn append_faults_poison_writer_and_do_not_erase_retained_prefixes() {
    for fault in [
        Fault::BeforeWrite,
        Fault::PartialWrite,
        Fault::AfterWrite,
        Fault::AfterSync,
    ] {
        let directory = Directory::new();
        let path = directory.journal();
        let journal = Journal::create(&path, [7; 16]).unwrap();
        journal.fault(2, fault);
        assert!(journal.append(reserve("first")).is_err());
        assert_eq!(
            journal.append(reserve("second")),
            Err(JournalError::Unavailable)
        );
        drop(journal);
        let result = inspect(&path);
        if matches!(fault, Fault::PartialWrite) {
            assert_eq!(result, Err(JournalError::InvalidJournal));
        } else {
            assert_eq!(
                result.unwrap().reservations_consumed,
                usize::from(!matches!(fault, Fault::BeforeWrite))
            );
        }
    }
}

#[test]
fn closing_the_owner_explicitly_releases_a_lock_even_with_a_temporary_inherited_description() {
    let directory = Directory::new();
    let path = directory.journal();
    let journal = Journal::create(&path, [7; 16]).unwrap();
    let duplicate = journal.writer.lock().unwrap().file.try_clone().unwrap();
    assert_eq!(inspect(&path), Err(JournalError::Busy));
    drop(journal);
    assert!(inspect(&path).is_ok());
    drop(duplicate);
}
#[test]
fn impossible_validated_expiry_is_corrupt_even_though_raw_receipts_are_untrusted() {
    let mut events = successful_events();
    events[3] = Event::TokenReceived {
        request_id: id("first"),
        reported_expires_at: u64::MAX,
    };
    assert!(parse(&encoded(&events[..4])).is_ok());
    assert!(parse(&encoded(&events[..5])).is_err());
}

#[test]
fn empty_revocation_event_rejects_unknown_and_duplicate_fields() {
    let mut events = successful_events();
    events.push(Event::RevokeAuthority {});
    let text = String::from_utf8(encoded(&events)).unwrap();
    for value in [
        text.replace(
            "\"type\":\"revoke_authority\"",
            "\"type\":\"revoke_authority\",\"unexpected\":true",
        ),
        text.replace(
            "\"type\":\"revoke_authority\"",
            "\"type\":\"revoke_authority\",\"unexpected\":true,\"unexpected\":false",
        ),
        text.replace(
            "\"type\":\"revoke_authority\"",
            "\"type\":\"revoke_authority\",\"type\":\"revoke_authority\"",
        ),
    ] {
        assert!(parse(value.as_bytes()).is_err());
    }
}

#[test]
fn terminal_uncertainty_or_quarantine_cannot_be_followed_by_new_reservations() {
    let mut events = vec![
        start(),
        reserve("first"),
        Event::MintIntent {
            request_id: id("first"),
        },
        Event::Complete {
            request_id: id("first"),
            outcome: Terminal::Unknown,
            blocks_new_requests: true,
        },
    ];
    assert!(parse(&encoded(&events)).is_ok());
    events.push(reserve("new"));
    assert!(parse(&encoded(&events)).is_err());
    events = vec![
        start(),
        reserve("first"),
        Event::MintIntent {
            request_id: id("first"),
        },
        Event::TokenReceived {
            request_id: id("first"),
            reported_expires_at: 0,
        },
        Event::Complete {
            request_id: id("first"),
            outcome: Terminal::Failed,
            blocks_new_requests: true,
        },
    ];
    assert!(parse(&encoded(&events)).is_ok());
    events.push(reserve("new"));
    assert!(parse(&encoded(&events)).is_err());
    events.pop();
    events.pop();
    events.push(Event::Complete {
        request_id: id("first"),
        outcome: Terminal::Failed,
        blocks_new_requests: false,
    });
    assert!(parse(&encoded(&events)).is_err());
}
