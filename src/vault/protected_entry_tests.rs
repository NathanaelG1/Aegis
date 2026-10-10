use super::*;
use std::{
    os::unix::fs::symlink,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    },
    thread,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Harness {
    root: PathBuf,
    clock: Arc<ManualClock>,
    ceremony: Ceremony,
    identity: Identity,
}
impl Harness {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "aegis-protected-entry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let clock = Arc::new(ManualClock::default());
        let ceremony = Ceremony::fixture(clock.clone()).unwrap();
        Self {
            root: root.canonicalize().unwrap(),
            clock,
            ceremony,
            identity: Identity::generate(),
        }
    }
    fn destination(&self) -> PathBuf {
        self.root.join("import")
    }
    fn session(&self) -> ImportSession<'_> {
        ImportSession::fixture(&self.ceremony, &self.destination(), &self.identity).unwrap()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn approve(session: &ImportSession<'_>) {
    session
        .approve(&session.review.entry.bindings.operator, &session.review)
        .unwrap();
}
fn import(session: &ImportSession<'_>, identity: &Identity, fault: Fault) -> Result<(), ErrorCode> {
    session.import(
        &mut Cursor::new(&fixture_frame().0),
        &session.review,
        identity,
        fault,
    )
}
fn assert_no_plaintext(bytes: &[u8]) {
    assert!(!bytes.windows(CANARY.len()).any(|window| window == CANARY));
}
fn frame(bytes: &[u8]) -> PrivateBytes {
    let mut result = PrivateBytes(Vec::with_capacity(12 + bytes.len()));
    result.0.extend_from_slice(INPUT_MAGIC);
    result
        .0
        .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    result.0.extend_from_slice(bytes);
    result
}
struct Reader<F>(F);
impl<F: FnMut(&mut [u8]) -> io::Result<usize>> Read for Reader<F> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0(buffer)
    }
}

#[test]
fn metadata_fits_the_bounded_envelope() {
    let h = Harness::new();
    let session = h.session();
    let size = serde_json::to_vec(&session.review).unwrap().len();
    assert!(size <= MAX_METADATA, "metadata size: {size}");
    let input = Input::read(&mut Cursor::new(&fixture_frame().0), || Ok(())).unwrap();
    assert!(envelope(&session.review, &input).unwrap().0.len() <= crypto::MAX_CLEAR);
}

#[test]
fn composed_import_keeps_actual_ciphertext_and_binds_exact_broker_and_profile() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    let imported = import_delivery_canary(&h.destination(), &material).unwrap();
    let ciphertext = committed_ciphertext(&h.destination()).unwrap();
    let metadata = serde_json::to_vec(&imported.review).unwrap();
    assert!(metadata.len() <= MAX_METADATA);
    assert_eq!(
        imported.review.broker.as_ref().unwrap().profile,
        DeliveryProfile::fixture(1)
    );
    let clear = material.storage.decrypt(&ciphertext).unwrap();
    let value = decode_imported_value(
        &clear.0,
        &crypto::hash(&metadata),
        &DeliveryParameters::fixture(1).secret,
    )
    .unwrap();
    assert_eq!(value.0, store::CANARY_ONE.as_bytes());
    let vault = store::Store::create_imported(&h.root.join("vault"), material, imported).unwrap();
    vault.check_imported_record(&h.destination()).unwrap();
    assert_eq!(
        fs::read(h.root.join("vault/secret-1.age")).unwrap(),
        ciphertext
    );
    assert!(!h.root.join("vault/secret-2.age").exists());
    assert!(!ciphertext
        .windows(store::CANARY_ONE.len())
        .any(|b| b == store::CANARY_ONE.as_bytes()));
}

#[test]
fn composed_import_rejects_changed_custody_profile_reference_and_ciphertext() {
    let mutations: &[fn(&mut ImportReview)] = &[
        |r| r.broker.as_mut().unwrap().vault_id.push('x'),
        |r| r.broker.as_mut().unwrap().writer_key_digest.push('x'),
        |r| r.broker.as_mut().unwrap().recipient_key_digest.push('x'),
        |r| r.broker.as_mut().unwrap().receipt_key_digest.push('x'),
        |r| r.broker.as_mut().unwrap().secret.version = 2,
        |r| r.broker.as_mut().unwrap().profile.recipient.slot.push('x'),
        |r| r.storage_recipient.push('x'),
        |r| r.entry.bindings.secret_version = 2,
        |r| r.entry.bindings.secret_reference = "different-secret",
        |r| r.entry.bindings.recipient_generation = 1,
        |r| r.entry.bindings.recipient_destination_digest[0] ^= 1,
        |r| r.entry.bindings.recipient.verification_key_digest[0] ^= 1,
        |r| r.broker = None,
        |r| r.destination.push("missing"),
    ];
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    for (n, change) in mutations.iter().enumerate() {
        let mut imported =
            import_delivery_canary(&h.root.join(format!("input-{n}")), &material).unwrap();
        change(&mut imported.review);
        assert!(imported.consume(&material).is_err());
    }
    let other = store::Kit::create(&h.root.join("other-kit")).unwrap();
    let imported = import_delivery_canary(&h.destination(), &material).unwrap();
    assert_eq!(
        imported.consume(&other.broker_material()).err(),
        Some(ErrorCode::PolicyChanged)
    );
    // Matching ciphertext hashes alone cannot substitute a different legitimate
    // import: its encrypted frozen review must match this consumed capability.
    let mut first = import_delivery_canary(&h.root.join("first"), &material).unwrap();
    let second = import_delivery_canary(&h.root.join("second"), &material).unwrap();
    let substitute = committed_ciphertext(&second.review.destination).unwrap();
    fs::write(first.review.destination.join(COMMITTED), &substitute).unwrap();
    first.ciphertext_digest = crypto::hash(&substitute);
    assert_eq!(
        first.consume(&material).err(),
        Some(ErrorCode::PolicyChanged)
    );
    for missing in [false, true] {
        let destination = h.root.join(if missing {
            "missing-input"
        } else {
            "tampered-input"
        });
        let imported = import_delivery_canary(&destination, &material).unwrap();
        if missing {
            fs::remove_file(destination.join(COMMITTED)).unwrap();
        } else {
            fs::write(destination.join(COMMITTED), b"changed ciphertext").unwrap();
        }
        let vault = h.root.join(if missing {
            "missing-vault"
        } else {
            "tampered-vault"
        });
        assert!(store::Store::create_imported(&vault, material.clone(), imported).is_err());
        assert!(!vault.exists());
    }
}

#[test]
fn composed_input_rejects_noncanaries_and_changed_metadata_without_retry() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    for (n, bytes) in [CANARY, store::CANARY_TWO.as_bytes(), b"untrusted input"]
        .into_iter()
        .enumerate()
    {
        let ceremony = Ceremony::fixture(h.clock.clone()).unwrap();
        let mut session =
            ImportSession::fixture(&ceremony, &h.root.join(format!("input-{n}")), &kit.storage)
                .unwrap();
        session.review.broker = Some(BrokerImportBinding::fixture(&kit.broker_material()));
        approve(&session);
        assert_eq!(
            session.import(
                &mut Cursor::new(&frame(bytes).0),
                &session.review,
                &kit.storage,
                Fault::None
            ),
            Err(ErrorCode::ScopeDenied)
        );
        assert_eq!(
            session.import(
                &mut Cursor::new(&frame(store::CANARY_ONE.as_bytes()).0),
                &session.review,
                &kit.storage,
                Fault::None
            ),
            Err(ErrorCode::BudgetExhausted)
        );
        assert!(!session.review.destination.exists());
    }
    let imported = import_delivery_canary(&h.destination(), &kit.broker_material()).unwrap();
    let ciphertext = committed_ciphertext(&h.destination()).unwrap();
    let clear = kit.storage.decrypt(&ciphertext).unwrap();
    let digest = crypto::hash(&serde_json::to_vec(&imported.review).unwrap());
    for pos in [0, 12, clear.0.len() - 1] {
        let mut changed = PrivateBytes(clear.0.clone());
        changed.0[pos] ^= 1;
        assert!(
            decode_imported_value(&changed.0, &digest, &DeliveryParameters::fixture(1).secret)
                .is_err()
        );
    }
    assert!(
        decode_imported_value(&clear.0, &digest, &DeliveryParameters::fixture(2).secret).is_err()
    );
    assert!(decode_imported_value(
        &clear.0,
        &crypto::hash(b"other metadata"),
        &DeliveryParameters::fixture(1).secret
    )
    .is_err());
    let mut trailing = PrivateBytes(clear.0.clone());
    trailing.0.push(0);
    assert!(
        decode_imported_value(&trailing.0, &digest, &DeliveryParameters::fixture(1).secret)
            .is_err()
    );
}

#[cfg(feature = "application-slot")]
#[test]
fn rotation_imports_freeze_separate_reviews_and_preserve_both_committed_ciphertexts() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    let paths = [h.root.join("input-one"), h.root.join("input-two")];
    let imported = import_delivery_rotation_canaries(&paths[0], &paths[1], &material).unwrap();
    assert_ne!(
        imported[0].review.entry.instance,
        imported[1].review.entry.instance
    );
    let mut digests = Vec::new();
    for (version, input) in [ImportVersion::One, ImportVersion::Two]
        .into_iter()
        .zip(&imported)
    {
        let review = &input.review;
        assert_eq!(review.entry.bindings, version.bindings());
        assert!(review.entry.receipts.iter().all(|receipt| {
            receipt.bindings == version.bindings() && receipt.instance == review.entry.instance
        }));
        assert_eq!(
            review.broker.as_ref().unwrap().profile,
            DeliveryProfile::installation(version.number())
        );
        let metadata = serde_json::to_vec(review).unwrap();
        assert!(metadata.len() <= MAX_METADATA);
        digests.push(crypto::hash(&metadata));
        let ciphertext = committed_ciphertext(&review.destination).unwrap();
        let clear = material.storage.decrypt(&ciphertext).unwrap();
        assert_eq!(
            decode_imported_for(
                &clear.0,
                digests.last().unwrap(),
                &version.reference(),
                &material,
                ReceiptContract::Installation
            )
            .unwrap()
            .0,
            version.canary()
        );
    }
    assert_ne!(digests[0], digests[1]);
    let vault_path = h.root.join("vault");
    let vault =
        store::Store::create_imported_rotation(&vault_path, material.clone(), imported).unwrap();
    vault.check_imported_rotation(&paths[0], &paths[1]).unwrap();
    assert_eq!(
        vault.check_imported_record(&paths[0]),
        Err(ErrorCode::PolicyChanged)
    );
    assert_eq!(
        vault.check_imported_rotation(&paths[1], &paths[0]),
        Err(ErrorCode::PolicyChanged)
    );
    assert_eq!(
        vault.check_imported_rotation(&paths[0], &paths[0]),
        Err(ErrorCode::PolicyChanged)
    );
    for (version, path) in [1, 2].into_iter().zip(&paths) {
        assert_eq!(
            fs::read(vault_path.join(format!("secret-{version}.age"))).unwrap(),
            committed_ciphertext(path).unwrap()
        );
    }
    let signed =
        crypto::Signed::parse(&fs::read(vault_path.join("manifest.jws")).unwrap()).unwrap();
    let manifest: serde_json::Value = kit.writer.verifier().verify(&signed).unwrap();
    assert_eq!(manifest["receipt_contract"], "installation");
    for (index, version) in [1, 2].into_iter().enumerate() {
        assert_eq!(
            manifest["records"][index]["import_metadata_digest"],
            digests[index]
        );
        assert_eq!(
            manifest["acl"][index]["profile"],
            serde_json::to_value(DeliveryProfile::installation(version)).unwrap()
        );
    }
    drop(vault);
    let reopened = store::Store::open(&vault_path, material).unwrap();
    reopened
        .check_imported_rotation(&paths[0], &paths[1])
        .unwrap();
    let copied = h.root.join("copied-input");
    store::new_directory(&copied).unwrap();
    store::write_new(
        &copied.join(COMMITTED),
        &committed_ciphertext(&paths[1]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        reopened.check_imported_rotation(&paths[0], &copied),
        Err(ErrorCode::PolicyChanged)
    );
    let second = committed_ciphertext(&paths[1]).unwrap();
    fs::write(
        paths[1].join(COMMITTED),
        committed_ciphertext(&paths[0]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        reopened.check_imported_rotation(&paths[0], &paths[1]),
        Err(ErrorCode::PolicyChanged)
    );
    fs::write(paths[1].join(COMMITTED), second).unwrap();
    reopened
        .check_imported_rotation(&paths[0], &paths[1])
        .unwrap();
}

#[cfg(feature = "application-slot")]
#[test]
fn rotation_constructor_rejects_reordered_duplicate_and_corrupted_import_capabilities() {
    for variant in 0..5 {
        let h = Harness::new();
        let kit = store::Kit::create(&h.root.join("kit")).unwrap();
        let material = kit.broker_material();
        let mut pair =
            import_delivery_rotation_canaries(&h.root.join("one"), &h.root.join("two"), &material)
                .unwrap();
        match variant {
            0 => pair.swap(0, 1),
            1 => pair[1].review.entry.instance = pair[0].review.entry.instance,
            2 => pair[1].review.broker.as_mut().unwrap().profile = DeliveryProfile::installation(1),
            3 => pair[1].review.entry.bindings.recipient_generation = 0,
            _ => {
                let mut ciphertext = committed_ciphertext(&pair[1].review.destination).unwrap();
                ciphertext[0] ^= 1;
                fs::write(pair[1].review.destination.join(COMMITTED), ciphertext).unwrap();
            }
        }
        let destination = h.root.join("vault");
        assert_eq!(
            store::Store::create_imported_rotation(&destination, material, pair).err(),
            Some(ErrorCode::PolicyChanged)
        );
        assert!(!destination.exists());
    }
}

#[cfg(feature = "application-slot")]
#[test]
fn second_import_rejects_the_first_canary_and_cannot_reuse_its_review() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    let mut ceremony = Ceremony::fixture(h.clock.clone()).unwrap();
    ceremony.bindings = ImportVersion::Two.bindings();
    let mut session = ImportSession::fixture(&ceremony, &h.destination(), &kit.storage).unwrap();
    session.review.broker = Some(BrokerImportBinding::for_version(
        &material,
        ReceiptContract::Installation,
        ImportVersion::Two,
    ));
    approve(&session);
    assert_eq!(
        session.import(
            &mut Cursor::new(&canary_frame(store::CANARY_ONE.as_bytes()).0),
            &session.review,
            &kit.storage,
            Fault::None
        ),
        Err(ErrorCode::ScopeDenied)
    );
    assert_eq!(
        session.import(
            &mut Cursor::new(&canary_frame(store::CANARY_TWO.as_bytes()).0),
            &session.review,
            &kit.storage,
            Fault::None
        ),
        Err(ErrorCode::BudgetExhausted)
    );
    assert!(!h.destination().exists());
}

#[cfg(feature = "application-slot")]
#[test]
fn rotation_decode_rejects_changed_frozen_evidence_even_with_a_matching_metadata_digest() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    let [_, second] =
        import_delivery_rotation_canaries(&h.root.join("one"), &h.root.join("two"), &material)
            .unwrap();
    let mutations: &[fn(&mut ImportReview)] = &[
        |r| r.input_contract += 1,
        |r| r.maximum_input_bytes += 1,
        |r| r.entry.bindings.secret_version = 1,
        |r| r.entry.bindings.recipient_generation = 0,
        |r| r.entry.bindings.configuration_digest[0] ^= 1,
        |r| r.entry.bindings.operator.enrollment_revision += 1,
        |r| r.entry.expires_at += 1,
        |r| r.entry.canary_use_limit += 1,
        |r| r.entry.receipts[0].instance[0] ^= 1,
        |r| r.entry.receipts[1].bindings.secret_version = 1,
        |r| r.entry.receipts[2].observer = r.entry.bindings.agent.clone(),
        |r| r.entry.receipts[3].observed_at += 1,
        |r| r.entry.receipts[4].expires_at -= 1,
        |r| r.broker.as_mut().unwrap().secret.version = 1,
        |r| r.broker.as_mut().unwrap().profile.revision = 1,
        |r| r.broker.as_mut().unwrap().profile.adapter_contract = 1,
        |r| r.broker.as_mut().unwrap().profile.output_contract = 1,
        |r| r.broker.as_mut().unwrap().vault_id.push('x'),
        |r| r.storage_recipient.push('x'),
        |r| r.broker = None,
    ];
    let input = Input::read(
        &mut Cursor::new(&canary_frame(store::CANARY_TWO.as_bytes()).0),
        || Ok(()),
    )
    .unwrap();
    for mutate in mutations {
        let mut review = second.review.clone();
        mutate(&mut review);
        let clear = envelope(&review, &input).unwrap();
        let digest = crypto::hash(&serde_json::to_vec(&review).unwrap());
        assert_eq!(
            decode_imported_for(
                &clear.0,
                &digest,
                &ImportVersion::Two.reference(),
                &material,
                ReceiptContract::Installation
            )
            .err(),
            Some(ErrorCode::PolicyChanged)
        );
    }
    let first_input = Input::read(
        &mut Cursor::new(&canary_frame(store::CANARY_ONE.as_bytes()).0),
        || Ok(()),
    )
    .unwrap();
    let wrong_canary = envelope(&second.review, &first_input).unwrap();
    let digest = crypto::hash(&serde_json::to_vec(&second.review).unwrap());
    assert_eq!(
        decode_imported_for(
            &wrong_canary.0,
            &digest,
            &ImportVersion::Two.reference(),
            &material,
            ReceiptContract::Installation
        )
        .err(),
        Some(ErrorCode::InvalidProviderResult)
    );
    let valid = envelope(&second.review, &input).unwrap();
    assert_eq!(
        decode_imported_for(
            &valid.0,
            &digest,
            &ImportVersion::Two.reference(),
            &material,
            ReceiptContract::Acceptance
        )
        .err(),
        Some(ErrorCode::PolicyChanged)
    );
    for version in [0, 3, u64::MAX] {
        let mut reference = ImportVersion::Two.reference();
        reference.version = version;
        assert_eq!(
            decode_imported_for(
                &valid.0,
                &digest,
                &reference,
                &material,
                ReceiptContract::Installation
            )
            .err(),
            Some(ErrorCode::InvalidProviderResult)
        );
    }
}

#[test]
fn import_decode_rejects_unsupported_versions_before_fixture_arithmetic() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    let imported = import_delivery_canary(&h.destination(), &material).unwrap();
    let clear = material
        .storage
        .decrypt(&committed_ciphertext(&h.destination()).unwrap())
        .unwrap();
    let digest = crypto::hash(&serde_json::to_vec(&imported.review).unwrap());
    for version in [0, 3, u64::MAX] {
        let mut reference = DeliveryParameters::fixture(1).secret;
        reference.version = version;
        assert_eq!(
            decode_imported_for(
                &clear.0,
                &digest,
                &reference,
                &material,
                ReceiptContract::Acceptance
            )
            .err(),
            Some(ErrorCode::InvalidProviderResult)
        );
    }
}

#[cfg(feature = "application-slot")]
#[test]
fn rotation_decode_rejects_unknown_or_missing_frozen_metadata_fields() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    let [_, second] =
        import_delivery_rotation_canaries(&h.root.join("one"), &h.root.join("two"), &material)
            .unwrap();
    let original = material
        .storage
        .decrypt(&committed_ciphertext(&second.review.destination).unwrap())
        .unwrap();
    let original_length = u32::from_be_bytes(original.0[8..12].try_into().unwrap()) as usize;
    let original_metadata: serde_json::Value =
        serde_json::from_slice(&original.0[12..12 + original_length]).unwrap();
    for variant in 0..4 {
        let mut changed = original_metadata.clone();
        match variant {
            0 => changed["unexpected"] = serde_json::json!(true),
            1 => {
                changed["entry"].as_object_mut().unwrap().remove("receipts");
            }
            2 => changed["entry"]["receipts"][0]["unexpected"] = serde_json::json!(true),
            _ => changed["broker"]["unexpected"] = serde_json::json!(true),
        }
        let metadata = serde_json::to_vec(&changed).unwrap();
        let mut clear = PrivateBytes(Vec::new());
        clear.0.extend_from_slice(ENVELOPE_MAGIC);
        clear
            .0
            .extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        clear.0.extend_from_slice(&metadata);
        clear
            .0
            .extend_from_slice(&original.0[12 + original_length..]);
        assert_eq!(
            decode_imported_for(
                &clear.0,
                &crypto::hash(&metadata),
                &ImportVersion::Two.reference(),
                &material,
                ReceiptContract::Installation
            )
            .err(),
            Some(ErrorCode::PolicyChanged)
        );
    }
}

#[cfg(feature = "application-slot")]
#[test]
fn rotation_manifest_requires_two_distinct_imports_and_both_exact_installation_profiles() {
    let h = Harness::new();
    let kit = store::Kit::create(&h.root.join("kit")).unwrap();
    let material = kit.broker_material();
    let pair =
        import_delivery_rotation_canaries(&h.root.join("one"), &h.root.join("two"), &material)
            .unwrap();
    let path = h.root.join("vault");
    let store = store::Store::create_imported_rotation(&path, material.clone(), pair).unwrap();
    drop(store);
    let manifest_path = path.join("manifest.jws");
    let signed = crypto::Signed::parse(&fs::read(&manifest_path).unwrap()).unwrap();
    let original: serde_json::Value = kit.writer.verifier().verify(&signed).unwrap();
    for variant in 0..7 {
        let mut changed = original.clone();
        match variant {
            0 => {
                changed["records"][1]["import_metadata_digest"] =
                    changed["records"][0]["import_metadata_digest"].clone()
            }
            1 => {
                changed["records"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("import_metadata_digest");
            }
            2 => changed["receipt_contract"] = serde_json::json!("acceptance"),
            3 => {
                changed["acl"].as_array_mut().unwrap().pop();
            }
            4 => changed["acl"][1] = changed["acl"][0].clone(),
            5 => changed["records"].as_array_mut().unwrap().reverse(),
            _ => changed["acl"][1]["profile"]["adapter_contract"] = serde_json::json!(1),
        }
        fs::write(&manifest_path, kit.writer.sign(&changed).unwrap().bytes()).unwrap();
        assert_eq!(
            store::Store::open(&path, material.clone()).err(),
            Some(ErrorCode::PersistenceUnavailable)
        );
    }
    fs::write(&manifest_path, signed.bytes()).unwrap();
    store::Store::open(&path, material).unwrap();
}

#[test]
fn public_drill_has_closed_safe_results_and_only_ciphertext_on_disk() {
    let h = Harness::new();
    let report = run_synthetic_protected_entry_drill(&h.destination()).unwrap();
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::json!({
            "synthetic_only": true,
            "maximum_reader_payload_bytes": 4096,
            "fixed_import_payload_bytes": CANARY.len(),
            "encrypted_fixture_imported": true,
            "exact_metadata_round_trip": true,
            "repeated_import": "budget_exhausted",
            "cancellation": "request_canceled",
            "trailing_input": "invalid_request",
            "plaintext_in_persisted_fixture": false,
            "plaintext_in_report": false,
            "authenticated_human_verified": false,
            "protected_display_verified": false,
            "protected_custody_verified": false,
            "operational_recovery_verified": false,
            "ready_for_real_keys": false
        })
    );
    assert_no_plaintext(&serde_json::to_vec(&report).unwrap());
    assert_no_plaintext(format!("{report:?}").as_bytes());
    let files: Vec<_> = fs::read_dir(h.destination())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(files, [COMMITTED]);
    let bytes = fs::read(h.destination().join(COMMITTED)).unwrap();
    assert_no_plaintext(&bytes);
    assert!(bytes.starts_with(b"age-encryption.org/v1"));
    assert_eq!(
        crate::vault::require_live_deployment(),
        Err(ErrorCode::UnsupportedDeployment)
    );
    // Fresh process/session authority cannot reuse a committed destination.
    assert_eq!(
        run_synthetic_protected_entry_drill(&h.destination()),
        Err(ErrorCode::PersistenceUnavailable)
    );
    assert_eq!(fs::read(h.destination().join(COMMITTED)).unwrap(), bytes);
}

#[test]
fn decrypted_envelope_retains_the_complete_exact_review_and_length_delimited_canary() {
    let h = Harness::new();
    let session = h.session();
    approve(&session);
    import(&session, &h.identity, Fault::None).unwrap();
    let ciphertext = fs::read(h.destination().join(COMMITTED)).unwrap();
    let plaintext = h.identity.decrypt(&ciphertext).unwrap();
    assert_eq!(&plaintext.0[..8], ENVELOPE_MAGIC);
    let metadata_len = u32::from_be_bytes(plaintext.0[8..12].try_into().unwrap()) as usize;
    let encoded_review: serde_json::Value =
        serde_json::from_slice(&plaintext.0[12..12 + metadata_len]).unwrap();
    assert_eq!(
        encoded_review,
        serde_json::to_value(&session.review).unwrap()
    );
    let offset = 12 + metadata_len;
    let value_len =
        u32::from_be_bytes(plaintext.0[offset..offset + 4].try_into().unwrap()) as usize;
    assert_eq!(value_len, CANARY.len());
    assert_eq!(&plaintext.0[offset + 4..], CANARY);
    assert_eq!(
        Identity::generate().decrypt(&ciphertext).err(),
        Some(ErrorCode::InvalidRequest)
    );
    let mut damaged = ciphertext;
    *damaged.last_mut().unwrap() ^= 1;
    assert_eq!(
        h.identity.decrypt(&damaged).err(),
        Some(ErrorCode::InvalidRequest)
    );
}

#[test]
fn input_accepts_exact_maximum_and_chunked_bytes_without_text_conversion() {
    let bytes: Vec<_> = (0..MAX_INPUT).map(|i| (i % 256) as u8).collect();
    let framed = frame(&bytes);
    let mut cursor = Cursor::new(&framed.0);
    let mut attempts = 0;
    let mut reader = Reader(|buffer: &mut [u8]| {
        attempts += 1;
        if attempts % 2 == 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        cursor.read(&mut buffer[..1])
    });
    let input = Input::read(&mut reader, || Ok(())).unwrap();
    assert_eq!(input.len, MAX_INPUT);
    assert_eq!(&input.bytes[..], &bytes);
}

#[test]
fn envelope_rejects_metadata_total_size_and_arithmetic_overflow_before_copying() {
    let h = Harness::new();
    let session = h.session();
    let input = Input::read(&mut Cursor::new(&fixture_frame().0), || Ok(())).unwrap();
    let mut oversized = session.review.clone();
    oversized.storage_recipient = "x".repeat(MAX_METADATA);
    assert_eq!(
        envelope(&oversized, &input).err(),
        Some(ErrorCode::CapacityExceeded)
    );
    let maximum_input = Input {
        bytes: Zeroizing::new([0; MAX_INPUT]),
        len: MAX_INPUT,
    };
    // The reader bound does not promise that an arbitrary payload can fit beside
    // this complete fixture review, nor authorize importing anything but CANARY.
    assert_eq!(
        envelope(&session.review, &maximum_input).err(),
        Some(ErrorCode::CapacityExceeded)
    );
    let impossible_input = Input {
        bytes: Zeroizing::new([0; MAX_INPUT]),
        len: usize::MAX,
    };
    assert_eq!(
        envelope(&session.review, &impossible_input).err(),
        Some(ErrorCode::CapacityExceeded)
    );
}

#[test]
fn zero_length_bad_magic_all_truncations_and_trailing_input_are_rejected() {
    let good = fixture_frame();
    for end in 0..good.0.len() {
        assert_eq!(
            Input::read(&mut Cursor::new(&good.0[..end]), || Ok(())).err(),
            Some(ErrorCode::InvalidRequest)
        );
    }
    let mut malformed = vec![
        frame(&[]),
        fixture_frame(),
        fixture_frame(),
        fixture_frame(),
    ];
    malformed[1].0[0] ^= 1;
    malformed[2].0.push(0);
    malformed[3].0.extend_from_slice(&good.0);
    for bytes in malformed {
        assert_eq!(
            Input::read(&mut Cursor::new(bytes.0.as_slice()), || Ok(())).err(),
            Some(ErrorCode::InvalidRequest)
        );
    }
}

#[test]
fn oversized_length_is_rejected_before_requesting_any_payload() {
    for length in [MAX_INPUT as u32 + 1, u32::MAX] {
        let mut header = [0u8; 12];
        header[..8].copy_from_slice(INPUT_MAGIC);
        header[8..].copy_from_slice(&length.to_be_bytes());
        let mut reads = 0;
        let mut reader = Reader(|buffer: &mut [u8]| {
            reads += 1;
            assert_eq!(reads, 1);
            buffer.copy_from_slice(&header);
            Ok(header.len())
        });
        assert_eq!(
            Input::read(&mut reader, || Ok(())).err(),
            Some(ErrorCode::CapacityExceeded)
        );
    }
}

#[test]
fn errors_impossible_read_counts_and_interrupted_loops_are_bounded_and_sanitized() {
    let mut attempts = 0;
    let mut reader = Reader(|_: &mut [u8]| {
        attempts += 1;
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "private diagnostic",
        ))
    });
    assert_eq!(
        Input::read(&mut reader, || Ok(())).err(),
        Some(ErrorCode::CapacityExceeded)
    );
    assert_eq!(attempts, MAX_INPUT * 2 + 64);
    let mut error = Reader(|_: &mut [u8]| Err(io::Error::other("private diagnostic")));
    assert_eq!(
        Input::read(&mut error, || Ok(())).err(),
        Some(ErrorCode::InvalidRequest)
    );
    let mut impossible = Reader(|buffer: &mut [u8]| Ok(buffer.len() + 1));
    assert_eq!(
        Input::read(&mut impossible, || Ok(())).err(),
        Some(ErrorCode::InvalidRequest)
    );
}

#[test]
fn failed_reads_noncanary_input_and_panics_consume_authority_without_files() {
    for kind in 0..4 {
        let h = Harness::new();
        let session = h.session();
        approve(&session);
        if kind == 3 {
            let mut reader =
                Reader(|_: &mut [u8]| -> io::Result<usize> { panic!("synthetic read failure") });
            assert!(catch_unwind(AssertUnwindSafe(|| session.import(
                &mut reader,
                &session.review,
                &h.identity,
                Fault::None
            )))
            .is_err());
        } else {
            let mut bytes = fixture_frame();
            let expected = match kind {
                0 => {
                    bytes.0.truncate(15);
                    ErrorCode::InvalidRequest
                }
                1 => {
                    bytes.0.push(0);
                    ErrorCode::InvalidRequest
                }
                _ => {
                    bytes.0[12] ^= 1;
                    ErrorCode::ScopeDenied
                }
            };
            assert_eq!(
                session.import(
                    &mut Cursor::new(&bytes.0),
                    &session.review,
                    &h.identity,
                    Fault::None
                ),
                Err(expected)
            );
        }
        assert_eq!(
            import(&session, &h.identity, Fault::None),
            Err(ErrorCode::BudgetExhausted)
        );
        assert!(!h.destination().exists());
        assert!(session.lock().unwrap().reservation.is_none());
    }
}

#[test]
fn frozen_metadata_changes_latch_failure_before_any_input_or_filesystem_effect() {
    let mutations: &[fn(&mut ImportReview)] = &[
        |r| r.destination.push("elsewhere"),
        |r| r.storage_recipient.push('x'),
        |r| r.input_contract += 1,
        |r| r.maximum_input_bytes += 1,
        |r| r.entry.instance[0] ^= 1,
        |r| r.entry.expires_at += 1,
        |r| r.entry.canary_use_limit += 1,
        |r| r.entry.bindings.artifact_digest[0] ^= 1,
        |r| r.entry.bindings.configuration_digest[0] ^= 1,
        |r| r.entry.bindings.acl_revision += 1,
        |r| r.entry.bindings.operator.enrollment_revision += 1,
        |r| r.entry.bindings.recipient.verification_key_digest[0] ^= 1,
        |r| r.entry.bindings.secret_version += 1,
        |r| r.entry.bindings.recipient_generation += 1,
        |r| r.entry.receipts[0].bindings.endpoint_digest[0] ^= 1,
        |r| r.entry.receipts[1].instance[0] ^= 1,
        |r| r.entry.receipts[2].observed_at += 1,
        |r| r.entry.receipts[3].observer.principal = "another-actor",
        |r| r.entry.receipts[4].expires_at -= 1,
    ];
    for mutate in mutations {
        for after_approval in [false, true] {
            let h = Harness::new();
            let session = h.session();
            let mut changed = session.review.clone();
            mutate(&mut changed);
            if after_approval {
                approve(&session);
                let mut reader =
                    Reader(|_: &mut [u8]| -> io::Result<usize> { panic!("must not read") });
                assert_eq!(
                    session.import(&mut reader, &changed, &h.identity, Fault::None),
                    Err(ErrorCode::PolicyChanged)
                );
            } else {
                assert_eq!(
                    session.approve(&h.ceremony.bindings.operator, &changed),
                    Err(ErrorCode::PolicyChanged)
                );
            }
            assert_eq!(
                session.approve(&h.ceremony.bindings.operator, &session.review),
                Err(ErrorCode::BudgetExhausted)
            );
            assert_eq!(
                import(&session, &h.identity, Fault::None),
                Err(ErrorCode::BudgetExhausted)
            );
            assert!(!h.destination().exists());
        }
    }
}

#[test]
fn actor_checks_and_approval_cannot_be_skipped() {
    let h = Harness::new();
    let session = h.session();
    let mut reader = Reader(|_: &mut [u8]| -> io::Result<usize> { panic!("must not read") });
    assert_eq!(
        session.import(&mut reader, &session.review, &h.identity, Fault::None),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(
        session.approve(&h.ceremony.bindings.agent, &session.review),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        session.cancel(&h.ceremony.bindings.agent),
        Err(ErrorCode::AuthenticationRequired)
    );
    approve(&session);
    assert_eq!(
        session.approve(&h.ceremony.bindings.operator, &session.review),
        Err(ErrorCode::BudgetExhausted)
    );
    import(&session, &h.identity, Fault::None).unwrap();
    assert_eq!(
        session.cancel(&h.ceremony.bindings.operator),
        Err(ErrorCode::BudgetExhausted)
    );
}

#[test]
fn a_different_ephemeral_identity_is_denied_before_read_and_consumes_the_permit() {
    let h = Harness::new();
    let session = h.session();
    approve(&session);
    let mut reader = Reader(|_: &mut [u8]| -> io::Result<usize> { panic!("must not read") });
    assert_eq!(
        session.import(
            &mut reader,
            &session.review,
            &Identity::generate(),
            Fault::None
        ),
        Err(ErrorCode::PolicyChanged)
    );
    assert_eq!(
        import(&session, &h.identity, Fault::None),
        Err(ErrorCode::BudgetExhausted)
    );
    assert!(!h.destination().exists());
}

#[test]
fn cancel_before_approval_after_approval_or_during_input_never_publishes() {
    for point in 0..3 {
        let h = Harness::new();
        let session = h.session();
        if point > 0 {
            approve(&session);
        }
        if point == 2 {
            let bytes = fixture_frame();
            let mut cursor = Cursor::new(&bytes.0);
            let mut reads = 0;
            let mut reader = Reader(|buffer: &mut [u8]| {
                let n = cursor.read(buffer)?;
                reads += 1;
                if reads == 2 {
                    session.cancel(&h.ceremony.bindings.operator).unwrap();
                }
                Ok(n)
            });
            assert_eq!(
                session.import(&mut reader, &session.review, &h.identity, Fault::None),
                Err(ErrorCode::RequestCanceled)
            );
        } else {
            session.cancel(&h.ceremony.bindings.operator).unwrap();
        }
        assert_eq!(
            import(&session, &h.identity, Fault::None),
            Err(ErrorCode::RequestCanceled)
        );
        assert_eq!(
            session.approve(&h.ceremony.bindings.operator, &session.review),
            Err(ErrorCode::BudgetExhausted)
        );
        assert!(session.lock().unwrap().reservation.is_none());
        assert!(!h.destination().exists());
    }
}

#[test]
fn deadline_and_clock_regression_during_read_latch_failure() {
    for regression in [false, true] {
        let h = Harness::new();
        let session = h.session();
        h.clock.set(10);
        approve(&session);
        let bytes = fixture_frame();
        let mut cursor = Cursor::new(&bytes.0);
        let mut reader = Reader(|buffer: &mut [u8]| {
            let n = cursor.read(buffer)?;
            h.clock.set(if regression {
                9
            } else {
                session.review.entry.expires_at
            });
            Ok(n)
        });
        let error = if regression {
            ErrorCode::SessionExpired
        } else {
            ErrorCode::RequestExpired
        };
        assert_eq!(
            session.import(&mut reader, &session.review, &h.identity, Fault::None),
            Err(error)
        );
        h.clock.set(10);
        assert_eq!(
            import(&session, &h.identity, Fault::None),
            Err(ErrorCode::BudgetExhausted)
        );
        assert!(!h.destination().exists());
    }
}

#[test]
fn publication_faults_preserve_consumption_and_report_cleanup_or_uncertainty() {
    for fault in [
        Fault::PartialWrite,
        Fault::BeforePublish,
        Fault::AfterPublish,
        Fault::Cleanup,
    ] {
        let h = Harness::new();
        let session = h.session();
        approve(&session);
        let expected = if matches!(fault, Fault::AfterPublish | Fault::Cleanup) {
            ErrorCode::ReconciliationRequired
        } else {
            ErrorCode::PersistenceUnavailable
        };
        assert_eq!(import(&session, &h.identity, fault), Err(expected));
        assert_eq!(
            import(&session, &h.identity, Fault::None),
            Err(ErrorCode::BudgetExhausted)
        );
        match fault {
            Fault::AfterPublish => {
                assert!(session.lock().unwrap().phase == Phase::Uncertain);
                assert!(h.destination().join(COMMITTED).exists());
                for entry in fs::read_dir(h.destination()).unwrap() {
                    assert_no_plaintext(&fs::read(entry.unwrap().path()).unwrap());
                }
            }
            Fault::Cleanup => {
                assert_eq!(
                    fs::read(h.destination().join("unexpected")).unwrap(),
                    b"nonsecret fixture"
                );
                assert!(!h.destination().join(STAGED).exists());
                assert!(!h.destination().join(COMMITTED).exists());
            }
            _ => assert!(!h.destination().exists()),
        }
    }
}

#[test]
fn existing_destinations_are_never_overwritten_even_when_empty() {
    for as_directory in [false, true] {
        let h = Harness::new();
        if as_directory {
            fs::create_dir(h.destination()).unwrap();
        } else {
            fs::write(h.destination(), b"existing fixture").unwrap();
        }
        let session = h.session();
        approve(&session);
        assert_eq!(
            import(&session, &h.identity, Fault::None),
            Err(ErrorCode::PersistenceUnavailable)
        );
        if as_directory {
            assert_eq!(fs::read_dir(h.destination()).unwrap().count(), 0);
        } else {
            assert_eq!(fs::read(h.destination()).unwrap(), b"existing fixture");
        }
    }
}

#[test]
fn publication_and_cleanup_never_clobber_unexpected_objects() {
    let h = Harness::new();
    let mut transaction =
        Transaction::stage(&h.destination(), b"synthetic ciphertext", Fault::None).unwrap();
    fs::write(h.destination().join(COMMITTED), b"existing record").unwrap();
    assert_eq!(
        transaction.publish(Fault::None),
        Err(ErrorCode::PersistenceUnavailable)
    );
    assert_eq!(
        transaction.abort(ErrorCode::PersistenceUnavailable),
        Err(ErrorCode::ReconciliationRequired)
    );
    drop(transaction);
    assert_eq!(
        fs::read(h.destination().join(COMMITTED)).unwrap(),
        b"existing record"
    );
    assert!(!h.destination().join(STAGED).exists());
}

#[test]
fn unsafe_path_forms_and_existing_symlink_components_are_rejected() {
    let h = Harness::new();
    for path in [
        PathBuf::from("relative"),
        PathBuf::from("/"),
        h.root.join("../other"),
        PathBuf::from(format!("{}/./import", h.root.display())),
        PathBuf::from(format!("{}//import", h.root.display())),
        PathBuf::from(format!("{}/import/", h.root.display())),
        h.root.join("x".repeat(1025)),
    ] {
        assert_eq!(validate_destination(&path), Err(ErrorCode::InvalidRequest));
    }
    let target = h.root.join("target");
    fs::create_dir(&target).unwrap();
    let link = h.root.join("link");
    symlink(&target, &link).unwrap();
    assert_eq!(validate_destination(&link), Err(ErrorCode::InvalidRequest));
    assert_eq!(
        validate_destination(&link.join("child")),
        Err(ErrorCode::InvalidRequest)
    );
    let dangling = h.root.join("dangling");
    symlink(h.root.join("absent"), &dangling).unwrap();
    assert_eq!(
        validate_destination(&dangling),
        Err(ErrorCode::InvalidRequest)
    );
}

#[test]
fn dropping_an_unpublished_transaction_cleans_only_its_owned_staging_object() {
    let h = Harness::new();
    let transaction =
        Transaction::stage(&h.destination(), b"synthetic ciphertext", Fault::None).unwrap();
    assert!(h.destination().join(STAGED).exists());
    drop(transaction);
    assert!(!h.destination().exists());
    let transaction =
        Transaction::stage(&h.destination(), b"synthetic ciphertext", Fault::None).unwrap();
    // Hold the old inode through the open file while replacing its path.
    fs::remove_file(h.destination().join(STAGED)).unwrap();
    fs::write(h.destination().join(STAGED), b"replacement fixture").unwrap();
    drop(transaction);
    assert_eq!(
        fs::read(h.destination().join(STAGED)).unwrap(),
        b"replacement fixture"
    );
}

#[test]
fn dropping_approval_does_not_refund_the_ceremony_reservation() {
    let h = Harness::new();
    let session = h.session();
    approve(&session);
    let review = session.review.entry.clone();
    drop(session);
    assert_eq!(
        h.ceremony.reserve(&h.ceremony.bindings, &review).err(),
        Some(ErrorCode::BudgetExhausted)
    );
    assert!(!h.destination().exists());
}

#[test]
fn racing_imports_consume_only_one_permit() {
    let h = Harness::new();
    let session = h.session();
    approve(&session);
    let barrier = Barrier::new(2);
    let results = thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            import(&session, &h.identity, Fault::None)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            import(&session, &h.identity, Fault::None)
        });
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results.contains(&Err(ErrorCode::BudgetExhausted)));
    assert!(verified_fixture(&session.review, &h.identity).unwrap());
}

#[test]
fn racing_cancel_and_publish_have_one_serialized_outcome() {
    for _ in 0..8 {
        let h = Harness::new();
        let session = h.session();
        approve(&session);
        let barrier = Barrier::new(2);
        let (imported, canceled) = thread::scope(|scope| {
            let a = scope.spawn(|| {
                barrier.wait();
                import(&session, &h.identity, Fault::None)
            });
            let b = scope.spawn(|| {
                barrier.wait();
                session.cancel(&h.ceremony.bindings.operator)
            });
            (a.join().unwrap(), b.join().unwrap())
        });
        match imported {
            Ok(()) => {
                assert_eq!(canceled, Err(ErrorCode::BudgetExhausted));
                assert!(verified_fixture(&session.review, &h.identity).unwrap());
            }
            Err(ErrorCode::RequestCanceled) => {
                assert_eq!(canceled, Ok(()));
                assert!(!h.destination().exists());
            }
            other => panic!("unexpected safe status: {other:?}"),
        }
    }
}
