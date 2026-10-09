use super::*;
use std::sync::Barrier;

fn store() -> (EphemeralStore, Arc<FixtureClock>) {
    let clock = Arc::new(FixtureClock::new());
    let store = EphemeralStore::new(clock.clone()).unwrap();
    (store, clock)
}
fn signed_raw(store: &EphemeralStore, header: &str, payload: &str) -> AppJwt {
    require_fixed_provider().unwrap();
    let state = store.shared.state.lock().unwrap();
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &state.material.as_ref().unwrap().encoding,
        Algorithm::RS256,
    )
    .unwrap();
    AppJwt(format!("{message}.{signature}"))
}
fn valid_claims() -> String {
    format!(r#"{{"iss":"{ISSUER}","iat":1799999940,"exp":1800000540}}"#)
}
#[test]
fn fixed_demo_reports_verified_rsa_and_lifecycle_without_credential_fields() {
    let report = run_synthetic_signing_demo().unwrap();
    assert_eq!(report.algorithm, "RS256");
    assert_eq!(report.rsa_bits, 2048);
    assert_eq!(report.signatures_created, 1);
    assert!(
        report.synthetic_only
            && report.verified_signature_and_claims
            && report.lock_denied_signing
            && report.stale_handle_denied
            && report.revoke_denied_signing
            && report.already_issued_jwt_still_verifies
            && report.protected_storage_unavailable
    );
    assert!(!report.live_available);
    let value = serde_json::to_value(&report).unwrap();
    assert!(value.get("token").is_none());
    assert!(value.get("private_key").is_none());
    assert!(!format!("{report:?}").contains("PRIVATE KEY"));
}
#[test]
fn generated_key_signs_exact_fixed_claims_and_library_verifies_signature() {
    let (store, clock) = store();
    let jwt = store
        .resolve(&KeyBinding::fixture())
        .unwrap()
        .sign_app_jwt()
        .unwrap();
    let claims = strict_parts(&jwt.0).unwrap();
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.iat, clock.now().utc - 60);
    assert_eq!(claims.exp, clock.now().utc + 540);
    assert_eq!(claims.exp - claims.iat, 600);
    store.verifier().unwrap().verify(&jwt, clock.now()).unwrap();
    let report = run_synthetic_signing_demo().unwrap();
    assert!(!serde_json::to_string(&report).unwrap().contains(&jwt.0));
}
#[test]
fn key_source_is_exact_reference_version_issuer_and_algorithm_bound() {
    let (store, _) = store();
    for mutation in [
        |b: &mut KeyBinding| b.label = "real-key".into(),
        |b: &mut KeyBinding| b.label = "/tmp/key.pem".into(),
        |b: &mut KeyBinding| b.version = 0,
        |b: &mut KeyBinding| b.version = 2,
        |b: &mut KeyBinding| b.issuer = "another-app".into(),
        |b: &mut KeyBinding| b.algorithm = Algorithm::HS256,
        |b: &mut KeyBinding| b.algorithm = Algorithm::RS512,
    ] {
        let mut binding = KeyBinding::fixture();
        mutation(&mut binding);
        assert!(matches!(
            store.resolve(&binding),
            Err(SigningError::InvalidBinding)
        ));
    }
    assert_eq!(store.shared.state.lock().unwrap().signatures, 0);
}
#[test]
fn protected_store_fails_closed_without_resolving_any_reference() {
    for label in [LABEL, "arbitrary-key", "/path/to/a/key"] {
        let mut binding = KeyBinding::fixture();
        binding.label = label.into();
        assert!(matches!(
            UnavailableProtectedStore.resolve(&binding),
            Err(SigningError::UnsupportedProtectedStorage)
        ));
    }
}
#[test]
fn lock_unlock_invalidates_old_handles_and_new_ones_remain_bounded() {
    let (store, _) = store();
    let old = store.resolve(&KeyBinding::fixture()).unwrap();
    store.lock().unwrap();
    assert!(matches!(old.sign_app_jwt(), Err(SigningError::Locked)));
    assert!(matches!(
        store.resolve(&KeyBinding::fixture()),
        Err(SigningError::Locked)
    ));
    store.unlock_fixture().unwrap();
    assert!(matches!(old.sign_app_jwt(), Err(SigningError::StaleHandle)));
    store
        .resolve(&KeyBinding::fixture())
        .unwrap()
        .sign_app_jwt()
        .unwrap();
}
#[test]
fn rotation_invalidates_version_and_handle_without_recalling_prior_jwt() {
    let (store, clock) = store();
    let old = store.resolve(&KeyBinding::fixture()).unwrap();
    let jwt = old.sign_app_jwt().unwrap();
    let verifier = store.verifier().unwrap();
    let binding = store.rotate_fixture().unwrap();
    assert_eq!(binding.version, 2);
    assert!(matches!(old.sign_app_jwt(), Err(SigningError::StaleHandle)));
    assert!(matches!(
        store.resolve(&KeyBinding::fixture()),
        Err(SigningError::InvalidBinding)
    ));
    let newer = store.resolve(&binding).unwrap().sign_app_jwt().unwrap();
    verifier.verify(&jwt, clock.now()).unwrap();
    assert_eq!(
        verifier.verify(&newer, clock.now()),
        Err(SigningError::InvalidToken)
    );
    store
        .verifier()
        .unwrap()
        .verify(&newer, clock.now())
        .unwrap();
}
#[test]
fn revocation_denies_future_signing_but_expiry_controls_existing_jwt() {
    let (store, clock) = store();
    let signer = store.resolve(&KeyBinding::fixture()).unwrap();
    let verifier = store.verifier().unwrap();
    let jwt = signer.sign_app_jwt().unwrap();
    store.revoke().unwrap();
    assert!(matches!(signer.sign_app_jwt(), Err(SigningError::Revoked)));
    assert!(matches!(
        store.resolve(&KeyBinding::fixture()),
        Err(SigningError::Revoked)
    ));
    assert_eq!(store.unlock_fixture(), Err(SigningError::Revoked));
    verifier
        .verify(
            &jwt,
            Stamp {
                utc: clock.now().utc + 539,
                elapsed: 539,
            },
        )
        .unwrap();
    assert_eq!(
        verifier.verify(
            &jwt,
            Stamp {
                utc: clock.now().utc + 540,
                elapsed: 540
            }
        ),
        Err(SigningError::InvalidToken)
    );
}
#[test]
fn handle_and_store_lifetimes_use_elapsed_time_at_exact_boundaries() {
    let (store, clock) = store();
    let signer = store.resolve(&KeyBinding::fixture()).unwrap();
    clock.elapsed.store(30, Ordering::SeqCst);
    assert!(matches!(
        signer.sign_app_jwt(),
        Err(SigningError::LeaseExpired)
    ));
    store
        .resolve(&KeyBinding::fixture())
        .unwrap()
        .sign_app_jwt()
        .unwrap();
    clock.elapsed.store(600, Ordering::SeqCst);
    assert!(matches!(
        store.resolve(&KeyBinding::fixture()),
        Err(SigningError::LeaseExpired)
    ));
}
#[test]
fn either_clock_regression_is_sticky_even_after_time_recovers() {
    for wall in [true, false] {
        let (store, clock) = store();
        clock.utc.fetch_add(10, Ordering::SeqCst);
        clock.elapsed.store(10, Ordering::SeqCst);
        let signer = store.resolve(&KeyBinding::fixture()).unwrap();
        if wall {
            clock.utc.fetch_sub(1, Ordering::SeqCst);
        } else {
            clock.elapsed.store(9, Ordering::SeqCst);
        }
        assert!(matches!(
            signer.sign_app_jwt(),
            Err(SigningError::ClockInvalid)
        ));
        clock.utc.fetch_add(20, Ordering::SeqCst);
        clock.elapsed.store(20, Ordering::SeqCst);
        assert!(matches!(
            store.resolve(&KeyBinding::fixture()),
            Err(SigningError::ClockInvalid)
        ));
        assert_eq!(store.unlock_fixture(), Err(SigningError::ClockInvalid));
    }
}
#[test]
fn claim_clock_overflow_or_underflow_never_creates_a_signature() {
    for utc in [0, 59, u64::MAX] {
        let (store, clock) = store();
        let signer = store.resolve(&KeyBinding::fixture()).unwrap();
        clock.utc.store(utc, Ordering::SeqCst);
        assert!(matches!(
            signer.sign_app_jwt(),
            Err(SigningError::ClockInvalid)
        ));
        assert_eq!(store.shared.state.lock().unwrap().signatures, 0);
    }
}
#[test]
fn strict_header_rejects_algorithm_confusion_unknown_fields_and_duplicate_members() {
    let (store, clock) = store();
    let verifier = store.verifier().unwrap();
    for header in [
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"alg":"RS512","typ":"JWT"}"#,
        r#"{"alg":"none","typ":"JWT"}"#,
        r#"{"alg":"RS256"}"#,
        r#"{"alg":"RS256","typ":"JWS"}"#,
        r#"{"alg":"RS256","typ":"JWT","alg":"RS256"}"#,
        r#"{"alg":"RS256","typ":"JWT","a\u006cg":"RS256"}"#,
        r#"{"alg":"RS256","typ":"JWT","kid":"other"}"#,
        r#"{"alg":"RS256","typ":"JWT","jku":"https://invalid.example"}"#,
        r#"{"alg":"RS256","typ":"JWT","extra":1,"extra":2}"#,
        r#"{"alg":"RS256","typ":"JWT","crit":["extra"]}"#,
    ] {
        let jwt = signed_raw(&store, header, &valid_claims());
        assert_eq!(
            verifier.verify(&jwt, clock.now()),
            Err(SigningError::InvalidToken)
        );
    }
}
#[test]
fn strict_claims_reject_missing_duplicate_unknown_wrong_type_or_scope() {
    let (store, clock) = store();
    let verifier = store.verifier().unwrap();
    let valid = valid_claims();
    for payload in [
        valid.replace(ISSUER, "other-app"),
        valid.replace("\"iat\":1799999940,", ""),
        valid.replace(
            "\"exp\":1800000540",
            "\"exp\":1800000540,\"exp\":1800000540",
        ),
        valid.replace("\"exp\":1800000540", "\"exp\":1800000540,\"aud\":\"extra\""),
        valid.replace("\"iat\":1799999940", "\"iat\":\"1799999940\""),
        valid.replace("\"iat\":1799999940", "\"iat\":-1"),
        valid.replace("\"exp\":1800000540", "\"exp\":1.80000054e9"),
        valid.replace(
            &format!("\"iss\":\"{ISSUER}\""),
            "\"iss\":[\"Iv1_SYNTHETIC_ONLY\"]",
        ),
        valid.replace(
            "\"exp\":1800000540",
            "\"exp\":1800000540,\"private_key\":\"canary\"",
        ),
    ] {
        let jwt = signed_raw(&store, r#"{"alg":"RS256","typ":"JWT"}"#, &payload);
        assert_eq!(
            verifier.verify(&jwt, clock.now()),
            Err(SigningError::InvalidToken)
        );
    }
}
#[test]
fn valid_signatures_do_not_bypass_iat_expiry_or_maximum_lifetime() {
    let (store, clock) = store();
    let verifier = store.verifier().unwrap();
    for (iat, exp) in [
        (1_800_000_001, 1_800_000_540),
        (1_799_999_940, 1_800_000_000),
        (1_799_999_940, 1_800_000_541),
        (u64::MAX, u64::MAX),
        (1_800_000_000, 1_799_999_999),
    ] {
        let payload = serde_json::to_string(&AppClaims {
            iss: ISSUER.into(),
            iat,
            exp,
        })
        .unwrap();
        let jwt = signed_raw(&store, r#"{"alg":"RS256","typ":"JWT"}"#, &payload);
        assert_eq!(
            verifier.verify(&jwt, clock.now()),
            Err(SigningError::InvalidToken)
        );
    }
}
#[test]
fn wrong_key_and_corrupted_signature_are_rejected() {
    let (store, clock) = store();
    let jwt = store
        .resolve(&KeyBinding::fixture())
        .unwrap()
        .sign_app_jwt()
        .unwrap();
    let (other, _) = self::store();
    assert_eq!(
        other.verifier().unwrap().verify(&jwt, clock.now()),
        Err(SigningError::InvalidToken)
    );
    let mut parts: Vec<String> = jwt.0.split('.').map(str::to_owned).collect();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    assert_eq!(
        store
            .verifier()
            .unwrap()
            .verify(&AppJwt(parts.join(".")), clock.now()),
        Err(SigningError::InvalidToken)
    );
}
#[test]
fn compact_jws_parser_is_bounded_and_rejects_noncanonical_shapes() {
    let (store, clock) = store();
    let verifier = store.verifier().unwrap();
    let jwt = store
        .resolve(&KeyBinding::fixture())
        .unwrap()
        .sign_app_jwt()
        .unwrap();
    for malformed in [
        "".into(),
        "a.b".into(),
        format!("{}.extra", jwt.0),
        format!("{}=", jwt.0),
        "é.x.y".into(),
        "x".repeat(MAX_JWT + 1),
        format!("{}.b.c", "x".repeat(MAX_PART + 1)),
    ] {
        assert_eq!(
            verifier.verify(&AppJwt(malformed), clock.now()),
            Err(SigningError::InvalidToken)
        );
    }
}
#[test]
fn rsa_key_type_confusion_is_not_accepted_as_an_hmac_credential() {
    let (store, clock) = store();
    let state = store.shared.state.lock().unwrap();
    let wrong = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &AppClaims {
            iss: ISSUER.into(),
            iat: 1_799_999_940,
            exp: 1_800_000_540,
        },
        &state.material.as_ref().unwrap().encoding,
    );
    assert!(wrong.is_err());
    drop(state);
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &AppClaims {
            iss: ISSUER.into(),
            iat: 1_799_999_940,
            exp: 1_800_000_540,
        },
        &EncodingKey::from_secret(b"public synthetic hmac data"),
    )
    .unwrap();
    assert_eq!(
        store
            .verifier()
            .unwrap()
            .verify(&AppJwt(token), clock.now()),
        Err(SigningError::InvalidToken)
    );
}
#[test]
fn final_signing_budget_is_serialized_across_concurrent_handles() {
    let (store, _) = store();
    let first = store.resolve(&KeyBinding::fixture()).unwrap();
    let second = store.resolve(&KeyBinding::fixture()).unwrap();
    store.shared.state.lock().unwrap().signatures = 31;
    let barrier = Arc::new(Barrier::new(3));
    let b = barrier.clone();
    let one = std::thread::spawn(move || {
        b.wait();
        first.sign_app_jwt().map(|_| ())
    });
    let b = barrier.clone();
    let two = std::thread::spawn(move || {
        b.wait();
        second.sign_app_jwt().map(|_| ())
    });
    barrier.wait();
    let results = [one.join().unwrap(), two.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(SigningError::CapacityExceeded))
            .count(),
        1
    );
    assert_eq!(store.shared.state.lock().unwrap().signatures, 32);
}
#[test]
fn provider_preinitialized_worker() {
    if std::env::var_os("AEGIS_SYNTHETIC_PREINITIALIZED_CRYPTO_TEST").is_none() {
        return;
    }
    jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        .install_default()
        .unwrap();
    assert_eq!(
        run_synthetic_signing_demo(),
        Err(SigningError::ProviderUnavailable)
    );
    assert_eq!(
        run_synthetic_signing_demo(),
        Err(SigningError::ProviderUnavailable)
    );
}
#[test]
fn preinitialized_global_provider_fails_closed_in_a_fresh_process() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "signing::tests::provider_preinitialized_worker",
            "--nocapture",
        ])
        .env("AEGIS_SYNTHETIC_PREINITIALIZED_CRYPTO_TEST", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE KEY"));
}
#[test]
fn repeated_and_concurrent_public_demos_share_fixed_provider_initialization_safely() {
    let one = std::thread::spawn(run_synthetic_signing_demo);
    let two = std::thread::spawn(run_synthetic_signing_demo);
    assert!(one.join().unwrap().unwrap().verified_signature_and_claims);
    assert!(two.join().unwrap().unwrap().verified_signature_and_claims);
}

#[test]
fn exhausted_generation_fails_closed_instead_of_acknowledging_a_lock() {
    let (store, _) = store();
    let lease = store.resolve(&KeyBinding::fixture()).unwrap();
    store.shared.state.lock().unwrap().generation = u64::MAX;
    assert_eq!(store.lock(), Err(SigningError::Unavailable));
    assert!(matches!(lease.sign_app_jwt(), Err(SigningError::Revoked)));
    assert!(store.shared.state.lock().unwrap().material.is_none());
}
struct Release(Arc<SignPause>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
#[test]
fn signing_and_lock_share_one_serialization_point() {
    let (store, clock) = store();
    let store = Arc::new(store);
    let signer = store.resolve(&KeyBinding::fixture()).unwrap();
    let verifier = store.verifier().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let pause = Arc::new(SignPause {
        entered: Mutex::new(sender),
        released: Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let _release = Release(pause.clone());
    store.shared.state.lock().unwrap().pause = Some(pause.clone());
    let signing = std::thread::spawn(move || signer.sign_app_jwt());
    receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert!(store.shared.state.try_lock().is_err());
    let locking_store = store.clone();
    let locking = std::thread::spawn(move || locking_store.lock());
    pause.release();
    let jwt = signing.join().unwrap().unwrap();
    locking.join().unwrap().unwrap();
    assert!(matches!(
        store.resolve(&KeyBinding::fixture()),
        Err(SigningError::Locked)
    ));
    verifier.verify(&jwt, clock.now()).unwrap();
    assert_eq!(store.shared.state.lock().unwrap().signatures, 1);
}

#[test]
fn dropping_store_owner_revokes_outstanding_leases_without_recalling_issued_jwt() {
    let (store, clock) = store();
    let lease = store.resolve(&KeyBinding::fixture()).unwrap();
    let verifier = store.verifier().unwrap();
    let jwt = lease.sign_app_jwt().unwrap();
    drop(store);
    assert!(matches!(lease.sign_app_jwt(), Err(SigningError::Revoked)));
    verifier.verify(&jwt, clock.now()).unwrap();
}
