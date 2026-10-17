use super::*;
use crate::broker::{Clock as BrokerTimeSource, ManualClock};

fn fixture() -> (BoundSource, SigningAuthorization, Arc<ManualClock>) {
    let setup = OperationSetup::synthetic_github();
    let clock = Arc::new(ManualClock::default());
    let view = OperationApprovalView {
        broker_instance: [4; 16],
        prepared_request_id: 1,
        request_id: RequestId::new("fixed").unwrap(),
        limits: OperationLimits {
            initial_uses: setup.uses,
            idle_seconds: setup.idle_seconds,
            maximum_seconds: setup.maximum_seconds,
            request_seconds: setup.request_seconds,
            maximum_requests: setup.maximum_requests,
            maximum_concurrent: setup.maximum_concurrent,
        },
        principal: setup.principal.clone(),
        session: 1,
        profile: setup.profile.clone(),
        operation: OperationIntent::GithubMetadata(GithubMetadataParameters {
            repository_id: 4242,
        }),
        policy_generation: 1,
        expires_at: 15,
        remaining_uses: setup.uses,
    };
    let dispatch = AuthorizedDispatch {
        approval: view,
        request_id: RequestId::new("fixed").unwrap(),
        reserved_at: 0,
        remaining_before: setup.uses,
    };
    (
        BoundSource::new([4; 16], &setup, clock.clone()).unwrap(),
        SigningAuthorization::from_dispatch(&dispatch).unwrap(),
        clock,
    )
}
#[test]
fn source_rejects_substituted_review_context_before_signing() {
    let (source, original, _) = fixture();
    for change in [
        |a: &mut SigningAuthorization| a.view.broker_instance = [5; 16],
        |a: &mut SigningAuthorization| a.view.principal = PrincipalId::new("other").unwrap(),
        |a: &mut SigningAuthorization| a.view.session = 2,
        |a: &mut SigningAuthorization| a.view.policy_generation = 2,
        |a: &mut SigningAuthorization| a.view.prepared_request_id = 0,
        |a: &mut SigningAuthorization| a.view.limits.maximum_concurrent = 2,
        |a: &mut SigningAuthorization| a.view.limits.initial_uses = 19,
        |a: &mut SigningAuthorization| {
            a.view.operation = OperationIntent::GithubMetadata(GithubMetadataParameters {
                repository_id: 4243,
            })
        },
        |a: &mut SigningAuthorization| {
            if let OperationProfile::GithubMetadata(p) = &mut a.view.profile {
                p.credential.version = 2;
            }
        },
        |a: &mut SigningAuthorization| {
            if let OperationProfile::GithubMetadata(p) = &mut a.view.profile {
                p.revision = 2;
            }
        },
        |a: &mut SigningAuthorization| {
            if let OperationProfile::GithubMetadata(p) = &mut a.view.profile {
                p.installation_id = 999;
            }
        },
        |a: &mut SigningAuthorization| {
            if let OperationProfile::GithubMetadata(p) = &mut a.view.profile {
                p.account_login = "other".into();
            }
        },
        |a: &mut SigningAuthorization| {
            if let OperationProfile::GithubMetadata(p) = &mut a.view.profile {
                p.requested_metadata = GithubPermission::Write;
            }
        },
        |a: &mut SigningAuthorization| a.remaining_before = 0,
        |a: &mut SigningAuthorization| a.remaining_before = 21,
        |a: &mut SigningAuthorization| a.view.remaining_uses = 21,
        |a: &mut SigningAuthorization| a.reserved_at = 15,
    ] {
        let mut changed = original.clone();
        change(&mut changed);
        assert!(matches!(
            source.reserve(&changed),
            Err(SigningError::InvalidBinding)
        ));
    }
    assert_eq!(source.signatures(), 0);
}
#[test]
fn one_shot_permit_and_exchange_envelope_bind_complete_review_and_budget() {
    let (source, original, clock) = fixture();
    for change in [
        |a: &mut SigningAuthorization| a.view.request_id = RequestId::new("other").unwrap(),
        |a: &mut SigningAuthorization| a.view.prepared_request_id = 2,
        |a: &mut SigningAuthorization| a.view.expires_at = 14,
        |a: &mut SigningAuthorization| a.view.remaining_uses = 19,
        |a: &mut SigningAuthorization| a.remaining_before = 19,
        |a: &mut SigningAuthorization| a.reserved_at = 1,
    ] {
        let permit = source.reserve(&original).unwrap();
        let mut changed = original.clone();
        change(&mut changed);
        assert!(matches!(
            permit.sign(&changed),
            Err(SigningError::InvalidBinding)
        ));
    }
    assert_eq!(source.signatures(), 0);
    let permit = source.reserve(&original).unwrap();
    clock.set(5);
    let jwt = permit.sign(&original).unwrap();
    assert!(jwt.verify(&original, 1_800_000_000 + clock.now(), clock.now()));
    let claims = strict_parts(&jwt.jwt.0).unwrap();
    assert_eq!(claims.iat, 1_799_999_945);
    assert_eq!(claims.exp, 1_800_000_545);
    let mut changed = original.clone();
    changed.remaining_before = 19;
    assert!(!jwt.verify(&changed, 1_800_000_000 + clock.now(), clock.now()));
    clock.set(545);
    assert!(!jwt.verify(&original, 1_800_000_000 + clock.now(), clock.now()));
}
#[test]
fn exchange_verifier_rejects_wrong_key_corruption_and_clock_rollback() {
    let (source, original, clock) = fixture();
    let mut jwt = source.reserve(&original).unwrap().sign(&original).unwrap();
    let other = KeyMaterial::generate().unwrap();
    let real = jwt.verifier.key.clone();
    jwt.verifier.key = other.verification;
    assert!(!jwt.verify(&original, 1_800_000_000 + clock.now(), clock.now()));
    jwt.verifier.key = real;
    assert!(jwt.verify(&original, 1_800_000_000 + clock.now(), clock.now()));
    jwt.jwt.0.push('x');
    assert!(!jwt.verify(&original, 1_800_000_000 + clock.now(), clock.now()));
    let jwt = source.reserve(&original).unwrap().sign(&original).unwrap();
    clock.set(1);
    let jwt2 = source.reserve(&original).unwrap().sign(&original).unwrap();
    clock.set(0);
    assert!(!jwt2.verify(&original, 1_800_000_000 + clock.now(), clock.now()));
    assert!(jwt.verify(&original, 1_800_000_000 + clock.now(), clock.now())); // Verification cannot recall an earlier signed credential.
}
#[test]
fn reviewed_budget_can_exceed_actual_remaining_without_broadening_it() {
    let (source, mut approval, clock) = fixture();
    approval.remaining_before = 1;
    let jwt = source.reserve(&approval).unwrap().sign(&approval).unwrap();
    assert!(jwt.verify(&approval, 1_800_000_000 + clock.now(), clock.now()));
    let mut different = approval.clone();
    different.remaining_before = 2;
    assert!(!jwt.verify(&different, 1_800_000_000 + clock.now(), clock.now()));
}
#[test]
fn single_checked_signing_observation_rejects_and_latches_regression() {
    use std::collections::VecDeque;
    struct Script(Mutex<VecDeque<u64>>);
    impl crate::broker::Clock for Script {
        fn now(&self) -> u64 {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .expect("exact clock sampling")
        }
    }
    let (baseline, authorization, _) = fixture();
    drop(baseline);
    // Source construction, lease resolution, signing regression, retry after recovery.
    let clock = Arc::new(Script(Mutex::new(VecDeque::from([0, 100, 50, 100]))));
    let source =
        BoundSource::new([4; 16], &OperationSetup::synthetic_github(), clock.clone()).unwrap();
    let permit = source.reserve(&authorization).unwrap();
    assert!(matches!(
        permit.sign(&authorization),
        Err(SigningError::ClockInvalid)
    ));
    assert!(matches!(
        source.reserve(&authorization),
        Err(SigningError::ClockInvalid)
    ));
    assert!(clock.0.lock().unwrap().is_empty());
    assert_eq!(source.signatures(), 0);
}
#[test]
fn reservation_floor_is_checked_before_crypto_and_is_sticky() {
    let (source, mut authorization, clock) = fixture();
    authorization.reserved_at = 5;
    let permit = source.reserve(&authorization).unwrap();
    assert!(matches!(
        permit.sign(&authorization),
        Err(SigningError::ClockInvalid)
    ));
    clock.set(5);
    assert!(matches!(
        source.reserve(&authorization),
        Err(SigningError::ClockInvalid)
    ));
    assert_eq!(source.signatures(), 0);
}
