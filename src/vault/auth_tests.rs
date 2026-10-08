use super::*;
use crate::ManualClock;
fn fixture() -> (Actors, Gate, Arc<ManualClock>) {
    let actors = Actors::generate().unwrap();
    let clock = Arc::new(ManualClock::default());
    let gate = Gate::new(
        [9; 16],
        DeliveryProfile::fixture(1),
        clock.clone(),
        &actors.enrollment(),
    )
    .unwrap();
    (actors, gate, clock)
}
fn claims(c: &Challenge) -> Claims {
    Claims {
        iss: c.purpose.subject().into(),
        sub: c.purpose.subject().into(),
        aud: c.purpose.audience().into(),
        iat: c.issued,
        exp: c.expires,
        jti: c.nonce.clone(),
        epoch: c.epoch.clone(),
        purpose: c.purpose,
        digest: c.digest.clone(),
        enrollment_revision: c.enrollment_revision,
        acl_revision: c.acl_revision,
    }
}
#[test]
fn correctly_signed_but_substituted_claims_are_rejected() {
    let (a, g, _) = fixture();
    for change in [
        |c: &mut Claims| c.iss = "untrusted-issuer".into(),
        |c: &mut Claims| c.sub = ADMIN.into(),
        |c: &mut Claims| c.aud = Purpose::Approve.audience().into(),
        |c: &mut Claims| c.epoch = "other".into(),
        |c: &mut Claims| c.purpose = Purpose::Approve,
        |c: &mut Claims| c.digest = crypto::hash(b"other-plan"),
        |c: &mut Claims| c.enrollment_revision = 2,
        |c: &mut Claims| c.acl_revision = 2,
        |c: &mut Claims| c.iat += 1,
        |c: &mut Claims| c.exp += 1,
        |c: &mut Claims| c.exp = c.iat,
    ] {
        let challenge = g
            .challenge(
                Purpose::Connect,
                g.context_digest(Purpose::Connect).unwrap(),
            )
            .unwrap();
        let mut body = claims(&challenge);
        change(&mut body);
        assert_eq!(
            g.connect(a.agent.sign(&body).unwrap()).map(|_| ()),
            Err(ErrorCode::AuthenticationRequired)
        );
    }
    assert_eq!(g.check_active(), Err(ErrorCode::AuthenticationRequired));
}
#[test]
fn unknown_keys_and_cross_role_keys_cannot_authenticate() {
    let (a, g, _) = fixture();
    let other = SigningKey::generate().unwrap();
    let c = g
        .challenge(
            Purpose::Connect,
            g.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    assert_eq!(
        g.connect(other.sign(&claims(&c)).unwrap()).map(|_| ()),
        Err(ErrorCode::AuthenticationRequired)
    );
    assert_eq!(
        g.connect(a.admin.sign(&claims(&c)).unwrap()).map(|_| ()),
        Err(ErrorCode::AuthenticationRequired)
    );
    g.connect(a.agent.sign(&claims(&c)).unwrap())
        .map(|_| ())
        .unwrap();
}
#[test]
fn strict_jose_and_claim_parsing_rejects_duplicates_unknown_fields_and_algorithms() {
    let (a, g, _) = fixture();
    let c = g
        .challenge(
            Purpose::Connect,
            g.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    let raw = serde_json::to_string(&claims(&c)).unwrap();
    for header in [
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"alg":"none","typ":"JWT"}"#,
        r#"{"alg":"RS256","typ":"JWT","jku":"https://invalid.test/key"}"#,
        r#"{"alg":"RS256","alg":"RS256","typ":"JWT"}"#,
        r#"{"alg":"RS256","typ":"JWT","kid":"other"}"#,
    ] {
        assert_eq!(
            g.connect(a.agent.sign_raw(header, &raw)).map(|_| ()),
            Err(ErrorCode::AuthenticationRequired)
        );
    }
    for body in [
        raw.replacen("\"iss\":", "\"iss\":\"duplicate\",\"iss\":", 1),
        raw.replacen("\"iat\":", "\"extra\":true,\"iat\":", 1),
        raw.replace(&format!("\"iat\":{}", c.issued), "\"iat\":\"not-a-number\""),
    ] {
        assert_eq!(
            g.connect(a.agent.sign_raw(r#"{"alg":"RS256","typ":"JWT"}"#, &body))
                .map(|_| ()),
            Err(ErrorCode::AuthenticationRequired)
        );
    }
    g.connect(a.sign(&c).unwrap()).map(|_| ()).unwrap();
}
#[test]
fn challenge_expiry_and_session_expiry_are_exact_and_not_renewed_by_replays() {
    let (a, g, c) = fixture();
    let challenge = g
        .challenge(
            Purpose::Connect,
            g.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    let signed = a.sign(&challenge).unwrap();
    c.set(30);
    assert_eq!(
        g.connect(signed).map(|_| ()),
        Err(ErrorCode::AuthenticationRequired)
    );
    let challenge = g
        .challenge(
            Purpose::Connect,
            g.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    let signed = a.sign(&challenge).unwrap();
    let replay = Signed::parse(signed.bytes()).unwrap();
    g.connect(signed).map(|_| ()).unwrap();
    c.set(629);
    g.check_active().unwrap();
    assert_eq!(
        g.connect(replay).map(|_| ()),
        Err(ErrorCode::AuthenticationRequired)
    );
    c.set(630);
    assert_eq!(g.check_active(), Err(ErrorCode::AuthenticationRequired));
}
#[test]
fn assertion_from_an_earlier_epoch_cannot_bootstrap_a_new_session() {
    let (a, g, c) = fixture();
    let challenge = g
        .challenge(
            Purpose::Connect,
            g.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    let signed = a.sign(&challenge).unwrap();
    let other = Gate::new([8; 16], DeliveryProfile::fixture(1), c, &a.enrollment()).unwrap();
    assert_eq!(
        other.connect(signed).map(|_| ()),
        Err(ErrorCode::AuthenticationRequired)
    );
}
#[test]
fn revoked_gate_denies_existing_session_and_outstanding_proofs() {
    let (a, g, _) = fixture();
    let challenge = g
        .challenge(
            Purpose::Connect,
            g.context_digest(Purpose::Connect).unwrap(),
        )
        .unwrap();
    let proof = a.sign(&challenge).unwrap();
    g.revoke();
    assert_eq!(g.connect(proof).map(|_| ()), Err(ErrorCode::GrantRevoked));
    assert_eq!(g.check_active(), Err(ErrorCode::GrantRevoked));
}
#[test]
fn malformed_assertions_return_only_static_errors() {
    let (_a, g, _) = fixture();
    for raw in ["x", "a.b.c", "not-a-token", super::super::store::CANARY_ONE] {
        let error = g
            .connect(Signed::parse(raw.as_bytes()).unwrap())
            .err()
            .expect("malformed fixture assertion denied");
        assert_eq!(error, ErrorCode::AuthenticationRequired);
        assert!(!error.to_string().contains(raw));
    }
}
