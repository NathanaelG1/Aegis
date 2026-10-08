//! Cryptographically verified fixture principals and purpose-bound one-use assertions.
//! Key possession is not human presence. No network enrollment/bootstrap exists.
use super::{
    crypto::{self, Signed, SigningKey, Verifier},
    model::*,
};
use crate::{
    broker::{AuthorizedDispatch, Clock},
    ErrorCode, OperationApprovalView, OperationIntent, OperationProfile, PrincipalId, RequestId,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub(super) const AGENT: &str = "synthetic-vault-agent";
pub(super) const ADMIN: &str = "synthetic-vault-admin";
const ORIGIN: u64 = 1_800_000_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Connect,
    AdminConnect,
    Approve,
    Invoke,
    Revoke,
}
impl Purpose {
    fn agent(self) -> bool {
        matches!(self, Self::Connect | Self::Invoke)
    }
    fn audience(self) -> &'static str {
        if self.agent() {
            "urn:aegis:synthetic:agent:v1"
        } else {
            "urn:aegis:synthetic:human-control:v1"
        }
    }
    fn subject(self) -> &'static str {
        if self.agent() {
            AGENT
        } else {
            ADMIN
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub nonce: String,
    pub epoch: String,
    pub purpose: Purpose,
    pub digest: String,
    pub issued: u64,
    pub expires: u64,
    pub issued_elapsed: u64,
    pub expires_elapsed: u64,
    pub enrollment_revision: u64,
    pub acl_revision: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    jti: String,
    epoch: String,
    purpose: Purpose,
    digest: String,
    enrollment_revision: u64,
    acl_revision: u64,
}
pub(super) struct Actors {
    pub agent: Arc<SigningKey>,
    pub admin: Arc<SigningKey>,
}
/// Public verification material only; runtime gates never retain actor signers.
#[derive(Clone)]
pub(super) struct Enrollment {
    agent: Verifier,
    admin: Verifier,
}
impl Enrollment {
    pub(super) fn from_verifiers(agent: Verifier, admin: Verifier) -> Self {
        Self { agent, admin }
    }
}
/// One simulated actor's signer. It cannot mint the other role's assertions.
pub(super) struct ActorSigner {
    key: Arc<SigningKey>,
    agent: bool,
}
impl ActorSigner {
    pub(super) fn agent(key: Arc<SigningKey>) -> Self {
        Self { key, agent: true }
    }
    pub(super) fn admin(key: Arc<SigningKey>) -> Self {
        Self { key, agent: false }
    }
    pub(super) fn sign(&self, c: &Challenge) -> Result<Signed, ErrorCode> {
        if self.agent != c.purpose.agent() {
            return Err(ErrorCode::AuthenticationRequired);
        }
        sign_challenge(&self.key, c)
    }
}
fn sign_challenge(key: &SigningKey, c: &Challenge) -> Result<Signed, ErrorCode> {
    key.sign(&Claims {
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
    })
}
impl Actors {
    pub fn enrollment(&self) -> Enrollment {
        Enrollment {
            agent: self.agent.verifier(),
            admin: self.admin.verifier(),
        }
    }
    pub fn generate() -> Result<Self, ErrorCode> {
        Ok(Self {
            agent: Arc::new(SigningKey::generate()?),
            admin: Arc::new(SigningKey::generate()?),
        })
    }
    pub fn sign(&self, c: &Challenge) -> Result<Signed, ErrorCode> {
        let key = if c.purpose.agent() {
            &self.agent
        } else {
            &self.admin
        };
        sign_challenge(key, c)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub instance: [u8; 16],
    pub prepared: u64,
    pub request_id: RequestId,
    pub principal: PrincipalId,
    pub session: u64,
    pub profile: DeliveryProfile,
    pub operation: DeliveryParameters,
    pub generation: u64,
    pub expires: u64,
    pub remaining: u32,
    pub limits: [u64; 6],
}
impl Review {
    pub fn of(v: &OperationApprovalView) -> Result<Self, ErrorCode> {
        let (OperationProfile::Delivery(profile), OperationIntent::Delivery(operation)) =
            (&v.profile, &v.operation)
        else {
            return Err(ErrorCode::ScopeDenied);
        };
        Ok(Self {
            instance: v.broker_instance,
            prepared: v.prepared_request_id,
            request_id: v.request_id.clone(),
            principal: v.principal.clone(),
            session: v.session,
            profile: profile.clone(),
            operation: operation.clone(),
            generation: v.policy_generation,
            expires: v.expires_at,
            remaining: v.remaining_uses,
            limits: [
                v.limits.initial_uses as u64,
                v.limits.idle_seconds,
                v.limits.maximum_seconds,
                v.limits.request_seconds,
                v.limits.maximum_requests as u64,
                v.limits.maximum_concurrent as u64,
            ],
        })
    }
    pub fn digest(&self) -> Result<String, ErrorCode> {
        digest(self)
    }
}
pub(super) fn digest<T: Serialize>(v: &T) -> Result<String, ErrorCode> {
    serde_json::to_vec(v)
        .map(|b| crypto::hash(&b))
        .map_err(|_| ErrorCode::InvalidRequest)
}
pub(super) fn dispatch_digest(d: &AuthorizedDispatch) -> Result<String, ErrorCode> {
    digest(&(
        "aegis.vault.invoke.v1",
        Review::of(&d.approval)?,
        d.remaining_before,
    ))
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub subject: String,
    pub purpose: Purpose,
    pub challenge: String,
    pub digest: String,
    pub epoch: String,
    pub enrollment_revision: u64,
    pub acl_revision: u64,
}
/// Opaque, non-serializable connection capability created only after signature verification.
/// Pointer identity prevents a different or pre-authentication client handle inheriting it.
pub(crate) struct AuthenticatedSession {
    epoch: String,
}
pub(super) struct AdminSession {
    epoch: String,
}
struct State {
    last: u64,
    invalid_clock: bool,
    revoked: bool,
    active_until: Option<u64>,
    session: Option<Arc<AuthenticatedSession>>,
    admin_until: Option<u64>,
    admin_session: Option<Arc<AdminSession>>,
    challenges: BTreeMap<String, Challenge>,
    agent_proofs: BTreeMap<u64, Signed>,
    admin_proofs: BTreeMap<u64, (Signed, Arc<AdminSession>)>,
}
pub(super) struct Gate {
    epoch: String,
    profile: DeliveryProfile,
    clock: Arc<dyn Clock>,
    agent: Verifier,
    admin: Verifier,
    state: Mutex<State>,
}
impl Gate {
    pub fn new(
        epoch: [u8; 16],
        profile: DeliveryProfile,
        clock: Arc<dyn Clock>,
        enrollment: &Enrollment,
    ) -> Result<Self, ErrorCode> {
        let now = clock.now();
        ORIGIN.checked_add(now).ok_or(ErrorCode::SessionExpired)?;
        Ok(Self {
            epoch: crypto::encode(&epoch),
            profile,
            clock,
            agent: enrollment.agent.clone(),
            admin: enrollment.admin.clone(),
            state: Mutex::new(State {
                last: now,
                invalid_clock: false,
                revoked: false,
                active_until: None,
                session: None,
                admin_until: None,
                admin_session: None,
                challenges: BTreeMap::new(),
                agent_proofs: BTreeMap::new(),
                admin_proofs: BTreeMap::new(),
            }),
        })
    }
    fn time(&self, state: &mut State) -> Result<(u64, u64), ErrorCode> {
        let now = self.clock.now();
        if state.invalid_clock || now < state.last {
            state.invalid_clock = true;
            return Err(ErrorCode::SessionExpired);
        }
        state.last = now;
        let utc = ORIGIN.checked_add(now).ok_or(ErrorCode::SessionExpired)?;
        Ok((now, utc))
    }
    pub fn context_digest(&self, purpose: Purpose) -> Result<String, ErrorCode> {
        digest(&(
            "aegis.vault.context.v1",
            &self.epoch,
            &self.profile,
            purpose,
        ))
    }
    pub fn challenge(&self, purpose: Purpose, digest: String) -> Result<Challenge, ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let (elapsed, utc) = self.time(&mut s)?;
        if s.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if digest.len() != 43 {
            return Err(ErrorCode::InvalidRequest);
        }
        s.challenges.retain(|_, c| elapsed < c.expires_elapsed);
        if s.challenges.len() >= 32 {
            return Err(ErrorCode::CapacityExceeded);
        }
        let c = Challenge {
            nonce: crypto::random_id()?,
            epoch: self.epoch.clone(),
            purpose,
            digest,
            issued: utc,
            expires: utc.checked_add(30).ok_or(ErrorCode::SessionExpired)?,
            issued_elapsed: elapsed,
            expires_elapsed: elapsed.checked_add(30).ok_or(ErrorCode::SessionExpired)?,
            enrollment_revision: 1,
            acl_revision: self.profile.acl_revision,
        };
        s.challenges.insert(c.nonce.clone(), c.clone());
        Ok(c)
    }
    fn consume(
        &self,
        s: &mut State,
        purpose: Purpose,
        expected: &str,
        proof: &Signed,
        reserved_at: Option<u64>,
    ) -> Result<Receipt, ErrorCode> {
        let (elapsed, utc) = self.time(s)?;
        if s.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if proof.bytes().len() > 4096 {
            return Err(ErrorCode::AuthenticationRequired);
        }
        let verifier = if purpose.agent() {
            &self.agent
        } else {
            &self.admin
        };
        let claims: Claims = verifier.verify(proof)?;
        // Validly signed attempts consume their one-use challenge even if the context is wrong.
        let c = s
            .challenges
            .remove(&claims.jti)
            .ok_or(ErrorCode::AuthenticationRequired)?;
        if claims.iss != purpose.subject()
            || claims.sub != purpose.subject()
            || claims.aud != purpose.audience()
            || claims.purpose != purpose
            || c.purpose != purpose
            || claims.digest != expected
            || c.digest != expected
            || claims.epoch != self.epoch
            || c.epoch != self.epoch
            || claims.enrollment_revision != 1
            || c.enrollment_revision != 1
            || claims.acl_revision != self.profile.acl_revision
            || c.acl_revision != self.profile.acl_revision
            || claims.iat != c.issued
            || claims.exp != c.expires
            || claims.iat > utc
            || utc >= claims.exp
            || claims.exp.checked_sub(claims.iat) != Some(30)
            || elapsed >= c.expires_elapsed
            || elapsed < c.issued_elapsed
            || reserved_at
                .is_some_and(|t| t < c.issued_elapsed || t >= c.expires_elapsed || t > elapsed)
        {
            return Err(ErrorCode::AuthenticationRequired);
        }
        Ok(Receipt {
            subject: claims.sub,
            purpose,
            challenge: claims.jti,
            digest: claims.digest,
            epoch: claims.epoch,
            enrollment_revision: claims.enrollment_revision,
            acl_revision: claims.acl_revision,
        })
    }
    pub fn connect(&self, proof: Signed) -> Result<Arc<AuthenticatedSession>, ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        if s.active_until.is_some() {
            return Err(ErrorCode::AuthenticationRequired);
        }
        self.consume(
            &mut s,
            Purpose::Connect,
            &self.context_digest(Purpose::Connect)?,
            &proof,
            None,
        )?;
        s.active_until = Some(s.last.checked_add(600).ok_or(ErrorCode::SessionExpired)?);
        let session = Arc::new(AuthenticatedSession {
            epoch: self.epoch.clone(),
        });
        s.session = Some(session.clone());
        Ok(session)
    }
    pub fn check_active(&self) -> Result<(), ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let (elapsed, _) = self.time(&mut s)?;
        if s.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if s.active_until.is_none_or(|until| elapsed >= until) {
            return Err(ErrorCode::AuthenticationRequired);
        }
        Ok(())
    }
    pub fn connect_admin(&self, proof: Signed) -> Result<Arc<AdminSession>, ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        if s.admin_until.is_some() {
            return Err(ErrorCode::AuthenticationRequired);
        }
        self.consume(
            &mut s,
            Purpose::AdminConnect,
            &self.context_digest(Purpose::AdminConnect)?,
            &proof,
            None,
        )?;
        s.admin_until = Some(s.last.checked_add(600).ok_or(ErrorCode::SessionExpired)?);
        let session = Arc::new(AdminSession {
            epoch: self.epoch.clone(),
        });
        s.admin_session = Some(session.clone());
        Ok(session)
    }
    fn check_admin_at(
        &self,
        state: &State,
        session: Option<&Arc<AdminSession>>,
        elapsed: u64,
    ) -> Result<(), ErrorCode> {
        if state.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if state.admin_until.is_none_or(|until| elapsed >= until) {
            return Err(ErrorCode::AuthenticationRequired);
        }
        let (Some(actual), Some(expected)) = (session, state.admin_session.as_ref()) else {
            return Err(ErrorCode::AuthenticationRequired);
        };
        if actual.epoch != self.epoch || !Arc::ptr_eq(actual, expected) {
            return Err(ErrorCode::AuthenticationRequired);
        }
        Ok(())
    }
    pub fn check_admin(&self, session: Option<&Arc<AdminSession>>) -> Result<(), ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let (elapsed, _) = self.time(&mut s)?;
        self.check_admin_at(&s, session, elapsed)
    }
    pub fn stage_admin(
        &self,
        id: u64,
        session: Arc<AdminSession>,
        proof: Signed,
    ) -> Result<(), ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let (elapsed, _) = self.time(&mut s)?;
        self.check_admin_at(&s, Some(&session), elapsed)?;
        if s.admin_proofs.len() >= 32 {
            return Err(ErrorCode::CapacityExceeded);
        }
        if s.admin_proofs.contains_key(&id) {
            return Err(ErrorCode::RequestIdConflict);
        }
        s.admin_proofs.insert(id, (proof, session));
        Ok(())
    }
    pub fn check_agent(
        &self,
        session: Option<&Arc<AuthenticatedSession>>,
    ) -> Result<(), ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let (elapsed, _) = self.time(&mut s)?;
        if s.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if s.active_until.is_none_or(|until| elapsed >= until) {
            return Err(ErrorCode::AuthenticationRequired);
        }
        let (Some(actual), Some(expected)) = (session, s.session.as_ref()) else {
            return Err(ErrorCode::AuthenticationRequired);
        };
        if actual.epoch != self.epoch || !Arc::ptr_eq(actual, expected) {
            return Err(ErrorCode::AuthenticationRequired);
        }
        Ok(())
    }
    pub fn stage_agent(&self, id: u64, proof: Signed) -> Result<(), ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        self.time(&mut s)?;
        let map = &mut s.agent_proofs;
        if map.len() >= 32 {
            return Err(ErrorCode::CapacityExceeded);
        }
        if map.contains_key(&id) {
            return Err(ErrorCode::RequestIdConflict);
        }
        map.insert(id, proof);
        Ok(())
    }
    pub fn discard(&self, id: u64, admin: bool) {
        if let Ok(mut s) = self.state.lock() {
            if admin {
                s.admin_proofs.remove(&id);
            } else {
                s.agent_proofs.remove(&id);
            }
        }
    }
    pub fn approval(&self, view: &OperationApprovalView) -> Result<Receipt, ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let (proof, session) = s
            .admin_proofs
            .remove(&view.prepared_request_id)
            .ok_or(ErrorCode::AuthenticationRequired)?;
        let (elapsed, _) = self.time(&mut s)?;
        self.check_admin_at(&s, Some(&session), elapsed)?;
        self.consume(
            &mut s,
            Purpose::Approve,
            &Review::of(view)?.digest()?,
            &proof,
            None,
        )
    }
    pub fn dispatch(&self, d: &AuthorizedDispatch) -> Result<Receipt, ErrorCode> {
        self.check_active()?;
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let proof = s
            .agent_proofs
            .remove(&d.approval.prepared_request_id)
            .ok_or(ErrorCode::AuthenticationRequired)?;
        self.consume(
            &mut s,
            Purpose::Invoke,
            &dispatch_digest(d)?,
            &proof,
            Some(d.reserved_at),
        )
    }
    pub fn authorize_revoke(&self) -> Result<Receipt, ErrorCode> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::BrokerUnavailable)?;
        let (proof, session) = s
            .admin_proofs
            .remove(&0)
            .ok_or(ErrorCode::AuthenticationRequired)?;
        let (elapsed, _) = self.time(&mut s)?;
        self.check_admin_at(&s, Some(&session), elapsed)?;
        self.consume(
            &mut s,
            Purpose::Revoke,
            &self.context_digest(Purpose::Revoke)?,
            &proof,
            None,
        )
    }
    pub fn revoke(&self) {
        if let Ok(mut s) = self.state.lock() {
            s.revoked = true;
            s.agent_proofs.clear();
            s.admin_proofs.clear();
            s.challenges.clear();
        }
    }
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
