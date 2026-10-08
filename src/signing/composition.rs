//! Crate-private composition. Only an already reserved core dispatch can obtain a
//! one-shot permit; credentials retain zeroizing ownership and never expose bytes.
use super::*;
use crate::broker::{AuthorizedDispatch, OperationSetup};
use crate::types::*;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SigningAuthorization {
    view: OperationApprovalView,
    reserved_at: u64,
    remaining_before: u32,
}
impl SigningAuthorization {
    pub(crate) fn from_dispatch(dispatch: &AuthorizedDispatch) -> Result<Self, SigningError> {
        if dispatch.request_id != dispatch.approval.request_id {
            return Err(SigningError::InvalidBinding);
        }
        Ok(Self {
            view: dispatch.approval.clone(),
            reserved_at: dispatch.reserved_at,
            remaining_before: dispatch.remaining_before,
        })
    }
}
struct BrokerClock(Arc<dyn crate::broker::Clock>);
impl Clock for BrokerClock {
    fn now(&self) -> Stamp {
        let elapsed = self.0.now();
        Stamp {
            utc: 1_800_000_000u64.checked_add(elapsed).unwrap_or(0),
            elapsed,
        }
    }
}
pub(crate) struct BoundSource {
    store: EphemeralStore,
    instance: [u8; 16],
    setup: OperationSetup,
    #[cfg(test)]
    fault: Arc<std::sync::atomic::AtomicUsize>,
}
impl BoundSource {
    pub(crate) fn new(
        instance: [u8; 16],
        setup: &OperationSetup,
        clock: Arc<dyn crate::broker::Clock>,
    ) -> Result<Self, SigningError> {
        if setup.profile != OperationProfile::GithubMetadata(GithubProfile::synthetic())
            || setup.approval_mode != ApprovalMode::EachRequest
        {
            return Err(SigningError::InvalidBinding);
        }
        Ok(Self {
            store: EphemeralStore::new(Arc::new(BrokerClock(clock)))?,
            instance,
            setup: setup.clone(),
            #[cfg(test)]
            fault: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }
    pub(crate) fn reserve(
        &self,
        authorization: &SigningAuthorization,
    ) -> Result<BoundPermit, SigningError> {
        let view = &authorization.view;
        let expected_limits = OperationLimits {
            initial_uses: self.setup.uses,
            idle_seconds: self.setup.idle_seconds,
            maximum_seconds: self.setup.maximum_seconds,
            request_seconds: self.setup.request_seconds,
            maximum_requests: self.setup.maximum_requests,
            maximum_concurrent: self.setup.maximum_concurrent,
        };
        if view.broker_instance != self.instance
            || view.principal != self.setup.principal
            || view.session != 1
            || view.policy_generation != 1
            || view.profile != self.setup.profile
            || view.limits != expected_limits
            || view.operation
                != OperationIntent::GithubMetadata(GithubMetadataParameters {
                    repository_id: 4242,
                })
            || view.prepared_request_id == 0
            || authorization.reserved_at >= view.expires_at
            || authorization.remaining_before == 0
            || authorization.remaining_before > view.remaining_uses
            || view.remaining_uses > self.setup.uses
        {
            return Err(SigningError::InvalidBinding);
        }
        let lease = self.store.resolve(&KeyBinding::fixture())?;
        Ok(BoundPermit {
            authorization: authorization.clone(),
            lease,
            verifier: self.store.verifier()?,
            #[cfg(test)]
            fault: self.fault.clone(),
        })
    }
    #[cfg(test)]
    pub(crate) fn fault(&self, at: usize) {
        self.fault.store(at, Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(crate) fn signatures(&self) -> u32 {
        self.store.shared.state.lock().unwrap().signatures
    }
    #[cfg(test)]
    pub(crate) fn lock(&self) {
        self.store.lock().unwrap();
    }
}
/// No Clone: removing reserved adapter work consumes the only path to this permit.
pub(crate) struct BoundPermit {
    authorization: SigningAuthorization,
    lease: Box<dyn SigningLease>,
    verifier: FixtureVerifier,
    #[cfg(test)]
    fault: Arc<std::sync::atomic::AtomicUsize>,
}
impl BoundPermit {
    pub(crate) fn sign(self, expected: &SigningAuthorization) -> Result<BoundJwt, SigningError> {
        if self.authorization != *expected {
            return Err(SigningError::InvalidBinding);
        }
        // A dispatch is already authorized. Request expiry is a reservation limit,
        // not cancellation of work that won the broker's reserve/revoke race.
        #[cfg(test)]
        assert_ne!(
            self.fault.load(Ordering::SeqCst),
            1,
            "synthetic pre-sign panic"
        );
        #[cfg(test)]
        if self.fault.load(Ordering::SeqCst) == 3 {
            std::process::exit(93);
        }
        let (jwt, issued) = self.lease.sign_with_stamp(self.authorization.reserved_at)?;
        #[cfg(test)]
        if self.fault.load(Ordering::SeqCst) == 4 {
            std::process::exit(93);
        }
        #[cfg(test)]
        assert_ne!(
            self.fault.load(Ordering::SeqCst),
            2,
            "synthetic post-sign panic"
        );
        Ok(BoundJwt {
            jwt,
            issued,
            authorization: self.authorization,
            verifier: self.verifier,
        })
    }
}
pub(crate) struct BoundJwt {
    jwt: AppJwt,
    issued: Stamp,
    authorization: SigningAuthorization,
    verifier: FixtureVerifier,
}
impl BoundJwt {
    pub(crate) fn issued_at(&self) -> (u64, u64) {
        (self.issued.utc, self.issued.elapsed)
    }
    pub(crate) fn verify(&self, expected: &SigningAuthorization, utc: u64, elapsed: u64) -> bool {
        if self.authorization != *expected {
            return false;
        }
        let now = Stamp { utc, elapsed };
        if !now.after(self.issued) || self.verifier.verify(&self.jwt, now).is_err() {
            return false;
        }
        let Ok(claims) = strict_parts(&self.jwt.0) else {
            return false;
        };
        claims.iss == ISSUER
            && Some(claims.iat) == self.issued.utc.checked_sub(60)
            && Some(claims.exp) == self.issued.utc.checked_add(540)
    }
}

#[cfg(test)]
#[path = "composition_tests.rs"]
mod tests;
