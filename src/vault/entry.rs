//! Fixed-fixture operator-entry metadata ceremony. This is not a key-entry API.
//!
//! Receipts are simulated observations, not signed attestations, human-presence
//! evidence or measurements of this host. The ceremony never opens a vault or
//! accepts a secret, deployment configuration, readiness flag or provider route.
//!
//! ```compile_fail
//! use aegis::vault::entry::Ceremony;
//! ```
//! ```compile_fail
//! use aegis::vault::entry::CanaryReservation;
//! ```
//! ```compile_fail
//! aegis::vault::entry::run_synthetic_operator_entry_drill(b"not-an-entry-interface");
//! ```
use crate::{Clock, ErrorCode, ManualClock};
use serde::Serialize;
use std::sync::{Arc, Mutex, MutexGuard};

#[path = "protected_entry.rs"]
pub mod protected_entry;

const LIFETIME: u64 = 60;
const RECEIPT_COUNT: usize = 5;

/// The only supported scope; it does not represent operational entry authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryDrillScope {
    SyntheticMetadataOnly,
}

/// Closed observations from the built-in drill. No keys, paths or receipt bodies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorEntryReport {
    pub scope: EntryDrillScope,
    pub prerequisite_receipts: usize,
    pub canary_reservations: u32,
    pub repeated_reservation: ErrorCode,
    pub canceled_reservation: ErrorCode,
    pub expired_reservation: ErrorCode,
    pub production_entry: ErrorCode,
}

// Everything below is private. These identifiers describe dummy actors; equality
// checks are not a verifier of real identity, custody or deployed artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct RoleBinding {
    principal: &'static str,
    enrollment_revision: u64,
    verification_key_digest: [u8; 32],
}
impl RoleBinding {
    fn fixture(principal: &'static str, key: u8) -> Self {
        Self {
            principal,
            enrollment_revision: 1,
            verification_key_digest: [key; 32],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Bindings {
    artifact_digest: [u8; 32],
    dependency_digest: [u8; 32],
    configuration_digest: [u8; 32],
    acl_revision: u64,
    operator: RoleBinding,
    agent: RoleBinding,
    broker: RoleBinding,
    recipient: RoleBinding,
    recovery: RoleBinding,
    reviewer: RoleBinding,
    recovery_destination_digest: [u8; 32],
    anchor_identity_digest: [u8; 32],
    recipient_destination_digest: [u8; 32],
    endpoint_digest: [u8; 32],
    resource: &'static str,
    secret_reference: &'static str,
    secret_version: u64,
    recipient_generation: u64,
}
impl Bindings {
    fn fixture() -> Self {
        Self {
            artifact_digest: [1; 32],
            dependency_digest: [2; 32],
            configuration_digest: [3; 32],
            acl_revision: 1,
            operator: RoleBinding::fixture("fixture-operator", 11),
            agent: RoleBinding::fixture("fixture-agent", 12),
            broker: RoleBinding::fixture("fixture-broker", 13),
            recipient: RoleBinding::fixture("fixture-recipient", 14),
            recovery: RoleBinding::fixture("fixture-recovery", 15),
            reviewer: RoleBinding::fixture("fixture-reviewer", 16),
            recovery_destination_digest: [4; 32],
            anchor_identity_digest: [5; 32],
            recipient_destination_digest: [6; 32],
            endpoint_digest: [7; 32],
            resource: "synthetic-repository-4242",
            secret_reference: "synthetic-provider-key",
            secret_version: 1,
            recipient_generation: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum Prerequisite {
    ArtifactAndConfigurationReview,
    IndependentRecoveryAndAnchor,
    PrivilegedAccessRemoval,
    RemainingToolsCanary,
    EnrolledRecipientCanary,
}
impl Prerequisite {
    const ALL: [Self; RECEIPT_COUNT] = [
        Self::ArtifactAndConfigurationReview,
        Self::IndependentRecoveryAndAnchor,
        Self::PrivilegedAccessRemoval,
        Self::RemainingToolsCanary,
        Self::EnrolledRecipientCanary,
    ];

    fn index(self) -> usize {
        match self {
            Self::ArtifactAndConfigurationReview => 0,
            Self::IndependentRecoveryAndAnchor => 1,
            Self::PrivilegedAccessRemoval => 2,
            Self::RemainingToolsCanary => 3,
            Self::EnrolledRecipientCanary => 4,
        }
    }

    fn observer(self, bindings: &Bindings) -> &RoleBinding {
        match self {
            Self::ArtifactAndConfigurationReview | Self::RemainingToolsCanary => &bindings.reviewer,
            Self::IndependentRecoveryAndAnchor => &bindings.recovery,
            Self::PrivilegedAccessRemoval => &bindings.operator,
            Self::EnrolledRecipientCanary => &bindings.recipient,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct FixtureReceipt {
    instance: [u8; 16],
    bindings: Bindings,
    prerequisite: Prerequisite,
    observer: RoleBinding,
    observed_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct FrozenReview {
    instance: [u8; 16],
    bindings: Bindings,
    receipts: [FixtureReceipt; RECEIPT_COUNT],
    expires_at: u64,
    canary_use_limit: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Collecting,
    Frozen,
    Approved,
    CanaryReserved,
    Canceled,
    Expired,
    Invalidated,
    ClockInvalid,
}
struct State {
    phase: Phase,
    last_time: u64,
    receipts: [Option<FixtureReceipt>; RECEIPT_COUNT],
    review: Option<FrozenReview>,
    reservations: u32,
}
struct Ceremony {
    instance: [u8; 16],
    bindings: Bindings,
    started_at: u64,
    expires_at: u64,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}
// Not Clone, serializable, externally constructible or accepted by any dispatcher.
struct CanaryReservation {
    instance: [u8; 16],
    review: FrozenReview,
}

impl Ceremony {
    fn fixture(clock: Arc<dyn Clock>) -> Result<Self, ErrorCode> {
        let started_at = clock.now();
        let expires_at = started_at
            .checked_add(LIFETIME)
            .ok_or(ErrorCode::RequestExpired)?;
        let mut instance = [0; 16];
        getrandom::getrandom(&mut instance).map_err(|_| ErrorCode::BrokerUnavailable)?;
        Ok(Self {
            instance,
            bindings: Bindings::fixture(),
            started_at,
            expires_at,
            clock,
            state: Mutex::new(State {
                phase: Phase::Collecting,
                last_time: started_at,
                receipts: std::array::from_fn(|_| None),
                review: None,
                reservations: 0,
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, ErrorCode> {
        self.state.lock().map_err(|_| ErrorCode::BrokerUnavailable)
    }

    fn active(&self, state: &mut State, current: &Bindings) -> Result<u64, ErrorCode> {
        match state.phase {
            Phase::CanaryReserved => return Err(ErrorCode::BudgetExhausted),
            Phase::Canceled => return Err(ErrorCode::RequestCanceled),
            Phase::Expired => return Err(ErrorCode::RequestExpired),
            Phase::Invalidated => return Err(ErrorCode::PolicyChanged),
            Phase::ClockInvalid => return Err(ErrorCode::SessionExpired),
            Phase::Collecting | Phase::Frozen | Phase::Approved => {}
        }
        if current != &self.bindings {
            state.phase = Phase::Invalidated;
            return Err(ErrorCode::PolicyChanged);
        }
        let now = self.clock.now();
        if now < state.last_time {
            state.phase = Phase::ClockInvalid;
            return Err(ErrorCode::SessionExpired);
        }
        state.last_time = now;
        if now >= self.expires_at
            || state
                .receipts
                .iter()
                .flatten()
                .any(|receipt| now >= receipt.expires_at)
        {
            state.phase = Phase::Expired;
            return Err(ErrorCode::RequestExpired);
        }
        Ok(now)
    }

    fn fixture_receipt(&self, prerequisite: Prerequisite) -> FixtureReceipt {
        FixtureReceipt {
            instance: self.instance,
            bindings: self.bindings.clone(),
            prerequisite,
            observer: prerequisite.observer(&self.bindings).clone(),
            observed_at: self.started_at,
            expires_at: self.expires_at,
        }
    }

    fn record(&self, current: &Bindings, receipt: FixtureReceipt) -> Result<(), ErrorCode> {
        let mut state = self.lock()?;
        let now = self.active(&mut state, current)?;
        if state.phase != Phase::Collecting {
            return Err(ErrorCode::PolicyChanged);
        }
        if receipt.instance != self.instance
            || receipt.bindings != self.bindings
            || &receipt.observer != receipt.prerequisite.observer(&self.bindings)
        {
            return Err(ErrorCode::ScopeDenied);
        }
        if receipt.observed_at < self.started_at
            || receipt.observed_at > now
            || receipt.expires_at <= now
            || receipt.expires_at > self.expires_at
        {
            return Err(ErrorCode::RequestExpired);
        }
        let slot = &mut state.receipts[receipt.prerequisite.index()];
        if let Some(existing) = slot {
            return if existing == &receipt {
                Ok(())
            } else {
                Err(ErrorCode::RequestIdConflict)
            };
        }
        *slot = Some(receipt);
        Ok(())
    }

    fn freeze(&self, current: &Bindings) -> Result<FrozenReview, ErrorCode> {
        let mut state = self.lock()?;
        self.active(&mut state, current)?;
        if state.phase != Phase::Collecting {
            return Err(ErrorCode::PolicyChanged);
        }
        let receipts = state
            .receipts
            .clone()
            .map(|receipt| receipt.ok_or(ErrorCode::ApprovalRequired));
        let [a, b, c, d, e] = receipts;
        let receipts = [a?, b?, c?, d?, e?];
        let review = FrozenReview {
            instance: self.instance,
            bindings: self.bindings.clone(),
            expires_at: receipts
                .iter()
                .map(|receipt| receipt.expires_at)
                .min()
                .ok_or(ErrorCode::ApprovalRequired)?,
            receipts,
            canary_use_limit: 1,
        };
        state.review = Some(review.clone());
        state.phase = Phase::Frozen;
        Ok(review)
    }

    fn approve(
        &self,
        current: &Bindings,
        operator: &RoleBinding,
        expected: &FrozenReview,
    ) -> Result<(), ErrorCode> {
        let mut state = self.lock()?;
        self.active(&mut state, current)?;
        if operator != &self.bindings.operator {
            return Err(ErrorCode::AuthenticationRequired);
        }
        if state.phase != Phase::Frozen || state.review.as_ref() != Some(expected) {
            return Err(ErrorCode::PolicyChanged);
        }
        state.phase = Phase::Approved;
        Ok(())
    }

    fn reserve(
        &self,
        current: &Bindings,
        expected: &FrozenReview,
    ) -> Result<CanaryReservation, ErrorCode> {
        let mut state = self.lock()?;
        self.active(&mut state, current)?;
        if state.phase != Phase::Approved {
            return Err(ErrorCode::ApprovalRequired);
        }
        if state.review.as_ref() != Some(expected) {
            return Err(ErrorCode::PolicyChanged);
        }
        // Reservation and cancellation share this serialization point. The base
        // ceremony performs no effect; only the separate fixed-canary import
        // fixture may consume this token. No broker dispatcher accepts it.
        state.reservations = 1;
        state.phase = Phase::CanaryReserved;
        Ok(CanaryReservation {
            instance: self.instance,
            review: expected.clone(),
        })
    }

    fn cancel(&self, current: &Bindings, operator: &RoleBinding) -> Result<(), ErrorCode> {
        let mut state = self.lock()?;
        self.active(&mut state, current)?;
        if operator != &self.bindings.operator {
            return Err(ErrorCode::AuthenticationRequired);
        }
        state.phase = Phase::Canceled;
        Ok(())
    }
}

fn reviewed_fixture(ceremony: &Ceremony) -> Result<FrozenReview, ErrorCode> {
    for prerequisite in Prerequisite::ALL {
        ceremony.record(&ceremony.bindings, ceremony.fixture_receipt(prerequisite))?;
    }
    ceremony.freeze(&ceremony.bindings)
}

/// Run a bounded, in-memory metadata drill using only built-in dummy identities.
/// It reserves one simulated canary intent, without dispatching or delivering it.
/// No argument can enable production entry, import evidence or supply a value.
pub fn run_synthetic_operator_entry_drill() -> Result<OperatorEntryReport, ErrorCode> {
    let clock = Arc::new(ManualClock::default());
    let ceremony = Ceremony::fixture(clock.clone())?;
    let review = reviewed_fixture(&ceremony)?;
    ceremony.approve(&ceremony.bindings, &ceremony.bindings.operator, &review)?;
    {
        let reservation = ceremony.reserve(&ceremony.bindings, &review)?;
        if reservation.instance != ceremony.instance || reservation.review != review {
            return Err(ErrorCode::BrokerUnavailable);
        }
    }
    // Dropping the metadata token cannot refund or recreate the consumed use.
    let repeated_reservation = ceremony
        .reserve(&ceremony.bindings, &review)
        .err()
        .ok_or(ErrorCode::BrokerUnavailable)?;

    let canceled = Ceremony::fixture(clock.clone())?;
    let canceled_review = reviewed_fixture(&canceled)?;
    canceled.cancel(&canceled.bindings, &canceled.bindings.operator)?;
    let canceled_reservation = canceled
        .reserve(&canceled.bindings, &canceled_review)
        .err()
        .ok_or(ErrorCode::BrokerUnavailable)?;

    let expired = Ceremony::fixture(clock.clone())?;
    let expired_review = reviewed_fixture(&expired)?;
    expired.approve(
        &expired.bindings,
        &expired.bindings.operator,
        &expired_review,
    )?;
    clock.set(expired.expires_at);
    let expired_reservation = expired
        .reserve(&expired.bindings, &expired_review)
        .err()
        .ok_or(ErrorCode::BrokerUnavailable)?;
    let production_entry = super::require_live_deployment()
        .err()
        .ok_or(ErrorCode::BrokerUnavailable)?;
    if repeated_reservation != ErrorCode::BudgetExhausted
        || canceled_reservation != ErrorCode::RequestCanceled
        || expired_reservation != ErrorCode::RequestExpired
        || production_entry != ErrorCode::UnsupportedDeployment
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let canary_reservations = ceremony.lock()?.reservations;
    Ok(OperatorEntryReport {
        scope: EntryDrillScope::SyntheticMetadataOnly,
        prerequisite_receipts: review.receipts.len(),
        canary_reservations,
        repeated_reservation,
        canceled_reservation,
        expired_reservation,
        production_entry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    fn setup() -> (Arc<ManualClock>, Ceremony) {
        let clock = Arc::new(ManualClock::default());
        let ceremony = Ceremony::fixture(clock.clone()).unwrap();
        (clock, ceremony)
    }

    fn approved(ceremony: &Ceremony) -> FrozenReview {
        let review = reviewed_fixture(ceremony).unwrap();
        ceremony
            .approve(&ceremony.bindings, &ceremony.bindings.operator, &review)
            .unwrap();
        review
    }

    #[test]
    fn drill_has_a_closed_metadata_only_report_and_refuses_production() {
        let report = run_synthetic_operator_entry_drill().unwrap();
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::json!({
                "scope": "synthetic_metadata_only",
                "prerequisite_receipts": 5,
                "canary_reservations": 1,
                "repeated_reservation": "budget_exhausted",
                "canceled_reservation": "request_canceled",
                "expired_reservation": "request_expired",
                "production_entry": "unsupported_deployment"
            })
        );
        let debug = format!("{report:?}");
        assert!(!debug.contains(super::super::store::CANARY_ONE));
        assert!(!debug.contains(super::super::store::CANARY_TWO));
        assert_eq!(
            super::super::require_live_deployment(),
            Err(ErrorCode::UnsupportedDeployment)
        );
    }

    #[test]
    fn each_prerequisite_is_required_and_repeated_receipts_do_not_fill_other_slots() {
        for missing in Prerequisite::ALL {
            let (_, ceremony) = setup();
            for prerequisite in Prerequisite::ALL {
                if prerequisite != missing {
                    for _ in 0..3 {
                        ceremony
                            .record(&ceremony.bindings, ceremony.fixture_receipt(prerequisite))
                            .unwrap();
                    }
                }
            }
            assert_eq!(
                ceremony.freeze(&ceremony.bindings),
                Err(ErrorCode::ApprovalRequired)
            );
            assert_eq!(ceremony.lock().unwrap().phase, Phase::Collecting);
            assert_eq!(ceremony.lock().unwrap().reservations, 0);
        }
    }

    #[test]
    fn approval_and_reservation_cannot_skip_review_or_prerequisites() {
        let (_, ceremony) = setup();
        let (_, other) = setup();
        let unrelated = reviewed_fixture(&other).unwrap();
        assert_eq!(
            ceremony.approve(&ceremony.bindings, &ceremony.bindings.operator, &unrelated),
            Err(ErrorCode::PolicyChanged)
        );
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &unrelated).err(),
            Some(ErrorCode::ApprovalRequired)
        );
        let review = reviewed_fixture(&ceremony).unwrap();
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &review).err(),
            Some(ErrorCode::ApprovalRequired)
        );
        assert_eq!(ceremony.lock().unwrap().reservations, 0);
    }

    #[test]
    fn foreign_instance_receipts_and_reviews_never_transfer_authority() {
        let (_, ceremony) = setup();
        let (_, other) = setup();
        let receipt = other.fixture_receipt(Prerequisite::PrivilegedAccessRemoval);
        assert_eq!(
            ceremony.record(&ceremony.bindings, receipt),
            Err(ErrorCode::ScopeDenied)
        );
        let review = reviewed_fixture(&ceremony).unwrap();
        let foreign = reviewed_fixture(&other).unwrap();
        assert_eq!(
            ceremony.approve(&ceremony.bindings, &ceremony.bindings.operator, &foreign),
            Err(ErrorCode::PolicyChanged)
        );
        ceremony
            .approve(&ceremony.bindings, &ceremony.bindings.operator, &review)
            .unwrap();
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &foreign).err(),
            Some(ErrorCode::PolicyChanged)
        );
        assert!(ceremony.reserve(&ceremony.bindings, &review).is_ok());
    }

    #[test]
    fn receipt_binding_observer_and_time_are_checked_without_consuming_a_slot() {
        type Mutation = fn(&mut FixtureReceipt);
        let mutations: [(Mutation, ErrorCode); 9] = [
            (|r| r.instance[0] ^= 1, ErrorCode::ScopeDenied),
            (
                |r| r.bindings.configuration_digest[0] ^= 1,
                ErrorCode::ScopeDenied,
            ),
            (
                |r| r.observer.principal = "fixture-agent",
                ErrorCode::ScopeDenied,
            ),
            (
                |r| r.observer.enrollment_revision += 1,
                ErrorCode::ScopeDenied,
            ),
            (
                |r| r.observer.verification_key_digest[0] ^= 1,
                ErrorCode::ScopeDenied,
            ),
            (|r| r.observed_at = 9, ErrorCode::RequestExpired),
            (|r| r.observed_at = 11, ErrorCode::RequestExpired),
            (|r| r.expires_at = 10, ErrorCode::RequestExpired),
            (|r| r.expires_at += 1, ErrorCode::RequestExpired),
        ];
        for (mutate, expected) in mutations {
            let clock = Arc::new(ManualClock::default());
            clock.set(10);
            let ceremony = Ceremony::fixture(clock).unwrap();
            let mut receipt = ceremony.fixture_receipt(Prerequisite::PrivilegedAccessRemoval);
            mutate(&mut receipt);
            assert_eq!(ceremony.record(&ceremony.bindings, receipt), Err(expected));
            assert!(ceremony
                .lock()
                .unwrap()
                .receipts
                .iter()
                .all(Option::is_none));
        }
    }

    #[test]
    fn receipt_kind_cannot_be_relabelled_to_a_different_observer_role() {
        let (_, ceremony) = setup();
        let mut receipt = ceremony.fixture_receipt(Prerequisite::PrivilegedAccessRemoval);
        receipt.prerequisite = Prerequisite::EnrolledRecipientCanary;
        assert_eq!(
            ceremony.record(&ceremony.bindings, receipt),
            Err(ErrorCode::ScopeDenied)
        );
    }

    #[test]
    fn conflicting_receipt_cannot_replace_existing_evidence() {
        let (_, ceremony) = setup();
        let first = ceremony.fixture_receipt(Prerequisite::PrivilegedAccessRemoval);
        ceremony.record(&ceremony.bindings, first.clone()).unwrap();
        let mut changed = first.clone();
        changed.expires_at -= 1;
        assert_eq!(
            ceremony.record(&ceremony.bindings, changed),
            Err(ErrorCode::RequestIdConflict)
        );
        assert_eq!(ceremony.lock().unwrap().receipts[2], Some(first));
    }

    fn binding_variants(original: &Bindings) -> Vec<Bindings> {
        let mut variants = Vec::new();
        macro_rules! variant {
            ($field:ident, $value:expr) => {{
                let mut changed = original.clone();
                changed.$field = $value;
                variants.push(changed);
            }};
        }
        variant!(artifact_digest, [90; 32]);
        variant!(dependency_digest, [90; 32]);
        variant!(configuration_digest, [90; 32]);
        variant!(acl_revision, 2);
        variant!(recovery_destination_digest, [90; 32]);
        variant!(anchor_identity_digest, [90; 32]);
        variant!(recipient_destination_digest, [90; 32]);
        variant!(endpoint_digest, [90; 32]);
        variant!(resource, "other-resource");
        variant!(secret_reference, "other-secret");
        variant!(secret_version, 2);
        variant!(recipient_generation, 1);
        for role_index in 0..6 {
            for field in 0..3 {
                let mut changed = original.clone();
                let role = match role_index {
                    0 => &mut changed.operator,
                    1 => &mut changed.agent,
                    2 => &mut changed.broker,
                    3 => &mut changed.recipient,
                    4 => &mut changed.recovery,
                    _ => &mut changed.reviewer,
                };
                match field {
                    0 => role.principal = "another-principal",
                    1 => role.enrollment_revision += 1,
                    _ => role.verification_key_digest[0] ^= 1,
                }
                variants.push(changed);
            }
        }
        variants
    }

    #[test]
    fn every_exact_binding_change_latches_invalidation_before_reservation() {
        for changed in binding_variants(&Bindings::fixture()) {
            let (_, ceremony) = setup();
            let review = approved(&ceremony);
            assert_eq!(
                ceremony.reserve(&changed, &review).err(),
                Some(ErrorCode::PolicyChanged)
            );
            // Reverting a configuration cannot revive the old approval.
            assert_eq!(
                ceremony.reserve(&ceremony.bindings, &review).err(),
                Some(ErrorCode::PolicyChanged)
            );
            assert_eq!(ceremony.lock().unwrap().reservations, 0);
        }
    }

    #[test]
    fn current_binding_change_is_also_rejected_during_collection_review_and_approval() {
        for stage in 0..3 {
            let (_, ceremony) = setup();
            let mut current = ceremony.bindings.clone();
            current.artifact_digest[0] ^= 1;
            let result = match stage {
                0 => ceremony.record(
                    &current,
                    ceremony.fixture_receipt(Prerequisite::PrivilegedAccessRemoval),
                ),
                1 => ceremony.freeze(&current).map(|_| ()),
                _ => {
                    let review = reviewed_fixture(&ceremony).unwrap();
                    ceremony.approve(&current, &ceremony.bindings.operator, &review)
                }
            };
            assert_eq!(result, Err(ErrorCode::PolicyChanged));
            assert_eq!(ceremony.lock().unwrap().phase, Phase::Invalidated);
        }
    }

    #[test]
    fn frozen_review_binds_each_field_and_receipt_and_cannot_be_substituted() {
        type Mutation = fn(&mut FrozenReview);
        let mutations: [Mutation; 10] = [
            |r| r.instance[0] ^= 1,
            |r| r.bindings.acl_revision += 1,
            |r| r.expires_at += 1,
            |r| r.canary_use_limit += 1,
            |r| r.receipts[0].instance[0] ^= 1,
            |r| r.receipts[0].bindings.artifact_digest[0] ^= 1,
            |r| r.receipts[0].observer.enrollment_revision += 1,
            |r| r.receipts[0].observed_at += 1,
            |r| r.receipts[0].expires_at -= 1,
            |r| r.receipts.swap(0, 1),
        ];
        for mutate in mutations {
            let (_, ceremony) = setup();
            let review = reviewed_fixture(&ceremony).unwrap();
            let mut forged = review.clone();
            mutate(&mut forged);
            assert_eq!(
                ceremony.approve(&ceremony.bindings, &ceremony.bindings.operator, &forged),
                Err(ErrorCode::PolicyChanged)
            );
            ceremony
                .approve(&ceremony.bindings, &ceremony.bindings.operator, &review)
                .unwrap();
            assert_eq!(
                ceremony.reserve(&ceremony.bindings, &forged).err(),
                Some(ErrorCode::PolicyChanged)
            );
            assert!(ceremony.reserve(&ceremony.bindings, &review).is_ok());
        }
    }

    #[test]
    fn all_non_operator_roles_fail_approval_and_cancellation() {
        let (_, ceremony) = setup();
        let review = reviewed_fixture(&ceremony).unwrap();
        for actor in [
            &ceremony.bindings.agent,
            &ceremony.bindings.broker,
            &ceremony.bindings.recipient,
            &ceremony.bindings.recovery,
            &ceremony.bindings.reviewer,
        ] {
            assert_eq!(
                ceremony.approve(&ceremony.bindings, actor, &review),
                Err(ErrorCode::AuthenticationRequired)
            );
            assert_eq!(
                ceremony.cancel(&ceremony.bindings, actor),
                Err(ErrorCode::AuthenticationRequired)
            );
        }
        let mut stale_operator = ceremony.bindings.operator.clone();
        stale_operator.enrollment_revision += 1;
        assert_eq!(
            ceremony.approve(&ceremony.bindings, &stale_operator, &review),
            Err(ErrorCode::AuthenticationRequired)
        );
        assert_eq!(ceremony.lock().unwrap().phase, Phase::Frozen);
    }

    #[test]
    fn freezing_prohibits_receipt_mutation_and_second_freeze_or_approval() {
        let (_, ceremony) = setup();
        let review = reviewed_fixture(&ceremony).unwrap();
        assert_eq!(
            ceremony.freeze(&ceremony.bindings),
            Err(ErrorCode::PolicyChanged)
        );
        assert_eq!(
            ceremony.record(
                &ceremony.bindings,
                ceremony.fixture_receipt(Prerequisite::PrivilegedAccessRemoval)
            ),
            Err(ErrorCode::PolicyChanged)
        );
        ceremony
            .approve(&ceremony.bindings, &ceremony.bindings.operator, &review)
            .unwrap();
        assert_eq!(
            ceremony.approve(&ceremony.bindings, &ceremony.bindings.operator, &review),
            Err(ErrorCode::PolicyChanged)
        );
    }

    #[test]
    fn earliest_receipt_expiry_bounds_review_and_is_not_refreshable() {
        let (clock, ceremony) = setup();
        for prerequisite in Prerequisite::ALL {
            let mut receipt = ceremony.fixture_receipt(prerequisite);
            if prerequisite == Prerequisite::IndependentRecoveryAndAnchor {
                receipt.expires_at = 9;
            }
            ceremony.record(&ceremony.bindings, receipt).unwrap();
        }
        let review = ceremony.freeze(&ceremony.bindings).unwrap();
        assert_eq!(review.expires_at, 9);
        ceremony
            .approve(&ceremony.bindings, &ceremony.bindings.operator, &review)
            .unwrap();
        clock.set(9);
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &review).err(),
            Some(ErrorCode::RequestExpired)
        );
        clock.set(0);
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &review).err(),
            Some(ErrorCode::RequestExpired)
        );
        assert_eq!(ceremony.lock().unwrap().reservations, 0);
    }

    #[test]
    fn deadline_boundary_and_expired_collection_fail_closed() {
        for now in [LIFETIME - 1, LIFETIME, LIFETIME + 1] {
            let (clock, ceremony) = setup();
            let review = approved(&ceremony);
            clock.set(now);
            assert_eq!(
                ceremony.reserve(&ceremony.bindings, &review).is_ok(),
                now < LIFETIME
            );
        }
        let (clock, ceremony) = setup();
        clock.set(LIFETIME);
        assert_eq!(
            ceremony.record(
                &ceremony.bindings,
                ceremony.fixture_receipt(Prerequisite::PrivilegedAccessRemoval)
            ),
            Err(ErrorCode::RequestExpired)
        );
        assert_eq!(
            ceremony.freeze(&ceremony.bindings),
            Err(ErrorCode::RequestExpired)
        );
    }

    #[test]
    fn clock_regression_latches_and_overflow_never_constructs_a_ceremony() {
        let (clock, ceremony) = setup();
        let review = approved(&ceremony);
        clock.set(5);
        // A rejected second approval still records the clock observation.
        assert_eq!(
            ceremony.approve(&ceremony.bindings, &ceremony.bindings.operator, &review),
            Err(ErrorCode::PolicyChanged)
        );
        clock.set(4);
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &review).err(),
            Some(ErrorCode::SessionExpired)
        );
        clock.set(6);
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &review).err(),
            Some(ErrorCode::SessionExpired)
        );
        clock.set(u64::MAX);
        assert_eq!(
            Ceremony::fixture(clock).err(),
            Some(ErrorCode::RequestExpired)
        );
    }

    #[test]
    fn cancellation_is_terminal_in_every_pre_reservation_phase() {
        for stage in 0..3 {
            let (_, ceremony) = setup();
            let (_, other) = setup();
            let review = match stage {
                0 => reviewed_fixture(&other).unwrap(),
                1 => reviewed_fixture(&ceremony).unwrap(),
                _ => approved(&ceremony),
            };
            ceremony
                .cancel(&ceremony.bindings, &ceremony.bindings.operator)
                .unwrap();
            assert_eq!(
                ceremony.reserve(&ceremony.bindings, &review).err(),
                Some(ErrorCode::RequestCanceled)
            );
            assert_eq!(
                ceremony.approve(&ceremony.bindings, &ceremony.bindings.operator, &review),
                Err(ErrorCode::RequestCanceled)
            );
            assert_eq!(ceremony.lock().unwrap().reservations, 0);
        }
    }

    #[test]
    fn dropped_reservation_cancellation_and_expiry_never_refund_or_reopen() {
        let (clock, ceremony) = setup();
        let review = approved(&ceremony);
        {
            let _reservation = ceremony.reserve(&ceremony.bindings, &review).unwrap();
        }
        assert_eq!(
            ceremony.cancel(&ceremony.bindings, &ceremony.bindings.operator),
            Err(ErrorCode::BudgetExhausted)
        );
        clock.set(LIFETIME + 1);
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &review).err(),
            Some(ErrorCode::BudgetExhausted)
        );
        assert_eq!(ceremony.lock().unwrap().phase, Phase::CanaryReserved);
        assert_eq!(ceremony.lock().unwrap().reservations, 1);
    }

    #[test]
    fn concurrent_reservations_have_one_winner() {
        let (_, ceremony) = setup();
        let review = approved(&ceremony);
        let ceremony = Arc::new(ceremony);
        let barrier = Arc::new(Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (ceremony, review, barrier) =
                    (ceremony.clone(), review.clone(), barrier.clone());
                thread::spawn(move || {
                    barrier.wait();
                    ceremony.reserve(&ceremony.bindings, &review).map(|_| ())
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(ErrorCode::BudgetExhausted))
                .count(),
            15
        );
        assert_eq!(ceremony.lock().unwrap().reservations, 1);
    }

    #[test]
    fn cancellation_and_reservation_share_one_serialization_point() {
        let (_, ceremony) = setup();
        let review = approved(&ceremony);
        let ceremony = Arc::new(ceremony);
        let barrier = Arc::new(Barrier::new(2));
        let reserved = {
            let ceremony = ceremony.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                ceremony.reserve(&ceremony.bindings, &review).map(|_| ())
            })
        };
        barrier.wait();
        let canceled = ceremony.cancel(&ceremony.bindings, &ceremony.bindings.operator);
        let reserved = reserved.join().unwrap();
        assert!(matches!(
            (canceled, reserved),
            (Ok(()), Err(ErrorCode::RequestCanceled)) | (Err(ErrorCode::BudgetExhausted), Ok(()))
        ));
        assert_eq!(
            ceremony.lock().unwrap().reservations,
            u32::from(reserved.is_ok())
        );
    }

    #[test]
    fn poisoned_state_never_allows_a_reservation() {
        let (_, ceremony) = setup();
        let review = approved(&ceremony);
        let ceremony = Arc::new(ceremony);
        let broken = ceremony.clone();
        assert!(thread::spawn(move || {
            let _state = broken.state.lock().unwrap();
            panic!("fixed fixture failure");
        })
        .join()
        .is_err());
        assert_eq!(
            ceremony.reserve(&ceremony.bindings, &review).err(),
            Some(ErrorCode::BrokerUnavailable)
        );
    }

    #[test]
    fn fresh_fixture_restores_neither_receipts_nor_approval() {
        let (_, first) = setup();
        let review = approved(&first);
        {
            let _reservation = first.reserve(&first.bindings, &review).unwrap();
        }
        let (_, fresh) = setup();
        assert_ne!(first.instance, fresh.instance);
        assert_eq!(
            fresh.freeze(&fresh.bindings),
            Err(ErrorCode::ApprovalRequired)
        );
        assert_eq!(
            fresh.reserve(&fresh.bindings, &review).err(),
            Some(ErrorCode::ApprovalRequired)
        );
        assert_eq!(fresh.lock().unwrap().reservations, 0);
    }
}
