//! Report-only operator-host deployment prerequisites and a synthetic evidence model.
//!
//! No host collector, attestation verifier, deployment capability, secret input or
//! live factory exists here. A complete simulation still reports `no_go`. The
//! private receipts are deliberately not OS observations or human authentication.
//!
//! ```compile_fail
//! use aegis::vault::deployment::Preflight;
//! ```
//! ```compile_fail
//! use aegis::vault::deployment::FixtureReceipt;
//! ```
//! ```compile_fail
//! aegis::vault::deployment::run_synthetic_deployment_preflight_drill(b"secret");
//! ```
use crate::{Clock, ErrorCode, ManualClock};
use serde::Serialize;
use std::sync::{Arc, Mutex, MutexGuard};

const PREREQUISITE_COUNT: usize = 10;
const MAX_EVIDENCE_AGE: u64 = 60;

/// Required evidence domains, not switches that enable a deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPrerequisite {
    DistinctServiceIdentities,
    AgentFileProcessDebugDenial,
    ImmutableApplicationConfigurationDeployment,
    ProtectedLogsBackupsRecovery,
    OperatorOwnedControlPlane,
    IndependentlyAuthenticatedHuman,
    AuthenticatedApplicationPeers,
    ConfidentialAuthenticatedTransport,
    ExternalAnchorAndConcurrentWakeFencing,
    DurableAuditAndRevocation,
}
impl DeploymentPrerequisite {
    const ALL: [Self; PREREQUISITE_COUNT] = [
        Self::DistinctServiceIdentities,
        Self::AgentFileProcessDebugDenial,
        Self::ImmutableApplicationConfigurationDeployment,
        Self::ProtectedLogsBackupsRecovery,
        Self::OperatorOwnedControlPlane,
        Self::IndependentlyAuthenticatedHuman,
        Self::AuthenticatedApplicationPeers,
        Self::ConfidentialAuthenticatedTransport,
        Self::ExternalAnchorAndConcurrentWakeFencing,
        Self::DurableAuditAndRevocation,
    ];

    fn index(self) -> usize {
        Self::ALL.iter().position(|item| *item == self).unwrap()
    }
}

/// This version has no affirmative operational admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentDecision {
    NoGo,
}

/// An explicit distinction between absent host measurements and fixture claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOrigin {
    NoHostObservations,
    SimulatedAttestations,
}

/// Closed diagnostic vocabulary. Even `simulated_consistent` is not a pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Missing,
    UnsupportedObservation,
    SimulatedConsistent,
    BoundaryViolated,
    Unknown,
    Contradictory,
    Stale,
    InvalidTime,
    WrongInstance,
    BindingChanged,
    ObserverMismatch,
    IdentitySeparationInvalid,
    ClockInvalid,
}

/// Code integrations still unavailable regardless of supplied fixture evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentGap {
    HostObservationAndAttestationVerifier,
    ProductionIdentityClockAndTransport,
    ProtectedCustodyAndOperatorEntry,
    IndependentAnchorAndFencing,
    IsolatedRecipientAndDurableRecovery,
    IndependentSecurityReview,
    LiveFactoryDisabled,
}
const GAPS: [DeploymentGap; 7] = [
    DeploymentGap::HostObservationAndAttestationVerifier,
    DeploymentGap::ProductionIdentityClockAndTransport,
    DeploymentGap::ProtectedCustodyAndOperatorEntry,
    DeploymentGap::IndependentAnchorAndFencing,
    DeploymentGap::IsolatedRecipientAndDurableRecovery,
    DeploymentGap::IndependentSecurityReview,
    DeploymentGap::LiveFactoryDisabled,
];

/// Metadata-only result. Reports have no import or authorization consumer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrerequisiteReport {
    pub prerequisite: DeploymentPrerequisite,
    pub status: EvidenceStatus,
}

/// No input strings, host paths, identity values, raw evidence or secret values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeploymentPreflightReport {
    pub decision: DeploymentDecision,
    pub origin: EvidenceOrigin,
    pub prerequisites: [PrerequisiteReport; PREREQUISITE_COUNT],
    pub gaps: [DeploymentGap; 7],
}
impl DeploymentPreflightReport {
    fn new(origin: EvidenceOrigin, statuses: [EvidenceStatus; PREREQUISITE_COUNT]) -> Self {
        Self {
            decision: DeploymentDecision::NoGo,
            origin,
            prerequisites: std::array::from_fn(|index| PrerequisiteReport {
                prerequisite: DeploymentPrerequisite::ALL[index],
                status: statuses[index],
            }),
            gaps: GAPS,
        }
    }
}

/// Enumerate the current NO-GO without claiming to inspect this or another host.
/// There is no supported host collector. This function accepts no host metadata,
/// attestation, credential, caller readiness flag or privileged access handle.
pub fn deployment_prerequisites() -> DeploymentPreflightReport {
    DeploymentPreflightReport::new(
        EvidenceOrigin::NoHostObservations,
        [EvidenceStatus::UnsupportedObservation; PREREQUISITE_COUNT],
    )
}

/// Stable diagnostics actually exercised by the fixed, metadata-only drill.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyntheticDeploymentPreflightReport {
    pub complete_simulation: DeploymentPreflightReport,
    pub missing: EvidenceStatus,
    pub unknown: EvidenceStatus,
    pub same_uid: EvidenceStatus,
    pub contradictory: EvidenceStatus,
    pub stale: EvidenceStatus,
    pub changed_binding: EvidenceStatus,
    pub regressed_clock: EvidenceStatus,
    pub production_entry: ErrorCode,
}

// These are equality bindings of synthetic facts, not digests measured on a host.
// In particular, an OS identity label is not proof of effective permissions.
#[derive(Clone, Debug, Eq, PartialEq)]
struct IdentityBinding {
    principal_digest: [u8; 32],
    enrollment_revision: u64,
    verification_key_digest: [u8; 32],
    security_domain: [u8; 32],
    uid: u32,
}
impl IdentityBinding {
    fn fixture(id: u8) -> Self {
        Self {
            principal_digest: [id; 32],
            enrollment_revision: 1,
            verification_key_digest: [id + 20; 32],
            security_domain: [1; 32],
            uid: u32::from(id),
        }
    }
    fn shares_execution_identity(&self, other: &Self) -> bool {
        self.security_domain == other.security_domain && self.uid == other.uid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeploymentBindings {
    artifact_digest: [u8; 32],
    dependencies_digest: [u8; 32],
    configuration_digest: [u8; 32],
    host_identity: [u8; 32],
    boot_epoch: [u8; 16],
    host_policy_revision: u64,
    agent_tools_digest: [u8; 32],
    agent: IdentityBinding,
    broker: IdentityBinding,
    recipient: IdentityBinding,
    operator: IdentityBinding,
    reviewer: IdentityBinding,
    recovery: IdentityBinding,
    anchor: IdentityBinding,
    acl_revision: u64,
    recipient_generation: u64,
    recovery_generation: u64,
    anchor_generation: u64,
    endpoint_digest: [u8; 32],
}
impl DeploymentBindings {
    fn fixture() -> Self {
        Self {
            artifact_digest: [1; 32],
            dependencies_digest: [2; 32],
            configuration_digest: [3; 32],
            host_identity: [4; 32],
            boot_epoch: [5; 16],
            host_policy_revision: 1,
            agent_tools_digest: [6; 32],
            agent: IdentityBinding::fixture(1),
            broker: IdentityBinding::fixture(2),
            recipient: IdentityBinding::fixture(3),
            operator: IdentityBinding::fixture(4),
            reviewer: IdentityBinding::fixture(5),
            recovery: IdentityBinding::fixture(6),
            anchor: IdentityBinding::fixture(7),
            acl_revision: 1,
            recipient_generation: 1,
            recovery_generation: 1,
            anchor_generation: 1,
            endpoint_digest: [7; 32],
        }
    }
    fn agent_is_separate(&self) -> bool {
        [
            &self.broker,
            &self.recipient,
            &self.operator,
            &self.reviewer,
            &self.recovery,
            &self.anchor,
        ]
        .iter()
        .all(|identity| {
            !self.agent.shares_execution_identity(identity)
                && self.agent.principal_digest != identity.principal_digest
                && self.agent.verification_key_digest != identity.verification_key_digest
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureFinding {
    BoundaryHeld,
    BoundaryViolated,
    Unknown,
    Unsupported,
}

// This is deliberately not an `ActualObservation` type with a caller-selectable
// trust flag. Only the fixed drill constructs receipts; no verifier is exported.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureReceipt {
    instance: [u8; 16],
    bindings: DeploymentBindings,
    prerequisite: DeploymentPrerequisite,
    observer: IdentityBinding,
    observed_at: u64,
    finding: FixtureFinding,
}
impl FixtureReceipt {
    fn status(&self, now: u64) -> EvidenceStatus {
        let Some(expires_at) = self.observed_at.checked_add(MAX_EVIDENCE_AGE) else {
            return EvidenceStatus::InvalidTime;
        };
        if self.observed_at > now {
            return EvidenceStatus::InvalidTime;
        }
        if now >= expires_at {
            return EvidenceStatus::Stale;
        }
        match self.finding {
            FixtureFinding::BoundaryHeld => EvidenceStatus::SimulatedConsistent,
            FixtureFinding::BoundaryViolated => EvidenceStatus::BoundaryViolated,
            FixtureFinding::Unknown => EvidenceStatus::Unknown,
            FixtureFinding::Unsupported => EvidenceStatus::UnsupportedObservation,
        }
    }
}

// Each slot retains at most one receipt or a latched rejection, never a history.
#[derive(Clone)]
enum Slot {
    Empty,
    Receipt(Box<FixtureReceipt>),
    Rejected(EvidenceStatus),
}
struct State {
    last_time: u64,
    terminal: Option<EvidenceStatus>,
    slots: [Slot; PREREQUISITE_COUNT],
}
struct Preflight {
    instance: [u8; 16],
    bindings: DeploymentBindings,
    started_at: u64,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}
impl Preflight {
    fn fixture(clock: Arc<dyn Clock>) -> Result<Self, ErrorCode> {
        let mut instance = [0; 16];
        getrandom::getrandom(&mut instance).map_err(|_| ErrorCode::BrokerUnavailable)?;
        let started_at = clock.now();
        Ok(Self {
            instance,
            bindings: DeploymentBindings::fixture(),
            started_at,
            state: Mutex::new(State {
                last_time: started_at,
                terminal: None,
                slots: std::array::from_fn(|_| Slot::Empty),
            }),
            clock,
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, ErrorCode> {
        self.state.lock().map_err(|_| ErrorCode::BrokerUnavailable)
    }
    fn synchronize(&self, state: &mut State, current: &DeploymentBindings) -> u64 {
        let now = self.clock.now();
        // Invalidity is sticky. Restoring a previous binding or clock reading
        // cannot rehabilitate observations from this instance.
        if state.terminal.is_none() {
            state.terminal = if now < state.last_time {
                Some(EvidenceStatus::ClockInvalid)
            } else if current != &self.bindings {
                Some(EvidenceStatus::BindingChanged)
            } else if !current.agent_is_separate() {
                Some(EvidenceStatus::IdentitySeparationInvalid)
            } else {
                None
            };
        }
        state.last_time = now;
        now
    }
    fn fixture_receipt(&self, prerequisite: DeploymentPrerequisite) -> FixtureReceipt {
        FixtureReceipt {
            instance: self.instance,
            bindings: self.bindings.clone(),
            prerequisite,
            observer: self.bindings.reviewer.clone(),
            observed_at: self.clock.now(),
            finding: FixtureFinding::BoundaryHeld,
        }
    }
    fn record(
        &self,
        current: &DeploymentBindings,
        receipt: FixtureReceipt,
    ) -> Result<EvidenceStatus, ErrorCode> {
        let mut state = self.lock()?;
        let now = self.synchronize(&mut state, current);
        if let Some(failure) = state.terminal {
            return Ok(failure);
        }
        let slot = &mut state.slots[receipt.prerequisite.index()];
        match slot {
            Slot::Rejected(reason) => return Ok(*reason),
            Slot::Receipt(existing) if existing.as_ref() == &receipt => {
                return Ok(existing.status(now));
            }
            Slot::Receipt(_) => {
                *slot = Slot::Rejected(EvidenceStatus::Contradictory);
                return Ok(EvidenceStatus::Contradictory);
            }
            Slot::Empty => {}
        }
        let status = if receipt.instance != self.instance {
            EvidenceStatus::WrongInstance
        } else if receipt.bindings != self.bindings {
            EvidenceStatus::BindingChanged
        } else if receipt.observer != self.bindings.reviewer {
            EvidenceStatus::ObserverMismatch
        } else if receipt.observed_at < self.started_at {
            EvidenceStatus::InvalidTime
        } else {
            receipt.status(now)
        };
        *slot = match status {
            EvidenceStatus::SimulatedConsistent
            | EvidenceStatus::BoundaryViolated
            | EvidenceStatus::Unknown
            | EvidenceStatus::UnsupportedObservation => Slot::Receipt(Box::new(receipt)),
            other => Slot::Rejected(other),
        };
        Ok(status)
    }
    fn inspect(
        &self,
        current: &DeploymentBindings,
    ) -> Result<DeploymentPreflightReport, ErrorCode> {
        let mut state = self.lock()?;
        let now = self.synchronize(&mut state, current);
        let statuses = std::array::from_fn(|index| {
            if let Some(failure) = state.terminal {
                return failure;
            }
            match &state.slots[index] {
                Slot::Empty => EvidenceStatus::Missing,
                Slot::Rejected(reason) => *reason,
                Slot::Receipt(receipt) => receipt.status(now),
            }
        });
        Ok(DeploymentPreflightReport::new(
            EvidenceOrigin::SimulatedAttestations,
            statuses,
        ))
    }
    fn fill_fixture(&self) -> Result<(), ErrorCode> {
        for prerequisite in DeploymentPrerequisite::ALL {
            self.record(&self.bindings, self.fixture_receipt(prerequisite))?;
        }
        Ok(())
    }
}

/// Exercise the bounded metadata gate with fixed synthetic attestations only.
/// No filesystem, process inspection, listener, provider or live factory is used.
/// This is an implementation check, never a host admission or security review.
pub fn run_synthetic_deployment_preflight_drill(
) -> Result<SyntheticDeploymentPreflightReport, ErrorCode> {
    let clock = Arc::new(ManualClock::default());
    let model = Preflight::fixture(clock.clone())?;
    let prerequisite = DeploymentPrerequisite::AgentFileProcessDebugDenial;
    let index = prerequisite.index();
    let missing = model.inspect(&model.bindings)?.prerequisites[index].status;
    model.fill_fixture()?;
    let complete_simulation = model.inspect(&model.bindings)?;

    let mut conflict = model.fixture_receipt(prerequisite);
    conflict.finding = FixtureFinding::BoundaryViolated;
    let contradictory = model.record(&model.bindings, conflict)?;
    // An exact earlier positive receipt cannot repair contradictory evidence.
    model.record(&model.bindings, model.fixture_receipt(prerequisite))?;
    clock.advance(MAX_EVIDENCE_AGE);
    let stale = model.inspect(&model.bindings)?.prerequisites[0].status;
    let mut changed = model.bindings.clone();
    changed.host_policy_revision += 1;
    let changed_binding = model.inspect(&changed)?.prerequisites[0].status;

    let unknown_model = Preflight::fixture(Arc::new(ManualClock::default()))?;
    let mut unknown_receipt = unknown_model.fixture_receipt(prerequisite);
    unknown_receipt.finding = FixtureFinding::Unknown;
    let unknown = unknown_model.record(&unknown_model.bindings, unknown_receipt)?;
    // Unsupported measurements also remain explicitly unavailable.
    let mut unsupported =
        unknown_model.fixture_receipt(DeploymentPrerequisite::DurableAuditAndRevocation);
    unsupported.finding = FixtureFinding::Unsupported;
    unknown_model.record(&unknown_model.bindings, unsupported)?;

    let mut same_uid_model = Preflight::fixture(Arc::new(ManualClock::default()))?;
    same_uid_model.bindings.broker.uid = same_uid_model.bindings.agent.uid;
    let same_uid = same_uid_model
        .inspect(&same_uid_model.bindings)?
        .prerequisites[0]
        .status;

    let regression_clock = Arc::new(ManualClock::default());
    regression_clock.advance(1);
    let regression_model = Preflight::fixture(regression_clock.clone())?;
    // A private clock permits deterministic regression testing without changing
    // any operating-system clock or security settings.
    regression_clock.set(0);
    let regressed_clock = regression_model
        .inspect(&regression_model.bindings)?
        .prerequisites[0]
        .status;
    let production_entry = match super::require_live_deployment() {
        Err(ErrorCode::UnsupportedDeployment) => ErrorCode::UnsupportedDeployment,
        _ => return Err(ErrorCode::BrokerUnavailable),
    };
    Ok(SyntheticDeploymentPreflightReport {
        complete_simulation,
        missing,
        unknown,
        same_uid,
        contradictory,
        stale,
        changed_binding,
        regressed_clock,
        production_entry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Preflight, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::default());
        (Preflight::fixture(clock.clone()).unwrap(), clock)
    }
    fn status(model: &Preflight, prerequisite: DeploymentPrerequisite) -> EvidenceStatus {
        model.inspect(&model.bindings).unwrap().prerequisites[prerequisite.index()].status
    }
    fn assert_all(model: &Preflight, expected: EvidenceStatus) {
        let report = model.inspect(&model.bindings).unwrap();
        assert_eq!(report.decision, DeploymentDecision::NoGo);
        assert!(report
            .prerequisites
            .iter()
            .all(|item| item.status == expected));
    }

    #[test]
    fn actual_host_observations_are_unsupported_and_never_inferred() {
        let report = deployment_prerequisites();
        assert_eq!(report.origin, EvidenceOrigin::NoHostObservations);
        assert_eq!(report.decision, DeploymentDecision::NoGo);
        assert!(report
            .prerequisites
            .iter()
            .all(|item| item.status == EvidenceStatus::UnsupportedObservation));
        assert_eq!(report.gaps, GAPS);
        assert_eq!(
            super::super::require_live_deployment(),
            Err(ErrorCode::UnsupportedDeployment)
        );
    }

    #[test]
    fn all_simulated_evidence_is_still_no_go() {
        let (model, _) = fixture();
        assert_all(&model, EvidenceStatus::Missing);
        model.fill_fixture().unwrap();
        assert_all(&model, EvidenceStatus::SimulatedConsistent);
        let report = model.inspect(&model.bindings).unwrap();
        assert_eq!(report.origin, EvidenceOrigin::SimulatedAttestations);
        assert!(report.gaps.contains(&DeploymentGap::LiveFactoryDisabled));
        assert!(report
            .gaps
            .contains(&DeploymentGap::HostObservationAndAttestationVerifier));
    }

    #[test]
    fn no_admin_claim_cannot_compensate_for_same_uid_or_shared_identity() {
        // BoundaryHeld is the strongest fixture claim and includes the simulated
        // control-plane no-admin denial. It cannot override identity equality.
        for role in 0..6 {
            for identity_dimension in 0..3 {
                let (mut model, _) = fixture();
                let agent = model.bindings.agent.clone();
                let target = match role {
                    0 => &mut model.bindings.broker,
                    1 => &mut model.bindings.recipient,
                    2 => &mut model.bindings.operator,
                    3 => &mut model.bindings.reviewer,
                    4 => &mut model.bindings.recovery,
                    _ => &mut model.bindings.anchor,
                };
                match identity_dimension {
                    0 => target.uid = agent.uid,
                    1 => target.principal_digest = agent.principal_digest,
                    _ => target.verification_key_digest = agent.verification_key_digest,
                }
                model.fill_fixture().unwrap();
                assert_all(&model, EvidenceStatus::IdentitySeparationInvalid);
            }
        }
    }

    #[test]
    fn every_domain_requires_its_own_evidence() {
        for missing in DeploymentPrerequisite::ALL {
            let (model, _) = fixture();
            for prerequisite in DeploymentPrerequisite::ALL {
                if prerequisite != missing {
                    model
                        .record(&model.bindings, model.fixture_receipt(prerequisite))
                        .unwrap();
                }
            }
            assert_eq!(status(&model, missing), EvidenceStatus::Missing);
            assert_eq!(
                model.inspect(&model.bindings).unwrap().decision,
                DeploymentDecision::NoGo
            );
        }
    }

    #[test]
    fn unknown_unsupported_and_negative_evidence_remain_closed_in_every_domain() {
        for prerequisite in DeploymentPrerequisite::ALL {
            for (finding, expected) in [
                (FixtureFinding::Unknown, EvidenceStatus::Unknown),
                (
                    FixtureFinding::Unsupported,
                    EvidenceStatus::UnsupportedObservation,
                ),
                (
                    FixtureFinding::BoundaryViolated,
                    EvidenceStatus::BoundaryViolated,
                ),
            ] {
                let (model, _) = fixture();
                let mut receipt = model.fixture_receipt(prerequisite);
                receipt.finding = finding;
                assert_eq!(model.record(&model.bindings, receipt).unwrap(), expected);
                assert_eq!(status(&model, prerequisite), expected);
            }
        }
    }

    #[test]
    fn identical_receipts_are_idempotent_but_conflicting_receipts_latch_denial() {
        for prerequisite in DeploymentPrerequisite::ALL {
            let (model, clock) = fixture();
            let receipt = model.fixture_receipt(prerequisite);
            assert_eq!(
                model.record(&model.bindings, receipt.clone()).unwrap(),
                EvidenceStatus::SimulatedConsistent
            );
            assert_eq!(
                model.record(&model.bindings, receipt.clone()).unwrap(),
                EvidenceStatus::SimulatedConsistent
            );
            let mut conflict = receipt.clone();
            conflict.finding = FixtureFinding::BoundaryViolated;
            assert_eq!(
                model.record(&model.bindings, conflict).unwrap(),
                EvidenceStatus::Contradictory
            );
            assert_eq!(
                model.record(&model.bindings, receipt).unwrap(),
                EvidenceStatus::Contradictory
            );
            clock.advance(MAX_EVIDENCE_AGE);
            assert_eq!(status(&model, prerequisite), EvidenceStatus::Contradictory);
        }
    }

    #[test]
    fn a_newer_receipt_cannot_silently_refresh_an_old_observation() {
        let (model, clock) = fixture();
        let prerequisite = DeploymentPrerequisite::DurableAuditAndRevocation;
        model
            .record(&model.bindings, model.fixture_receipt(prerequisite))
            .unwrap();
        clock.advance(1);
        assert_eq!(
            model
                .record(&model.bindings, model.fixture_receipt(prerequisite))
                .unwrap(),
            EvidenceStatus::Contradictory
        );
    }

    #[test]
    fn age_is_checked_on_inspection_and_duplicate_without_extending_deadline() {
        let (model, clock) = fixture();
        model.fill_fixture().unwrap();
        let receipt = model.fixture_receipt(DeploymentPrerequisite::DistinctServiceIdentities);
        clock.advance(MAX_EVIDENCE_AGE - 1);
        assert_all(&model, EvidenceStatus::SimulatedConsistent);
        assert_eq!(
            model.record(&model.bindings, receipt.clone()).unwrap(),
            EvidenceStatus::SimulatedConsistent
        );
        clock.advance(1);
        assert_all(&model, EvidenceStatus::Stale);
        assert_eq!(
            model.record(&model.bindings, receipt).unwrap(),
            EvidenceStatus::Stale
        );
    }

    #[test]
    fn invalid_future_pre_instance_stale_and_overflow_times_are_rejected() {
        for (start, observed, expected) in [
            (10, 11, EvidenceStatus::InvalidTime),
            (10, 9, EvidenceStatus::InvalidTime),
            (u64::MAX - 10, u64::MAX - 10, EvidenceStatus::InvalidTime),
        ] {
            let clock = Arc::new(ManualClock::default());
            clock.set(start);
            let model = Preflight::fixture(clock).unwrap();
            let prerequisite = DeploymentPrerequisite::ExternalAnchorAndConcurrentWakeFencing;
            let mut receipt = model.fixture_receipt(prerequisite);
            receipt.observed_at = observed;
            assert_eq!(model.record(&model.bindings, receipt).unwrap(), expected);
            assert_eq!(status(&model, prerequisite), expected);
        }
        let (model, clock) = fixture();
        let prerequisite = DeploymentPrerequisite::ExternalAnchorAndConcurrentWakeFencing;
        let receipt = model.fixture_receipt(prerequisite);
        clock.advance(MAX_EVIDENCE_AGE);
        assert_eq!(
            model.record(&model.bindings, receipt).unwrap(),
            EvidenceStatus::Stale
        );
    }

    #[test]
    fn clock_regression_is_terminal_even_after_time_recovers() {
        let (model, clock) = fixture();
        model.fill_fixture().unwrap();
        clock.set(10);
        assert_all(&model, EvidenceStatus::SimulatedConsistent);
        clock.set(9);
        assert_all(&model, EvidenceStatus::ClockInvalid);
        clock.set(20);
        model.fill_fixture().unwrap();
        assert_all(&model, EvidenceStatus::ClockInvalid);
    }

    fn binding_changes() -> Vec<DeploymentBindings> {
        let base = DeploymentBindings::fixture();
        let mut changes = Vec::new();
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut binding = base.clone();
                binding.$field = $value;
                changes.push(binding);
            }};
        }
        changed!(artifact_digest, [50; 32]);
        changed!(dependencies_digest, [50; 32]);
        changed!(configuration_digest, [50; 32]);
        changed!(host_identity, [50; 32]);
        changed!(boot_epoch, [50; 16]);
        changed!(host_policy_revision, 2);
        changed!(agent_tools_digest, [50; 32]);
        changed!(acl_revision, 2);
        changed!(recipient_generation, 2);
        changed!(recovery_generation, 2);
        changed!(anchor_generation, 2);
        changed!(endpoint_digest, [50; 32]);
        for role in 0..7 {
            for dimension in 0..5 {
                let mut binding = base.clone();
                let identity = match role {
                    0 => &mut binding.agent,
                    1 => &mut binding.broker,
                    2 => &mut binding.recipient,
                    3 => &mut binding.operator,
                    4 => &mut binding.reviewer,
                    5 => &mut binding.recovery,
                    _ => &mut binding.anchor,
                };
                match dimension {
                    0 => identity.principal_digest = [50; 32],
                    1 => identity.enrollment_revision += 1,
                    2 => identity.verification_key_digest = [50; 32],
                    3 => identity.security_domain = [50; 32],
                    _ => identity.uid += 10,
                }
                changes.push(binding);
            }
        }
        changes
    }

    #[test]
    fn every_artifact_host_identity_and_policy_binding_invalidates_evidence() {
        for changed in binding_changes() {
            let (model, _) = fixture();
            model.fill_fixture().unwrap();
            let report = model.inspect(&changed).unwrap();
            assert!(report
                .prerequisites
                .iter()
                .all(|item| item.status == EvidenceStatus::BindingChanged));
            assert_all(&model, EvidenceStatus::BindingChanged);
        }
    }

    #[test]
    fn receipt_bindings_cannot_substitute_other_versions() {
        for changed in binding_changes() {
            let (model, _) = fixture();
            let prerequisite = DeploymentPrerequisite::ImmutableApplicationConfigurationDeployment;
            let mut receipt = model.fixture_receipt(prerequisite);
            receipt.bindings = changed;
            assert_eq!(
                model.record(&model.bindings, receipt).unwrap(),
                EvidenceStatus::BindingChanged
            );
            assert_eq!(status(&model, prerequisite), EvidenceStatus::BindingChanged);
        }
    }

    #[test]
    fn wrong_instance_or_observer_is_rejected_without_repair() {
        for dimension in 0..6 {
            let (model, _) = fixture();
            let prerequisite = DeploymentPrerequisite::IndependentlyAuthenticatedHuman;
            let mut receipt = model.fixture_receipt(prerequisite);
            match dimension {
                0 => receipt.instance[0] ^= 1,
                1 => receipt.observer.principal_digest = [50; 32],
                2 => receipt.observer.enrollment_revision += 1,
                3 => receipt.observer.verification_key_digest = [50; 32],
                4 => receipt.observer.security_domain = [50; 32],
                _ => receipt.observer.uid += 1,
            }
            let expected = if dimension == 0 {
                EvidenceStatus::WrongInstance
            } else {
                EvidenceStatus::ObserverMismatch
            };
            assert_eq!(model.record(&model.bindings, receipt).unwrap(), expected);
            assert_eq!(
                model
                    .record(&model.bindings, model.fixture_receipt(prerequisite))
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn a_new_instance_restores_no_evidence() {
        let (old, _) = fixture();
        old.fill_fixture().unwrap();
        let (new, _) = fixture();
        assert_all(&new, EvidenceStatus::Missing);
        let prerequisite = DeploymentPrerequisite::ProtectedLogsBackupsRecovery;
        assert_eq!(
            new.record(&new.bindings, old.fixture_receipt(prerequisite))
                .unwrap(),
            EvidenceStatus::WrongInstance
        );
    }

    #[test]
    fn concurrent_conflicting_receipts_cannot_leave_a_positive_status() {
        let (model, _) = fixture();
        let model = Arc::new(model);
        let prerequisite = DeploymentPrerequisite::AgentFileProcessDebugDenial;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            for finding in [
                FixtureFinding::BoundaryHeld,
                FixtureFinding::BoundaryViolated,
            ] {
                let model = model.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let mut receipt = model.fixture_receipt(prerequisite);
                    receipt.finding = finding;
                    barrier.wait();
                    model.record(&model.bindings, receipt).unwrap();
                });
            }
        });
        assert_eq!(status(&model, prerequisite), EvidenceStatus::Contradictory);
    }

    #[test]
    fn poisoned_state_cannot_produce_an_inspection_or_accept_evidence() {
        let (model, _) = fixture();
        let model = Arc::new(model);
        let worker = model.clone();
        let _ = std::thread::spawn(move || {
            let _guard = worker.state.lock().unwrap();
            panic!("synthetic poison");
        })
        .join();
        assert_eq!(
            model.inspect(&model.bindings),
            Err(ErrorCode::BrokerUnavailable)
        );
        assert_eq!(
            model.record(
                &model.bindings,
                model.fixture_receipt(DeploymentPrerequisite::DurableAuditAndRevocation)
            ),
            Err(ErrorCode::BrokerUnavailable)
        );
    }

    #[test]
    fn public_drill_and_serialized_reports_are_closed_non_authoritative_metadata() {
        let report = run_synthetic_deployment_preflight_drill().unwrap();
        assert_eq!(
            report.complete_simulation.decision,
            DeploymentDecision::NoGo
        );
        assert_eq!(report.missing, EvidenceStatus::Missing);
        assert_eq!(report.unknown, EvidenceStatus::Unknown);
        assert_eq!(report.same_uid, EvidenceStatus::IdentitySeparationInvalid);
        assert_eq!(report.contradictory, EvidenceStatus::Contradictory);
        assert_eq!(report.stale, EvidenceStatus::Stale);
        assert_eq!(report.changed_binding, EvidenceStatus::BindingChanged);
        assert_eq!(report.regressed_clock, EvidenceStatus::ClockInvalid);
        assert_eq!(report.production_entry, ErrorCode::UnsupportedDeployment);
        let json = serde_json::to_value(&report).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(object.len(), 9);
        let complete = object["complete_simulation"].as_object().unwrap();
        assert_eq!(complete.len(), 4);
        assert_eq!(complete["decision"], "no_go");
        assert_eq!(complete["origin"], "simulated_attestations");
        let prerequisites = complete["prerequisites"].as_array().unwrap();
        assert_eq!(prerequisites.len(), PREREQUISITE_COUNT);
        for prerequisite in prerequisites {
            let object = prerequisite.as_object().unwrap();
            assert_eq!(object.len(), 2);
            assert!(object["prerequisite"].is_string());
            assert_eq!(object["status"], "simulated_consistent");
        }
        assert_eq!(complete["gaps"].as_array().unwrap().len(), GAPS.len());
        assert_eq!(
            deployment_prerequisites().decision,
            DeploymentDecision::NoGo
        );
        assert_eq!(
            super::super::require_live_deployment(),
            Err(ErrorCode::UnsupportedDeployment)
        );
    }
}
