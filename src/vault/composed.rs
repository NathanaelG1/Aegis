//! One fixed-canary import, authenticated TLS approval and separate recipient.
//!
//! Both TLS peers and simulated human signing remain trusted-process fixtures.
//! The recipient uses inherited socketpair IPC, signed age capsules and receipts;
//! it is a separate same-UID process, not an isolated or TLS-speaking recipient.
//! No arbitrary input, executable, route, keys or readiness flags are accepted.
//!
//! ```compile_fail
//! aegis::vault::composed::run_synthetic_composed_drill(
//!     std::path::Path::new("/tmp/example"), b"credential");
//! ```
use super::{
    custody::BrokerRole,
    entry::protected_entry,
    process_recipient::{self, ProcessRecipient},
    protocol::SyntheticProtocol,
    store::{self, Store},
    tls,
};
use crate::{ErrorCode, Lifecycle, ManualClock};
use serde::Serialize;
use std::{path::Path, sync::Arc};

/// Closed observations from one disposable composed workflow.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComposedCanaryReport {
    pub synthetic_only: bool,
    pub input_import_bound: bool,
    pub authenticated_role_channels: usize,
    pub tls13_mutual_authentication_verified: bool,
    pub separate_recipient_process: bool,
    pub bootstrap_in_child: bool,
    pub broker_loaded_recipient_private_keys: bool,
    pub unauthenticated_agent_denied: bool,
    pub unauthenticated_admin_denied: bool,
    pub completed_deliveries: usize,
    pub duplicate_reused: bool,
    pub cold_start_required_authentication: bool,
    pub consumed_uses: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub revoked: bool,
    pub revocation_survived_restart: bool,
    pub agent_transcript_contains_canary: bool,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub workflow_mode: &'static str,
    pub independent_human_presence_verified: bool,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Existing evidence only. Inspection never constructs a protocol or restores
/// approval, sessions, a grant, or permission to retry an incomplete delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComposedRecoveryReport {
    pub synthetic_only: bool,
    pub input_import_bound: bool,
    pub consumed_uses: usize,
    pub incomplete_deliveries: usize,
    pub unknown_deliveries: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub revoked: bool,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub workflow_mode: &'static str,
    pub protected_custody_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Create a new absolute root containing only disposable fixture state. The
/// embedding executable must dispatch `process_recipient::synthetic_child_entry`
/// first. Its current executable is the only possible recipient program.
pub fn run_synthetic_composed_drill(root: &Path) -> Result<ComposedCanaryReport, ErrorCode> {
    protected_entry::validate_destination(root)?;
    store::new_directory(root)?;
    let custody = root.join("custody");
    let input = root.join("input");
    let vault = root.join("vault");
    let state = root.join("recipient");
    process_recipient::bootstrap_in_child(&custody)?;
    let broker = BrokerRole::open(&custody.join("broker"))?;
    let vault_id = broker.material.vault_id.clone();
    let imported = protected_entry::import_delivery_canary(&input, &broker.material)?;
    let store = Store::create_imported(&vault, broker.material.clone(), imported)?;
    store.check_imported_record(&input)?;
    let recipient =
        ProcessRecipient::start(broker.material, &custody.join("recipient"), &state, true)?;
    let protocol = SyntheticProtocol::assemble(
        broker.enrollment,
        store,
        recipient,
        1,
        Arc::new(ManualClock::default()),
    )?;
    let round = tls::composed_round(protocol, &custody, &vault_id)?;
    if round.run.state != Lifecycle::Succeeded {
        return Err(ErrorCode::BrokerUnavailable);
    }

    // The first protocol and child have been dropped. Reopen the same records,
    // authenticate fresh sessions over new TLS channels and durably revoke.
    let broker = BrokerRole::open(&custody.join("broker"))?;
    let store = Store::open(&vault, broker.material.clone())?;
    store.check_imported_record(&input)?;
    let recipient =
        ProcessRecipient::start(broker.material, &custody.join("recipient"), &state, false)?;
    let protocol = SyntheticProtocol::assemble(
        broker.enrollment,
        store,
        recipient,
        1,
        Arc::new(ManualClock::default()),
    )?;
    let cold_start_required_authentication =
        tls::composed_revoke_after_restart(protocol, &custody, &vault_id)?;
    let inspected = inspect_synthetic_composed(root)?;

    let broker = BrokerRole::open(&custody.join("broker"))?;
    let store = Store::open(&vault, broker.material.clone())?;
    let recipient =
        ProcessRecipient::start(broker.material, &custody.join("recipient"), &state, false)?;
    let revocation_survived_restart = matches!(
        SyntheticProtocol::assemble(
            broker.enrollment,
            store,
            recipient,
            1,
            Arc::new(ManualClock::default())
        ),
        Err(ErrorCode::GrantRevoked)
    );
    if !(round.duplicate_reused
        && round.unauthenticated_agent_denied
        && round.unauthenticated_admin_denied
        && cold_start_required_authentication
        && revocation_survived_restart
        && !round.agent_transcript_contains_canary
        && inspected.consumed_uses == 1
        && inspected.remaining_uses == 3
        && inspected.recipient_generation == 1
        && inspected.incomplete_deliveries == 0
        && inspected.unknown_deliveries == 0
        && inspected.revoked
        && super::require_live_deployment() == Err(ErrorCode::UnsupportedDeployment))
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(ComposedCanaryReport {
        synthetic_only: true,
        input_import_bound: inspected.input_import_bound,
        authenticated_role_channels: 2,
        tls13_mutual_authentication_verified: true,
        separate_recipient_process: true,
        bootstrap_in_child: true,
        broker_loaded_recipient_private_keys: false,
        unauthenticated_agent_denied: round.unauthenticated_agent_denied,
        unauthenticated_admin_denied: round.unauthenticated_admin_denied,
        completed_deliveries: 1,
        duplicate_reused: round.duplicate_reused,
        cold_start_required_authentication,
        consumed_uses: inspected.consumed_uses,
        remaining_uses: inspected.remaining_uses,
        recipient_generation: inspected.recipient_generation,
        revoked: inspected.revoked,
        revocation_survived_restart,
        agent_transcript_contains_canary: round.agent_transcript_contains_canary,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        independent_human_presence_verified: false,
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

/// Read fixed existing evidence without appending records. A fresh recipient
/// child verifies its own journal and returns a nonce-bound signed status. The
/// broker never loads that child's private role or plaintext slot.
pub fn inspect_synthetic_composed(root: &Path) -> Result<ComposedRecoveryReport, ErrorCode> {
    protected_entry::validate_destination(root)?;
    store::safe_directory(root)?;
    let custody = root.join("custody");
    let broker = BrokerRole::open(&custody.join("broker"))?;
    let store = Store::open(&root.join("vault"), broker.material.clone())?;
    store.check_imported_record(&root.join("input"))?;
    let recipient = ProcessRecipient::start(
        broker.material,
        &custody.join("recipient"),
        &root.join("recipient"),
        false,
    )?;
    let snapshot = recipient.snapshot()?;
    store.check_process_receipts(&snapshot.received)?;
    let (consumed, incomplete, unknown, remaining, revoked) = store.history_counts()?;
    Ok(ComposedRecoveryReport {
        synthetic_only: true,
        input_import_bound: true,
        consumed_uses: consumed,
        incomplete_deliveries: incomplete,
        unknown_deliveries: unknown,
        remaining_uses: remaining,
        recipient_generation: snapshot.generation,
        revoked,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        workflow_mode: "UNISOLATED",
        protected_custody_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}

#[cfg(test)]
#[path = "composed_tests.rs"]
mod tests;
