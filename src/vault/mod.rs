//! Optional integrated synthetic vault-to-recipient exercise.
//!
//! All keys and payloads are disposable fixtures. No live key input, deployment
//! attestation, HTTP listener or independently authenticated human presence exists.
//!
//! ```compile_fail
//! use aegis::vault::AuthenticatedSession;
//! ```
//! ```compile_fail
//! use aegis::vault::runtime::Host;
//! ```
//! ```compile_fail
//! use aegis::vault::crypto::PrivateBytes;
//! ```
mod auth;
mod crypto;
pub mod custody;
pub mod deployment;
pub mod entry;
mod model;
pub mod protocol;
pub mod recipient_adapter;
mod runtime;
mod store;
pub mod tls;
pub mod transport;
pub(crate) use auth::AuthenticatedSession;
pub use model::{
    DeliveryParameters, DeliveryProfile, DeliveryProjection, RecipientBinding, SecretReference,
};
pub(crate) use runtime::Adapter;

use crate::{ErrorCode, Lifecycle, ManualClock, OperationResult};
use serde::Serialize;
use std::{path::Path, sync::Arc};

/// Safe observations from a fixed canary workflow, never a deployment attestation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyntheticVaultReport {
    pub synthetic_only: bool,
    pub unauthenticated_agent_denied: bool,
    pub unsigned_approval_denied: bool,
    pub completed_deliveries: usize,
    pub consumed_uses: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub duplicate_reused: bool,
    pub cold_start_required_authentication: bool,
    pub previous_request_id_denied: bool,
    pub revocation_survived_restart: bool,
    pub agent_transcript_contains_canary: bool,
    pub restored_sessions: usize,
    pub independent_human_presence_verified: bool,
    pub protected_deployment_verified: bool,
    pub ready_for_real_keys: bool,
}
/// Strict inspection of fixed synthetic evidence. This restores no authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VaultRecoveryReport {
    pub synthetic_only: bool,
    pub consumed_uses: usize,
    pub incomplete_deliveries: usize,
    pub unknown_deliveries: usize,
    pub remaining_uses: u32,
    pub recipient_generation: u64,
    pub revoked: bool,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub protected_anchor_verified: bool,
    pub ready_for_real_keys: bool,
}
/// No caller-provided boolean, file mode or host label can enable real-key use.
/// The operator-owned isolation, key entry and custody ceremony remains unimplemented.
pub fn require_live_deployment() -> Result<(), ErrorCode> {
    Err(ErrorCode::UnsupportedDeployment)
}

/// Create a NEW synthetic vault, separate dummy key/anchor kit and dummy recipient,
/// deliver version one, cold start with fresh authentication, rotate to version two,
/// then revoke and inspect. Accepts no credential values or live configuration.
pub fn run_synthetic_vault_drill(
    root: &Path,
    kit: &Path,
    recipient: &Path,
) -> Result<SyntheticVaultReport, ErrorCode> {
    let clock = Arc::new(ManualClock::default());
    let host = runtime::Host::create(root, kit, recipient, clock.clone())?;
    let unauthenticated_agent_denied = matches!(
        host.prepare("unauthenticated", 1),
        Err(ErrorCode::AuthenticationRequired)
    );
    host.connect()?;
    let id = host.prepare("install-one", 1)?;
    host.agent.request_operation_approval(id)?;
    let review = host.control.inspect_operation_approval(id)?;
    let unsigned_approval_denied = matches!(
        host.control.approve_operation_reviewed(id, &review),
        Err(ErrorCode::AuthenticationRequired)
    );
    let first = host.reviewed_invoke(id)?;
    if first.state != Lifecycle::Succeeded {
        return Err(ErrorCode::BrokerUnavailable);
    }
    let duplicate_reused = host.agent.invoke_operation(id)? == first;
    let mut transcript = serde_json::to_string(&first).map_err(|_| ErrorCode::BrokerUnavailable)?;
    drop(host);
    let host = runtime::Host::open(root, kit, recipient, 2, clock.clone())?;
    let cold_start_required_authentication = matches!(
        host.prepare("before-auth", 2),
        Err(ErrorCode::AuthenticationRequired)
    );
    host.connect()?;
    let previous_request_id_denied = matches!(
        host.prepare("install-one", 2),
        Err(ErrorCode::RequestIdConflict)
    );
    let id = host.prepare("rotate-two", 2)?;
    let second = host.reviewed_invoke(id)?;
    if second.state != Lifecycle::Succeeded
        || !matches!(second.result, Some(OperationResult::Delivery(_)))
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    transcript.push_str(&serde_json::to_string(&second).map_err(|_| ErrorCode::BrokerUnavailable)?);
    let recipient_generation = host.adapter.recipient.generation()?;
    host.revoke()?;
    drop(host);
    let report = inspect_synthetic_vault(root, kit, recipient)?;
    let revocation_survived_restart = matches!(
        runtime::Host::open(root, kit, recipient, 2, clock),
        Err(ErrorCode::GrantRevoked)
    );
    let agent_transcript_contains_canary =
        transcript.contains(store::CANARY_ONE) || transcript.contains(store::CANARY_TWO);
    if !(unauthenticated_agent_denied
        && unsigned_approval_denied
        && duplicate_reused
        && cold_start_required_authentication
        && previous_request_id_denied
        && revocation_survived_restart
        && !agent_transcript_contains_canary
        && recipient_generation == 2
        && report.consumed_uses == 2
        && report.remaining_uses == 2)
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(SyntheticVaultReport {
        synthetic_only: true,
        unauthenticated_agent_denied,
        unsigned_approval_denied,
        completed_deliveries: 2,
        consumed_uses: report.consumed_uses,
        remaining_uses: report.remaining_uses,
        recipient_generation,
        duplicate_reused,
        cold_start_required_authentication,
        previous_request_id_denied,
        revocation_survived_restart,
        agent_transcript_contains_canary,
        restored_sessions: 0,
        independent_human_presence_verified: false,
        protected_deployment_verified: false,
        ready_for_real_keys: false,
    })
}
/// Inspect existing synthetic fixture paths with their separate dummy kit. It cannot
/// resume a grant, import an arbitrary secret, or export a decrypted record.
pub fn inspect_synthetic_vault(
    root: &Path,
    kit_path: &Path,
    recipient_path: &Path,
) -> Result<VaultRecoveryReport, ErrorCode> {
    let kit = store::Kit::open(kit_path)?;
    let store = store::Store::open(root, kit.broker_material())?;
    let recipient = store::Recipient::open(recipient_path, kit.recipient_material())?;
    store.check_recipient(&recipient)?;
    let (consumed, incomplete, unknown, remaining, revoked) = store.history_counts()?;
    Ok(VaultRecoveryReport {
        synthetic_only: true,
        consumed_uses: consumed,
        incomplete_deliveries: incomplete,
        unknown_deliveries: unknown,
        remaining_uses: remaining,
        recipient_generation: recipient.generation()?,
        revoked,
        restored_sessions: 0,
        automatic_retry_allowed: false,
        protected_anchor_verified: false,
        ready_for_real_keys: false,
    })
}

#[cfg(test)]
mod tests;
