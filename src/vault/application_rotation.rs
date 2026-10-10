//! Two independently reviewed, encrypted dummy imports installed through fresh
//! authenticated broker phases into the same fixed canary application file.
//!
//! This is a closed fixture, not a persistent rotation service. It has no value,
//! version, recipient, endpoint, fault, custody or deployment configuration API.
use super::{application_slot, process_service};
use crate::ErrorCode;
use serde::Serialize;
use std::path::Path;

/// Observations from two fixed imports and two separately approved deliveries.
/// Duplicate outcomes are reused within each live broker phase; cold starts
/// restore durable evidence only and require fresh authentication and approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationRotationReport {
    #[serde(flatten)]
    pub installation: application_slot::ApplicationSlotReport,
    pub imported_versions: [u64; 2],
    pub completed_installation_generations: [u64; 2],
    pub exact_import_ciphertexts_verified: bool,
    pub distinct_import_bindings_verified: bool,
    pub exact_approvals_verified: bool,
    pub retained_duplicate_outcomes: usize,
    pub old_version_rollback_prevented: bool,
    pub delivery_broker_phases: usize,
    pub fresh_authentication_between_versions: bool,
}

/// Read-only verification of both original imports and the retained histories.
/// A completed first install may coexist with an uncertain second delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationRotationRecoveryReport {
    #[serde(flatten)]
    pub installation: application_slot::ApplicationSlotRecoveryReport,
    pub imported_versions: [u64; 2],
    pub exact_import_ciphertexts_verified: bool,
    pub distinct_import_bindings_verified: bool,
}

/// Run only the compiled canary pair in a NEW absolute directory. The executable
/// must dispatch `process_service::synthetic_child_entry` before normal parsing.
pub fn run_synthetic_application_rotation_drill(
    root: &Path,
) -> Result<ApplicationRotationReport, ErrorCode> {
    let service = process_service::run_rotation(root)?;
    let inspected = inspect_synthetic_application_rotation(root)?;
    if inspected.installation.completed_installations != 2
        || inspected.installation.installed_version != 2
        || inspected.installation.incomplete_installations != 0
        || !inspected.installation.installation_receipt_verified
    {
        return Err(ErrorCode::ReconciliationRequired);
    }
    Ok(ApplicationRotationReport {
        installation: application_slot::report_from_service(service, inspected.installation),
        imported_versions: [1, 2],
        completed_installation_generations: [1, 2],
        exact_import_ciphertexts_verified: inspected.exact_import_ciphertexts_verified,
        distinct_import_bindings_verified: inspected.distinct_import_bindings_verified,
        exact_approvals_verified: true,
        retained_duplicate_outcomes: 2,
        old_version_rollback_prevented: true,
        delivery_broker_phases: 2,
        fresh_authentication_between_versions: true,
    })
}

/// Inspect only. Never completes an intent, restores a session, or redispatches.
pub fn inspect_synthetic_application_rotation(
    root: &Path,
) -> Result<ApplicationRotationRecoveryReport, ErrorCode> {
    let observation = process_service::inspect_rotation(root)?;
    Ok(ApplicationRotationRecoveryReport {
        installation: application_slot::recovery_from_observation(observation)?,
        imported_versions: [1, 2],
        exact_import_ciphertexts_verified: true,
        distinct_import_bindings_verified: true,
    })
}
