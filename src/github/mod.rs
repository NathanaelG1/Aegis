//! Synthetic GitHub App adapter with a fixed reviewed main-broker integration.
//!
//! No key input, live HTTP, Git subprocess, or deployment capability exists.
//! An opt-in composition signs with disposable unregistered keys; defaults use mock JWTs.
//! All token-bearing types and extension points are private. See `docs/github-app.md`.
//!
//! ```compile_fail
//! // Token-bearing implementation types are not an embedding or agent API.
//! use aegis::github::runtime::Token;
//! ```
#[cfg(unix)]
mod journal;
mod model;
mod runtime;
#[cfg(all(unix, test))]
pub(crate) use journal::Fault as JournalFault;
#[cfg(unix)]
pub(crate) use runtime::BrokerAdapter;
#[cfg(all(unix, test))]
pub(crate) use runtime::BrokerPause;

use serde::{Deserialize, Serialize};

/// Closed, non-sensitive error categories; never provider bodies or native exceptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubError {
    InvalidBinding,
    ScopeDenied,
    ApprovalExpired,
    BindingChanged,
    RequestConflict,
    CapacityExceeded,
    InProgress,
    Revoked,
    ClockInvalid,
    SignerUnavailable,
    ProviderRejected,
    InvalidProviderResult,
    OutcomeUnknown,
    ReconciliationRequired,
    Unavailable,
    PersistenceUnavailable,
}
impl std::fmt::Display for GithubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for GithubError {}

/// Reviewed metadata projection: no provider strings, URLs, names, headers or credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryProjection {
    pub repository_id: u64,
    pub private: bool,
    pub archived: bool,
}

/// Provider revocation and local future-use denial are distinct facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    NoKnownToken,
    ProviderConfirmed,
    OutcomeUnknown,
    InProgress,
    UnresolvedExchange,
}

/// No caller-supplied platform label or approval boolean can enable live use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiveReadiness {
    pub available: bool,
    pub missing: [ReadinessGate; 6],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessGate {
    ProtectedKeyCustody,
    IndependentHumanApproval,
    VerifiedOsIsolation,
    DurableIntentAndRecovery,
    ReviewedLiveTransportAndSigning,
    ReviewedLiveBrokerComposition,
}
/// Reports closed live-use gates on every OS. This is not an OS verifier.
pub fn live_readiness() -> LiveReadiness {
    LiveReadiness {
        available: false,
        missing: [
            ReadinessGate::ProtectedKeyCustody,
            ReadinessGate::IndependentHumanApproval,
            ReadinessGate::VerifiedOsIsolation,
            ReadinessGate::DurableIntentAndRecovery,
            ReadinessGate::ReviewedLiveTransportAndSigning,
            ReadinessGate::ReviewedLiveBrokerComposition,
        ],
    }
}

/// Safe evidence from the fixed mock exercise, not a live-provider/security attestation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyntheticReport {
    pub synthetic_only: bool,
    pub metadata: RepositoryProjection,
    pub duplicate_reused: bool,
    pub exchanges: usize,
    pub metadata_requests: usize,
    pub provider_revocation: RevocationStatus,
    pub later_request_denied: bool,
    pub live_available: bool,
}

/// Runs only built-in public synthetic fixtures. Accepts no credentials or configuration.
pub fn run_synthetic_demo() -> Result<SyntheticReport, GithubError> {
    runtime::demo()
}

/// Static failures from the synthetic-only journal; no native path/parser text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalError {
    Incomplete,
    InvalidPath,
    DestinationExists,
    UnsafeFile,
    Busy,
    Io,
    InvalidJournal,
    UnsupportedSchema,
    CapacityExceeded,
    Unavailable,
    UnsupportedPlatform,
}
impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for JournalError {}
/// Inspection-only recovery evidence. Never contains credentials or restored authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalRecovery {
    pub synthetic_only: bool,
    pub reservations_consumed: usize,
    pub incomplete_operations: usize,
    pub unknown_operations: usize,
    pub uncertain_mints: usize,
    pub unresolved_tokens: usize,
    pub uncertain_revocations: usize,
    pub local_authority_revoked: bool,
    pub restored_grants: usize,
    pub restored_sessions: usize,
    pub automatic_retry_allowed: bool,
    pub reconciliation_required: bool,
}
/// Create only a fixed synthetic operation/revocation drill in a NEW directory.
/// No credentials are accepted. Existing directories can never resume execution.
pub fn create_synthetic_intent_drill(path: &std::path::Path) -> Result<(), JournalError> {
    #[cfg(unix)]
    {
        runtime::journal_demo(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(JournalError::UnsupportedPlatform)
    }
}
/// Read a closed synthetic journal without starting a provider, session, grant or writer.
pub fn inspect_synthetic_intents(path: &std::path::Path) -> Result<JournalRecovery, JournalError> {
    #[cfg(unix)]
    {
        journal::inspect(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(JournalError::UnsupportedPlatform)
    }
}
