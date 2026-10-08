//! Versioned agent-visible contracts. Unknown fields and invalid identifiers fail closed.
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ErrorCode> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > 64
                    || !value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                {
                    return Err(ErrorCode::InvalidRequest);
                }
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = ErrorCode;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}
identifier!(ProfileId);
identifier!(RequestId);
identifier!(PrincipalId);

/// Stable non-sensitive errors: no native/provider exception text crosses this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    ScopeDenied,
    ApprovalRequired,
    InteractionRequired,
    RequestExpired,
    PrincipalMismatch,
    BudgetExhausted,
    RequestIdConflict,
    PolicyChanged,
    GrantRevoked,
    SessionExpired,
    CapacityExceeded,
    RequestCanceled,
    NotFound,
    ProviderUnavailable,
    InvalidProviderResult,
    OutcomeUnknown,
    BrokerUnavailable,
    UnsupportedVersion,
    PersistenceUnavailable,
    ReconciliationRequired,
    AuthenticationRequired,
    UnsupportedDeployment,
}
impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This enum contains no caller-controlled text.
        match serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
        {
            Some(s) => f.write_str(&s),
            None => f.write_str("broker_unavailable"),
        }
    }
}
impl std::error::Error for ErrorCode {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub repository_id: u64,
    pub issue_number: u32,
}
impl Parameters {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        if self.repository_id == 0 || self.issue_number == 0 {
            Err(ErrorCode::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareInput {
    pub request_id: RequestId,
    pub profile_id: ProfileId,
    pub parameters: Parameters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Prepared,
    AwaitingApproval,
    Approved,
    Reserved,
    Dispatched,
    Succeeded,
    Failed,
    OutcomeUnknown,
    Canceled,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueState {
    Open,
    Closed,
}

/// Reviewed result contract: two numeric identifiers and a closed enumeration only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusProjection {
    pub repository_id: u64,
    pub issue_number: u32,
    pub state: IssueState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunView {
    pub prepared_request_id: u64,
    pub state: Lifecycle,
    pub result: Option<StatusProjection>,
    pub error: Option<ErrorCode>,
}

/// Returned only to the trusted control capability; generated from resolved broker policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalView {
    pub(crate) broker_instance: [u8; 16],
    pub prepared_request_id: u64,
    pub principal: PrincipalId,
    pub session: u64,
    pub profile: Profile,
    pub parameters: Parameters,
    pub policy_generation: u64,
    pub expires_at: u64,
    pub remaining_uses: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialBinding {
    pub secret_id: String,
    pub version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub id: ProfileId,
    pub revision: u64,
    pub repository_id: u64,
    pub credential: CredentialBinding,
    pub adapter_contract: u32,
    pub output_contract: u32,
}
impl Profile {
    pub fn synthetic() -> Self {
        Self {
            id: ProfileId::new("issue-status").expect("constant"),
            revision: 1,
            repository_id: 4242,
            credential: CredentialBinding {
                secret_id: "synthetic-fixture".into(),
                version: 1,
            },
            adapter_contract: 1,
            output_contract: 1,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ErrorCode> {
        if self.revision == 0
            || self.repository_id == 0
            || self.credential.secret_id != "synthetic-fixture"
            || self.credential.version == 0
            || self.adapter_contract != 1
            || self.output_contract != 1
        {
            Err(ErrorCode::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub verified: bool,
    pub profile_id: ProfileId,
    pub operation: String,
    pub input_contract: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalMode {
    EachRequest,
    BoundedSession,
}

/// Non-secret fixed GitHub enrollment shown by the trusted review channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubProfile {
    pub id: ProfileId,
    pub revision: u64,
    pub app_id: u64,
    pub client_id: String,
    pub installation_id: u64,
    pub account_id: u64,
    pub account_login: String,
    pub repository_id: u64,
    pub repository_name: String,
    pub credential: CredentialBinding,
    pub installation_contents: GithubPermission,
    pub installation_metadata: GithubPermission,
    pub requested_metadata: GithubPermission,
    pub adapter_contract: u32,
    pub output_contract: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubPermission {
    Read,
    Write,
}
impl GithubProfile {
    pub fn synthetic() -> Self {
        Self {
            id: ProfileId::new("github-metadata").expect("constant"),
            revision: 1,
            app_id: 101,
            client_id: "Iv1_SYNTHETIC_ONLY".into(),
            installation_id: 202,
            account_id: 303,
            account_login: "NathanaelG1".into(),
            repository_id: 4242,
            repository_name: "Aegis".into(),
            credential: CredentialBinding {
                secret_id: "synthetic-github-key".into(),
                version: 1,
            },
            installation_contents: GithubPermission::Write,
            installation_metadata: GithubPermission::Read,
            requested_metadata: GithubPermission::Read,
            adapter_contract: 1,
            output_contract: 1,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ErrorCode> {
        let mut expected = Self::synthetic();
        expected.revision = self.revision;
        expected.credential.version = self.credential.version;
        if *self != expected || self.revision == 0 || self.credential.version == 0 {
            Err(ErrorCode::InvalidRequest)
        } else {
            Ok(())
        }
    }
}
/// Versioned operation kinds cannot borrow another operation's profile or result shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationProfile {
    IssueStatus(Profile),
    GithubMetadata(GithubProfile),
    #[cfg(all(unix, feature = "vault-spike"))]
    Delivery(crate::vault::DeliveryProfile),
}
impl OperationProfile {
    pub(crate) fn validate(&self) -> Result<(), ErrorCode> {
        match self {
            Self::IssueStatus(p) => p.validate(),
            Self::GithubMetadata(p) => p.validate(),
            #[cfg(all(unix, feature = "vault-spike"))]
            Self::Delivery(p) => p.validate(),
        }
    }
    pub(crate) fn id(&self) -> &ProfileId {
        match self {
            Self::IssueStatus(p) => &p.id,
            Self::GithubMetadata(p) => &p.id,
            #[cfg(all(unix, feature = "vault-spike"))]
            Self::Delivery(p) => &p.id,
        }
    }
    pub(crate) fn repository_id(&self) -> u64 {
        match self {
            Self::IssueStatus(p) => p.repository_id,
            Self::GithubMetadata(p) => p.repository_id,
            #[cfg(all(unix, feature = "vault-spike"))]
            Self::Delivery(p) => p.repository_id,
        }
    }
    pub(crate) fn permits(&self, operation: &OperationIntent) -> bool {
        match (self, operation) {
            (Self::IssueStatus(_), OperationIntent::IssueStatus(parameters)) => {
                parameters.repository_id == self.repository_id()
            }
            (Self::GithubMetadata(_), OperationIntent::GithubMetadata(parameters)) => {
                parameters.repository_id == self.repository_id()
            }
            #[cfg(all(unix, feature = "vault-spike"))]
            (Self::Delivery(profile), OperationIntent::Delivery(parameters)) => {
                profile.permits(parameters)
            }
            _ => false,
        }
    }
    pub(crate) fn durable(&self) -> bool {
        !matches!(self, Self::IssueStatus(_))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubMetadataParameters {
    pub repository_id: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "parameters", deny_unknown_fields)]
pub enum OperationIntent {
    #[serde(rename = "synthetic.issue-status.v1")]
    IssueStatus(Parameters),
    #[serde(rename = "synthetic.github.repository-metadata.v1")]
    GithubMetadata(GithubMetadataParameters),
    #[cfg(all(unix, feature = "vault-spike"))]
    #[serde(rename = "synthetic.vault.deliver.v1")]
    Delivery(crate::vault::DeliveryParameters),
}
impl OperationIntent {
    pub(crate) fn validate(&self) -> Result<(), ErrorCode> {
        match self {
            Self::IssueStatus(parameters) => parameters.validate(),
            Self::GithubMetadata(parameters) if parameters.repository_id > 0 => Ok(()),
            #[cfg(all(unix, feature = "vault-spike"))]
            Self::Delivery(parameters) => parameters.validate(),
            _ => Err(ErrorCode::InvalidRequest),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPrepareInput {
    pub request_id: RequestId,
    pub profile_id: ProfileId,
    pub operation: OperationIntent,
}
impl From<PrepareInput> for OperationPrepareInput {
    fn from(input: PrepareInput) -> Self {
        Self {
            request_id: input.request_id,
            profile_id: input.profile_id,
            operation: OperationIntent::IssueStatus(input.parameters),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub enum OperationResult {
    #[serde(rename = "synthetic.issue-status.v1")]
    IssueStatus(StatusProjection),
    #[serde(rename = "synthetic.github.repository-metadata.v1")]
    GithubMetadata(crate::github::RepositoryProjection),
    #[cfg(all(unix, feature = "vault-spike"))]
    #[serde(rename = "synthetic.vault.deliver.v1")]
    Delivery(crate::vault::DeliveryProjection),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRunView {
    pub prepared_request_id: u64,
    pub state: Lifecycle,
    pub result: Option<OperationResult>,
    pub error: Option<ErrorCode>,
}
impl OperationRunView {
    pub(crate) fn into_legacy(self) -> Result<RunView, ErrorCode> {
        let result = match self.result {
            None => None,
            Some(OperationResult::IssueStatus(result)) => Some(result),
            Some(_) => return Err(ErrorCode::ScopeDenied),
        };
        Ok(RunView {
            prepared_request_id: self.prepared_request_id,
            state: self.state,
            result,
            error: self.error,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationLimits {
    pub initial_uses: u32,
    pub idle_seconds: u64,
    pub maximum_seconds: u64,
    pub request_seconds: u64,
    pub maximum_requests: usize,
    pub maximum_concurrent: usize,
}
/// Trusted review data only; never an agent-supplied approval capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationApprovalView {
    pub(crate) broker_instance: [u8; 16],
    pub prepared_request_id: u64,
    pub request_id: RequestId,
    pub limits: OperationLimits,
    pub principal: PrincipalId,
    pub session: u64,
    pub profile: OperationProfile,
    pub operation: OperationIntent,
    pub policy_generation: u64,
    pub expires_at: u64,
    pub remaining_uses: u32,
}
impl OperationApprovalView {
    pub(crate) fn into_legacy(self) -> Result<ApprovalView, ErrorCode> {
        let (profile, parameters) = match (self.profile, self.operation) {
            (OperationProfile::IssueStatus(profile), OperationIntent::IssueStatus(parameters)) => {
                (profile, parameters)
            }
            _ => return Err(ErrorCode::ScopeDenied),
        };
        Ok(ApprovalView {
            broker_instance: self.broker_instance,
            prepared_request_id: self.prepared_request_id,
            principal: self.principal,
            session: self.session,
            profile,
            parameters,
            policy_generation: self.policy_generation,
            expires_at: self.expires_at,
            remaining_uses: self.remaining_uses,
        })
    }
}
impl OperationApprovalView {
    pub(crate) fn from_legacy(
        view: &ApprovalView,
        request_id: RequestId,
        limits: OperationLimits,
    ) -> Self {
        Self {
            broker_instance: view.broker_instance,
            request_id,
            limits,
            prepared_request_id: view.prepared_request_id,
            principal: view.principal.clone(),
            session: view.session,
            profile: OperationProfile::IssueStatus(view.profile.clone()),
            operation: OperationIntent::IssueStatus(view.parameters.clone()),
            policy_generation: view.policy_generation,
            expires_at: view.expires_at,
            remaining_uses: view.remaining_uses,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationDiscovery {
    pub verified: bool,
    pub profile_id: ProfileId,
    pub operation: String,
    pub protocol_version: u32,
}
