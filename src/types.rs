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
