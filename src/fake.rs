//! Reviewed synthetic adapter. No networking, arbitrary routes, or real credential input.
use crate::types::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const SYNTHETIC_CANARY: &str = "AEGIS_SYNTHETIC_ONLY_CANARY_7e3f6a";
pub struct Dispatch {
    pub profile: Profile,
    pub parameters: Parameters,
}
/// Trusted adapter output is deliberately not Debug or Serialize.
pub struct RawStatus {
    pub repository_id: u64,
    pub issue_number: u32,
    pub state: String,
}
pub enum ProviderOutcome {
    Status(RawStatus),
    Unavailable,
    Unknown,
}
pub trait Executor: Send + Sync {
    fn execute(&self, dispatch: &Dispatch) -> ProviderOutcome;
}

/// Secret material has no Debug, Clone, Serialize, or agent-facing accessor.
struct Credential(&'static [u8]);
trait CredentialSource {
    fn resolve(&self, binding: &CredentialBinding) -> Option<Credential>;
}
struct SyntheticSource;
impl CredentialSource for SyntheticSource {
    fn resolve(&self, binding: &CredentialBinding) -> Option<Credential> {
        (binding.secret_id == "synthetic-fixture" && binding.version == 1)
            .then_some(Credential(SYNTHETIC_CANARY.as_bytes()))
    }
}

#[derive(Default)]
pub struct FakeProvider {
    calls: AtomicUsize,
}
impl FakeProvider {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl Executor for FakeProvider {
    fn execute(&self, dispatch: &Dispatch) -> ProviderOutcome {
        let Some(credential) = SyntheticSource.resolve(&dispatch.profile.credential) else {
            return ProviderOutcome::Unavailable;
        };
        if credential.0 != SYNTHETIC_CANARY.as_bytes()
            || dispatch.profile.adapter_contract != 1
            || dispatch.profile.output_contract != 1
        {
            return ProviderOutcome::Unavailable;
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        ProviderOutcome::Status(RawStatus {
            repository_id: dispatch.parameters.repository_id,
            issue_number: dispatch.parameters.issue_number,
            state: if dispatch.parameters.issue_number.is_multiple_of(2) {
                "closed"
            } else {
                "open"
            }
            .into(),
        })
    }
}
