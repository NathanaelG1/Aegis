//! Experimental, synthetic-only capability broker. See docs/threat-model.md.
//! The embedding host is trusted. An `AgentClient` is an API boundary, not an OS sandbox.
#![forbid(unsafe_code)]

pub mod broker;
pub mod fake;
pub mod github;
pub mod mcp;
pub mod protocol;
#[cfg(feature = "signing-spike")]
pub mod signing;
pub mod types;
#[cfg(all(unix, feature = "vault-spike"))]
pub mod vault;

#[cfg(unix)]
pub mod ipc;
#[cfg(feature = "storage-spike")]
pub mod storage;

pub use broker::{
    AgentClient, Clock, Control, ManualClock, MonotonicClock, OperationSetup, SyntheticSetup,
};
pub use types::*;
