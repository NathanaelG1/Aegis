//! Experimental, synthetic-only capability broker. See docs/threat-model.md.
//! The embedding host is trusted. An `AgentClient` is an API boundary, not an OS sandbox.
#![forbid(unsafe_code)]

pub mod broker;
pub mod fake;
pub mod mcp;
pub mod protocol;
pub mod types;

#[cfg(unix)]
pub mod ipc;
#[cfg(feature = "storage-spike")]
pub mod storage;

pub use broker::{AgentClient, Clock, Control, ManualClock, MonotonicClock, SyntheticSetup};
pub use types::*;
