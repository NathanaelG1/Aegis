//! Experimental capability broker and optional secret proxy. See docs/threat-model.md.
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

#[cfg(all(feature = "sprite-demo", unix))]
pub mod sprite;

#[cfg(all(feature = "proxy", unix))]
pub mod proxy;

#[cfg(all(feature = "proxy", unix))]
pub mod sprite_client;

#[cfg(unix)]
pub mod ipc;
#[cfg(feature = "storage-spike")]
pub mod storage;

pub use broker::{
    AgentClient, Clock, Control, ManualClock, MonotonicClock, OperationSetup, SyntheticSetup,
};
pub use types::*;
