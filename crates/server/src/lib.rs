#![doc = "Server-side user authorization and active session state."]

mod bootstrap;
mod daemon;
mod daemon_error;
mod rate_limit;
mod sessions;
mod state;
mod users;

pub use bootstrap::generate_example_configs;
pub use daemon::run;
pub use daemon_error::ServerDaemonError;
pub use sessions::{ActiveSession, SessionAccessError, SessionInsertError, SessionTable};
pub use state::{ProvisionedDevice, RevokeResult, ServerState, StateError};
pub use users::{RegistryError, User, UserId, UserRegistry};
mod controller;
