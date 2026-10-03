#![doc = "Validated TOML configuration for `MouseVPN` binaries."]

mod client;
mod error;
mod keys;
mod load;
mod server;

pub use client::{ClientConfig, ClientProtocol, ValidatedClientConfig};
pub use error::ConfigError;
pub use keys::{decode_public_key, decode_secret_key, encode_public_key, encode_secret_key};
pub use load::load_toml;
pub use server::{
    AuthorizedClientConfig, ServerConfig, ServerTunConfig, TrafficConfig,
    ValidatedAuthorizedClient, ValidatedServerConfig, DEFAULT_TUN_MTU, MAX_SAFE_TUN_MTU,
};
