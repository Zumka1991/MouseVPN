use std::{error::Error, fmt, path::PathBuf};

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    InsecurePermissions { path: PathBuf, mode: u32 },
    InvalidKeyEncoding,
    InvalidKeyLength(usize),
    DuplicateClientAddress,
    DuplicateClientKey,
    ClientAddressMatchesServer,
    ClientOutsideTunnelSubnet,
    ServerKeyPairMismatch,
    InvalidPrefix(u8),
    InvalidMtu(u16),
    EmptyClients,
    InvalidBandwidth,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "configuration I/O error: {error}"),
            Self::Toml(error) => write!(formatter, "invalid TOML configuration: {error}"),
            Self::InsecurePermissions { path, mode } => write!(
                formatter,
                "configuration {} has insecure mode {mode:o}; expected no group/other access",
                path.display()
            ),
            Self::InvalidKeyEncoding => formatter.write_str("invalid URL-safe Base64 key"),
            Self::InvalidKeyLength(length) => write!(formatter, "invalid key length {length}"),
            Self::DuplicateClientAddress => formatter.write_str("duplicate client tunnel address"),
            Self::DuplicateClientKey => formatter.write_str("duplicate client public key"),
            Self::ClientAddressMatchesServer => {
                formatter.write_str("client address matches the server TUN address")
            }
            Self::ClientOutsideTunnelSubnet => {
                formatter.write_str("client address is outside the configured TUN subnet")
            }
            Self::ServerKeyPairMismatch => {
                formatter.write_str("server public and private keys do not match")
            }
            Self::InvalidPrefix(prefix) => write!(formatter, "invalid IPv4 prefix length {prefix}"),
            Self::InvalidMtu(mtu) => write!(formatter, "invalid tunnel MTU {mtu}"),
            Self::EmptyClients => formatter.write_str("server must authorize at least one client"),
            Self::InvalidBandwidth => {
                formatter.write_str("traffic.bandwidth_mbps must be between 1 and 100000")
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Toml(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(error: toml::de::Error) -> Self {
        Self::Toml(error)
    }
}
