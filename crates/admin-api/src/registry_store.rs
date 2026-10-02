use std::{collections::HashSet, fmt, fs, io::Write, net::Ipv4Addr, path::Path};

use mousevpn_config::decode_public_key;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::registry::DeviceRecord;

const REGISTRY_VERSION: u8 = 1;
const MAX_DEVICE_NAME_LEN: usize = 80;

#[derive(Debug, Deserialize, Serialize)]
struct RegistryDocument {
    version: u8,
    devices: Vec<DeviceRecord>,
}

pub(crate) fn load_devices(path: &Path) -> Result<Vec<DeviceRecord>, RegistryError> {
    ensure_private_permissions(path)?;
    let document: RegistryDocument = toml::from_str(&fs::read_to_string(path)?)?;
    if document.version != REGISTRY_VERSION {
        return Err(RegistryError::new("unsupported device registry version"));
    }
    Ok(document.devices)
}

pub(crate) fn persist_devices(path: &Path, devices: &[DeviceRecord]) -> Result<(), RegistryError> {
    let parent = path
        .parent()
        .ok_or_else(|| RegistryError::new("device registry has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let document = RegistryDocument {
        version: REGISTRY_VERSION,
        devices: devices.to_vec(),
    };
    let encoded = toml::to_string_pretty(&document)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    set_private_permissions(temporary.as_file())?;
    temporary.write_all(encoded.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| RegistryError::new(error.error.to_string()))?;
    Ok(())
}

pub(crate) fn next_address(
    devices: &[DeviceRecord],
    tunnel_address: Ipv4Addr,
    prefix_len: u8,
) -> Result<Ipv4Addr, RegistryError> {
    let mask = prefix_mask(prefix_len)?;
    let network = u32::from(tunnel_address) & mask;
    let broadcast = network | !mask;
    let used: HashSet<Ipv4Addr> = devices.iter().map(|device| device.address).collect();
    let upper = broadcast.min(network.saturating_add(65_535));
    ((network + 1)..upper)
        .map(Ipv4Addr::from)
        .find(|candidate| *candidate != tunnel_address && !used.contains(candidate))
        .ok_or_else(|| RegistryError::new("tunnel address pool is exhausted"))
}

pub(crate) fn validate_devices(
    devices: &[DeviceRecord],
    tunnel_address: Ipv4Addr,
    prefix_len: u8,
) -> Result<(), RegistryError> {
    let mask = prefix_mask(prefix_len)?;
    let network = u32::from(tunnel_address) & mask;
    let mut keys = HashSet::new();
    let mut addresses = HashSet::new();
    for device in devices {
        validate_name(&device.name)?;
        let key = decode_public_key(&device.public_key)
            .map_err(|error| RegistryError::new(error.to_string()))?;
        if !keys.insert(key) {
            return Err(RegistryError::new("duplicate device public key"));
        }
        if device.address == tunnel_address || u32::from(device.address) & mask != network {
            return Err(RegistryError::new(
                "device address is outside the tunnel subnet",
            ));
        }
        if !addresses.insert(device.address) {
            return Err(RegistryError::new("duplicate device address"));
        }
    }
    Ok(())
}

pub(crate) fn validate_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() || name.len() > MAX_DEVICE_NAME_LEN || name.chars().any(char::is_control) {
        return Err(RegistryError::new(
            "device name must contain 1 to 80 printable characters",
        ));
    }
    Ok(())
}

fn prefix_mask(prefix_len: u8) -> Result<u32, RegistryError> {
    if prefix_len == 0 || prefix_len > 30 {
        return Err(RegistryError::new(
            "admin address allocation requires a /1 to /30 subnet",
        ));
    }
    Ok(u32::MAX << (32 - u32::from(prefix_len)))
}

#[cfg(unix)]
fn ensure_private_permissions(path: &Path) -> Result<(), RegistryError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(RegistryError::new(format!(
            "device registry permissions are insecure: {mode:o}"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_permissions(_path: &Path) -> Result<(), RegistryError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(file: &fs::File) -> Result<(), RegistryError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &fs::File) -> Result<(), RegistryError> {
    Ok(())
}

#[derive(Debug)]
pub struct RegistryError(String);

impl RegistryError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RegistryError {}

impl From<std::io::Error> for RegistryError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<toml::de::Error> for RegistryError {
    fn from(error: toml::de::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<toml::ser::Error> for RegistryError {
    fn from(error: toml::ser::Error) -> Self {
        Self::new(error.to_string())
    }
}
