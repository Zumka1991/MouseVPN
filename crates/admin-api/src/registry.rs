use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

use mousevpn_config::{decode_public_key, encode_public_key};
use mousevpn_crypto::{KeyPair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::registry_store::{
    load_devices, next_address, persist_devices, validate_devices, validate_name, RegistryError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    Android,
    Linux,
    Windows,
}

impl fmt::Display for DevicePlatform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Android => formatter.write_str("android"),
            Self::Linux => formatter.write_str("linux"),
            Self::Windows => formatter.write_str("windows"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRecord {
    pub name: String,
    pub platform: DevicePlatform,
    pub public_key: String,
    pub address: Ipv4Addr,
    /// Missing fields are legacy keys and remain unlimited until manually revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

#[derive(Clone)]
pub struct DeviceLease {
    pub name: String,
    pub address: Ipv4Addr,
    pub public_key: PublicKey,
    pub authorization: DeviceAuthorization,
}

#[derive(Clone)]
pub struct DeviceAuthorization(Arc<AtomicBool>);

impl DeviceAuthorization {
    fn active() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}

pub struct SeedDevice {
    pub name: String,
    pub public_key: PublicKey,
    pub address: Ipv4Addr,
}

pub struct ProvisionedDevice {
    pub record: DeviceRecord,
    pub private_key: SecretKey,
}

struct DeviceRegistry {
    path: PathBuf,
    tunnel_address: Ipv4Addr,
    prefix_len: u8,
    devices: Vec<DeviceRecord>,
    leases: HashMap<PublicKey, DeviceLease>,
}

#[derive(Clone)]
pub struct SharedDeviceRegistry(Arc<RwLock<DeviceRegistry>>);

impl SharedDeviceRegistry {
    /// Opens the persistent registry, seeding it from the server config once.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid seed data, insecure permissions, or I/O failures.
    pub fn open(
        path: impl Into<PathBuf>,
        seeds: Vec<SeedDevice>,
        tunnel_address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<Self, RegistryError> {
        let path = path.into();
        let devices = if path.exists() {
            load_devices(&path)?
        } else {
            seeds
                .into_iter()
                .map(|seed| DeviceRecord {
                    name: seed.name,
                    platform: DevicePlatform::Linux,
                    public_key: encode_public_key(&seed.public_key),
                    address: seed.address,
                    managed_by: None,
                    valid_until: None,
                })
                .collect()
        };
        validate_devices(&devices, tunnel_address, prefix_len)?;
        let leases = build_leases(&devices)?;
        let registry = DeviceRegistry {
            path,
            tunnel_address,
            prefix_len,
            devices,
            leases,
        };
        if !registry.path.exists() {
            persist_devices(&registry.path, &registry.devices)?;
        }
        Ok(Self(Arc::new(RwLock::new(registry))))
    }

    /// Returns a snapshot of all registered devices.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry lock is poisoned.
    pub fn list(&self) -> Result<Vec<DeviceRecord>, RegistryError> {
        Ok(self.read()?.devices.clone())
    }

    #[must_use]
    pub fn authorize(&self, public_key: &PublicKey) -> Option<DeviceLease> {
        self.0
            .read()
            .ok()?
            .leases
            .get(public_key)
            .filter(|lease| lease.authorization.is_active())
            .cloned()
    }

    /// Creates and persists a separately revocable device key.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, exhausted addresses, key generation, or persistence.
    pub fn provision(
        &self,
        name: &str,
        platform: DevicePlatform,
    ) -> Result<ProvisionedDevice, RegistryError> {
        let name = name.trim().to_owned();
        validate_name(&name)?;
        let keys = KeyPair::generate().map_err(|error| RegistryError::new(error.to_string()))?;
        let mut registry = self.write()?;
        let address = next_address(
            &registry.devices,
            registry.tunnel_address,
            registry.prefix_len,
        )?;
        let record = DeviceRecord {
            name,
            platform,
            public_key: encode_public_key(&keys.public),
            address,
            managed_by: None,
            valid_until: None,
        };
        let mut next = registry.devices.clone();
        next.push(record.clone());
        persist_devices(&registry.path, &next)?;
        registry.devices = next;
        registry.leases.insert(
            keys.public,
            DeviceLease {
                name: record.name.clone(),
                address: record.address,
                public_key: keys.public,
                authorization: DeviceAuthorization::active(),
            },
        );
        Ok(ProvisionedDevice {
            record,
            private_key: keys.secret,
        })
    }

    /// Permanently removes a public key and disables its active sessions.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key or persistence failure.
    pub fn revoke(&self, public_key: &str) -> Result<bool, RegistryError> {
        let decoded =
            decode_public_key(public_key).map_err(|error| RegistryError::new(error.to_string()))?;
        let mut registry = self.write()?;
        let mut next = registry.devices.clone();
        let before = next.len();
        next.retain(|device| device.public_key != public_key);
        if next.len() == before {
            return Ok(false);
        }
        persist_devices(&registry.path, &next)?;
        registry.devices = next;
        if let Some(lease) = registry.leases.remove(&decoded) {
            lease.authorization.revoke();
        }
        Ok(true)
    }

    /// Reconciles only this controller's keys; legacy keys are never overwritten
    /// or removed. The snapshot is fully validated before disk or session changes.
    ///
    /// # Errors
    /// Returns an error for a stale snapshot, key collision or persistence failure.
    pub fn sync_managed(
        &self,
        snapshot: &mousevpn_account_client::NodeSnapshot,
        now: u64,
    ) -> Result<(), RegistryError> {
        validate_snapshot(snapshot, now)?;
        let mut registry = self.write()?;
        let mut next: Vec<_> = registry
            .devices
            .iter()
            .filter(|device| device.managed_by.as_deref() != Some(&snapshot.server_id))
            .cloned()
            .collect();
        let mut keys = HashSet::new();
        // Reserve existing addresses before allocating a new one: snapshot order
        // must not move another device's live tunnel address.
        let mut allocated = registry
            .devices
            .iter()
            .filter(|device| {
                device.managed_by.as_deref() != Some(&snapshot.server_id)
                    || snapshot
                        .devices
                        .iter()
                        .any(|incoming| incoming.public_key == device.public_key)
            })
            .cloned()
            .collect::<Vec<_>>();
        for incoming in &snapshot.devices {
            validate_name(&incoming.name)?;
            let key = decode_public_key(&incoming.public_key)
                .map_err(|error| RegistryError::new(error.to_string()))?;
            if !keys.insert(key)
                || next
                    .iter()
                    .any(|device| device.public_key == encode_public_key(&key))
            {
                return Err(RegistryError::new(
                    "controller key conflicts with another device",
                ));
            }
            if incoming.valid_until <= now || incoming.valid_until > snapshot.lease_until {
                return Err(RegistryError::new("invalid controller device deadline"));
            }
            let platform = match incoming.platform.as_str() {
                "android" => DevicePlatform::Android,
                "windows" => DevicePlatform::Windows,
                "linux" => DevicePlatform::Linux,
                _ => return Err(RegistryError::new("invalid controller platform")),
            };
            let public_key = encode_public_key(&key);
            let address = registry
                .devices
                .iter()
                .find(|device| device.public_key == public_key)
                .map(|device| device.address)
                .filter(|address| !next.iter().any(|device| device.address == *address))
                .map_or_else(
                    || next_address(&allocated, registry.tunnel_address, registry.prefix_len),
                    Ok,
                )?;
            let record = DeviceRecord {
                name: incoming.name.clone(),
                platform,
                public_key,
                address,
                managed_by: Some(snapshot.server_id.clone()),
                valid_until: Some(incoming.valid_until),
            };
            allocated.push(record.clone());
            next.push(record);
        }
        validate_devices(&next, registry.tunnel_address, registry.prefix_len)?;
        persist_devices(&registry.path, &next)?;
        let mut leases = HashMap::new();
        for record in &next {
            let key = decode_public_key(&record.public_key)
                .map_err(|error| RegistryError::new(error.to_string()))?;
            let lease = registry
                .leases
                .get(&key)
                .filter(|lease| lease.address == record.address && lease.authorization.is_active())
                .cloned()
                .unwrap_or_else(|| DeviceLease {
                    name: record.name.clone(),
                    address: record.address,
                    public_key: key,
                    authorization: DeviceAuthorization::active(),
                });
            leases.insert(key, lease);
        }
        for (key, lease) in &registry.leases {
            if !leases
                .get(key)
                .is_some_and(|next| Arc::ptr_eq(&next.authorization.0, &lease.authorization.0))
            {
                lease.authorization.revoke();
            }
        }
        registry.devices = next;
        registry.leases = leases;
        Ok(())
    }

    /// Expiration touches only atomic flags, including those of live sessions.
    ///
    /// # Errors
    /// Returns an error if the registry lock is poisoned.
    pub fn expire_at(&self, now: u64) -> Result<(), RegistryError> {
        let registry = self.read()?;
        for device in &registry.devices {
            if device.valid_until.is_some_and(|until| until <= now) {
                let key = decode_public_key(&device.public_key)
                    .map_err(|error| RegistryError::new(error.to_string()))?;
                if let Some(lease) = registry.leases.get(&key) {
                    lease.authorization.revoke();
                }
            }
        }
        Ok(())
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, DeviceRegistry>, RegistryError> {
        self.0
            .read()
            .map_err(|_| RegistryError::new("device registry lock is poisoned"))
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, DeviceRegistry>, RegistryError> {
        self.0
            .write()
            .map_err(|_| RegistryError::new("device registry lock is poisoned"))
    }
}

fn build_leases(
    devices: &[DeviceRecord],
) -> Result<HashMap<PublicKey, DeviceLease>, RegistryError> {
    devices
        .iter()
        .map(|device| {
            let public_key = decode_public_key(&device.public_key)
                .map_err(|error| RegistryError::new(error.to_string()))?;
            let authorization = DeviceAuthorization::active();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(u64::MAX, |value| value.as_secs());
            if device.valid_until.is_some_and(|until| until <= now) {
                authorization.revoke();
            }
            Ok((
                public_key,
                DeviceLease {
                    name: device.name.clone(),
                    address: device.address,
                    public_key,
                    authorization,
                },
            ))
        })
        .collect()
}

fn validate_snapshot(
    snapshot: &mousevpn_account_client::NodeSnapshot,
    now: u64,
) -> Result<(), RegistryError> {
    if snapshot.server_id.is_empty()
        || snapshot.generated_at > now.saturating_add(30)
        || snapshot.lease_until <= now
        || snapshot.lease_until > now.saturating_add(300)
        || snapshot.lease_until > snapshot.generated_at.saturating_add(300)
        || snapshot.generated_at > snapshot.lease_until
    {
        return Err(RegistryError::new("invalid or stale controller snapshot"));
    }
    Ok(())
}
