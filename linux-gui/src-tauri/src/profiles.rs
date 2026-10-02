use mousevpn_config::{ClientConfig, ClientProtocol};
use mousevpn_profile_cli::decrypt_profile;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroize;
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileSummary {
    id: String,
    name: String,
    endpoint: String,
    protocol: ClientProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_user: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct StoredProfile {
    id: String,
    name: String,
    server: String,
    server_public_key: String,
    client_private_key: String,
    tun_name: String,
    #[serde(default)]
    protocol: ClientProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_user: Option<String>,
}

impl StoredProfile {
    fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            endpoint: self.server.clone(),
            protocol: self.protocol,
            managed_user: self.managed_user.clone(),
        }
    }

    fn client_config(&self) -> Result<ClientConfig, String> {
        Ok(ClientConfig {
            server: self
                .server
                .parse()
                .map_err(|error| format!("Неверный адрес сервера: {error}"))?,
            server_public_key: self.server_public_key.clone(),
            client_private_key: self.client_private_key.clone(),
            tun_name: self.tun_name.clone(),
            protocol: self.protocol,
        })
    }
}

pub(crate) fn list() -> Result<Vec<ProfileSummary>, String> {
    let directory = profiles_dir()?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut profiles = Vec::new();
    for entry in fs::read_dir(directory).map_err(display_error)? {
        let path = entry.map_err(display_error)?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let contents = fs::read_to_string(&path).map_err(display_error)?;
        let stored: StoredProfile = toml::from_str(&contents).map_err(display_error)?;
        profiles.push(stored.summary());
    }
    profiles.sort_by_key(|profile| profile.name.to_lowercase());
    Ok(profiles)
}

pub(crate) fn import(token: String, mut password: String) -> Result<ProfileSummary, String> {
    let decrypted = decrypt_profile(token.trim(), password.as_bytes()).map_err(display_error);
    password.zeroize();
    let (portable_id, name, endpoint, server_public_key, client_private_key) =
        decrypted?.into_parts();
    let id = Uuid::parse_str(&portable_id)
        .unwrap_or_else(|_| Uuid::new_v4())
        .to_string();
    let profile = StoredProfile {
        id,
        name: name.trim().to_owned(),
        server: endpoint.trim().to_owned(),
        server_public_key,
        client_private_key,
        tun_name: "mousevpn0".to_owned(),
        protocol: ClientProtocol::Legacy,
        managed_user: None,
    };
    if profile.name.is_empty() {
        return Err("В конфигурации отсутствует название".to_owned());
    }
    profile.client_config()?.validate().map_err(display_error)?;
    let directory = profiles_dir()?;
    create_private_dir(&directory)?;
    let path = profile_path(&profile.id)?;
    write_private_atomic(
        &path,
        toml::to_string_pretty(&profile)
            .map_err(display_error)?
            .as_bytes(),
    )?;
    Ok(profile.summary())
}

fn profiles_dir() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|directory| directory.join("mousevpn").join("profiles"))
        .ok_or_else(|| "Не удалось определить каталог конфигурации пользователя".to_owned())
}

pub(crate) fn profile_path(id: &str) -> Result<PathBuf, String> {
    Ok(profiles_dir()?.join(format!("{}.toml", normalized_id(id)?)))
}

pub(crate) fn normalized_id(id: &str) -> Result<String, String> {
    Uuid::parse_str(id)
        .map(|value| value.to_string())
        .map_err(|_| "Неверный идентификатор профиля".to_owned())
}

pub(crate) fn create_private_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        return fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(display_error);
    }
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(display_error)
}

pub(crate) fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(display_error)?;
        file.write_all(contents).map_err(display_error)?;
        file.sync_all().map_err(display_error)?;
        fs::rename(&temporary, path).map_err(display_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(crate) fn set_protocol(id: &str, protocol: ClientProtocol) -> Result<ProfileSummary, String> {
    let path = profile_path(id)?;
    let mut profile: StoredProfile =
        toml::from_str(&fs::read_to_string(&path).map_err(display_error)?)
            .map_err(display_error)?;
    if profile.managed_user.is_some() {
        super::account::set_protocol(protocol)?;
        return list()?
            .into_iter()
            .find(|p| p.id == id)
            .ok_or("Сервер больше недоступен".to_owned());
    }
    profile.protocol = protocol;
    profile.client_config()?.validate().map_err(display_error)?;
    write_private_atomic(
        &path,
        toml::to_string_pretty(&profile)
            .map_err(display_error)?
            .as_bytes(),
    )?;
    Ok(profile.summary())
}
pub(crate) fn is_managed(id: &str) -> Result<bool, String> {
    let profile: StoredProfile =
        toml::from_str(&fs::read_to_string(profile_path(id)?).map_err(display_error)?)
            .map_err(display_error)?;
    Ok(profile.managed_user.is_some())
}
pub(crate) fn remove(id: &str) -> Result<(), String> {
    if is_managed(id)? {
        return Err(
            "Серверы подписки распределяет администратор. Устройство можно отключить в аккаунте."
                .to_owned(),
        );
    }
    fs::remove_file(profile_path(id)?).map_err(display_error)
}
pub(crate) fn connection_config(id: &str) -> Result<(ClientConfig, bool), String> {
    let profile: StoredProfile =
        toml::from_str(&fs::read_to_string(profile_path(id)?).map_err(display_error)?)
            .map_err(display_error)?;
    if let Some(user) = &profile.managed_user {
        super::account::private_key(user, id)?;
    }
    Ok((profile.client_config()?, profile.managed_user.is_some()))
}
pub(crate) fn replace_managed(
    account: Option<&mousevpn_account_client::Account>,
    key: &str,
    protocol: ClientProtocol,
) -> Result<(), String> {
    reconcile(&profiles_dir()?, account, key, protocol)
}
fn reconcile(
    directory: &Path,
    account: Option<&mousevpn_account_client::Account>,
    key: &str,
    protocol: ClientProtocol,
) -> Result<(), String> {
    create_private_dir(directory)?;
    let mut replacements = Vec::new();
    if let Some(account) = account {
        for server in &account.servers {
            let path = directory.join(format!("{}.toml", normalized_id(&server.id)?));
            if path.exists() {
                let previous: StoredProfile =
                    toml::from_str(&fs::read_to_string(&path).map_err(display_error)?)
                        .map_err(display_error)?;
                if previous.managed_user.is_none() {
                    return Err("Профиль сервера совпал с личным профилем".to_owned());
                }
            }
            let profile = StoredProfile {
                id: server.id.clone(),
                name: server.name.clone(),
                server: server.endpoint.clone(),
                server_public_key: server.public_key.clone(),
                client_private_key: key.to_owned(),
                tun_name: "mousevpn0".to_owned(),
                protocol,
                managed_user: Some(account.id.clone()),
            };
            profile.client_config()?.validate().map_err(display_error)?;
            replacements.push((
                path,
                toml::to_string_pretty(&profile).map_err(display_error)?,
            ));
        }
    }
    for entry in fs::read_dir(directory).map_err(display_error)? {
        let path = entry.map_err(display_error)?.path();
        if path.extension().and_then(|v| v.to_str()) != Some("toml") {
            continue;
        }
        let previous: StoredProfile =
            toml::from_str(&fs::read_to_string(&path).map_err(display_error)?)
                .map_err(display_error)?;
        if previous.managed_user.is_some() && !replacements.iter().any(|(p, _)| p == &path) {
            fs::remove_file(path).map_err(display_error)?;
        }
    }
    for (path, text) in replacements {
        write_private_atomic(&path, text.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousevpn_account_client::{Account, Server};
    use mousevpn_config::{encode_public_key, encode_secret_key};
    use mousevpn_crypto::KeyPair;

    fn fixture() -> (Account, String) {
        let key = KeyPair::generate().unwrap();
        (
            Account {
                id: Uuid::new_v4().to_string(),
                login: "test@example.invalid".to_owned(),
                valid_until: i64::MAX,
                active: true,
                device_limit: 2,
                devices: vec![],
                unread_messages: 0,
                servers: (0..2)
                    .map(|i| Server {
                        online_devices: None,
                        online_updated_at: None,
                        id: Uuid::new_v4().to_string(),
                        name: format!("Node {i}"),
                        endpoint: format!("127.0.0.1:{}", 51820 + i),
                        public_key: encode_public_key(&key.public),
                        protocol: "legacy".to_owned(),
                    })
                    .collect(),
            },
            encode_secret_key(&key.secret),
        )
    }
    fn read_profile(dir: &Path, id: &str) -> StoredProfile {
        toml::from_str(&fs::read_to_string(dir.join(format!("{id}.toml"))).unwrap()).unwrap()
    }
    fn legacy(dir: &Path, id: &str, node: &Server, key: &str) -> PathBuf {
        let profile = StoredProfile {
            id: id.to_owned(),
            name: "My old key".to_owned(),
            server: node.endpoint.clone(),
            server_public_key: node.public_key.clone(),
            client_private_key: key.to_owned(),
            tun_name: "mousevpn0".to_owned(),
            protocol: ClientProtocol::Legacy,
            managed_user: None,
        };
        let path = dir.join(format!("{id}.toml"));
        write_private_atomic(&path, toml::to_string(&profile).unwrap().as_bytes()).unwrap();
        path
    }
    #[test]
    fn subscription_updates_preserve_legacy_and_apply_user_mode_to_all_servers() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let (mut account, key) = fixture();
        let old = legacy(dir, &Uuid::new_v4().to_string(), &account.servers[0], &key);
        let original = fs::read(&old).unwrap();
        reconcile(dir, Some(&account), &key, ClientProtocol::MorphBalanced).unwrap();
        for node in &account.servers {
            let profile = read_profile(dir, &node.id);
            assert_eq!(profile.protocol, ClientProtocol::MorphBalanced);
            assert_eq!(profile.managed_user.as_deref(), Some(account.id.as_str()));
            assert_eq!(profile.client_private_key, key);
            assert_eq!(
                fs::metadata(dir.join(format!("{}.toml", node.id)))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let removed = account.servers.pop().unwrap();
        account.servers[0].endpoint = "127.0.0.2:51821".to_owned();
        reconcile(dir, Some(&account), &key, ClientProtocol::Speedy).unwrap();
        assert!(!dir.join(format!("{}.toml", removed.id)).exists());
        let updated = read_profile(dir, &account.servers[0].id);
        assert_eq!(updated.server, "127.0.0.2:51821");
        assert_eq!(updated.protocol, ClientProtocol::Speedy);
        reconcile(dir, None, &key, ClientProtocol::MorphBalanced).unwrap();
        assert_eq!(fs::read(&old).unwrap(), original);
        assert_eq!(fs::read_dir(dir).unwrap().count(), 1);
    }
    #[test]
    fn invalid_update_never_deletes_legacy_or_existing_subscription_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let (mut account, key) = fixture();
        reconcile(dir, Some(&account), &key, ClientProtocol::MorphBalanced).unwrap();
        let retained = account.servers[0].id.clone();
        let collision = Uuid::new_v4().to_string();
        let old = legacy(dir, &collision, &account.servers[0], &key);
        let original = fs::read(&old).unwrap();
        account.servers.truncate(1);
        account.servers[0].id = collision;
        assert!(reconcile(dir, Some(&account), &key, ClientProtocol::MorphBalanced).is_err());
        assert_eq!(fs::read(&old).unwrap(), original);
        assert!(dir.join(format!("{retained}.toml")).exists());
        account.servers[0].id = "../../escape".to_owned();
        assert!(reconcile(dir, Some(&account), &key, ClientProtocol::MorphBalanced).is_err());
    }
}
