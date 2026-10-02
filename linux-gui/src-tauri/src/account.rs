use mousevpn_account_client::{Account, AccountClient, EnrollRequest};
use mousevpn_config::{encode_public_key, encode_secret_key, ClientProtocol};
use mousevpn_crypto::KeyPair;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};
use zeroize::{Zeroize, Zeroizing};

static ACCOUNT_LOCK: Mutex<()> = Mutex::new(());
fn default_protocol() -> ClientProtocol {
    ClientProtocol::MorphBalanced
}
fn primary() -> &'static str {
    option_env!("MOUSEVPN_ACCOUNT_URL").unwrap_or("https://mousevpn.space/vpn")
}
fn fallback() -> Option<&'static str> {
    option_env!("MOUSEVPN_ACCOUNT_FALLBACK_URL").or_else(|| {
        (primary() == "https://mousevpn.space/vpn").then_some("https://myaifriend.su/vpn")
    })
}
#[derive(Deserialize, Serialize)]
struct SavedAccount {
    base: String,
    token: String,
    private_key: String,
    public_key: String,
    account: Account,
    #[serde(default = "default_protocol")]
    protocol: ClientProtocol,
    #[serde(default)]
    enrollment_error: Option<String>,
}
impl Drop for SavedAccount {
    fn drop(&mut self) {
        self.token.zeroize();
        self.private_key.zeroize();
    }
}
#[derive(Serialize)]
pub(crate) struct AccountView {
    pub base: String,
    pub signed_in: bool,
    pub public_key: String,
    pub account: Option<Account>,
    pub registered: bool,
    pub notice: Option<String>,
}
fn lock() -> Result<MutexGuard<'static, ()>, String> {
    ACCOUNT_LOCK
        .lock()
        .map_err(|_| "Аккаунт недоступен".to_owned())
}
fn empty_view() -> AccountView {
    AccountView {
        base: primary().to_owned(),
        signed_in: false,
        public_key: String::new(),
        account: None,
        registered: false,
        notice: None,
    }
}
pub(crate) fn view() -> Result<AccountView, String> {
    let _guard = lock()?;
    Ok(read()?.as_ref().map_or_else(empty_view, as_view))
}
pub(crate) fn login(base: String, login: String, password: String) -> Result<AccountView, String> {
    let password = Zeroizing::new(password);
    let _guard = lock()?;
    let mut base = if base.trim().is_empty() {
        primary().to_owned()
    } else {
        base.trim().trim_end_matches('/').to_owned()
    };
    if base != primary() && fallback() != Some(base.as_str()) {
        return Err("Неверный адрес сервиса MouseVPN".to_owned());
    }
    let mut response = AccountClient::new(&base)?.login(login.trim(), &password);
    if response
        .as_ref()
        .is_err_and(|error| error == "Сервис аккаунтов недоступен")
        && base == primary()
    {
        if let Some(alternate) = fallback() {
            alternate.clone_into(&mut base);
            response = AccountClient::new(&base)?.login(login.trim(), &password);
        }
    }
    let response = response?;
    let (private_key, public_key) = device_identity(&response.account.id)?;
    let previous = read()?;
    let protocol = previous
        .as_ref()
        .filter(|s| s.account.id == response.account.id)
        .map_or_else(default_protocol, |s| s.protocol);
    let mut saved = SavedAccount {
        base,
        token: response.token,
        private_key,
        public_key,
        account: response.account,
        protocol,
        enrollment_error: None,
    };
    // Save the identity before POST: retrying a lost response must reuse one device slot.
    write(&saved)?;
    enroll(&mut saved);
    apply(&saved)?;
    Ok(as_view(&saved))
}
fn enroll(saved: &mut SavedAccount) {
    let result = AccountClient::new(&saved.base).and_then(|client| {
        client.enroll(
            &saved.token,
            &EnrollRequest {
                name: "Linux".to_owned(),
                platform: "linux".to_owned(),
                public_key: saved.public_key.clone(),
            },
        )
    });
    match result {
        Ok(account) => {
            saved.account = account;
            saved.enrollment_error = None;
        }
        Err(error) => saved.enrollment_error = Some(error),
    }
}
pub(crate) fn register_device() -> Result<AccountView, String> {
    let _guard = lock()?;
    let mut saved = read()?.ok_or("Войдите в аккаунт")?;
    if saved.token.is_empty() {
        return Err("Войдите в аккаунт".to_owned());
    }
    enroll(&mut saved);
    apply(&saved)?;
    Ok(as_view(&saved))
}
pub(crate) fn refresh() -> Result<AccountView, String> {
    let _guard = lock()?;
    let Some(mut saved) = read()? else {
        return Ok(empty_view());
    };
    if saved.token.is_empty() {
        return Ok(as_view(&saved));
    }
    saved.account = AccountClient::new(&saved.base)?.account(&saved.token)?;
    if registered(&saved) {
        saved.enrollment_error = None;
    }
    apply(&saved)?;
    Ok(as_view(&saved))
}
pub(crate) fn revoke(id: &str) -> Result<AccountView, String> {
    let _guard = lock()?;
    super::profiles::normalized_id(id)?;
    let mut saved = read()?.ok_or("Войдите в аккаунт")?;
    saved.account = AccountClient::new(&saved.base)?.revoke(&saved.token, id)?;
    apply(&saved)?;
    Ok(as_view(&saved))
}
pub(crate) fn logout() -> Result<AccountView, String> {
    let _guard = lock()?;
    if let Some(mut saved) = read()? {
        let token = Zeroizing::new(saved.token.clone());
        saved.token.zeroize();
        saved.token.clear();
        saved.enrollment_error = None;
        apply(&saved)?;
        let _ = AccountClient::new(&saved.base)?.logout(&token);
    }
    Ok(empty_view())
}
pub(crate) fn set_protocol(protocol: ClientProtocol) -> Result<(), String> {
    let _guard = lock()?;
    let mut saved = read()?.ok_or("Войдите в аккаунт")?;
    saved.protocol = protocol;
    apply(&saved)
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(i64::MAX, |t| i64::try_from(t.as_secs()).unwrap_or(i64::MAX))
}
fn registered(saved: &SavedAccount) -> bool {
    saved
        .account
        .devices
        .iter()
        .any(|device| device.public_key == saved.public_key)
}
fn allowed(saved: &SavedAccount, user: &str, server: &str) -> bool {
    !saved.token.is_empty()
        && saved.account.id == user
        && saved.account.active
        && saved.account.valid_until > now()
        && registered(saved)
        && saved.account.servers.iter().any(|node| node.id == server)
}
pub(crate) fn private_key(user: &str, server: &str) -> Result<String, String> {
    let saved = read()?.ok_or("Войдите в аккаунт")?;
    if !allowed(&saved, user, server) {
        return Err("Подписка истекла или доступ отключён. Обновите аккаунт.".to_owned());
    }
    Ok(saved.private_key.clone())
}
pub(crate) fn allows_server(server: &str) -> bool {
    read()
        .ok()
        .flatten()
        .is_some_and(|saved| allowed(&saved, &saved.account.id, server))
}
fn apply(saved: &SavedAccount) -> Result<(), String> {
    write(saved)?;
    let active = !saved.token.is_empty()
        && saved.account.active
        && saved.account.valid_until > now()
        && registered(saved);
    super::profiles::replace_managed(
        active.then_some(&saved.account),
        &saved.private_key,
        saved.protocol,
    )
}
fn as_view(saved: &SavedAccount) -> AccountView {
    AccountView {
        base: saved.base.clone(),
        signed_in: !saved.token.is_empty(),
        public_key: saved.public_key.clone(),
        account: (!saved.token.is_empty()).then(|| saved.account.clone()),
        registered: registered(saved),
        notice: saved.enrollment_error.clone(),
    }
}
fn directory() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|p| p.join("mousevpn"))
        .ok_or("Не найден каталог пользователя".to_owned())
}
fn read() -> Result<Option<SavedAccount>, String> {
    let contents = match fs::read(directory()?.join("account.json")) {
        Ok(v) => Zeroizing::new(v),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    serde_json::from_slice(&contents)
        .map(Some)
        .map_err(|_| "Хранилище аккаунта повреждено".to_owned())
}
fn write(saved: &SavedAccount) -> Result<(), String> {
    let dir = directory()?;
    super::profiles::create_private_dir(&dir)?;
    let plain = Zeroizing::new(serde_json::to_vec(saved).map_err(|e| e.to_string())?);
    super::profiles::write_private_atomic(&dir.join("account.json"), &plain)
}
#[derive(Serialize, Deserialize)]
struct Identity {
    private_key: String,
    public_key: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
fn device_identity(user: &str) -> Result<(String, String), String> {
    device_identity_at(&directory()?.join("device-identities"), user)
}
fn device_identity_at(dir: &std::path::Path, user: &str) -> Result<(String, String), String> {
    let id = super::profiles::normalized_id(user)?;
    super::profiles::create_private_dir(dir)?;
    let path = dir.join(format!("{id}.json"));
    match fs::read(&path) {
        Ok(bytes) => {
            let plain = Zeroizing::new(bytes);
            let identity: Identity = serde_json::from_slice(&plain)
                .map_err(|_| "Ключ устройства повреждён".to_owned())?;
            return Ok((identity.private_key.clone(), identity.public_key.clone()));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let keys = KeyPair::generate().map_err(|e| e.to_string())?;
    let identity = Identity {
        private_key: encode_secret_key(&keys.secret),
        public_key: encode_public_key(&keys.public),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&identity).map_err(|e| e.to_string())?);
    super::profiles::write_private_atomic(&path, &plain)?;
    Ok((identity.private_key.clone(), identity.public_key.clone()))
}
fn support_call<T>(
    call: impl FnOnce(&AccountClient, &str) -> Result<T, String>,
) -> Result<T, String> {
    let _guard = lock()?;
    let saved = read()?.ok_or("Войдите в аккаунт")?;
    if saved.token.is_empty() {
        return Err("Войдите в аккаунт".to_owned());
    }
    call(&AccountClient::new(&saved.base)?, &saved.token)
}
pub(crate) fn tickets() -> Result<Vec<mousevpn_account_client::TicketSummary>, String> {
    support_call(AccountClient::tickets)
}
pub(crate) fn create_ticket(
    subject: &str,
    text: &str,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|c, t| c.create_ticket(t, subject, text))
}
pub(crate) fn ticket(
    id: &str,
    before: Option<i64>,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|c, t| c.ticket(t, id, before))
}
pub(crate) fn reply(id: &str, text: &str) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|c, t| c.reply(t, id, text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousevpn_account_client::{Device, Server};
    use std::os::unix::fs::PermissionsExt;

    fn saved() -> SavedAccount {
        SavedAccount {
            base: primary().to_owned(),
            token: "test-session".to_owned(),
            private_key: "test-secret".to_owned(),
            public_key: "test-public".to_owned(),
            protocol: default_protocol(),
            enrollment_error: None,
            account: Account {
                id: "user".to_owned(),
                login: "test@example.invalid".to_owned(),
                active: true,
                valid_until: now() + 3600,
                device_limit: 2,
                unread_messages: 0,
                devices: vec![Device {
                    id: "device".to_owned(),
                    name: "Linux".to_owned(),
                    platform: "linux".to_owned(),
                    public_key: "test-public".to_owned(),
                }],
                servers: vec![Server {
                    online_devices: None,
                    online_updated_at: None,
                    id: "server".to_owned(),
                    name: "Node".to_owned(),
                    endpoint: "127.0.0.1:51820".to_owned(),
                    public_key: String::new(),
                    protocol: "legacy".to_owned(),
                }],
            },
        }
    }
    #[test]
    fn access_requires_subscription_device_server_and_session() {
        let mut state = saved();
        assert!(allowed(&state, "user", "server"));
        assert!(!allowed(&state, "other-user", "server"));
        assert!(!allowed(&state, "user", "other-server"));
        state.account.valid_until = now() - 1;
        assert!(!allowed(&state, "user", "server"));
        state.account.valid_until = now() + 3600;
        state.account.active = false;
        assert!(!allowed(&state, "user", "server"));
        state.account.active = true;
        state.account.devices.clear();
        assert!(!allowed(&state, "user", "server"));
        state = saved();
        state.token.clear();
        assert!(!allowed(&state, "user", "server"));
    }
    #[test]
    fn identity_survives_sign_out_without_consuming_another_slot() {
        let temp = tempfile::tempdir().unwrap();
        let user = uuid::Uuid::new_v4().to_string();
        let first = device_identity_at(temp.path(), &user).unwrap();
        let again = device_identity_at(temp.path(), &user).unwrap();
        assert_eq!(first, again);
        let other = device_identity_at(temp.path(), &uuid::Uuid::new_v4().to_string()).unwrap();
        assert_ne!(first.1, other.1);
        let file = temp.path().join(format!("{user}.json"));
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(device_identity_at(temp.path(), "../../outside").is_err());
    }
}

pub(crate) fn billing() -> Result<mousevpn_account_client::BillingView, String> {
    support_call(AccountClient::billing)
}
pub(crate) fn request_payment(
    request: mousevpn_account_client::NewPaymentRequest,
) -> Result<mousevpn_account_client::PaymentRequest, String> {
    support_call(|client, token| client.request_payment(token, &request))
}
