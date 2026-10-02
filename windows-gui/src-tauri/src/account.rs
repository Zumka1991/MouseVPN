use mousevpn_account_client::{Account, AccountClient, EnrollRequest};
use mousevpn_config::{encode_public_key, encode_secret_key};
use mousevpn_crypto::KeyPair;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroize;

static ACCOUNT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Deserialize, Serialize)]
struct SavedAccount {
    base: String,
    token: String,
    private_key: String,
    public_key: String,
    account: Account,
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
}

fn lock() -> Result<MutexGuard<'static, ()>, String> {
    ACCOUNT_LOCK
        .lock()
        .map_err(|_| "Аккаунт недоступен".to_owned())
}

pub(crate) fn view() -> Result<AccountView, String> {
    let _guard = lock()?;
    let saved = read()?;
    Ok(saved.as_ref().map_or_else(
        || AccountView {
            base: option_env!("MOUSEVPN_ACCOUNT_URL").unwrap_or("").to_owned(),
            signed_in: false,
            public_key: String::new(),
            account: None,
        },
        |saved| AccountView {
            base: saved.base.clone(),
            signed_in: !saved.token.is_empty(),
            public_key: saved.public_key.clone(),
            account: Some(saved.account.clone()),
        },
    ))
}

pub(crate) fn login(
    base: String,
    login: String,
    mut password: String,
) -> Result<AccountView, String> {
    let _guard = lock()?;
    let base = base.trim().trim_end_matches('/').to_owned();
    let client = AccountClient::new(&base)?;
    let response = client.login(&login, &password);
    password.zeroize();
    let response = response?;
    let previous = read()?;
    let (private_key, public_key) = if let Some(previous) =
        previous.filter(|saved| saved.base == base && saved.account.id == response.account.id)
    {
        (previous.private_key.clone(), previous.public_key.clone())
    } else {
        let keys = KeyPair::generate().map_err(|error| error.to_string())?;
        (
            encode_secret_key(&keys.secret),
            encode_public_key(&keys.public),
        )
    };
    let mut saved = SavedAccount {
        base,
        token: response.token,
        private_key,
        public_key,
        account: response.account,
    };
    write(&saved)?;
    saved.account = client.enroll(
        &saved.token,
        &EnrollRequest {
            name: "Windows".to_owned(),
            platform: "windows".to_owned(),
            public_key: saved.public_key.clone(),
        },
    )?;
    apply(&saved)?;
    Ok(as_view(&saved))
}

pub(crate) fn refresh() -> Result<AccountView, String> {
    let _guard = lock()?;
    let Some(mut saved) = read()? else {
        return Ok(AccountView {
            base: option_env!("MOUSEVPN_ACCOUNT_URL").unwrap_or("").to_owned(),
            signed_in: false,
            public_key: String::new(),
            account: None,
        });
    };
    if saved.token.is_empty() {
        return Ok(as_view(&saved));
    }
    saved.account = AccountClient::new(&saved.base)?.account(&saved.token)?;
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
        let _ = AccountClient::new(&saved.base)?.logout(&saved.token);
        saved.token.clear();
        write(&saved)?;
        super::profiles::replace_managed(None)?;
        return Ok(as_view(&saved));
    }
    Ok(AccountView {
        base: String::new(),
        signed_in: false,
        public_key: String::new(),
        account: None,
    })
}

pub(crate) fn private_key(user: &str, server: &str) -> Result<String, String> {
    // No mutex here: called by reconciliation while ACCOUNT_LOCK is held.
    let saved = read()?.ok_or("Войдите в аккаунт")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(i64::MAX, |time| {
            i64::try_from(time.as_secs()).unwrap_or(i64::MAX)
        });
    if saved.token.is_empty()
        || saved.account.id != user
        || !saved.account.active
        || saved.account.valid_until <= now
        || !saved
            .account
            .devices
            .iter()
            .any(|device| device.public_key == saved.public_key)
        || !saved.account.servers.iter().any(|node| node.id == server)
    {
        return Err("Подписка истекла или доступ отключён. Обновите аккаунт.".to_owned());
    }
    Ok(saved.private_key.clone())
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
    support_call(|client, token| client.create_ticket(token, subject, text))
}
pub(crate) fn ticket(
    id: &str,
    before: Option<i64>,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|client, token| client.ticket(token, id, before))
}
pub(crate) fn reply(id: &str, text: &str) -> Result<mousevpn_account_client::TicketDetail, String> {
    support_call(|client, token| client.reply(token, id, text))
}

fn apply(saved: &SavedAccount) -> Result<(), String> {
    write(saved)?;
    let registered = saved.account.active
        && saved
            .account
            .devices
            .iter()
            .any(|device| device.public_key == saved.public_key);
    super::profiles::replace_managed(registered.then_some(&saved.account))
}
fn as_view(saved: &SavedAccount) -> AccountView {
    AccountView {
        base: saved.base.clone(),
        signed_in: !saved.token.is_empty(),
        public_key: saved.public_key.clone(),
        account: Some(saved.account.clone()),
    }
}
fn path() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|dir| dir.join("MouseVPN").join("account.sealed"))
        .ok_or("Не найден каталог пользователя".to_owned())
}
fn read() -> Result<Option<SavedAccount>, String> {
    let path = path()?;
    let encrypted = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut plain = mousevpn_windows_client::unprotect_account(&encrypted)?;
    let result =
        serde_json::from_slice(&plain).map_err(|_| "Хранилище аккаунта повреждено".to_owned());
    plain.zeroize();
    result.map(Some)
}
fn write(saved: &SavedAccount) -> Result<(), String> {
    let mut plain = serde_json::to_vec(saved).map_err(|error| error.to_string())?;
    let encrypted = mousevpn_windows_client::protect_account(&plain);
    plain.zeroize();
    let encrypted = encrypted?;
    let path = path()?;
    fs::create_dir_all(path.parent().ok_or("Неверный каталог")?)
        .map_err(|error| error.to_string())?;
    super::profiles::write_atomic(&path, &encrypted)
}

pub(crate) fn billing() -> Result<mousevpn_account_client::BillingView, String> {
    support_call(AccountClient::billing)
}
pub(crate) fn request_payment(
    request: mousevpn_account_client::NewPaymentRequest,
) -> Result<mousevpn_account_client::PaymentRequest, String> {
    support_call(|client, token| client.request_payment(token, &request))
}
