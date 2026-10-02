use std::{fs, path::Path};

use chrono::{DateTime, Months, Utc};
use mousevpn_account_client::{Account, Device, NodeDevice, NodeSnapshot, Server};
use mousevpn_config::{decode_public_key, encode_public_key};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ApiError;

pub const MONTH_PRICE: i64 = 300;
pub const DEVICE_LIMIT: usize = 2;
pub const NODE_LEASE_SECONDS: i64 = 300;

pub struct Store {
    pub(crate) db: Connection,
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub login: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct UserAccess {
    pub enabled: bool,
    pub all_servers: bool,
    #[serde(default)]
    pub server_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct ServerInput {
    pub name: String,
    pub endpoint: String,
    pub public_key: String,
    pub protocol: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

const fn yes() -> bool {
    true
}

#[derive(Serialize)]
pub struct AdminServer {
    #[serde(flatten)]
    pub server: Server,
    pub enabled: bool,
    pub last_seen: Option<i64>,
}

#[derive(Serialize)]
pub struct AdminUser {
    #[serde(flatten)]
    pub account: Account,
    pub enabled: bool,
    pub all_servers: bool,
    pub server_ids: Vec<String>,
    pub payments: Vec<Payment>,
    pub lifetime: bool,
    pub paid_valid_until: i64,
}

#[derive(Serialize)]
pub struct Payment {
    pub reference: String,
    pub amount_rub: i64,
    pub months: u32,
    pub confirmed_at: i64,
    pub valid_until: i64,
}

#[derive(Deserialize)]
pub struct ConfirmPayment {
    pub reference: String,
    pub amount_rub: i64,
    pub months: u32,
}

impl Store {
    /// # Errors
    /// Returns an error if the database cannot be secured, opened or migrated.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                return Err("database must have permissions 0600".into());
            }
        }
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        if db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))? > 4 {
            return Err("unsupported database version".into());
        }
        db.execute_batch(include_str!("schema.sql"))?;
        Ok(Self { db })
    }

    pub(crate) fn create_user(
        &self,
        login: &str,
        password_hash: &str,
        now: i64,
    ) -> Result<AdminUser, ApiError> {
        let login = normalized_login(login)?;
        if self
            .db
            .query_row("SELECT id FROM users WHERE login=?", [&login], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .is_some()
        {
            return Err(ApiError::conflict("Логин уже занят"));
        }
        let id = Uuid::new_v4().to_string();
        self.db.execute(
            "INSERT INTO users(id,login,password_hash) VALUES(?,?,?)",
            params![id, login, password_hash],
        )?;
        self.admin_user(&id, now)
    }

    pub(crate) fn password_hash(&self, login: &str) -> Result<Option<(String, String)>, ApiError> {
        Ok(self
            .db
            .query_row(
                "SELECT id,password_hash FROM users WHERE login=? AND enabled=1",
                [login],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub(crate) fn session(&self, user: &str, now: i64) -> Result<String, ApiError> {
        let token = random_token();
        self.db
            .execute("DELETE FROM sessions WHERE expires_at<=?", [now])?;
        self.db.execute(
            "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
            params![hash_token(&token), user, now + 30 * 86_400],
        )?;
        Ok(token)
    }

    pub(crate) fn authenticate(&self, token: &str, now: i64) -> Result<String, ApiError> {
        self.db.query_row("SELECT u.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1", params![hash_token(token), now], |row| row.get(0)).optional()?.ok_or_else(ApiError::unauthorized)
    }

    pub(crate) fn logout(&self, token: &str) -> Result<(), ApiError> {
        self.db.execute(
            "DELETE FROM sessions WHERE token_hash=?",
            [hash_token(token)],
        )?;
        Ok(())
    }

    pub(crate) fn account(&self, user: &str, now: i64) -> Result<Account, ApiError> {
        let (login, valid_until, enabled, all_servers): (String, i64, bool, bool) = self
            .db
            .query_row(
                "SELECT login,CASE WHEN EXISTS(SELECT 1 FROM lifetime_access l WHERE l.user_id=users.id AND l.enabled=1) THEN 253402300799 ELSE valid_until END,enabled,all_servers FROM users WHERE id=?",
                [user],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or_else(ApiError::missing)?;
        let active = enabled && valid_until > now;
        let mut devices = self.db.prepare("SELECT id,name,platform,public_key FROM devices WHERE user_id=? ORDER BY created_at,id")?;
        let devices = devices
            .query_map([user], |row| {
                Ok(Device {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    platform: row.get(2)?,
                    public_key: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut servers = if active {
            let mut statement = self.db.prepare("SELECT id,name,endpoint,public_key,protocol FROM servers WHERE enabled=1 AND (?=1 OR id IN(SELECT server_id FROM user_servers WHERE user_id=?)) ORDER BY name,id")?;
            let result = statement
                .query_map(params![all_servers, user], server_row)?
                .collect::<Result<Vec<_>, _>>()?;
            result
        } else {
            Vec::new()
        };
        for server in &mut servers {
            self.fill_online(server, now)?;
        }
        let unread_messages=self.db.query_row("SELECT COUNT(*) FROM ticket_messages m JOIN tickets t ON t.id=m.ticket_id WHERE t.user_id=? AND m.author='admin' AND m.id>t.user_read",[user],|row| row.get(0))?;
        Ok(Account {
            id: user.to_owned(),
            login,
            valid_until,
            active,
            device_limit: DEVICE_LIMIT,
            devices,
            servers,
            unread_messages,
        })
    }

    pub(crate) fn users(&self, now: i64) -> Result<Vec<AdminUser>, ApiError> {
        let mut statement = self.db.prepare("SELECT id FROM users ORDER BY login")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| self.admin_user(&id, now))
            .collect()
    }

    pub(crate) fn admin_user(&self, id: &str, now: i64) -> Result<AdminUser, ApiError> {
        let account = self.account(id, now)?;
        let (enabled, all_servers) = self.db.query_row(
            "SELECT enabled,all_servers FROM users WHERE id=?",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut statement = self
            .db
            .prepare("SELECT server_id FROM user_servers WHERE user_id=? ORDER BY server_id")?;
        let server_ids = statement
            .query_map([id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut statement = self.db.prepare("SELECT reference,amount_rub,months,confirmed_at,valid_until FROM payments WHERE user_id=? ORDER BY confirmed_at DESC,rowid DESC")?;
        let payments = statement
            .query_map([id], |row| {
                Ok(Payment {
                    reference: row.get(0)?,
                    amount_rub: row.get(1)?,
                    months: row.get(2)?,
                    confirmed_at: row.get(3)?,
                    valid_until: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let (lifetime, paid_valid_until) = self.db.query_row("SELECT EXISTS(SELECT 1 FROM lifetime_access l WHERE l.user_id=users.id AND l.enabled=1),valid_until FROM users WHERE id=?", [id], |r| Ok((r.get(0)?,r.get(1)?)))?;
        Ok(AdminUser {
            account,
            enabled,
            all_servers,
            server_ids,
            payments,
            lifetime,
            paid_valid_until,
        })
    }

    pub(crate) fn access(
        &mut self,
        user: &str,
        access: &UserAccess,
        now: i64,
    ) -> Result<AdminUser, ApiError> {
        if access.all_servers && !access.server_ids.is_empty() {
            return Err(ApiError::bad("Выберите все серверы или конкретный список"));
        }
        let tx = self.db.transaction()?;
        if tx.execute(
            "UPDATE users SET enabled=?,all_servers=? WHERE id=?",
            params![access.enabled, access.all_servers, user],
        )? == 0
        {
            return Err(ApiError::missing());
        }
        tx.execute("DELETE FROM user_servers WHERE user_id=?", [user])?;
        for id in &access.server_ids {
            if !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM servers WHERE id=?)",
                [id],
                |row| row.get::<_, bool>(0),
            )? {
                return Err(ApiError::bad("Сервер не найден"));
            }
            tx.execute(
                "INSERT OR IGNORE INTO user_servers(user_id,server_id) VALUES(?,?)",
                params![user, id],
            )?;
        }
        tx.commit()?;
        self.admin_user(user, now)
    }

    pub(crate) fn payment(
        &mut self,
        user: &str,
        payment: &ConfirmPayment,
        now: i64,
    ) -> Result<AdminUser, ApiError> {
        if payment.reference.starts_with("request:") {
            return Err(ApiError::bad(
                "Для заявки используйте подтверждение в разделе оплаты",
            ));
        }
        let tx = self.db.transaction()?;
        record_payment(&tx, user, payment, now)?;
        tx.commit()?;
        self.admin_user(user, now)
    }

    pub(crate) fn enroll(
        &mut self,
        user: &str,
        device: &mousevpn_account_client::EnrollRequest,
        now: i64,
    ) -> Result<Account, ApiError> {
        printable(&device.name, 80)?;
        if !matches!(device.platform.as_str(), "android" | "windows" | "linux") {
            return Err(ApiError::bad("Неверная платформа"));
        }
        let key = canonical_key(&device.public_key)?;
        let tx = self.db.transaction()?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT user_id FROM device_owners WHERE public_key=?",
                [&key],
                |r| r.get(0),
            )
            .optional()?;
        if previous.is_some_and(|owner| owner != user) {
            return Err(ApiError::conflict("Ключ уже принадлежит другому аккаунту"));
        }
        let owner: Option<String> = tx
            .query_row(
                "SELECT user_id FROM devices WHERE public_key=?",
                [&key],
                |row| row.get(0),
            )
            .optional()?;
        match owner {
            Some(owner) if owner != user => {
                return Err(ApiError::conflict("Ключ уже зарегистрирован"))
            }
            Some(_) => {}
            None => {
                let count: usize = tx.query_row(
                    "SELECT COUNT(*) FROM devices WHERE user_id=?",
                    [user],
                    |row| row.get(0),
                )?;
                if count >= DEVICE_LIMIT {
                    return Err(ApiError::conflict(
                        "Уже зарегистрированы два устройства. Сначала отключите одно из них.",
                    ));
                }
                tx.execute("INSERT INTO devices(id,user_id,name,platform,public_key,created_at) VALUES(?,?,?,?,?,?)", params![Uuid::new_v4().to_string(),user,device.name,device.platform,key,now])?;
            }
        }
        tx.execute("INSERT INTO device_owners VALUES(?,?,?) ON CONFLICT(public_key) DO UPDATE SET name=excluded.name", params![key,user,device.name])?;
        tx.commit()?;
        self.account(user, now)
    }

    pub(crate) fn revoke(&self, user: &str, id: &str, now: i64) -> Result<Account, ApiError> {
        if self.db.execute(
            "DELETE FROM devices WHERE id=? AND user_id=?",
            params![id, user],
        )? == 0
        {
            return Err(ApiError::missing());
        }
        self.account(user, now)
    }

    pub(crate) fn servers(&self) -> Result<Vec<AdminServer>, ApiError> {
        let mut statement = self.db.prepare("SELECT id,name,endpoint,public_key,protocol,enabled,last_seen FROM servers ORDER BY name,id")?;
        let mut result = statement
            .query_map([], |row| {
                Ok(AdminServer {
                    server: server_row(row)?,
                    enabled: row.get(5)?,
                    last_seen: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for server in &mut result {
            self.fill_online(&mut server.server, crate::now())?;
        }
        Ok(result)
    }

    pub(crate) fn create_server(&self, input: &ServerInput) -> Result<(String, String), ApiError> {
        validate_server(input)?;
        let id = Uuid::new_v4().to_string();
        let token = random_token();
        self.db.execute("INSERT INTO servers(id,name,endpoint,public_key,protocol,enabled,token_hash) VALUES(?,?,?,?,?,?,?)", params![id,input.name,input.endpoint,canonical_key(&input.public_key)?,input.protocol,input.enabled,hash_token(&token)])?;
        Ok((id, token))
    }

    pub(crate) fn update_server(&self, id: &str, input: &ServerInput) -> Result<(), ApiError> {
        validate_server(input)?;
        if self.db.execute(
            "UPDATE servers SET name=?,endpoint=?,public_key=?,protocol=?,enabled=? WHERE id=?",
            params![
                input.name,
                input.endpoint,
                canonical_key(&input.public_key)?,
                input.protocol,
                input.enabled,
                id
            ],
        )? == 0
        {
            return Err(ApiError::missing());
        }
        Ok(())
    }

    pub(crate) fn snapshot(&self, token: &str, now: i64) -> Result<NodeSnapshot, ApiError> {
        let (id, key, enabled): (String, String, bool) = self
            .db
            .query_row(
                "SELECT id,public_key,enabled FROM servers WHERE token_hash=?",
                [hash_token(token)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(ApiError::unauthorized)?;
        self.db.execute(
            "UPDATE servers SET last_seen=? WHERE id=?",
            params![now, id],
        )?;
        let until = now + NODE_LEASE_SECONDS;
        let mut statement = self.db.prepare("SELECT d.name,d.platform,d.public_key,CASE WHEN l.enabled=1 THEN 253402300799 ELSE u.valid_until END FROM devices d JOIN users u ON u.id=d.user_id LEFT JOIN lifetime_access l ON l.user_id=u.id WHERE u.enabled=1 AND (u.valid_until>? OR l.enabled=1) AND (?=1) AND (u.all_servers=1 OR EXISTS(SELECT 1 FROM user_servers a WHERE a.user_id=u.id AND a.server_id=?)) ORDER BY d.id")?;
        let devices = statement
            .query_map(params![now, enabled, id], |row| {
                Ok(NodeDevice {
                    name: row.get(0)?,
                    platform: row.get(1)?,
                    public_key: row.get(2)?,
                    valid_until: u64::try_from(row.get::<_, i64>(3)?.min(until)).unwrap_or(0),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(NodeSnapshot {
            server_id: id,
            server_public_key: key,
            generated_at: u64::try_from(now).unwrap_or(0),
            lease_until: u64::try_from(until).unwrap_or(0),
            devices,
        })
    }
}

pub(crate) fn hash_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
pub(crate) fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
pub(crate) fn normalized_login(login: &str) -> Result<String, ApiError> {
    let login = login.trim().to_ascii_lowercase();
    if login.is_empty()
        || login.len() > if login.contains('@') { 254 } else { 64 }
        || !login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-@+%".contains(&byte))
    {
        return Err(ApiError::bad(
            "Введите почту или логин из латинских букв, цифр и . _ - @ + %",
        ));
    }
    Ok(login)
}
fn printable(value: &str, limit: usize) -> Result<(), ApiError> {
    if value.trim().is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(ApiError::bad("Пустое или слишком длинное название"));
    }
    Ok(())
}
fn canonical_key(value: &str) -> Result<String, ApiError> {
    decode_public_key(value)
        .map(|key| encode_public_key(&key))
        .map_err(|_| ApiError::bad("Неверный публичный ключ"))
}
fn validate_server(input: &ServerInput) -> Result<(), ApiError> {
    printable(&input.name, 80)?;
    let endpoint = input
        .endpoint
        .parse::<std::net::SocketAddr>()
        .map_err(|_| ApiError::bad("Нужен адрес IPv4:порт"))?;
    if !endpoint.is_ipv4() || endpoint.port() == 0 {
        return Err(ApiError::bad("Нужен адрес IPv4:порт"));
    }
    canonical_key(&input.public_key)?;
    if !matches!(
        input.protocol.as_str(),
        "legacy" | "morph_quiet" | "morph_balanced" | "morph_paranoid"
    ) {
        return Err(ApiError::bad("Неверный протокол"));
    }
    Ok(())
}
fn server_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Server> {
    Ok(Server {
        online_devices: None,
        online_updated_at: None,
        id: row.get(0)?,
        name: row.get(1)?,
        endpoint: row.get(2)?,
        public_key: row.get(3)?,
        protocol: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calendar_months_extend_paid_time_and_expired_renewals_start_now() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut store = Store::open(&temp.path().join("db.sqlite")).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-01-31T12:15:00Z")
            .unwrap()
            .timestamp();
        let user = store.create_user("alice", "hash", now).unwrap();
        let payment = ConfirmPayment {
            reference: "first".to_owned(),
            amount_rub: 900,
            months: 3,
        };
        let paid = store.payment(&user.account.id, &payment, now).unwrap();
        assert_eq!(
            DateTime::<Utc>::from_timestamp(paid.account.valid_until, 0)
                .unwrap()
                .to_rfc3339(),
            "2026-04-30T12:15:00+00:00"
        );
        let next = store
            .payment(
                &user.account.id,
                &ConfirmPayment {
                    reference: "second".to_owned(),
                    amount_rub: 900,
                    months: 3,
                },
                now + 86400,
            )
            .unwrap();
        assert_eq!(
            DateTime::<Utc>::from_timestamp(next.account.valid_until, 0)
                .unwrap()
                .to_rfc3339(),
            "2026-07-30T12:15:00+00:00"
        );
        let later = DateTime::parse_from_rfc3339("2026-09-01T10:00:00Z")
            .unwrap()
            .timestamp();
        let renewed = store
            .payment(
                &user.account.id,
                &ConfirmPayment {
                    reference: "third".to_owned(),
                    amount_rub: 900,
                    months: 3,
                },
                later,
            )
            .unwrap();
        assert_eq!(
            DateTime::<Utc>::from_timestamp(renewed.account.valid_until, 0)
                .unwrap()
                .to_rfc3339(),
            "2026-12-01T10:00:00+00:00"
        );
        assert!(
            !store
                .account(&user.account.id, renewed.account.valid_until)
                .unwrap()
                .active
        );
        drop(store);
        let reopened = Store::open(&temp.path().join("db.sqlite")).unwrap();
        assert_eq!(
            reopened
                .admin_user(&user.account.id, later)
                .unwrap()
                .payments
                .len(),
            3
        );
    }
}

/// Adds calendar months exactly once for a payment reference, inside the caller's transaction.
pub(crate) fn record_payment(
    tx: &Connection,
    user: &str,
    payment: &ConfirmPayment,
    now: i64,
) -> Result<i64, ApiError> {
    printable(&payment.reference, 120)?;
    if !(3..=120).contains(&payment.months)
        || payment.amount_rub != MONTH_PRICE * i64::from(payment.months)
    {
        return Err(ApiError::bad(
            "Минимум 3 месяца; сумма должна быть 300 ₽ × число месяцев",
        ));
    }
    let previous: Option<(i64, u32)> = tx
        .query_row(
            "SELECT amount_rub,months FROM payments WHERE user_id=? AND reference=?",
            params![user, payment.reference],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some(previous) = previous {
        if previous != (payment.amount_rub, payment.months) {
            return Err(ApiError::conflict(
                "Этот платёж уже подтверждён с другой суммой",
            ));
        }
    } else {
        let until: i64 = tx
            .query_row("SELECT valid_until FROM users WHERE id=?", [user], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or_else(ApiError::missing)?;
        let base = DateTime::<Utc>::from_timestamp(until.max(now), 0)
            .ok_or_else(|| ApiError::bad("Неверная дата подписки"))?;
        let until = base
            .checked_add_months(Months::new(payment.months))
            .ok_or_else(|| ApiError::bad("Слишком большой срок"))?
            .timestamp();
        tx.execute("INSERT INTO payments(user_id,reference,amount_rub,months,confirmed_at,valid_until) VALUES(?,?,?,?,?,?)", params![user,payment.reference,payment.amount_rub,payment.months,now,until])?;
        tx.execute(
            "UPDATE users SET valid_until=? WHERE id=?",
            params![until, user],
        )?;
    }
    Ok(tx.query_row(
        "SELECT valid_until FROM payments WHERE user_id=? AND reference=?",
        params![user, payment.reference],
        |row| row.get(0),
    )?)
}

impl Store {
    pub(crate) fn report_online(&self, id: &str, count: u32, at: i64) -> Result<(), ApiError> {
        self.db.execute("INSERT INTO node_status(server_id,online_devices,updated_at) VALUES(?,?,?) ON CONFLICT(server_id) DO UPDATE SET online_devices=excluded.online_devices,updated_at=excluded.updated_at",params![id,count,at])?;
        Ok(())
    }
    fn fill_online(&self, server: &mut Server, at: i64) -> Result<(), ApiError> {
        if let Some((count, updated)) = self
            .db
            .query_row(
                "SELECT online_devices,updated_at FROM node_status WHERE server_id=?",
                [&server.id],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            server.online_updated_at = Some(updated);
            if (0..=90).contains(&(at - updated)) {
                server.online_devices = Some(count);
            }
        }
        Ok(())
    }
}
