//! Central accounts, manually confirmed payments and per-user server allocation.

mod billing;
mod error;
mod grants;
mod invites;
mod store;
mod support;
mod usage;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use argon2::{
    password_hash::{PasswordHash, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use mousevpn_account_client::{Account, EnrollRequest, LoginRequest, LoginResponse, NodeSnapshot};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use zeroize::Zeroize;

use error::ApiError;
pub use store::Store;
use store::{AdminServer, AdminUser, ConfirmPayment, CreateUser, ServerInput, UserAccess};

#[derive(Clone)]
struct App {
    store: Arc<Mutex<Store>>,
    admin: Arc<str>,
    dummy_hash: Arc<str>,
    passwords: Arc<Semaphore>,
    login_attempts: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

impl App {
    fn db(&self) -> Result<MutexGuard<'_, Store>, ApiError> {
        self.store.lock().map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Хранилище недоступно".to_owned(),
            )
        })
    }
    fn admin(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        if bool::from(bearer(headers)?.as_bytes().ct_eq(self.admin.as_bytes())) {
            Ok(())
        } else {
            Err(ApiError::unauthorized())
        }
    }
    fn user(&self, headers: &HeaderMap) -> Result<String, ApiError> {
        self.db()?.authenticate(bearer(headers)?, now())
    }
    fn login_limit(&self, login: &str) -> Result<(), ApiError> {
        let mut attempts = self
            .login_attempts
            .lock()
            .map_err(|_| ApiError::unauthorized())?;
        attempts.retain(|_, (at, _)| at.elapsed() < Duration::from_secs(300));
        if attempts.len() >= 1024 && !attempts.contains_key(login) {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "Повторите вход позже".to_owned(),
            ));
        }
        let total: u32 = attempts.values().map(|(_, count)| *count).sum();
        let (_, count) = attempts
            .entry(login.to_owned())
            .or_insert((Instant::now(), 0));
        if *count >= 10 || total >= 100 {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "Слишком много попыток. Повторите вход через 5 минут.".to_owned(),
            ));
        }
        *count += 1;
        Ok(())
    }
}

/// Builds the controller API and its administration UI. Bind it to loopback
/// behind an HTTPS reverse proxy; account and node clients refuse remote HTTP.
///
/// # Errors
/// Returns an error if the owner token is too short or hashing is unavailable.
pub fn router(store: Store, admin_token: &str) -> Result<Router, String> {
    router_with_site(store, admin_token, None)
}

/// Like [`router`], and also serves the landing page from `public_dir` under
/// `/site`, open only to visitors who came through an invite link.
///
/// # Errors
/// Returns an error if the owner token is too short or hashing is unavailable.
pub fn router_with_site(
    store: Store,
    admin_token: &str,
    public_dir: Option<PathBuf>,
) -> Result<Router, String> {
    if admin_token.len() < 32 || admin_token.chars().any(char::is_whitespace) {
        return Err("admin token needs at least 32 non-whitespace characters".to_owned());
    }
    let app = App {
        store: Arc::new(Mutex::new(store)),
        admin: Arc::from(admin_token),
        dummy_hash: Arc::from(password_hash("invalid-password")?),
        passwords: Arc::new(Semaphore::new(2)),
        login_attempts: Arc::default(),
    };
    let site = public_dir.map(|directory| invites::Site {
        app: app.clone(),
        files: tower_http::services::ServeDir::new(directory),
    });
    let router = Router::new()
        .route("/", get(|| async { Html(include_str!("admin.html")) }))
        .route(
            "/admin.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("admin.js"),
                )
            }),
        )
        .route(
            "/admin.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("admin.css"),
                )
            }),
        )
        .route("/v1/login", post(login))
        .route("/v1/signup", post(signup))
        .route("/v1/logout", post(logout))
        .route("/v1/account", get(account))
        .route("/v1/account/devices", post(enroll))
        .route("/v1/account/devices/{id}", delete(revoke))
        .route(
            "/v1/node/snapshot",
            get(snapshot).post(snapshot_with_status),
        )
        .route("/v1/admin/users", get(users).post(create_user))
        .route("/v1/admin/users/{id}/access", put(access))
        .route("/v1/admin/users/{id}/payments", post(payment))
        .route("/v1/admin/users/{id}/password", put(reset_password))
        .route(
            "/v1/admin/users/{user}/devices/{device}",
            delete(admin_revoke),
        )
        .route("/v1/admin/servers", get(servers).post(create_server))
        .route("/v1/admin/servers/{id}", put(update_server))
        .merge(support::routes())
        .merge(billing::routes())
        .merge(usage::routes())
        .merge(grants::routes())
        .merge(invites::routes())
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(app);
    // The landing page keeps the reverse proxy's caching and CSP headers.
    Ok(match site {
        Some(site) => router.nest_service(
            "/site",
            Router::new().fallback(invites::site).with_state(site),
        ),
        None => router,
    })
}

async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            axum::http::HeaderValue::from_static(value),
        );
    }
    response
}

#[derive(Deserialize)]
struct SignupRequest {
    email: String,
    password: String,
}

async fn signup(
    State(app): State<App>,
    headers: HeaderMap,
    Json(mut request): Json<SignupRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Only the trusted HTTPS proxy sets this header; the service port is private.
    let source = headers
        .get("x-relay-client-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<std::net::IpAddr>().ok())
        .map_or_else(|| "local".to_owned(), |v| v.to_string());
    app.login_limit(&format!("signup/{source}"))?;
    let email = store::normalized_login(&request.email)?;
    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| ApiError::bad("Введите почту"))?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !domain.contains('.')
        || domain.contains('@')
        || domain.split('.').any(|part| {
            part.is_empty()
                || part.starts_with('-')
                || part.ends_with('-')
                || !part.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'-')
        })
    {
        return Err(ApiError::bad("Введите корректную почту"));
    }
    validate_password(&request.password)?;
    let permit = app
        .passwords
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "Повторите позже".to_owned()))?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = password_hash(&request.password);
        request.password.zeroize();
        result
    })
    .await
    .map_err(|_| ApiError::bad("Ошибка создания заявки"))?
    .map_err(ApiError::bad)?;
    let invite = invites::cookie(&headers, invites::COOKIE);
    let (user, trial_days) = app.db()?.signup(&email, &hash, invite, now())?;
    if trial_days > 0 {
        return Ok(Json(serde_json::json!({
            "login": email,
            "trial_days": trial_days,
            "valid_until": user.account.valid_until,
            "message": "Аккаунт создан, пробный период уже действует. Войдите в приложение с этой почтой и паролем.",
        })));
    }
    Ok(Json(
        serde_json::json!({"login":email,"trial_days":0,"message":"Заявка принята. Свяжитесь с владельцем для оплаты. VPN-доступ появится после подтверждения оплаты."}),
    ))
}

async fn login(
    State(app): State<App>,
    Json(mut request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let login = store::normalized_login(&request.login)?;
    app.login_limit(&login)?;
    if request.password.len() > 256 {
        request.password.zeroize();
        return Err(ApiError::invalid_credentials());
    }
    let found = app.db()?.password_hash(&login)?;
    let hash = found
        .as_ref()
        .map_or_else(|| app.dummy_hash.to_string(), |(_, hash)| hash.clone());
    let permit = app.passwords.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Повторите вход позже".to_owned(),
        )
    })?;
    let accepted = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let accepted = PasswordHash::new(&hash).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(request.password.as_bytes(), &hash)
                .is_ok()
        });
        request.password.zeroize();
        accepted
    })
    .await
    .map_err(|_| ApiError::unauthorized())?;
    let (id, _) = found
        .filter(|_| accepted)
        .ok_or_else(ApiError::invalid_credentials)?;
    let db = app.db()?;
    let token = db.session(&id, now())?;
    Ok(Json(LoginResponse {
        token,
        account: db.account(&id, now())?,
    }))
}

async fn logout(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    app.db()?.logout(bearer(&headers)?)?;
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn account(State(app): State<App>, headers: HeaderMap) -> Result<Json<Account>, ApiError> {
    let user = app.user(&headers)?;
    Ok(Json(app.db()?.account(&user, now())?))
}
async fn enroll(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<EnrollRequest>,
) -> Result<Json<Account>, ApiError> {
    let user = app.user(&headers)?;
    Ok(Json(app.db()?.enroll(&user, &request, now())?))
}
async fn revoke(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Account>, ApiError> {
    let user = app.user(&headers)?;
    Ok(Json(app.db()?.revoke(&user, &id, now())?))
}
async fn snapshot(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<NodeSnapshot>, ApiError> {
    Ok(Json(app.db()?.snapshot(bearer(&headers)?, now())?))
}
async fn users(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminUser>>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.users(now())?))
}
async fn create_user(
    State(app): State<App>,
    headers: HeaderMap,
    Json(mut request): Json<CreateUser>,
) -> Result<Json<AdminUser>, ApiError> {
    app.admin(&headers)?;
    store::normalized_login(&request.login)?;
    validate_password(&request.password)?;
    let login = request.login.clone();
    let permit = app
        .passwords
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "Повторите позже".to_owned()))?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = password_hash(&request.password);
        request.password.zeroize();
        result
    })
    .await
    .map_err(|_| ApiError::bad("Ошибка создания аккаунта"))?
    .map_err(ApiError::bad)?;
    Ok(Json(app.db()?.create_user(&login, &hash, now())?))
}
async fn access(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UserAccess>,
) -> Result<Json<AdminUser>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.access(&id, &request, now())?))
}
async fn payment(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<ConfirmPayment>,
) -> Result<Json<AdminUser>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.payment(&id, &request, now())?))
}
async fn admin_revoke(
    State(app): State<App>,
    headers: HeaderMap,
    Path((user, device)): Path<(String, String)>,
) -> Result<Json<AdminUser>, ApiError> {
    app.admin(&headers)?;
    let db = app.db()?;
    db.revoke(&user, &device, now())?;
    Ok(Json(db.admin_user(&user, now())?))
}
#[derive(Deserialize)]
struct PasswordRequest {
    password: String,
}
async fn reset_password(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut request): Json<PasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    app.admin(&headers)?;
    validate_password(&request.password)?;
    let permit = app
        .passwords
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "Повторите позже".to_owned()))?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = password_hash(&request.password);
        request.password.zeroize();
        result
    })
    .await
    .map_err(|_| ApiError::bad("Ошибка смены пароля"))?
    .map_err(ApiError::bad)?;
    let mut db = app.db()?;
    let tx = db.db.transaction()?;
    if tx.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        rusqlite::params![hash, id],
    )? == 0
    {
        return Err(ApiError::missing());
    }
    tx.execute("DELETE FROM sessions WHERE user_id=?", [id])?;
    tx.commit()?;
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn servers(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminServer>>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.servers()?))
}
async fn create_server(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<ServerInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    app.admin(&headers)?;
    let (id, token) = app.db()?.create_server(&request)?;
    Ok(Json(serde_json::json!({"id":id,"node_token":token})))
}
async fn update_server(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<ServerInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    app.admin(&headers)?;
    app.db()?.update_server(&id, &request)?;
    Ok(Json(serde_json::json!({"ok":true})))
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| value.len() <= 256)
        .ok_or_else(ApiError::unauthorized)
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn validate_password(password: &str) -> Result<(), ApiError> {
    if !(10..=256).contains(&password.len()) {
        return Err(ApiError::bad("Пароль должен содержать от 10 до 256 байт"));
    }
    Ok(())
}
fn password_hash(password: &str) -> Result<String, String> {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|error| error.to_string())?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| error.to_string())
}

#[derive(serde::Deserialize)]
struct NodeStatus {
    online_devices: u32,
}
async fn snapshot_with_status(
    State(app): State<App>,
    headers: HeaderMap,
    Json(report): Json<NodeStatus>,
) -> Result<Json<mousevpn_account_client::NodeSnapshot>, ApiError> {
    let db = app.db()?;
    let at = now();
    let snapshot = db.snapshot(bearer(&headers)?, at)?;
    db.report_online(&snapshot.server_id, report.online_devices, at)?;
    Ok(Json(snapshot))
}
