//! Invite links open the closed landing page and may carry a free trial.
//!
//! A visitor opens `/?invite=<code>`; the code is stored in an `HttpOnly` cookie
//! and checked on every page request, so revoking an invite closes the site
//! for everyone who came through it. Without a working invite the site answers
//! 404, as if nothing were there.
use std::convert::Infallible;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get},
    Json, Router,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use tower_http::services::ServeDir;

use crate::{
    error::ApiError,
    now,
    store::{normalized_login, random_token, AdminUser, Store},
    App,
};

pub(crate) const COOKIE: &str = "mv_invite";
const COOKIE_AGE: u32 = 365 * 86_400;
/// Images for link previews and direct build links stay reachable without an invite.
const OPEN_PREFIXES: [&str; 2] = ["/assets/", "/downloads/"];

#[derive(Deserialize)]
pub(crate) struct NewInvite {
    #[serde(default)]
    code: String,
    #[serde(default)]
    note: String,
    trial_days: u32,
    max_signups: u32,
}

#[derive(Serialize)]
pub(crate) struct Invite {
    code: String,
    note: String,
    trial_days: u32,
    max_signups: u32,
    signups: Vec<String>,
    created_at: i64,
    revoked_at: Option<i64>,
}

/// The invite an account registered through, shown in the owner's user card.
#[derive(Serialize)]
pub(crate) struct InviteSource {
    code: String,
    note: String,
    trial_days: u32,
    at: i64,
}

pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/v1/invite", get(offer))
        .route("/v1/admin/invites", get(list).post(create))
        .route("/v1/admin/invites/{code}", delete(revoke))
}

async fn offer(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let trial_days = match cookie(&headers, COOKIE) {
        Some(code) => app.db()?.trial_offer(code)?,
        None => 0,
    };
    Ok(Json(serde_json::json!({ "trial_days": trial_days })))
}
async fn list(State(app): State<App>, headers: HeaderMap) -> Result<Json<Vec<Invite>>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.invites()?))
}
async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<NewInvite>,
) -> Result<Json<Invite>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.create_invite(&request, now())?))
}
async fn revoke(
    State(app): State<App>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Result<Json<Invite>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.revoke_invite(&code, now())?))
}

/// Serves the landing page only to visitors holding a working invite.
#[derive(Clone)]
pub(crate) struct Site {
    pub(crate) app: App,
    pub(crate) files: ServeDir,
}

pub(crate) async fn site(State(site): State<Site>, request: Request) -> Response {
    let path = request.uri().path();
    if OPEN_PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
        return serve(&site.files, request).await;
    }
    let open = |code: &str| {
        site.app
            .db()
            .and_then(|db| db.invite_open(code))
            .unwrap_or(false)
    };
    let offered = request
        .uri()
        .query()
        .and_then(|query| query_param(query, "invite"))
        .map(|code| code.trim().to_ascii_lowercase())
        .filter(|code| open(code));
    if let Some(code) = offered {
        let secure = request
            .headers()
            .get("x-forwarded-proto")
            .is_some_and(|value| value == "https");
        let mut response = serve(&site.files, request).await;
        let cookie = format!(
            "{COOKIE}={code}; Max-Age={COOKIE_AGE}; Path=/; HttpOnly; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    if cookie(request.headers(), COOKIE).is_some_and(open) {
        // Revalidate every time, so a revoked invite cannot keep a cached copy open.
        let mut response = serve(&site.files, request).await;
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert(header::VARY, HeaderValue::from_static("Cookie"));
        return response;
    }
    (
        StatusCode::NOT_FOUND,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::HeaderName::from_static("x-robots-tag"), "noindex"),
        ],
        "404 page not found\n",
    )
        .into_response()
}

async fn serve(files: &ServeDir, request: Request) -> Response {
    let result: Result<_, Infallible> = files.clone().oneshot(request).await;
    match result {
        Ok(response) => response.map(Body::new),
        Err(never) => match never {},
    }
}

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn valid_code(code: &str) -> bool {
    (4..=40).contains(&code.len())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl Store {
    pub(crate) fn invite_open(&self, code: &str) -> Result<bool, ApiError> {
        if !valid_code(code) {
            return Ok(false);
        }
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM invites WHERE code=? AND revoked_at IS NULL)",
            [code],
            |row| row.get(0),
        )?)
    }

    /// Trial days a new signup through this invite would receive right now.
    pub(crate) fn trial_offer(&self, code: &str) -> Result<u32, ApiError> {
        if !valid_code(code) {
            return Ok(0);
        }
        Ok(self
            .db
            .query_row(
                "SELECT trial_days FROM invites i WHERE code=? AND revoked_at IS NULL AND max_signups>(SELECT COUNT(*) FROM invite_signups s WHERE s.code=i.code)",
                [code],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    pub(crate) fn invites(&self) -> Result<Vec<Invite>, ApiError> {
        let mut query = self.db.prepare(
            "SELECT code FROM invites ORDER BY revoked_at IS NOT NULL,created_at DESC,rowid DESC LIMIT 200",
        )?;
        let codes = query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        codes.iter().map(|code| self.invite(code)).collect()
    }

    fn invite(&self, code: &str) -> Result<Invite, ApiError> {
        let mut invite = self
            .db
            .query_row(
                "SELECT code,note,trial_days,max_signups,created_at,revoked_at FROM invites WHERE code=?",
                [code],
                |row| {
                    Ok(Invite {
                        code: row.get(0)?,
                        note: row.get(1)?,
                        trial_days: row.get(2)?,
                        max_signups: row.get(3)?,
                        signups: Vec::new(),
                        created_at: row.get(4)?,
                        revoked_at: row.get(5)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(ApiError::missing)?;
        let mut query = self.db.prepare(
            "SELECT u.login FROM invite_signups s JOIN users u ON u.id=s.user_id WHERE s.code=? ORDER BY s.at,u.login",
        )?;
        invite.signups = query
            .query_map([code], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(invite)
    }

    pub(crate) fn create_invite(&self, request: &NewInvite, at: i64) -> Result<Invite, ApiError> {
        let note = request.note.trim();
        if note.chars().count() > 200 || note.chars().any(char::is_control) {
            return Err(ApiError::bad("Комментарий — до 200 символов"));
        }
        if request.trial_days > 365 {
            return Err(ApiError::bad("Пробный период — от 0 до 365 дней"));
        }
        if !(1..=1000).contains(&request.max_signups) {
            return Err(ApiError::bad("Регистраций по ссылке — от 1 до 1000"));
        }
        let custom = request.code.trim().to_ascii_lowercase();
        let code = if custom.is_empty() {
            let token = random_token();
            // Both halves come from separate random UUIDs; skip their version digits.
            format!("{}{}", &token[..8], &token[32..40])
        } else if valid_code(&custom) {
            custom
        } else {
            return Err(ApiError::bad(
                "Код — от 4 до 40 латинских букв, цифр или дефисов",
            ));
        };
        if self
            .db
            .execute(
                "INSERT OR IGNORE INTO invites(code,note,trial_days,max_signups,created_at) VALUES(?,?,?,?,?)",
                params![code, note, request.trial_days, request.max_signups, at],
            )?
            == 0
        {
            return Err(ApiError::conflict("Такой код уже есть"));
        }
        self.invite(&code)
    }

    pub(crate) fn revoke_invite(&self, code: &str, at: i64) -> Result<Invite, ApiError> {
        self.db.execute(
            "UPDATE invites SET revoked_at=? WHERE code=? AND revoked_at IS NULL",
            params![at, code],
        )?;
        self.invite(code)
    }

    pub(crate) fn invite_source(&self, user: &str) -> Result<Option<InviteSource>, ApiError> {
        Ok(self
            .db
            .query_row(
                "SELECT s.code,i.note,s.trial_days,s.at FROM invite_signups s JOIN invites i ON i.code=s.code WHERE s.user_id=?",
                [user],
                |row| {
                    Ok(InviteSource {
                        code: row.get(0)?,
                        note: row.get(1)?,
                        trial_days: row.get(2)?,
                        at: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Creates a site signup; a working invite with free places records the
    /// account and starts its trial in the same transaction.
    pub(crate) fn signup(
        &mut self,
        login: &str,
        password_hash: &str,
        invite: Option<&str>,
        at: i64,
    ) -> Result<(AdminUser, u32), ApiError> {
        let login = normalized_login(login)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE login=?)",
            [&login],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(ApiError::conflict("Логин уже занят"));
        }
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO users(id,login,password_hash) VALUES(?,?,?)",
            params![id, login, password_hash],
        )?;
        let mut trial = 0;
        if let Some(code) = invite.filter(|code| valid_code(code)) {
            let offer: Option<u32> = tx
                .query_row(
                    "SELECT trial_days FROM invites i WHERE code=? AND revoked_at IS NULL AND max_signups>(SELECT COUNT(*) FROM invite_signups s WHERE s.code=i.code)",
                    [code],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(days) = offer {
                tx.execute(
                    "INSERT INTO invite_signups(user_id,code,at,trial_days) VALUES(?,?,?,?)",
                    params![id, code, at, days],
                )?;
                if days > 0 {
                    let until = at + i64::from(days) * 86_400;
                    tx.execute("INSERT INTO day_grants(user_id,reference,days,note,granted_at,valid_until) VALUES(?,?,?,?,?,?)", params![id, uuid::Uuid::new_v4().to_string(), days, "Пробный период по приглашению", at, until])?;
                    tx.execute(
                        "UPDATE users SET valid_until=? WHERE id=?",
                        params![until, id],
                    )?;
                    trial = days;
                }
            }
        }
        tx.commit()?;
        Ok((self.admin_user(&id, at)?, trial))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_and_queries_are_parsed_by_exact_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("x_mv_invite=a; mv_invite=friends-14"),
        );
        assert_eq!(cookie(&headers, COOKIE), Some("friends-14"));
        assert_eq!(query_param("utm=1&invite=abcd", "invite"), Some("abcd"));
        assert_eq!(query_param("xinvite=abcd", "invite"), None);
        assert!(!valid_code("ABCD") && !valid_code("abc") && !valid_code("a b c d"));
    }
}
