//! Manual day grants are separate from the monthly payment ledger.
use crate::{
    error::ApiError,
    now,
    store::{AdminUser, Store},
    App,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct GrantDays {
    reference: String,
    days: u32,
    #[serde(default)]
    note: String,
}
#[derive(Serialize)]
pub(crate) struct DayGrant {
    reference: String,
    days: u32,
    note: String,
    granted_at: i64,
    valid_until: i64,
}
pub(crate) fn routes() -> Router<App> {
    Router::new().route("/v1/admin/users/{id}/days", post(grant))
}
async fn grant(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<GrantDays>,
) -> Result<Json<AdminUser>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.grant_days(&id, &request, now())?))
}
impl Store {
    pub(crate) fn day_grants(&self, user: &str) -> Result<Vec<DayGrant>, ApiError> {
        let mut query = self.db.prepare("SELECT reference,days,note,granted_at,valid_until FROM day_grants WHERE user_id=? ORDER BY granted_at DESC,rowid DESC LIMIT 50")?;
        let grants = query
            .query_map([user], |r| {
                Ok(DayGrant {
                    reference: r.get(0)?,
                    days: r.get(1)?,
                    note: r.get(2)?,
                    granted_at: r.get(3)?,
                    valid_until: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(grants)
    }
    pub(crate) fn grant_days(
        &mut self,
        user: &str,
        request: &GrantDays,
        at: i64,
    ) -> Result<AdminUser, ApiError> {
        let reference = uuid::Uuid::parse_str(&request.reference)
            .map_err(|_| ApiError::bad("Неверная отметка выдачи доступа"))?
            .to_string();
        let note = request.note.trim();
        if !(1..=3650).contains(&request.days)
            || note.chars().count() > 200
            || note.chars().any(char::is_control)
        {
            return Err(ApiError::bad(
                "Укажите от 1 до 3650 дней и комментарий до 200 символов",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(u32, String)> = tx
            .query_row(
                "SELECT days,note FROM day_grants WHERE user_id=? AND reference=?",
                params![user, reference],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some(previous) = previous {
            if previous != (request.days, note.to_owned()) {
                return Err(ApiError::conflict(
                    "Эта выдача уже сохранена с другими параметрами",
                ));
            }
        } else {
            let until: i64 = tx
                .query_row("SELECT valid_until FROM users WHERE id=?", [user], |r| {
                    r.get(0)
                })
                .optional()?
                .ok_or_else(ApiError::missing)?;
            let until = until
                .max(at)
                .checked_add(i64::from(request.days) * 86400)
                .filter(|until| *until < 253_402_300_799)
                .ok_or_else(|| ApiError::bad("Слишком большой срок доступа"))?;
            tx.execute("INSERT INTO day_grants(user_id,reference,days,note,granted_at,valid_until) VALUES(?,?,?,?,?,?)",params![user,reference,request.days,note,at,until])?;
            tx.execute(
                "UPDATE users SET valid_until=? WHERE id=?",
                params![until, user],
            )?;
        }
        tx.commit()?;
        self.admin_user(user, at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const AT: i64 = 1_800_000_000;
    fn request(days: u32) -> GrantDays {
        GrantDays {
            reference: uuid::Uuid::new_v4().to_string(),
            days,
            note: "Пробный доступ".into(),
        }
    }

    #[test]
    fn days_extend_from_current_expiry_or_now_and_retries_do_not_double() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("accounts.sqlite");
        let mut store = Store::open(&path).unwrap();
        let user = store.create_user("days", "unused", AT).unwrap().account.id;
        let first = request(1);
        assert_eq!(
            store
                .grant_days(&user, &first, AT)
                .unwrap()
                .paid_valid_until,
            AT + 86400
        );
        assert_eq!(
            store
                .grant_days(&user, &first, AT + 1)
                .unwrap()
                .paid_valid_until,
            AT + 86400
        );
        assert_eq!(
            store
                .grant_days(&user, &request(2), AT + 1)
                .unwrap()
                .paid_valid_until,
            AT + 3 * 86400
        );
        let changed = GrantDays { days: 2, ..first };
        assert!(store.grant_days(&user, &changed, AT).is_err());
        let current = store.admin_user(&user, AT).unwrap();
        assert_eq!(current.day_grants.len(), 2);
        assert!(current.payments.is_empty());
        let later = AT + 10 * 86400;
        assert_eq!(
            store
                .grant_days(&user, &request(1), later)
                .unwrap()
                .paid_valid_until,
            later + 86400
        );
        for days in [0, 3651, u32::MAX] {
            assert!(store.grant_days(&user, &request(days), later).is_err());
        }
        assert!(store.grant_days("missing", &request(1), later).is_err());
        drop(store);
        assert_eq!(
            Store::open(&path)
                .unwrap()
                .admin_user(&user, later)
                .unwrap()
                .day_grants
                .len(),
            3
        );
    }

    #[test]
    fn days_preserve_lifetime_blocking_and_restrictions_and_migrate_v4() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("accounts.sqlite");
        let mut store = Store::open(&path).unwrap();
        let user = store
            .create_user("friend-days", "unused", AT)
            .unwrap()
            .account
            .id;
        store
            .db
            .execute(
                "UPDATE users SET enabled=0,all_servers=0 WHERE id=?",
                [&user],
            )
            .unwrap();
        store
            .db
            .execute("INSERT INTO lifetime_access VALUES(?,1)", [&user])
            .unwrap();
        let result = store.grant_days(&user, &request(1), AT).unwrap();
        assert!(result.lifetime);
        assert!(!result.account.active);
        assert!(!result.all_servers);
        assert!(!result.enabled);
        assert_eq!(result.paid_valid_until, AT + 86400);
        assert_eq!(result.account.valid_until, 253_402_300_799);
        store
            .db
            .execute(
                "UPDATE lifetime_access SET enabled=0 WHERE user_id=?",
                [&user],
            )
            .unwrap();
        store
            .db
            .execute("UPDATE users SET enabled=1 WHERE id=?", [&user])
            .unwrap();
        assert!(store.account(&user, AT).unwrap().active);
        assert!(store.account(&user, AT).unwrap().servers.is_empty());
        store
            .db
            .execute_batch("DROP TABLE day_grants; PRAGMA user_version=4;")
            .unwrap();
        drop(store);
        let reopened = Store::open(&path).unwrap();
        let result = reopened.admin_user(&user, AT).unwrap();
        assert_eq!(result.paid_valid_until, AT + 86400);
        assert!(result.day_grants.is_empty());
        assert!(!result.lifetime);
    }
}
