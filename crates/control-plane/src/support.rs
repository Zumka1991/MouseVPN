use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post, put},
    Json, Router,
};
use mousevpn_account_client::{TicketDetail, TicketMessage, TicketSummary};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;

use crate::{error::ApiError, now, store::Store, App};

pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route("/v1/account/tickets", get(user_list).post(user_create))
        .route("/v1/account/tickets/{id}", get(user_detail))
        .route("/v1/account/tickets/{id}/messages", post(user_reply))
        .route("/v1/admin/tickets", get(admin_list))
        .route("/v1/admin/tickets/{id}", get(admin_detail))
        .route("/v1/admin/tickets/{id}/messages", post(admin_reply))
        .route("/v1/admin/tickets/{id}/status", put(admin_status))
        .route("/v1/admin/users/{id}/messages", post(admin_message))
}

#[derive(Deserialize)]
struct NewTicket {
    subject: String,
    text: String,
}
#[derive(Deserialize)]
struct Reply {
    text: String,
}
#[derive(Deserialize)]
struct Page {
    before: Option<i64>,
}
#[derive(Deserialize)]
struct TicketStatus {
    status: String,
}

async fn user_list(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<Vec<TicketSummary>>, ApiError> {
    let user = app.user(&headers)?;
    Ok(Json(app.db()?.tickets(Some(&user))?))
}
async fn admin_list(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<Vec<TicketSummary>>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.tickets(None)?))
}
async fn user_create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<NewTicket>,
) -> Result<Json<TicketDetail>, ApiError> {
    let user = app.user(&headers)?;
    let mut db = app.db()?;
    let id = db.new_ticket(&user, &request.subject, &request.text, "user", now())?;
    Ok(Json(db.ticket_detail(&id, Some(&user), None, true)?))
}
async fn admin_message(
    State(app): State<App>,
    headers: HeaderMap,
    Path(user): Path<String>,
    Json(request): Json<NewTicket>,
) -> Result<Json<TicketDetail>, ApiError> {
    app.admin(&headers)?;
    let mut db = app.db()?;
    let id = db.new_ticket(&user, &request.subject, &request.text, "admin", now())?;
    Ok(Json(db.ticket_detail(&id, None, None, true)?))
}
async fn user_detail(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> Result<Json<TicketDetail>, ApiError> {
    let user = app.user(&headers)?;
    Ok(Json(app.db()?.ticket_detail(
        &id,
        Some(&user),
        page.before,
        page.before.is_none(),
    )?))
}
async fn admin_detail(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> Result<Json<TicketDetail>, ApiError> {
    app.admin(&headers)?;
    Ok(Json(app.db()?.ticket_detail(
        &id,
        None,
        page.before,
        page.before.is_none(),
    )?))
}
async fn user_reply(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<Reply>,
) -> Result<Json<TicketDetail>, ApiError> {
    let user = app.user(&headers)?;
    let mut db = app.db()?;
    db.ticket_reply(&id, Some(&user), &request.text, now())?;
    Ok(Json(db.ticket_detail(&id, Some(&user), None, true)?))
}
async fn admin_reply(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<Reply>,
) -> Result<Json<TicketDetail>, ApiError> {
    app.admin(&headers)?;
    let mut db = app.db()?;
    db.ticket_reply(&id, None, &request.text, now())?;
    Ok(Json(db.ticket_detail(&id, None, None, true)?))
}
async fn admin_status(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<TicketStatus>,
) -> Result<Json<TicketDetail>, ApiError> {
    app.admin(&headers)?;
    if !matches!(request.status.as_str(), "open" | "closed") {
        return Err(ApiError::bad("Неверный статус"));
    }
    let db = app.db()?;
    if db.db.execute(
        "UPDATE tickets SET status=?,updated_at=? WHERE id=?",
        params![request.status, now(), id],
    )? == 0
    {
        return Err(ApiError::missing());
    }
    Ok(Json(db.ticket_detail(&id, None, None, true)?))
}

impl Store {
    fn tickets(&self, user: Option<&str>) -> Result<Vec<TicketSummary>, ApiError> {
        let mut statement=self.db.prepare("SELECT t.id,t.user_id,u.login,t.subject,t.kind,t.status,t.updated_at,(SELECT COUNT(*) FROM ticket_messages m WHERE m.ticket_id=t.id AND m.author=? AND m.id>CASE WHEN ?=1 THEN t.user_read ELSE t.admin_read END) FROM tickets t JOIN users u ON u.id=t.user_id WHERE (? IS NULL OR t.user_id=?) ORDER BY t.updated_at DESC,t.rowid DESC LIMIT 200")?;
        let values = statement
            .query_map(
                params![
                    if user.is_some() { "admin" } else { "user" },
                    user.is_some(),
                    user,
                    user
                ],
                ticket_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(values)
    }
    fn ticket_owner(&self, id: &str, user: Option<&str>) -> Result<(), ApiError> {
        let owner: Option<String> = self
            .db
            .query_row("SELECT user_id FROM tickets WHERE id=?", [id], |row| {
                row.get(0)
            })
            .optional()?;
        if owner.is_none() || user.is_some_and(|user| owner.as_deref() != Some(user)) {
            return Err(ApiError::missing());
        }
        Ok(())
    }
    fn new_ticket(
        &mut self,
        user: &str,
        subject: &str,
        text: &str,
        author: &str,
        now: i64,
    ) -> Result<String, ApiError> {
        check_text(subject, 160)?;
        check_text(text, 6000)?;
        if !self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=?)",
            [user],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(ApiError::missing());
        }
        if author == "user" {
            let recent:i64=self.db.query_row("SELECT COUNT(*) FROM ticket_messages m JOIN tickets t ON t.id=m.ticket_id WHERE t.user_id=? AND m.author='user' AND m.created_at>?",params![user,now-3600],|row| row.get(0))?;
            if recent >= 60 {
                return Err(ApiError::bad("Слишком много сообщений. Повторите позже."));
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let tx = self.db.transaction()?;
        tx.execute("INSERT INTO tickets(id,user_id,subject,kind,created_at,updated_at) VALUES(?,?,?,?,?,?)",params![id,user,subject.trim(),if author=="admin"{"announcement"}else{"support"},now,now])?;
        tx.execute(
            "INSERT INTO ticket_messages(ticket_id,author,text,created_at) VALUES(?,?,?,?)",
            params![id, author, text.trim(), now],
        )?;
        tx.commit()?;
        Ok(id)
    }
    fn ticket_reply(
        &mut self,
        id: &str,
        user: Option<&str>,
        text: &str,
        now: i64,
    ) -> Result<(), ApiError> {
        check_text(text, 6000)?;
        self.ticket_owner(id, user)?;
        if let Some(user) = user {
            let recent:i64=self.db.query_row("SELECT COUNT(*) FROM ticket_messages m JOIN tickets t ON t.id=m.ticket_id WHERE t.user_id=? AND m.author='user' AND m.created_at>?",params![user,now-3600],|row| row.get(0))?;
            if recent >= 60 {
                return Err(ApiError::bad("Слишком много сообщений. Повторите позже."));
            }
        }
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO ticket_messages(ticket_id,author,text,created_at) VALUES(?,?,?,?)",
            params![
                id,
                if user.is_some() { "user" } else { "admin" },
                text.trim(),
                now
            ],
        )?;
        tx.execute(
            "UPDATE tickets SET status='open',updated_at=? WHERE id=?",
            params![now, id],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn ticket_detail(
        &self,
        id: &str,
        user: Option<&str>,
        before: Option<i64>,
        mark_read: bool,
    ) -> Result<TicketDetail, ApiError> {
        self.ticket_owner(id, user)?;
        let mut statement=self.db.prepare("SELECT id,author,text,created_at FROM ticket_messages WHERE ticket_id=? AND (? IS NULL OR id<?) ORDER BY id DESC LIMIT 51")?;
        let mut messages = statement
            .query_map(params![id, before, before], |row| {
                Ok(TicketMessage {
                    id: row.get(0)?,
                    author: row.get(1)?,
                    text: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = messages.len() > 50;
        messages.truncate(50);
        messages.reverse();
        if mark_read {
            let field = if user.is_some() {
                "user_read"
            } else {
                "admin_read"
            };
            self.db.execute(&format!("UPDATE tickets SET {field}=(SELECT COALESCE(MAX(id),0) FROM ticket_messages WHERE ticket_id=?) WHERE id=?"),params![id,id])?;
        }
        let ticket=self.db.query_row("SELECT t.id,t.user_id,u.login,t.subject,t.kind,t.status,t.updated_at,0 FROM tickets t JOIN users u ON u.id=t.user_id WHERE t.id=?",[id],ticket_row)?;
        Ok(TicketDetail {
            ticket,
            messages,
            has_more,
        })
    }
}
fn ticket_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TicketSummary> {
    Ok(TicketSummary {
        id: row.get(0)?,
        user_id: row.get(1)?,
        login: row.get(2)?,
        subject: row.get(3)?,
        kind: row.get(4)?,
        status: row.get(5)?,
        updated_at: row.get(6)?,
        unread_count: row.get(7)?,
    })
}
fn check_text(text: &str, limit: usize) -> Result<(), ApiError> {
    if text.trim().is_empty()
        || text.len() > limit
        || text
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(ApiError::bad("Сообщение пустое или слишком длинное"));
    }
    Ok(())
}
