//! Owner-only usage history. Nodes submit absolute counters with retry-safe keys.
use crate::{bearer, error::ApiError, now, store::hash_token, App};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::HeaderMap,
    routing::{get, post, put},
    Json, Router,
};
use mousevpn_account_client::NodeTraffic;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub(crate) fn routes() -> Router<App> {
    Router::new()
        .route(
            "/v1/node/traffic",
            post(ingest).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route("/v1/admin/usage", get(report))
        .route("/v1/admin/users/{id}/lifetime", put(lifetime))
}

async fn ingest(
    State(app): State<App>,
    headers: HeaderMap,
    Json(batch): Json<NodeTraffic>,
) -> Result<Json<Value>, ApiError> {
    let mut db = app.db()?;
    let server: String = db
        .db
        .query_row(
            "SELECT id FROM servers WHERE token_hash=?",
            [hash_token(bearer(&headers)?)],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(ApiError::unauthorized)?;
    let at = now();
    let oldest = at - 400 * 86400;
    if batch.hours.len() > 128
        || batch.connections.len() > 128
        || batch.hours.iter().any(|h| {
            h.hour < 0
                || h.hour % 3600 != 0
                || h.hour > at / 3600 * 3600
                || h.upload_bytes < 0
                || h.download_bytes < 0
                || h.upload_bytes > 1_i64 << 50
                || h.download_bytes > 1_i64 << 50
                || h.public_key.len() != 43
        })
        || batch.connections.iter().any(|e| {
            e.id.is_empty()
                || e.id.len() > 128
                || e.public_key.len() != 43
                || e.at < 0
                || e.at > at + 60
                || !matches!(
                    e.protocol.as_str(),
                    "legacy" | "speedy" | "morph_quiet" | "morph_balanced" | "morph_paranoid"
                )
        })
    {
        return Err(ApiError::bad("Некорректная статистика узла"));
    }
    let tx = db.db.transaction()?;
    for h in batch
        .hours
        .iter()
        .filter(|h| h.hour >= oldest / 3600 * 3600)
    {
        tx.execute("INSERT INTO usage_hourly(server_id,public_key,hour,upload_bytes,download_bytes) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM device_owners WHERE public_key=?) ON CONFLICT(server_id,public_key,hour) DO UPDATE SET upload_bytes=max(upload_bytes,excluded.upload_bytes),download_bytes=max(download_bytes,excluded.download_bytes)",params![server,h.public_key,h.hour,h.upload_bytes,h.download_bytes,h.public_key])?;
    }
    for e in batch.connections.iter().filter(|e| e.at >= oldest) {
        tx.execute("INSERT OR IGNORE INTO connection_history(server_id,id,public_key,at,protocol) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM device_owners WHERE public_key=?)",params![server,e.id,e.public_key,e.at,e.protocol,e.public_key])?;
    }
    tx.execute(
        "DELETE FROM usage_hourly WHERE hour<?",
        [oldest / 3600 * 3600],
    )?;
    tx.execute("DELETE FROM connection_history WHERE at<?", [oldest])?;
    tx.execute("INSERT INTO traffic_sync VALUES(?,?) ON CONFLICT(server_id) DO UPDATE SET updated_at=excluded.updated_at",params![server,at])?;
    tx.commit()?;
    Ok(Json(json!({"accepted":true})))
}

#[derive(Deserialize)]
struct Selection {
    #[serde(default)]
    user: String,
    #[serde(default = "default_days")]
    days: i64,
    #[serde(default = "default_group")]
    group: String,
    #[serde(default)]
    offset: i64,
    #[serde(default)]
    page: i64,
}
fn default_days() -> i64 {
    7
}
fn default_group() -> String {
    "day".into()
}
async fn report(
    State(app): State<App>,
    headers: HeaderMap,
    Query(q): Query<Selection>,
) -> Result<Json<Value>, ApiError> {
    app.admin(&headers)?;
    if !(1..=400).contains(&q.days)
        || !(-840..=840).contains(&q.offset)
        || !(0..=10000).contains(&q.page)
        || !matches!(q.group.as_str(), "hour" | "day" | "week")
    {
        return Err(ApiError::bad("Неверный период"));
    }
    let store = app.db()?;
    let db = &store.db;
    let at = now();
    let offset = q.offset * 60;
    let start = (at - q.days * 86400) / 3600 * 3600;
    let day = (at + offset) / 86400 * 86400 - offset;
    let week = day - ((day + offset) / 86400 + 3) % 7 * 86400;
    let mut stmt=db.prepare("SELECT u.id,u.login,COALESCE(SUM(CASE WHEN h.hour>=?4 THEN h.upload_bytes ELSE 0 END),0),COALESCE(SUM(CASE WHEN h.hour>=?4 THEN h.download_bytes ELSE 0 END),0),COALESCE(SUM(CASE WHEN h.hour>=?1 THEN h.upload_bytes+h.download_bytes ELSE 0 END),0),COALESCE(SUM(CASE WHEN h.hour>=?2 THEN h.upload_bytes+h.download_bytes ELSE 0 END),0),COALESCE(SUM(CASE WHEN h.hour>=?3 THEN h.upload_bytes+h.download_bytes ELSE 0 END),0) FROM users u LEFT JOIN device_owners d ON d.user_id=u.id LEFT JOIN usage_hourly h ON h.public_key=d.public_key AND h.hour>=?6 WHERE (?5='' OR u.id=?5) GROUP BY u.id ORDER BY SUM(h.upload_bytes+h.download_bytes) DESC,u.login")?;
    let users=stmt.query_map(params![at/3600*3600,day,week,start,q.user,start.min(week)],|r|Ok(json!({"id":r.get::<_,String>(0)?,"login":r.get::<_,String>(1)?,"upload":r.get::<_,i64>(2)?,"download":r.get::<_,i64>(3)?,"hour":r.get::<_,i64>(4)?,"day":r.get::<_,i64>(5)?,"week":r.get::<_,i64>(6)?})))?.collect::<Result<Vec<_>,_>>()?;
    let step = match q.group.as_str() {
        "hour" => 3600,
        "week" => 604_800,
        _ => 86400,
    };
    // Weekly buckets start on Monday; daily buckets use the selected local offset.
    let shift = if step == 604_800 {
        offset - 4 * 86400
    } else if step == 3600 {
        0
    } else {
        offset
    };
    let mut stmt=db.prepare("SELECT ((h.hour+?1)/?2)*?2-?1 AS bucket,SUM(h.upload_bytes),SUM(h.download_bytes) FROM usage_hourly h JOIN device_owners d ON d.public_key=h.public_key WHERE h.hour>=?3 AND (?4='' OR d.user_id=?4) GROUP BY bucket ORDER BY bucket")?;
    let series=stmt.query_map(params![shift,step,start,q.user],|r|Ok(json!({"at":r.get::<_,i64>(0)?,"upload":r.get::<_,i64>(1)?,"download":r.get::<_,i64>(2)?})))?.collect::<Result<Vec<_>,_>>()?;
    let mut stmt=db.prepare("SELECT s.id,s.name,s.endpoint,SUM(h.upload_bytes),SUM(h.download_bytes) FROM usage_hourly h JOIN device_owners d ON d.public_key=h.public_key JOIN servers s ON s.id=h.server_id WHERE h.hour>=?1 AND (?2='' OR d.user_id=?2) GROUP BY s.id ORDER BY SUM(h.upload_bytes+h.download_bytes) DESC")?;
    let servers=stmt.query_map(params![start,q.user],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"endpoint":r.get::<_,String>(2)?,"upload":r.get::<_,i64>(3)?,"download":r.get::<_,i64>(4)?})))?.collect::<Result<Vec<_>,_>>()?;
    let mut stmt=db.prepare("SELECT c.at,u.login,d.name,s.name,c.protocol FROM connection_history c JOIN device_owners d ON d.public_key=c.public_key JOIN users u ON u.id=d.user_id JOIN servers s ON s.id=c.server_id WHERE c.at>=?1 AND (?2='' OR u.id=?2) ORDER BY c.at DESC,c.rowid DESC LIMIT 101 OFFSET ?3")?;
    let mut connections=stmt.query_map(params![start,q.user,q.page*100],|r|Ok(json!({"at":r.get::<_,i64>(0)?,"login":r.get::<_,String>(1)?,"device":r.get::<_,String>(2)?,"server":r.get::<_,String>(3)?,"protocol":r.get::<_,String>(4)?})))?.collect::<Result<Vec<_>,_>>()?;
    let has_more = connections.len() > 100;
    connections.truncate(100);
    let mut stmt=db.prepare("SELECT s.name,t.updated_at FROM servers s LEFT JOIN traffic_sync t ON t.server_id=s.id WHERE s.enabled=1 ORDER BY s.name")?;
    let sync = stmt
        .query_map([], |r| {
            Ok(json!({"name":r.get::<_,String>(0)?,"at":r.get::<_,Option<i64>>(1)?}))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(
        json!({"generated_at":at,"from":start,"step":step,"users":users,"series":series,"servers":servers,"connections":connections,"has_more":has_more,"sync":sync}),
    ))
}

#[derive(Deserialize)]
struct Lifetime {
    enabled: bool,
}
async fn lifetime(
    State(app): State<App>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(value): Json<Lifetime>,
) -> Result<Json<crate::store::AdminUser>, ApiError> {
    app.admin(&headers)?;
    let db = app.db()?;
    db.admin_user(&id, now())?;
    db.db.execute("INSERT INTO lifetime_access VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled",params![id,value.enabled])?;
    Ok(Json(db.admin_user(&id, now())?))
}
