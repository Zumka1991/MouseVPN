use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mousevpn_control_plane::{router, Store};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

const OWNER: &str = "owner-test-token-01234567890123456789";
const KEY_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const KEY_C: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

#[tokio::test]
async fn public_requests_keep_passwords_private_and_wait_for_manual_payment() {
    let (temp, app) = setup();
    let requested = ok(
        &app,
        "POST",
        "/v1/signup",
        "",
        json!({
            "email":"Friend+Phone@Example.ru", "password":"correct-horse-battery"
        }),
    )
    .await;
    assert_eq!(requested["login"], "friend+phone@example.ru");
    assert!(requested.get("password").is_none());
    let before = login(&app, "friend+phone@example.ru").await;
    assert_eq!(before["account"]["active"], false);
    assert_eq!(before["account"]["servers"], json!([]));
    let owner = ok(&app, "GET", "/v1/admin/users", OWNER, Value::Null).await;
    let id = owner[0]["id"].as_str().unwrap();
    assert_eq!(owner[0]["valid_until"], 0);
    assert!(owner[0].get("password_hash").is_none());
    let db = rusqlite::Connection::open(temp.path().join("accounts.sqlite")).unwrap();
    let hash: String = db
        .query_row("SELECT password_hash FROM users WHERE id=?", [id], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(!hash.contains("correct-horse-battery"));
    let (status, _) = call(
        &app,
        "POST",
        "/v1/signup",
        "",
        json!({
            "email":"friend+phone@example.ru", "password":"replacement-password"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    login(&app, "friend+phone@example.ru").await;
    for (email, password) in [
        ("bad@@example.ru", "correct-horse-battery"),
        ("friend@example.ru", "short"),
    ] {
        let (status, _) = call(
            &app,
            "POST",
            "/v1/signup",
            "",
            json!({"email":email,"password":password}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    ok(
        &app,
        "POST",
        &format!("/v1/admin/users/{id}/payments"),
        OWNER,
        json!({"reference":"signup-payment","months":3,"amount_rub":900}),
    )
    .await;
    let after = login(&app, "friend+phone@example.ru").await;
    assert_eq!(after["account"]["active"], true);
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn ok(app: &axum::Router, method: &str, path: &str, token: &str, body: Value) -> Value {
    let (status, value) = call(app, method, path, token, body).await;
    assert!(status.is_success(), "{path}: {status} {value}");
    value
}
fn setup() -> (TempDir, axum::Router) {
    let temp = TempDir::new().unwrap();
    let app = router(
        Store::open(&temp.path().join("accounts.sqlite")).unwrap(),
        OWNER,
    )
    .unwrap();
    (temp, app)
}
async fn user(app: &axum::Router, login: &str) -> Value {
    ok(
        app,
        "POST",
        "/v1/admin/users",
        OWNER,
        json!({"login":login,"password":"correct-horse-battery"}),
    )
    .await
}
async fn login(app: &axum::Router, login: &str) -> Value {
    ok(
        app,
        "POST",
        "/v1/login",
        "",
        json!({"login":login,"password":"correct-horse-battery"}),
    )
    .await
}
async fn server(app: &axum::Router, name: &str) -> Value {
    ok(app,"POST","/v1/admin/servers",OWNER,json!({"name":name,"endpoint":"198.51.100.20:51821","public_key":KEY_A,"protocol":"morph_quiet"})).await
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end scenario includes authorization and state assertions"
)]
async fn paid_accounts_filter_catalog_and_node_authorization_together() {
    let (_temp, app) = setup();
    let first = server(&app, "Finland").await;
    let second = server(&app, "France").await;
    let alice = user(&app, "Alice").await;
    let id = alice["id"].as_str().unwrap();
    assert_eq!(alice["all_servers"], true);
    let session = login(&app, "ALICE").await;
    let token = session["token"].as_str().unwrap();
    assert!(session["account"]["servers"].as_array().unwrap().is_empty());
    let enrolled = ok(
        &app,
        "POST",
        "/v1/account/devices",
        token,
        json!({"name":"phone","platform":"android","public_key":KEY_B}),
    )
    .await;
    assert_eq!(enrolled["devices"].as_array().unwrap().len(), 1);
    assert_eq!(
        ok(
            &app,
            "GET",
            "/v1/node/snapshot",
            first["node_token"].as_str().unwrap(),
            json!(null)
        )
        .await["devices"],
        json!([])
    );
    let payment_path = format!("/v1/admin/users/{id}/payments");
    assert_eq!(
        call(
            &app,
            "POST",
            &payment_path,
            token,
            json!({"reference":"transfer-1","amount_rub":900,"months":3})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let paid = ok(
        &app,
        "POST",
        &payment_path,
        OWNER,
        json!({"reference":"transfer-1","amount_rub":900,"months":3}),
    )
    .await;
    assert_eq!(paid["servers"].as_array().unwrap().len(), 2);
    let again = ok(
        &app,
        "POST",
        &payment_path,
        OWNER,
        json!({"reference":"transfer-1","amount_rub":900,"months":3}),
    )
    .await;
    assert_eq!(again["valid_until"], paid["valid_until"]);
    assert_eq!(again["payments"].as_array().unwrap().len(), 1);
    assert_eq!(
        call(
            &app,
            "POST",
            &payment_path,
            OWNER,
            json!({"reference":"transfer-1","amount_rub":1800,"months":6})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &payment_path,
            OWNER,
            json!({"reference":"bad","amount_rub":300,"months":1})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    ok(
        &app,
        "PUT",
        &format!("/v1/admin/users/{id}/access"),
        OWNER,
        json!({"enabled":true,"all_servers":false,"server_ids":[first["id"]]}),
    )
    .await;
    let catalog = ok(&app, "GET", "/v1/account", token, json!(null)).await;
    assert_eq!(catalog["servers"].as_array().unwrap().len(), 1);
    assert_eq!(catalog["servers"][0]["id"], first["id"]);
    let first_snapshot = ok(
        &app,
        "GET",
        "/v1/node/snapshot",
        first["node_token"].as_str().unwrap(),
        json!(null),
    )
    .await;
    assert_eq!(first_snapshot["devices"].as_array().unwrap().len(), 1);
    assert!(
        first_snapshot["devices"][0]["valid_until"]
            .as_u64()
            .unwrap()
            <= first_snapshot["lease_until"].as_u64().unwrap()
    );
    let hidden_snapshot = ok(
        &app,
        "GET",
        "/v1/node/snapshot",
        second["node_token"].as_str().unwrap(),
        json!(null),
    )
    .await;
    assert_eq!(hidden_snapshot["devices"], json!([]));
    assert_eq!(
        call(&app, "GET", "/v1/admin/servers", token, json!(null))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/account",
            first["node_token"].as_str().unwrap(),
            json!(null)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    ok(
        &app,
        "PUT",
        &format!("/v1/admin/users/{id}/access"),
        OWNER,
        json!({"enabled":true,"all_servers":false,"server_ids":[]}),
    )
    .await;
    assert_eq!(
        ok(&app, "GET", "/v1/account", token, json!(null)).await["servers"],
        json!([])
    );
    assert_eq!(
        ok(
            &app,
            "GET",
            "/v1/node/snapshot",
            first["node_token"].as_str().unwrap(),
            json!(null)
        )
        .await["devices"],
        json!([])
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end scenario includes authorization and state assertions"
)]
async fn enrollment_is_global_idempotent_and_owned_by_the_account() {
    let (_temp, app) = setup();
    user(&app, "alice").await;
    user(&app, "bob").await;
    let alice = login(&app, "alice").await;
    let token = alice["token"].as_str().unwrap();
    let bob = login(&app, "bob").await;
    let bob_token = bob["token"].as_str().unwrap();
    let first = ok(
        &app,
        "POST",
        "/v1/account/devices",
        token,
        json!({"name":"phone","platform":"android","public_key":KEY_A}),
    )
    .await;
    let second = ok(
        &app,
        "POST",
        "/v1/account/devices",
        token,
        json!({"name":"PC","platform":"windows","public_key":KEY_B}),
    )
    .await;
    assert_eq!(second["devices"].as_array().unwrap().len(), 2);
    assert_eq!(
        ok(
            &app,
            "POST",
            "/v1/account/devices",
            token,
            json!({"name":"PC","platform":"windows","public_key":KEY_B})
        )
        .await["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/account/devices",
            token,
            json!({"name":"third","platform":"android","public_key":KEY_C})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/account/devices",
            bob_token,
            json!({"name":"stolen","platform":"android","public_key":KEY_A})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let device = first["devices"][0]["id"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/v1/account/devices/{device}"),
            bob_token,
            json!(null)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    ok(
        &app,
        "DELETE",
        &format!("/v1/account/devices/{device}"),
        token,
        json!(null),
    )
    .await;
    assert_eq!(
        ok(
            &app,
            "POST",
            "/v1/account/devices",
            token,
            json!({"name":"replacement","platform":"android","public_key":KEY_C})
        )
        .await["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    ok(&app, "POST", "/v1/logout", token, json!(null)).await;
    assert_eq!(
        call(&app, "GET", "/v1/account", token, json!(null)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn blocking_and_password_reset_invalidate_login_sessions() {
    let (_temp, app) = setup();
    let alice = user(&app, "alice").await;
    let id = alice["id"].as_str().unwrap();
    let session = login(&app, "alice").await;
    let token = session["token"].as_str().unwrap();
    ok(
        &app,
        "PUT",
        &format!("/v1/admin/users/{id}/password"),
        OWNER,
        json!({"password":"another-correct-password"}),
    )
    .await;
    assert_eq!(
        call(&app, "GET", "/v1/account", token, json!(null)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/login",
            "",
            json!({"login":"alice","password":"correct-horse-battery"})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let changed = ok(
        &app,
        "POST",
        "/v1/login",
        "",
        json!({"login":"alice","password":"another-correct-password"}),
    )
    .await;
    ok(
        &app,
        "PUT",
        &format!("/v1/admin/users/{id}/access"),
        OWNER,
        json!({"enabled":false,"all_servers":true,"server_ids":[]}),
    )
    .await;
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/account",
            changed["token"].as_str().unwrap(),
            json!(null)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end scenario includes authorization and state assertions"
)]
async fn tickets_and_admin_messages_are_private_and_work_without_paid_access() {
    let (_temp, app) = setup();
    let alice = user(&app, "alice").await;
    user(&app, "bob").await;
    let alice_login = login(&app, "alice").await;
    let token = alice_login["token"].as_str().unwrap();
    let bob_login = login(&app, "bob").await;
    let other = bob_login["token"].as_str().unwrap();
    let ticket = ok(
        &app,
        "POST",
        "/v1/account/tickets",
        token,
        json!({"subject":"Connection","text":"Please help","author":"admin"}),
    )
    .await;
    assert_eq!(ticket["messages"][0]["author"], "user");
    let id = ticket["ticket"]["id"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/v1/account/tickets/{id}"),
            other,
            json!(null)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/account/tickets/{id}/messages"),
            other,
            json!({"text":"intrusion"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/admin/tickets/{id}/messages"),
            token,
            json!({"text":"forged"})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        ok(&app, "GET", "/v1/admin/tickets", OWNER, json!(null)).await[0]["unread_count"],
        1
    );
    ok(
        &app,
        "POST",
        &format!("/v1/admin/tickets/{id}/messages"),
        OWNER,
        json!({"text":"Try again"}),
    )
    .await;
    assert_eq!(
        ok(&app, "GET", "/v1/account", token, json!(null)).await["unread_messages"],
        1
    );
    let detail = ok(
        &app,
        "GET",
        &format!("/v1/account/tickets/{id}"),
        token,
        json!(null),
    )
    .await;
    assert_eq!(detail["messages"].as_array().unwrap().len(), 2);
    assert_eq!(
        ok(&app, "GET", "/v1/account", token, json!(null)).await["unread_messages"],
        0
    );
    ok(
        &app,
        "PUT",
        &format!("/v1/admin/tickets/{id}/status"),
        OWNER,
        json!({"status":"closed"}),
    )
    .await;
    let reopened = ok(
        &app,
        "POST",
        &format!("/v1/account/tickets/{id}/messages"),
        token,
        json!({"text":"Still have a question"}),
    )
    .await;
    assert_eq!(reopened["ticket"]["status"], "open");
    let notice = ok(
        &app,
        "POST",
        &format!("/v1/admin/users/{}/messages", alice["id"].as_str().unwrap()),
        OWNER,
        json!({"subject":"News","text":"Your server is available"}),
    )
    .await;
    assert_eq!(notice["ticket"]["kind"], "announcement");
    assert_eq!(
        ok(&app, "GET", "/v1/account", token, json!(null)).await["unread_messages"],
        1
    );
    assert_eq!(
        ok(&app, "GET", "/v1/account/tickets", other, json!(null)).await,
        json!([])
    );
}

#[tokio::test]
async fn manual_payment_requests_are_private_idempotent_and_extend_only_on_approval() {
    let (temp, app) = setup();
    let person = user(&app, "payer@example.ru").await;
    user(&app, "other@example.ru").await;
    let auth = login(&app, "payer@example.ru").await;
    let other = login(&app, "other@example.ru").await;
    let token = auth["token"].as_str().unwrap();
    let other_token = other["token"].as_str().unwrap();
    let path = "/v1/account/payment-requests";
    let id = uuid::Uuid::new_v4().to_string();
    let mut draft = json!({"id":id,"months":3,"note":"Transfer at 12:00","details_revision":1});
    assert_eq!(
        call(&app, "GET", "/v1/account/billing", "", Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/v1/admin/payment-requests",
            token,
            Value::Null
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "POST", path, token, draft.clone()).await.0,
        StatusCode::BAD_REQUEST
    );
    let details = ok(&app,"PUT","/v1/admin/payment-details",OWNER,json!({"revision":0,"enabled":true,"bank":"Test Bank","recipient":"Test Recipient","card_number":"0000 0000 0000 0000","instructions":"Test only"})).await;
    draft["details_revision"] = details["revision"].clone();
    let mut invalid = draft.clone();
    invalid["months"] = json!(2);
    assert_eq!(
        call(&app, "POST", path, token, invalid).await.0,
        StatusCode::BAD_REQUEST
    );
    let claim = ok(&app, "POST", path, token, draft.clone()).await;
    assert_eq!(claim["amount_rub"], 900);
    assert_eq!(claim["status"], "pending");
    assert_eq!(ok(&app, "POST", path, token, draft.clone()).await, claim);
    assert_eq!(
        login(&app, "payer@example.ru").await["account"]["active"],
        false
    );
    assert_eq!(
        ok(&app, "GET", "/v1/account/billing", other_token, Value::Null).await["requests"],
        json!([])
    );
    assert_eq!(
        call(&app, "POST", path, other_token, draft.clone()).await.0,
        StatusCode::CONFLICT
    );
    let mut duplicate = draft.clone();
    duplicate["id"] = json!(uuid::Uuid::new_v4().to_string());
    assert_eq!(
        call(&app, "POST", path, token, duplicate.clone()).await.0,
        StatusCode::CONFLICT
    );
    let decision = format!("/v1/admin/payment-requests/{id}/decision");
    assert_eq!(
        call(&app, "POST", &decision, token, json!({"status":"approved"}))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // A failure during the decision must roll back BOTH the ledger and subscription.
    let db = rusqlite::Connection::open(temp.path().join("accounts.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER reject_decision BEFORE UPDATE ON payment_requests BEGIN SELECT RAISE(ABORT,'test rollback'); END;").unwrap();
    assert!(
        !call(&app, "POST", &decision, OWNER, json!({"status":"approved"}))
            .await
            .0
            .is_success()
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM payments", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        login(&app, "payer@example.ru").await["account"]["active"],
        false
    );
    db.execute_batch("DROP TRIGGER reject_decision;").unwrap();
    let (first, retry) = tokio::join!(
        call(&app, "POST", &decision, OWNER, json!({"status":"approved"})),
        call(&app, "POST", &decision, OWNER, json!({"status":"approved"}))
    );
    assert!(first.0.is_success());
    assert_eq!(first, retry);
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM payments", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        login(&app, "payer@example.ru").await["account"]["active"],
        true
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &decision,
            OWNER,
            json!({"status":"rejected","note":"changed mind"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!(
                "/v1/admin/users/{}/payments",
                person["id"].as_str().unwrap()
            ),
            OWNER,
            json!({"reference":format!("request:{id}"),"months":3,"amount_rub":900})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // Editing recipient details must not rewrite the destination of an existing transfer.
    let mut changed = details.clone();
    changed["bank"] = json!("New Bank");
    changed["enabled"] = json!(false);
    ok(&app, "PUT", "/v1/admin/payment-details", OWNER, changed).await;
    assert_eq!(
        call(
            &app,
            "PUT",
            "/v1/admin/payment-details",
            OWNER,
            details.clone()
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let old_destination = ok(&app, "POST", path, token, duplicate.clone()).await;
    assert_eq!(old_destination["details"]["bank"], "Test Bank");
    let rejection = format!(
        "/v1/admin/payment-requests/{}/decision",
        old_destination["id"].as_str().unwrap()
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &rejection,
            OWNER,
            json!({"status":"rejected"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    ok(
        &app,
        "POST",
        &rejection,
        OWNER,
        json!({"status":"rejected","note":"Поступление не найдено"}),
    )
    .await;
    assert_eq!(
        login(&app, "payer@example.ru").await["account"]["valid_until"],
        first.1["valid_until"]
    );
    let history = ok(&app, "GET", "/v1/account/billing", token, Value::Null).await;
    assert!(history["requests"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["admin_note"] == "Поступление не найдено"));
}

#[tokio::test]
async fn node_counts_require_node_credentials_and_stale_data_is_unknown() {
    let (temp, app) = setup();
    let node = server(&app, "Node A").await;
    let other = server(&app, "Node B").await;
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/node/snapshot",
            OWNER,
            json!({"online_devices":10})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let node_token = node["node_token"].as_str().unwrap();
    ok(
        &app,
        "POST",
        "/v1/node/snapshot",
        node_token,
        json!({"online_devices":10}),
    )
    .await;
    let nodes = ok(&app, "GET", "/v1/admin/servers", OWNER, Value::Null).await;
    assert_eq!(nodes[0]["online_devices"], 10);
    assert!(nodes[1]["online_devices"].is_null());
    ok(
        &app,
        "POST",
        "/v1/node/snapshot",
        other["node_token"].as_str().unwrap(),
        json!({"online_devices":0}),
    )
    .await;
    let db = rusqlite::Connection::open(temp.path().join("accounts.sqlite")).unwrap();
    db.execute(
        "UPDATE node_status SET updated_at=1 WHERE server_id=?",
        [node["id"].as_str().unwrap()],
    )
    .unwrap();
    let nodes = ok(&app, "GET", "/v1/admin/servers", OWNER, Value::Null).await;
    assert!(nodes[0]["online_devices"].is_null());
    assert_eq!(nodes[1]["online_devices"], 0);
    // Older agents still synchronize without inventing a count.
    ok(&app, "GET", "/v1/node/snapshot", node_token, Value::Null).await;
    assert!(
        ok(&app, "GET", "/v1/admin/servers", OWNER, Value::Null).await[0]["online_devices"]
            .is_null()
    );
}

#[tokio::test]
async fn billing_migration_preserves_existing_accounts_and_payments() {
    let (temp, app) = setup();
    let old = user(&app, "existing@example.ru").await;
    let id = old["id"].as_str().unwrap();
    let paid = ok(
        &app,
        "POST",
        &format!("/v1/admin/users/{id}/payments"),
        OWNER,
        json!({"reference":"before-migration","months":3,"amount_rub":900}),
    )
    .await;
    drop(app);
    let db = rusqlite::Connection::open(temp.path().join("accounts.sqlite")).unwrap();
    db.execute_batch("DROP TABLE payment_requests; DROP TABLE payment_details; DROP TABLE node_status; PRAGMA user_version=2;").unwrap();
    drop(db);
    let reopened = router(
        Store::open(&temp.path().join("accounts.sqlite")).unwrap(),
        OWNER,
    )
    .unwrap();
    let current = login(&reopened, "existing@example.ru").await;
    assert_eq!(current["account"]["valid_until"], paid["valid_until"]);
    assert_eq!(current["account"]["id"], id);
    assert_eq!(
        ok(&reopened, "GET", "/v1/admin/users", OWNER, Value::Null).await[0]["payments"][0]
            ["reference"],
        "before-migration"
    );
    assert!(ok(
        &reopened,
        "GET",
        "/v1/admin/payment-details",
        OWNER,
        Value::Null
    )
    .await
    .is_null());
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end authorization and persistence scenario"
)]
async fn lifetime_preserves_paid_expiry_restrictions_blocking_and_node_leases() {
    let (_temp, app) = setup();
    let u = user(&app, "friend").await;
    let uid = u["id"].as_str().unwrap();
    let a = server(&app, "A").await;
    let b = server(&app, "B").await;
    let session = login(&app, "friend").await;
    let token = session["token"].as_str().unwrap();
    let path = format!("/v1/admin/users/{uid}/lifetime");
    assert_eq!(
        call(&app, "PUT", &path, token, json!({"enabled":true}))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    ok(
        &app,
        "POST",
        "/v1/account/devices",
        token,
        json!({"name":"Phone","platform":"android","public_key":KEY_B}),
    )
    .await;
    ok(
        &app,
        "PUT",
        &format!("/v1/admin/users/{uid}/access"),
        OWNER,
        json!({"enabled":true,"all_servers":false,"server_ids":[a["id"]]}),
    )
    .await;
    let granted = ok(&app, "PUT", &path, OWNER, json!({"enabled":true})).await;
    assert_eq!(granted["active"], true);
    assert_eq!(granted["lifetime"], true);
    assert_eq!(granted["paid_valid_until"], 0);
    assert_eq!(granted["servers"].as_array().unwrap().len(), 1);
    let snap = ok(
        &app,
        "GET",
        "/v1/node/snapshot",
        a["node_token"].as_str().unwrap(),
        Value::Null,
    )
    .await;
    assert_eq!(snap["devices"].as_array().unwrap().len(), 1);
    assert_eq!(snap["devices"][0]["valid_until"], snap["lease_until"]);
    assert!(ok(
        &app,
        "GET",
        "/v1/node/snapshot",
        b["node_token"].as_str().unwrap(),
        Value::Null
    )
    .await["devices"]
        .as_array()
        .unwrap()
        .is_empty());
    ok(
        &app,
        "PUT",
        &format!("/v1/admin/users/{uid}/access"),
        OWNER,
        json!({"enabled":false,"all_servers":true,"server_ids":[]}),
    )
    .await;
    assert!(ok(
        &app,
        "GET",
        "/v1/node/snapshot",
        a["node_token"].as_str().unwrap(),
        Value::Null
    )
    .await["devices"]
        .as_array()
        .unwrap()
        .is_empty());
    ok(
        &app,
        "POST",
        &format!("/v1/admin/users/{uid}/payments"),
        OWNER,
        json!({"reference":"gift-test-payment","months":3,"amount_rub":900}),
    )
    .await;
    let removed = ok(&app, "PUT", &path, OWNER, json!({"enabled":false})).await;
    assert_eq!(removed["valid_until"], removed["paid_valid_until"]);
    assert_eq!(removed["active"], false);
    assert!(removed["paid_valid_until"].as_i64().unwrap() > chrono::Utc::now().timestamp());
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end authorization and persistence scenario"
)]
async fn traffic_retries_ordering_server_isolation_revocation_and_privacy() {
    let (_temp, app) = setup();
    let u = user(&app, "usage").await;
    let uid = u["id"].as_str().unwrap();
    let session = login(&app, "usage").await;
    let token = session["token"].as_str().unwrap();
    let enrolled = ok(
        &app,
        "POST",
        "/v1/account/devices",
        token,
        json!({"name":"Phone","platform":"android","public_key":KEY_B}),
    )
    .await;
    let device = enrolled["devices"][0]["id"].as_str().unwrap();
    let a = server(&app, "A").await;
    let b = server(&app, "B").await;
    let at = chrono::Utc::now().timestamp();
    let hour = at / 3600 * 3600;
    let batch = json!({"hours":[{"hour":hour,"public_key":KEY_B,"upload_bytes":100,"download_bytes":300}],"connections":[{"id":"event-1","at":at,"public_key":KEY_B,"protocol":"morph_balanced"}]});
    assert_eq!(
        call(&app, "POST", "/v1/node/traffic", OWNER, batch.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/v1/admin/usage", token, Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    for _ in 0..2 {
        ok(
            &app,
            "POST",
            "/v1/node/traffic",
            a["node_token"].as_str().unwrap(),
            batch.clone(),
        )
        .await;
    }
    let mut newer = batch.clone();
    newer["hours"][0]["download_bytes"] = json!(500);
    ok(
        &app,
        "POST",
        "/v1/node/traffic",
        a["node_token"].as_str().unwrap(),
        newer,
    )
    .await;
    ok(
        &app,
        "POST",
        "/v1/node/traffic",
        a["node_token"].as_str().unwrap(),
        batch.clone(),
    )
    .await;
    ok(
        &app,
        "POST",
        "/v1/node/traffic",
        b["node_token"].as_str().unwrap(),
        batch.clone(),
    )
    .await;
    ok(
        &app,
        "DELETE",
        &format!("/v1/account/devices/{device}"),
        token,
        Value::Null,
    )
    .await;
    let mut late = batch.clone();
    late["hours"][0]["upload_bytes"] = json!(200);
    ok(
        &app,
        "POST",
        "/v1/node/traffic",
        a["node_token"].as_str().unwrap(),
        late,
    )
    .await;
    let result = ok(
        &app,
        "GET",
        &format!("/v1/admin/usage?user={uid}&group=week&offset=420"),
        OWNER,
        Value::Null,
    )
    .await;
    assert_eq!(result["users"][0]["upload"], 300);
    assert_eq!(result["users"][0]["download"], 800);
    assert_eq!(result["connections"].as_array().unwrap().len(), 2);
    assert_eq!(result["servers"].as_array().unwrap().len(), 2);
    assert_eq!(result["series"][0]["upload"], 300);
    let bucket = result["series"][0]["at"].as_i64().unwrap();
    assert_eq!((bucket + 420 * 60) / 86400 % 7, 4); // Monday
    let mut bad = batch;
    bad["hours"][0]["upload_bytes"] = json!(-1);
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/node/traffic",
            a["node_token"].as_str().unwrap(),
            bad
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    user(&app, "other").await;
    let other = login(&app, "other").await;
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/account/devices",
            other["token"].as_str().unwrap(),
            json!({"name":"Stolen key","platform":"linux","public_key":KEY_B})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert!(ok(&app, "GET", "/v1/account", token, Value::Null)
        .await
        .get("connections")
        .is_none());
}

#[tokio::test]
async fn rejected_login_explains_credentials_without_disclosing_account_existence() {
    let (_temp, app) = setup();
    user(&app, "login-feedback").await;
    let expected = json!({"error":"Неверная почта или пароль. Проверьте введённые данные."});
    for (login, password) in [
        ("login-feedback", "wrong-password".to_owned()),
        ("unknown-feedback", "wrong-password".to_owned()),
        ("login-feedback", "x".repeat(257)),
    ] {
        let (status, body) = call(
            &app,
            "POST",
            "/v1/login",
            "",
            json!({"login":login,"password":password}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, expected);
    }
    let (status, body) = call(&app, "GET", "/v1/account", "expired-token", Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error":"Войдите в аккаунт"}));
    login(&app, "login-feedback").await;
}

#[tokio::test]
async fn manual_days_require_owner_and_authorize_devices_without_a_payment() {
    let (_temp, app) = setup();
    let u = user(&app, "one-day").await;
    let id = u["id"].as_str().unwrap();
    let session = login(&app, "one-day").await;
    let token = session["token"].as_str().unwrap();
    let server = server(&app, "day-node").await;
    let path = format!("/v1/admin/users/{id}/days");
    let body = json!({"reference":uuid::Uuid::new_v4().to_string(),"days":1,"note":"Trial"});
    assert_eq!(
        call(&app, "POST", &path, token, body.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut bad = body.clone();
    bad["days"] = json!(0);
    assert_eq!(
        call(&app, "POST", &path, OWNER, bad).await.0,
        StatusCode::BAD_REQUEST
    );
    let granted = ok(&app, "POST", &path, OWNER, body.clone()).await;
    assert_eq!(granted["active"], true);
    assert_eq!(granted["day_grants"][0]["days"], 1);
    assert!(granted["payments"].as_array().unwrap().is_empty());
    assert_eq!(
        ok(&app, "POST", &path, OWNER, body).await["valid_until"],
        granted["valid_until"]
    );
    let enrolled = ok(
        &app,
        "POST",
        "/v1/account/devices",
        token,
        json!({"name":"Windows","platform":"windows","public_key":KEY_B}),
    )
    .await;
    assert_eq!(enrolled["valid_until"], granted["valid_until"]);
    assert_eq!(enrolled["servers"].as_array().unwrap().len(), 1);
    let snapshot = ok(
        &app,
        "GET",
        "/v1/node/snapshot",
        server["node_token"].as_str().unwrap(),
        Value::Null,
    )
    .await;
    assert_eq!(snapshot["devices"].as_array().unwrap().len(), 1);
    assert!(
        snapshot["devices"][0]["valid_until"].as_u64().unwrap()
            <= snapshot["lease_until"].as_u64().unwrap()
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end policy authorization and accepted-payment compatibility scenario"
)]
async fn billing_minimum_is_owner_configurable_and_preserves_accepted_terms() {
    let (_temp, app) = setup();
    let person = user(&app, "minimum@example.ru").await;
    let auth = login(&app, "minimum@example.ru").await;
    let token = auth["token"].as_str().unwrap();
    let node = server(&app, "policy-node").await;
    let policy = "/v1/admin/billing-policy";
    assert_eq!(
        ok(&app, "GET", "/v1/pricing", "", Value::Null).await,
        json!({"min_months":3,"max_months":120,"month_price":300})
    );
    for credentials in ["", token, node["node_token"].as_str().unwrap()] {
        assert_eq!(
            call(
                &app,
                "PUT",
                policy,
                credentials,
                json!({"revision":0,"min_months":1})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    for invalid in [json!(0), json!(121), json!(-1), json!(1.5)] {
        assert!(!call(
            &app,
            "PUT",
            policy,
            OWNER,
            json!({"revision":0,"min_months":invalid})
        )
        .await
        .0
        .is_success());
    }
    let request_path = "/v1/account/payment-requests";
    let details=ok(&app,"PUT","/v1/admin/payment-details",OWNER,json!({"revision":0,"enabled":true,"bank":"Test","recipient":"Test","card_number":"0000000000000000","instructions":""})).await;
    let draft = json!({"id":uuid::Uuid::new_v4().to_string(),"months":1,"note":"","details_revision":details["revision"]});
    assert_eq!(
        call(&app, "POST", request_path, token, draft.clone())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let manual_path = format!(
        "/v1/admin/users/{}/payments",
        person["id"].as_str().unwrap()
    );
    let manual = json!({"reference":"minimum-manual","months":1,"amount_rub":300});
    assert_eq!(
        call(&app, "POST", &manual_path, OWNER, manual.clone())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let changed = ok(
        &app,
        "PUT",
        policy,
        OWNER,
        json!({"revision":0,"min_months":1}),
    )
    .await;
    assert_eq!(changed, json!({"revision":1,"min_months":1}));
    assert_eq!(ok(&app, "GET", policy, OWNER, Value::Null).await, changed);
    assert_eq!(
        ok(&app, "GET", "/v1/account/billing", token, Value::Null).await["min_months"],
        1
    );
    assert_eq!(
        ok(&app, "GET", "/v1/pricing", "", Value::Null).await["min_months"],
        1
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            policy,
            OWNER,
            json!({"revision":0,"min_months":6})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let claim = ok(&app, "POST", request_path, token, draft.clone()).await;
    assert_eq!(claim["amount_rub"], 300);
    let paid = ok(&app, "POST", &manual_path, OWNER, manual.clone()).await;
    ok(
        &app,
        "PUT",
        policy,
        OWNER,
        json!({"revision":1,"min_months":6}),
    )
    .await;
    assert_eq!(
        ok(&app, "POST", request_path, token, draft.clone()).await,
        claim
    );
    assert_eq!(
        ok(&app, "POST", &manual_path, OWNER, manual.clone()).await,
        paid
    );
    let decision = format!(
        "/v1/admin/payment-requests/{}/decision",
        draft["id"].as_str().unwrap()
    );
    let approved = ok(&app, "POST", &decision, OWNER, json!({"status":"approved"})).await;
    let expected = chrono::DateTime::from_timestamp(paid["valid_until"].as_i64().unwrap(), 0)
        .unwrap()
        .checked_add_months(chrono::Months::new(1))
        .unwrap()
        .timestamp();
    assert_eq!(approved["valid_until"], expected);
    assert_eq!(
        ok(&app, "POST", &decision, OWNER, json!({"status":"approved"})).await,
        approved
    );
    let mut new_draft = draft;
    new_draft["id"] = json!(uuid::Uuid::new_v4().to_string());
    assert_eq!(
        call(&app, "POST", request_path, token, new_draft).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut new_manual = manual;
    new_manual["reference"] = json!("below-new-minimum");
    assert_eq!(
        call(&app, "POST", &manual_path, OWNER, new_manual).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        ok(
            &app,
            "PUT",
            policy,
            OWNER,
            json!({"revision":2,"min_months":120})
        )
        .await["min_months"],
        120
    );
}

#[tokio::test]
async fn minimum_migration_preserves_claims_and_removes_three_month_constraint() {
    let (temp, app) = setup();
    user(&app, "migration-minimum@example.ru").await;
    let auth = login(&app, "migration-minimum@example.ru").await;
    let token = auth["token"].as_str().unwrap();
    let details=ok(&app,"PUT","/v1/admin/payment-details",OWNER,json!({"revision":0,"enabled":true,"bank":"Test","recipient":"Test","card_number":"0000000000000000","instructions":""})).await;
    let draft = json!({"id":uuid::Uuid::new_v4().to_string(),"months":3,"note":"pre-migration","details_revision":details["revision"]});
    let claim = ok(
        &app,
        "POST",
        "/v1/account/payment-requests",
        token,
        draft.clone(),
    )
    .await;
    drop(app);
    let path = temp.path().join("accounts.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    // Recreate the actual v5 constraint, then exercise the normal startup migration.
    db.execute_batch(
        &include_str!("../src/migrate_v6.sql").replace("BETWEEN 1 AND 120", "BETWEEN 3 AND 120"),
    )
    .unwrap();
    db.execute_batch("DROP TABLE billing_policy; PRAGMA user_version=5;")
        .unwrap();
    drop(db);
    let app = router(Store::open(&path).unwrap(), OWNER).unwrap();
    assert_eq!(
        ok(
            &app,
            "POST",
            "/v1/account/payment-requests",
            token,
            draft.clone()
        )
        .await,
        claim
    );
    let decision = format!(
        "/v1/admin/payment-requests/{}/decision",
        draft["id"].as_str().unwrap()
    );
    ok(
        &app,
        "POST",
        &decision,
        OWNER,
        json!({"status":"rejected","note":"test"}),
    )
    .await;
    ok(
        &app,
        "PUT",
        "/v1/admin/billing-policy",
        OWNER,
        json!({"revision":0,"min_months":1}),
    )
    .await;
    let new = json!({"id":uuid::Uuid::new_v4().to_string(),"months":1,"note":"after migration","details_revision":details["revision"]});
    assert_eq!(
        ok(&app, "POST", "/v1/account/payment-requests", token, new).await["amount_rub"],
        300
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM payment_requests", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    drop(app);
    drop(db);
    let app = router(Store::open(&path).unwrap(), OWNER).unwrap();
    assert_eq!(
        ok(&app, "GET", "/v1/pricing", "", Value::Null).await["min_months"],
        1
    );
}
