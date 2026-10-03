use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mousevpn_control_plane::{router_with_site, Store};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

const OWNER: &str = "owner-test-token-01234567890123456789";

fn setup() -> (TempDir, axum::Router) {
    let temp = TempDir::new().unwrap();
    let public = temp.path().join("public");
    std::fs::create_dir_all(public.join("assets")).unwrap();
    std::fs::create_dir_all(public.join("downloads")).unwrap();
    std::fs::write(public.join("index.html"), "landing").unwrap();
    std::fs::write(public.join("assets/logo.png"), "logo").unwrap();
    std::fs::write(public.join("downloads/app.apk"), "apk").unwrap();
    let app = router_with_site(
        Store::open(&temp.path().join("accounts.sqlite")).unwrap(),
        OWNER,
        Some(public),
    )
    .unwrap();
    (temp, app)
}

async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .header("content-type", "application/json")
                .body(if body.is_null() {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

async fn json(
    app: &axum::Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> (StatusCode, Value) {
    let (status, _, bytes) = send(app, method, path, headers, body).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

const AUTH: (&str, &str) = (
    "authorization",
    "Bearer owner-test-token-01234567890123456789",
);

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "One scenario covers the gate before, during and after revocation"
)]
async fn site_is_404_without_an_invite_and_opens_through_one() {
    let (_temp, app) = setup();
    for path in ["/site/", "/site/index.html", "/site/?invite=missing-code"] {
        let (status, headers, body) = send(&app, "GET", path, &[], Value::Null).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body, b"404 page not found\n");
        assert!(headers.get("set-cookie").is_none());
    }
    for path in ["/site/assets/logo.png", "/site/downloads/app.apk"] {
        assert_eq!(
            send(&app, "GET", path, &[], Value::Null).await.0,
            StatusCode::OK
        );
    }
    let (status, invite) = json(
        &app,
        "POST",
        "/v1/admin/invites",
        &[AUTH],
        json!({"note":"Друзья","trial_days":14,"max_signups":1}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = invite["code"].as_str().unwrap();
    assert_eq!(code.len(), 16);
    let (status, headers, body) = send(
        &app,
        "GET",
        &format!("/site/?invite={code}"),
        &[("x-forwarded-proto", "https")],
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"landing");
    let cookie = headers.get("set-cookie").unwrap().to_str().unwrap();
    assert!(
        cookie.starts_with(&format!("mv_invite={code};"))
            && cookie.contains("HttpOnly")
            && cookie.contains("Secure")
    );
    let carried = format!("other=1; mv_invite={code}");
    let (status, headers, _) =
        send(&app, "GET", "/site/", &[("cookie", &carried)], Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-cache");
    assert_eq!(
        json(
            &app,
            "GET",
            "/v1/invite",
            &[("cookie", &carried)],
            Value::Null
        )
        .await
        .1["trial_days"],
        14
    );

    let (status, _) = json(
        &app,
        "DELETE",
        &format!("/v1/admin/invites/{code}"),
        &[],
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, revoked) = json(
        &app,
        "DELETE",
        &format!("/v1/admin/invites/{code}"),
        &[AUTH],
        Value::Null,
    )
    .await;
    assert!(revoked["revoked_at"].is_i64());
    assert_eq!(
        send(&app, "GET", "/site/", &[("cookie", &carried)], Value::Null)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/site/?invite={code}"),
            &[],
            Value::Null
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        json(
            &app,
            "GET",
            "/v1/invite",
            &[("cookie", &carried)],
            Value::Null
        )
        .await
        .1["trial_days"],
        0
    );
}

#[tokio::test]
async fn invite_signups_get_the_trial_until_places_run_out() {
    let (_temp, app) = setup();
    let (_, invite) = json(
        &app,
        "POST",
        "/v1/admin/invites",
        &[AUTH],
        json!({"code":"Friends-14","note":"Друзья","trial_days":14,"max_signups":1}),
    )
    .await;
    assert_eq!(invite["code"], "friends-14");
    let (status, _) = json(
        &app,
        "POST",
        "/v1/admin/invites",
        &[AUTH],
        json!({"code":"friends-14","trial_days":3,"max_signups":1}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    for bad in [
        json!({"trial_days":366,"max_signups":1}),
        json!({"trial_days":1,"max_signups":0}),
        json!({"code":"a b","trial_days":1,"max_signups":1}),
    ] {
        assert_eq!(
            json(&app, "POST", "/v1/admin/invites", &[AUTH], bad)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let cookie = [("cookie", "mv_invite=friends-14")];
    let (status, first) = json(
        &app,
        "POST",
        "/v1/signup",
        &cookie,
        json!({"email":"first@example.ru","password":"correct-horse-battery"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["trial_days"], 14);
    let until = first["valid_until"].as_i64().unwrap();
    let now = chrono_now();
    assert!((now + 14 * 86_400 - 5..=now + 14 * 86_400 + 5).contains(&until));
    let (status, login) = json(
        &app,
        "POST",
        "/v1/login",
        &[],
        json!({"login":"first@example.ru","password":"correct-horse-battery"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(login["account"]["active"], true);
    assert_eq!(
        json(&app, "GET", "/v1/invite", &cookie, Value::Null)
            .await
            .1["trial_days"],
        0
    );

    let (_, second) = json(
        &app,
        "POST",
        "/v1/signup",
        &cookie,
        json!({"email":"second@example.ru","password":"correct-horse-battery"}),
    )
    .await;
    assert_eq!(second["trial_days"], 0);
    let (_, plain) = json(
        &app,
        "POST",
        "/v1/signup",
        &[],
        json!({"email":"plain@example.ru","password":"correct-horse-battery"}),
    )
    .await;
    assert_eq!(plain["trial_days"], 0);

    let (_, users) = json(&app, "GET", "/v1/admin/users", &[AUTH], Value::Null).await;
    let by_login = |login: &str| {
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["login"] == login)
            .unwrap()
            .clone()
    };
    let first = by_login("first@example.ru");
    assert_eq!(first["invite"]["code"], "friends-14");
    assert_eq!(first["invite"]["trial_days"], 14);
    assert_eq!(first["day_grants"][0]["days"], 14);
    assert!(first["payments"].as_array().unwrap().is_empty());
    assert!(by_login("second@example.ru")["invite"].is_null());
    assert_eq!(by_login("second@example.ru")["valid_until"], 0);
    let (_, invites) = json(&app, "GET", "/v1/admin/invites", &[AUTH], Value::Null).await;
    assert_eq!(invites[0]["signups"], json!(["first@example.ru"]));
}

fn chrono_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}
