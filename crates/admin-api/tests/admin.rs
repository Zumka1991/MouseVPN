use std::{net::SocketAddr, path::Path};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use mousevpn_admin_api::{
    router, AdminSettings, AdminToken, DevicePlatform, SeedDevice, SharedDeviceRegistry,
    TrafficStore,
};
use mousevpn_config::decode_public_key;
use mousevpn_crypto::KeyPair;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn empty_registry_denies_all_keys_and_stays_empty_on_restart() {
    let temporary = TempDir::new().unwrap();
    let registry = registry(temporary.path());
    let record = registry.list().unwrap().remove(0);
    let key = decode_public_key(&record.public_key).unwrap();
    let live = registry.authorize(&key).unwrap();
    assert!(registry.revoke(&record.public_key).unwrap());
    assert!(!live.authorization.is_active());
    assert!(registry.list().unwrap().is_empty());
    assert!(registry.authorize(&key).is_none());
    let reopened = SharedDeviceRegistry::open(
        temporary.path().join("devices.toml"),
        Vec::new(),
        "10.77.0.1".parse().unwrap(),
        24,
    )
    .unwrap();
    assert!(reopened.list().unwrap().is_empty());
    let snapshot = mousevpn_account_client::NodeSnapshot {
        server_id: "central".to_owned(),
        server_public_key: String::new(),
        generated_at: 100,
        lease_until: 400,
        devices: Vec::new(),
    };
    reopened.sync_managed(&snapshot, 100).unwrap();
}

#[tokio::test]
async fn requires_admin_token() {
    let temporary = TempDir::new().expect("temporary directory");
    let app = test_router(&temporary);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/devices")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provisions_lists_and_revokes_persistent_devices() {
    let temporary = TempDir::new().expect("temporary directory");
    let app = test_router(&temporary);

    let device = send_json(
        &app,
        Method::POST,
        "/v1/devices",
        Some(r#"{"name":"Alice phone","platform":"android","profile_password":"correct horse"}"#),
    )
    .await;
    assert_eq!(device["device"]["name"], "Alice phone");
    assert_eq!(device["device"]["address"], "10.77.0.3");
    assert!(device["profile_token"]
        .as_str()
        .expect("profile token")
        .starts_with("MV1."));
    assert!(device["client_config"]
        .as_str()
        .expect("client config")
        .contains("198.51.100.10:51820"));

    let devices = send_json(&app, Method::GET, "/v1/devices", None).await;
    assert_eq!(devices.as_array().expect("devices").len(), 2);
    let public_key = device["device"]["public_key"].as_str().expect("public key");
    let revoked = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/devices/{public_key}"),
        None,
    )
    .await;
    assert_eq!(revoked["revoked"], true);

    let registry = SharedDeviceRegistry::open(
        temporary.path().join("devices.toml"),
        Vec::new(),
        "10.77.0.1".parse().expect("tunnel address"),
        24,
    )
    .expect("reopened registry");
    assert_eq!(registry.list().expect("device list").len(), 1);
}

#[test]
fn revocation_disables_an_existing_session_flag() {
    let temporary = TempDir::new().expect("temporary directory");
    let registry = registry(temporary.path());
    let provisioned = registry
        .provision("phone", DevicePlatform::Android)
        .expect("provisioned device");
    let public_key = decode_public_key(&provisioned.record.public_key).expect("public key");
    let lease = registry.authorize(&public_key).expect("device lease");
    assert!(lease.authorization.is_active());

    assert!(registry
        .revoke(&provisioned.record.public_key)
        .expect("revoked device"));
    assert!(!lease.authorization.is_active());
}

fn test_router(temporary: &TempDir) -> axum::Router {
    router(
        registry(temporary.path()),
        TrafficStore::open(temporary.path().join("traffic.sqlite")).expect("traffic store"),
        AdminToken::new(TOKEN).expect("admin token"),
        AdminSettings {
            public_endpoint: "198.51.100.10:51820"
                .parse::<SocketAddr>()
                .expect("endpoint"),
            server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            tun_name: "mousevpn0".to_owned(),
        },
    )
}

#[tokio::test]
async fn returns_authenticated_traffic_report() {
    let temporary = TempDir::new().expect("temporary directory");
    let traffic =
        TrafficStore::open(temporary.path().join("traffic.sqlite")).expect("traffic store");
    let counter = traffic.counter("phone-key", "Alice phone");
    counter.add_upload(1_024);
    counter.add_download(2_048);
    let app = router(
        registry(temporary.path()),
        traffic,
        AdminToken::new(TOKEN).expect("admin token"),
        AdminSettings {
            public_endpoint: "198.51.100.10:51820".parse().expect("endpoint"),
            server_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            tun_name: "mousevpn0".to_owned(),
        },
    );

    let report = send_json(&app, Method::GET, "/v1/traffic?hours=24", None).await;
    assert_eq!(report["totals"]["hour"]["upload_bytes"], 1_024);
    assert_eq!(report["totals"]["day"]["download_bytes"], 2_048);
    assert_eq!(report["hourly"].as_array().expect("hourly").len(), 24);
    assert_eq!(report["devices"][0]["name"], "Alice phone");
}

fn registry(directory: &Path) -> SharedDeviceRegistry {
    let owner = KeyPair::generate().expect("owner keys");
    SharedDeviceRegistry::open(
        directory.join("devices.toml"),
        vec![SeedDevice {
            name: "owner".to_owned(),
            public_key: owner.public,
            address: "10.77.0.2".parse().expect("owner address"),
        }],
        "10.77.0.1".parse().expect("tunnel address"),
        24,
    )
    .expect("device registry")
}

async fn send_json(app: &axum::Router, method: Method, uri: &str, body: Option<&str>) -> Value {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.unwrap_or_default().to_owned()))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    assert!(
        response.status().is_success(),
        "status: {}",
        response.status()
    );
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("JSON response")
}

#[test]
fn managed_expiration_and_restriction_preserve_legacy_keys_and_live_addresses() {
    use mousevpn_account_client::{NodeDevice, NodeSnapshot};
    let temporary = TempDir::new().unwrap();
    let registry = registry(temporary.path());
    let owner = registry.list().unwrap()[0].public_key.clone();
    let owner_key = decode_public_key(&owner).unwrap();
    let first = KeyPair::generate().unwrap();
    let second = KeyPair::generate().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let make = |keys: &KeyPair, name: &str| NodeDevice {
        name: name.to_owned(),
        platform: "windows".to_owned(),
        public_key: mousevpn_config::encode_public_key(&keys.public),
        valid_until: now + 120,
    };
    let mut snapshot = NodeSnapshot {
        server_id: "node-a".to_owned(),
        server_public_key: String::new(),
        generated_at: now,
        lease_until: now + 300,
        devices: vec![make(&first, "first")],
    };
    registry.sync_managed(&snapshot, now).unwrap();
    let first_lease = registry.authorize(&first.public).unwrap();
    let first_address = first_lease.address;
    snapshot.devices.insert(0, make(&second, "second"));
    registry.sync_managed(&snapshot, now).unwrap();
    assert_eq!(
        registry.authorize(&first.public).unwrap().address,
        first_address
    );
    assert!(first_lease.authorization.is_active());
    let second_lease = registry.authorize(&second.public).unwrap();
    snapshot.devices.remove(0);
    registry.sync_managed(&snapshot, now).unwrap();
    assert!(!second_lease.authorization.is_active());
    assert!(registry.authorize(&second.public).is_none());
    registry.expire_at(now + 120).unwrap();
    assert!(!first_lease.authorization.is_active());
    assert!(registry.authorize(&first.public).is_none());
    assert!(registry
        .authorize(&owner_key)
        .unwrap()
        .authorization
        .is_active());
    snapshot.devices.clear();
    registry.sync_managed(&snapshot, now).unwrap();
    assert_eq!(registry.list().unwrap().len(), 1);
    assert_eq!(registry.list().unwrap()[0].public_key, owner);
}

#[test]
fn controller_cannot_take_over_legacy_keys_or_revive_expired_keys_after_restart() {
    use mousevpn_account_client::{NodeDevice, NodeSnapshot};
    let temporary = TempDir::new().unwrap();
    let registry = registry(temporary.path());
    let legacy = registry.list().unwrap()[0].clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut snapshot = NodeSnapshot {
        server_id: "node-a".to_owned(),
        server_public_key: String::new(),
        generated_at: now,
        lease_until: now + 300,
        devices: vec![NodeDevice {
            name: "collision".to_owned(),
            platform: "android".to_owned(),
            public_key: legacy.public_key.clone(),
            valid_until: now + 200,
        }],
    };
    assert!(registry.sync_managed(&snapshot, now).is_err());
    assert_eq!(registry.list().unwrap(), vec![legacy.clone()]);
    let keys = KeyPair::generate().unwrap();
    snapshot.devices[0].public_key = mousevpn_config::encode_public_key(&keys.public);
    registry.sync_managed(&snapshot, now).unwrap();
    let path = temporary.path().join("devices.toml");
    let contents = std::fs::read_to_string(&path)
        .unwrap()
        .replace(&format!("valid_until = {}", now + 200), "valid_until = 1");
    std::fs::write(&path, contents).unwrap();
    let reopened =
        SharedDeviceRegistry::open(&path, Vec::new(), "10.77.0.1".parse().unwrap(), 24).unwrap();
    assert!(reopened.authorize(&keys.public).is_none());
    assert!(reopened
        .authorize(&decode_public_key(&legacy.public_key).unwrap())
        .is_some());
}
