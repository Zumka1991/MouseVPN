use std::panic::{catch_unwind, AssertUnwindSafe};

use anyhow::{anyhow, Result};
use jni::{
    objects::{JObject, JString},
    sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE},
    JNIEnv,
};
use mousevpn_client_wire::ClientWire;
use mousevpn_config::{ClientConfig, ClientProtocol};

use crate::{
    handshake::{bind_socket, negotiate_cancellable},
    registry::{
        insert_pending, insert_running, metrics, network_changed, status, stop, take_pending,
        PendingSession,
    },
    session,
    socket_protector::SocketProtector,
};

#[no_mangle]
pub extern "system" fn Java_dev_mousevpn_app_NativeBridge_prepare(
    mut env: JNIEnv,
    _object: JObject,
    service: JObject,
    endpoint: JString,
    server_public_key: JString,
    client_private_key: JString,
    protocol: JString,
    generation: jlong,
) -> jstring {
    let result = catch_unwind(AssertUnwindSafe(|| {
        prepare(
            &mut env,
            &service,
            &endpoint,
            &server_public_key,
            &client_private_key,
            &protocol,
            generation,
        )
    }));
    match result {
        Ok(Ok(value)) => env
            .new_string(value)
            .map_or(std::ptr::null_mut(), JString::into_raw),
        Ok(Err(error)) => {
            throw(&mut env, &error);
            std::ptr::null_mut()
        }
        Err(_) => {
            throw(&mut env, &anyhow!("native panic during connection setup"));
            std::ptr::null_mut()
        }
    }
}

fn prepare(
    env: &mut JNIEnv,
    service: &JObject,
    endpoint: &JString,
    server_public_key: &JString,
    client_private_key: &JString,
    protocol: &JString,
    generation: i64,
) -> Result<String> {
    let protocol = parse_protocol(env.get_string(protocol)?.to_str()?)?;
    let config = ClientConfig {
        server: env.get_string(endpoint)?.to_str()?.parse()?,
        server_public_key: env.get_string(server_public_key)?.into(),
        client_private_key: env.get_string(client_private_key)?.into(),
        tun_name: "android".to_owned(),
        protocol,
    }
    .validate()?;
    let wire = ClientWire::from_config(&config)?;
    let protector = SocketProtector::new(env, service)?;
    let socket = bind_socket(config.server)?;
    protector.protect(&socket)?;
    let (transport, plane, parameters) = negotiate_cancellable(socket, &config, &wire, || {
        protector.connection_cancelled(generation)
    })?;
    let handle = insert_pending(PendingSession {
        transport,
        plane,
        wire,
        config,
        parameters,
        protector,
    })?;
    Ok(serde_json::json!({
        "handle": handle,
        "address": parameters.client_address.to_string(),
        "prefix": parameters.prefix_len,
        "mtu": parameters.mtu,
        "dns": parameters.dns.to_string(),
    })
    .to_string())
}

fn parse_protocol(value: &str) -> Result<ClientProtocol> {
    match value {
        "legacy" => Ok(ClientProtocol::Legacy),
        "morph_quiet" => Ok(ClientProtocol::MorphQuiet),
        "morph_balanced" => Ok(ClientProtocol::MorphBalanced),
        "morph_paranoid" => Ok(ClientProtocol::MorphParanoid),
        _ => Err(anyhow!("unsupported MouseVPN protocol mode: {value}")),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_mousevpn_app_NativeBridge_start(
    mut env: JNIEnv,
    _object: JObject,
    handle: jlong,
    tun_fd: jint,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
        let pending = take_pending(handle)?;
        let spawned = session::spawn(
            tun_fd,
            pending.transport,
            pending.plane,
            pending.wire,
            pending.config,
            pending.parameters,
            pending.protector,
        )?;
        insert_running(handle, spawned)
    }));
    match result {
        Ok(Ok(())) => JNI_TRUE,
        Ok(Err(error)) => {
            throw(&mut env, &error);
            JNI_FALSE
        }
        Err(_) => {
            throw(&mut env, &anyhow!("native panic while starting tunnel"));
            JNI_FALSE
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_mousevpn_app_NativeBridge_networkChanged(
    _env: JNIEnv,
    _object: JObject,
    handle: jlong,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| network_changed(handle)));
}

#[no_mangle]
pub extern "system" fn Java_dev_mousevpn_app_NativeBridge_stop(
    _env: JNIEnv,
    _object: JObject,
    handle: jlong,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| stop(handle)));
}

#[no_mangle]
pub extern "system" fn Java_dev_mousevpn_app_NativeBridge_status(
    env: JNIEnv,
    _object: JObject,
    handle: jlong,
) -> jstring {
    env.new_string(status(handle))
        .map_or(std::ptr::null_mut(), JString::into_raw)
}

#[no_mangle]
pub extern "system" fn Java_dev_mousevpn_app_NativeBridge_metrics(
    env: JNIEnv,
    _object: JObject,
    handle: jlong,
) -> jstring {
    env.new_string(metrics(handle))
        .map_or(std::ptr::null_mut(), JString::into_raw)
}

fn throw(env: &mut JNIEnv, error: &anyhow::Error) {
    let _ = env.throw_new("java/lang/IllegalStateException", format!("{error:#}"));
}

#[no_mangle]
pub extern "system" fn Java_dev_mousevpn_app_NativeBridge_generateDeviceKeys(
    mut env: JNIEnv,
    _object: JObject,
) -> jstring {
    if let Ok(Ok(keys)) = catch_unwind(AssertUnwindSafe(mousevpn_crypto::KeyPair::generate)) {
        let json = serde_json::json!({
            "private_key":mousevpn_config::encode_secret_key(&keys.secret),
            "public_key":mousevpn_config::encode_public_key(&keys.public),
        })
        .to_string();
        env.new_string(json)
            .map_or(std::ptr::null_mut(), JString::into_raw)
    } else {
        throw(&mut env, &anyhow!("device key generation failed"));
        std::ptr::null_mut()
    }
}
