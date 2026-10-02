use mousevpn_account_client::AccountClient;
use mousevpn_admin_api::SharedDeviceRegistry;
use std::{
    env, fs, io, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) fn start(
    registry: &SharedDeviceRegistry,
    server_public_key: &str,
    online: impl Fn() -> Option<u32> + Send + 'static,
) -> io::Result<()> {
    // Expiration runs separately from HTTP: a slow/offline controller cannot
    // delay a subscription deadline, and legacy keys have no deadline.
    let expiring = registry.clone();
    thread::spawn(move || loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX, |value| value.as_secs());
        if let Err(error) = expiring.expire_at(now) {
            eprintln!("access expiration failed: {error}");
        }
        thread::sleep(Duration::from_secs(1));
    });
    let Ok(base) = env::var("RELAY_CONTROL_URL") else {
        return Ok(());
    };
    let path = env::var("RELAY_NODE_TOKEN_FILE")
        .map_err(|_| io::Error::other("RELAY_NODE_TOKEN_FILE is required"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "node token file must have permissions 0600",
            ));
        }
    }
    let token = fs::read_to_string(path)?.trim().to_owned();
    if token.len() < 32 {
        return Err(io::Error::other("node token is too short"));
    }
    let client = AccountClient::new(&base).map_err(io::Error::other)?;
    let registry = registry.clone();
    let server_public_key = server_public_key.to_owned();
    thread::spawn(move || loop {
        let response = match online() {
            Some(count) => client.snapshot_with_status(&token, count),
            None => client.snapshot(&token),
        };
        let result = response.and_then(|snapshot| {
            if snapshot.server_public_key != server_public_key {
                return Err("controller public key does not match this node".to_owned());
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(u64::MAX, |value| value.as_secs());
            registry
                .sync_managed(&snapshot, now)
                .map_err(|error| error.to_string())
        });
        if let Err(error) = result {
            eprintln!("controller synchronization failed: {error}");
        }
        thread::sleep(Duration::from_secs(15));
    });
    Ok(())
}
