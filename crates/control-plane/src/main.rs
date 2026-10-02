use serde::Deserialize;
use std::{env, fs, net::SocketAddr, path::PathBuf};

#[derive(Deserialize)]
struct Settings {
    listen: SocketAddr,
    database: PathBuf,
    admin_token_file: PathBuf,
    public_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    let [flag, path] = arguments.as_slice() else {
        return Err("usage: relay-hub --config <hub.toml>".into());
    };
    if flag != "--config" {
        return Err("usage: relay-hub --config <hub.toml>".into());
    }
    let settings: Settings = toml::from_str(&fs::read_to_string(path)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&settings.admin_token_file)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("admin token file must have permissions 0600".into());
        }
    }
    let token = fs::read_to_string(&settings.admin_token_file)?;
    let mut app = mousevpn_control_plane::router(
        mousevpn_control_plane::Store::open(&settings.database)?,
        token.trim(),
    )?;
    if let Some(directory) = settings.public_dir {
        app = app.nest_service("/site", tower_http::services::ServeDir::new(directory));
    }
    let listener = tokio::net::TcpListener::bind(settings.listen).await?;
    eprintln!("controller listening on {}", settings.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                if let Ok(mut terminate) =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                {
                    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
                } else {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
