#![allow(clippy::needless_pass_by_value)] // Tauri IPC commands deserialize owned arguments.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    thread,
};

use mousevpn_config::ClientProtocol;
use profiles::{create_private_dir, normalized_id, profile_path};
use serde::Serialize;
use tauri::{Manager, State, WindowEvent};
use uuid::Uuid;

mod account;
mod helper_log;
mod helper_runtime;
mod profiles;
mod reliability;
#[tauri::command]
fn open_account_page(kind: String) -> Result<(), String> {
    let url = match kind.as_str() {
        "signup" => "https://mousevpn.space/#request",
        "contact" => "https://t.me/napsy13",
        _ => return Err("Неизвестная страница".to_owned()),
    };
    Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(display_error)
}

#[tauri::command]
async fn account_view() -> Result<account::AccountView, String> {
    tauri::async_runtime::spawn_blocking(account::view)
        .await
        .map_err(display_error)?
}

#[tauri::command]
async fn account_login(
    base: String,
    login: String,
    password: String,
) -> Result<account::AccountView, String> {
    tauri::async_runtime::spawn_blocking(move || account::login(base, login, password))
        .await
        .map_err(display_error)?
}

#[tauri::command]
async fn account_refresh() -> Result<account::AccountView, String> {
    tauri::async_runtime::spawn_blocking(account::refresh)
        .await
        .map_err(display_error)?
}

#[tauri::command]
async fn account_revoke_device(id: String) -> Result<account::AccountView, String> {
    tauri::async_runtime::spawn_blocking(move || account::revoke(&id))
        .await
        .map_err(display_error)?
}

#[tauri::command]
async fn account_logout() -> Result<account::AccountView, String> {
    tauri::async_runtime::spawn_blocking(account::logout)
        .await
        .map_err(display_error)?
}

#[tauri::command]
async fn billing_view() -> Result<mousevpn_account_client::BillingView, String> {
    tauri::async_runtime::spawn_blocking(account::billing)
        .await
        .map_err(display_error)?
}
#[tauri::command]
async fn billing_submit(
    request: mousevpn_account_client::NewPaymentRequest,
) -> Result<mousevpn_account_client::PaymentRequest, String> {
    tauri::async_runtime::spawn_blocking(move || account::request_payment(request))
        .await
        .map_err(display_error)?
}
#[tauri::command]
async fn support_tickets() -> Result<Vec<mousevpn_account_client::TicketSummary>, String> {
    tauri::async_runtime::spawn_blocking(account::tickets)
        .await
        .map_err(display_error)?
}
#[tauri::command]
async fn support_create(
    subject: String,
    text: String,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    tauri::async_runtime::spawn_blocking(move || account::create_ticket(&subject, &text))
        .await
        .map_err(display_error)?
}
#[tauri::command]
async fn support_ticket(
    id: String,
    before: Option<i64>,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    tauri::async_runtime::spawn_blocking(move || account::ticket(&id, before))
        .await
        .map_err(display_error)?
}
#[tauri::command]
async fn support_reply(
    id: String,
    text: String,
) -> Result<mousevpn_account_client::TicketDetail, String> {
    tauri::async_runtime::spawn_blocking(move || account::reply(&id, &text))
        .await
        .map_err(display_error)?
}

#[tauri::command]
async fn account_register_device() -> Result<account::AccountView, String> {
    tauri::async_runtime::spawn_blocking(account::register_device)
        .await
        .map_err(display_error)?
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionSnapshot {
    state: String,
    message: String,
    profile_id: Option<String>,
}

impl Default for ConnectionSnapshot {
    fn default() -> Self {
        Self {
            state: "disconnected".to_owned(),
            message: "VPN выключен".to_owned(),
            profile_id: None,
        }
    }
}

struct AppState {
    child: Mutex<Option<Child>>,
    managed: std::sync::atomic::AtomicBool,
    snapshot: Arc<Mutex<ConnectionSnapshot>>,
    reliability: Arc<Mutex<reliability::ReliabilityMonitor>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
            managed: std::sync::atomic::AtomicBool::new(false),
            snapshot: Arc::new(Mutex::new(ConnectionSnapshot::default())),
            reliability: Arc::new(Mutex::new(reliability::ReliabilityMonitor::load())),
        }
    }
}

#[tauri::command]
fn list_profiles() -> Result<Vec<profiles::ProfileSummary>, String> {
    profiles::list()
}
#[tauri::command]
fn import_profile(token: String, password: String) -> Result<profiles::ProfileSummary, String> {
    profiles::import(token, password)
}
#[tauri::command]
async fn set_profile_protocol(
    id: String,
    protocol: ClientProtocol,
    state: State<'_, AppState>,
) -> Result<profiles::ProfileSummary, String> {
    let id = normalized_id(&id)?;
    let snapshot = lock(&state.snapshot)?.clone();
    if matches!(
        snapshot.state.as_str(),
        "connecting" | "connected" | "disconnecting"
    ) && (snapshot.profile_id.as_deref() == Some(&id) || profiles::is_managed(&id)?)
    {
        return Err("Сначала отключите VPN".to_owned());
    }
    tauri::async_runtime::spawn_blocking(move || profiles::set_protocol(&id, protocol))
        .await
        .map_err(display_error)?
}
#[tauri::command]
fn delete_profile(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let id = normalized_id(&id)?;
    let snapshot = lock(&state.snapshot)?.clone();
    if snapshot.profile_id.as_deref() == Some(&id) && snapshot.state != "disconnected" {
        return Err("Сначала отключите VPN".to_owned());
    }
    profiles::remove(&id)?;
    lock(&state.reliability)?.clear_profile(&id)
}

#[tauri::command]
fn connect_profile(id: String, state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    let id = normalized_id(&id)?;
    let path = profile_path(&id)?;
    let (config, managed) = profiles::connection_config(&id)?;
    let protocol = config.protocol;
    config.validate().map_err(display_error)?;

    let mut child_slot = lock(&state.child)?;
    if let Some(child) = child_slot.as_mut() {
        if child.try_wait().map_err(display_error)?.is_none() {
            return Err("VPN уже запущен".to_owned());
        }
        *child_slot = None;
    }

    let (executable, is_standalone_helper) = privileged_helper_executable()?;
    let mut command = Command::new("pkexec");
    command.arg(executable);
    if !is_standalone_helper {
        command.arg("--helper");
    }
    let mut child = command
        .arg("--config")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Не удалось открыть PolicyKit: {error}"))?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Не удалось открыть журнал helper-процесса".to_owned())?;
    let snapshot = ConnectionSnapshot {
        state: "connecting".to_owned(),
        message: "Ожидание разрешения PolicyKit…".to_owned(),
        profile_id: Some(id.clone()),
    };
    *lock(&state.snapshot)? = snapshot.clone();
    let shared_snapshot = Arc::clone(&state.snapshot);
    let reliability = Arc::clone(&state.reliability);
    lock(&reliability)?.begin(id.clone(), protocol);
    let log = helper_log::HelperLog::open().ok();
    thread::spawn(move || {
        read_helper_status(stderr, &shared_snapshot, &reliability, &id, protocol, log);
    });
    state
        .managed
        .store(managed, std::sync::atomic::Ordering::Release);
    *child_slot = Some(child);
    Ok(snapshot)
}

fn privileged_helper_executable() -> Result<(PathBuf, bool), String> {
    let Some(appdir) = std::env::var_os("APPDIR") else {
        return std::env::current_exe()
            .map(|path| (path, false))
            .map_err(display_error);
    };
    let bundled = PathBuf::from(appdir).join("usr/lib/mousevpn/mousevpn-helper");
    if !bundled.is_file() {
        return Err("В AppImage отсутствует привилегированный MouseVPN helper".to_owned());
    }
    let directory = dirs::cache_dir()
        .ok_or_else(|| "Не удалось определить каталог кэша пользователя".to_owned())?
        .join("mousevpn");
    create_private_dir(&directory)?;
    let destination = directory.join("mousevpn-helper");
    let temporary = directory.join(format!("mousevpn-helper.tmp-{}", Uuid::new_v4()));
    let result = (|| {
        fs::copy(&bundled, &temporary).map_err(display_error)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))
            .map_err(display_error)?;
        fs::rename(&temporary, &destination).map_err(display_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok((destination, true))
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    disconnect_inner(&state)
}

fn disconnect_inner(state: &AppState) -> Result<ConnectionSnapshot, String> {
    let mut child_slot = lock(&state.child)?;
    let child = child_slot
        .as_mut()
        .ok_or_else(|| "VPN уже выключен".to_owned())?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| "Канал управления VPN закрыт".to_owned())?;
    stdin.write_all(b"stop\n").map_err(display_error)?;
    stdin.flush().map_err(display_error)?;
    let mut snapshot = lock(&state.snapshot)?;
    "disconnecting".clone_into(&mut snapshot.state);
    "Безопасно отключаем VPN…".clone_into(&mut snapshot.message);
    Ok(snapshot.clone())
}

#[tauri::command]
fn connection_status(state: State<'_, AppState>) -> Result<ConnectionSnapshot, String> {
    let mut child_slot = lock(&state.child)?;
    if let Some(child) = child_slot.as_mut() {
        if let Some(exit) = child.try_wait().map_err(display_error)? {
            *child_slot = None;
            let mut snapshot = lock(&state.snapshot)?;
            if snapshot.state == "disconnecting" || exit.success() {
                *snapshot = ConnectionSnapshot::default();
            } else if snapshot.state != "error" {
                "error".clone_into(&mut snapshot.state);
                "VPN-процесс неожиданно завершился".clone_into(&mut snapshot.message);
            }
        }
    }
    drop(child_slot);
    let snapshot = lock(&state.snapshot)?.clone();
    if state.managed.load(std::sync::atomic::Ordering::Acquire)
        && matches!(snapshot.state.as_str(), "connecting" | "connected")
        && snapshot
            .profile_id
            .as_ref()
            .is_some_and(|id| !account::allows_server(id))
    {
        return disconnect_inner(&state);
    }
    Ok(snapshot)
}

#[tauri::command]
fn reliability_diagnostics(
    profile_id: String,
    state: State<'_, AppState>,
) -> Result<reliability::ReliabilitySummary, String> {
    let profile_id = normalized_id(&profile_id)?;
    Ok(lock(&state.reliability)?.summary(&profile_id))
}

#[tauri::command]
fn clear_reliability_diagnostics(
    profile_id: String,
    state: State<'_, AppState>,
) -> Result<reliability::ReliabilitySummary, String> {
    let profile_id = normalized_id(&profile_id)?;
    let mut monitor = lock(&state.reliability)?;
    monitor.clear_profile(&profile_id)?;
    Ok(monitor.summary(&profile_id))
}

fn read_helper_status(
    stderr: impl std::io::Read,
    snapshot: &Arc<Mutex<ConnectionSnapshot>>,
    reliability: &Arc<Mutex<reliability::ReliabilityMonitor>>,
    profile_id: &str,
    protocol: ClientProtocol,
    mut log: Option<helper_log::HelperLog>,
) {
    let log_path = log.as_ref().map(|log| log.path().display().to_string());
    if let Some(log) = log.as_mut() {
        log.write("MOUSEVPN_STATE=helper_started");
    }
    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
        if let Some(log) = log.as_mut() {
            log.write(&line);
        }
        if let Some(payload) = line.strip_prefix("MOUSEVPN_METRICS=") {
            match serde_json::from_str::<reliability::RuntimeMetrics>(payload) {
                Ok(metrics) => {
                    if let Ok(mut monitor) = reliability.lock() {
                        if let Err(error) = monitor.observe(profile_id, protocol, metrics) {
                            if let Some(log) = log.as_mut() {
                                log.write(&format!("MOUSEVPN_DIAGNOSTICS_WARNING={error}"));
                            }
                        }
                    }
                }
                Err(error) => {
                    if let Some(log) = log.as_mut() {
                        log.write(&format!("MOUSEVPN_DIAGNOSTICS_WARNING={error}"));
                    }
                }
            }
            continue;
        }
        let Ok(mut current) = snapshot.lock() else {
            return;
        };
        if current.profile_id.as_deref() != Some(profile_id) || current.state == "disconnecting" {
            continue;
        }
        if matches!(
            line.as_str(),
            "MOUSEVPN_STATE=connected" | "MOUSEVPN_STATE=reconnected"
        ) || line.contains("MouseVPN connected")
        {
            "connected".clone_into(&mut current.state);
            if line == "MOUSEVPN_STATE=reconnected" {
                "Соединение восстановлено".clone_into(&mut current.message);
            } else {
                "Защищённое соединение установлено".clone_into(&mut current.message);
            }
        } else if line == "MOUSEVPN_STATE=reconnecting" {
            "connecting".clone_into(&mut current.state);
            "Сеть изменилась, переподключаемся…".clone_into(&mut current.message);
        } else if let Some(message) = line.strip_prefix("MOUSEVPN_RECONNECT_ERROR=") {
            "connecting".clone_into(&mut current.state);
            current.message = format!("Ждём восстановления сети: {message}");
        } else if let Some(message) = line.strip_prefix("MOUSEVPN_ERROR=") {
            "error".clone_into(&mut current.state);
            current.message = log_path.as_ref().map_or_else(
                || message.to_owned(),
                |path| format!("{message}\nЖурнал: {path}"),
            );
        }
    }
    if let Some(log) = log.as_mut() {
        log.write("MOUSEVPN_STATE=helper_stderr_closed");
    }
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, String> {
    mutex
        .lock()
        .map_err(|_| "Внутренняя блокировка повреждена".to_owned())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

struct MouseVpnTray {
    app: tauri::AppHandle,
}

impl ksni::Tray for MouseVpnTray {
    fn id(&self) -> String {
        "mousevpn".to_owned()
    }

    fn title(&self) -> String {
        let state = self.app.state::<AppState>();
        let label = state.snapshot.lock().ok().map_or(
            "состояние неизвестно",
            |snapshot| match snapshot.state.as_str() {
                "connected" => "подключено",
                "connecting" => "подключение",
                "disconnecting" => "отключение",
                "error" => "ошибка",
                _ => "отключено",
            },
        );
        format!("MouseVPN — {label}")
    }

    fn icon_name(&self) -> String {
        "network-vpn".to_owned()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        static ICON: OnceLock<ksni::Icon> = OnceLock::new();
        vec![ICON
            .get_or_init(|| {
                let image = image::load_from_memory_with_format(
                    include_bytes!("../icons/icon.png"),
                    image::ImageFormat::Png,
                )
                .expect("embedded tray icon is valid")
                .into_rgba8();
                let (width, height) = image.dimensions();
                let mut data = image.into_raw();
                for pixel in data.chunks_exact_mut(4) {
                    pixel.rotate_right(1);
                }
                ksni::Icon {
                    width: i32::try_from(width).expect("tray icon width fits i32"),
                    height: i32::try_from(height).expect("tray icon height fits i32"),
                    data,
                }
            })
            .clone()]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        show_main_window(&self.app);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;

        vec![
            StandardItem {
                label: "Открыть MouseVPN".to_owned(),
                icon_name: "window-new".to_owned(),
                activate: Box::new(|tray: &mut Self| show_main_window(&tray.app)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Отключить VPN".to_owned(),
                icon_name: "network-vpn-disconnected".to_owned(),
                activate: Box::new(|tray: &mut Self| {
                    let state = tray.app.state::<AppState>();
                    let _ = disconnect_inner(&state);
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Выйти".to_owned(),
                icon_name: "application-exit".to_owned(),
                activate: Box::new(|tray: &mut Self| {
                    let state = tray.app.state::<AppState>();
                    let _ = disconnect_inner(&state);
                    tray.app.exit(0);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

fn start_linux_tray(app: tauri::AppHandle) {
    thread::spawn(move || {
        use ksni::blocking::TrayMethods;

        match (MouseVpnTray { app }).spawn() {
            Ok(_tray) => loop {
                thread::park();
            },
            Err(error) => eprintln!("MouseVPN tray unavailable: {error}"),
        }
    });
}

fn run_gui() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            start_linux_tray(app.handle().clone());

            if let Some(window) = app.get_webview_window("main") {
                let hidden_window = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = hidden_window.hide();
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            open_account_page,
            account_view,
            account_login,
            account_refresh,
            account_revoke_device,
            account_logout,
            account_register_device,
            billing_view,
            billing_submit,
            support_tickets,
            support_create,
            support_ticket,
            support_reply,
            list_profiles,
            import_profile,
            set_profile_protocol,
            delete_profile,
            connect_profile,
            disconnect,
            connection_status,
            reliability_diagnostics,
            clear_reliability_diagnostics,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run MouseVPN GUI");
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if let [_, watchdog, parent_flag, parent, started_flag, started, server_flag, server] =
        arguments.as_slice()
    {
        if watchdog == "--network-watchdog"
            && parent_flag == "--parent"
            && started_flag == "--started"
            && server_flag == "--server"
        {
            let result = parent
                .parse()
                .map_err(|_| "Неверный PID watchdog".to_owned())
                .and_then(|parent| {
                    started
                        .parse()
                        .map_err(|_| "Неверное время старта watchdog".to_owned())
                        .map(|started| (parent, started))
                })
                .and_then(|(parent, started)| {
                    server
                        .parse()
                        .map_err(|_| "Неверный адрес сервера watchdog".to_owned())
                        .map(|server| (parent, started, server))
                })
                .and_then(|(parent, started, server)| {
                    helper_runtime::run_watchdog(parent, started, server)
                });
            if let Err(error) = result {
                eprintln!("MOUSEVPN_ERROR={error}");
                std::process::exit(1);
            }
            return;
        }
    }
    let helper_path = match arguments.as_slice() {
        [_, helper, config, path] if helper == "--helper" && config == "--config" => Some(path),
        _ => None,
    };
    if let Some(path) = helper_path {
        if let Err(error) = helper_runtime::run(Path::new(path.as_str())) {
            eprintln!("MOUSEVPN_ERROR={error}");
            std::process::exit(1);
        }
    } else {
        run_gui();
    }
}
