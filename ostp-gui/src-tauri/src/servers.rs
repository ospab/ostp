//! Servers the app installs and manages over SSH: the Tauri side of
//! `ostp_ssh::manager`. The servers list sits next to the app's config; the
//! master key that seals passwords and private keys in it lives in the
//! system credential store (Windows Credential Manager, Secret Service).

use ostp_ssh::manager::{Action, Channel, Manager};
use ostp_ssh::{Auth, Target};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::OnceCell;

static MANAGER: OnceCell<Arc<Manager>> = OnceCell::const_new();

/// Installs and server changes in progress. Quitting from the tray waits for
/// them to end.
static JOBS: AtomicUsize = AtomicUsize::new(0);

pub fn jobs_running() -> usize {
    JOBS.load(Ordering::SeqCst)
}

struct Job;

impl Job {
    fn start() -> Self {
        JOBS.fetch_add(1, Ordering::SeqCst);
        Job
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        JOBS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Limits on what the page may send. They are generous; they exist so a
/// pasted file or a runaway string is refused here, with a reason.
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_NAME_CHARS: usize = 64;
const MAX_ARG_BYTES: usize = 512;
const MAX_ARGS: usize = 4;

fn short_text(what: &str, v: &str, max: usize) -> Result<(), String> {
    if v.chars().count() > max || v.contains('\0') {
        return Err(format!("{what} is too long or contains a null character"));
    }
    Ok(())
}

const KEYRING_SERVICE: &str = "ostp-gui";
const KEYRING_ENTRY: &str = "servers-master-key";

/// The master key from the credential store, made on first use. `None` when
/// the system has no usable store: then nothing secret is saved.
fn master_key() -> Option<[u8; 32]> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ENTRY).ok()?;
    let decode = |hex: &str| -> Option<[u8; 32]> {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| hex.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
            .collect::<Option<_>>()?;
        bytes.try_into().ok()
    };
    match entry.get_password() {
        Ok(hex) => decode(hex.trim()),
        Err(keyring::Error::NoEntry) => {
            let key = ostp_ssh::store::Vault::random_key();
            let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            entry.set_password(&hex).ok()?;
            // Read back: some stores accept a write they cannot keep.
            (entry.get_password().ok()?.trim() == hex).then_some(key)
        }
        Err(e) => {
            eprintln!("[OSTP] credential store unavailable: {e}");
            None
        }
    }
}

async fn manager() -> Result<Arc<Manager>, String> {
    MANAGER
        .get_or_try_init(|| async {
            let file = crate::get_config_path().with_file_name("servers.json");
            let key = tauri::async_runtime::spawn_blocking(master_key).await.ok().flatten();
            Manager::new(&file, key).map(Arc::new).map_err(|e| format!("{e:#}"))
        })
        .await
        .cloned()
}

/// A password or key typed in the app, for a server whose secret is not
/// remembered (or when adding one).
#[derive(Deserialize)]
pub struct AuthIn {
    kind: String,
    secret: String,
    #[serde(default)]
    passphrase: Option<String>,
}

impl AuthIn {
    fn into_auth(self) -> Result<Auth, String> {
        if self.secret.is_empty() {
            return Err("enter the password or the private key".into());
        }
        if self.secret.len() > MAX_SECRET_BYTES || self.passphrase.as_ref().is_some_and(|p| p.len() > 1024) {
            return Err("the password or the key is too long".into());
        }
        match self.kind.as_str() {
            "password" => Ok(Auth::Password(self.secret)),
            "key" => Ok(Auth::Key { text: self.secret, passphrase: self.passphrase }),
            other => Err(format!("unknown sign-in kind {other}")),
        }
    }
}

fn auth(a: Option<AuthIn>) -> Result<Option<Auth>, String> {
    a.map(AuthIn::into_auth).transpose()
}

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

fn channel() -> Channel {
    Channel::of_version(&crate::app_build_tag())
}

/// Sends each output line to the page while a long command runs.
fn line_sink(app: &tauri::AppHandle, id: &str) -> impl FnMut(&str) {
    let app = app.clone();
    let id = id.to_string();
    move |line: &str| {
        let _ = app.emit("server-line", json!({ "id": id, "line": line }));
    }
}

#[tauri::command]
pub async fn servers_list() -> Result<Value, String> {
    let m = manager().await?;
    Ok(json!({ "servers": m.list().await, "can_remember": m.can_remember() }))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn server_add(name: String, host: String, port: u16, user: String, auth: AuthIn, remember: bool) -> Result<Value, String> {
    let m = manager().await?;
    let host = host.trim().to_string();
    if host.is_empty() || user.trim().is_empty() {
        return Err("enter the server's address and the login".into());
    }
    if port == 0 {
        return Err("the SSH port must be from 1 to 65535".into());
    }
    if host.len() > 253 || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("the server address is not valid".into());
    }
    short_text("the login", user.trim(), MAX_NAME_CHARS)?;
    short_text("the name", &name, MAX_NAME_CHARS)?;
    let target = Target { host, port, user: user.trim().to_string() };
    let info = m.add(&name, target, auth.into_auth()?, remember).await.map_err(err)?;
    Ok(json!(info))
}

#[tauri::command]
pub async fn server_rename(id: String, name: String) -> Result<(), String> {
    short_text("the name", &name, MAX_NAME_CHARS)?;
    manager().await?.rename(&id, &name).await.map_err(err)
}

#[tauri::command]
pub async fn server_remove(id: String) -> Result<(), String> {
    manager().await?.remove(&id).await.map_err(err)
}

#[tauri::command]
pub async fn server_probe(id: String, auth: Option<AuthIn>) -> Result<Value, String> {
    manager().await?.probe(&id, self::auth(auth)?).await.map_err(err)
}

#[tauri::command]
pub async fn server_install(app: tauri::AppHandle, id: String, auth: Option<AuthIn>, port: Option<u16>) -> Result<Value, String> {
    let _job = Job::start();
    let m = manager().await?;
    m.install(&id, self::auth(auth)?, channel(), port.unwrap_or(50000), line_sink(&app, &id)).await.map_err(err)
}

/// `ostp manage` on the server: `["status"]`, `["users"]`, `["user-add", name]`,
/// `["user-remove", who]`, `["user-rename", who, name]`, `["logs", "-n", "300"]`.
#[tauri::command]
pub async fn server_manage(id: String, auth: Option<AuthIn>, args: Vec<String>) -> Result<Value, String> {
    if !args.first().is_some_and(|a| ostp_ssh::manager::MANAGE_COMMANDS.contains(&a.as_str())) {
        return Err("unknown server command".into());
    }
    if args.len() > MAX_ARGS + 2 || args.iter().any(|a| a.len() > MAX_ARG_BYTES || a.contains('\0')) {
        return Err("a server command argument is too long".into());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    manager().await?.manage(&id, self::auth(auth)?, &args).await.map_err(err)
}

/// A change with plain-text output, streamed as `server-line` events.
#[tauri::command]
pub async fn server_action(app: tauri::AppHandle, id: String, auth: Option<AuthIn>, action: String, params: Option<Value>) -> Result<String, String> {
    let params = params.unwrap_or(Value::Null);
    if params.to_string().len() > 4096 {
        return Err("the action parameters are too long".into());
    }
    let action = Action::parse(&action, &params, channel()).map_err(err)?;
    let _job = Job::start();
    let m = manager().await?;
    let out = m.action(&id, self::auth(auth)?, action, line_sink(&app, &id)).await.map_err(err)?;
    Ok(out.stdout)
}

/// Opens the server's web panel through the SSH connection in the browser.
#[tauri::command]
pub async fn server_open_panel(app: tauri::AppHandle, id: String, auth: Option<AuthIn>) -> Result<String, String> {
    use tauri_plugin_opener::OpenerExt;
    let url = manager().await?.open_panel(&id, self::auth(auth)?).await.map_err(err)?;
    app.opener().open_url(&url, None::<&str>).map_err(|e| e.to_string())?;
    Ok(url)
}
