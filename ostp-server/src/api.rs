//! Management REST API for OSTP server.
//!
//! Provides endpoints for third-party panels (like 3x-ui) to manage users,
//! query traffic statistics, and control the server.
//!
//! ## Endpoints
//!
//! - `GET  /api/server/status`       -- Server status (uptime, sessions, version)
//! - `GET  /api/users`               -- List all users with traffic stats
//! - `GET  /api/users/:key`          -- Single user stats
//! - `POST /api/users`               -- Create new access key
//! - `DELETE /api/users/:key`        -- Remove access key
//! - `PUT  /api/users/:key/limit`    -- Set traffic limit for a user
//! - `POST /api/users/:key/reset`    -- Reset user traffic counters
//! - `GET|PUT /api/server/info`      -- What clients are told about the server (in the tunnel)

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use portable_atomic::AtomicU64;
use std::time::Instant;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode, Uri},
    response::{IntoResponse},
    routing::{get, post, put},
    Json, Router,
};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};

use crate::dispatcher::{UserStats, UserStatsSnapshot};
use crate::outbound::OutboundRule;

/// A signed-in panel session. It ends after `SESSION_IDLE` without a request
/// (each request renews it) and in any case `SESSION_MAX` after sign-in, so a
/// token left in a forgotten browser or a log stops working.
#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    created: Instant,
    last_seen: Instant,
}

const SESSION_IDLE: std::time::Duration = std::time::Duration::from_secs(12 * 3600);
const SESSION_MAX: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

impl Session {
    pub fn new(token: String) -> Self {
        let now = Instant::now();
        Self { token, created: now, last_seen: now }
    }

    fn expired_at(&self, now: Instant) -> bool {
        now.duration_since(self.last_seen) >= SESSION_IDLE || now.duration_since(self.created) >= SESSION_MAX
    }
}

/// What `scripts/gha.ps1` commits with every release. The package version is
/// "0.5.0" for every alpha, beta and the stable release, so the channel comes
/// from here, the same way `ostp_client::updates::version()` reads it (ostp-server
/// cannot depend on ostp-client).
const RELEASE_STATE: &str = include_str!("../../.release-state.json");

/// This build's version as people read it, with its channel: "0.5.0-alpha.5",
/// "0.5.0-beta.1", "0.5.0".
pub fn build_version() -> &'static str {
    #[derive(Deserialize)]
    struct ReleaseState {
        target_version: String,
        branch: String,
        #[serde(default)]
        alpha_iteration: u32,
        #[serde(default)]
        beta_iteration: u32,
    }
    static V: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| match serde_json::from_str::<ReleaseState>(RELEASE_STATE) {
        Ok(s) => match s.branch.as_str() {
            "alpha" => format!("{}-alpha.{}", s.target_version, s.alpha_iteration),
            "beta" => format!("{}-beta.{}", s.target_version, s.beta_iteration),
            _ => s.target_version,
        },
        Err(_) => env!("CARGO_PKG_VERSION").to_string(),
    });
    &V
}

// ── Shared state for API handlers ────────────────────────────────────────────

/// API server shared state. Held behind Arc for axum handlers.
#[derive(Clone)]
pub struct ApiState {
    pub access_keys: Arc<RwLock<HashMap<String, UserMeta>>>,
    pub user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    pub start_time: Instant,
    /// Live panel sessions, oldest first: a second admin signing in must not
    /// log the first one out.
    pub session_token: Arc<RwLock<Vec<Session>>>,
    pub api_token: Option<String>,
    pub webpath: String,
    pub username: String,
    pub password_hash: String,
    /// Server address for subscription links (e.g. "example.com")
    pub server_host: String,
    pub server_port: u16,
    /// The server's static public key (protocol v6); goes into every link as `pk`.
    pub server_pk: Option<[u8; 32]>,
    /// Where clients reach the server over TLS, when that is set up.
    pub tls_link: Option<TlsLink>,
    /// Subscription URL prefix (e.g. "/sub") when subscriptions are served.
    pub subscription_prefix: Option<String>,
    pub config_path: Option<std::path::PathBuf>,
    pub dns_server: std::sync::Arc<crate::dns::DnsServer>,
    pub audit_logs: Arc<RwLock<Vec<AuditLogEntry>>>,
    pub router: std::sync::Arc<crate::router::Router>,
    /// Devices that fetched a subscription (by HWID), for users with a device limit.
    pub devices: Arc<crate::devices::DeviceStore>,
}

/// The TLS endpoint put in subscription links.
#[derive(Debug, Clone)]
pub struct TlsLink {
    pub host: String,
    pub port: u16,
    /// Upgrade path, needed when a web server fronts OSTP on 443.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub time: String,
    #[serde(rename = "eventEn")]
    pub event_en: String,
    #[serde(rename = "eventRu")]
    pub event_ru: String,
    pub success: bool,
}

#[derive(Deserialize)]
pub struct CreateAuditLogRequest {
    #[serde(rename = "eventEn")]
    pub event_en: String,
    #[serde(rename = "eventRu")]
    pub event_ru: String,
    pub success: bool,
}

// ── API configuration ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: String,
    pub token: Option<String>,
    #[serde(default)]
    pub webpath: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password_hash: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9090".to_string(),
            token: None,
            webpath: String::new(),
            username: String::new(),
            password_hash: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserMeta {
    pub name: Option<String>,
    pub limit_bytes: Option<u64>,
    /// Devices (HWIDs) a subscription may serve; `None` = no limit.
    #[serde(default)]
    pub max_devices: Option<u32>,
    /// When the key stops working, Unix seconds (UTC); `None` = never.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl UserMeta {
    /// Whether the key has expired at `now` (Unix seconds).
    pub fn is_expired(&self, now: u64) -> bool {
        ostp_core::access_keys::is_expired(self.expires_at, now)
    }
}

// ── Request/Response types ───────────────────────────────────────────────────

#[derive(Serialize)]
struct ServerStatus {
    version: &'static str,
    uptime_seconds: u64,
    /// Users that moved any traffic since the start.
    active_users: usize,
    total_users: usize,
    /// Users with a live session right now.
    online_users: usize,
    connections: u64,
    bytes_up: u64,
    bytes_down: u64,
    /// `strict`, `normal` or `debug`: what this server's log may say.
    log_privacy: &'static str,
    endpoint: Endpoint,
    /// What clients get inside the tunnel: `{operator?, server}`.
    server_info: serde_json::Value,
}

#[derive(Serialize)]
struct Endpoint {
    host: String,
    udp_port: u16,
    tls: Option<TlsEndpoint>,
    subscription_prefix: Option<String>,
    dns_enabled: bool,
}

#[derive(Serialize)]
struct TlsEndpoint {
    host: String,
    port: u16,
    path: Option<String>,
}

#[derive(Serialize)]
struct UserShare {
    tls: Option<String>,
    udp: String,
    subscription: Option<String>,
}

#[derive(Deserialize)]
struct QrRequest {
    text: String,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub access_key: Option<String>,
    pub name: Option<String>,
    pub limit_bytes: Option<u64>,
    pub max_devices: Option<u32>,
    /// Unix seconds (UTC); absent or `null` = never.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    /// Absent = unchanged; `null` or empty = no name.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<Option<String>>,
    /// Absent = unchanged; `null` = no limit; a number = that many bytes.
    #[serde(default, deserialize_with = "present")]
    pub limit_bytes: Option<Option<u64>>,
    /// Absent = unchanged; `null` = no limit; a number = that many devices.
    #[serde(default, deserialize_with = "present")]
    pub max_devices: Option<Option<u32>>,
    /// Absent = unchanged; `null` = never expires; a number = Unix seconds (UTC).
    #[serde(default, deserialize_with = "present")]
    pub expires_at: Option<Option<u64>>,
}

/// Tells a field that is absent from one that is `null`: a request from a panel
/// or app that predates a field must not clear what it never sent.
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
pub struct SetLimitRequest {
    pub limit_bytes: Option<u64>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: Option<String>, // We'll accept raw password and hash it
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> Json<Self> {
        Json(Self { ok: true, data: Some(data), error: None })
    }
}

fn api_error<T: Serialize>(msg: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (StatusCode::BAD_REQUEST, Json(ApiResponse { ok: false, data: None, error: Some(msg.to_string()) }))
}

fn api_status<T: Serialize>(code: StatusCode, msg: &str) -> (StatusCode, Json<ApiResponse<T>>) {
    (code, Json(ApiResponse { ok: false, data: None, error: Some(msg.to_string()) }))
}

fn api_unauthorized<T: Serialize>() -> (StatusCode, Json<ApiResponse<T>>) {
    (StatusCode::UNAUTHORIZED, Json(ApiResponse { ok: false, data: None, error: Some("unauthorized".to_string()) }))
}

/// The panel: plain HTML/CSS/JS, no build step, embedded into the binary.
#[derive(RustEmbed)]
#[folder = "panel/"]
struct Assets;

/// Headers of every panel file: it must not be framed (clickjacking a panel
/// that controls the server) and a file is only ever what its type says.
fn panel_headers(content_type: &str) -> [(header::HeaderName, String); 4] {
    [
        (header::CONTENT_TYPE, content_type.to_string()),
        (header::X_FRAME_OPTIONS, "DENY".to_string()),
        (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'".to_string()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
    ]
}

async fn static_handler(State(state): State<ApiState>, uri: Uri) -> impl IntoResponse {
    let mut path = uri.path();
    
    let webpath = state.webpath.trim_matches('/');
    let prefix = if webpath.is_empty() {
        "/panel".to_string()
    } else {
        format!("/{}", webpath)
    };
    
    if path.starts_with(&prefix) {
        path = &path[prefix.len()..];
    }
    path = path.trim_start_matches('/');
    
    if path.is_empty() || path == "index.html" {
        path = "index.html";
    }

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (panel_headers(mime.as_ref()), content.data).into_response()
        }
        None => {
            if let Some(index) = Assets::get("index.html") {
                (panel_headers("text/html"), index.data).into_response()
            } else {
                (StatusCode::NOT_FOUND, "404 Not Found").into_response()
            }
        }
    }
}

// ── API router ───────────────────────────────────────────────────────────────

pub fn create_api_router(state: ApiState) -> Router {
    let api_router = Router::new()
        .route("/server/status", get(handle_status))
        .route("/server/config", get(handle_get_config).put(handle_put_config))
        .route("/server/info", get(handle_get_server_info).put(handle_put_server_info))
        .route(
            "/users",
            get(handle_list_users).post(handle_create_user),
        )
        .route(
            "/users/{key}",
            get(handle_get_user)
                .put(update_user)
                .delete(delete_user),
        )
        .route("/users/{key}/limit", put(handle_set_limit))
        .route("/users/{key}/reset", post(handle_reset_stats))
        .route("/users/{key}/devices", get(handle_list_devices).delete(handle_clear_devices))
        .route("/users/{key}/devices/{hwid}", axum::routing::delete(handle_remove_device))
        .route("/users/{key}/share", get(handle_user_share))
        .route("/qr", post(handle_qr))
        .route("/subscribe/{key}", get(handle_subscribe))
        .route("/login", post(handle_login))
        .route("/logout", post(handle_logout))
        .route(
            "/audit",
            get(handle_get_audit)
                .post(handle_create_audit)
                .delete(handle_clear_audit),
        )
        .route("/users/bulk", post(handle_bulk_create_users))
        .route("/router/rules", get(handle_get_rules).put(handle_put_rules))
        .route("/dns/stats", get(handle_dns_stats))
        .route("/dns/log", get(handle_dns_log).delete(handle_dns_clear_log))
        .route("/dns/settings", get(handle_dns_get_settings).put(handle_dns_put_settings))
        .route("/dns/update", post(handle_dns_update))
        .route("/dns/test", post(handle_dns_test))
        .route("/dns/meta", get(handle_dns_meta))
        .route("/overnet", get(handle_overnet_status).put(handle_overnet_put))
        // Every body here is small except a pasted config.json; a larger one is a mistake or an attack.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY));

    let webpath = state.webpath.clone();
    let webpath = webpath.trim_matches('/');

    let base_route = if webpath.is_empty() {
        "/panel".to_string()
    } else {
        format!("/{}", webpath)
    };

    let redirect_target = format!("{}/", base_route);
    let redirect_route = base_route.clone();

    Router::new()
        // Exact /{webpath} → redirect to /{webpath}/ (so relative asset paths work)
        .route(&redirect_route, get(move || {
            let target = redirect_target.clone();
            async move { axum::response::Redirect::permanent(&target) }
        }))
        // /{webpath}/ and /{webpath}/** → serve embedded static files
        .route(&format!("{}/", base_route), get(static_handler.clone()))
        .route(&format!("{}/{{*path}}", base_route), get(static_handler))
        // /{webpath}/api/* → API handlers
        .nest(&format!("{}/api", base_route), api_router)
        .with_state(state)
}

/// Start the Management API server on the configured bind address.
pub async fn start_api_server(
    config: ApiConfig,
    access_keys: Arc<RwLock<HashMap<String, UserMeta>>>,
    user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    server_host: String,
    server_port: u16,
    server_pk: Option<[u8; 32]>,
    tls_link: Option<TlsLink>,
    subscription_prefix: Option<String>,
    config_path: Option<std::path::PathBuf>,
    dns_server: std::sync::Arc<crate::dns::DnsServer>,
    router: std::sync::Arc<crate::router::Router>,
) {
    // An empty token in the config means no token, not one that an empty
    // Authorization header matches.
    let api_token = config.token.clone().filter(|t| !t.trim().is_empty());
    if !has_credentials(&config.username, &config.password_hash, api_token.as_deref()) {
        // Loopback is no protection: every client of this server reaches
        // 127.0.0.1 through the tunnel as 10.1.0.1.
        tracing::error!(
            "Management API not started: no sign-in is configured, and the panel controls the server. \
             Set one with `ostp panel on` (or api.username and api.password_hash, or api.token) and restart."
        );
        return;
    }
    let state = ApiState {
        access_keys,
        user_stats,
        start_time: Instant::now(),
        session_token: Arc::new(RwLock::new(Vec::new())),
        api_token,
        webpath: config.webpath.clone(),
        username: config.username.clone(),
        password_hash: config.password_hash.clone(),
        server_host,
        server_port,
        server_pk,
        tls_link,
        subscription_prefix,
        devices: crate::devices::DeviceStore::shared(config_path.as_ref().and_then(|p| p.parent()).map(|d| d.join("devices.json"))),
        config_path,
        dns_server,
        audit_logs: Arc::new(RwLock::new(Vec::new())),
        router,
    };

    let app = create_api_router(state);

    let listener = match tokio::net::TcpListener::bind(&config.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Management API failed to bind on {}: {}", config.bind, e);
            return;
        }
    };

    tracing::info!("Management API listening on {}", config.bind);

    // The peer address is what sign-in attempts are limited by.
    if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await {
        tracing::error!("Management API error: {}", e);
    }
}

// ── Middleware: token check ──────────────────────────────────────────────────

/// Constant-time string equality for secrets (tokens, password hashes).
/// Plain `==` short-circuits on the first differing byte, which leaks how
/// many leading bytes an attacker's guess got right through response
/// timing - a classic remote timing side-channel against exactly the kind
/// of long-lived bearer/session secrets compared here. `subtle` is already
/// pulled in transitively (chacha20poly1305 etc.); pinning it as a direct
/// dependency here makes that guarantee explicit for this call site.
fn secure_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Whether anyone can sign in at all: a name and password for the panel, or
/// a static token for relays. Without either the API does not run.
fn has_credentials(username: &str, password_hash: &str, token: Option<&str>) -> bool {
    (!username.is_empty() && !password_hash.is_empty()) || token.is_some_and(|t| !t.trim().is_empty())
}

fn check_token(state: &ApiState, headers: &axum::http::HeaderMap) -> bool {
    // Both session token (for web UI) and static API token (for relays) are checked
    let mut allowed = false;
    let api_token = state.api_token.as_deref().filter(|t| !t.is_empty());

    if let Some(value) = headers.get("authorization") {
        if let Ok(val) = value.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                let now = Instant::now();
                let mut sessions = state.session_token.write().unwrap_or_else(|e| e.into_inner());
                sessions.retain(|s| !s.expired_at(now));
                for session in sessions.iter_mut() {
                    if secure_eq(token, &session.token) {
                        session.last_seen = now;
                        allowed = true;
                    }
                }
                drop(sessions);

                if let Some(api_tok) = api_token {
                    if secure_eq(token, api_tok) {
                        allowed = true;
                    }
                }
            } else {
                if let Some(api_tok) = api_token {
                    if secure_eq(val, api_tok) {
                        allowed = true;
                    }
                }
            }
        }
    }

    allowed
}

async fn handle_login(
    State(state): State<ApiState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    if state.username.is_empty() || state.password_hash.is_empty() {
        return api_error("Auth not configured");
    }

    // The attempt is paid for up front: with PBKDF2 running off the async
    // workers, checking the bucket and spending it only after a failure would
    // let any number of parallel requests through at once.
    let peer = peer.ip();
    if !login_reserve(peer) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse { ok: false, data: None, error: Some("too many sign-in attempts, wait a minute".into()) }),
        );
    }

    let password = payload.password.unwrap_or_default();
    if payload.username.len() > 256 || password.len() > 1024 {
        login_failed();
        return api_unauthorized::<LoginResponse>();
    }
    let stored = state.password_hash.clone();
    // PBKDF2 is meant to be slow: off the async workers.
    let password_ok = tokio::task::spawn_blocking(move || crate::password::verify(&password, &stored))
        .await
        .unwrap_or(false);

    if secure_eq(&payload.username, &state.username) && password_ok {
        login_refund(peer);
        let token = uuid::Uuid::new_v4().to_string();
        {
            let mut sessions = state.session_token.write().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            sessions.retain(|s| !s.expired_at(now));
            sessions.push(Session::new(token.clone()));
            if sessions.len() > MAX_SESSIONS {
                sessions.remove(0);
            }
        }
        (StatusCode::OK, ApiResponse::success(LoginResponse { token }))
    } else {
        login_failed();
        api_unauthorized::<LoginResponse>()
    }
}

/// Ends the session the request signed in with. Other sessions and the static
/// API token are untouched.
async fn handle_logout(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<()>();
    }
    if let Some(token) = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")) {
        state.session_token.write().unwrap_or_else(|e| e.into_inner()).retain(|s| !secure_eq(token, &s.token));
    }
    (StatusCode::OK, ApiResponse::success(()))
}

/// Failed sign-ins: a bucket of 10 per source address, refilled at 10 a minute,
/// and a much larger one for the whole server, so one address cannot lock the
/// administrator out and a flood from many still has a ceiling. While a bucket
/// is empty every sign-in it covers is refused, the right password too;
/// signed-in sessions keep working and the CLI is unaffected.
///
/// The address is the real peer of the connection, never a forwarded-for
/// header (that is the client's to forge). Through the tunnel and the built-in
/// HTTPS frontend the peer is 127.0.0.1, so those sign-ins share one per-address
/// bucket, as they did before there were two kinds.
const LOGIN_BURST: f64 = 10.0;
const LOGIN_REFILL_PER_SEC: f64 = 10.0 / 60.0;
const LOGIN_GLOBAL_BURST: f64 = 200.0;
const LOGIN_GLOBAL_REFILL_PER_SEC: f64 = 200.0 / 60.0;
/// Addresses remembered at once; a full table forgets the ones that have refilled.
const LOGIN_MAX_ADDRS: usize = 10_000;

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64, now: Instant) -> Self {
        Self { tokens: burst, last: now }
    }

    fn refill(&mut self, burst: f64, per_sec: f64, now: Instant) {
        self.tokens = (self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * per_sec).min(burst);
        self.last = now;
    }
}

struct LoginLimiter {
    global: Bucket,
    per_addr: HashMap<std::net::IpAddr, Bucket>,
}

/// An IPv6 client owns a whole /64, so that is the unit.
fn login_source(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip.to_canonical() {
        std::net::IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            std::net::IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

impl LoginLimiter {
    fn new(now: Instant) -> Self {
        Self { global: Bucket::new(LOGIN_GLOBAL_BURST, now), per_addr: HashMap::new() }
    }

    /// Takes one attempt for `ip` from its bucket and from the global one.
    fn reserve(&mut self, ip: std::net::IpAddr, now: Instant) -> bool {
        self.global.refill(LOGIN_GLOBAL_BURST, LOGIN_GLOBAL_REFILL_PER_SEC, now);
        if self.global.tokens < 1.0 {
            return false;
        }
        if self.per_addr.len() >= LOGIN_MAX_ADDRS && !self.per_addr.contains_key(&ip) {
            self.per_addr.retain(|_, b| {
                b.refill(LOGIN_BURST, LOGIN_REFILL_PER_SEC, now);
                b.tokens < LOGIN_BURST
            });
            if self.per_addr.len() >= LOGIN_MAX_ADDRS {
                self.per_addr.clear();
            }
        }
        let b = self.per_addr.entry(ip).or_insert_with(|| Bucket::new(LOGIN_BURST, now));
        b.refill(LOGIN_BURST, LOGIN_REFILL_PER_SEC, now);
        if b.tokens < 1.0 {
            return false;
        }
        b.tokens -= 1.0;
        self.global.tokens -= 1.0;
        true
    }

    fn refund(&mut self, ip: std::net::IpAddr) {
        if let Some(b) = self.per_addr.get_mut(&ip) {
            b.tokens = (b.tokens + 1.0).min(LOGIN_BURST);
        }
        self.global.tokens = (self.global.tokens + 1.0).min(LOGIN_GLOBAL_BURST);
    }
}

static LOGIN_LIMITER: std::sync::Mutex<Option<LoginLimiter>> = std::sync::Mutex::new(None);

/// Takes one attempt for this source; false when its bucket (or the server's) is empty.
fn login_reserve(peer: std::net::IpAddr) -> bool {
    let now = Instant::now();
    LOGIN_LIMITER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(|| LoginLimiter::new(now))
        .reserve(login_source(peer), now)
}

/// A correct sign-in gives its attempt back: only failures count.
fn login_refund(peer: std::net::IpAddr) {
    if let Some(l) = LOGIN_LIMITER.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        l.refund(login_source(peer));
    }
}

fn login_failed() {
    tracing::warn!("panel: failed sign-in");
}

// ── Limits ───────────────────────────────────────────────────────────────────

/// Largest request body. Only a pasted config.json comes near it.
const MAX_BODY: usize = 1 << 20;
/// Users the server keeps: every one is rewritten into config.json on each
/// change and listed on each panel refresh.
const MAX_USERS: usize = 10_000;
const MAX_NAME_CHARS: usize = 100;
/// 1 PiB. Also keeps the number exact in the panel's JavaScript (below 2^53).
const MAX_LIMIT_BYTES: u64 = 1 << 50;
/// Panel sessions held at once; the oldest is dropped past this.
const MAX_SESSIONS: usize = 8;

/// 8 to 128 characters, nothing that breaks a URL path or a share link.
fn check_key(key: &str) -> Result<(), &'static str> {
    let n = key.chars().count();
    if !(8..=128).contains(&n) || key.chars().any(|c| c.is_whitespace() || c.is_control() || "/?#%\\".contains(c)) {
        return Err("access key must be 8 to 128 characters with no spaces, slashes, ? or #");
    }
    Ok(())
}

/// Trims the name; empty means none.
fn check_name(name: Option<String>) -> Result<Option<String>, &'static str> {
    let Some(name) = name else { return Ok(None) };
    let name = name.trim();
    if name.chars().count() > MAX_NAME_CHARS || name.chars().any(|c| c.is_control()) {
        return Err("name is too long (100 characters at most) or has control characters");
    }
    Ok(Some(name.to_string()).filter(|n| !n.is_empty()))
}

/// A device limit is a small number; 0 means none and is stored as none.
fn check_devices(n: Option<u32>) -> Result<Option<u32>, &'static str> {
    match n {
        Some(0) | None => Ok(None),
        Some(n) if n <= 1000 => Ok(Some(n)),
        Some(_) => Err("device limit is too large (1000 at most)"),
    }
}

/// An expiry is a Unix time no later than the year 9999; 0 means none.
fn check_expires(t: Option<u64>) -> Result<Option<u64>, &'static str> {
    match t {
        Some(0) | None => Ok(None),
        Some(t) if t <= ostp_core::access_keys::MAX_EXPIRES_AT => Ok(Some(t)),
        Some(_) => Err("expiry is too far in the future (the year 9999 at most)"),
    }
}

fn check_limit(limit: Option<u64>) -> Result<(), &'static str> {
    match limit {
        Some(l) if l > MAX_LIMIT_BYTES => Err("traffic limit is too large (1 PiB at most)"),
        _ => Ok(()),
    }
}

// ── config.json ──────────────────────────────────────────────────────────────

#[cfg(test)]
use crate::config_io::parse_config;
use crate::config_io::{edit_config, lock_config, write_config_atomic};

/// One change to the `access_keys` list. It is applied to the list that is on
/// disk, not written from memory: a user the CLI added a moment ago, or an
/// edit made in the panel's config editor, is not undone by an unrelated change.
enum KeyChange {
    /// New users. One that is already in the file is an error.
    Add(Vec<(String, UserMeta)>),
    /// New name, limit and device limit of a user that is in the file.
    Set { key: String, meta: UserMeta },
    Remove(String),
}

const ERR_ALREADY_IN_FILE: &str = "user already exists in config.json";
const ERR_NOT_IN_FILE: &str = "user is not in config.json any more (removed by another change)";

/// What a failed save says to the panel: the two known causes as they are, any
/// other (a disk error, a config that does not parse) in general terms.
fn save_error_message(e: &str) -> &'static str {
    match e {
        ERR_ALREADY_IN_FILE => ERR_ALREADY_IN_FILE,
        ERR_NOT_IN_FILE => ERR_NOT_IN_FILE,
        _ => "failed to save configuration",
    }
}

/// An `access_keys` entry for `key`. Fields this server does not know about
/// stay as they are in `existing`; the short form (a bare string) is used when
/// there is nothing to say about the user.
fn key_entry(key: &str, meta: &UserMeta, existing: Option<&serde_json::Value>) -> serde_json::Value {
    use serde_json::Value;
    if existing.is_none_or(|e| e.is_string())
        && meta.name.is_none()
        && meta.limit_bytes.is_none()
        && meta.max_devices.is_none()
        && meta.expires_at.is_none()
    {
        return Value::String(key.to_string());
    }
    let mut obj = match existing {
        Some(Value::Object(o)) => o.clone(),
        _ => serde_json::Map::new(),
    };
    obj.insert("access_key".to_string(), Value::String(key.to_string()));
    for (field, value) in [
        ("name", meta.name.clone().map(Value::String)),
        ("limit_bytes", meta.limit_bytes.map(|n| Value::Number(n.into()))),
        ("max_devices", meta.max_devices.map(|n| Value::Number(n.into()))),
        ("expires_at", meta.expires_at.map(|t| Value::Number(t.into()))),
    ] {
        match value {
            Some(v) => {
                obj.insert(field.to_string(), v);
            }
            None => {
                obj.remove(field);
            }
        }
    }
    Value::Object(obj)
}

fn apply_key_change(config: &mut serde_json::Value, change: &KeyChange) -> Result<(), String> {
    use ostp_core::access_keys::key_of;
    let obj = config.as_object_mut().ok_or("config root is not an object")?;
    let list = obj
        .entry("access_keys")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or("access_keys is not a list")?;
    let position = |list: &[serde_json::Value], key: &str| list.iter().position(|e| key_of(e).as_deref() == Some(key));
    match change {
        KeyChange::Add(users) => {
            if users.iter().any(|(k, _)| position(list, k).is_some()) {
                return Err(ERR_ALREADY_IN_FILE.to_string());
            }
            for (k, m) in users {
                list.push(key_entry(k, m, None));
            }
        }
        KeyChange::Set { key, meta } => {
            let i = position(list, key).ok_or(ERR_NOT_IN_FILE)?;
            list[i] = key_entry(key, meta, Some(&list[i]));
        }
        KeyChange::Remove(key) => list.retain(|e| key_of(e).as_deref() != Some(key.as_str())),
    }
    Ok(())
}

/// Applies `change` to config.json under the config lock. Without a config
/// path (run-time only) there is nothing to save.
fn save_key_change(state: &ApiState, change: KeyChange) -> Result<(), String> {
    let Some(ref path) = state.config_path else {
        return Ok(());
    };
    edit_config(path, false, |config| apply_key_change(config, &change))
}


// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_get_config(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<serde_json::Value>();
    }

    let Some(ref path) = state.config_path else {
        return api_error("No config path registered (run-time only)");
    };

    match std::fs::read_to_string(path) {
        Ok(content) => {
            let mut stripped = json_comments::StripComments::new(content.as_bytes());
            let mut content_str = String::new();
            use std::io::Read;
            if let Err(e) = stripped.read_to_string(&mut content_str) {
                return api_error(&format!("Failed to strip comments: {}", e));
            }
            match serde_json::from_str::<serde_json::Value>(&content_str) {
                Ok(val) => (StatusCode::OK, ApiResponse::success(val)),
                Err(e) => api_error(&format!("Failed to parse config JSON: {}", e)),
            }
        }
        Err(e) => api_error(&format!("Failed to read config file: {}", e)),
    }
}

async fn handle_put_config(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }

    let Some(ref path) = state.config_path else {
        return api_error("No config path registered (run-time only)");
    };

    if body.get("mode").and_then(|m| m.as_str()).is_none() {
        return api_error("Invalid config: missing 'mode' field");
    }
    if let Some(keys) = body.get("access_keys") {
        match keys.as_array() {
            None => return api_error("Invalid config: access_keys must be a list"),
            Some(list) if list.len() > MAX_USERS => return api_error("too many users (10000 at most)"),
            Some(_) => {}
        }
    }

    let new_content = match serde_json::to_string_pretty(&body) {
        Ok(s) => s,
        Err(e) => return api_error(&format!("Failed to format config JSON: {}", e)),
    };

    {
        // Same lock as every other change, so a user created at this moment is
        // not half-merged into the new file; a copy of the old file is kept.
        let _guard = lock_config(path);
        let _ = std::fs::copy(path, path.with_extension("json.bak"));
        if let Err(e) = write_config_atomic(path, &new_content) {
            return api_error(&e);
        }
    }

    (StatusCode::OK, ApiResponse::success(true))
}

async fn handle_status(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<ServerStatus>();
    }

    let dns_enabled = state.dns_server.enabled();
    let keys = state.access_keys.read().unwrap_or_else(|e| e.into_inner());
    let stats = state.user_stats.read().unwrap_or_else(|e| e.into_inner());
    let (mut active, mut online, mut connections, mut up, mut down) = (0, 0, 0u64, 0u64, 0u64);
    for us in stats.values() {
        let (u, d, c) = (
            us.bytes_up.load(Ordering::Relaxed),
            us.bytes_down.load(Ordering::Relaxed),
            us.connections.load(Ordering::Relaxed),
        );
        active += usize::from(u + d > 0);
        online += usize::from(c > 0);
        connections += c;
        up += u;
        down += d;
    }

    let status = ServerStatus {
        version: build_version(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        active_users: active,
        total_users: keys.len(),
        online_users: online,
        connections,
        bytes_up: up,
        bytes_down: down,
        log_privacy: ostp_core::logpriv::privacy().as_str(),
        endpoint: Endpoint {
            host: state.server_host.clone(),
            udp_port: state.server_port,
            tls: state.tls_link.as_ref().map(|t| TlsEndpoint { host: t.host.clone(), port: t.port, path: t.path.clone() }),
            subscription_prefix: state.subscription_prefix.clone(),
            dns_enabled,
        },
        server_info: crate::server_info::info_value(&state.router.info.operator(), &state.router.facts()),
    };

    (StatusCode::OK, ApiResponse::success(status))
}

/// What clients are told about this server inside the tunnel.
async fn handle_get_server_info(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<serde_json::Value>();
    }
    (StatusCode::OK, ApiResponse::success(crate::server_info::info_value(&state.router.info.operator(), &state.router.facts())))
}

/// Replaces the operator's info (`server_info` in config.json): every field
/// sent is set, an empty or missing one removed. Too long a field is refused
/// rather than cut, so the panel shows what is kept.
async fn handle_put_server_info(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<crate::server_info::OperatorInfo>,
) -> impl IntoResponse {
    use crate::server_info::{ABOUT_MAX, SHORT_FIELD_MAX};
    if !check_token(&state, &headers) {
        return api_unauthorized::<serde_json::Value>();
    }
    let too_long = [body.name.as_deref(), body.location.as_deref(), body.contact.as_deref()]
        .into_iter()
        .flatten()
        .any(|s| s.trim().chars().count() > SHORT_FIELD_MAX);
    if too_long {
        return api_error("name, location and contact are 128 characters at most");
    }
    if body.about.as_ref().is_some_and(|a| a.len() > ABOUT_MAX) {
        return api_error("the description is 8 KiB at most");
    }
    let info = body.sanitized();
    if let Some(ref path) = state.config_path {
        let saved = edit_config(path, false, |config| {
            let obj = config.as_object_mut().ok_or("config root is not an object")?;
            if info.is_empty() {
                obj.remove("server_info");
            } else {
                obj.insert("server_info".into(), serde_json::to_value(&info).map_err(|e| e.to_string())?);
            }
            Ok(())
        });
        if let Err(e) = saved {
            tracing::error!("Failed to save config after changing server_info: {}", e);
            return api_error("failed to save configuration");
        }
    }
    state.router.info.set_operator(info);
    (StatusCode::OK, ApiResponse::success(crate::server_info::info_value(&state.router.info.operator(), &state.router.facts())))
}

async fn handle_list_users(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<Vec<UserStatsSnapshot>>();
    }

    let keys = state.access_keys.read().unwrap_or_else(|e| e.into_inner());
    let stats = state.user_stats.read().unwrap_or_else(|e| e.into_inner());

    let mut users: Vec<UserStatsSnapshot> = keys.iter().map(|(key, meta)| {
        if let Some(st) = stats.get(key) {
            UserStatsSnapshot {
                access_key: key.clone(),
                name: meta.name.clone(),
                bytes_up: st.bytes_up.load(Ordering::Relaxed),
                bytes_down: st.bytes_down.load(Ordering::Relaxed),
                connections: st.connections.load(Ordering::Relaxed),
                limit_bytes: st.limit_bytes,
                online: st.connections.load(Ordering::Relaxed) > 0,
                last_seen: None,
                expires_at: meta.expires_at,
            }
        } else {
            UserStatsSnapshot {
                access_key: key.clone(),
                name: meta.name.clone(),
                bytes_up: 0,
                bytes_down: 0,
                connections: 0,
                limit_bytes: meta.limit_bytes,
                online: false,
                last_seen: None,
                expires_at: meta.expires_at,
            }
        }
    }).collect();

    users.sort_by(|a, b| b.bytes_down.cmp(&a.bytes_down));

    (StatusCode::OK, ApiResponse::success(users))
}

async fn handle_get_user(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<UserStatsSnapshot>();
    }

    let keys = state.access_keys.read().unwrap_or_else(|e| e.into_inner());
    let meta = match keys.get(&key) {
        Some(m) => m.clone(),
        None => return api_error("user not found"),
    };

    let stats = state.user_stats.read().unwrap_or_else(|e| e.into_inner());
    let snapshot = if let Some(st) = stats.get(&key) {
        UserStatsSnapshot {
            access_key: key.clone(),
            name: meta.name.clone(),
            bytes_up: st.bytes_up.load(Ordering::Relaxed),
            bytes_down: st.bytes_down.load(Ordering::Relaxed),
            connections: st.connections.load(Ordering::Relaxed),
            limit_bytes: st.limit_bytes,
            online: st.connections.load(Ordering::Relaxed) > 0,
            last_seen: None,
            expires_at: meta.expires_at,
        }
    } else {
        UserStatsSnapshot {
            access_key: key.clone(),
            name: meta.name.clone(),
            bytes_up: 0,
            bytes_down: 0,
            connections: 0,
            limit_bytes: meta.limit_bytes,
            online: false,
            last_seen: None,
            expires_at: meta.expires_at,
        }
    };

    (StatusCode::OK, ApiResponse::success(snapshot))
}

async fn handle_create_user(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<String>();
    }

    let name = match check_name(body.name) {
        Ok(n) => n,
        Err(m) => return api_error::<String>(m),
    };
    if let Err(m) = check_limit(body.limit_bytes) {
        return api_error::<String>(m);
    }
    let max_devices = match check_devices(body.max_devices) {
        Ok(n) => n,
        Err(m) => return api_error::<String>(m),
    };
    let expires_at = match check_expires(body.expires_at) {
        Ok(t) => t,
        Err(m) => return api_error::<String>(m),
    };
    let key = match body.access_key.filter(|k| !k.is_empty()) {
        Some(k) => {
            if let Err(m) = check_key(&k) {
                return api_error::<String>(m);
            }
            k
        }
        None => ostp_core::keys::access_key_hex(),
    };

    {
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        // Inserting over an existing key would silently reset that user's traffic and limit.
        if keys.contains_key(&key) {
            return api_status::<String>(StatusCode::CONFLICT, "user already exists");
        }
        if keys.len() >= MAX_USERS {
            return api_error::<String>("too many users (10000 at most)");
        }
        keys.insert(key.clone(), UserMeta { name: name.clone(), limit_bytes: body.limit_bytes, max_devices, expires_at });
    }

    let mut stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
    stats.insert(key.clone(), Arc::new(UserStats::new(body.limit_bytes)));
    drop(stats);

    let meta = UserMeta { name, limit_bytes: body.limit_bytes, max_devices, expires_at };
    if let Err(e) = save_key_change(&state, KeyChange::Add(vec![(key.clone(), meta)])) {
        tracing::error!("Failed to save config after creating user: {}", e);
        // Not on disk, so not kept in memory either: a restart would lose it silently.
        state.access_keys.write().unwrap_or_else(|e| e.into_inner()).remove(&key);
        state.user_stats.write().unwrap_or_else(|e| e.into_inner()).remove(&key);
        return api_error::<String>(save_error_message(&e));
    }

    tracing::info!("API: created user key (fp={})", crate::dispatcher::key_fp(&key));
    (StatusCode::OK, ApiResponse::success(key))
}

/// Puts a new traffic limit into a user's live counters, keeping the counts.
/// Returns the counters that were there, to put back if the save fails.
fn replace_stats_limit(state: &ApiState, key: &str, limit: Option<u64>) -> Option<Arc<UserStats>> {
    let mut stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
    let old = stats.get(key).cloned();
    let entry = stats.entry(key.to_string()).or_insert_with(|| Arc::new(UserStats::new(limit)));
    *entry = Arc::new(UserStats {
        bytes_up: AtomicU64::new(entry.bytes_up.load(Ordering::Relaxed)),
        bytes_down: AtomicU64::new(entry.bytes_down.load(Ordering::Relaxed)),
        connections: AtomicU64::new(entry.connections.load(Ordering::Relaxed)),
        limit_bytes: limit,
        created_at: entry.created_at,
    });
    old
}

/// Undoes a change that could not be saved: memory goes back to what the file
/// says, so a restart does not silently change it.
fn restore_user(state: &ApiState, key: &str, meta: Option<UserMeta>, stats: Option<Arc<UserStats>>) {
    match meta {
        Some(m) => {
            state.access_keys.write().unwrap_or_else(|e| e.into_inner()).insert(key.to_string(), m);
        }
        None => {
            state.access_keys.write().unwrap_or_else(|e| e.into_inner()).remove(key);
        }
    }
    let mut live = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
    match stats {
        Some(s) => {
            live.insert(key.to_string(), s);
        }
        None => {
            live.remove(key);
        }
    }
}

async fn delete_user(
    State(state): State<ApiState>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<String>();
    }

    let old_meta = match state.access_keys.write().unwrap_or_else(|e| e.into_inner()).remove(&key) {
        Some(m) => m,
        None => return api_error::<String>("User not found"),
    };
    let old_stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner()).remove(&key);

    if let Err(e) = save_key_change(&state, KeyChange::Remove(key.clone())) {
        tracing::error!("Failed to save config after removing user: {}", e);
        restore_user(&state, &key, Some(old_meta), old_stats);
        return api_error::<String>(save_error_message(&e));
    }
    // Only once the removal is on disk: the record of its devices goes with it.
    let devices = state.devices.clone();
    let token = ostp_core::subscription::token_for_key(&key);
    let _ = tokio::task::spawn_blocking(move || devices.clear(&token)).await;

    (StatusCode::OK, ApiResponse::success("User removed".to_string()))
}

async fn update_user(
    State(state): State<ApiState>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<String>();
    }

    // Absent = unchanged, `null` = cleared (a name removed, no limit).
    let name = match body.name.map(check_name).transpose() {
        Ok(n) => n,
        Err(m) => return api_error::<String>(m),
    };
    if let Some(Some(l)) = body.limit_bytes {
        if let Err(m) = check_limit(Some(l)) {
            return api_error::<String>(m);
        }
    }
    let max_devices = match body.max_devices {
        Some(n) => match check_devices(n) {
            Ok(n) => Some(n),
            Err(m) => return api_error::<String>(m),
        },
        None => None,
    };
    let expires_at = match body.expires_at {
        Some(t) => match check_expires(t) {
            Ok(t) => Some(t),
            Err(m) => return api_error::<String>(m),
        },
        None => None,
    };

    let (old_meta, new_meta) = {
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        let Some(meta) = keys.get_mut(&key) else {
            return api_error::<String>("User not found");
        };
        let old = meta.clone();
        if let Some(n) = name {
            meta.name = n;
        }
        if let Some(l) = body.limit_bytes {
            meta.limit_bytes = l;
        }
        if let Some(n) = max_devices {
            meta.max_devices = n;
        }
        if let Some(t) = expires_at {
            meta.expires_at = t;
        }
        (old, meta.clone())
    };
    let old_stats = if body.limit_bytes.is_some() {
        replace_stats_limit(&state, &key, new_meta.limit_bytes)
    } else {
        None
    };

    if let Err(e) = save_key_change(&state, KeyChange::Set { key: key.clone(), meta: new_meta }) {
        tracing::error!("Failed to save config after updating user: {}", e);
        let current_stats = state.user_stats.read().unwrap_or_else(|e| e.into_inner()).get(&key).cloned();
        restore_user(&state, &key, Some(old_meta), if body.limit_bytes.is_some() { old_stats } else { current_stats });
        return api_error::<String>(save_error_message(&e));
    }

    (StatusCode::OK, ApiResponse::success("User updated".to_string()))
}

async fn handle_set_limit(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<SetLimitRequest>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }
    if let Err(m) = check_limit(body.limit_bytes) {
        return api_error(m);
    }

    let (old_meta, new_meta) = {
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        let Some(meta) = keys.get_mut(&key) else {
            return api_error("user not found");
        };
        let old = meta.clone();
        meta.limit_bytes = body.limit_bytes;
        (old, meta.clone())
    };
    let old_stats = replace_stats_limit(&state, &key, body.limit_bytes);

    if let Err(e) = save_key_change(&state, KeyChange::Set { key: key.clone(), meta: new_meta }) {
        tracing::error!("Failed to save config after setting user limit: {}", e);
        restore_user(&state, &key, Some(old_meta), old_stats);
        return api_error(save_error_message(&e));
    }

    (StatusCode::OK, ApiResponse::success(true))
}

async fn handle_reset_stats(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }

    let mut stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
    if let Some(us) = stats.get(&key) {
        let limit = us.limit_bytes;
        stats.insert(key.clone(), Arc::new(UserStats::new(limit)));
        (StatusCode::OK, ApiResponse::success(true))
    } else {
        api_error("user not found")
    }
}

#[derive(Serialize)]
struct DevicesView {
    /// 0 = no limit.
    max_devices: u32,
    devices: Vec<crate::devices::Device>,
}

/// The device limit of a user and the devices that fetched its subscription.
async fn handle_list_devices(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<DevicesView>();
    }
    let max = match state.access_keys.read().unwrap_or_else(|e| e.into_inner()).get(&key) {
        Some(m) => m.max_devices.unwrap_or(0),
        None => return api_error("user not found"),
    };
    let devices = state.devices.list(&ostp_core::subscription::token_for_key(&key));
    (StatusCode::OK, ApiResponse::success(DevicesView { max_devices: max, devices }))
}

/// Frees one slot of a user's device limit.
async fn handle_remove_device(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path((key, hwid)): Path<(String, String)>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }
    if !state.access_keys.read().unwrap_or_else(|e| e.into_inner()).contains_key(&key) {
        return api_error("user not found");
    }
    if state.devices.remove(&ostp_core::subscription::token_for_key(&key), &hwid) {
        (StatusCode::OK, ApiResponse::success(true))
    } else {
        api_error("device not found")
    }
}

/// Forgets every device of a user.
async fn handle_clear_devices(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<usize>();
    }
    if !state.access_keys.read().unwrap_or_else(|e| e.into_inner()).contains_key(&key) {
        return api_error("user not found");
    }
    let n = state.devices.clear(&ostp_core::subscription::token_for_key(&key));
    (StatusCode::OK, ApiResponse::success(n))
}

/// The links and subscription URL to hand a user, as the panel shows them.
async fn handle_user_share(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<UserShare>();
    }
    let name = match state.access_keys.read().unwrap_or_else(|e| e.into_inner()).get(&key) {
        Some(meta) => meta.name.clone().filter(|n| !n.is_empty()),
        None => return api_error("user not found"),
    };
    let owndns = state.dns_server.enabled();
    let dnsall = state.dns_server.settings().intercept_all_port53;

    use ostp_core::share_link::ShareLink;
    let title = |kind: &str| match &name {
        Some(n) => format!("{n} · {kind}"),
        None => format!("{} · {kind}", state.server_host),
    };
    let mut udp = ShareLink::udp_for(&key, &state.server_host, state.server_port, owndns).with_pk(state.server_pk);
    udp.name = Some(title("UDP"));
    udp.dnsall = dnsall;
    let tls = state.tls_link.as_ref().map(|t| {
        let mut l = ShareLink::tls_for(&key, &t.host, t.port, t.path.clone(), owndns).with_pk(state.server_pk);
        l.name = Some(title("TLS"));
        l.dnsall = dnsall;
        l.to_uri()
    });
    let subscription = match (&state.subscription_prefix, &state.tls_link) {
        (Some(prefix), Some(t)) => Some(ostp_core::subscription::subscription_url(
            &t.host,
            t.port,
            prefix,
            &ostp_core::subscription::token_for_key(&key),
        )),
        _ => None,
    };
    (StatusCode::OK, ApiResponse::success(UserShare { tls, udp: udp.to_uri(), subscription }))
}

/// Renders a QR code on the server, so the panel needs no script from
/// anywhere else and keys never go to a third-party QR service.
async fn handle_qr(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<QrRequest>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<String>();
    }
    if req.text.len() > 2048 {
        return api_error("text too long for a QR code");
    }
    match qrcode::QrCode::new(req.text.as_bytes()) {
        Ok(code) => {
            let svg = code
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(240, 240)
                .dark_color(qrcode::render::svg::Color("#000000"))
                .light_color(qrcode::render::svg::Color("#ffffff"))
                .build();
            (StatusCode::OK, ApiResponse::success(svg))
        }
        Err(e) => api_error(&format!("cannot encode a QR code: {e}")),
    }
}

// ── Subscription endpoint ────────────────────────────────────────────────────

/// Returns a ready-to-use client configuration for the given access key.
/// No Bearer token required -- the access key itself authenticates the request.
/// Compatible with subscription managers (sub-store, NekoBox, custom panels).
///
/// GET /api/subscribe/{key}
/// Response: JSON client config or ostp:// share link (via Accept header)

#[derive(Debug, Deserialize)]
struct SubscribeQuery {
    /// "udp" or "tls"; defaults to tls when it is configured.
    transport: Option<String>,
}

/// Unknown keys tried on `/subscribe/{key}`: 30 per 10 minutes.
static SUBSCRIBE_MISSES: std::sync::LazyLock<crate::transport::limiter::FailureLimiter> =
    std::sync::LazyLock::new(|| crate::transport::limiter::FailureLimiter::new(std::time::Duration::from_secs(600), 30));
const SUBSCRIBE_SOURCE: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

async fn handle_subscribe(
    State(state): State<ApiState>,
    Path(key): Path<String>,
    axum::extract::Query(query): axum::extract::Query<SubscribeQuery>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Validate that the key exists in a tightly scoped block to drop the guard
    let max_devices = {
        let keys = state.access_keys.read().unwrap_or_else(|e| e.into_inner());
        keys.get(&key).map(|m| m.max_devices)
    };

    let Some(max_devices) = max_devices else {
        // Guessing is capped server-wide (behind the tunnel and the HTTPS
        // frontend the peer is always loopback, so not per address); a correct
        // key is never counted or refused.
        if !SUBSCRIBE_MISSES.allowed(SUBSCRIBE_SOURCE) {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        SUBSCRIBE_MISSES.record_failure(SUBSCRIBE_SOURCE);
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false,
            "error": "invalid access key"
        }))).into_response();
    };

    // The same device limit as the subscription endpoint: this one hands out the
    // same profile, so it must not be a way around the limit.
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
    let hwid = crate::devices::Hwid::parse(header("x-hwid"), header("x-device-os"), header("x-device-model"));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let token = ostp_core::subscription::token_for_key(&key);
    if let Err(refusal) = state.devices.check_blocking(&token, max_devices, hwid, now).await {
        let (code, message) = refusal.code_and_message();
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "ok": false,
            "error": code,
            "message": message
        }))).into_response();
    }

    let accept = headers.get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    use ostp_core::share_link::ShareLink;
    let dns_enabled = state.dns_server.enabled();
    let udp = ShareLink::udp_for(&key, &state.server_host, state.server_port, dns_enabled).with_pk(state.server_pk);
    let tls = state.tls_link.as_ref().map(|t| ShareLink::tls_for(&key, &t.host, t.port, t.path.clone(), dns_enabled).with_pk(state.server_pk));
    let chosen = match (query.transport.as_deref(), &tls) {
        (Some("udp"), _) | (_, None) => udp.clone(),
        (_, Some(t)) => t.clone(),
    };
    let links = serde_json::json!({
        "udp": udp.to_uri(),
        "tls": tls.as_ref().map(|t| t.to_uri()),
    });

    // If client requests plain text, return ostp:// share link
    if accept.contains("text/plain") {
        return (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "data": chosen.to_uri(),
            "links": links
        }))).into_response();
    }

    let carrier = if chosen.tls {
        serde_json::json!({ "mode": "uot", "tls": true, "ws_path": chosen.path })
    } else {
        serde_json::json!({ "mode": "udp" })
    };

    // Default: return full client config JSON. `server_pk` makes it a v6 profile
    // when the server has a key (without it the client would speak v5 and not
    // check the server); `carrier` is the section new configs write.
    let mut config = serde_json::json!({
        "mode": "client",
        "server": chosen.server(),
        "access_key": key,
        "carrier": carrier,
        "socks5_bind": "127.0.0.1:1088",
        "tun": {
            "enable": false,
            "dns": "1.1.1.1"
        },
        "exclude": {
            "domains": [],
            "ips": [],
            "processes": []
        },
        "mux": {
            "enabled": false,
            "sessions": 1
        },
        "debug": false
    });
    if let Some(pk) = state.server_pk {
        config["server_pk"] = serde_json::Value::String(ostp_core::server_key::encode_key(&pk));
    }

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "data": config,
        "links": links
    }))).into_response()
}


#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_state(webpath: &str) -> ApiState {
        ApiState {
            access_keys: Arc::new(RwLock::new(HashMap::new())),
            user_stats: Arc::new(RwLock::new(HashMap::new())),
            start_time: std::time::Instant::now(),
            session_token: Arc::new(RwLock::new(Vec::new())),
            api_token: Some("test-token".to_string()),
            webpath: webpath.to_string(),
            username: "admin".to_string(),
            password_hash: "hash".to_string(),
            server_host: "127.0.0.1".to_string(),
            server_port: 50000,
            server_pk: None,
            tls_link: None,
            subscription_prefix: None,
            config_path: None,
            dns_server: crate::dns::DnsServer::new(Default::default(), None),
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            devices: Arc::new(crate::devices::DeviceStore::in_memory()),
            router: Arc::new(crate::router::Router::new(None, None, crate::dns::DnsServer::new(Default::default(), None), false)),
        }
    }

    #[test]
    fn test_router_creation() {
        let state = make_test_state("bNAzr8Ss");
        let _router = create_api_router(state);
    }

    #[test]
    fn test_router_creation_empty_webpath() {
        let state = make_test_state("");
        let _router = create_api_router(state);
    }

    #[test]
    fn test_secure_eq_matches_and_rejects() {
        assert!(secure_eq("same-secret", "same-secret"));
        assert!(!secure_eq("same-secret", "different"));
        assert!(!secure_eq("short", "much-longer-value"));
        assert!(secure_eq("", ""));
    }

    fn headers_with_bearer(token: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    // These pin down check_token's behavior directly: it's the single gate
    // every mutating/sensitive handler (including the audit-log ones - see
    // the missing-auth fix) relies on, so its logic must be independently
    // verified rather than only exercised incidentally through handlers.
    #[test]
    fn test_check_token_rejects_missing_header_when_configured() {
        let state = make_test_state("panel");
        assert!(!check_token(&state, &axum::http::HeaderMap::new()));
    }

    #[test]
    fn test_check_token_accepts_matching_api_token_as_bearer() {
        let state = make_test_state("panel");
        assert!(check_token(&state, &headers_with_bearer("test-token")));
    }

    #[test]
    fn test_check_token_accepts_matching_api_token_raw() {
        let state = make_test_state("panel");
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", "test-token".parse().unwrap());
        assert!(check_token(&state, &h));
    }

    #[test]
    fn test_check_token_rejects_wrong_token() {
        let state = make_test_state("panel");
        assert!(!check_token(&state, &headers_with_bearer("wrong-token")));
    }

    #[test]
    fn test_check_token_accepts_matching_session_token() {
        let state = make_test_state("panel");
        state.session_token.write().unwrap().push(Session::new("live-session".to_string()));
        assert!(check_token(&state, &headers_with_bearer("live-session")));
    }

    #[test]
    fn test_check_token_refuses_everyone_without_credentials() {
        let mut state = make_test_state("panel");
        state.api_token = None;
        state.username.clear();
        state.password_hash.clear();
        // There is no open-panel mode: the panel controls the server and
        // loopback is reachable through the tunnel.
        assert!(!check_token(&state, &axum::http::HeaderMap::new()));
        assert!(!has_credentials("", "", None));
        assert!(!has_credentials("admin", "", Some("  ")));
        assert!(has_credentials("admin", "hash", None));
        assert!(has_credentials("", "", Some("relay-token")));
    }

    /// `"token": ""` is what `ostp init server` writes. It must not let an
    /// empty Authorization header through.
    #[test]
    fn test_check_token_empty_token_is_no_token() {
        let mut state = make_test_state("panel");
        state.api_token = Some(String::new());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", axum::http::HeaderValue::from_static(""));
        assert!(!check_token(&state, &headers));
        assert!(!check_token(&state, &headers_with_bearer("")));
    }

    #[test]
    fn test_check_key_rules() {
        assert!(check_key("0123456789abcdef").is_ok());
        assert!(check_key("short").is_err());
        assert!(check_key(&"a".repeat(129)).is_err());
        assert!(check_key("has space in it").is_err());
        assert!(check_key("slash/inside-key").is_err());
        assert!(check_key("hash#inside-key").is_err());
        assert!(check_key("nul\u{0}inside-key").is_err());
    }

    #[test]
    fn expiry_requests() {
        assert_eq!(check_expires(None), Ok(None));
        assert_eq!(check_expires(Some(0)), Ok(None));
        assert_eq!(check_expires(Some(1_767_225_599)), Ok(Some(1_767_225_599)));
        assert!(check_expires(Some(u64::MAX)).is_err());
        let r: UpdateUserRequest = serde_json::from_str(r#"{"name": "a"}"#).unwrap();
        assert_eq!(r.expires_at, None, "absent: unchanged");
        let r: UpdateUserRequest = serde_json::from_str(r#"{"expires_at": null}"#).unwrap();
        assert_eq!(r.expires_at, Some(None), "null: cleared");
        let r: UpdateUserRequest = serde_json::from_str(r#"{"expires_at": 5}"#).unwrap();
        assert_eq!(r.expires_at, Some(Some(5)));
        let c: CreateUserRequest = serde_json::from_str(r#"{"expires_at": 7}"#).unwrap();
        assert_eq!(c.expires_at, Some(7));
        // Written to config.json only when set, and dropped when cleared.
        let mut m = meta(Some("a"), None);
        m.expires_at = Some(9);
        let e = key_entry("k", &m, None);
        assert_eq!(e["expires_at"], 9);
        m.expires_at = None;
        assert!(key_entry("k", &m, Some(&e)).get("expires_at").is_none());
        assert!(!m.is_expired(0));
        m.expires_at = Some(10);
        assert!(m.is_expired(10) && !m.is_expired(9));
    }

    #[test]
    fn test_check_name_and_limit() {
        assert_eq!(check_name(None), Ok(None));
        assert_eq!(check_name(Some("  ".into())), Ok(None));
        assert_eq!(check_name(Some(" alice ".into())), Ok(Some("alice".into())));
        assert!(check_name(Some("x".repeat(101))).is_err());
        assert!(check_name(Some("a\nb".into())).is_err());
        assert!(check_limit(Some(MAX_LIMIT_BYTES)).is_ok());
        assert!(check_limit(Some(MAX_LIMIT_BYTES + 1)).is_err());
        assert!(check_limit(Some(u64::MAX)).is_err());
        assert!(check_limit(None).is_ok());
    }

    #[test]
    fn test_check_rules_caps() {
        let rule = |n: usize| OutboundRule {
            domain_suffix: vec!["example.org".into(); n],
            ip_cidr: vec![],
            protocol: None,
            action: crate::outbound::OutboundAction::Direct,
            send_from: None,
        };
        assert!(check_rules(&[rule(3)]).is_ok());
        assert!(check_rules(&vec![rule(1); 2_001]).is_err());
        assert!(check_rules(&vec![rule(26); 2_000]).is_err());
        let mut long = rule(1);
        long.domain_suffix[0] = "a".repeat(300);
        assert!(check_rules(&[long]).is_err());
    }

    /// Many requests changing config.json at once: every change must survive
    /// and the file must stay valid JSON.
    #[test]
    fn test_edit_config_concurrent_writes_keep_all_changes() {
        let dir = std::env::temp_dir().join(format!("ostp-api-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{ "mode": "server", "n": [] }"#).unwrap();
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    edit_config(&path, false, |v| {
                        v["n"].as_array_mut().unwrap().push(serde_json::json!(i));
                        Ok(())
                    })
                    .unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let v = parse_config(&path).unwrap();
        assert_eq!(v["n"].as_array().unwrap().len(), 16);
        let leftovers = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().ends_with(".tmp")).count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn meta(name: Option<&str>, limit: Option<u64>) -> UserMeta {
        UserMeta { name: name.map(String::from), limit_bytes: limit, max_devices: None, expires_at: None }
    }

    /// A change is applied to the list on disk: a user the CLI added and the
    /// server has not reloaded yet survives, and so do unknown fields.
    #[test]
    fn test_key_change_keeps_what_is_on_disk() {
        let mut cfg = serde_json::json!({
            "mode": "server",
            "access_keys": ["cli-added-key", {"access_key": "kept-key", "name": "old", "note": "x"}]
        });
        apply_key_change(&mut cfg, &KeyChange::Add(vec![("new-key-0001".into(), meta(None, None))])).unwrap();
        apply_key_change(&mut cfg, &KeyChange::Set { key: "kept-key".into(), meta: meta(Some("new"), Some(5)) }).unwrap();
        let list = cfg["access_keys"].as_array().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], "cli-added-key");
        assert_eq!(list[1]["name"], "new");
        assert_eq!(list[1]["limit_bytes"], 5);
        assert_eq!(list[1]["note"], "x");
        assert_eq!(list[2], "new-key-0001", "a user with nothing to say stays a bare string");

        apply_key_change(&mut cfg, &KeyChange::Remove("kept-key".into())).unwrap();
        assert_eq!(cfg["access_keys"].as_array().unwrap().len(), 2);
        assert_eq!(
            apply_key_change(&mut cfg, &KeyChange::Add(vec![("cli-added-key".into(), meta(None, None))])),
            Err(ERR_ALREADY_IN_FILE.to_string())
        );
        assert_eq!(
            apply_key_change(&mut cfg, &KeyChange::Set { key: "gone".into(), meta: meta(None, None) }),
            Err(ERR_NOT_IN_FILE.to_string())
        );
    }

    #[test]
    fn test_login_limit_is_per_address_with_a_larger_global_cap() {
        let now = Instant::now();
        let mut l = LoginLimiter::new(now);
        let a: std::net::IpAddr = "203.0.113.1".parse().unwrap();
        let b: std::net::IpAddr = "203.0.113.2".parse().unwrap();
        for _ in 0..10 {
            assert!(l.reserve(a, now));
        }
        assert!(!l.reserve(a, now), "one address is out of attempts");
        assert!(l.reserve(b, now), "another address is not locked out by it");
        l.refund(b);
        // A minute later the address has 10 attempts again.
        assert!(l.reserve(a, now + std::time::Duration::from_secs(60)));
        // The server-wide ceiling still holds against many addresses.
        let mut allowed = 0;
        for i in 0..400u32 {
            let ip: std::net::IpAddr = std::net::Ipv4Addr::from(0x0a00_0000 + i).into();
            allowed += usize::from(l.reserve(ip, now));
        }
        assert!(allowed < 400 && allowed > 100, "{allowed}");
    }

    #[test]
    fn test_login_source_groups_ipv6_by_64() {
        let x: std::net::IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let y: std::net::IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        assert_eq!(login_source(x), login_source(y));
        let v4: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(login_source(v4), v4);
    }

    #[test]
    fn test_panel_files_cannot_be_framed() {
        let h = panel_headers("text/html");
        assert!(h.iter().any(|(k, v)| *k == header::X_FRAME_OPTIONS && v == "DENY"));
        assert!(h.iter().any(|(k, v)| *k == header::X_CONTENT_TYPE_OPTIONS && v == "nosniff"));
        assert!(h.iter().any(|(k, v)| *k == header::CONTENT_SECURITY_POLICY && v.contains("frame-ancestors 'none'")));
    }

    #[test]
    fn test_build_version_carries_the_channel() {
        let v = build_version();
        assert!(v.starts_with(env!("CARGO_PKG_VERSION")), "{v}");
        assert!(!v.starts_with('v'));
    }

    #[test]
    fn test_update_request_tells_absent_from_null() {
        let r: UpdateUserRequest = serde_json::from_str(r#"{"max_devices": 2}"#).unwrap();
        assert_eq!(r.name, None);
        assert_eq!(r.limit_bytes, None);
        let r: UpdateUserRequest = serde_json::from_str(r#"{"name": null, "limit_bytes": 7}"#).unwrap();
        assert_eq!(r.name, Some(None));
        assert_eq!(r.limit_bytes, Some(Some(7)));
        assert_eq!(r.max_devices, None);
    }

    /// A config that does not parse is not overwritten.
    #[test]
    fn test_edit_config_leaves_broken_file_alone() {
        let dir = std::env::temp_dir().join(format!("ostp-api-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert!(edit_config(&path, false, |_| Ok(())).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sessions_expire_idle_and_absolute() {
        let state = make_test_state("panel");
        let now = Instant::now();
        let mut idle = Session::new("idle".into());
        idle.last_seen = now.checked_sub(SESSION_IDLE).unwrap();
        let mut old = Session::new("old".into());
        old.created = now.checked_sub(SESSION_MAX).unwrap();
        state.session_token.write().unwrap().extend([idle, old, Session::new("fresh".into())]);
        assert!(!check_token(&state, &headers_with_bearer("idle")));
        assert!(!check_token(&state, &headers_with_bearer("old")));
        assert!(check_token(&state, &headers_with_bearer("fresh")));
        assert_eq!(state.session_token.read().unwrap().len(), 1, "expired sessions are dropped");
    }

    #[tokio::test]
    async fn test_logout_drops_only_its_own_session() {
        let state = make_test_state("panel");
        state.session_token.write().unwrap().extend([Session::new("a".into()), Session::new("b".into())]);
        let resp = handle_logout(State(state.clone()), headers_with_bearer("a")).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!check_token(&state, &headers_with_bearer("a")));
        assert!(check_token(&state, &headers_with_bearer("b")));
        let resp = handle_logout(State(state), headers_with_bearer("a")).await.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_sessions_of_two_admins_both_work() {
        let state = make_test_state("panel");
        state.session_token.write().unwrap().extend([Session::new("first".into()), Session::new("second".into())]);
        assert!(check_token(&state, &headers_with_bearer("first")));
        assert!(check_token(&state, &headers_with_bearer("second")));
        assert!(!check_token(&state, &headers_with_bearer("third")));
    }

    /// The server does not serve the API at all without a way to sign in.
    #[tokio::test]
    async fn test_api_is_not_started_without_credentials() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let config = ApiConfig {
            enabled: true,
            bind: format!("127.0.0.1:{port}"),
            token: Some(String::new()),
            ..Default::default()
        };
        let state = make_test_state("");
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            start_api_server(
                config,
                state.access_keys,
                state.user_stats,
                String::new(),
                0,
                None,
                None,
                None,
                None,
                state.dns_server,
                state.router,
            ),
        )
        .await
        .expect("start_api_server must return instead of serving");
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
}

async fn handle_get_audit(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<Vec<AuditLogEntry>>();
    }
    let logs = state.audit_logs.read().unwrap_or_else(|e| e.into_inner());
    (StatusCode::OK, ApiResponse::success(logs.clone()))
}

async fn handle_create_audit(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateAuditLogRequest>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }
    // The panel writes these; a client of the API may write anything.
    let short = |s: String| -> String { s.chars().take(300).collect() };
    let mut logs = state.audit_logs.write().unwrap_or_else(|e| e.into_inner());
    let id = format!("{:x}", rand::random::<u64>());
    let now = chrono::Local::now();
    let entry = AuditLogEntry {
        id,
        time: now.format("%H:%M:%S").to_string(),
        event_en: short(req.event_en),
        event_ru: short(req.event_ru),
        success: req.success,
    };
    logs.insert(0, entry);
    if logs.len() > 100 {
        logs.truncate(100);
    }

    (StatusCode::OK, ApiResponse::success(true))
}

// ── Bulk keys & Router Rules ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BulkCreateRequest {
    pub count: usize,
    pub limit_bytes: Option<u64>,
    pub max_devices: Option<u32>,
    /// Unix seconds (UTC); absent or `null` = never.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

async fn handle_bulk_create_users(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<BulkCreateRequest>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) { return api_unauthorized(); }
    if payload.count > 1000 {
        return api_error("Count too large, max 1000");
    }
    if payload.count == 0 {
        return api_error("Count must be at least 1");
    }
    if let Err(m) = check_limit(payload.limit_bytes) {
        return api_error(m);
    }
    let bulk_devices = match check_devices(payload.max_devices) {
        Ok(n) => n,
        Err(m) => return api_error(m),
    };
    let bulk_expires = match check_expires(payload.expires_at) {
        Ok(t) => t,
        Err(m) => return api_error(m),
    };

    let mut new_keys = Vec::new();
    let mut keys = match state.access_keys.write() {
        Ok(k) => k,
        Err(e) => e.into_inner(),
    };
    if keys.len() + payload.count > MAX_USERS {
        return api_error("too many users (10000 at most)");
    }

    for _ in 0..payload.count {
        // 128 random bits, like a single created key: the access key is the
        // handshake's pre-shared key, so a captured handshake can be guessed
        // against offline. (Sixteen hex digits of a UUIDv4 are only 60 bits.)
        let key = ostp_core::keys::access_key_hex();
        keys.insert(key.clone(), UserMeta {
            name: None,
            limit_bytes: payload.limit_bytes,
            max_devices: bulk_devices,
            expires_at: bulk_expires,
        });
        new_keys.push(key);
    }
    // Save keys by dropping lock, then saving to config
    drop(keys);
    let added = new_keys
        .iter()
        .map(|k| (k.clone(), UserMeta { name: None, limit_bytes: payload.limit_bytes, max_devices: bulk_devices, expires_at: bulk_expires }))
        .collect();
    if let Err(e) = save_key_change(&state, KeyChange::Add(added)) {
        tracing::error!("Failed to save config after bulk create: {}", e);
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        for k in &new_keys {
            keys.remove(k);
        }
        return api_error(save_error_message(&e));
    }

    (StatusCode::OK, ApiResponse::success(new_keys))
}

// ── DNS ──────────────────────────────────────────────────────────────────────

async fn handle_dns_stats(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<ostp_dns::Stats>();
    }
    (StatusCode::OK, ApiResponse::success(state.dns_server.stats()))
}

#[derive(Deserialize)]
struct DnsLogQuery {
    limit: Option<usize>,
    q: Option<String>,
}

async fn handle_dns_log(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<DnsLogQuery>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<Vec<ostp_dns::LogEntry>>();
    }
    let q = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    (StatusCode::OK, ApiResponse::success(state.dns_server.query_log(query.limit.unwrap_or(200).min(2000), q)))
}

async fn handle_dns_clear_log(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }
    state.dns_server.clear_log();
    (StatusCode::OK, ApiResponse::success(true))
}

async fn handle_dns_get_settings(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<ostp_dns::DnsSettings>();
    }
    (StatusCode::OK, ApiResponse::success((*state.dns_server.settings()).clone()))
}

/// Applies the settings live (no restart) and writes them to config.json.
async fn handle_dns_put_settings(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(settings): Json<ostp_dns::DnsSettings>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }
    if let Err(m) = check_dns_settings(&settings) {
        return api_error(m);
    }
    if let Err(e) = state.dns_server.apply(settings) {
        return api_error(&format!("{e:#}"));
    }
    if let Some(path) = &state.config_path {
        let saved = edit_config(path, true, |v| {
            v["dns"] = serde_json::to_value(&*state.dns_server.settings()).map_err(|e| e.to_string())?;
            Ok(())
        });
        if let Err(e) = saved {
            return api_error(&format!("applied, but config.json was not written: {e}"));
        }
    }
    (StatusCode::OK, ApiResponse::success(true))
}

/// Downloads every filter list: slow and heavy, so one run at a time.
static DNS_UPDATING: AtomicBool = AtomicBool::new(false);

struct UpdateFlight;
impl Drop for UpdateFlight {
    fn drop(&mut self) {
        DNS_UPDATING.store(false, Ordering::Release);
    }
}

async fn handle_dns_update(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<Vec<ostp_dns::lists::UpdateResult>>();
    }
    if DNS_UPDATING.swap(true, Ordering::AcqRel) {
        return api_error("a list update is already running");
    }
    let _flight = UpdateFlight;
    // Shorter than the panel's own timeout, so the panel gets an answer.
    match tokio::time::timeout(std::time::Duration::from_secs(100), state.dns_server.update_lists()).await {
        Ok(results) => (StatusCode::OK, ApiResponse::success(results)),
        Err(_) => api_error("the list update took too long and was stopped"),
    }
}

/// Caps on what one settings request may carry: every entry stays in memory and in config.json.
fn check_dns_settings(s: &ostp_dns::DnsSettings) -> Result<(), &'static str> {
    if s.upstreams.len() > 16 || s.lists.len() > 200 || s.allowlists.len() > 200 || s.rewrites.len() > 5_000
        || s.user_rules.len() > 50_000 || s.blocked_services.len() > 500
    {
        return Err("too many entries in the DNS settings");
    }
    if s.cache_size > 1_000_000 || s.query_log_size > 100_000 {
        return Err("DNS cache or query log size is too large");
    }
    let long = |x: &str| x.len() > 2048;
    if s.upstreams.iter().any(|x| long(x))
        || s.user_rules.iter().any(|x| long(x))
        || s.lists.iter().chain(&s.allowlists).any(|l| long(&l.name) || long(&l.url))
        || s.rewrites.iter().any(|r| long(&r.domain) || long(&r.answer))
    {
        return Err("an entry in the DNS settings is too long");
    }
    Ok(())
}

#[derive(Deserialize)]
struct DnsTestRequest {
    domain: String,
}

async fn handle_dns_test(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DnsTestRequest>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<ostp_dns::Explanation>();
    }
    if req.domain.len() > 253 {
        return api_error("domain name is too long");
    }
    (StatusCode::OK, ApiResponse::success(state.dns_server.explain(&req.domain)))
}

async fn handle_overnet_status(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<crate::overnet::OvernetStatus>();
    }
    (StatusCode::OK, ApiResponse::success(state.router.overnet().status()))
}

/// Applies the overnet section live (no restart) and writes it to config.json.
async fn handle_overnet_put(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(cfg): Json<crate::overnet::OvernetConfig>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<crate::overnet::OvernetStatus>();
    }
    // Applying opens and closes listeners: two requests at once would race over them.
    static APPLYING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one_at_a_time = APPLYING.lock().await;
    if let Err(e) = crate::overnet::apply(cfg.clone(), &state.router).await {
        return api_error(&format!("{e:#}"));
    }
    if let Some(path) = &state.config_path {
        let saved = edit_config(path, true, |v| {
            v["overnet"] = serde_json::to_value(&cfg).map_err(|e| e.to_string())?;
            Ok(())
        });
        if let Err(e) = saved {
            return api_error(&format!("applied, but config.json was not written: {e}"));
        }
    }
    (StatusCode::OK, ApiResponse::success(state.router.overnet().status()))
}

#[derive(Serialize)]
struct DnsMeta {
    presets: Vec<(String, String, String)>,
    services: Vec<(String, String)>,
}

async fn handle_dns_meta(State(state): State<ApiState>, headers: axum::http::HeaderMap) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<DnsMeta>();
    }
    let meta = DnsMeta {
        presets: ostp_dns::PRESET_LISTS.iter().map(|(i, n, u)| (i.to_string(), n.to_string(), u.to_string())).collect(),
        services: ostp_dns::services::SERVICES.iter().map(|(i, n, _)| (i.to_string(), n.to_string())).collect(),
    };
    (StatusCode::OK, ApiResponse::success(meta))
}

async fn handle_get_rules(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) { return api_unauthorized(); }
    
    let lock = state.router.outbound_cfg.read().unwrap();
    let rules = if let Some(cfg) = lock.as_ref() {
        cfg.rules.clone()
    } else {
        Vec::new()
    };
    
    (StatusCode::OK, ApiResponse::success(rules))
}

/// Caps for a rule set: the whole list is matched against every connection.
fn check_rules(rules: &[OutboundRule]) -> Result<(), &'static str> {
    if rules.len() > 2_000 {
        return Err("too many rules (2000 at most)");
    }
    let mut entries = 0usize;
    for r in rules {
        entries += r.domain_suffix.len() + r.ip_cidr.len();
        if r.domain_suffix.iter().chain(&r.ip_cidr).any(|x| x.len() > 253 || x.chars().any(|c| c.is_control())) {
            return Err("a rule entry is too long or has control characters");
        }
        if r.protocol.as_deref().is_some_and(|p| p.len() > 32) || r.send_from.as_deref().is_some_and(|p| p.len() > 64) {
            return Err("a rule field is too long");
        }
    }
    if entries > 50_000 {
        return Err("too many entries in the rules (50000 at most)");
    }
    Ok(())
}

async fn handle_put_rules(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(new_rules): Json<Vec<OutboundRule>>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) { return api_unauthorized(); }
    if let Err(m) = check_rules(&new_rules) {
        return api_error(m);
    }

    // Update memory
    #[allow(unused_assignments)]
    let mut updated_outbound = None;
    {
        let mut lock = state.router.outbound_cfg.write().unwrap();
        if let Some(cfg) = lock.as_mut() {
            cfg.rules = new_rules.clone();
            updated_outbound = Some(cfg.clone());
        } else {
            return api_error("Outbound routing is not enabled in config");
        }
    }

    if let Some(cfg) = updated_outbound {
        state.dns_server.set_proxy(crate::dns::proxy_url(Some(&cfg)));
    }

    // Save to config.json. A config that cannot be parsed is left alone (never
    // "null" over every access key); the rules stay applied either way.
    if let Some(path) = &state.config_path {
        let saved = edit_config(path, false, |cfg| {
            if let Some(outbound_obj) = cfg.get_mut("outbound").and_then(|o| o.as_object_mut()) {
                let rules_json = serde_json::to_value(&new_rules).map_err(|e| e.to_string())?;
                outbound_obj.insert("rules".to_string(), rules_json);
            }
            Ok(())
        });
        if let Err(e) = saved {
            return api_error(&format!("applied, but config.json was not written: {e}"));
        }
    }

    (StatusCode::OK, ApiResponse::success(true))
}

async fn handle_clear_audit(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<()>();
    }
    let mut logs = state.audit_logs.write().unwrap_or_else(|e| e.into_inner());
    logs.clear();
    (StatusCode::OK, ApiResponse::success(()))
}


