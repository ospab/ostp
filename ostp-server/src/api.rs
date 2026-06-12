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

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::Ordering;
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
use sha2::Digest;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::dispatcher::{UserStats, UserStatsSnapshot};
use crate::outbound::OutboundRule;

// ── Shared state for API handlers ────────────────────────────────────────────

/// API server shared state. Held behind Arc for axum handlers.
#[derive(Clone)]
pub struct ApiState {
    pub access_keys: Arc<RwLock<HashMap<String, UserMeta>>>,
    pub user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    pub start_time: Instant,
    pub session_token: Arc<RwLock<Option<String>>>,
    pub api_token: Option<String>,
    pub webpath: String,
    pub username: String,
    pub password_hash: String,
    /// Server address for subscription links (e.g. "example.com")
    pub server_host: String,
    pub server_port: u16,
    pub config_path: Option<std::path::PathBuf>,
    pub dns_server: std::sync::Arc<crate::dns::DnsServer>,
    pub audit_logs: Arc<RwLock<Vec<AuditLogEntry>>>,
    pub router: std::sync::Arc<crate::router::Router>,
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
}

// ── Request/Response types ───────────────────────────────────────────────────

#[derive(Serialize)]
struct ServerStatus {
    version: &'static str,
    uptime_seconds: u64,
    active_users: usize,
    total_users: usize,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub access_key: Option<String>,
    pub name: Option<String>,
    pub limit_bytes: Option<u64>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub limit_bytes: Option<u64>,
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

fn api_unauthorized<T: Serialize>() -> (StatusCode, Json<ApiResponse<T>>) {
    (StatusCode::UNAUTHORIZED, Json(ApiResponse { ok: false, data: None, error: Some("unauthorized".to_string()) }))
}

#[derive(RustEmbed)]
#[folder = "../ostp-control/dist/"]
struct Assets;

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
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => {
            if let Some(index) = Assets::get("index.html") {
                ([(header::CONTENT_TYPE, "text/html")], index.data).into_response()
            } else {
                (StatusCode::NOT_FOUND, "404 Not Found").into_response()
            }
        }
    }
}

// ── API router ───────────────────────────────────────────────────────────────

pub fn create_api_router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_router = Router::new()
        .route("/server/status", get(handle_status))
        .route("/server/config", get(handle_get_config).put(handle_put_config))
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
        .route("/subscribe/{key}", get(handle_subscribe))
        .route("/login", post(handle_login))
        .route(
            "/audit",
            get(handle_get_audit)
                .post(handle_create_audit)
                .delete(handle_clear_audit),
        )
        .route("/users/bulk", post(handle_bulk_create_users))
        .route("/router/rules", get(handle_get_rules).put(handle_put_rules));

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
        .layer(cors)
        .with_state(state)
}

/// Start the Management API server on the configured bind address.
pub async fn start_api_server(
    config: ApiConfig,
    access_keys: Arc<RwLock<HashMap<String, UserMeta>>>,
    user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    server_host: String,
    server_port: u16,
    config_path: Option<std::path::PathBuf>,
    dns_server: std::sync::Arc<crate::dns::DnsServer>,
    router: std::sync::Arc<crate::router::Router>,
) {
    let state = ApiState {
        access_keys,
        user_stats,
        start_time: Instant::now(),
        session_token: Arc::new(RwLock::new(None)),
        api_token: config.token.clone(),
        webpath: config.webpath.clone(),
        username: config.username.clone(),
        password_hash: config.password_hash.clone(),
        server_host,
        server_port,
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

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Management API error: {}", e);
    }
}

// ── Middleware: token check ──────────────────────────────────────────────────

fn check_token(state: &ApiState, headers: &axum::http::HeaderMap) -> bool {
    // Both session token (for web UI) and static API token (for relays) are checked
    let mut allowed = false;

    // If no credentials configured, panel is open (unsafe but possible)
    if state.username.is_empty() && state.password_hash.is_empty() && state.api_token.is_none() {
        return true;
    }

    if let Some(value) = headers.get("authorization") {
        if let Ok(val) = value.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                let current_session = state.session_token.read().unwrap_or_else(|e| e.into_inner()).clone();
                if let Some(session) = current_session {
                    if token == session {
                        allowed = true;
                    }
                }
                
                if let Some(ref api_tok) = state.api_token {
                    if token == api_tok {
                        allowed = true;
                    }
                }
            } else {
                if let Some(ref api_tok) = state.api_token {
                    if val == api_tok {
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
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    if state.username.is_empty() || state.password_hash.is_empty() {
        return api_error("Auth not configured");
    }

    if payload.username != state.username {
        return api_unauthorized::<LoginResponse>();
    }

    let password = payload.password.unwrap_or_default();
    let hash = sha2::Sha256::digest(password.as_bytes());
    let hash_hex = format!("{:x}", hash);

    if hash_hex == state.password_hash {
        let token = uuid::Uuid::new_v4().to_string();
        *state.session_token.write().unwrap_or_else(|e| e.into_inner()) = Some(token.clone());
        (StatusCode::OK, ApiResponse::success(LoginResponse { token }))
    } else {
        api_unauthorized::<LoginResponse>()
    }
}

fn save_config_keys(state: &ApiState) -> Result<(), String> {
    let Some(ref path) = state.config_path else {
        return Ok(());
    };

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file: {}", e))?;

    let mut stripped = json_comments::StripComments::new(content.as_bytes());
    let mut content_str = String::new();
    use std::io::Read;
    stripped.read_to_string(&mut content_str)
        .map_err(|e| format!("failed to strip comments from config: {}", e))?;

    let mut json_val: serde_json::Value = serde_json::from_str(&content_str)
        .map_err(|e| format!("failed to parse config JSON: {}", e))?;

    let keys = state.access_keys.read().unwrap_or_else(|e| e.into_inner());
    let mut access_keys_json = Vec::new();
    for (k, m) in keys.iter() {
        if m.name.is_none() && m.limit_bytes.is_none() {
            access_keys_json.push(serde_json::Value::String(k.clone()));
        } else {
            let mut obj = serde_json::Map::new();
            obj.insert("access_key".to_string(), serde_json::Value::String(k.clone()));
            if let Some(ref name) = m.name {
                obj.insert("name".to_string(), serde_json::Value::String(name.clone()));
            }
            if let Some(limit) = m.limit_bytes {
                obj.insert("limit_bytes".to_string(), serde_json::Value::Number(limit.into()));
            }
            access_keys_json.push(serde_json::Value::Object(obj));
        }
    }

    if let Some(obj) = json_val.as_object_mut() {
        obj.insert("access_keys".to_string(), serde_json::Value::Array(access_keys_json));
    } else {
        return Err("config root is not an object".to_string());
    }

    let new_content = serde_json::to_string_pretty(&json_val)
        .map_err(|e| format!("failed to serialize config JSON: {}", e))?;

    std::fs::write(path, new_content)
        .map_err(|e| format!("failed to write config file: {}", e))?;

    Ok(())
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

    if body.get("mode").is_none() {
        return api_error("Invalid config: missing 'mode' field");
    }

    let new_content = match serde_json::to_string_pretty(&body) {
        Ok(s) => s,
        Err(e) => return api_error(&format!("Failed to format config JSON: {}", e)),
    };

    if let Err(e) = std::fs::write(path, new_content) {
        return api_error(&format!("Failed to write config file: {}", e));
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

    let keys = state.access_keys.read().unwrap_or_else(|e| e.into_inner());
    let stats = state.user_stats.read().unwrap_or_else(|e| e.into_inner());
    let online = stats.values()
        .filter(|us| {
            let total = us.bytes_up.load(Ordering::Relaxed) + us.bytes_down.load(Ordering::Relaxed);
            total > 0
        })
        .count();

    let status = ServerStatus {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        active_users: online,
        total_users: keys.len(),
    };

    (StatusCode::OK, ApiResponse::success(status))
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

    let key = body.access_key.unwrap_or_else(|| {
        use rand::RngCore;
        let mut buf = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut buf);
        buf.iter().map(|b| format!("{:02x}", b)).collect()
    });

    {
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        keys.insert(key.clone(), UserMeta { name: body.name.clone(), limit_bytes: body.limit_bytes });
    }

    let mut stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
    stats.insert(key.clone(), Arc::new(UserStats::new(body.limit_bytes)));
    drop(stats);

    if let Err(e) = save_config_keys(&state) {
        tracing::error!("Failed to save config after creating user: {}", e);
        return api_error::<String>("failed to save configuration");
    }

    tracing::info!("API: created user key {}", &key[..8.min(key.len())]);
    (StatusCode::OK, ApiResponse::success(key))
}

async fn delete_user(
    State(state): State<ApiState>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<String>();
    }

    {
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        if keys.remove(&key).is_none() {
            return api_error::<String>("User not found");
        }
    }

    {
        let mut stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
        stats.remove(&key);
    }

    if let Err(e) = save_config_keys(&state) {
        tracing::error!("Failed to save config after removing user: {}", e);
        return api_error::<String>("failed to save configuration");
    }

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

    {
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        if let Some(meta) = keys.get_mut(&key) {
            meta.name = body.name.clone();
            meta.limit_bytes = body.limit_bytes;
        } else {
            return api_error::<String>("User not found");
        }
    }

    {
        let mut stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
        let entry = stats.entry(key.clone())
            .or_insert_with(|| Arc::new(UserStats::new(body.limit_bytes)));
        
        *entry = Arc::new(UserStats {
            bytes_up: AtomicU64::new(entry.bytes_up.load(Ordering::Relaxed)),
            bytes_down: AtomicU64::new(entry.bytes_down.load(Ordering::Relaxed)),
            connections: AtomicU64::new(entry.connections.load(Ordering::Relaxed)),
            limit_bytes: body.limit_bytes,
            created_at: entry.created_at,
        });
    }

    if let Err(e) = save_config_keys(&state) {
        tracing::error!("Failed to save config after updating user: {}", e);
        return api_error::<String>("failed to save configuration");
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

    {
        let mut keys = state.access_keys.write().unwrap_or_else(|e| e.into_inner());
        if let Some(meta) = keys.get_mut(&key) {
            meta.limit_bytes = body.limit_bytes;
        } else {
            return api_error("user not found");
        }
    }

    let mut stats = state.user_stats.write().unwrap_or_else(|e| e.into_inner());
    let entry = stats.entry(key.clone())
        .or_insert_with(|| Arc::new(UserStats::new(body.limit_bytes)));

    *entry = Arc::new(UserStats {
        bytes_up: AtomicU64::new(entry.bytes_up.load(Ordering::Relaxed)),
        bytes_down: AtomicU64::new(entry.bytes_down.load(Ordering::Relaxed)),
        connections: AtomicU64::new(entry.connections.load(Ordering::Relaxed)),
        limit_bytes: body.limit_bytes,
        created_at: entry.created_at,
    });
    drop(stats);

    if let Err(e) = save_config_keys(&state) {
        tracing::error!("Failed to save config after setting user limit: {}", e);
        return api_error("failed to save configuration");
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

// ── Subscription endpoint ────────────────────────────────────────────────────

/// Returns a ready-to-use client configuration for the given access key.
/// No Bearer token required -- the access key itself authenticates the request.
/// Compatible with subscription managers (sub-store, NekoBox, custom panels).
///
/// GET /api/subscribe/{key}
/// Response: JSON client config or ostp:// share link (via Accept header)

async fn handle_subscribe(
    State(state): State<ApiState>,
    Path(key): Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Validate that the key exists in a tightly scoped block to drop the guard
    let key_exists = {
        let keys = state.access_keys.read().unwrap_or_else(|e| e.into_inner());
        keys.contains_key(&key)
    };

    if !key_exists {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false,
            "error": "invalid access key"
        }))).into_response();
    }

    let accept = headers.get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    // If client requests plain text, return ostp:// share link
    if accept.contains("text/plain") {
        let dns_enabled = state.dns_server.config.read().await.enabled;
        let rq = if dns_enabled {
            "?type=udp&owndns=true".to_string()
        } else {
            "?type=udp".to_string()
        };
        let link = format!("ostp://{}@{}:{}{}", key, state.server_host, state.server_port, rq);
        return (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "data": link
        }))).into_response();
    }

    // Default: return full client config JSON
    let config = serde_json::json!({
        "mode": "client",
        "server": format!("{}:{}", state.server_host, state.server_port),
        "access_key": key,
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
        "turn": {
            "enabled": false
        },
        "mux": {
            "enabled": false,
            "sessions": 1
        },
        "debug": false
    });

    (StatusCode::OK, Json(serde_json::json!({
        "ok": true,
        "data": config
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
            session_token: Arc::new(RwLock::new(None)),
            api_token: Some("test-token".to_string()),
            webpath: webpath.to_string(),
            username: "admin".to_string(),
            password_hash: "hash".to_string(),
            server_host: "127.0.0.1".to_string(),
            server_port: 50000,
            config_path: None,
            dns_server: crate::dns::DnsServer::new(Default::default()),
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            router: Arc::new(crate::router::Router::new(None, crate::dns::DnsServer::new(Default::default()), false)),
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
}

async fn handle_get_audit(State(state): State<ApiState>) -> impl IntoResponse {
    let logs = state.audit_logs.read().unwrap();
    ApiResponse::success(logs.clone())
}

async fn handle_create_audit(State(state): State<ApiState>, Json(req): Json<CreateAuditLogRequest>) -> impl IntoResponse {
    let mut logs = state.audit_logs.write().unwrap();
    let id = format!("{:x}", rand::random::<u64>());
    let now = chrono::Local::now();
    let entry = AuditLogEntry {
        id,
        time: now.format("%H:%M:%S").to_string(),
        event_en: req.event_en,
        event_ru: req.event_ru,
        success: req.success,
    };
    logs.insert(0, entry);
    if logs.len() > 100 {
        logs.truncate(100);
    }

    ApiResponse::success(true)
}

// ── Bulk keys & Router Rules ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BulkCreateRequest {
    pub count: usize,
    pub limit_bytes: Option<u64>,
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

    let mut new_keys = Vec::new();
    let mut keys = match state.access_keys.write() {
        Ok(k) => k,
        Err(e) => e.into_inner(),
    };

    for _ in 0..payload.count {
        let key = uuid::Uuid::new_v4().to_string().replace("-", "")[..16].to_string();
        keys.insert(key.clone(), UserMeta {
            name: None,
            limit_bytes: payload.limit_bytes,
        });
        new_keys.push(key);
    }
    // Save keys by dropping lock, then saving to config
    drop(keys);
    let _ = save_config_keys(&state);

    (StatusCode::OK, ApiResponse::success(new_keys))
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

async fn handle_put_rules(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(new_rules): Json<Vec<OutboundRule>>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) { return api_unauthorized(); }
    
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
        state.dns_server.update_proxy(Some(&cfg)).await;
    }
    
    // Save to config.json
    if let Some(path) = &state.config_path {
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut cfg: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
            if let Some(obj) = cfg.as_object_mut() {
                if let Some(outbound) = obj.get_mut("outbound") {
                    if let Some(outbound_obj) = outbound.as_object_mut() {
                        if let Ok(rules_json) = serde_json::to_value(&new_rules) {
                            outbound_obj.insert("rules".to_string(), rules_json);
                        }
                    }
                }
            }
            let _ = std::fs::write(path, serde_json::to_string_pretty(&cfg).unwrap_or_default());
        }
    }
    
    (StatusCode::OK, ApiResponse::success(true))
}

async fn handle_clear_audit(State(state): State<ApiState>) -> impl IntoResponse {
    let mut logs = state.audit_logs.write().unwrap();
    logs.clear();
    ApiResponse::success(())
}


