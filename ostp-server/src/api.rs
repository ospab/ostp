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
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::dispatcher::{UserStats, UserStatsSnapshot};

// ── Shared state for API handlers ────────────────────────────────────────────

/// API server shared state. Held behind Arc for axum handlers.
#[derive(Clone)]
pub struct ApiState {
    pub access_keys: Arc<RwLock<HashMap<String, ()>>>,
    pub user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    pub start_time: Instant,
    pub api_token: String,
    /// Server address for subscription links (e.g. "example.com")
    pub server_host: String,
    /// Server listen port
    pub server_port: u16,
}

// ── API configuration ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: String,
    pub token: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9090".to_string(),
            token: String::new(),
        }
    }
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
    pub limit_bytes: Option<u64>,
}

#[derive(Deserialize)]
pub struct SetLimitRequest {
    pub limit_bytes: Option<u64>,
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

// ── API router ───────────────────────────────────────────────────────────────

pub fn create_api_router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/server/status", get(handle_status))
        .route("/api/users", get(handle_list_users))
        .route("/api/users", post(handle_create_user))
        .route("/api/users/{key}", get(handle_get_user))
        .route("/api/users/{key}", delete(handle_delete_user))
        .route("/api/users/{key}/limit", put(handle_set_limit))
        .route("/api/users/{key}/reset", post(handle_reset_stats))
        .route("/api/subscribe/{key}", get(handle_subscribe))
        .layer(cors)
        .with_state(state)
}

/// Start the Management API server on the configured bind address.
pub async fn start_api_server(
    config: ApiConfig,
    access_keys: Arc<RwLock<HashMap<String, ()>>>,
    user_stats: Arc<RwLock<HashMap<String, Arc<UserStats>>>>,
    server_host: String,
    server_port: u16,
) {
    let state = ApiState {
        access_keys,
        user_stats,
        start_time: Instant::now(),
        api_token: config.token.clone(),
        server_host,
        server_port,
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
    if state.api_token.is_empty() {
        return true; // No auth required if token is empty
    }
    match headers.get("authorization") {
        Some(value) => {
            let val = value.to_str().unwrap_or("");
            val == format!("Bearer {}", state.api_token) || val == state.api_token
        }
        None => false,
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_status(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<ServerStatus>();
    }

    let keys = state.access_keys.read().unwrap();
    let stats = state.user_stats.read().unwrap();
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

    let keys = state.access_keys.read().unwrap();
    let stats = state.user_stats.read().unwrap();

    let mut users: Vec<UserStatsSnapshot> = keys.keys().map(|key| {
        if let Some(us) = stats.get(key) {
            UserStatsSnapshot {
                access_key: key.clone(),
                bytes_up: us.bytes_up.load(Ordering::Relaxed),
                bytes_down: us.bytes_down.load(Ordering::Relaxed),
                connections: us.connections.load(Ordering::Relaxed),
                limit_bytes: us.limit_bytes,
                online: true, // Simplified; real check requires session map
            }
        } else {
            UserStatsSnapshot {
                access_key: key.clone(),
                bytes_up: 0,
                bytes_down: 0,
                connections: 0,
                limit_bytes: None,
                online: false,
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

    let keys = state.access_keys.read().unwrap();
    if !keys.contains_key(&key) {
        return api_error("user not found");
    }

    let stats = state.user_stats.read().unwrap();
    let snapshot = if let Some(us) = stats.get(&key) {
        UserStatsSnapshot {
            access_key: key.clone(),
            bytes_up: us.bytes_up.load(Ordering::Relaxed),
            bytes_down: us.bytes_down.load(Ordering::Relaxed),
            connections: us.connections.load(Ordering::Relaxed),
            limit_bytes: us.limit_bytes,
            online: true,
        }
    } else {
        UserStatsSnapshot {
            access_key: key.clone(),
            bytes_up: 0,
            bytes_down: 0,
            connections: 0,
            limit_bytes: None,
            online: false,
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
        let mut keys = state.access_keys.write().unwrap();
        keys.insert(key.clone(), ());
    }

    if let Some(limit) = body.limit_bytes {
        let mut stats = state.user_stats.write().unwrap();
        stats.insert(key.clone(), Arc::new(UserStats::new(Some(limit))));
    }

    tracing::info!("API: created user key {}", &key[..8.min(key.len())]);
    (StatusCode::OK, ApiResponse::success(key))
}

async fn handle_delete_user(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_token(&state, &headers) {
        return api_unauthorized::<bool>();
    }

    let removed = {
        let mut keys = state.access_keys.write().unwrap();
        keys.remove(&key).is_some()
    };

    if removed {
        let mut stats = state.user_stats.write().unwrap();
        stats.remove(&key);
        tracing::info!("API: deleted user key {}", &key[..8.min(key.len())]);
    }

    (StatusCode::OK, ApiResponse::success(removed))
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

    let keys = state.access_keys.read().unwrap();
    if !keys.contains_key(&key) {
        return api_error("user not found");
    }
    drop(keys);

    let mut stats = state.user_stats.write().unwrap();
    let entry = stats.entry(key.clone())
        .or_insert_with(|| Arc::new(UserStats::new(body.limit_bytes)));

    *entry = Arc::new(UserStats {
        bytes_up: AtomicU64::new(entry.bytes_up.load(Ordering::Relaxed)),
        bytes_down: AtomicU64::new(entry.bytes_down.load(Ordering::Relaxed)),
        connections: AtomicU64::new(entry.connections.load(Ordering::Relaxed)),
        limit_bytes: body.limit_bytes,
        created_at: entry.created_at,
    });

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

    let mut stats = state.user_stats.write().unwrap();
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
) -> impl IntoResponse {
    // Validate that the key exists
    let keys = state.access_keys.read().unwrap();
    if !keys.contains_key(&key) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "ok": false,
            "error": "invalid access key"
        })));
    }
    drop(keys);

    let accept = headers.get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    // If client requests plain text, return ostp:// share link
    if accept.contains("text/plain") {
        let link = format!("ostp://{}@{}:{}", key, state.server_host, state.server_port);
        return (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "data": link
        })));
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
    })))
}
