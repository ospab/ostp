//! A stand-in for Cloudflare's registration service, for tests: a local HTTP
//! server that answers the three calls `api.rs` makes in the shape `wgcf`'s
//! OpenAPI spec lists, and records what it was sent. Nothing here talks to
//! Cloudflare.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub user_agent: Option<String>,
    pub body: String,
}

pub struct FakeApi {
    pub base: String,
    pub requests: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
pub struct FakeApiConfig {
    /// Base64 public key of the WireGuard peer the answers name.
    pub peer_public_b64: String,
    /// `host:port` the answers give as the peer's endpoint.
    pub endpoint_host: String,
    /// Base64 `client_id`.
    pub client_id: String,
    /// A license the service refuses (HTTP 400); everything else is accepted.
    pub refuse_license: Option<String>,
}

impl FakeApi {
    pub async fn start(cfg: FakeApiConfig) -> std::io::Result<Self> {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = l.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let plus = Arc::new(AtomicBool::new(false));
        let reqs = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let (cfg, reqs, plus) = (cfg.clone(), reqs.clone(), plus.clone());
                tokio::spawn(async move {
                    let Some(rec) = read_request(&mut s).await else { return };
                    let (status, body) = answer(&cfg, &plus, &rec);
                    reqs.lock().unwrap().push(rec);
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        Ok(Self { base: format!("http://{addr}"), requests, task })
    }
}

async fn read_request(s: &mut tokio::net::TcpStream) -> Option<Recorded> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let header = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    };
    let len: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    while raw.len() < head_end + 4 + len {
        let n = s.read(&mut buf).await.ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8_lossy(&raw[head_end + 4..]).to_string();
    Some(Recorded { method, path, authorization: header("authorization"), user_agent: header("user-agent"), body })
}

fn device_json(cfg: &FakeApiConfig, id: &str, with_token: bool, account_type: &str) -> String {
    let token = if with_token { r#""token":"tok-from-the-fake","# } else { "" };
    format!(
        r#"{{"id":"{id}",{token}"account":{{"id":"acc-1","account_type":"{account_type}","license":"account-own-key"}},"config":{{"client_id":"{}","peers":[{{"public_key":"{}","endpoint":{{"host":"{}","v4":"127.0.0.1:0","v6":"[::1]:0"}}}}],"interface":{{"addresses":{{"v4":"172.16.0.2","v6":"2606:4700:110:8000::2"}}}},"services":{{"http_proxy":"172.16.0.1:2480"}}}}}}"#,
        cfg.client_id, cfg.peer_public_b64, cfg.endpoint_host
    )
}

fn answer(cfg: &FakeApiConfig, plus: &AtomicBool, r: &Recorded) -> (&'static str, String) {
    let path = r.path.split('?').next().unwrap_or("");
    let v = crate::api::API_VERSION;
    if r.method == "POST" && path == format!("/{v}/reg") {
        return ("200 OK", device_json(cfg, "dev-fake-1", true, "free"));
    }
    if let Some(rest) = path.strip_prefix(&format!("/{v}/reg/")) {
        if r.method == "GET" && !rest.contains('/') {
            let t = if plus.load(Ordering::SeqCst) { "limited" } else { "free" };
            return ("200 OK", device_json(cfg, rest, false, t));
        }
        if r.method == "PUT" && rest.ends_with("/account") {
            let lic = serde_json::from_str::<serde_json::Value>(&r.body).ok().and_then(|b| b["license"].as_str().map(String::from));
            if lic.is_some() && lic == cfg.refuse_license {
                return ("400 Bad Request", r#"{"success":false,"errors":[{"code":1,"message":"Invalid license"}]}"#.into());
            }
            plus.store(true, Ordering::SeqCst);
            return ("200 OK", r#"{"id":"acc-1","account_type":"limited","warp_plus":true}"#.into());
        }
    }
    ("404 Not Found", r#"{"success":false}"#.into())
}
