//! Let's Encrypt (ACME) issuance and renewal over HTTP-01.
//!
//! Challenge answers live in memory and in `<config_dir>/acme/challenges/`,
//! so a certificate issued by the CLI while the service owns port 80 (or the
//! local responder a web server proxies to) is still answered by the service.

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{Path as AxPath, State};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::http_frontend::RedirectTarget;
use super::{write_atomic, write_pem_pair, CertSource, Frontend, HotCertResolver, TlsSettings};

const ORDER_TIMEOUT: Duration = Duration::from_secs(120);
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
const STALE_LOCK: Duration = Duration::from_secs(15 * 60);
const MAX_SLEEP: Duration = Duration::from_secs(12 * 3600);
const FIRST_BACKOFF: Duration = Duration::from_secs(3600);
const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

pub fn state_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("acme")
}

pub fn directory_url(staging: bool, directory: Option<&str>) -> String {
    match directory {
        Some(d) => d.to_string(),
        None if staging => LetsEncrypt::Staging.url().to_string(),
        None => LetsEncrypt::Production.url().to_string(),
    }
}

// ── Challenge store and responder ────────────────────────────────────────────

pub struct ChallengeStore {
    mem: RwLock<HashMap<String, String>>,
    dir: PathBuf,
}

/// ACME tokens are base64url; anything else could be a path traversal.
fn valid_token(t: &str) -> bool {
    (16..=128).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl ChallengeStore {
    pub fn new(state_dir: &Path) -> Arc<Self> {
        Arc::new(Self { mem: RwLock::new(HashMap::new()), dir: state_dir.join("challenges") })
    }

    pub fn put(&self, token: &str, key_authorization: &str) -> Result<()> {
        if !valid_token(token) {
            bail!("CA sent a malformed challenge token");
        }
        self.mem
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token.to_string(), key_authorization.to_string());
        write_atomic(&self.dir.join(token), key_authorization.as_bytes(), false)
    }

    pub fn remove(&self, token: &str) {
        self.mem.write().unwrap_or_else(|e| e.into_inner()).remove(token);
        if valid_token(token) {
            let _ = std::fs::remove_file(self.dir.join(token));
        }
    }

    pub fn get(&self, token: &str) -> Option<String> {
        if !valid_token(token) {
            return None;
        }
        if let Some(v) = self.mem.read().unwrap_or_else(|e| e.into_inner()).get(token) {
            return Some(v.clone());
        }
        std::fs::read_to_string(self.dir.join(token)).ok().map(|s| s.trim().to_string())
    }
}

#[derive(Clone)]
struct ResponderState {
    store: Arc<ChallengeStore>,
    redirect: Option<RedirectTarget>,
}

/// Serves `/.well-known/acme-challenge/{token}`; everything else is redirected
/// to https (the built-in port 80) or 404 (the local responder).
pub fn challenge_router(store: Arc<ChallengeStore>, redirect: Option<RedirectTarget>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(serve_challenge))
        .fallback(not_a_challenge)
        .with_state(ResponderState { store, redirect })
}

async fn serve_challenge(State(s): State<ResponderState>, AxPath(token): AxPath<String>) -> Response {
    match s.store.get(&token) {
        Some(v) => ([(header::CONTENT_TYPE, "text/plain")], v).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn not_a_challenge(State(s): State<ResponderState>, uri: Uri) -> Response {
    match &s.redirect {
        Some(t) => t.redirect(&uri),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── Certificate inspection and renewal policy ────────────────────────────────

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub not_before: i64,
    pub not_after: i64,
    pub sans: Vec<String>,
    pub issuer: String,
    pub self_signed: bool,
}

impl CertInfo {
    pub fn is_staging(&self) -> bool {
        let i = self.issuer.to_ascii_uppercase();
        i.contains("STAGING") || i.contains("FAKE LE")
    }

    pub fn days_left(&self, now: i64) -> i64 {
        (self.not_after - now) / 86_400
    }
}

pub fn cert_info(path: &Path) -> Result<CertInfo> {
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&data)
        .map_err(|e| anyhow!("{} is not a PEM certificate: {e}", path.display()))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow!("{} is not a valid certificate: {e}", path.display()))?;
    let validity = cert.validity();
    let sans = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(CertInfo {
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
        sans,
        issuer: cert.issuer().to_string(),
        self_signed: cert.issuer().as_raw() == cert.subject().as_raw(),
    })
}

/// Unix time at which the certificate should be renewed (<= now: renew now).
pub fn renew_at(info: Option<&CertInfo>, domain: &str, staging: bool, renew_days_before: Option<u32>) -> i64 {
    let Some(info) = info else { return 0 };
    if info.self_signed || !info.sans.iter().any(|s| s.eq_ignore_ascii_case(domain)) || info.is_staging() != staging {
        return 0;
    }
    match renew_days_before {
        Some(days) => info.not_after - i64::from(days) * 86_400,
        // A third of the lifetime left: 30 days for today's 90-day
        // certificates, and still sensible if the CA shortens them.
        None => info.not_after - (info.not_after - info.not_before) / 3,
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ── Issuance ─────────────────────────────────────────────────────────────────

/// One issuance at a time across the CLI and the service.
pub struct AcmeLock {
    path: PathBuf,
}

impl Drop for AcmeLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn acquire_lock(state_dir: &Path) -> Result<AcmeLock> {
    std::fs::create_dir_all(state_dir).with_context(|| format!("cannot create {}", state_dir.display()))?;
    let path = state_dir.join(".lock");
    for _ in 0..2 {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "{} {}", std::process::id(), unix_now());
                return Ok(AcmeLock { path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let age = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|m| m.elapsed().ok())
                    .unwrap_or_default();
                if age < STALE_LOCK {
                    bail!("another certificate issuance is already running ({})", path.display());
                }
                let _ = std::fs::remove_file(&path);
            }
            Err(e) => return Err(e).with_context(|| format!("cannot create {}", path.display())),
        }
    }
    bail!("cannot take the ACME lock {}", path.display())
}

fn http_client() -> Result<Box<dyn instant_acme::HttpClient>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Test CAs (e.g. Pebble) only.
    if let Ok(extra) = std::env::var("OSTP_ACME_CA_FILE") {
        for cert in CertificateDer::pem_file_iter(&extra).map_err(|e| anyhow!("OSTP_ACME_CA_FILE: {e:?}"))? {
            roots.add(cert.map_err(|e| anyhow!("OSTP_ACME_CA_FILE: {e:?}"))?)?;
        }
    }
    let cfg = rustls::ClientConfig::builder_with_provider(super::provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cfg)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, BodyWrapper<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https);
    Ok(Box::new(client))
}

async fn load_or_create_account(state_dir: &Path, directory_url: &str, email: Option<&str>) -> Result<Account> {
    let id = hex::encode(&Sha256::digest(directory_url.as_bytes())[..8]);
    let path = state_dir.join("accounts").join(format!("{id}.json"));
    if let Ok(data) = std::fs::read(&path) {
        if let Ok(creds) = serde_json::from_slice::<AccountCredentials>(&data) {
            return Ok(Account::builder_with_http(http_client()?).from_credentials(creds).await?);
        }
    }
    let contact: Vec<String> = email.map(|e| vec![format!("mailto:{e}")]).unwrap_or_default();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, creds) = Account::builder_with_http(http_client()?)
        .create(
            &NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false },
            directory_url.to_string(),
            None,
        )
        .await?;
    write_atomic(&path, &serde_json::to_vec(&creds)?, true)?;
    Ok(account)
}

pub struct IssueRequest<'a> {
    pub domain: &'a str,
    pub email: Option<&'a str>,
    pub directory_url: String,
    pub state_dir: &'a Path,
    pub store: &'a ChallengeStore,
    pub cert_path: &'a Path,
    pub key_path: &'a Path,
}

/// Issues a certificate for `domain` and writes it to `cert_path`/`key_path`.
/// The caller holds the lock and makes sure `store` is served on port 80.
pub async fn issue(req: IssueRequest<'_>) -> Result<CertInfo> {
    preflight(req.domain, req.store).await?;
    let account = load_or_create_account(req.state_dir, &req.directory_url, req.email)
        .await
        .context("ACME account")?;
    let mut tokens = Vec::new();
    let result = run_order(&account, &req, &mut tokens).await;
    for t in &tokens {
        req.store.remove(t);
    }
    let (chain, key) = result?;
    write_pem_pair(req.cert_path, &chain, req.key_path, &key)?;
    cert_info(req.cert_path)
}

async fn run_order(account: &Account, req: &IssueRequest<'_>, tokens: &mut Vec<String>) -> Result<(String, String)> {
    let ids = [Identifier::Dns(req.domain.to_string())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await.context("ACME new order")?;
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => bail!("authorization for {} is {other:?}", req.domain),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow!("the CA offered no http-01 challenge"))?;
            req.store.put(&challenge.token, challenge.key_authorization().as_str())?;
            tokens.push(challenge.token.clone());
            challenge.set_ready().await?;
        }
    }
    let retry = RetryPolicy::new().timeout(ORDER_TIMEOUT);
    let status = order.poll_ready(&retry).await.context("waiting for validation")?;
    if !matches!(status, OrderStatus::Ready) {
        bail!(
            "Let's Encrypt could not validate {} (order {status:?}); check that http://{}/.well-known/acme-challenge/ reaches this server",
            req.domain,
            req.domain
        );
    }
    let key = order.finalize().await.context("finalizing the order")?;
    let chain = order.poll_certificate(&retry).await.context("downloading the certificate")?;
    Ok((chain, key))
}

/// Proves that `http://domain/.well-known/acme-challenge/` reaches this
/// store before asking the CA, whose failed validations are rate limited.
pub async fn preflight(domain: &str, store: &ChallengeStore) -> Result<()> {
    let token: String = (0..32)
        .map(|_| {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            A[rand::random::<usize>() % A.len()] as char
        })
        .collect();
    let value = format!("ostp-preflight-{}", hex::encode(rand::random::<[u8; 8]>()));
    store.put(&token, &value)?;
    let res = tokio::time::timeout(
        PREFLIGHT_TIMEOUT,
        http_get(domain, &format!("/.well-known/acme-challenge/{token}")),
    )
    .await;
    store.remove(&token);
    match res {
        Ok(Ok(body)) if body.contains(&value) => Ok(()),
        Ok(Ok(_)) => bail!(
            "http://{domain}/.well-known/acme-challenge/ is answered by something other than OSTP \
             (another web server on port 80, or DNS points elsewhere)"
        ),
        Ok(Err(e)) => bail!("cannot reach http://{domain}/ from this server: {e:#} (DNS record, firewall on port 80?)"),
        Err(_) => bail!("http://{domain}/ did not answer within {}s (firewall on port 80?)", PREFLIGHT_TIMEOUT.as_secs()),
    }
}

async fn http_get(host: &str, path: &str) -> Result<String> {
    let mut s = tokio::net::TcpStream::connect((host, 80)).await?;
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ostp-acme-preflight\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    let mut buf = Vec::new();
    s.take(64 * 1024).read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// ── Service-side renewal ─────────────────────────────────────────────────────

/// Keeps the certificate issued and fresh; spawned by the server when
/// `tls.cert` is "acme" and OSTP (not caddy) owns the certificate.
pub async fn renewal_task(t: TlsSettings, store: Arc<ChallengeStore>, resolver: Option<Arc<HotCertResolver>>) {
    let Some(domain) = t.domain.clone() else { return };
    if t.cert != CertSource::Acme || t.frontend == Frontend::Caddy {
        return;
    }
    let state = state_dir(&t.config_dir);
    let mut backoff = FIRST_BACKOFF;
    // The challenge listeners are bound right after this task is spawned.
    tokio::time::sleep(Duration::from_secs(5)).await;
    loop {
        let info = cert_info(&t.cert_path).ok();
        let at = renew_at(info.as_ref(), &domain, t.acme.staging, t.acme.renew_days_before);
        let now = unix_now();
        if at > now {
            let wait = Duration::from_secs((at - now) as u64).min(MAX_SLEEP) + Duration::from_secs(rand::random::<u64>() % 3600);
            tokio::time::sleep(wait).await;
            continue;
        }

        tracing::info!("Requesting a certificate for {domain} from {}", directory_url(t.acme.staging, t.acme.directory.as_deref()));
        let result = async {
            let _lock = acquire_lock(&state)?;
            issue(IssueRequest {
                domain: &domain,
                email: t.acme.email.as_deref(),
                directory_url: directory_url(t.acme.staging, t.acme.directory.as_deref()),
                state_dir: &state,
                store: &store,
                cert_path: &t.cert_path,
                key_path: &t.key_path,
            })
            .await
        }
        .await;

        match result {
            Ok(new) => {
                backoff = FIRST_BACKOFF;
                if let Some(r) = &resolver {
                    if let Err(e) = r.reload() {
                        tracing::warn!("New certificate written but not loaded: {e:#}");
                    }
                }
                tracing::info!("Certificate for {domain} issued by {}, valid for {} days", new.issuer, new.days_left(unix_now()));
                if let Some(cmd) = &t.reload_command {
                    run_reload_command(cmd).await;
                }
            }
            Err(e) => {
                let left = info.as_ref().filter(|i| !i.self_signed).map(|i| i.days_left(now));
                match left {
                    Some(d) if d < 7 => tracing::error!("Certificate for {domain} expires in {d} days and renewal failed: {e:#}"),
                    _ => tracing::warn!("Certificate for {domain} not issued: {e:#}; retrying in {}h", backoff.as_secs() / 3600),
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

pub async fn run_reload_command(cmd: &str) {
    let mut c = if cfg!(windows) {
        let mut c = tokio::process::Command::new("cmd");
        c.arg("/C").arg(cmd);
        c
    } else {
        let mut c = tokio::process::Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    };
    match tokio::time::timeout(Duration::from_secs(30), c.output()).await {
        Ok(Ok(out)) if out.status.success() => tracing::info!("Ran `{cmd}`"),
        Ok(Ok(out)) => tracing::error!("`{cmd}` failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr).trim()),
        Ok(Err(e)) => tracing::error!("cannot run `{cmd}`: {e}"),
        Err(_) => tracing::error!("`{cmd}` did not finish within 30s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("ostp-acme-test-{}", rand::random::<u64>()))
    }

    fn info(days_total: i64, days_left: i64, san: &str, issuer: &str, self_signed: bool) -> CertInfo {
        let now = unix_now();
        CertInfo {
            not_before: now - (days_total - days_left) * 86_400,
            not_after: now + days_left * 86_400,
            sans: vec![san.into()],
            issuer: issuer.into(),
            self_signed,
        }
    }

    #[test]
    fn tokens_are_validated() {
        assert!(valid_token("abcDEF0123456789_-xyz"));
        assert!(!valid_token("../../etc/passwd"));
        assert!(!valid_token("short"));
        assert!(!valid_token("has/a/slash0123456789"));
    }

    #[test]
    fn store_answers_from_memory_then_disk() {
        let dir = tmp();
        let a = ChallengeStore::new(&dir);
        a.put("tokentokentoken01", "ka-1").unwrap();
        assert_eq!(a.get("tokentokentoken01").as_deref(), Some("ka-1"));
        // Another process (the service) sees what the CLI wrote.
        let b = ChallengeStore::new(&dir);
        assert_eq!(b.get("tokentokentoken01").as_deref(), Some("ka-1"));
        a.remove("tokentokentoken01");
        assert_eq!(b.get("tokentokentoken01"), None);
        assert!(a.put("../escape-attempt-0", "x").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn renewal_policy() {
        let now = unix_now();
        let le = "C=US, O=Let's Encrypt, CN=R11";
        let staging = "C=US, O=(STAGING) Let's Encrypt, CN=(STAGING) Ersatz Edamame E1";
        // Fresh production cert: due when a third of 90 days is left.
        let at = renew_at(Some(&info(90, 80, "a.example", le, false)), "a.example", false, None);
        assert!((at - (now + 50 * 86_400)).abs() < 5);
        assert!(renew_at(Some(&info(90, 20, "a.example", le, false)), "a.example", false, None) <= now);
        // Explicit override.
        assert!(renew_at(Some(&info(90, 80, "a.example", le, false)), "a.example", false, Some(89)) <= now);
        // Placeholder, wrong name, or staging/production mismatch: renew now.
        assert_eq!(renew_at(Some(&info(90, 80, "a.example", "CN=a.example", true)), "a.example", false, None), 0);
        assert_eq!(renew_at(Some(&info(90, 80, "b.example", le, false)), "a.example", false, None), 0);
        assert_eq!(renew_at(Some(&info(90, 80, "a.example", staging, false)), "a.example", false, None), 0);
        assert!(renew_at(Some(&info(90, 80, "a.example", staging, false)), "a.example", true, None) > now);
        assert_eq!(renew_at(None, "a.example", false, None), 0);
    }

    #[test]
    fn placeholder_is_recognised_as_self_signed() {
        let dir = tmp();
        let (c, k) = (dir.join("c.pem"), dir.join("k.pem"));
        super::super::write_placeholder("a.example", &c, &k).unwrap();
        let i = cert_info(&c).unwrap();
        assert!(i.self_signed);
        assert_eq!(i.sans, vec!["a.example".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lock_is_exclusive_and_released() {
        let dir = tmp();
        let l = acquire_lock(&dir).unwrap();
        assert!(acquire_lock(&dir).is_err());
        drop(l);
        assert!(acquire_lock(&dir).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn responder_serves_tokens_and_redirects_the_rest() {
        let dir = tmp();
        let store = ChallengeStore::new(&dir);
        store.put("tokentokentoken01", "ka-1").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = challenge_router(store, Some(RedirectTarget::new("vpn.example.com", 443)));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let get = |path: &'static str| async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut r = String::new();
            s.read_to_string(&mut r).await.unwrap();
            r
        };
        let ok = get("/.well-known/acme-challenge/tokentokentoken01").await;
        assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("ka-1"), "{ok}");
        let missing = get("/.well-known/acme-challenge/unknowntokenxyz01").await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
        let other = get("/x").await;
        assert!(other.starts_with("HTTP/1.1 308") && other.to_lowercase().contains("location: https://vpn.example.com/x"), "{other}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
