//! TLS termination for the TCP transport, with a certificate that can be
//! replaced on disk (ACME renewal, or an operator swapping files) and picked up
//! without a restart.

use anyhow::{anyhow, Context, Result};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio_rustls::TlsAcceptor;

const WATCH_INTERVAL: Duration = Duration::from_secs(60);

/// The only crypto backend the project uses; always passed explicitly so a
/// second backend appearing in the graph can never make rustls ambiguous.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Serves whatever certificate is currently loaded from `cert_path`/`key_path`.
pub struct HotCertResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    cert_path: PathBuf,
    key_path: PathBuf,
    loaded_mtime: Mutex<Option<(SystemTime, SystemTime)>>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for HotCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotCertResolver").field("cert_path", &self.cert_path).finish()
    }
}

impl ResolvesServerCert for HotCertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl HotCertResolver {
    pub fn new(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(None),
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            loaded_mtime: Mutex::new(None),
            provider: provider(),
        })
    }

    pub fn has_cert(&self) -> bool {
        self.current.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Loads the files; on any error the previously loaded certificate stays in use.
    pub fn reload(&self) -> Result<()> {
        let mtimes = (mtime(&self.cert_path)?, mtime(&self.key_path)?);
        let key = load_certified_key(&self.cert_path, &self.key_path, &self.provider)?;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(key));
        *self.loaded_mtime.lock().unwrap_or_else(|e| e.into_inner()) = Some(mtimes);
        Ok(())
    }

    /// Reloads when either file's mtime differs from what was last loaded.
    pub fn reload_if_changed(&self) -> Result<bool> {
        let now = (mtime(&self.cert_path)?, mtime(&self.key_path)?);
        if *self.loaded_mtime.lock().unwrap_or_else(|e| e.into_inner()) == Some(now) {
            return Ok(false);
        }
        self.reload()?;
        Ok(true)
    }

    pub fn spawn_watch(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(WATCH_INTERVAL).await;
                match this.reload_if_changed() {
                    Ok(true) => tracing::info!("TLS certificate reloaded from {}", this.cert_path.display()),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("TLS certificate not reloaded, keeping the current one: {e:#}"),
                }
            }
        });
    }
}

fn mtime(p: &Path) -> Result<SystemTime> {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .with_context(|| format!("cannot stat {}", p.display()))
}

pub fn load_certified_key(cert_path: &Path, key_path: &Path, provider: &CryptoProvider) -> Result<CertifiedKey> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("cannot read {}", cert_path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("invalid certificate PEM in {}: {e}", cert_path.display()))?;
    if chain.is_empty() {
        return Err(anyhow!("no certificate found in {}", cert_path.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| anyhow!("invalid private key in {}: {e}", key_path.display()))?;
    let signing = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| anyhow!("unsupported private key in {}: {e}", key_path.display()))?;
    let ck = CertifiedKey::new(chain, signing);
    ck.keys_match().map_err(|e| anyhow!("certificate and key do not match: {e}"))?;
    Ok(ck)
}

pub fn build_acceptor(resolver: Arc<HotCertResolver>) -> Result<TlsAcceptor> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Writes a self-signed certificate for `domain`, so TLS (and a web server's
/// config test) works before the real certificate is issued.
pub fn write_placeholder(domain: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
    let ck = rcgen::generate_simple_self_signed(vec![domain.to_string()])?;
    write_pem_pair(cert_path, &ck.cert.pem(), key_path, &ck.signing_key.serialize_pem())
}

/// Writes a certificate/key pair atomically, the key readable by root only.
pub fn write_pem_pair(cert_path: &Path, cert_pem: &str, key_path: &Path, key_pem: &str) -> Result<()> {
    write_atomic(key_path, key_pem.as_bytes(), true)?;
    write_atomic(cert_path, cert_pem.as_bytes(), false)
}

fn write_atomic(path: &Path, data: &[u8], private: bool) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut f = opts.open(&tmp).with_context(|| format!("cannot write {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    /// A CA and a leaf for `name` signed by it: (ca_pem, leaf_cert_pem, leaf_key_pem).
    pub fn ca_and_leaf(name: &str) -> (String, String, String) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        (ca.pem(), leaf.pem(), leaf_key.serialize_pem())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_loads_and_swaps_on_change() {
        let dir = std::env::temp_dir().join(format!("ostp-tls-test-{}", rand::random::<u64>()));
        let (cert, key) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
        write_placeholder("a.example", &cert, &key).unwrap();

        let r = HotCertResolver::new(&cert, &key);
        assert!(!r.has_cert());
        r.reload().unwrap();
        assert!(r.has_cert());
        let first = r.current.read().unwrap().clone().unwrap();
        assert!(!r.reload_if_changed().unwrap(), "unchanged files must not reload");

        std::thread::sleep(Duration::from_millis(1100));
        write_placeholder("b.example", &cert, &key).unwrap();
        assert!(r.reload_if_changed().unwrap());
        let second = r.current.read().unwrap().clone().unwrap();
        assert_ne!(first.cert[0], second.cert[0]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn broken_key_keeps_the_old_certificate() {
        let dir = std::env::temp_dir().join(format!("ostp-tls-test-{}", rand::random::<u64>()));
        let (cert, key) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
        write_placeholder("a.example", &cert, &key).unwrap();
        let r = HotCertResolver::new(&cert, &key);
        r.reload().unwrap();

        std::fs::write(&key, "not a key").unwrap();
        assert!(r.reload().is_err());
        assert!(r.has_cert(), "a failed reload must not drop the working certificate");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mismatched_cert_and_key_are_rejected() {
        let dir = std::env::temp_dir().join(format!("ostp-tls-test-{}", rand::random::<u64>()));
        let (cert, key) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
        write_placeholder("a.example", &cert, &key).unwrap();
        let other = rcgen::KeyPair::generate().unwrap();
        std::fs::write(&key, other.serialize_pem()).unwrap();
        assert!(load_certified_key(&cert, &key, &provider()).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
