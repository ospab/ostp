//! The servers the app manages, kept in a JSON file. Passwords and private
//! keys in it are sealed with ChaCha20-Poly1305 under a master key that lives
//! in the operating system's credential store (Windows Credential Manager,
//! Secret Service, Keychain, Android Keystore); the store itself only ever
//! holds that one 32-byte key, which fits every platform's size limit.
//! Without a master key nothing secret is written, and the app asks for the
//! password or key when it connects.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{Auth, Target};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    Password,
    Key,
}

/// One server, as saved.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthKind,
    /// SHA-256 fingerprint of the host key seen on the first connection.
    pub host_key: String,
    /// The sealed password or private key; `None` when not remembered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    pub added_at: u64,
}

impl Server {
    pub fn target(&self) -> Target {
        Target { host: self.host.clone(), port: self.port, user: self.user.clone() }
    }

    pub fn remembered(&self) -> bool {
        self.secret.is_some()
    }
}

/// What the app shows about a server: everything but the secrets.
#[derive(Clone, Debug, Serialize)]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthKind,
    pub host_key: String,
    pub remembered: bool,
    pub added_at: u64,
}

impl From<&Server> for ServerInfo {
    fn from(s: &Server) -> Self {
        ServerInfo {
            id: s.id.clone(),
            name: s.name.clone(),
            host: s.host.clone(),
            port: s.port,
            user: s.user.clone(),
            auth: s.auth,
            host_key: s.host_key.clone(),
            remembered: s.remembered(),
            added_at: s.added_at,
        }
    }
}

/// Seals and opens secrets with the master key.
pub struct Vault {
    cipher: Option<ChaCha20Poly1305>,
}

impl Vault {
    /// `None`: no credential store on this system; secrets are not kept.
    pub fn new(master_key: Option<[u8; 32]>) -> Self {
        Vault { cipher: master_key.map(|k| ChaCha20Poly1305::new(Key::from_slice(&k))) }
    }

    pub fn can_remember(&self) -> bool {
        self.cipher.is_some()
    }

    pub fn random_key() -> [u8; 32] {
        rand::random()
    }

    /// The master key as the platform credential store keeps it: 64 hex digits.
    pub fn key_from_hex(hex: &str) -> Option<[u8; 32]> {
        let hex = hex.trim();
        if hex.len() != 64 || !hex.is_ascii() {
            return None;
        }
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(key)
    }

    pub fn key_to_hex(key: &[u8; 32]) -> String {
        key.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn seal(&self, plain: &str) -> Option<String> {
        let cipher = self.cipher.as_ref()?;
        let nonce: [u8; 12] = rand::random();
        let sealed = cipher.encrypt(Nonce::from_slice(&nonce), plain.as_bytes()).ok()?;
        let mut out = nonce.to_vec();
        out.extend(sealed);
        Some(base64::engine::general_purpose::STANDARD.encode(out))
    }

    fn open(&self, sealed: &str) -> Result<String> {
        let cipher = self.cipher.as_ref().ok_or_else(|| anyhow!("the credential store is not available"))?;
        let raw = base64::engine::general_purpose::STANDARD.decode(sealed)?;
        if raw.len() < 12 {
            bail!("a saved secret is damaged");
        }
        let plain = cipher
            .decrypt(Nonce::from_slice(&raw[..12]), &raw[12..])
            .map_err(|_| anyhow!("a saved secret cannot be opened (the credential store's key changed?)"))?;
        Ok(String::from_utf8(plain)?)
    }
}

/// Created private from the first byte, flushed to disk, then renamed over the
/// target so a crash leaves either the old file or the new one.
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    // A leftover temp file keeps its old mode; start from a fresh one.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp)?;
    std::io::Write::write_all(&mut f, body)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// The saved servers.
pub struct Store {
    path: PathBuf,
    servers: Vec<Server>,
}

impl Store {
    pub fn load(path: &Path) -> Result<Store> {
        let servers = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("cannot parse {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        Ok(Store { path: path.to_path_buf(), servers })
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_private(&self.path, &serde_json::to_vec_pretty(&self.servers)?)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<ServerInfo> {
        self.servers.iter().map(ServerInfo::from).collect()
    }

    pub fn get(&self, id: &str) -> Result<&Server> {
        self.servers.iter().find(|s| s.id == id).ok_or_else(|| anyhow!("no such server"))
    }

    /// Adds a server that was just connected to (`host_key` from that
    /// connection). The secret is kept only when `remember` and the vault can.
    pub fn add(&mut self, vault: &Vault, name: &str, target: &Target, auth: &Auth, host_key: &str, remember: bool) -> Result<ServerInfo> {
        let (kind, secret, passphrase) = match auth {
            Auth::Password(p) => (AuthKind::Password, p.as_str(), None),
            Auth::Key { text, passphrase } => (AuthKind::Key, text.as_str(), passphrase.as_deref()),
        };
        let keep = remember && vault.can_remember();

        // The same login on the same machine is one server: adding it again
        // (a retried install, the first-run screen after "Add server") updates
        // the saved sign-in instead of listing it twice. A different host key
        // is not quietly accepted: either the server was reinstalled or
        // someone is in the middle, and the user has to decide which.
        if let Some(existing) = self
            .servers
            .iter_mut()
            .find(|s| s.host.eq_ignore_ascii_case(&target.host) && s.port == target.port && s.user == target.user)
        {
            if existing.host_key != host_key {
                bail!(
                    "{}@{}:{} is already in the list with a different host key. If the server was reinstalled, \
                     forget it in the list and add it again",
                    target.user,
                    target.host,
                    target.port
                );
            }
            existing.auth = kind;
            existing.secret = if keep { vault.seal(secret) } else { None };
            existing.passphrase = if keep { passphrase.filter(|p| !p.is_empty()).and_then(|p| vault.seal(p)) } else { None };
            let info = ServerInfo::from(&*existing);
            self.save()?;
            return Ok(info);
        }

        let server = Server {
            id: format!("{:016x}", rand::random::<u64>()),
            name: if name.trim().is_empty() { target.host.clone() } else { name.trim().to_string() },
            host: target.host.clone(),
            port: target.port,
            user: target.user.clone(),
            auth: kind,
            host_key: host_key.to_string(),
            secret: if keep { vault.seal(secret) } else { None },
            passphrase: if keep { passphrase.filter(|p| !p.is_empty()).and_then(|p| vault.seal(p)) } else { None },
            added_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        };
        let info = ServerInfo::from(&server);
        self.servers.push(server);
        self.save()?;
        Ok(info)
    }

    pub fn rename(&mut self, id: &str, name: &str) -> Result<()> {
        let s = self.servers.iter_mut().find(|s| s.id == id).ok_or_else(|| anyhow!("no such server"))?;
        s.name = name.trim().to_string();
        self.save()
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        let before = self.servers.len();
        self.servers.retain(|s| s.id != id);
        if self.servers.len() == before {
            bail!("no such server");
        }
        self.save()
    }

    /// How to sign in to a saved server: the remembered secret, or the one
    /// the app just asked for.
    pub fn auth(&self, vault: &Vault, id: &str, given: Option<Auth>) -> Result<Auth> {
        if let Some(auth) = given {
            return Ok(auth);
        }
        let s = self.get(id)?;
        let secret = s.secret.as_deref().ok_or_else(|| anyhow!("SECRET_NEEDED"))?;
        let secret = vault.open(secret)?;
        Ok(match s.auth {
            AuthKind::Password => Auth::Password(secret),
            AuthKind::Key => Auth::Key { text: secret, passphrase: s.passphrase.as_deref().map(|p| vault.open(p)).transpose()? },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("ostp-servers-{}-{}.json", std::process::id(), rand::random::<u32>()))
    }

    fn target() -> Target {
        Target { host: "203.0.113.5".into(), port: 22, user: "root".into() }
    }

    #[test]
    fn secrets_are_sealed_on_disk_and_open_again() {
        let path = temp_path();
        let vault = Vault::new(Some(Vault::random_key()));
        let mut store = Store::load(&path).unwrap();
        let key = Auth::Key { text: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n".into(), passphrase: Some("pp".into()) };
        let info = store.add(&vault, "", &target(), &key, "SHA256:x", true).unwrap();
        assert!(info.remembered);
        assert_eq!(info.name, "203.0.113.5");

        let disk = std::fs::read_to_string(&path).unwrap();
        assert!(!disk.contains("OPENSSH") && !disk.contains("\"pp\""), "{disk}");

        let store = Store::load(&path).unwrap();
        match store.auth(&vault, &info.id, None).unwrap() {
            Auth::Key { text, passphrase } => {
                assert!(text.contains("OPENSSH"));
                assert_eq!(passphrase.as_deref(), Some("pp"));
            }
            _ => panic!("wrong kind"),
        }
        // Another master key cannot open it.
        assert!(store.auth(&Vault::new(Some(Vault::random_key())), &info.id, None).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn without_a_credential_store_nothing_secret_is_kept() {
        let path = temp_path();
        let vault = Vault::new(None);
        let mut store = Store::load(&path).unwrap();
        let info = store.add(&vault, "vps", &target(), &Auth::Password("hunter22".into()), "SHA256:x", true).unwrap();
        assert!(!info.remembered);
        assert!(!std::fs::read_to_string(&path).unwrap().contains("hunter22"));
        let err = store.auth(&vault, &info.id, None).unwrap_err();
        assert_eq!(err.to_string(), "SECRET_NEEDED");
        assert!(matches!(store.auth(&vault, &info.id, Some(Auth::Password("p".into()))).unwrap(), Auth::Password(_)));

        store.rename(&info.id, "Amsterdam").unwrap();
        assert_eq!(Store::load(&path).unwrap().list()[0].name, "Amsterdam");
        store.remove(&info.id).unwrap();
        assert!(Store::load(&path).unwrap().list().is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn adding_the_same_login_again_keeps_one_entry() {
        let path = temp_path();
        let vault = Vault::new(Some(Vault::random_key()));
        let mut store = Store::load(&path).unwrap();
        let first = store.add(&vault, "vps", &target(), &Auth::Password("old".into()), "SHA256:x", true).unwrap();
        let upper = Target { host: "203.0.113.5".to_uppercase(), ..target() };
        let again = store.add(&vault, "", &upper, &Auth::Password("new".into()), "SHA256:x", true).unwrap();
        assert_eq!(first.id, again.id);
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].name, "vps");
        assert!(matches!(store.auth(&vault, &first.id, None).unwrap(), Auth::Password(p) if p == "new"));

        // Another login on the same machine is another entry.
        let admin = Target { user: "admin".into(), ..target() };
        store.add(&vault, "", &admin, &Auth::Password("p".into()), "SHA256:x", true).unwrap();
        assert_eq!(store.list().len(), 2);

        // A changed host key is refused, not silently accepted.
        let err = store.add(&vault, "", &target(), &Auth::Password("p".into()), "SHA256:other", true).unwrap_err();
        assert!(err.to_string().contains("different host key"), "{err}");
        assert_eq!(store.list().len(), 2);
        std::fs::remove_file(path).unwrap();
    }
}
