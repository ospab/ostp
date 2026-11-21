//! The SSH client the desktop app uses to install OSTP on a server and manage
//! it: connect with a password or a private key, check the server's host key,
//! run commands as root, and forward a local port to the server's web panel.

pub mod manager;
pub mod store;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Where to connect and as whom.
#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
}

/// How to sign in.
#[derive(Clone)]
pub enum Auth {
    Password(String),
    /// A private key in OpenSSH, PEM or PuTTY format, with its passphrase.
    Key { text: String, passphrase: Option<String> },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Auth::Password(_) => "Auth::Password(..)",
            Auth::Key { .. } => "Auth::Key(..)",
        })
    }
}

/// The server presented a different host key than the one remembered.
#[derive(Debug)]
pub struct HostKeyChanged {
    pub expected: String,
    pub presented: String,
}

impl std::fmt::Display for HostKeyChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the server's host key changed (was {}, now {}). Someone may be intercepting the connection; \
             if the server was reinstalled, remove it from the app and add it again",
            self.expected, self.presented
        )
    }
}

impl std::error::Error for HostKeyChanged {}

/// The result of a command.
#[derive(Debug, Default)]
pub struct Output {
    pub status: u32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    /// The last line of stdout that parses as a JSON object: what
    /// `ostp manage` prints after anything an installer wrote before it.
    pub fn last_json_line(&self) -> Option<&str> {
        self.stdout.lines().rev().map(str::trim).find(|l| l.starts_with('{') && l.ends_with('}'))
    }
}

struct Checker {
    known: Option<String>,
    presented: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Checker {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fingerprint = match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256).to_string(),
            russh::keys::PublicKeyOrCertificate::Certificate(c) => c.public_key().fingerprint(HashAlg::Sha256).to_string(),
        };
        *self.presented.lock().unwrap() = Some(fingerprint.clone());
        match &self.known {
            Some(expected) if *expected != fingerprint => {
                Err(HostKeyChanged { expected: expected.clone(), presented: fingerprint }.into())
            }
            _ => Ok(true),
        }
    }
}

/// An authenticated connection.
pub struct Session {
    handle: Handle<Checker>,
    user: String,
    password: Option<String>,
    fingerprint: String,
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

impl Session {
    /// Connects and signs in. `known_host_key` is the fingerprint remembered
    /// from an earlier connection: a different key is refused. With `None`
    /// the key is accepted and returned by [`Session::host_key`], to be
    /// remembered.
    pub async fn connect(target: &Target, auth: &Auth, known_host_key: Option<&str>) -> Result<Session> {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(600)),
            keepalive_interval: Some(Duration::from_secs(15)),
            ..Default::default()
        });
        let presented = Arc::new(Mutex::new(None));
        let checker = Checker { known: known_host_key.map(str::to_string), presented: presented.clone() };
        let addr = (target.host.trim_matches(['[', ']']), target.port);
        let mut handle = tokio::time::timeout(CONNECT_TIMEOUT, client::connect(config, addr, checker))
            .await
            .map_err(|_| anyhow!("{}:{} did not answer within {}s", target.host, target.port, CONNECT_TIMEOUT.as_secs()))?
            .with_context(|| format!("cannot connect to {}:{}", target.host, target.port))?;
        let fingerprint = presented.lock().unwrap().clone().ok_or_else(|| anyhow!("the server sent no host key"))?;

        let ok = match auth {
            Auth::Password(password) => handle.authenticate_password(&target.user, password).await?.success(),
            Auth::Key { text, passphrase } => {
                let key = russh::keys::decode_secret_key(text.trim(), passphrase.as_deref().filter(|p| !p.is_empty()))
                    .map_err(|e| match e {
                        russh::keys::Error::KeyIsEncrypted => anyhow!("the private key is protected by a passphrase; enter it"),
                        other => anyhow!("cannot read the private key: {other}"),
                    })?;
                let hash = handle.best_supported_rsa_hash().await?.flatten();
                handle
                    .authenticate_publickey(&target.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                    .await?
                    .success()
            }
        };
        if !ok {
            bail!("the server did not accept the {} for {}", match auth {
                Auth::Password(_) => "password",
                Auth::Key { .. } => "key",
            }, target.user);
        }
        let password = match auth {
            Auth::Password(p) => Some(p.clone()),
            Auth::Key { .. } => None,
        };
        Ok(Session { handle, user: target.user.clone(), password, fingerprint })
    }

    /// SHA-256 fingerprint of the server's host key, `SHA256:...`.
    pub fn host_key(&self) -> &str {
        &self.fingerprint
    }

    /// Runs `command` through the user's shell.
    pub async fn run(&self, command: &str) -> Result<Output> {
        self.run_with(command, None, |_| {}).await
    }

    /// Runs `command` as root: directly when signed in as root, otherwise
    /// through sudo (with the sign-in password when there is one).
    pub async fn run_root(&self, command: &str) -> Result<Output> {
        self.run_root_with(command, |_| {}).await
    }

    /// [`Session::run_root`], calling `on_line` with each line of output
    /// (stdout and stderr) as it arrives.
    pub async fn run_root_with(&self, command: &str, on_line: impl FnMut(&str)) -> Result<Output> {
        let (wrapped, stdin) = privileged(&self.user, self.password.as_deref(), command);
        self.finish_root(self.run_with(&wrapped, stdin.as_deref(), on_line).await?)
    }

    /// [`Session::run_root_with`] with `input` on the command's stdin; for a
    /// secret that must not be in a command line (see `privileged_with_input`).
    pub async fn run_root_with_input(&self, command: &str, input: &str, on_line: impl FnMut(&str)) -> Result<Output> {
        let (wrapped, stdin) = privileged_with_input(&self.user, self.password.as_deref(), command, input);
        self.finish_root(self.run_with(&wrapped, Some(&stdin), on_line).await?)
    }

    fn finish_root(&self, out: Output) -> Result<Output> {
        if out.status != 0 && self.user != "root" && sudo_refused(&out.stderr) {
            bail!(
                "{} cannot run commands as root: {}",
                self.user,
                out.stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("sudo refused")
            );
        }
        Ok(out)
    }

    async fn run_with(&self, command: &str, stdin: Option<&[u8]>, mut on_line: impl FnMut(&str)) -> Result<Output> {
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, command).await?;
        if let Some(input) = stdin {
            channel.data_bytes(input.to_vec()).await?;
        }
        channel.eof().await?;

        let mut out = Output::default();
        let (mut pending_out, mut pending_err) = (Vec::new(), Vec::new());
        let mut status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => emit_lines(&mut pending_out, &data, &mut out.stdout, &mut on_line),
                ChannelMsg::ExtendedData { data, .. } => emit_lines(&mut pending_err, &data, &mut out.stderr, &mut on_line),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    out.stderr.push_str(&format!("killed by signal {signal_name:?}\n"));
                    status = Some(128);
                }
                _ => {}
            }
        }
        flush_line(&mut pending_out, &mut out.stdout, &mut on_line);
        flush_line(&mut pending_err, &mut out.stderr, &mut on_line);
        out.stdout.truncate(out.stdout.trim_end_matches('\n').len());
        out.stderr.truncate(out.stderr.trim_end_matches('\n').len());
        out.status = status.unwrap_or(255);
        Ok(out)
    }

    /// Listens on 127.0.0.1 on a free port and forwards every connection to
    /// `remote_port` on the server's loopback. Returns the local port; the
    /// forwarding lasts as long as the session.
    pub async fn forward_local(self: &Arc<Self>, remote_port: u16) -> Result<u16> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let session = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Ok((mut local, peer)) = listener.accept().await {
                let Some(session) = session.upgrade() else { break };
                tokio::spawn(async move {
                    let channel = match session
                        .handle
                        .channel_open_direct_tcpip("127.0.0.1", remote_port.into(), peer.ip().to_string(), peer.port().into())
                        .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("SSH forward to port {remote_port} failed: {e}");
                            return;
                        }
                    };
                    let mut remote = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
                });
            }
        });
        Ok(port)
    }

    pub async fn close(&self) {
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

fn emit_lines(pending: &mut Vec<u8>, data: &[u8], all: &mut String, on_line: &mut impl FnMut(&str)) {
    pending.extend_from_slice(data);
    while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = pending.drain(..=pos).collect();
        let text = String::from_utf8_lossy(&line[..line.len() - 1]);
        let text = text.trim_end_matches('\r');
        on_line(text);
        all.push_str(text);
        all.push('\n');
    }
}

/// Output that did not end with a newline.
fn flush_line(pending: &mut Vec<u8>, all: &mut String, on_line: &mut impl FnMut(&str)) {
    if !pending.is_empty() {
        pending.push(b'\n');
        emit_lines(pending, &[], all, on_line);
    }
}

/// Quotes `s` for a POSIX shell.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Runs `command` as root with `input` on its stdin, without either secret
/// (the sudo password, the input) in any command line: the exec'd command is
/// a bare `sh`, and a script on its stdin gives each secret to its command as
/// a here-document. With a sudo password the script first asks `sudo -n`
/// whether one is needed at all, so a passwordless sudo does not hand the
/// password to the command as the first line of its input.
fn privileged_with_input(user: &str, password: Option<&str>, command: &str, input: &str) -> (String, Vec<u8>) {
    let tag = format!("OSTP_EOF_{:032x}", rand::random::<u128>());
    let inner = format!("sh -c {}", shell_quote(command));
    let doc = |body: &str| format!("<<'{tag}'\n{body}{}{tag}\n", if body.is_empty() || body.ends_with('\n') { "" } else { "\n" });
    let script = if user == "root" {
        format!("{inner} {}", doc(input))
    } else {
        match password {
            Some(p) => format!(
                "if sudo -n true </dev/null 2>/dev/null; then\nsudo -n {inner} {}\nelse\nsudo -S -p '' {inner} {}\nfi\n",
                doc(input),
                doc(&format!("{p}\n{input}"))
            ),
            None => format!("sudo -n {inner} {}", doc(input)),
        }
    };
    ("sh".to_string(), script.into_bytes())
}

/// The command line and stdin that run `command` as root for `user`.
/// sudo reads the password from stdin (`-S`) with an empty prompt, so it
/// never shows up in the output or on the server's process list.
fn privileged(user: &str, password: Option<&str>, command: &str) -> (String, Option<Vec<u8>>) {
    let inner = format!("sh -c {}", shell_quote(command));
    if user == "root" {
        return (inner, None);
    }
    match password {
        Some(p) => (format!("sudo -S -p '' {inner}"), Some(format!("{p}\n").into_bytes())),
        None => (format!("sudo -n {inner}"), None),
    }
}

fn sudo_refused(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("is not in the sudoers")
        || s.contains("a password is required")
        || s.contains("incorrect password")
        || s.contains("sudo: command not found")
        || s.contains("not allowed to execute")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_survives_the_shell() {
        let s = "it's $HOME `x` \"q\"";
        let out = std::process::Command::new("sh").arg("-c").arg(format!("printf %s {}", shell_quote(s))).output().unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), s);
    }

    #[test]
    fn privileged_commands() {
        assert_eq!(privileged("root", Some("pw"), "id -u"), ("sh -c 'id -u'".into(), None));
        let (cmd, stdin) = privileged("admin", Some("pw"), "id -u");
        assert_eq!(cmd, "sudo -S -p '' sh -c 'id -u'");
        assert_eq!(stdin.unwrap(), b"pw\n");
        assert_eq!(privileged("admin", None, "id -u").0, "sudo -n sh -c 'id -u'");
    }

    #[test]
    fn a_secret_input_reaches_the_command_and_is_in_no_command_line() {
        use std::io::Write;
        let (cmd, stdin) = privileged_with_input("root", None, "cat", "s3cret value\n");
        assert_eq!(cmd, "sh");
        let mut child = std::process::Command::new("sh")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&stdin).unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "s3cret value\n");
        let (cmd, stdin) = privileged_with_input("admin", Some("pw"), "cat", "x");
        assert!(!cmd.contains("pw") && !cmd.contains('x'));
        let script = String::from_utf8(stdin).unwrap();
        assert!(script.contains("sudo -n true") && script.contains("sudo -S -p ''"));
    }

    #[test]
    fn lines_are_split_across_chunks() {
        let mut pending = Vec::new();
        let mut all = String::new();
        let mut seen = Vec::new();
        emit_lines(&mut pending, b"a\nb", &mut all, &mut |l| seen.push(l.to_string()));
        emit_lines(&mut pending, b"c\r\n", &mut all, &mut |l| seen.push(l.to_string()));
        emit_lines(&mut pending, b"\nlast", &mut all, &mut |l| seen.push(l.to_string()));
        flush_line(&mut pending, &mut all, &mut |l| seen.push(l.to_string()));
        flush_line(&mut pending, &mut all, &mut |l| seen.push(l.to_string()));
        assert_eq!(seen, vec!["a", "bc", "", "last"]);
        assert_eq!(all, "a\nbc\n\nlast\n");
    }

    #[test]
    fn the_last_json_line_is_found() {
        let out = Output { stdout: "Downloading...\n{\"a\":1}\nDone\n".into(), ..Default::default() };
        assert_eq!(out.last_json_line(), Some("{\"a\":1}"));
    }
}
