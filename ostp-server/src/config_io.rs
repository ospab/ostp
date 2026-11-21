//! Reading and writing config.json. The panel API and the CLI both change the
//! same file, so the rules live in one place: comments are allowed on read, a
//! write replaces the file in one step and keeps it private.

use std::path::{Path, PathBuf};

/// Every change to config.json goes through this lock: two requests at once
/// would otherwise each read the old file and the second write would drop the
/// first one's change. It covers one process; `lock_config` adds a lock file
/// so the CLI and the server exclude each other too.
pub static CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A lock file older than this belongs to a process that died holding it.
const STALE_LOCK: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a writer waits for another one before giving up on the file lock.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

thread_local! {
    /// Whether this thread already holds the config lock: taking it again (a
    /// CLI command locks the whole edit, `save_config` inside it locks too)
    /// must not wait for itself.
    static HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Holds both the in-process lock and the cross-process lock file
/// (`<config>.lock`, created exclusively) until dropped. A thread that already
/// holds the lock gets a guard that does nothing.
pub struct ConfigGuard {
    _process: Option<std::sync::MutexGuard<'static, ()>>,
    lock_file: Option<PathBuf>,
    /// This guard took the thread's hold and gives it back.
    owner: bool,
}

impl Drop for ConfigGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.lock_file {
            let _ = std::fs::remove_file(p);
        }
        if self.owner {
            HELD.with(|h| h.set(false));
        }
    }
}

/// Takes the config lock. If the lock file cannot be created at all (a
/// read-only directory) or stays held past `LOCK_WAIT`, the writer goes ahead
/// on the in-process lock alone: the rename still keeps the file whole.
/// Hold it only for the read-modify-write, never while waiting for a person.
pub fn lock_config(path: &Path) -> ConfigGuard {
    if HELD.with(|h| h.get()) {
        return ConfigGuard { _process: None, lock_file: None, owner: false };
    }
    let process = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    HELD.with(|h| h.set(true));
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut name = real.as_os_str().to_owned();
    name.push(".lock");
    let lock_path = PathBuf::from(name);
    let started = std::time::Instant::now();
    let lock_file = loop {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&lock_path) {
            Ok(mut f) => {
                use std::io::Write;
                let _ = write!(f, "{}", std::process::id());
                break Some(lock_path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&lock_path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > STALE_LOCK);
                if stale {
                    let _ = std::fs::remove_file(&lock_path);
                    continue;
                }
                if started.elapsed() > LOCK_WAIT {
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };
    ConfigGuard { _process: Some(process), lock_file, owner: true }
}

/// Reads config.json, lets `change` edit it and writes it back, all under the
/// lock, so a change the CLI made a moment ago is part of what is edited and
/// not overwritten. A config that cannot be parsed is left untouched.
pub fn edit_config(
    path: &Path,
    backup: bool,
    change: impl FnOnce(&mut serde_json::Value) -> Result<(), String>,
) -> Result<(), String> {
    let _guard = lock_config(path);
    let mut value = parse_config(path)?;
    change(&mut value)?;
    let text = serde_json::to_string_pretty(&value).map_err(|e| format!("failed to serialize config JSON: {e}"))?;
    if backup {
        let _ = std::fs::copy(path, path.with_extension("json.bak"));
    }
    write_config_atomic(path, &text)
}

/// Strips `//` and `/* */` comments, which config.json allows.
pub fn strip_comments(content: &str) -> Result<String, String> {
    use std::io::Read;
    let mut text = String::new();
    json_comments::StripComments::new(content.as_bytes())
        .read_to_string(&mut text)
        .map_err(|e| format!("failed to strip comments from config: {e}"))?;
    Ok(text)
}

pub fn parse_config(path: &Path) -> Result<serde_json::Value, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("failed to read config file: {e}"))?;
    let text = strip_comments(&content)?;
    serde_json::from_str(&text).map_err(|e| format!("failed to parse config JSON: {e}"))
}

/// Replaces the file in one step, so the hot-reloader and a crash see either
/// the old content or the new, never half of it.
pub fn write_config_atomic(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    // Through a symlink the real file is replaced, not the link.
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    // A name of its own per writer: two writers sharing one temporary file
    // could rename a mixture of both over the config.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.{:08x}.tmp", std::process::id(), rand::random::<u32>()));
    let tmp = PathBuf::from(tmp);
    let written = (|| -> std::io::Result<()> {
        // The file holds the password hash and every key: a new one is private
        // from the first byte (umask would make it 0644), an existing one keeps
        // its mode.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        if let Ok(meta) = std::fs::metadata(&path) {
            let _ = std::fs::set_permissions(&tmp, meta.permissions());
        }
        std::fs::rename(&tmp, &path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("failed to write config file: {e}"));
    }
    Ok(())
}

/// Writes `text` under the lock; with `backup`, the previous file is copied to
/// `<name>.json.bak` first (a missing file has nothing to back up).
pub fn save_config(path: &Path, text: &str, backup: bool) -> Result<(), String> {
    let _guard = lock_config(path);
    if backup && path.exists() {
        std::fs::copy(path, path.with_extension("json.bak"))
            .map_err(|e| format!("cannot back up {}: {e}", path.display()))?;
    }
    write_config_atomic(path, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("ostp-config-io-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn write_replaces_whole_file_and_leaves_no_temp() {
        let d = dir();
        let f = d.join("config.json");
        write_config_atomic(&f, "{\"a\":1}").unwrap();
        write_config_atomic(&f, "{\"a\":2}").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "{\"a\":2}");
        let leftovers = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
        assert!(!d.join("config.json.lock").exists(), "no lock is held after a save");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_stale_lock_file_does_not_block_a_writer() {
        let d = dir();
        let f = d.join("config.json");
        std::fs::write(&f, "{}").unwrap();
        // A lock file left by a dead process, older than the stale limit.
        let lock = d.join("config.json.lock");
        std::fs::write(&lock, "1").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
        std::fs::File::options().write(true).open(&lock).unwrap().set_modified(old).unwrap();
        save_config(&f, "{\"a\":1}", false).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "{\"a\":1}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_command_can_lock_the_whole_edit_and_save_inside_it() {
        let d = dir();
        let f = d.join("config.json");
        let outer = lock_config(&f);
        // Would wait for itself without the per-thread hold.
        save_config(&f, "{}", false).unwrap();
        drop(outer);
        assert!(!d.join("config.json.lock").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn backup_keeps_previous_content() {
        let d = dir();
        let f = d.join("config.json");
        save_config(&f, "one", true).unwrap();
        assert!(!f.with_extension("json.bak").exists(), "nothing to back up the first time");
        save_config(&f, "two", true).unwrap();
        assert_eq!(std::fs::read_to_string(f.with_extension("json.bak")).unwrap(), "one");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "two");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn comments_are_allowed_on_read() {
        let d = dir();
        let f = d.join("config.json");
        std::fs::write(&f, "{ // note\n \"a\": 1 }").unwrap();
        assert_eq!(parse_config(&f).unwrap()["a"], 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn new_file_is_private_and_existing_mode_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let f = d.join("config.json");
        write_config_atomic(&f, "x").unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_config_atomic(&f, "y").unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o640);
        let _ = std::fs::remove_dir_all(&d);
    }
}
