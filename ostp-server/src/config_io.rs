//! Reading and writing config.json. The panel API and the CLI both change the
//! same file, so the rules live in one place: comments are allowed on read, a
//! write replaces the file in one step and keeps it private.

use std::path::{Path, PathBuf};

/// Every change to config.json goes through this lock: two requests at once
/// would otherwise each read the old file and the second write would drop the
/// first one's change. It covers one process only; the rename keeps the file
/// whole when the CLI and the server write at the same moment.
pub static CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let written = (|| -> std::io::Result<()> {
        // The file holds the password hash and every key: a new one is private
        // from the first byte (umask would make it 0644), an existing one keeps
        // its mode.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
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
    let _guard = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        assert!(!d.join("config.json.tmp").exists());
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
