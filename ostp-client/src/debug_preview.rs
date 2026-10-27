//! Preview of bytes that did not parse as an ostp frame (a block page or an injected
//! reply from DPI or a transparent proxy), for `bridge.rs` and `prober.rs`.

/// Lossy-UTF8 text plus hex, capped at 300 bytes.
pub fn describe_foreign_bytes(data: &[u8]) -> String {
    const MAX_PREVIEW: usize = 300;
    let shown = &data[..data.len().min(MAX_PREVIEW)];
    let text: String = String::from_utf8_lossy(shown).chars().flat_map(|c| c.escape_default()).collect();
    let hex: String = shown.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
    let truncated = if data.len() > MAX_PREVIEW {
        format!(" (truncated, {} bytes total)", data.len())
    } else {
        String::new()
    };
    format!("text=\"{text}\" hex=[{hex}]{truncated}")
}
