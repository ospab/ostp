use anyhow::Result;

#[cfg(unix)]
pub async fn wait_for_shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }

    Ok(())
}

#[cfg(not(unix))]
pub async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
        let mut c_c = ctrl_c()?;
        let mut c_close = ctrl_close()?;
        let mut c_break = ctrl_break()?;

        tokio::select! {
            _ = c_c.recv() => {}
            _ = c_close.recv() => {}
            _ = c_break.recv() => {}
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        tokio::signal::ctrl_c().await?;
    }
    Ok(())
}
