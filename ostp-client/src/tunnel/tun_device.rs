use std::sync::Arc;
use anyhow::{anyhow, Result};
use tokio::sync::mpsc;
use tracing::{info, error, debug};

pub struct TunDevice {
    pub packet_rx: mpsc::Receiver<Vec<u8>>,
    pub packet_tx: mpsc::Sender<Vec<u8>>,
    _shutdown_tx: mpsc::Sender<()>,
}

#[cfg(target_os = "windows")]
pub fn create_tun_device(tun_name: &str, mtu: usize) -> Result<TunDevice> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow!("failed to get binary directory"))?;
    let wintun_dll = dir.join("wintun.dll");

    if !wintun_dll.exists() {
        return Err(anyhow!(
            "CRITICAL: 'wintun.dll' is missing at {}!\n\
             Please make sure wintun.dll is present in the binary directory.",
            dir.display()
        ));
    }

    info!("Loading wintun.dll from: {:?}", wintun_dll);
    let wintun = unsafe { wintun::load_from_path(wintun_dll)? };
    
    // Open or create adapter
    let adapter = match wintun::Adapter::open(&wintun, tun_name) {
        Ok(a) => a,
        Err(_) => {
            info!("TUN adapter '{}' not found, creating a new one...", tun_name);
            wintun::Adapter::create(&wintun, "Wintun", tun_name, None)?
        }
    };

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    
    let (packet_tx_in, packet_rx) = mpsc::channel::<Vec<u8>>(100000);
    let (packet_tx, mut packet_rx_out) = mpsc::channel::<Vec<u8>>(100000);
    let (shutdown_tx, _shutdown_rx) = mpsc::channel::<()>(1);

    // Spawning blocking read loop in a dedicated thread
    let session_read = session.clone();
    std::thread::spawn(move || {
        loop {
            match session_read.receive_blocking() {
                Ok(packet) => {
                    let bytes: &[u8] = packet.bytes();
                    if packet_tx_in.blocking_send(bytes.to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("Wintun receive packet error: {:?}", e);
                    break;
                }
            }
        }
    });

    // Spawning blocking write loop in a dedicated thread
    let session_write = session.clone();
    std::thread::spawn(move || {
        while let Some(pkt) = packet_rx_out.blocking_recv() {
            if pkt.len() > mtu {
                debug!("Dropped packet exceeding MTU: {} > {}", pkt.len(), mtu);
                continue;
            }
            match session_write.allocate_send_packet(pkt.len() as u16) {
                Ok(mut send_packet) => {
                    send_packet.bytes_mut().copy_from_slice(&pkt);
                    session_write.send_packet(send_packet);
                }
                Err(e) => {
                    error!("Wintun allocate send packet error: {:?}", e);
                }
            }
        }
    });

    Ok(TunDevice {
        packet_rx,
        packet_tx,
        _shutdown_tx: shutdown_tx,
    })
}

#[cfg(target_os = "linux")]
pub fn create_tun_device(tun_name: &str, mtu: usize) -> Result<TunDevice> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut config = tun::Configuration::default();
    config
        .name(tun_name)
        .address("10.1.0.2")
        .netmask("255.255.255.0")
        .mtu(mtu as i32)
        .up();

    let device = tun::create_as_async(&config)?;
    let (mut reader, mut writer) = tokio::io::split(device);

    let (packet_tx_in, packet_rx) = mpsc::channel::<Vec<u8>>(100000);
    let (packet_tx, mut packet_rx_out) = mpsc::channel::<Vec<u8>>(100000);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    // Read loop
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if packet_tx_in.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("TUN read error: {:?}", e);
                    break;
                }
            }
        }
    });

    // Write loop
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                pkt_opt = packet_rx_out.recv() => {
                    if let Some(pkt) = pkt_opt {
                        if let Err(e) = writer.write_all(&pkt).await {
                            error!("TUN write error: {:?}", e);
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    });

    Ok(TunDevice {
        packet_rx,
        packet_tx,
        _shutdown_tx: shutdown_tx,
    })
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn create_tun_device(_tun_name: &str, _mtu: usize) -> Result<TunDevice> {
    Err(anyhow!("Unsupported operating system for TUN device"))
}

#[cfg(unix)]
pub fn create_tun_device_from_fd(fd: i32, mtu: usize) -> Result<TunDevice> {
    use std::os::unix::io::FromRawFd;
    use std::io::{Read, Write};

    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut file_read = file.try_clone()?;
    let mut file_write = file;

    let (packet_tx_in, packet_rx) = mpsc::channel::<Vec<u8>>(100000);
    let (packet_tx, mut packet_rx_out) = mpsc::channel::<Vec<u8>>(100000);
    let (shutdown_tx, _shutdown_rx) = mpsc::channel::<()>(1);

    // Read loop thread
    std::thread::spawn(move || {
        let mut buf = vec![0_u8; 65535];
        loop {
            match file_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if packet_tx_in.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("TUN fd read error: {:?}", e);
                    break;
                }
            }
        }
    });

    // Write loop thread
    std::thread::spawn(move || {
        while let Some(pkt) = packet_rx_out.blocking_recv() {
            if pkt.len() > mtu {
                continue;
            }
            if let Err(e) = file_write.write_all(&pkt) {
                error!("TUN fd write error: {:?}", e);
                break;
            }
        }
    });

    Ok(TunDevice {
        packet_rx,
        packet_tx,
        _shutdown_tx: shutdown_tx,
    })
}

#[cfg(not(unix))]
pub fn create_tun_device_from_fd(_fd: i32, _mtu: usize) -> Result<TunDevice> {
    Err(anyhow!("Raw fd TUN device is not supported on this operating system"))
}
