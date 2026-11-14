//! A session over `StdPlatform` against the real server (in-process `ostp-server`) and an
//! echo target: handshake, ping, a relay stream with flow control, both carriers.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ostp_session::{CarrierKind, Event, Server, Session, SessionConfig, StdPlatform};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const KEY: &str = "session-e2e-key";

fn free_port() -> u16 {
    // UDP and TCP on the same port: the server binds both.
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

async fn start_server() -> SocketAddr {
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let params = ostp_server::ServerParams {
        bind_addrs: vec![addr.to_string()],
        server_public_ip: None,
        bind_ip: None,
        access_keys: vec![(
            KEY.to_string(),
            ostp_server::api::UserMeta { name: None, limit_bytes: None, max_devices: None },
        )],
        outbound: None,
        api_config: None,
        fallback_config: None,
        debug: false,
        dns_config: None,
        config_path: None,
        tls: None,
        subscription: None,
        overnet: None,
        warp: None,
        local_access: true,
    };
    tokio::spawn(async move {
        if let Err(e) = ostp_server::run_server(params).await {
            panic!("server failed: {e}");
        }
    });
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start");
}

async fn start_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match l.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Pump until `done` says so or the time is up.
fn drive(s: &mut Session<StdPlatform>, secs: u64, mut done: impl FnMut(&mut Session<StdPlatform>, Event) -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        s.pump().expect("session lost");
        while let Some(ev) = s.next_event() {
            if done(s, ev) {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("timed out");
}

fn run(carrier: &str, server: SocketAddr, echo: SocketAddr) {
    let link = format!("ostp://{KEY}@127.0.0.1:{}?type={carrier}", server.port());
    let srv = Server::parse(&link).unwrap();
    let mut p = StdPlatform;
    let mut s = Session::connect(&mut p, &srv, SessionConfig::default()).expect("handshake");
    assert_eq!(s.server().1, if carrier == "udp" { CarrierKind::Udp } else { CarrierKind::Uot });

    s.ping();
    drive(&mut s, 5, |_, ev| matches!(ev, Event::Pong { .. }));
    assert!(s.stats().flow_control, "the server should accept flow control");

    let id = s.open_stream(&echo.to_string()).unwrap();
    drive(&mut s, 5, |_, ev| match ev {
        Event::Connected(i) => i == id,
        Event::Failed(_, m) => panic!("stream failed: {m}"),
        _ => false,
    });

    // 2 MiB through the echo: more than WINDOW_UPDATE_STEP, so window grants must flow.
    let total = 2 * 1024 * 1024;
    let data: Vec<u8> = (0..total).map(|i| (i * 7 + i / 251) as u8).collect();
    let mut sent = 0usize;
    let mut got: Vec<u8> = Vec::with_capacity(total);
    let end = Instant::now() + Duration::from_secs(60);
    while got.len() < total {
        assert!(Instant::now() < end, "transfer timed out at {} of {total} bytes", got.len());
        if sent < total {
            sent += s.send(id, &data[sent..(sent + 64 * 1024).min(total)]);
        }
        s.pump().expect("session lost");
        while let Some(ev) = s.next_event() {
            match ev {
                Event::Data(i, d) if i == id => {
                    let n = d.len();
                    got.extend_from_slice(&d);
                    s.consumed(id, n);
                }
                Event::Closed(_) | Event::Failed(..) => panic!("stream ended early: {ev:?}"),
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    assert!(got == data, "echoed bytes differ");
    s.close_stream(id);
    let st = s.stats();
    assert!(st.rx_bytes > total as u64 && st.tx_bytes > total as u64);
    s.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_and_uot_sessions_against_the_server() {
    let server = start_server().await;
    let echo = start_echo().await;
    tokio::task::spawn_blocking(move || {
        run("udp", server, echo);
        run("uot", server, echo);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_key_fails_the_handshake() {
    let server = start_server().await;
    tokio::task::spawn_blocking(move || {
        let srv = Server::parse(&format!("ostp://not-the-key@127.0.0.1:{}?type=udp", server.port())).unwrap();
        let cfg = SessionConfig { handshake_timeout_ms: 1500, ..SessionConfig::default() };
        match Session::connect(&mut StdPlatform, &srv, cfg) {
            Err(ostp_session::Error::HandshakeTimeout) => {}
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("a wrong key must not get a session"),
        }
    })
    .await
    .unwrap();
}
