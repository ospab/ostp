use std::collections::{HashMap, VecDeque};
use std::time::Instant;
use anyhow::Result;
use tokio::sync::mpsc;
use tokio::sync::watch;
use bytes::Bytes;
use tracing::{info, error, debug};

use smoltcp::iface::{Config, Interface, SocketSet, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, State as TcpState};
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Packet, IpProtocol, TcpPacket};

use crate::tunnel::{ProxyEvent, ProxyToClientMsg};

// Custom smoltcp device that bridges to tokio channels
struct ChannelDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_sender: mpsc::Sender<Vec<u8>>,
    capabilities: DeviceCapabilities,
}

impl ChannelDevice {
    fn new(tx_sender: mpsc::Sender<Vec<u8>>, mtu: usize) -> Self {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = mtu;
        Self {
            rx_queue: VecDeque::new(),
            tx_sender,
            capabilities: caps,
        }
    }
}

struct ChannelRxToken(Vec<u8>);

impl RxToken for ChannelRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct ChannelTxToken(mpsc::Sender<Vec<u8>>);

impl TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        let _ = self.0.try_send(buffer);
        result
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = ChannelRxToken where Self: 'a;
    type TxToken<'a> = ChannelTxToken where Self: 'a;

    fn receive(&mut self, _timestamp: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(|packet| {
            (
                ChannelRxToken(packet),
                ChannelTxToken(self.tx_sender.clone()),
            )
        })
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken(self.tx_sender.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

struct VirtualStream {
    _stream_id: u16,
    socket_handle: SocketHandle,
    last_activity: Instant,
    target: String,
    established: bool,
}

pub async fn run_smoltcp_stack(
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    mtu: usize,
    proxy_events_tx: mpsc::Sender<ProxyEvent>,
    mut client_msgs_rx: mpsc::UnboundedReceiver<(u16, ProxyToClientMsg)>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut device = ChannelDevice::new(tun_tx, mtu);
    
    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
    
    let mut interface = Interface::new(config, &mut device, smoltcp::time::Instant::now());
    interface.set_any_ip(true); // Required to intercept all packets
    interface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 1, 0, 2), 24));
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut stream_id_counter: u16 = 1;
    let mut streams: HashMap<u16, VirtualStream> = HashMap::new();
    let mut handle_to_stream_id: HashMap<SocketHandle, u16> = HashMap::new();

    // Map to route incoming data from client_msgs_rx to target sockets
    let mut pending_client_msgs: VecDeque<(u16, ProxyToClientMsg)> = VecDeque::new();

    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(5));

    info!("smoltcp virtual TCP/IP stack runner active.");

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                break;
            }
            _ = ticker.tick() => {
                // Periodical stack poll
            }
            pkt_opt = tun_rx.recv() => {
                if let Some(pkt) = pkt_opt {
                    // Check if it's a new TCP connection (SYN) and dynamically spawn a listener
                    if let Ok(ipv4_packet) = Ipv4Packet::new_checked(&pkt) {
                        if ipv4_packet.next_header() == IpProtocol::Tcp {
                            if let Ok(tcp_packet) = TcpPacket::new_checked(ipv4_packet.payload()) {
                                if tcp_packet.syn() && !tcp_packet.ack() {
                                    let dst_ip = ipv4_packet.dst_addr();
                                    let dst_port = tcp_packet.dst_port();
                                    
                                    // Allocate a stream_id
                                    let stream_id = stream_id_counter;
                                    stream_id_counter = stream_id_counter.wrapping_add(1);
                                    if stream_id_counter == 0 {
                                        stream_id_counter = 1;
                                    }

                                    let target = format!("{}:{}", dst_ip, dst_port);
                                    debug!("Intercepted TCP SYN to {}, creating virtual socket. Stream ID: {}", target, stream_id);

                                    // Create socket inside smoltcp
                                    let mut tcp_socket = TcpSocket::new(
                                        smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
                                        smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
                                    );

                                    if let Err(e) = tcp_socket.listen((dst_ip, dst_port)) {
                                        error!("Failed to set TCP socket to listen: {:?}", e);
                                    } else {
                                        let handle = sockets.add(tcp_socket);
                                        streams.insert(stream_id, VirtualStream {
                                            _stream_id: stream_id,
                                            socket_handle: handle,
                                            last_activity: Instant::now(),
                                            target: target.clone(),
                                            established: false,
                                        });
                                        handle_to_stream_id.insert(handle, stream_id);
                                    }
                                }
                            }
                        }
                    }
                    device.rx_queue.push_back(pkt);
                }
            }
            msg_opt = client_msgs_rx.recv() => {
                if let Some((stream_id, msg)) = msg_opt {
                    pending_client_msgs.push_back((stream_id, msg));
                }
            }
        }

        // Process pending client messages (responses from OSTP bridge)
        let mut unhandled = VecDeque::new();
        while let Some((stream_id, msg)) = pending_client_msgs.pop_front() {
            if let Some(stream) = streams.get_mut(&stream_id) {
                let socket = sockets.get_mut::<TcpSocket>(stream.socket_handle);
                match msg {
                    ProxyToClientMsg::ConnectOk => {
                        stream.established = true;
                        debug!("Stream ID {} connected successfully via OSTP.", stream_id);
                    }
                    ProxyToClientMsg::Data(data) => {
                        if socket.can_send() {
                            let _ = socket.send_slice(&data);
                            stream.last_activity = Instant::now();
                        }
                    }
                    ProxyToClientMsg::Close | ProxyToClientMsg::Error(_) => {
                        socket.close();
                        // Socket clean-up will occur below
                    }
                }
            } else {
                unhandled.push_back((stream_id, msg));
            }
        }
        pending_client_msgs = unhandled;

        // Poll the virtual interface
        let timestamp = smoltcp::time::Instant::now();
        let _ = interface.poll(timestamp, &mut device, &mut sockets);

        // Process data transfer from virtual sockets -> OSTP client bridge
        let mut closed_streams = Vec::new();
        for (&stream_id, stream) in streams.iter_mut() {
            let socket = sockets.get_mut::<TcpSocket>(stream.socket_handle);
            
            // 1. Handshake detection & initiation
            if socket.is_active() && !stream.established {
                if socket.state() == TcpState::Established {
                    // Send Connect request to the bridge
                    if proxy_events_tx.try_send(ProxyEvent::NewStream {
                        stream_id,
                        target: stream.target.clone(),
                    }).is_ok() {
                        stream.established = true;
                    }
                }
            }

            // 2. Read inbound data from client OS applications
            if socket.may_recv() {
                let mut buf = vec![0; 4096];
                if let Ok(n) = socket.recv_slice(&mut buf) {
                    if n > 0 {
                        stream.last_activity = Instant::now();
                        let _ = proxy_events_tx.try_send(ProxyEvent::Data {
                            stream_id,
                            payload: Bytes::from(buf[..n].to_vec()),
                        });
                    }
                }
            }

            // 3. Connection termination detection
            let mut should_close = false;
            if !socket.is_active() || socket.state() == TcpState::Closed || socket.state() == TcpState::TimeWait {
                should_close = true;
            } else if stream.last_activity.elapsed() > std::time::Duration::from_secs(120) {
                // Timeout inactive streams
                should_close = true;
                socket.abort();
            }

            if should_close {
                closed_streams.push(stream_id);
            }
        }

        // Clean up closed streams
        for stream_id in closed_streams {
            if let Some(stream) = streams.remove(&stream_id) {
                debug!("Cleaning up virtual socket for stream ID: {}", stream_id);
                handle_to_stream_id.remove(&stream.socket_handle);
                sockets.remove(stream.socket_handle);
                let _ = proxy_events_tx.try_send(ProxyEvent::Close { stream_id });
            }
        }
    }

    Ok(())
}
