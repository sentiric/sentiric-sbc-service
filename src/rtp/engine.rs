// sentiric-sbc-service/src/rtp/engine.rs

use std::sync::Arc;
use tokio::net::UdpSocket;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, error, debug, warn};
use rand::Rng;

struct RtpRelay {
    pub local_port: u16,
    stop_signal: tokio::sync::broadcast::Sender<()>,
}

pub struct RtpEngine {
    active_relays: Arc<DashMap<u16, RtpRelay>>,
    call_id_map: Arc<DashMap<String, u16>>,
    start_port: u16,
    end_port: u16,
}

impl RtpEngine {
    pub fn new(start: u16, end: u16) -> Self {
        Self {
            active_relays: Arc::new(DashMap::new()),
            call_id_map: Arc::new(DashMap::new()),
            start_port: start,
            end_port: end,
        }
    }

    pub async fn get_or_allocate_relay(&self, call_id: &str) -> Option<u16> {
        if let Some(entry) = self.call_id_map.get(call_id) {
            return Some(*entry.value());
        }
        
        let mut rng = rand::thread_rng();
        for _ in 0..500 { 
            let port = rng.gen_range(self.start_port..=self.end_port);
            let port = if port % 2 != 0 { port.saturating_add(1) } else { port };
            if port > self.end_port { continue; }

            if !self.active_relays.contains_key(&port) {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                let relay = RtpRelay { local_port: port, stop_signal: tx.clone() };
                
                let active_relays_clone = self.active_relays.clone();
                let call_id_map_clone = self.call_id_map.clone();
                let call_id_owned = call_id.to_string();
                let stop_rx = tx.subscribe();

                tokio::spawn(async move {
                    if let Err(e) = run_relay_loop(port, stop_rx).await {
                        error!("🔥 RTP Relay Error [{}]: {}", port, e);
                    }
                    active_relays_clone.remove(&port);
                    call_id_map_clone.remove(&call_id_owned);
                    info!("♻️ Port {} released.", port);
                });

                self.active_relays.insert(port, relay);
                self.call_id_map.insert(call_id.to_string(), port);
                return Some(port);
            }
        }
        None
    }

    pub async fn release_relay_by_call_id(&self, call_id: &str) -> bool {
        if let Some((_, port)) = self.call_id_map.remove(call_id) {
            if let Some((_, relay)) = self.active_relays.remove(&port) {
                let _ = relay.stop_signal.send(());
                return true;
            }
        }
        false
    }
}

async fn run_relay_loop(port: u16, mut stop_signal: tokio::sync::broadcast::Receiver<()>) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    let mut buf = [0u8; 2048];

    let mut peer_ext: Option<SocketAddr> = None;
    let mut peer_int: Option<SocketAddr> = None;
    
    let timeout = Duration::from_secs(60); 

    loop {
        tokio::select! {
            _ = stop_signal.recv() => break,
            
            res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, src))) => {
                        // [v2.6 MİMARİ]: ZERO-TRUST LATCHING
                        let target = if Some(src) == peer_ext {
                            peer_int
                        } else if Some(src) == peer_int {
                            peer_ext
                        } else {
                            // Yeni bir bacak (Peer) geldi. 
                            // Eğer bu paket iç ağdan (Tailscale/Docker) geliyorsa İÇ BACAK yap.
                            if is_private_network(src.ip()) {
                                if peer_int.is_none() { info!("🔒 [LATCH-INT] Internal media path established: {}", src); }
                                peer_int = Some(src);
                                peer_ext
                            } else {
                                if peer_ext.is_none() { info!("🔒 [LATCH-EXT] External media path established: {}", src); }
                                peer_ext = Some(src);
                                peer_int
                            }
                        };

                        if let Some(dst) = target {
                            let _ = socket.send_to(&buf[..len], dst).await;
                        }
                    }
                    _ => {
                        warn!("💤 RTP Timeout on port {}", port);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn is_private_network(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let o = ipv4.octets();
            // 10.x (Docker), 100.64-127.x (Tailscale), 172.16.x, 192.168.x
            o[0] == 10 || (o[0] == 100 && o[1] >= 64 && o[1] <= 127) ||
            (o[0] == 172 && o[1] >= 16 && o[1] <= 31) || (o[0] == 192 && o[1] == 168)
        }
        _ => false,
    }
}