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
    let mut buf = [0u8; 4096];

    let mut peer_external: Option<SocketAddr> = None;
    let mut peer_internal: Option<SocketAddr> = None;
    
    let timeout = Duration::from_secs(60); 

    info!("🎤 RTP Relay Active on {}", addr);

    loop {
        tokio::select! {
            _ = stop_signal.recv() => break,
            
            res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, src))) => {
                        // [v2.4 MİMARİ]: Akıllı Çift Yönlü Latching
                        // 1. Paket dışarıdan mı geliyor (Public IP)?
                        // 2. Paket içeriden mi geliyor (Tailscale/Docker IP)?
                        
                        let target = if Some(src) == peer_external {
                            peer_internal
                        } else if Some(src) == peer_internal {
                            peer_external
                        } else {
                            // Yeni bir peer keşfedildi.
                            // Basit mantık: Eğer IP özel bloktaysa (10.x veya 100.x) INTERNAL'dır.
                            let is_private = is_private_network(src.ip());

                            if is_private && peer_internal.is_none() {
                                info!("🔒 RTP Latch INTERNAL: {} on port {}", src, port);
                                peer_internal = Some(src);
                                peer_external
                            } else if !is_private && peer_external.is_none() {
                                info!("🔒 RTP Latch EXTERNAL: {} on port {}", src, port);
                                peer_external = Some(src);
                                peer_internal
                            } else {
                                // Zaten kilitli bir bacak var ama gelen farklı, roaming olabilir.
                                if is_private { peer_internal = Some(src); peer_external }
                                else { peer_external = Some(src); peer_internal }
                            }
                        };

                        if let Some(dst) = target {
                            let _ = socket.send_to(&buf[..len], dst).await;
                        }
                    }
                    _ => break,
                }
            }
        }
    }
    Ok(())
}

// Yardımcı fonksiyon: IP'nin iç ağda olup olmadığını kontrol eder.
fn is_private_network(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 10 || (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127) || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] == 192 && octets[1] == 168)
        }
        _ => false,
    }
}