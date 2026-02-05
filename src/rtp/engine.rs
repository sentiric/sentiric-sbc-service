// sentiric-sbc-service/src/rtp/engine.rs

use std::sync::Arc;
use tokio::net::UdpSocket;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, error, debug, warn};
use rand::Rng;

struct RtpRelay {
    #[allow(dead_code)] // UYARI DÜZELTMESİ: Bu alan debug/loglama için tutuluyor.
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
                
                let relay = RtpRelay {
                    local_port: port,
                    stop_signal: tx.clone(),
                };
                
                let active_relays_clone = self.active_relays.clone();
                let call_id_map_clone = self.call_id_map.clone();
                let call_id_owned = call_id.to_string();

                let stop_rx = tx.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = run_relay_loop(port, stop_rx).await {
                        error!("🔥 RTP Relay Error on port {}: {}", port, e);
                    }
                    active_relays_clone.remove(&port);
                    call_id_map_clone.remove(&call_id_owned);
                    info!("♻️ RTP Port {} and session for {} released.", port, call_id_owned);
                });

                self.active_relays.insert(port, relay);
                self.call_id_map.insert(call_id.to_string(), port);
                info!("🎤 RTP Relay Allocated: Port {} for Call-ID {}", port, call_id);
                return Some(port);
            }
        }
        
        error!("❌ RTP Port Allocation FAILED. No available ports.");
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

    let mut peer_a: Option<SocketAddr> = None;
    let mut peer_b: Option<SocketAddr> = None;
    
    let timeout = Duration::from_secs(60); 

    info!("🎤 RTP Listener started on {}", addr);

    loop {
        tokio::select! {
            _ = stop_signal.recv() => {
                info!("🛑 RTP Relay Stopped (Signal) on port {}", port);
                break;
            }
            
            res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, src))) => {
                        let target = if Some(src) == peer_a {
                            peer_b
                        } else if Some(src) == peer_b {
                            peer_a
                        } else {
                            if peer_a.is_none() {
                                info!("🔒 RTP Latch A (First Peer): {} on port {}", src, port);
                                peer_a = Some(src);
                                None
                            } else if peer_b.is_none() {
                                info!("🔒 RTP Latch B (Second Peer): {} on port {}", src, port);
                                peer_b = Some(src);
                                peer_a
                            } else {
                                debug!("🛡️ RTP Security Drop: Stray packet from {} on port {}", src, port);
                                None
                            }
                        };

                        if let Some(dst) = target {
                            if let Err(e) = socket.send_to(&buf[..len], dst).await {
                                warn!("⚠️ RTP Send Error to {}: {}", dst, e);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        error!("🔥 RTP Socket I/O Error on port {}: {}", port, e);
                        break;
                    }
                    Err(_) => { 
                        info!("💤 RTP Timeout (Silence). Closing port {}", port);
                        break;
                    }
                }
            }
        }
    }
    
    Ok(())
}