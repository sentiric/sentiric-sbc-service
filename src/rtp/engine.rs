// src/rtp/engine.rs
use std::sync::Arc;
use tokio::net::UdpSocket;
use dashmap::DashMap;
use std::net::{SocketAddr, IpAddr};
use std::time::Duration;
use tracing::{info, error, warn, debug}; // DEBUG EKLENDİ
use rand::Rng;

fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if octets[0] == 10 && octets[1] == 88 && octets[3] == 1 { return true; } 
            if octets[0] == 10 || octets[0] == 127 { return true; }
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) { return true; }
            if octets[0] == 192 && octets[1] == 168 { return true; }
            if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) { return true; }
            false
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

fn is_docker_gateway(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[3] == 1,
        _ => false,
    }
}

struct RtpRelay {
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

    pub async fn get_or_allocate_relay(&self, call_id: &str, initial_peer: Option<SocketAddr>) -> Option<u16> {
        if let Some(entry) = self.call_id_map.get(call_id) {
            return Some(*entry.value());
        }
        
        let mut rng = rand::thread_rng();
        for _ in 0..1000 { 
            let port = rng.gen_range(self.start_port..=self.end_port);
            let port = if port % 2 != 0 { port.saturating_add(1) } else { port };
            if port > self.end_port { continue; }

            if !self.active_relays.contains_key(&port) {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                let relay = RtpRelay { stop_signal: tx.clone() };
                
                let active_relays_clone = self.active_relays.clone();
                let call_id_map_clone = self.call_id_map.clone();
                let call_id_owned = call_id.to_string();
                let stop_rx = tx.subscribe();

                tokio::spawn(async move {
                    info!(
                        event = "RTP_RELAY_STARTED",
                        sip.call_id = %call_id_owned, 
                        rtp.port = port,
                        "🚀 [RTP-RELAY] Başlatıldı"
                    );
                    
                    if let Err(e) = run_relay_loop(port, stop_rx, initial_peer, &call_id_owned).await {
                        error!(
                            event = "RTP_RELAY_ERROR",
                            sip.call_id = %call_id_owned,
                            rtp.port = port,
                            error = %e,
                            "🔥 [RTP-RELAY] Hata oluştu"
                        );
                    }
                    active_relays_clone.remove(&port);
                    call_id_map_clone.remove(&call_id_owned);
                });

                self.active_relays.insert(port, relay);
                self.call_id_map.insert(call_id.to_string(), port);
                return Some(port);
            }
        }
        
        warn!(
            event = "RTP_PORT_EXHAUSTED",
            trace_id = %call_id,
            sip.call_id = %call_id,
            "Port aralığı tükendi, relay ayrılamıyor."
        );
        None
    }

    pub async fn release_relay_by_call_id(&self, call_id: &str) -> bool {
        if let Some((_, port)) = self.call_id_map.remove(call_id) {
            if let Some((_, relay)) = self.active_relays.remove(&port) {
                let _ = relay.stop_signal.send(());
                
                info!(
                    event = "RTP_RELAY_RELEASED",
                    trace_id = %call_id,
                    sip.call_id = %call_id,
                    rtp.port = port,
                    "🛑 RTP Relay serbest bırakıldı."
                );
                return true;
            }
        }
        false
    }
}

async fn run_relay_loop(port: u16, mut stop_signal: tokio::sync::broadcast::Receiver<()>, initial_external_peer: Option<SocketAddr>, call_id: &str) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    let mut buf = [0u8; 2048];
    let mut peer_external = initial_external_peer;
    let mut peer_internal: Option<SocketAddr> = None;
    let timeout = Duration::from_secs(60); 
    
    debug!(
        event = "RTP_SOCKET_BOUND",
        sip.call_id = %call_id,
        rtp.port = port,
        "🎧 RTP Relay soketi IP adresine bağlandı ve dinliyor."
    );

    // [YENİ]: Eğer dış hedef (telefon) IP'si biliniyorsa, hemen ona boş paket at (Hole Punching)
    if let Some(target) = peer_external {
        info!(event="RTP_HOLE_PUNCH_INIT", target=%target, "Agresif NAT delme başlatılıyor...");
        let _ = socket.send_to(&[0u8; 4], target).await; // 4 byte null payload
    }

    loop {
        tokio::select! {
            _ = stop_signal.recv() => break,
            res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, src))) => {
                        let is_internal = is_internal_ip(src.ip());
                        
                        if is_internal {
                            // İÇERİDEN GELEN PAKET (Media Service -> SBC)
                            if peer_internal != Some(src) {
                                if !(is_docker_gateway(src.ip()) && peer_internal.is_some()) {
                                    info!(
                                        event = "RTP_LATCH_INTERNAL",
                                        trace_id = %call_id,
                                        sip.call_id = %call_id,
                                        rtp.port = port,
                                        net.peer.ip = %src.ip(),
                                        net.peer.port = src.port(),
                                        "🏢 [LATCH-INT] İç Bacak Kilitlendi"
                                    );
                                    peer_internal = Some(src);
                                }
                            }
                            
                            // Eğer dış hedef belliyse yönlendir
                            if let Some(dst) = peer_external { 
                                let _ = socket.send_to(&buf[..len], dst).await; 
                            } else {
                                // Hedef belli değilse, gelen ilk paketi logla (Debug amaçlı)
                                debug!(event="RTP_DROP_NO_EXT_PEER", len=len, "Dış hedef henüz yok, paket düşürüldü.");
                            }
                        } else {
                            // DIŞARIDAN GELEN PAKET (Telefon -> SBC)
                            if peer_external != Some(src) {
                                info!(
                                    event = "RTP_LATCH_EXTERNAL",
                                    trace_id = %call_id,
                                    sip.call_id = %call_id,
                                    rtp.port = port,
                                    net.peer.ip = %src.ip(),
                                    net.peer.port = src.port(),
                                    "🌍 [LATCH-EXT] Dış Bacak Kilitlendi! (SES GELİYOR)"
                                );
                                peer_external = Some(src);
                            }
                            if let Some(dst) = peer_internal { let _ = socket.send_to(&buf[..len], dst).await; }
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => {
                        warn!(
                            event = "RTP_RELAY_TIMEOUT",
                            trace_id = %call_id,
                            sip.call_id = %call_id,
                            rtp.port = port,
                            "⌛ RTP Relay zaman aşımına uğradı."
                        );
                        break;
                    },
                }
            }
        }
    }
    Ok(())
}