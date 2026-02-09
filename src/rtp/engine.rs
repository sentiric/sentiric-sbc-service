// sentiric-sbc-service/src/rtp/engine.rs

use std::sync::Arc;
use tokio::net::UdpSocket;
use dashmap::DashMap;
use std::net::{SocketAddr, IpAddr}; // IpAddr eklendi
use std::time::Duration;
use tracing::{info, error, debug, warn, trace};
use rand::Rng;

// [FIX]: IP Sınıflandırması için yardımcı fonksiyon
fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 { return true; }
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) { return true; }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 { return true; }
            // 100.64.0.0/10 (CGNAT / Tailscale - Sentiric Internal)
            if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) { return true; }
            // 127.0.0.0/8 (Loopback)
            if octets[0] == 127 { return true; }
            false
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

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
        for _ in 0..1000 { 
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
                    info!("🚀 RTP Relay Başlatıldı: Port {} | CallID: {}", port, call_id_owned);
                    if let Err(e) = run_relay_loop(port, stop_rx).await {
                        error!("🔥 RTP Relay Kritik Hata [{}]: {}", port, e);
                    }
                    info!("🛑 RTP Relay Durduruldu: Port {}", port);
                    active_relays_clone.remove(&port);
                    call_id_map_clone.remove(&call_id_owned);
                });

                self.active_relays.insert(port, relay);
                self.call_id_map.insert(call_id.to_string(), port);
                return Some(port);
            }
        }
        error!("❌ RTP PORT HAVUZU TÜKENDİ! Aralık: {}-{}", self.start_port, self.end_port);
        None
    }

    pub async fn release_relay_by_call_id(&self, call_id: &str) -> bool {
        if let Some((_, port)) = self.call_id_map.remove(call_id) {
            if let Some((_, relay)) = self.active_relays.remove(&port) {
                info!("♻️ Kaynak Temizliği: Relay Port {} serbest bırakılıyor (CallID: {})", relay.local_port, call_id);
                let _ = relay.stop_signal.send(());
                return true;
            }
        }
        // Log kirliliğini azaltmak için Warn -> Debug
        debug!("⚠️ Release istendi ama CallID bulunamadı: {}", call_id);
        false
    }
}

async fn run_relay_loop(port: u16, mut stop_signal: tokio::sync::broadcast::Receiver<()>) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    let mut buf = [0u8; 4096];

    // [CRITICAL FIX]: Network-Aware Latching (Internal vs External)
    let mut peer_external: Option<SocketAddr> = None; // Client (Public IP)
    let mut peer_internal: Option<SocketAddr> = None; // Media Service (Private IP)
    
    let mut packets_forwarded = 0u64;
    let mut last_log_time = std::time::Instant::now();
    let timeout = Duration::from_secs(60); 

    loop {
        if last_log_time.elapsed() > Duration::from_secs(5) {
            if packets_forwarded > 0 {
                debug!("📊 Relay [{}]: Son 5sn {} pkt. Ext={:?} <-> Int={:?}", 
                    port, packets_forwarded, peer_external, peer_internal);
                packets_forwarded = 0;
            }
            last_log_time = std::time::Instant::now();
        }

        tokio::select! {
            _ = stop_signal.recv() => break,
            
            res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, src))) => {
                        let target = if Some(src) == peer_external {
                            // Dışarıdan geldi -> İçeri gönder
                            peer_internal
                        } else if Some(src) == peer_internal {
                            // İçeriden geldi -> Dışarı gönder
                            peer_external
                        } else {
                            // YENİ BACAK TESPİTİ (Smart Latching)
                            let is_internal = is_internal_ip(src.ip());

                            if is_internal {
                                if peer_internal != Some(src) {
                                    info!("🏢 [LATCH-INT] İç Bacak (Media) Kilitlendi: {} (Port {})", src, port);
                                    peer_internal = Some(src);
                                }
                                peer_external // Hedef dışarı
                            } else {
                                if peer_external != Some(src) {
                                    info!("🌍 [LATCH-EXT] Dış Bacak (Client) Kilitlendi: {} (Port {})", src, port);
                                    peer_external = Some(src);
                                }
                                peer_internal // Hedef içeri
                            }
                        };

                        if let Some(dst) = target {
                            if let Err(e) = socket.send_to(&buf[..len], dst).await {
                                trace!("RTP Send Error [{}->{}]: {}", port, dst, e);
                            } else {
                                packets_forwarded += 1;
                            }
                        } else {
                            // Hedef henüz yoksa paketi düşür (Normal durum, diğer taraf bağlanana kadar)
                            // trace!("⏳ Drop [{}]: Hedef bekleniyor (Source: {})", port, src);
                        }
                    }
                    Ok(Err(e)) => error!("UDP Recv Error: {}", e),
                    Err(_) => {
                        warn!("⚠️ RTP Timeout on port {}. Closing relay.", port);
                        break;
                    },
                }
            }
        }
    }
    Ok(())
}