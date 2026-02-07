// sentiric-sbc-service/src/rtp/engine.rs

use std::sync::Arc;
use tokio::net::UdpSocket;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, error, debug, warn, trace}; // Trace eklendi
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
        // Port tükenmesini önlemek için 1000 deneme (Yüksek yük için güvenli marj)
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
                // [FIX]: local_port alanını burada okuyarak hem uyarıyı çözüyoruz hem de logluyoruz.
                info!("♻️ Kaynak Temizliği: Relay Port {} serbest bırakılıyor (CallID: {})", relay.local_port, call_id);
                let _ = relay.stop_signal.send(());
                return true;
            }
        }
        warn!("⚠️ Release istendi ama CallID bulunamadı: {}", call_id);
        false
    }
}

async fn run_relay_loop(port: u16, mut stop_signal: tokio::sync::broadcast::Receiver<()>) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    let mut buf = [0u8; 4096];

    // [v2.8 MİMARİ]: Complementary Peer Latching
    let mut peer_a: Option<SocketAddr> = None; 
    let mut peer_b: Option<SocketAddr> = None; 
    
    // Paket sayacı (Logging için)
    let mut packets_forwarded = 0u64;
    let mut last_log_time = std::time::Instant::now();
    
    // Timeout süresi: 60 saniye boyunca hiç paket gelmezse relay kapanır.
    let timeout = Duration::from_secs(60); 

    loop {
        // Her 5 saniyede bir trafik durumu raporla
        if last_log_time.elapsed() > Duration::from_secs(5) {
            if packets_forwarded > 0 {
                debug!("📊 Relay [{}]: Son 5sn içinde {} paket iletildi. Peers: A={:?} <-> B={:?}", 
                    port, packets_forwarded, peer_a, peer_b);
                packets_forwarded = 0;
            }
            last_log_time = std::time::Instant::now();
        }

        tokio::select! {
            _ = stop_signal.recv() => break,
            
            res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, src))) => {
                        let target = if Some(src) == peer_a {
                            peer_b
                        } else if Some(src) == peer_b {
                            peer_a
                        } else {
                            // Yeni bacak tespiti (Latching)
                            if peer_a.is_none() {
                                info!("🔒 [LATCH-A] Dış Bacak Kilitlendi: {} -> Relay:{}", src, port);
                                peer_a = Some(src);
                                None // Henüz hedef (B) yok, paket düşecek.
                            } else if peer_b.is_none() {
                                info!("🔒 [LATCH-B] İç Bacak Kilitlendi: {} -> Relay:{}", src, port);
                                peer_b = Some(src);
                                peer_a // Artık A'ya gönderebiliriz
                            } else {
                                // Roaming (IP değişimi)
                                if Some(src) != peer_a {
                                    warn!("🔄 [ROAMING] Bacak B güncellendi: {:?} -> {}", peer_b, src);
                                    peer_b = Some(src);
                                    peer_a
                                } else {
                                    warn!("🔄 [ROAMING] Bacak A güncellendi: {:?} -> {}", peer_a, src);
                                    peer_a = Some(src);
                                    peer_b
                                }
                            }
                        };

                        if let Some(dst) = target {
                            if let Err(e) = socket.send_to(&buf[..len], dst).await {
                                warn!("RTP Send Error [{}->{}]: {}", port, dst, e);
                            } else {
                                packets_forwarded += 1;
                            }
                        } else {
                            // Hedef yoksa (Tek bacak bağlıysa) paketi düşürüyoruz. Bunu trace seviyesinde loglayalım.
                            trace!("🗑️ Drop [{}]: Hedef henüz yok (Source: {})", port, src);
                        }
                    }
                    Ok(Err(e)) => {
                        error!("UDP Recv Error: {}", e);
                    }
                    Err(_) => {
                        warn!("⚠️ RTP Timeout on port {}. Traffic ceased. Closing relay.", port);
                        break;
                    },
                }
            }
        }
    }
    Ok(())
}