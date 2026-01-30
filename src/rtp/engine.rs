// sentiric-sbc-service/src/rtp/engine.rs

use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, error, debug}; // warn kaldırıldı
use rand::Rng;

pub struct RtpRelay {
    pub local_port: u16,
    #[allow(dead_code)] // Bu alan şu an okunmuyor ama mantıksal olarak gerekli
    stop_signal: tokio::sync::broadcast::Sender<()>,
}


pub struct RtpEngine {
    // Port -> Session mapping
    active_relays: Arc<Mutex<HashMap<u16, RtpRelay>>>,
    start_port: u16,
    end_port: u16,
}

impl RtpEngine {
    pub fn new(start: u16, end: u16) -> Self {
        Self {
            active_relays: Arc::new(Mutex::new(HashMap::new())),
            start_port: start,
            end_port: end,
        }
    }

    /// Yeni bir RTP Relay oturumu başlatır.
    /// Returns: Ayrılan yerel port numarası.
    pub async fn allocate_relay(&self) -> Option<u16> {
        let mut relays = self.active_relays.lock().await;
        
        // Basit port bulma (Random + Check)
        let mut rng = rand::thread_rng();
        for _ in 0..100 { // 100 deneme
            let port = rng.gen_range(self.start_port..self.end_port);
            // RTP portları çift sayı olmalı
            let port = if port % 2 != 0 { port + 1 } else { port };
            
            if !relays.contains_key(&port) {
                // Port boş, rezerve et ve başlat
                let (tx, _) = tokio::sync::broadcast::channel(1);
                
                let relay = RtpRelay {
                    local_port: port,
                    stop_signal: tx.clone(),
                };
                
                // Background Task Başlat
                let stop_rx = tx.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = run_relay_loop(port, stop_rx).await {
                        error!("RTP Relay Error on port {}: {}", port, e);
                    }
                });

                relays.insert(port, relay);
                info!("🎤 RTP Relay Allocated: Port {}", port);
                return Some(port);
            }
        }
        
        error!("No available RTP ports!");
        None
    }

    // Basit bir temizleme mekanizması gerekebilir (Call-ID ile eşleştirip silmek için)
    // Şimdilik timeout bazlı kapanışa güveniyoruz.
}

async fn run_relay_loop(port: u16, mut stop_signal: tokio::sync::broadcast::Receiver<()>) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    let mut buf = [0u8; 2048];

    // Latching State
    let mut peer_a: Option<SocketAddr> = None; // Operator
    let mut peer_b: Option<SocketAddr> = None; // UAS (Antalya)
    
    // Silence Timeout
    let timeout = Duration::from_secs(60); 

    info!("🎤 RTP Listener started on {}", addr);

    loop {
        tokio::select! {
            _ = stop_signal.recv() => {
                info!("🛑 RTP Relay Stopped (Signal): {}", port);
                break;
            }
            
            res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)) => {
                match res {
                    Ok(Ok((len, src))) => {
                        // --- LATCHING LOGIC ---
                        // Gelen paketin kaynağına göre hedefi belirle
                        
                        let target = if Some(src) == peer_a {
                            // Geldiği yer A, hedef B
                            peer_b
                        } else if Some(src) == peer_b {
                            // Geldiği yer B, hedef A
                            peer_a
                        } else {
                            // Bilinmeyen kaynak -> Yeni bir Peer olarak kaydet
                            if peer_a.is_none() {
                                info!("🔒 RTP Latch A (Operator?): {}", src);
                                peer_a = Some(src);
                                peer_b // Hedef hala yoksa None döner
                            } else if peer_b.is_none() {
                                info!("🔒 RTP Latch B (UAS?): {}", src);
                                peer_b = Some(src);
                                peer_a // Hedef A
                            } else {
                                // İkisi de dolu ama farklı bir IP'den geldi.
                                // Saldırı veya IP değişimi olabilir. Şimdilik drop veya re-latch.
                                debug!("⚠️ RTP Stray Packet from {}", src);
                                None
                            }
                        };

                        if let Some(dst) = target {
                            let _ = socket.send_to(&buf[..len], dst).await;
                        }
                    }
                    Ok(Err(e)) => {
                        error!("RTP Socket Error: {}", e);
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