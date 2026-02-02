use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, error, debug, warn};
use rand::Rng;

pub struct RtpRelay {
    pub local_port: u16,
    // Bu alan drop edildiğinde 'tx' kanalı kapanır, bu da 'rx' tarafında 
    // döngünün bitmesini sağlar. Dolayısıyla mantıksal olarak kullanılıyor.
    #[allow(dead_code)] 
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
        let mut rng = rand::thread_rng();
        
        // Port tükenmesini önlemek için maksimum deneme sayısı
        for _ in 0..500 { 
            let port = rng.gen_range(self.start_port..self.end_port);
            // RTP portları çift sayı olmalıdır (RFC 3550 Recommendation)
            let port = if port % 2 != 0 { port + 1 } else { port };
            
            if port > self.end_port { continue; }

            if !relays.contains_key(&port) {
                // Port müsait, rezerve et.
                let (tx, _) = tokio::sync::broadcast::channel(1);
                
                let relay = RtpRelay {
                    local_port: port,
                    stop_signal: tx.clone(),
                };
                
                // HashMap'e ekle (Clonelayıp engine'e geri referans veremeyiz, bu yüzden portu kopyalıyoruz)
                let active_relays_clone = self.active_relays.clone();
                let port_clone = port;

                // Background Task Başlat
                let stop_rx = tx.subscribe();
                tokio::spawn(async move {
                    // Task bittiğinde map'ten temizlemek için bir mekanizma
                    if let Err(e) = run_relay_loop(port_clone, stop_rx).await {
                        error!("🔥 RTP Relay Error on port {}: {}", port_clone, e);
                    }
                    // Temizlik (Cleanup)
                    let mut guard = active_relays_clone.lock().await;
                    guard.remove(&port_clone);
                    info!("♻️ RTP Port {} released and cleaned up.", port_clone);
                });

                relays.insert(port, relay);
                info!("🎤 RTP Relay Allocated: Port {}", port);
                return Some(port);
            }
        }
        
        error!("❌ RTP Port Allocation FAILED. No available ports in range {}-{}", self.start_port, self.end_port);
        None
    }
}

async fn run_relay_loop(port: u16, mut stop_signal: tokio::sync::broadcast::Receiver<()>) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    let mut buf = [0u8; 4096]; // MTU için güvenli boyut

    // Latching State
    let mut peer_a: Option<SocketAddr> = None; // Genellikle Operator (Dış)
    let mut peer_b: Option<SocketAddr> = None; // Genellikle UAS (İç)
    
    // Silence Timeout: 60 saniye boyunca paket gelmezse portu kapat.
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
                        // --- LATCHING LOGIC (STRICT) ---
                        // İlk gelen paket peer_a olur.
                        // peer_a'dan gelmeyen ilk farklı paket peer_b olur.
                        // Üçüncü bir IP'den paket gelirse DROP edilir (Güvenlik).
                        
                        let target = if Some(src) == peer_a {
                            peer_b
                        } else if Some(src) == peer_b {
                            peer_a
                        } else {
                            // Yeni bir kaynak
                            if peer_a.is_none() {
                                info!("🔒 RTP Latch A (First Peer): {} on port {}", src, port);
                                peer_a = Some(src);
                                None // Hedef henüz yok, paketi tutamayız (Bufferlanabilir ama şimdilik drop)
                            } else if peer_b.is_none() {
                                info!("🔒 RTP Latch B (Second Peer): {} on port {}", src, port);
                                peer_b = Some(src);
                                peer_a // Hedef A'dır
                            } else {
                                // Saldırı veya IP değişimi girişimi
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
                    Err(_) => { // Timeout
                        info!("💤 RTP Timeout (Silence). Closing port {}", port);
                        break;
                    }
                }
            }
        }
    }
    
    Ok(())
}