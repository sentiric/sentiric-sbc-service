// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use sentiric_sip_core::{SipTransport, parser};
use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
}

impl SipServer {
    pub async fn new(config: Arc<AppConfig>) -> anyhow::Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        
        Ok(Self {
            config,
            transport: Arc::new(transport),
            engine: SbcEngine::new(),
        })
    }

    pub async fn run(self, mut shutdown_rx: mpsc::Receiver<()>) {
        info!("📡 SBC SIP Listener aktif: {}:{}", self.config.sip_bind_ip, self.config.sip_port);
        info!("🎯 Forwarding Target (Proxy): {}", self.config.proxy_sip_addr);

        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("🛑 SIP Server kapatılıyor...");
                    break;
                }
                
                // SipTransport yerine raw socket kullanıyoruz çünkü performansı manuel yöneteceğiz
                // ve sip-core parser'ı ile entegre edeceğiz.
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            let data = &buf[..len];
                            
                            // 1. Parse
                            match parser::parse(data) {
                                Ok(mut packet) => {
                                    // 2. Inspect (Security)
                                    match self.engine.inspect(&packet) {
                                        SipAction::Drop => {
                                            warn!("Packet dropped from {}", src_addr);
                                            continue;
                                        },
                                        SipAction::Forward => {
                                            // 3. Sanitize
                                            self.engine.sanitize(&mut packet);
                                            
                                            // 4. Forward to Proxy
                                            // Orijinal paketi (veya sanitize edilmiş halini) proxy'ye ilet.
                                            // NOT: Şimdilik orijinal byte'ları gönderiyoruz, 
                                            // sanitize edilmiş byte'ları oluşturmak (re-serialize) maliyetli olabilir.
                                            // Ancak gerçek bir SBC'de packet.to_bytes() kullanılmalıdır.
                                            
                                            let forward_data = packet.to_bytes(); 
                                            
                                            if let Err(e) = self.transport.send(&forward_data, self.config.proxy_sip_addr).await {
                                                error!("Failed to forward packet to Proxy: {}", e);
                                            } else {
                                                // debug!("Forwarded {} bytes to Proxy", forward_data.len());
                                            }
                                        }
                                    }
                                },
                                Err(e) => {
                                    warn!("Malfromed SIP packet from {}: {}", src_addr, e);
                                }
                            }
                        },
                        Err(e) => {
                            error!("UDP Receive Error: {}", e);
                        }
                    }
                }
            }
        }
    }
}