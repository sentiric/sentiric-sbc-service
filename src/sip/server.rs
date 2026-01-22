// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn, debug};
use sentiric_sip_core::{SipTransport, parser, SipPacket};
use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};
use tokio::net::lookup_host;
use std::net::SocketAddr;

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
        info!("🎯 Default Forwarding Target (Proxy): {}", self.config.proxy_sip_addr);

        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("🛑 SIP Server kapatılıyor...");
                    break;
                }
                
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            let data = &buf[..len];
                            
                            match parser::parse(data) {
                                Ok(packet) => {
                                    match self.engine.inspect(&packet) {
                                        SipAction::Drop => {
                                            warn!("Packet dropped from {}", src_addr);
                                            continue;
                                        },
                                        SipAction::Forward => {
                                            self.handle_forwarding(packet, src_addr).await;
                                        }
                                    }
                                },
                                Err(e) => {
                                    if len > 4 { 
                                        warn!("Malformed SIP packet from {}: {}", src_addr, e);
                                    }
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

    async fn handle_forwarding(&self, mut packet: SipPacket, _src_addr: SocketAddr) {
        // HEDEF BELİRLEME
        // 1. İstek (Request) ise -> İçeri (Proxy)
        // 2. Yanıt (Response) ise -> Dışarı (Client - Via başlığından bulunur)
        
        let target_addr = if packet.is_request {
            // --- INBOUND TRAFFIC (Client -> SBC -> Proxy) ---
            match self.resolve_proxy_addr().await {
                Some(addr) => {
                    // SBC, yanıtın kendine dönmesi için en üste kendi VIA başlığını ekler.
                    let via_val = format!("SIP/2.0/UDP {}:{};branch=z9hG4bK-sbc-{}", 
                        self.config.sip_public_ip, 
                        self.config.sip_port,
                        rand::random::<u32>()
                    );
                    packet.headers.insert(0, sentiric_sip_core::Header::new(
                        sentiric_sip_core::HeaderName::Via, 
                        via_val
                    ));
                    Some(addr)
                },
                None => None,
            }
        } else {
            // --- OUTBOUND TRAFFIC (Proxy -> SBC -> Client) ---
            // Proxy'den gelen yanıttır.
            
            // 1. Kendi eklediğimiz (en üstteki) Via başlığını siliyoruz. (Pop)
            if !packet.headers.is_empty() && packet.headers[0].name.as_str() == "Via" {
                packet.headers.remove(0);
            }

            // 2. Bir sonraki Via başlığı, paketin gitmesi gereken müşterinin adresidir.
            if let Some(client_via) = packet.headers.iter().find(|h| h.name.as_str() == "Via") {
                self.parse_via_address(&client_via.value)
            } else {
                warn!("Response packet has no Via header, cannot route back.");
                None
            }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            if let Err(e) = self.transport.send(&data, target).await {
                error!("Failed to forward packet to {}: {}", target, e);
            } else {
                debug!("Packet forwarded to {}", target);
            }
        }
    }

    async fn resolve_proxy_addr(&self) -> Option<SocketAddr> {
         match lookup_host(&self.config.proxy_sip_addr).await {
            Ok(mut addrs) => addrs.next(),
            Err(e) => {
                error!("DNS Resolution error for {}: {}", self.config.proxy_sip_addr, e);
                None
            }
        }
    }
    
    fn parse_via_address(&self, via_val: &str) -> Option<SocketAddr> {
        // Basit parser: "SIP/2.0/UDP 1.2.3.4:5060;..."
        // received ve rport parametreleri varsa (ki Proxy eklemiş olabilir) onları kullanmak en doğrusudur.
        // Ancak şu an SBC en dışta olduğu için, Client'ın Via'sındaki ham IP:Port'a gitmek zorundayız 
        // (veya received varsa ona).
        
        let parts: Vec<&str> = via_val.split_whitespace().collect();
        if parts.len() < 2 { return None; }
        
        let mut addr_str = parts[1].split(';').next()?.to_string();
        
        // received ve rport parametrelerini kontrol et
        for param in via_val.split(';') {
            if let Some((k, v)) = param.trim().split_once('=') {
                if k == "received" {
                    // Portu orijinal stringden koruyarak IP'yi güncelle (Basitleştirilmiş)
                    if let Some(colon) = addr_str.find(':') {
                         addr_str = format!("{}:{}", v, &addr_str[colon+1..]);
                    } else {
                         addr_str = format!("{}:5060", v);
                    }
                }
                if k == "rport" {
                    // rport varsa portu güncelle
                     if let Some(colon) = addr_str.rfind(':') {
                         addr_str = format!("{}:{}", &addr_str[..colon], v);
                     }
                }
            }
        }

        addr_str.parse().ok()
    }
}