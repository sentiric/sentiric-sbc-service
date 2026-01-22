// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn}; // 'debug' kaldırıldı
use sentiric_sip_core::{SipTransport, parser, SipPacket, HeaderName};
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
                                        SipAction::Forward => self.handle_forwarding(packet, src_addr).await,
                                        SipAction::Drop => warn!("Packet dropped from {}", src_addr),
                                    }
                                },
                                Err(e) => if len > 4 { warn!("Malformed SIP: {}", e); }
                            }
                        },
                        Err(e) => error!("UDP Error: {}", e),
                    }
                }
            }
        }
    }

    async fn handle_forwarding(&self, mut packet: SipPacket, src_addr: SocketAddr) {
        let target_addr = if packet.is_request {
            if let Some(via_header) = packet.headers.iter_mut().find(|h| h.name == HeaderName::Via) {
                if !via_header.value.contains("received=") {
                    via_header.value.push_str(&format!(";received={}", src_addr.ip()));
                }
                if !via_header.value.contains("rport=") {
                     via_header.value.push_str(&format!(";rport={}", src_addr.port()));
                }
            }

            match self.resolve_proxy_addr().await {
                Some(addr) => {
                    let via_val = format!("SIP/2.0/UDP {}:{};branch=z9hG4bK-sbc-{}", 
                        self.config.sip_public_ip, 
                        self.config.sip_port,
                        rand::random::<u32>()
                    );
                    packet.headers.insert(0, sentiric_sip_core::Header::new(
                        HeaderName::Via, 
                        via_val
                    ));
                    Some(addr)
                },
                None => None,
            }
        } else {
            if !packet.headers.is_empty() && packet.headers[0].name == HeaderName::Via {
                packet.headers.remove(0);
            }
            if let Some(client_via) = packet.headers.iter().find(|h| h.name == HeaderName::Via) {
                self.parse_via_address(&client_via.value)
            } else {
                warn!("Response packet missing Via header");
                None
            }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            if let Err(e) = self.transport.send(&data, target).await {
                error!("Failed to forward packet to {}: {}", target, e);
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
    
    // [FIX] Borrow checker hatası çözüldü
    fn parse_via_address(&self, via_val: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = via_val.split_whitespace().collect();
        if parts.len() < 2 { return None; }
        
        let mut host_part = parts[1].split(';').next()?.to_string();
        
        // Ödünç alma sorununu çözmek için geçici değişkenler kullan
        let (temp_host, temp_port) = if let Some((h, p)) = host_part.rsplit_once(':') {
            (h.to_string(), p.to_string())
        } else {
            (host_part, "5060".to_string())
        };

        let mut host_str = temp_host;
        let mut port_str = temp_port;

        for param in via_val.split(';') {
            let p_trim = param.trim();
            if let Some((k, v)) = p_trim.split_once('=') {
                if k == "received" {
                    host_str = v.to_string();
                }
                if k == "rport" {
                    port_str = v.to_string();
                }
            }
        }

        format!("{}:{}", host_str, port_str).parse().ok()
    }
}