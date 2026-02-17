// sentiric-sbc-service/src/sip/server.rs

use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use anyhow::Result;
use sentiric_sip_core::{parser, SipTransport, SipPacket, HeaderName, SipRouter, builder::SipResponseFactory, Method};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn, debug};

pub const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
}

impl SipServer {
    pub async fn new(config: Arc<AppConfig>) -> Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        let rtp_engine = Arc::new(RtpEngine::new(config.rtp_start_port, config.rtp_end_port));
        
        Ok(Self {
            config: config.clone(),
            transport: Arc::new(transport),
            engine: SbcEngine::new(config, rtp_engine),
        })
    }
    
    pub async fn run(self, mut shutdown_rx: mpsc::Receiver<()>) {
        info!("📡 SBC Aktif (Strict Mode): {}:{}", self.config.sip_bind_ip, self.config.sip_port);
        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            if len < 4 { continue; }
                            match parser::parse(&buf[..len]) {
                                Ok(packet) => {
                                    if packet.is_request && packet.method == Method::Invite {
                                        let _ = self.transport.send(&SipResponseFactory::create_100_trying(&packet).to_bytes(), src_addr).await;
                                    }
                                    if let SipAction::Forward(mut processed) = self.engine.inspect(packet, src_addr).await {
                                        self.route_packet(&mut processed, src_addr).await;
                                    }
                                },
                                Err(e) => warn!("⚠️ Bozuk paket: {}", e),
                            }
                        },
                        Err(e) => error!("🔥 Socket hatası: {}", e),
                    }
                }
            }
        }
    }

    async fn route_packet(&self, packet: &mut SipPacket, _src_addr: SocketAddr) {
        let target_addr = if packet.is_request() {
            // İSTEK YÖNLENDİRME (Dış -> İç)
            packet.headers.retain(|h| h.name != HeaderName::Route && h.name != HeaderName::RecordRoute);
            SipRouter::add_via(packet, &self.config.sip_public_ip, self.config.sip_port, "UDP");

            // Proxy hedefini DNS üzerinden çöz (Asenkron)
            tokio::net::lookup_host(&self.config.proxy_sip_addr).await.ok().and_then(|mut i| i.next())
        } else { 
            // YANIT YÖNLENDİRME (İç -> Dış)
            SipRouter::strip_top_via(packet);
            packet.get_header_value(HeaderName::Via)
                  .and_then(|v| SipRouter::resolve_response_target(v, DEFAULT_SIP_PORT))
        };

        if let Some(target) = target_addr {
            let packet_bytes = packet.to_bytes();
            debug!("📤 [SBC-EGRESS] {} -> {}", packet.method, target);
            if let Err(e) = self.transport.send(&packet_bytes, target).await {
                error!("🔥 SIP gönderim hatası {}: {}", target, e);
            }
        }
    }
}