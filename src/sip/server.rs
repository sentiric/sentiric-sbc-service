// sentiric-sbc-service/src/sip/server.rs

use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use anyhow::{Context, Result};
use sentiric_sip_core::{parser, SipTransport, SipPacket, HeaderName, SipRouter, builder::SipResponseFactory, Method};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn, debug};
// [SİLİNDİ] gRPC bağımlılıkları
// use tonic::transport::Channel;
// use sentiric_contracts::sentiric::sip::v1::{proxy_service_client::ProxyServiceClient, GetNextHopRequest};

pub const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    // [DEĞİŞTİ] Proxy'nin gRPC istemcisi yerine çözümlenmiş SIP adresi
    proxy_target_addr: SocketAddr,
}

impl SipServer {
    // [DEĞİŞTİ] Artık gRPC istemcisi almıyor.
    pub async fn new(config: Arc<AppConfig>) -> Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        let rtp_engine = Arc::new(RtpEngine::new(config.rtp_start_port, config.rtp_end_port));
        
        // [YENİ] Başlangıçta proxy'nin adresini DNS'ten çöz.
        let proxy_target_addr = tokio::net::lookup_host(&config.proxy_sip_addr)
            .await?
            .next()
            .context("Proxy SIP hedefi çözümlenemedi")?;
        info!("🎯 Dahili SIP hedefi kilitlendi: {}", proxy_target_addr);

        Ok(Self {
            config: config.clone(),
            transport: Arc::new(transport),
            engine: SbcEngine::new(config, rtp_engine),
            proxy_target_addr,
        })
    }
    
    pub async fn run(self, mut shutdown_rx: mpsc::Receiver<()>) {
        info!("📡 SBC Aktif (Symmetric Mode): {}:{}", self.config.sip_bind_ip, self.config.sip_port);
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
                                        self.route_packet(&mut processed).await;
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

    async fn route_packet(&self, packet: &mut SipPacket) {
        let target_addr = if packet.is_request {
            // İSTEK YÖNLENDİRME (Dışarıdan -> İçeriye)
            // Artık gRPC yok, pakete kendi Via başlığımızı ekleyip doğrudan proxy'ye gönderiyoruz.
            SipRouter::add_via(packet, &self.config.sip_internal_ip, self.config.sip_port, "UDP");
            Some(self.proxy_target_addr)
        } else { 
            // YANIT YÖNLENDİRME (İçeriden -> Dışarıya)
            // Kendi Via başlığımızı (izimizi) siliyoruz.
            // Yanıtın en üstünde istemcinin (Baresip) kendi Via'sı kalmalı.
            SipRouter::strip_top_via(packet);
            
            packet.get_header_value(HeaderName::Via)
                  .and_then(|v| SipRouter::resolve_response_target(v, DEFAULT_SIP_PORT))
        };

        if let Some(target) = target_addr {
            let packet_bytes = packet.to_bytes();
            debug!("📤 [SBC-ROUTE] SIP Packet Forwarding: {} -> {}", packet.method, target);
            if let Err(e) = self.transport.send(&packet_bytes, target).await {
                error!("🔥 SIP paketi gönderilemedi {}: {}", target, e);
            }
        } else {
            warn!("⚠️ Rota bulunamadı, paket atlandı. Method: {}", packet.method);
        }
    }

}