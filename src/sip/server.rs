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

pub const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    proxy_target_addr: SocketAddr,
}

impl SipServer {
    pub async fn new(config: Arc<AppConfig>) -> Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        let rtp_engine = Arc::new(RtpEngine::new(config.rtp_start_port, config.rtp_end_port));
        
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
        info!("📡 SBC Aktif (Strict Topology Hiding): {}:{}", self.config.sip_bind_ip, self.config.sip_port);
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
            // İSTEK YÖNLENDİRME (Dış -> İç)
            SipRouter::add_via(packet, &self.config.sip_internal_ip, self.config.sip_port, "UDP");
            Some(self.proxy_target_addr)
        } else { 
            // [KRİTİK]: YANIT YÖNLENDİRME (İç -> Dış)
            // Error 71 ve 482 döngülerini bitiren "Nükleer Temizlik"
            
            // 1. İç ağa ait tüm kirliliği (Record-Route, Route) temizle.
            // Sadece SBC'nin Record-Route başlığı engine tarafında zaten eklendi.
            packet.headers.retain(|h| {
                if h.name == HeaderName::RecordRoute || h.name == HeaderName::Route {
                    // Sadece bizim dış IP'mizi içeren Record-Route kalabilir.
                    h.value.contains(&self.config.sip_public_ip)
                } else {
                    true
                }
            });

            // 2. Via başlıklarını temizle. 
            // RFC 3261: Yanıt yolunda sadece istemcinin Via'sı kalana kadar üsttekiler silinir.
            // Bizim mimarimizde üstte her zaman 2 Via olur (SBC ve Proxy).
            
            // En az bir Via kalana kadar ve en üstteki Via iç ağa ait olduğu sürece sil.
            loop {
                let via_count = packet.headers.iter().filter(|h| h.name == HeaderName::Via).count();
                if via_count <= 1 { break; } // Sadece 1 tane (istemcinin) kalsın.

                if let Some(top_via) = packet.get_header_value(HeaderName::Via) {
                    if top_via.contains("proxy-service") || 
                       top_via.contains("b2bua-service") || 
                       top_via.contains(&self.config.sip_internal_ip) ||
                       top_via.contains("10.88.") {
                        SipRouter::strip_top_via(packet);
                    } else {
                        break; 
                    }
                } else {
                    break;
                }
            }

            // 3. Hedefi istemcinin Via'sından çöz.
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