// sentiric-sbc-service/src/sip/server.rs

use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use anyhow::Result;
use sentiric_sip_core::{parser, SipTransport, SipPacket, HeaderName, SipRouter, builder::SipResponseFactory, Method};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn, debug};
use tonic::transport::Channel;
use sentiric_contracts::sentiric::sip::v1::{proxy_service_client::ProxyServiceClient, GetNextHopRequest};

pub const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
}

impl SipServer {
    pub async fn new(config: Arc<AppConfig>, proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>) -> Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        let rtp_engine = Arc::new(RtpEngine::new(config.rtp_start_port, config.rtp_end_port));
        
        Ok(Self {
            config: config.clone(),
            transport: Arc::new(transport),
            engine: SbcEngine::new(config, rtp_engine),
            proxy_client,
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

    async fn route_packet(&self, packet: &mut SipPacket, src_addr: SocketAddr) {
        let target_addr = if packet.is_request {
            // ... [İstek yönlendirme mantığı aynı kalıyor] ...
            let dest_uri = packet.uri.clone();
            let from_uri = packet.get_header_value(HeaderName::From).cloned().unwrap_or_default();
            let is_in_dialog = matches!(packet.method, Method::Ack | Method::Bye | Method::Cancel);
            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: dest_uri, source_ip: src_addr.ip().to_string(),
                method: packet.method.to_string(), from_uri, is_in_dialog,
            });

            match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => {
                    let r = res.into_inner();
                    SipRouter::add_via(packet, &self.config.sip_public_ip, self.config.sip_port, "UDP");
                    tokio::net::lookup_host(&r.uri).await.ok().and_then(|mut i| i.next())
                },
                Err(_) => None
            }
        } else { 
            // [KRİTİK DÜZELTME]: Yanıtlarda Via Silme
            // Kendi eklediğimiz Via başlığını siliyoruz ki istemci şaşırmasın.
            if SipRouter::strip_top_via(packet).is_none() {
                debug!("⚠️ Yanıtta silinecek Via bulunamadı.");
            }
            
            packet.get_header_value(HeaderName::Via)
                  .and_then(|v| SipRouter::resolve_response_target(v, DEFAULT_SIP_PORT))
        };

        if let Some(target) = target_addr {
            let _ = self.transport.send(&packet.to_bytes(), target).await;
        }
    }
}