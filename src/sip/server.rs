// sentiric-sbc-service/src/sip/server.rs

use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use anyhow::Result;
use sentiric_sip_core::{parser, SipTransport, SipPacket, HeaderName, SipRouter, builder::SipResponseFactory, Method}; // Method Eklendi
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};
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
        info!("📡 SBC (Iron Core v2.3 - Fixed Routing) Listener Active: {}:{}", self.config.sip_bind_ip, self.config.sip_port);
        
        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => { 
                    info!("🛑 SBC shut down gracefully.");
                    break; 
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            if len < 4 { continue; }
                            let data = &buf[..len];

                            match parser::parse(data) {
                                Ok(packet) => {
                                    if packet.is_request && packet.method == Method::Invite {
                                        let trying = SipResponseFactory::create_100_trying(&packet);
                                        let _ = self.transport.send(&trying.to_bytes(), src_addr).await;
                                    }

                                    if let SipAction::Forward(mut processed_packet) = self.engine.inspect(packet, src_addr).await {
                                        self.route_packet(&mut processed_packet, src_addr).await;
                                    }
                                },
                                Err(e) => warn!("⚠️ Malformed packet from {}: {}", src_addr, e),
                            }
                        },
                        Err(e) => error!("🔥 Socket Critical Error: {}", e),
                    }
                }
            }
        }
    }


async fn route_packet(&self, packet: &mut SipPacket, src_addr: SocketAddr) {
        let target_addr = if packet.is_request {
            let method = packet.method.to_string();
            
            // Request-URI üzerinden yönlendirme (Doğru hedef tespiti)
            let dest_uri = packet.uri.clone();
            let from_uri = packet.get_header_value(HeaderName::From).cloned().unwrap_or_default();

            // [FIX]: Proxy'ye bu paketin bir diyalog içi (ACK, BYE, CANCEL) paket olup olmadığını söylemeliyiz.
            let is_in_dialog = matches!(packet.method, Method::Ack | Method::Bye | Method::Cancel);

            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: dest_uri,
                source_ip: src_addr.ip().to_string(),
                method,
                from_uri,
                is_in_dialog,
            });

            match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => {
                    SipRouter::add_via(packet, &self.config.sip_public_ip, self.config.sip_port, "UDP");
                    let r = res.into_inner();
                    if !r.uri.is_empty() {
                        // [GÜÇLENDİRİLMİŞ LOGLAMA - DNS KONTROLÜ]
                        match tokio::net::lookup_host(&r.uri).await {
                            Ok(mut iter) => {
                                if let Some(addr) = iter.next() {
                                    info!("🎯 [YÖNLENDİRME] Hedef Çözümlendi: {} -> {}", r.uri, addr);
                                    Some(addr)
                                } else {
                                    error!("❌ [YÖNLENDİRME] DNS Boş Döndü: {}", r.uri);
                                    None
                                }
                            }
                            Err(e) => {
                                error!("❌ [YÖNLENDİRME] DNS Hatası ({}): {}", r.uri, e);
                                None
                            }
                        }
                    } else { 
                        warn!("⚠️ [YÖNLENDİRME] Proxy boş bir URI döndü");
                        None 
                    }
                },
                Err(e) => { error!("🔥 [YÖNLENDİRME] Proxy gRPC Çağrısı Başarısız: {}", e); None }
            }
        } else { 
            // Yanıt yönlendirmesi (Response routing)
            if SipRouter::strip_top_via(packet).is_none() { return; }
            packet.get_header_value(HeaderName::Via)
                  .and_then(|v| SipRouter::resolve_response_target(v, DEFAULT_SIP_PORT))
        };

        if let Some(target) = target_addr {
            info!("📤 [SIP-DIŞI] {} isteği şuraya gönderiliyor: {}", packet.method, target);
            if let Err(e) = self.transport.send(&packet.to_bytes(), target).await {
                error!("🔥 [SIP-DIŞI] Gönderim başarısız ({}): {}", target, e);
            }
        }
    }

}