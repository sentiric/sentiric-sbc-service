// sentiric-sbc-service/src/sip/server.rs

use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use anyhow::Result;
use sentiric_sip_core::{parser, SipTransport, SipPacket, HeaderName, SipRouter};
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
    pub async fn new(
        config: Arc<AppConfig>,
        proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
    ) -> Result<Self> {
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
        info!("📡 SBC SIP Listener Active: {}:{}", self.config.sip_bind_ip, self.config.sip_port);
        
        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => { 
                    info!("🛑 SIP Server shutdown signal received.");
                    break; 
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            if len < 4 || (len <= 4 && buf[..len].iter().all(|&b| b == b'\r' || b == b'\n')) { continue; }
                            
                            match parser::parse(&buf[..len]) {
                                Ok(packet) => {
                                    if let SipAction::Forward(mut processed_packet) = self.engine.inspect(packet, src_addr).await {
                                        self.route_packet(&mut processed_packet, src_addr).await;
                                    }
                                },
                                Err(e) => warn!("⚠️ Malformed SIP packet from {}: {}", src_addr, e),
                            }
                        },
                        Err(e) => error!("🔥 UDP Socket Error: {}", e),
                    }
                }
            }
        }
    }

    async fn route_packet(&self, packet: &mut SipPacket, src_addr: SocketAddr) {
        let target_addr = if packet.is_request {
            let method = packet.method.to_string();
            let to_header = packet.get_header_value(HeaderName::To).cloned().unwrap_or_default();
            let dest_uri = sentiric_sip_core::utils::extract_aor(&to_header);

            // [v1.15.0 ALIGNMENT] `From` başlığını ayıkla
            let from_uri = packet.get_header_value(HeaderName::From).cloned().unwrap_or_default();

            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: dest_uri,
                source_ip: src_addr.ip().to_string(),
                method,
                from_uri, // Yeni kontrata göre doldur
            });

            match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => {
                    SipRouter::add_via(packet, &self.config.sip_public_ip, self.config.sip_port, "UDP");
                    let r = res.into_inner();
                    if !r.uri.is_empty() {
                        tokio::net::lookup_host(r.uri).await.ok().and_then(|mut i| i.next())
                    } else { None }
                },
                Err(e) => { error!("🔥 Proxy RPC Failed: {}", e); None }
            }
        } else { 
            if SipRouter::strip_top_via(packet).is_none() { return; }
            packet.get_header_value(HeaderName::Via)
                  .and_then(|v| SipRouter::resolve_response_target(v, DEFAULT_SIP_PORT))
        };

        if let Some(target) = target_addr {
            if let Err(e) = self.transport.send(&packet.to_bytes(), target).await {
                error!("🔥 Failed to send to {}: {}", target, e);
            }
        } else {
            warn!("⚠️ Could not resolve target address for packet. Dropping.");
        }
    }
}