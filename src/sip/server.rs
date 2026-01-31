// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tonic::transport::Channel;
use tracing::{info, error, debug, warn};
use sentiric_sip_core::{
    SipTransport, parser, SipPacket, HeaderName, Header, 
    utils as sip_utils,
    SipRouter,           
    sdp::SdpManipulator  
};
use crate::config::AppConfig;
use sentiric_contracts::sentiric::sip::v1::{proxy_service_client::ProxyServiceClient, GetNextHopRequest};
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use tokio::net::lookup_host;
use std::net::SocketAddr;

const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
    rtp_engine: Arc<RtpEngine>,
}

impl SipServer {
    pub async fn new(
        config: Arc<AppConfig>,
        proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
    ) -> anyhow::Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        let rtp_engine = Arc::new(RtpEngine::new(config.rtp_start_port, config.rtp_end_port));

        Ok(Self {
            config,
            transport: Arc::new(transport),
            engine: SbcEngine::new(),
            proxy_client,
            rtp_engine,
        })
    }

    pub async fn run(self, mut shutdown_rx: mpsc::Receiver<()>) {
        info!("📡 SBC SIP Listener: {}:{}", self.config.sip_bind_ip, self.config.sip_port);
        info!("🎤 SBC RTP Relay Range: {}-{}", self.config.rtp_start_port, self.config.rtp_end_port);
        
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
                            if len < 4 { continue; }
                            if len <= 4 && buf[..len].iter().all(|&b| b == b'\r' || b == b'\n') {
                                continue;
                            }

                            let data = &buf[..len];
                            match parser::parse(data) {
                                Ok(packet) => {
                                    match self.engine.inspect(&packet, src_addr) {
                                        SipAction::Forward => self.handle_forwarding(packet, src_addr).await,
                                        SipAction::Drop => {
                                            debug!("⛔ SIP Packet dropped from {}", src_addr);
                                        },
                                    }
                                },
                                Err(e) => {
                                    warn!("⚠️ Malformed SIP packet from {}: {}", src_addr, e);
                                }
                            }
                        },
                        Err(e) => {
                            error!("🔥 UDP Socket Error: {}", e);
                        },
                    }
                }
            }
        }
    }

    async fn handle_forwarding(&self, mut packet: SipPacket, src_addr: SocketAddr) {
        let method = packet.method.to_string();
        
        // --- RTP RELAY LOGIC (Man-in-the-Middle) ---
        let has_sdp = packet.body.len() > 0 && 
                      packet.get_header_value(HeaderName::ContentType)
                            .map_or(false, |v| v.contains("application/sdp"));

        let is_invite_response = packet.status_code >= 100 && packet.status_code < 300 
                                 && packet.get_header_value(HeaderName::CSeq).map_or(false, |v| v.contains("INVITE"));

        if has_sdp && (method == "INVITE" || is_invite_response) {
            if let Some(relay_port) = self.rtp_engine.allocate_relay().await {
                // Request ise (Dışarıdan içeriye), Internal IP'yi advertise et.
                // Response ise (İçeriden dışarıya), Public IP'yi advertise et.
                let advertise_ip = if packet.is_request {
                    &self.config.sip_internal_ip 
                } else {
                    &self.config.sip_public_ip
                };

                if let Some(new_body) = SdpManipulator::rewrite_connection_info(&packet.body, advertise_ip, relay_port) {
                    packet.body = new_body;
                    info!("🎤 [SBC-MEDIA] SDP Rewritten: Advertise {} Port {}", advertise_ip, relay_port);
                    packet.headers.retain(|h| h.name != HeaderName::ContentLength);
                    packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
                }
            } else {
                error!("❌ RTP Port allocation failed! Call might drop audio.");
            }
        }

        // --- YÖNLENDİRME MANTIĞI ---
        let target_addr = if packet.is_request {
            // 1. Gelen Request: NAT Düzeltme ve Route Ekleme
            
            // [REFACTOR] Core fonksiyon kullanımı: fix_nat_via
            SipRouter::fix_nat_via(&mut packet, src_addr);
            
            if method == "INVITE" {
                // [REFACTOR] Core fonksiyon kullanımı: add_record_route
                SipRouter::add_record_route(&mut packet, &self.config.sip_public_ip, self.config.sip_port);
            }

            let to_header_val = packet.get_header_value(HeaderName::To).cloned().unwrap_or_default();
            let routing_destination = sip_utils::extract_aor(&to_header_val);
            
            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: routing_destination,
                source_ip: src_addr.ip().to_string(),
                method: method.clone(),
            });

            match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => {
                    let r = res.into_inner();
                    
                    // [REFACTOR] Core fonksiyon kullanımı: add_via
                    // SBC kendini via yığınına ekler
                    SipRouter::add_via(&mut packet, &self.config.sip_public_ip, self.config.sip_port, "UDP");
                    
                    if !r.uri.is_empty() {
                         self.resolve_address(&r.uri).await
                    } else { 
                        warn!("⚠️ Proxy service returned empty URI for destination.");
                        None 
                    }
                },
                Err(e) => {
                    error!("🔥 Proxy Service RPC Failed: {}", e);
                    None
                }
            }
        } else { 
            // 2. Gelen Response: Via stripping
            
            // [REFACTOR] Core fonksiyon kullanımı: strip_top_via
            if SipRouter::strip_top_via(&mut packet).is_none() {
                warn!("⚠️ Response received but no Via header found to strip.");
                return;
            }

            if let Some(client_via) = packet.headers.iter().find(|h| h.name == HeaderName::Via) {
                SipRouter::resolve_response_target(&client_via.value, DEFAULT_SIP_PORT)
            } else { 
                warn!("⚠️ Response has no second Via header, cannot route back.");
                None 
            }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            if let Err(e) = self.transport.send(&data, target).await {
                error!("🔥 Failed to send forwarded packet to {}: {}", target, e);
            }
        } else {
            warn!("⚠️ No routing target found for packet. Dropping.");
        }
    }

    async fn resolve_address(&self, address: &str) -> Option<SocketAddr> {
         if let Ok(addr) = address.parse::<SocketAddr>() {
             return Some(addr);
         }
         match lookup_host(address).await {
            Ok(mut addrs) => addrs.next(),
            Err(e) => {
                error!("DNS Resolution failed for {}: {}", address, e);
                None
            }
        }
    }
}