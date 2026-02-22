// src/sip/server.rs
use crate::config::AppConfig;
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use anyhow::{Context, Result};
use sentiric_sip_core::{parser, SipTransport, SipPacket, HeaderName, SipRouter, builder::SipResponseFactory, Method};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn}; 

pub const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    _proxy_target_addr: SocketAddr, 
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
        
        info!(
            event = "SIP_CONFIG_LOADED",
            proxy.target = %proxy_target_addr,
            sip.bind = %bind_addr,
            "SBC SIP Konfigürasyonu yüklendi"
        );

        Ok(Self {
            config: config.clone(),
            transport: Arc::new(transport),
            engine: SbcEngine::new(config, rtp_engine),
            _proxy_target_addr: proxy_target_addr,
        })
    }
    
    pub async fn run(self, mut shutdown_rx: mpsc::Receiver<()>) {
        info!(
            event = "SIP_SERVER_ACTIVE",
            bind_ip = %self.config.sip_bind_ip,
            port = self.config.sip_port,
            protocol = "UDP",
            "📡 SBC Sinyalleşme Sunucusu Aktif"
        );
        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            if len < 4 { continue; }
                            
                            if len <= 4 && buf[..len].iter().all(|&b| b == b'\r' || b == b'\n' || b == 0) {
                                continue;
                            }

                            let data = &buf[..len];

                            match parser::parse(&buf[..len]) {
                                Ok(packet) => {
                                    let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
                                    let method = packet.method.as_str();

                                    // [KRİTİK DÜZELTME]: 100 Trying Yanıtının Loglanması (ECO-SIP-002)
                                    if packet.is_request && packet.method == Method::Invite {
                                        let trying_packet = SipResponseFactory::create_100_trying(&packet);
                                        let trying_bytes = trying_packet.to_bytes();
                                        
                                        info!(
                                            event = "SIP_EGRESS",
                                            sip.call_id = %call_id,
                                            sip.method = "100",
                                            net.dst.ip = %src_addr.ip(),
                                            net.dst.port = src_addr.port(),
                                            packet.summary = "SIP/2.0 100 Trying",
                                            "📤 [SBC->UAC] 100 Trying gönderildi"
                                        );

                                        let _ = self.transport.send(&trying_bytes, src_addr).await;
                                    }
                                    
                                    // INGRESS LOG
                                    debug!(
                                        event = "SIP_PACKET_RECEIVED",
                                        sip.call_id = %call_id,
                                        sip.method = %method,
                                        net.src.ip = %src_addr.ip(),
                                        net.src.port = src_addr.port(),
                                        "📥 SIP paketi alındı"
                                    );
                                    
                                    // Engine Inspection
                                    if let SipAction::Forward(mut processed) = self.engine.inspect(packet, src_addr).await {
                                        self.route_packet(&mut processed, src_addr).await;
                                    }
                                },
                                Err(e) => warn!(
                                    event = "SIP_PARSE_ERROR",
                                    net.peer.ip = %src_addr.ip(),
                                    error = %e,
                                    "⚠️ Bozuk veya geçersiz SIP paketi alındı"
                                ),
                            }
                        },
                        Err(e) => error!(event="SIP_SOCKET_ERROR", error=%e, "🔥 UDP Socket okuma hatası"),
                    }
                }
            }
        }
    }

    async fn route_packet(&self, packet: &mut SipPacket, _src_addr: SocketAddr) {
        let target_addr = if packet.is_request() {
            tokio::net::lookup_host(&self.config.proxy_sip_addr).await.ok().and_then(|mut i| i.next())
        } else { 
            SipRouter::strip_top_via(packet);
            packet.get_header_value(HeaderName::Via)
                  .and_then(|v| SipRouter::resolve_response_target(v, DEFAULT_SIP_PORT))
        };

        if let Some(target) = target_addr {
            let packet_bytes = packet.to_bytes();
            let debug_line = String::from_utf8_lossy(&packet_bytes[..packet_bytes.len().min(50)]);
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            let method = packet.method.as_str();

            // EGRESS LOG
            info!(
                event = "SIP_EGRESS",
                sip.call_id = %call_id,
                sip.method = %method,
                net.dst.ip = %target.ip(),
                net.dst.port = target.port(),
                packet.summary = %debug_line.trim_end(),
                "📤 [SBC->NEXT] Paket yönlendiriliyor"
            );

            if let Err(e) = self.transport.send(&packet_bytes, target).await {
                error!(
                    event = "SIP_SEND_ERROR",
                    sip.call_id = %call_id,
                    net.dst.ip = %target.ip(),
                    error = %e,
                    "🔥 SIP paketi hedefe gönderilemedi"
                );
            }
        }
    }
}