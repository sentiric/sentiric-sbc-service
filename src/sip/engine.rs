// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, HeaderName, Header, SipRouter, sdp::SdpManipulator};
use tracing::{warn, debug, info, error};
use std::sync::Arc;
use crate::sip::security::SecurityGuard;
use std::net::SocketAddr;
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine;

pub enum SipAction {
    Forward(SipPacket),
    Drop,
}

pub struct SbcEngine {
    security: Arc<SecurityGuard>,
    rtp_engine: Arc<RtpEngine>,
    config: Arc<AppConfig>,
}

impl SbcEngine {
    pub fn new(config: Arc<AppConfig>, rtp_engine: Arc<RtpEngine>) -> Self {
        SbcEngine {
            security: Arc::new(SecurityGuard::new(500)),
            rtp_engine,
            config,
        }
    }

    pub async fn inspect(&self, mut packet: SipPacket, src_addr: SocketAddr) -> SipAction {
        if !self.security.is_allowed(src_addr.ip()) {
            return SipAction::Drop;
        }

        if packet.is_request && !self.is_request_sane(&packet) {
            warn!("🚫 SECURITY: Malicious User-Agent/Method/Max-Forwards detected from {}", src_addr);
            self.security.ban_ip(src_addr.ip(), "Malicious UA/Method".to_string());
            return SipAction::Drop;
        }

        if packet.is_request {
            SipRouter::fix_nat_via(&mut packet, src_addr);
        }
        
        if let Some(new_body) = self.handle_media(&packet).await {
            packet.body = new_body;
            packet.headers.retain(|h| h.name != HeaderName::ContentLength);
            packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
        }
        
        if packet.method == sentiric_sip_core::Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            if self.rtp_engine.release_relay_by_call_id(&call_id).await {
                debug!("♻️ Relay session cleaned for Call-ID: {}", call_id);
            }
        }
        
        SipAction::Forward(packet)
    }

    async fn handle_media(&self, packet: &SipPacket) -> Option<Vec<u8>> {
        let call_id = packet.get_header_value(HeaderName::CallId)?.clone();
        let has_sdp = packet.body.len() > 0 && 
                      packet.get_header_value(HeaderName::ContentType)
                            .map_or(false, |v| v.contains("application/sdp"));

        if !has_sdp { return None; }
        
        let relay_port = self.rtp_engine.get_or_allocate_relay(&call_id).await.unwrap_or(0);
        
        if relay_port > 0 {
            let advertise_ip = if packet.is_request {
                &self.config.sip_internal_ip 
            } else {
                &self.config.sip_public_ip
            };

            info!(call_id = %call_id, port = relay_port, "🎤 [SBC-MEDIA] SDP Rewritten with Sticky Port");
            return SdpManipulator::rewrite_connection_info(&packet.body, advertise_ip, relay_port);
        } else {
            error!("❌ RTP Port allocation failed for Call-ID: {}", call_id);
        }

        None
    }

    fn is_request_sane(&self, packet: &SipPacket) -> bool {
        if let Some(ua) = packet.get_header_value(HeaderName::UserAgent) {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("friendly-scanner") || ua_lower.contains("sipvicious") {
                return false;
            }
        }

        if let Some(mf) = packet.get_header_value(HeaderName::MaxForwards) {
            if let Ok(val) = mf.parse::<i32>() {
                if val <= 0 { return false; }
            }
        }
        true
    }
}