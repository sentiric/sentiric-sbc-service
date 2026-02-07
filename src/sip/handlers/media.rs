// sentiric-sbc-service/src/sip/handlers/media.rs

use sentiric_sip_core::{SipPacket, HeaderName, Header, sdp::SdpManipulator};
use std::sync::Arc;
use crate::rtp::engine::RtpEngine;
use crate::config::AppConfig;
use tracing::{info, error};

pub struct MediaHandler {
    rtp_engine: Arc<RtpEngine>,
    config: Arc<AppConfig>,
}

impl MediaHandler {
    pub fn new(config: Arc<AppConfig>, rtp_engine: Arc<RtpEngine>) -> Self {
        Self { rtp_engine, config }
    }

    pub async fn process_sdp(&self, packet: &mut SipPacket) -> bool {
        let call_id = match packet.get_header_value(HeaderName::CallId) {
            Some(cid) => cid.clone(),
            None => return true,
        };

        // SDP var mı kontrol et
        let has_sdp = !packet.body.is_empty() && 
                      packet.get_header_value(HeaderName::ContentType)
                            .map_or(false, |v| v.contains("application/sdp"));

        if !has_sdp { return true; }

        // Sticky Port Allocation: Aynı Call-ID her zaman aynı portu alır
        let relay_port = match self.rtp_engine.get_or_allocate_relay(&call_id).await {
            Some(port) => port,
            None => {
                error!("❌ RTP RELAY FAILURE: No ports available for Call-ID {}", call_id);
                return false;
            }
        };

        // SDP Rewrite: IP ve Port bilgisini SBC'nin Relay adresiyle değiştir
        let advertise_ip = if packet.is_request {
            &self.config.sip_internal_ip 
        } else {
            &self.config.sip_public_ip
        };

        if let Some(new_body) = SdpManipulator::rewrite_connection_info(&packet.body, advertise_ip, relay_port) {
            packet.body = new_body;
            // Content-Length başlığını güncelle
            packet.headers.retain(|h| h.name != HeaderName::ContentLength);
            packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
            info!(call_id, port = relay_port, "🎤 [SDP] Relay port fixed to sticky session.");
        }

        true
    }
}