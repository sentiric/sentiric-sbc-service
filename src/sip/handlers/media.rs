// sentiric-sbc-service/src/sip/handlers/media.rs

use sentiric_sip_core::{SipPacket, HeaderName, Header, sdp::SdpManipulator};
use std::sync::Arc;
use crate::rtp::engine::RtpEngine;
use crate::config::AppConfig;
use tracing::{info, error};
use regex::Regex;

pub struct MediaHandler {
    rtp_engine: Arc<RtpEngine>,
    config: Arc<AppConfig>,
    rtcp_regex: Regex,
}

impl MediaHandler {
    pub fn new(config: Arc<AppConfig>, rtp_engine: Arc<RtpEngine>) -> Self {
        Self { 
            rtp_engine, 
            config,
            rtcp_regex: Regex::new(r"(?m)^a=rtcp:.*\r\n").unwrap(),
        }
    }

    pub async fn process_sdp(&self, packet: &mut SipPacket) -> bool {
        let call_id = match packet.get_header_value(HeaderName::CallId) {
            Some(cid) => cid.clone(),
            None => return true,
        };

        let has_sdp = !packet.body.is_empty() && 
                      packet.get_header_value(HeaderName::ContentType)
                            .map_or(false, |v| v.contains("application/sdp"));

        if !has_sdp { return true; }

        let relay_port = match self.rtp_engine.get_or_allocate_relay(&call_id).await {
            Some(port) => port,
            None => {
                error!("❌ RTP RELAY FAILURE: No ports available for Call-ID {}", call_id);
                return false;
            }
        };

        let advertise_ip = if packet.is_request {
            &self.config.sip_internal_ip 
        } else {
            &self.config.sip_public_ip
        };

        if let Some(new_body) = SdpManipulator::rewrite_connection_info(&packet.body, advertise_ip, relay_port) {
            let body_str = String::from_utf8_lossy(&new_body);
            
            // [FIX]: RTCP satırını silmek yerine GÜNCELLE.
            // a=rtcp:<PORT+1> IN IP4 <IP>
            // Eski satır varsa sil, sonra yenisini m=audio'dan sonra ekle.
            let clean_body = self.rtcp_regex.replace_all(&body_str, "");
            
            // RTCP satırını m=audio satırından hemen sonraya değil, a=sendrecv öncesine ekleyelim.
            // Basitçe body'nin sonuna eklemek de çalışır ama düzenli olsun.
            let rtcp_line = format!("a=rtcp:{} IN IP4 {}\r\n", relay_port + 1, advertise_ip);
            
            // Body string'e çevir ve ekle
            let final_body = format!("{}{}", clean_body, rtcp_line);
            
            packet.body = final_body.as_bytes().to_vec();

            packet.headers.retain(|h| h.name != HeaderName::ContentLength);
            packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
            
            info!(call_id, port = relay_port, "🎤 [SDP] Relay port fixed & RTCP rewritten to {}.", relay_port + 1);
        }

        true
    }
}