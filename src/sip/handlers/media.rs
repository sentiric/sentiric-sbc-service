// sentiric-sbc-service/src/sip/handlers/media.rs

use sentiric_sip_core::{SipPacket, HeaderName, Header, sdp::SdpManipulator};
use std::sync::Arc;
use crate::rtp::engine::RtpEngine;
use crate::config::AppConfig;
use tracing::{info, error, warn};
use regex::Regex;
use std::net::SocketAddr;

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

        if packet.body.is_empty() { return true; }

        let mut client_rtp_addr: Option<SocketAddr> = None;
        let sdp_str = String::from_utf8_lossy(&packet.body);
        let mut extracted_ip = "0.0.0.0";
        let mut extracted_port = 0u16;

        for line in sdp_str.lines() {
            if line.starts_with("c=IN IP4 ") { 
                extracted_ip = line[9..].trim(); 
            }
            if line.starts_with("m=audio ") {
                extracted_port = line.split_whitespace().nth(1).and_then(|p| p.parse().ok()).unwrap_or(0);
            }
        }

        if extracted_port > 0 && extracted_ip != "0.0.0.0" {
             client_rtp_addr = format!("{}:{}", extracted_ip, extracted_port).parse().ok();
        } else if extracted_ip == "0.0.0.0" {
            warn!("⚠️ [SDP-AUDIT] 0.0.0.0 detected from client {}. Symmetric RTP Latching enabled.", call_id);
        }

        let relay_port = match self.rtp_engine.get_or_allocate_relay(&call_id, client_rtp_addr).await {
            Some(port) => port,
            None => {
                error!("❌ RTP RELAY FAILURE: No ports available for Call-ID {}", call_id);
                return false;
            }
        };

        let advertise_ip = if packet.is_request() {
            &self.config.sip_internal_ip 
        } else {
            &self.config.sip_public_ip
        };

        if let Some(new_body) = SdpManipulator::rewrite_connection_info(&packet.body, advertise_ip, relay_port) {
            let body_str = String::from_utf8_lossy(&new_body);
            
            // [CRITICAL FIX]: RTCP satırını temizle ve YENİSİNİ EKLEME.
            // Dinlemediğimiz portu (port+1) ilan edersek istemci ICMP Port Unreachable alır ve kopar.
            let clean_body = self.rtcp_regex.replace_all(&body_str, "");
            
            // RTCP satırı eklemiyoruz. Sadece temiz body.
            let final_body = clean_body.to_string();
            
            packet.body = final_body.as_bytes().to_vec();
            
            packet.headers.retain(|h| h.name != HeaderName::ContentLength);
            packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
            
            info!(call_id, port = relay_port, "🎤 [SDP-FIX] IP forced to {} (RTCP disabled).", advertise_ip);
        }

        true
    }
}