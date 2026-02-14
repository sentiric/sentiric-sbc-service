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

        // [HARDENING]: Müşterinin RTP adresini SDP'den ayıkla.
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

        // Eğer IP 0.0.0.0 ise, Latching mekanizmasının devreye girmesi için adres None bırakılır,
        // ancak B2BUA'ya giden pakette adres SBC'nin IP'si olmalıdır.
        if extracted_port > 0 && extracted_ip != "0.0.0.0" {
             client_rtp_addr = format!("{}:{}", extracted_ip, extracted_port).parse().ok();
        } else if extracted_ip == "0.0.0.0" {
            warn!("⚠️ [SDP-AUDIT] 0.0.0.0 detected from client {}. Symmetric RTP Latching enabled.", call_id);
        }

        // Relay Port Tahsisi (Aday adres ile)
        let relay_port = match self.rtp_engine.get_or_allocate_relay(&call_id, client_rtp_addr).await {
            Some(port) => port,
            None => {
                error!("❌ RTP RELAY FAILURE: No ports available for Call-ID {}", call_id);
                return false;
            }
        };

        // Reklamı yapılacak (Advertise) IP'yi belirle:
        // Gelen INVITE ise (İçeriye gidiyor) -> İç IP (Tailscale)
        // Gelen OK ise (Dışarıya gidiyor) -> Dış IP (Public)
        let advertise_ip = if packet.is_request() {
            &self.config.sip_internal_ip 
        } else {
            &self.config.sip_public_ip
        };

        // SDP REWRITE: 0.0.0.0 dahil her şeyi ezer.
        if let Some(new_body) = SdpManipulator::rewrite_connection_info(&packet.body, advertise_ip, relay_port) {
            let body_str = String::from_utf8_lossy(&new_body);
            // Eski RTCP satırını temizle ve yenisini ekle (Standard: RTP_PORT + 1)
            let clean_body = self.rtcp_regex.replace_all(&body_str, "");
            let rtcp_line = format!("a=rtcp:{} IN IP4 {}\r\n", relay_port + 1, advertise_ip);
            let final_body = format!("{}{}", clean_body, rtcp_line);
            
            packet.body = final_body.as_bytes().to_vec();
            
            // Content-Length güncelle
            packet.headers.retain(|h| h.name != HeaderName::ContentLength);
            packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
            
            info!(call_id, port = relay_port, "🎤 [SDP-FIX] IP forced to {} for Call Leg.", advertise_ip);
        }

        true
    }
}