// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Header, Method}; 
use sentiric_sip_core::utils as sip_utils;
use std::sync::Arc;
use std::net::SocketAddr;
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine; // [DÜZELTME]: Doğru import
use crate::sip::handlers::security::SecurityHandler;
use crate::sip::handlers::packet::PacketHandler;
use crate::sip::handlers::media::MediaHandler;
use tracing::debug;

pub enum SipAction {
    Forward(SipPacket),
    Drop,
}

pub struct SbcEngine {
    security: SecurityHandler,
    media: MediaHandler,
    rtp_engine: Arc<RtpEngine>,
    config: Arc<AppConfig>,
}

impl SbcEngine {
    pub fn new(config: Arc<AppConfig>, rtp_engine: Arc<RtpEngine>) -> Self {
        Self {
            security: SecurityHandler::new(1000), 
            media: MediaHandler::new(config.clone(), rtp_engine.clone()),
            rtp_engine,
            config,
        }
    }

    pub async fn inspect(&self, mut packet: SipPacket, src_addr: SocketAddr) -> SipAction {
        if !self.security.check_access(src_addr.ip()) { return SipAction::Drop; }
        
        if packet.is_request() {
            if !PacketHandler::sanitize(&packet) { return SipAction::Drop; }
            SipRouter::fix_nat_via(&mut packet, src_addr);
            self.fix_request_uri_for_internal(&mut packet);
            if !self.media.process_sdp(&mut packet).await { return SipAction::Drop; }
        } 
        
        if packet.is_response() {
            if !self.media.process_sdp(&mut packet).await { return SipAction::Drop; }
            self.apply_nuclear_sanitization(&mut packet);
        }

        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            let _ = self.rtp_engine.release_relay_by_call_id(&call_id).await;
        }
        
        SipAction::Forward(packet)
    }

    fn apply_nuclear_sanitization(&self, packet: &mut SipPacket) {
        let public_ip = &self.config.sip_public_ip;
        let public_port = self.config.sip_advertised_port;

        let mut vias_found = 0;
        let mut headers_to_keep = Vec::new();
        
        for h in packet.headers.iter().rev() {
            if h.name == HeaderName::Via {
                vias_found += 1;
                if vias_found == 1 { headers_to_keep.push(h.clone()); }
            } else if h.name != HeaderName::RecordRoute && h.name != HeaderName::Route && 
                      h.name != HeaderName::Contact && h.name != HeaderName::Server &&
                      h.name != HeaderName::UserAgent {
                headers_to_keep.push(h.clone());
            }
        }
        
        packet.headers = headers_to_keep.into_iter().rev().collect();
        packet.headers.insert(0, Header::new(HeaderName::RecordRoute, format!("<sip:{}:{};lr>", public_ip, public_port)));
        packet.headers.push(Header::new(HeaderName::Contact, format!("<sip:b2bua@{}:{}>", public_ip, public_port)));
        packet.headers.push(Header::new(HeaderName::Server, "Sentiric-SBC".to_string()));
        debug!("🛡️ [NUCLEAR] Topoloji gizlendi.");
    }

    fn fix_request_uri_for_internal(&self, packet: &mut SipPacket) {
        let user = sip_utils::extract_username_from_uri(&packet.uri);
        if user != "b2bua" { return; }
        let internal_port = self.config.b2bua_internal_port;
        let public_port_str = format!(":{}", self.config.sip_advertised_port);
        if packet.uri.contains(&public_port_str) || !packet.uri.contains(':') {
            if packet.uri.contains(':') {
                packet.uri = packet.uri.replace(&public_port_str, &format!(":{}", internal_port));
            } else {
                packet.uri.push_str(&format!(":{}", internal_port));
            }
        }
    }
}