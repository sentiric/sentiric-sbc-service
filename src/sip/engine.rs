// sentiric-sbc-service/src/sip/engine.rs
use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Method, Header}; 
use std::sync::Arc;
use std::net::SocketAddr;
use dashmap::DashMap;
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine;
use crate::sip::handlers::security::SecurityHandler;
use crate::sip::handlers::packet::PacketHandler;
use crate::sip::handlers::media::MediaHandler;
use tracing::{warn, info, debug}; // [FIX]: debug eklendi

pub enum SipAction {
    Forward(SipPacket),
    Drop,
}

pub struct SbcEngine {
    security: SecurityHandler,
    media: MediaHandler,
    rtp_engine: Arc<RtpEngine>,
    inflight_requests: Arc<DashMap<String, std::time::Instant>>,
    config: Arc<AppConfig>,
}

impl SbcEngine {
    pub fn new(config: Arc<AppConfig>, rtp_engine: Arc<RtpEngine>) -> Self {
        Self {
            security: SecurityHandler::new(1000), 
            media: MediaHandler::new(config.clone(), rtp_engine.clone()),
            rtp_engine,
            inflight_requests: Arc::new(DashMap::new()),
            config,
        }
    }

    pub async fn inspect(&self, mut packet: SipPacket, src_addr: SocketAddr) -> SipAction {
        // [FIX]: spdlog -> tracing::debug
        debug!("📥 [SBC-IN] Packet from {}: {}", src_addr, packet.method);

        if !self.security.check_access(src_addr.ip()) {
            return SipAction::Drop;
        }

        if packet.is_request && packet.method == Method::Invite {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            let cseq = packet.get_header_value(HeaderName::CSeq).cloned().unwrap_or_default();
            let tx_key = format!("{}-{}", call_id, cseq);

            if self.inflight_requests.contains_key(&tx_key) {
                return SipAction::Drop; 
            }
            self.inflight_requests.insert(tx_key.clone(), std::time::Instant::now());
            
            let cache = self.inflight_requests.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                cache.remove(&tx_key);
            });
        }

        if packet.is_request && !PacketHandler::sanitize(&packet) {
            self.security.ban(src_addr.ip(), "Malicious pattern");
            return SipAction::Drop;
        }

        if packet.is_request {
            SipRouter::fix_nat_via(&mut packet, src_addr);
        } else {
            self.rewrite_contact_header(&mut packet);
        }

        if !self.media.process_sdp(&mut packet).await {
            return SipAction::Drop;
        }
        
        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            self.rtp_engine.release_relay_by_call_id(&call_id).await;
        }
        
        SipAction::Forward(packet)
    }

    fn rewrite_contact_header(&self, packet: &mut SipPacket) {
        if packet.status_code < 180 || packet.status_code > 299 {
            return;
        }

        let public_port = self.config.sip_advertised_port; // Genellikle 5060
        
        // [STANDARDİZASYON]: User kısmını koru, host/port kısmını SBC yap.
        // Örn: <sip:b2bua@internal:13084> -> <sip:b2bua@public_ip:5060>
        // Bu sayede ACK tekrar SBC'ye gelir ama hedef kullanıcı (b2bua) korunur.
        
        let old_contact = packet.get_header_value(HeaderName::Contact).cloned().unwrap_or_default();
        let user_part = if let Some(idx) = old_contact.find('@') {
            if let Some(start) = old_contact.find(':') {
                // sip:user@...
                &old_contact[start+1..idx]
            } else {
                "sbc"
            }
        } else {
            "sbc"
        };

        let new_contact = format!("<sip:{}@{}:{}>", user_part, self.config.sip_public_ip, public_port);

        if let Some(idx) = packet.headers.iter().position(|h| h.name == HeaderName::Contact) {
            let old_val = packet.headers[idx].value.clone();
            if !old_val.contains(&self.config.sip_public_ip) {
                info!("🔄 [TOPOLOGY-HIDING] Contact Rewrite: {} -> {}", old_val, new_contact);
                packet.headers[idx] = Header::new(HeaderName::Contact, new_contact);
            }
        } else {
            debug!("⚠️ Response without Contact header from internal. Injecting SBC address.");
            packet.headers.push(Header::new(HeaderName::Contact, new_contact));
        }
    }
}