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
use tracing::{debug, warn};

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
            // [CRITICAL FIX]: Contact Header Rewrite
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

    /// Contact başlığını SBC'nin Public IP:Port'u ile değiştirir.
    fn rewrite_contact_header(&self, packet: &mut SipPacket) {
        if packet.status_code < 200 || packet.status_code > 299 {
            return;
        }

        if let Some(idx) = packet.headers.iter().position(|h| h.name == HeaderName::Contact) {
            let old_val = packet.headers[idx].value.clone();
            
            // [FIX]: Sadece IP'ye bakmak yetmez, PORT da eşleşmeli.
            // B2BUA Public IP'yi biliyor olabilir ama iç portu (13084) basıyordur.
            // Bizim istediğimiz: 34.122.40.122:5060 (veya SBC portu neyse)
            let sbc_signature = format!("{}:{}", self.config.sip_public_ip, self.config.sip_port);
            
            if old_val.contains(&sbc_signature) {
                // Zaten doğru formatta, dokunma.
                return;
            }

            // Kullanıcı adını ayıkla
            let username = if let Some(start) = old_val.find("sip:") {
                let rest = &old_val[start+4..];
                if let Some(end) = rest.find('@') {
                    &rest[..end]
                } else {
                    "sbc"
                }
            } else {
                "sbc"
            };

            // Yeni Contact: <sip:USER@PUBLIC_IP:SBC_PORT;transport=udp>
            let new_contact = format!("<sip:{}@{}:{}>", username, self.config.sip_public_ip, self.config.sip_port);
            
            debug!("🔄 Topology Hiding Fix: {} -> {}", old_val, new_contact);
            packet.headers[idx] = Header::new(HeaderName::Contact, new_contact);
        }
    }
}