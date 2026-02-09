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
use tracing::{debug, warn}; // Warn eklendi

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
            // [CRITICAL FIX]: Topology Hiding & ACK Routing Fix
            // 200 OK yanıtlarında Contact başlığını SBC'nin Public IP'si ile değiştir.
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
        if packet.status_code < 200 || packet.status_code > 299 {
            return;
        }

        // Contact başlığını bul ve değiştir
        // Iterator yerine index ile erişim daha güvenli (borrow checker için)
        if let Some(idx) = packet.headers.iter().position(|h| h.name == HeaderName::Contact) {
            let old_val = packet.headers[idx].value.clone();
            
            // Loop koruması
            if old_val.contains(&self.config.sip_public_ip) {
                return;
            }

            // Username'i koru, geri kalanını değiştir
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

            // Yeni Contact: <sip:USER@PUBLIC_IP:SIP_PORT>
            // transport=udp eklemek bazı clientlar için faydalıdır.
            let new_contact = format!("<sip:{}@{}:{}>", username, self.config.sip_public_ip, self.config.sip_port);
            
            debug!("🔄 Contact Rewrite: {} -> {}", old_val, new_contact);
            
            // Header'ı güncelle
            packet.headers[idx] = Header::new(HeaderName::Contact, new_contact);
        } else {
            // Contact yoksa ekle (Nadir durum ama gerekli)
            warn!("⚠️ Response without Contact header. Injecting default.");
            let default_contact = format!("<sip:sbc@{}:{}>", self.config.sip_public_ip, self.config.sip_port);
            packet.headers.push(Header::new(HeaderName::Contact, default_contact));
        }
    }
}