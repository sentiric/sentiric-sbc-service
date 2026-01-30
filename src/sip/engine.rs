// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, HeaderName};
use tracing::{warn, debug};
use std::sync::Arc;
use crate::sip::security::SecurityGuard;
use std::net::SocketAddr;

pub enum SipAction {
    Forward,
    Drop,
}

pub struct SbcEngine {
    security: Arc<SecurityGuard>,
}

impl SbcEngine {
    pub fn new() -> Self {
        // Default: Saniyede 500 paket (Yüksek performanslı Edge)
        SbcEngine {
            security: Arc::new(SecurityGuard::new(500)),
        }
    }

    /// Gelen paketi inceler ve ne yapılacağına karar verir.
    pub fn inspect(&self, packet: &SipPacket, src_addr: SocketAddr) -> SipAction {
        // 1. IP Seviyesi Güvenlik (Rate Limit & Blacklist)
        if !self.security.is_allowed(src_addr.ip()) {
            return SipAction::Drop;
        }

        // 0. Yanıtlara (Response) izin ver
        if !packet.is_request {
            return SipAction::Forward;
        }

        // 2. User-Agent Güvenlik Kontrolü
        if let Some(ua) = packet.get_header_value(HeaderName::UserAgent) {
            let ua_lower = ua.to_lowercase();
            // Bilinen tarayıcıları ve saldırı araçlarını engelle
            if ua_lower.contains("friendly-scanner") || 
               ua_lower.contains("sipcli") || 
               ua_lower.contains("sipvicious") ||
               ua_lower.contains("pplsip") ||
               ua_lower.contains("sundayddr") {
                
                warn!("🚫 SECURITY: Malicious User-Agent detected: {} from {}", ua, src_addr);
                self.security.ban_ip(src_addr.ip(), format!("Malicious UA: {}", ua));
                return SipAction::Drop;
            }
        }

        // 3. Metod Kontrolü
        match &packet.method {
            sentiric_sip_core::Method::Invite |
            sentiric_sip_core::Method::Ack |
            sentiric_sip_core::Method::Bye |
            sentiric_sip_core::Method::Cancel |
            sentiric_sip_core::Method::Register |
            sentiric_sip_core::Method::Options => {},
            
            sentiric_sip_core::Method::Other(m) => {
                match m.as_str() {
                    "MESSAGE" | "SUBSCRIBE" | "NOTIFY" | "REFER" | "INFO" | "PRACK" | "UPDATE" | "PUBLISH" => {},
                    _ => {
                        debug!("🚫 FILTER: Unsupported Method: {:?} from {}", packet.method, src_addr);
                        return SipAction::Drop;
                    }
                }
            }
        }

        // 4. Sanitize (Max-Forwards)
        if let Some(mf) = packet.get_header_value(HeaderName::MaxForwards) {
            if let Ok(val) = mf.parse::<i32>() {
                if val <= 0 {
                    warn!("TTL Expired (Max-Forwards: 0) from {}", src_addr);
                    return SipAction::Drop;
                }
            }
        }

        SipAction::Forward
    }
}