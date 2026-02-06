// sentiric-sbc-service/src/sip/handlers/packet.rs
use sentiric_sip_core::{SipPacket, HeaderName};
use tracing::warn;

pub struct PacketHandler;

impl PacketHandler {
    pub fn sanitize(packet: &SipPacket) -> bool {
        // 1. User-Agent Kontrolü (Scanner tespiti)
        if let Some(ua) = packet.get_header_value(HeaderName::UserAgent) {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("friendly-scanner") || ua_lower.contains("sipvicious") {
                warn!("🛡️ REJECTED: Known malicious scanner detected");
                return false;
            }
        }

        // 2. Max-Forwards Kontrolü (Döngü koruması)
        if let Some(mf) = packet.get_header_value(HeaderName::MaxForwards) {
            if let Ok(val) = mf.parse::<i32>() {
                if val <= 0 { 
                    warn!("🛡️ REJECTED: Max-Forwards reached zero");
                    return false; 
                }
            }
        }
        
        true
    }
}