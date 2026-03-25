// src/sip/handlers/packet.rs
use sentiric_sip_core::{SipPacket, HeaderName};
use tracing::warn;

pub struct PacketHandler;

impl PacketHandler {
    pub fn sanitize(packet: &SipPacket) -> bool {
        let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();

        // 1. User-Agent Kontrolü (Scanner tespiti)
        if let Some(ua) = packet.get_header_value(HeaderName::UserAgent) {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("friendly-scanner") || ua_lower.contains("sipvicious") {
                // [ARCH-COMPLIANCE] SUTS v4.0
                warn!(
                    event = "SIP_MALICIOUS_SCANNER",
                    sip.call_id = %call_id,
                    user_agent = %ua,
                    "🛡️ REJECTED: Bilinen zararlı tarayıcı tespit edildi."
                );
                return false;
            }
        }

        // 2. Max-Forwards Kontrolü (Döngü koruması)
        if let Some(mf) = packet.get_header_value(HeaderName::MaxForwards) {
            if let Ok(val) = mf.parse::<i32>() {
                if val <= 0 { 
                    // [ARCH-COMPLIANCE] SUTS v4.0
                    warn!(
                        event = "SIP_MAX_FORWARDS_ZERO",
                        sip.call_id = %call_id,
                        "🛡️ REJECTED: Max-Forwards sıfıra ulaştı (Routing Loop)."
                    );
                    return false; 
                }
            }
        }
        
        true
    }
}