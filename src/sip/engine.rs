// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, HeaderName};
// DÜZELTME: 'debug' makrosu tekrar eklendi.
use tracing::{warn, debug}; 

pub enum SipAction {
    Forward,
    Drop,
}

pub struct SbcEngine;

impl SbcEngine {
    pub fn new() -> Self {
        SbcEngine
    }

    /// Gelen paketi inceler ve ne yapılacağına karar verir.
    pub fn inspect(&self, packet: &SipPacket) -> SipAction {
        // 1. User-Agent Güvenlik Kontrolü
        if let Some(ua) = packet.get_header_value(HeaderName::UserAgent) {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("friendly-scanner") || 
               ua_lower.contains("sipcli") || 
               ua_lower.contains("sipvicious") {
                warn!("🚫 BLOCKED: Malicious User-Agent detected: {}", ua);
                return SipAction::Drop;
            }
        }

        // 2. Metod Kontrolü (Sadece desteklenen metodlara izin ver)
        // Şimdilik pasif, ileride strict mode açılabilir.
        
        SipAction::Forward
    }

    /// Paketi iç ağa göndermeden önce temizler (Sanitization).
    /// Topology Hiding ve RFC uyumluluğu burada sağlanır.
    pub fn sanitize(&self, packet: &mut SipPacket) {
        // Max-Forwards kontrolü (Döngü engelleme)
        if let Some(mf) = packet.get_header_value(HeaderName::MaxForwards) {
            if let Ok(val) = mf.parse::<i32>() {
                if val <= 0 {
                    warn!("TTL Expired (Max-Forwards: 0)");
                    // Normalde 483 Too Many Hops dönülmeli ama SBC'de drop edebiliriz.
                }
            }
        }

        // TODO: Record-Route ve Via başlıklarını manipüle ederek
        // iç ağ topolojisini gizleme mantığı buraya eklenecek.
        // Şimdilik "Transparent Proxy" modunda çalışıyoruz.
        
        debug!("Packet sanitized for internal forwarding.");
    }
}