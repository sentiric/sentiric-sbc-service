// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, HeaderName};
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
        // 0. [YENİ] Yanıtlara (Response) izin ver
        // SBC yanıtları geri döndürmek zorundadır. Via kontrolü server.rs içinde yapılıyor.
        if !packet.is_request {
            return SipAction::Forward;
        }

        // 1. [YENİ] User-Agent Güvenlik Kontrolü
        if let Some(ua) = packet.get_header_value(HeaderName::UserAgent) {
            let ua_lower = ua.to_lowercase();
            // Bilinen tarayıcıları ve saldırı araçlarını engelle
            if ua_lower.contains("friendly-scanner") || 
               ua_lower.contains("sipcli") || 
               ua_lower.contains("sipvicious") ||
               ua_lower.contains("pplsip") {
                warn!("🚫 BLOCKED: Malicious User-Agent detected: {}", ua);
                return SipAction::Drop;
            }
        }

        // 2. Metod Kontrolü
        match &packet.method {
            // İzin verilen standart metodlar
            sentiric_sip_core::Method::Invite |
            sentiric_sip_core::Method::Ack |
            sentiric_sip_core::Method::Bye |
            sentiric_sip_core::Method::Cancel |
            sentiric_sip_core::Method::Register |
            sentiric_sip_core::Method::Options => {},
            
            // Diğer metodlar (String olarak parse edilenler)
            sentiric_sip_core::Method::Other(m) => {
                match m.as_str() {
                    "MESSAGE" | "SUBSCRIBE" | "NOTIFY" | "REFER" | "INFO" | "PRACK" | "UPDATE" | "PUBLISH" => {},
                    _ => {
                        warn!("🚫 BLOCKED: Unsupported Method: {:?}", packet.method);
                        return SipAction::Drop;
                    }
                }
            }
        }

        SipAction::Forward
    }

    /// Paketi iç ağa göndermeden önce temizler (Sanitization).
    pub fn sanitize(&self, packet: &mut SipPacket) {
        // Max-Forwards kontrolü (Döngü engelleme)
        if let Some(mf) = packet.get_header_value(HeaderName::MaxForwards) {
            if let Ok(val) = mf.parse::<i32>() {
                if val <= 0 {
                    warn!("TTL Expired (Max-Forwards: 0)");
                }
            }
        }
        debug!("Packet sanitized for internal forwarding.");
    }
}