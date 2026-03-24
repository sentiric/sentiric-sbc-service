// Dosya: sentiric-sip-sbc-service/src/sip/engine.rs
use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Header, Method}; 
use sentiric_sip_core::utils as sip_utils;
use std::sync::Arc;
use std::net::{SocketAddr, IpAddr};
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine;
use crate::sip::handlers::security::SecurityHandler;
use crate::sip::handlers::packet::PacketHandler;
use crate::sip::handlers::media::MediaHandler;
use tracing::{info, warn};

// İç IP kontrolü (Proxy, B2BUA veya Local P2P Client trafiğini algılamak için)
fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if octets[0] == 10 || octets[0] == 127 { return true; }
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) { return true; }
            if octets[0] == 192 && octets[1] == 168 { return true; }
            if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) { return true; }
            false
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

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
        let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();

        if !self.security.check_access(src_addr.ip()) { 
            warn!(
                event = "SIP_ACCESS_DENIED",
                sip.call_id = %call_id,
                net.src.ip = %src_addr.ip(),
                "Erişim reddedildi (Rate Limit veya Blocklist)"
            );
            return SipAction::Drop; 
        }
        
        if packet.is_request() {
            if !PacketHandler::sanitize(&packet) { 
                warn!(
                    event = "SIP_SANITIZATION_FAILED", 
                    sip.call_id = %call_id, 
                    "Paket temizliği başarısız (User-Agent/Malform)"
                );
                return SipAction::Drop; 
            }
            
            SipRouter::fix_nat_via(&mut packet, src_addr);
            self.fix_request_uri_for_internal(&mut packet);
            
            if !self.media.process_sdp(&mut packet).await { 
                warn!(
                    event = "SIP_SDP_PROCESS_FAIL", 
                    sip.call_id = %call_id, 
                    "SDP işlenemedi, paket düşürülüyor"
                );
                return SipAction::Drop; 
            }
        } 
        
        if packet.is_response() {
            if !self.media.process_sdp(&mut packet).await { 
                warn!(
                    event = "SIP_RESPONSE_SDP_FAIL",
                    sip.call_id = %call_id,
                    "⚠️ Yanıt paketi SDP işlenemedi (Medya bacağı eksik olabilir)"
                );
            }
            
            self.apply_smart_topology_hiding(&mut packet, src_addr);
        }

        if packet.method == Method::Bye || packet.method == Method::Cancel {
            let _ = self.rtp_engine.release_relay_by_call_id(&call_id).await;
            info!(
                event = "RTP_RELAY_RELEASED",
                sip.call_id = %call_id,
                sip.method = %packet.method.as_str(),
                "Çağrı sonlandırma (BYE/CANCEL) sinyali üzerine RTP relay kapatıldı"
            );
        }
        
        SipAction::Forward(packet)
    }

    fn apply_smart_topology_hiding(&self, packet: &mut SipPacket, src_addr: SocketAddr) {
        let public_ip = &self.config.sip_public_ip;
        let public_port = self.config.sip_advertised_port;

        let old_contact_val = packet.get_header_value(HeaderName::Contact).cloned().unwrap_or_default();
        let user_part = sip_utils::extract_username_from_uri(&old_contact_val);
        let final_user = if user_part.is_empty() { "sbc".to_string() } else { user_part };

        packet.headers.retain(|h| {
            if h.name == HeaderName::Via {
                !h.value.contains("proxy-service") && 
                !h.value.contains("b2bua-service") && 
                !h.value.contains("registrar-service") &&
                !h.value.contains(&self.config.sip_internal_ip)
            } else {
                true 
            }
        });

        let mut is_register = false;
        if let Some(cseq) = packet.get_header_value(HeaderName::CSeq) {
            if cseq.to_uppercase().contains("REGISTER") {
                is_register = true;
            }
        }

        packet.headers.retain(|h| h.name != HeaderName::RecordRoute);
        let rr_val = format!("<sip:{}:{};lr>", public_ip, public_port);
        packet.headers.insert(0, Header::new(HeaderName::RecordRoute, rr_val));

        // [ARCH-COMPLIANCE]: Akıllı Topoloji Gizleme (Sadece iç IP'leri maskele, dış P2P IP'lere NAT Fix uygula)
        if !is_register {
            let is_internal_contact = old_contact_val.contains("10.") || old_contact_val.contains("192.168.") || old_contact_val.contains("172.") || old_contact_val.contains("100.");
            let is_external_src = !is_internal_ip(src_addr.ip());

            if is_external_src {
                // UAC'den veya Dış Trunk'tan geldi. NAT fix: Contact'ı public IP'sine çevir ki diğer UAC onu bulabilsin.
                packet.headers.retain(|h| h.name != HeaderName::Contact);
                let contact_val = format!("<sip:{}@{}:{}>", final_user, src_addr.ip(), src_addr.port());
                packet.headers.push(Header::new(HeaderName::Contact, contact_val));
            } else if is_internal_contact {
                // İçeriden (Proxy/B2BUA/Media) geldi ve Contact'ta iç IP var. 
                // Topolojisini gizlemek için SBC Public IP'ye çevir.
                packet.headers.retain(|h| h.name != HeaderName::Contact);
                let contact_val = format!("<sip:{}@{}:{}>", final_user, public_ip, public_port);
                packet.headers.push(Header::new(HeaderName::Contact, contact_val));
            }
            // Diğer durumda (içeriden geldi ve Contact zaten Public IP ise) dokunma!
            // Bu, UAC'nin yanıtı Proxy'den geçip SBC'ye döndüğünde Contact'ın bozulmasını önler.
        }
        
        packet.headers.retain(|h| h.name != HeaderName::Server && h.name != HeaderName::UserAgent);
        packet.headers.push(Header::new(HeaderName::Server, "Sentiric-SBC".to_string()));

        let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
        tracing::debug!(
            event = "SIP_TOPOLOGY_HIDDEN",
            sip.call_id = %call_id,
            advertise.ip = %public_ip,
            is_register = is_register,
            "🛡️ [HARDENING] Yanıt maskelendi"
        );
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