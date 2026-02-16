// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Method}; 
use sentiric_sip_core::utils as sip_utils;
use std::sync::Arc;
use std::net::SocketAddr;
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine;
use crate::sip::handlers::security::SecurityHandler;
use crate::sip::handlers::packet::PacketHandler;
use crate::sip::handlers::media::MediaHandler;
use tracing::{info, debug}; 

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
        // Log kirliliğini önlemek için sadece önemli metodları INFO yapıyoruz
        if packet.method == Method::Invite || packet.method == Method::Bye {
            info!("📥 [SBC-GİRİŞ] Paket Geldi: {} - Kaynak: {}", packet.method, src_addr);
        } else {
            debug!("📥 [SBC-GİRİŞ] Paket Geldi: {} - Kaynak: {}", packet.method, src_addr);
        }

        // 1. Güvenlik Kontrolleri
        if !self.security.check_access(src_addr.ip()) { return SipAction::Drop; }
        if packet.is_request() && !PacketHandler::sanitize(&packet) { return SipAction::Drop; }

        // 2. NAT Düzeltmesi
        if packet.is_request() {
            SipRouter::fix_nat_via(&mut packet, src_addr);
        }

        // 3. TOPOLOGY HIDING & CONTACT FIX (ÇİFT YÖNLÜ)
        if packet.is_response() {
            // Çıkış: İç Port -> Dış Port
            self.enforce_public_contact(&mut packet);
        } else if packet.is_request() {
            // Giriş: Dış Port -> İç Port (ACK Döngüsünü Kırmak İçin)
            self.fix_request_uri_for_internal(&mut packet);
        }

        // 4. SDP REWRITE & RTP ALLOCATION
        if !self.media.process_sdp(&mut packet).await {
            return SipAction::Drop;
        }
        
        // 5. Kaynak Temizliği (BYE)
        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            if self.rtp_engine.release_relay_by_call_id(&call_id).await {
                info!("♻️ [RTP-TEMİZLİK] Çağrı bitti, portlar serbest bırakıldı. CallID: {}", call_id);
            }
        }
        
        SipAction::Forward(packet)
    }

    /// [EGRESS FIX]: Contact başlığını kesinlikle Public IP/Port'a zorlar.
    fn enforce_public_contact(&self, packet: &mut SipPacket) {
        let public_ip = &self.config.sip_public_ip;
        let public_port = self.config.sip_advertised_port; // 5060
        let target_signature = format!("{}:{}", public_ip, public_port);

        if let Some(contact) = packet.get_header_value(HeaderName::Contact) {
            if contact.contains(&target_signature) { return; }

            // B2BUA veya 13084 tespit edilirse maskele
            // bu tarz tanımları hardcode yerıne confıg den almalı b2bua nın tanımlarını sabıtlemelıyız
            // yan etkı var ıse ılıglı servıs ve compose dosyaları ıle de guncellemelıyız.
            if contact.contains("13084") || contact.contains("b2bua") {
                let user_part = sip_utils::extract_username_from_uri(contact);
                let new_contact = format!("<sip:{}@{}:{}>", user_part, public_ip, public_port);
                
                info!("🛡️ [TOPOLOJİ-GİZLEME] Contact Maskelendi: {} -> {}", contact, new_contact);
                
                for h in &mut packet.headers {
                    if h.name == HeaderName::Contact {
                        h.value = new_contact.clone();
                        break;
                    }
                }
            }
        }
    }

    /// [INGRESS FIX]: Dışarıdan gelen ACK/BYE isteklerinin Request-URI'sini iç servise düzeltir.
    /// B2BUA servisi (13084), kendisine "5060" portuyla gelen bir paketi reddedebilir.
    /// Bu fonksiyon, paketin hedef portunu tekrar 13084 yaparak B2BUA'nın paketi kabul etmesini sağlar.
    fn fix_request_uri_for_internal(&self, packet: &mut SipPacket) {
        let user = sip_utils::extract_username_from_uri(&packet.uri);
        // Sadece 'b2bua' kullanıcısı için (Echo Test vb.)
        if user != "b2bua" { return; }

        let public_port_str = format!(":{}", self.config.sip_advertised_port); // ":5060"
        let internal_port = 13084; // B2BUA Standart Portu

        // Eğer URI ":5060" içeriyorsa veya hiç port yoksa, ":13084" ile değiştir.
        if packet.uri.contains(&public_port_str) {
            let old_uri = packet.uri.clone();
            packet.uri = packet.uri.replace(&public_port_str, &format!(":{}", internal_port));
            info!("🔧 [URI-DÜZELTME] Request-URI İç Porta Çevrildi: {} -> {}", old_uri, packet.uri);
        }
    }
}