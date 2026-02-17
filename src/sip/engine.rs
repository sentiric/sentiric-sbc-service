// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Header, Method}; 
use sentiric_sip_core::utils as sip_utils;
use std::sync::Arc;
use std::net::SocketAddr;
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine;
use crate::sip::handlers::security::SecurityHandler;
use crate::sip::handlers::packet::PacketHandler;
use crate::sip::handlers::media::MediaHandler;
use tracing::debug;

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
        if !self.security.check_access(src_addr.ip()) { return SipAction::Drop; }
        
        // 1. İSTEK İŞLEME (Gelen Aramalar)
        if packet.is_request() {
            if !PacketHandler::sanitize(&packet) { return SipAction::Drop; }
            SipRouter::fix_nat_via(&mut packet, src_addr);
            self.fix_request_uri_for_internal(&mut packet);
            if !self.media.process_sdp(&mut packet).await { return SipAction::Drop; }
        } 
        
        // 2. YANIT İŞLEME (Giden 200 OK vb.)
        if packet.is_response() {
            if !self.media.process_sdp(&mut packet).await { return SipAction::Drop; }
            
            // [KRİTİK]: Sadece sızıntı yapan başlıkları maskele, paketi bozma.
            self.apply_strict_topology_hiding(&mut packet);
        }

        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            let _ = self.rtp_engine.release_relay_by_call_id(&call_id).await;
        }
        
        SipAction::Forward(packet)
    }

    /// apply_strict_topology_hiding: Yanıt paketlerindeki iç ağ izlerini temizler.
    fn apply_strict_topology_hiding(&self, packet: &mut SipPacket) {
        let public_ip = &self.config.sip_public_ip;
        let public_port = self.config.sip_advertised_port;

        // 1. VIA TEMİZLİĞİ: Sadece İstemcinin orijinal Via'sı kalana kadar üsttekileri sil.
        // Rust'ta retain kullanarak iç ağ isimlerini içeren Via'ları eliyoruz.
        packet.headers.retain(|h| {
            if h.name == HeaderName::Via {
                // Eğer Via başlığı bizim iç ağ isimlerimizi içeriyorsa SİL.
                !h.value.contains("proxy-service") && 
                !h.value.contains("b2bua-service") && 
                !h.value.contains(&self.config.sip_internal_ip)
            } else {
                true // Diğer tüm başlıkları (From, To, CSeq vb.) KORU.
            }
        });

        // 2. RECORD-ROUTE & CONTACT MASKESİ
        // Eski Record-Route ve Contact'ları temizle, yerine sadece Public SBC IP'sini koy.
        packet.headers.retain(|h| h.name != HeaderName::RecordRoute && h.name != HeaderName::Contact);

        // Yeni Record-Route ekle (lr = loose routing)
        let rr_val = format!("<sip:{}:{};lr>", public_ip, public_port);
        packet.headers.insert(0, Header::new(HeaderName::RecordRoute, rr_val));

        // Yeni Contact ekle
        let contact_val = format!("<sip:b2bua@{}:{}>", public_ip, public_port);
        packet.headers.push(Header::new(HeaderName::Contact, contact_val));
        
        // Sunucu Kimliğini Gizle
        packet.headers.retain(|h| h.name != HeaderName::Server && h.name != HeaderName::UserAgent);
        packet.headers.push(Header::new(HeaderName::Server, "Sentiric-SBC".to_string()));

        debug!("🛡️ [HARDENING] Yanıt başarıyla maskelendi: {}", public_ip);
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