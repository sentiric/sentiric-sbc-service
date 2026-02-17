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
        
        if packet.is_request() {
            if !PacketHandler::sanitize(&packet) { return SipAction::Drop; }
            SipRouter::fix_nat_via(&mut packet, src_addr);
            self.fix_request_uri_for_internal(&mut packet);
        }

        // 1. Medya/SDP işlemleri (Relay Port tahsisi vb.)
        if !self.media.process_sdp(&mut packet).await {
            return SipAction::Drop;
        }

        // 2. [KRİTİK]: Topoloji Gizleme (Topology Hiding)
        // İster istek olsun ister yanıt, dışarı (Internet) giden her şey filtrelenmeli.
        // Dış şebekeye giden paketleri (Response veya Outbound Request) SBC temizler.
        let is_outbound = packet.is_response() || (packet.is_request() && src_addr.ip().to_string() != self.config.sip_public_ip);
        
        if is_outbound {
            self.apply_nuclear_sanitization(&mut packet);
        }

        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            let _ = self.rtp_engine.release_relay_by_call_id(&call_id).await;
        }
        
        SipAction::Forward(packet)
    }

    /// [ANAYASAL TEMİZLİK]: Dış dünyaya giden pakette hiçbir iç ağ izi kalamaz.
    fn apply_nuclear_sanitization(&self, packet: &mut SipPacket) {
        let public_ip = &self.config.sip_public_ip;
        let public_port = self.config.sip_advertised_port;

        // 1. VIA TEMİZLİĞİ: Sadece tek bir Via kalana kadar üsttekileri sil (RFC 3261 compliance)
        // Yanıtlarda en üstteki Via bizim eklediğimizdir, onu silmeliyiz ki istemci kendi Via'sını görsün.
        while packet.headers.iter().filter(|h| h.name == HeaderName::Via).count() > 1 {
            if let Some(top_via) = packet.get_header_value(HeaderName::Via) {
                // Eğer üstteki Via bizim iç ağımıza aitse sil
                if top_via.contains("proxy-service") || 
                   top_via.contains("b2bua-service") || 
                   top_via.contains(&self.config.sip_internal_ip) {
                    SipRouter::strip_top_via(packet);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // 2. DAHİLİ BAŞLIKLARI TEMİZLE (Record-Route ve Route sızıntılarını kes)
        packet.headers.retain(|h| {
            match h.name {
                HeaderName::RecordRoute | HeaderName::Route => {
                    // Sadece bizim Public IP'miz olan Record-Route kalsın, gerisi sızıntıdır.
                    h.value.contains(public_ip)
                },
                HeaderName::Contact | HeaderName::Server | HeaderName::UserAgent => {
                    // Bunları aşağıda biz yeniden ekleyeceğiz.
                    false
                },
                _ => true
            }
        });

        // 3. KİMLİK MASKESİ (Contact Header Rewrite)
        let clean_contact = format!("<sip:b2bua@{}:{}>", public_ip, public_port);
        packet.headers.push(Header::new(HeaderName::Contact, clean_contact));
        packet.headers.push(Header::new(HeaderName::Server, "Sentiric-SBC".to_string()));

        debug!("🛡️ [NUCLEAR-SANITY] Topoloji gizlendi (IP: {})", public_ip);
    }

    fn fix_request_uri_for_internal(&self, packet: &mut SipPacket) {
        let user = sip_utils::extract_username_from_uri(&packet.uri);
        if user != "b2bua" { return; }

        let public_port_str = format!(":{}", self.config.sip_advertised_port);
        let internal_port = self.config.b2bua_internal_port;

        if packet.uri.contains(&public_port_str) || !packet.uri.contains(':') {
            if packet.uri.contains(':') {
                packet.uri = packet.uri.replace(&public_port_str, &format!(":{}", internal_port));
            } else {
                packet.uri.push_str(&format!(":{}", internal_port));
            }
        }
    }
}