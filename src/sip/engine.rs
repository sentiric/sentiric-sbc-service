// sentiric-sbc-service/src/sip/engine.rs

// [DÜZELTME]: Header importu kaldırıldı (kullanılmıyordu)
use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Method}; 
use std::sync::Arc;
use std::net::SocketAddr;
use dashmap::DashMap;
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

/// SBC İşlem Hafızası ve Yönlendirme Motoru
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
        // 1. Güvenlik Filtresi
        if !self.security.check_access(src_addr.ip()) {
            return SipAction::Drop;
        }

        // 2. [DEDUPLICATION]: Mükerrer INVITE kontrolü
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

        // 3. Paket Sanitizasyonu
        if packet.is_request && !PacketHandler::sanitize(&packet) {
            self.security.ban(src_addr.ip(), "Malicious pattern");
            return SipAction::Drop;
        }

        // 4. NAT Fix ve Topology Hiding
        if packet.is_request {
            SipRouter::fix_nat_via(&mut packet, src_addr);
        } else {
            // [CRITICAL ARCHITECTURE FIX]: Topology Hiding
            // B2BUA'dan gelen cevaplarda (200 OK), Contact başlığı iç IP'yi gösterir.
            // Bunu SBC'nin dış IP'si ile değiştirmeliyiz ki ACK bize gelsin.
            self.rewrite_contact_header(&mut packet);
        }

        // 5. [STICKY MEDIA]: SDP rewrite ve port tahsisi
        if !self.media.process_sdp(&mut packet).await {
            return SipAction::Drop;
        }
        
        // 6. Yaşam Döngüsü: BYE geldiyse portu temizle
        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            self.rtp_engine.release_relay_by_call_id(&call_id).await;
        }
        
        SipAction::Forward(packet)
    }

    /// Contact başlığını SBC'nin Public IP'si ile değiştirir.
    /// Örnek: Contact: <sip:1001@10.0.0.5:13084>  -->  Contact: <sip:1001@34.122.40.122:5060>
    fn rewrite_contact_header(&self, packet: &mut SipPacket) {
        // Sadece 200 OK gibi başarılı cevaplarda Contact başlığı kritiktir.
        if packet.status_code != 200 {
            return;
        }

        if let Some(contact_header) = packet.headers.iter_mut().find(|h| h.name == HeaderName::Contact) {
            let old_val = contact_header.value.clone();
            
            // Eğer Contact zaten bizim Public IP'mizi içeriyorsa (Loop durumu), dokunma.
            if old_val.contains(&self.config.sip_public_ip) {
                return;
            }

            // Orijinal kullanıcı adını (örn: 1001 veya b2bua) koru.
            let username = if let Some(start) = old_val.find("sip:") {
                let rest = &old_val[start+4..];
                if let Some(end) = rest.find('@') {
                    &rest[..end] // @ işaretine kadar olan kısım
                } else {
                    "sbc" // Format bozuksa generic isim
                }
            } else {
                "sbc"
            };

            // Yeni Contact başlığını oluştur: <sip:USER@PUBLIC_IP:SIP_PORT>
            let new_contact = format!("<sip:{}@{}:{}>", username, self.config.sip_public_ip, self.config.sip_port);
            
            debug!("🔄 Topology Hiding (Contact Rewrite): {} -> {}", old_val, new_contact);
            contact_header.value = new_contact;
        }
    }
}