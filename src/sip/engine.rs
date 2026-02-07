// sentiric-sbc-service/src/sip/engine.rs
use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Method};
use std::sync::Arc;
use std::net::SocketAddr;
use dashmap::DashMap;
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine;
use crate::sip::handlers::security::SecurityHandler;
use crate::sip::handlers::packet::PacketHandler;
use crate::sip::handlers::media::MediaHandler;

pub enum SipAction {
    Forward(SipPacket),
    Drop,
}

/// [MİMARİ]: SBC İşlem Hafızası. 
/// Aynı anda işlenen gRPC isteklerini takip ederek 'Double Processing'i engeller.
pub struct SbcEngine {
    security: SecurityHandler,
    media: MediaHandler,
    rtp_engine: Arc<RtpEngine>,
    // Key: Call-ID + CSeq, Value: İşlem başlama zamanı
    inflight_requests: Arc<DashMap<String, std::time::Instant>>,
}

impl SbcEngine {
    pub fn new(config: Arc<AppConfig>, rtp_engine: Arc<RtpEngine>) -> Self {
        Self {
            security: SecurityHandler::new(1000), 
            media: MediaHandler::new(config.clone(), rtp_engine.clone()),
            rtp_engine,
            inflight_requests: Arc::new(DashMap::new()),
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
                // Bu paket zaten işleniyor, Proxy'ye tekrar sormaya gerek yok.
                return SipAction::Drop; 
            }
            self.inflight_requests.insert(tx_key.clone(), std::time::Instant::now());
            
            // 5 saniye sonra hafızadan sil (GC simülasyonu)
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

        // 4. NAT Fix (rport/received injection)
        if packet.is_request {
            SipRouter::fix_nat_via(&mut packet, src_addr);
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
}