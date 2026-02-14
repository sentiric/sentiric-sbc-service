// sentiric-sbc-service/src/sip/engine.rs

use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Method}; 
use sentiric_sip_core::utils::apply_topology_hiding; // Otorite kullanımı
use std::sync::Arc;
use std::net::SocketAddr;
use dashmap::DashMap;
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
        debug!("📥 [SBC-IN] Processing from {}: {}", src_addr, packet.method);

        // 1. IP Whitelist/Rate Limit Kontrolü
        if !self.security.check_access(src_addr.ip()) {
            return SipAction::Drop;
        }

        // 2. Transaction Flood Koruması
        if packet.is_request() && packet.method == Method::Invite {
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

        // 3. Zararlı Paket Taraması (Scanner vs.)
        if packet.is_request() && !PacketHandler::sanitize(&packet) {
            self.security.ban(src_addr.ip(), "Malicious pattern");
            return SipAction::Drop;
        }

        // 4. NAT Düzeltmesi (Via Header)
        if packet.is_request() {
            SipRouter::fix_nat_via(&mut packet, src_addr);
        }

        // 5. TOPOLOGY HIDING (Contact Header Fix)
        // [HARDENING]: 0.0.0.0 sızıntısını engellemek için core helper'ı her durumda çağırıyoruz.
        self.apply_hiding(&mut packet);

        // 6. SDP REWRITE & RTP ALLOCATION
        if !self.media.process_sdp(&mut packet).await {
            return SipAction::Drop;
        }
        
        // 7. Kaynak Temizliği (BYE gelirse)
        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            self.rtp_engine.release_relay_by_call_id(&call_id).await;
            info!("♻️ [RTP-CLEANUP] Call {} ended. Relay ports released.", call_id);
        }
        
        SipAction::Forward(packet)
    }

    fn apply_hiding(&self, packet: &mut SipPacket) {
        // Sadece 180-299 arası (Success/Ringing) cevaplar ve giden INVITE istekleri için
        let public_ip = &self.config.sip_public_ip;
        let public_port = self.config.sip_advertised_port;

        // Core library fonksiyonu ile Contact header rewrite lojiği
        // Bu fonksiyon, Contact içindeki IP'yi kontrol eder, hatalıysa (0.0.0.0)
        // veya iç ağ IP'siyse public IP ile ezer.
        if apply_topology_hiding(packet, public_ip, public_port) {
            debug!("🔄 [TOPOLOGY-HIDING] Contact Header sanitized to {}:{}", public_ip, public_port);
        }
    }
}