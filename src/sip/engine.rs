// sentiric-sbc-service/src/sip/engine.rs
use sentiric_sip_core::{SipPacket, SipRouter, HeaderName, Method};
use std::sync::Arc;
use std::net::SocketAddr;
use crate::config::AppConfig;
use crate::rtp::engine::RtpEngine;
use crate::sip::handlers::security::SecurityHandler;
use crate::sip::handlers::packet::PacketHandler;
use crate::sip::handlers::media::MediaHandler;

pub enum SipAction {
    Forward(SipPacket),
    Drop,
}

pub struct SbcEngine {
    security: SecurityHandler,
    media: MediaHandler,
    rtp_engine: Arc<RtpEngine>,
}

impl SbcEngine {
    pub fn new(config: Arc<AppConfig>, rtp_engine: Arc<RtpEngine>) -> Self {
        Self {
            security: SecurityHandler::new(1000), // Default: 1000 pkt/sec
            media: MediaHandler::new(config.clone(), rtp_engine.clone()),
            rtp_engine,
        }
    }

    pub async fn inspect(&self, mut packet: SipPacket, src_addr: SocketAddr) -> SipAction {
        // 1. Güvenlik ve Rate Limit
        if !self.security.check_access(src_addr.ip()) {
            return SipAction::Drop;
        }

        // 2. Paket Temizliği
        if packet.is_request && !PacketHandler::sanitize(&packet) {
            self.security.ban(src_addr.ip(), "Malicious SIP patterns");
            return SipAction::Drop;
        }

        // 3. NAT Traversal & Topology Hiding (Via Manipulation)
        if packet.is_request {
            // [v1.4.1 ALIGNMENT] fix_nat_via rport ve received parametrelerini işler
            SipRouter::fix_nat_via(&mut packet, src_addr);
        }

        // 4. Medya ve SDP (Sticky Ports)
        if !self.media.process_sdp(&mut packet).await {
            return SipAction::Drop;
        }
        
        // 5. Kaynak Temizliği (Call Life-cycle)
        if packet.method == Method::Bye {
            let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();
            // RTP Relay portunu serbest bırak
            self.rtp_engine.release_relay_by_call_id(&call_id).await;
        }
        
        SipAction::Forward(packet)
    }
}