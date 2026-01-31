// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tonic::transport::Channel;
use tracing::{info, error, debug, warn}; // DÜZELTME: 'instrument' kaldırıldı
use sentiric_sip_core::{
    SipTransport, parser, SipPacket, HeaderName, Header, 
    utils as sip_utils,
    builder as sip_builder
};
use crate::config::AppConfig;
use sentiric_contracts::sentiric::sip::v1::{proxy_service_client::ProxyServiceClient, GetNextHopRequest};
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use tokio::net::lookup_host;
use std::net::SocketAddr;
use regex::Regex;
use once_cell::sync::Lazy;

const DEFAULT_SIP_PORT: u16 = 5060;

// SDP Regex'leri (Performans için derlenmiş ve statik)
static SDP_CONNECTION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"c=IN IP4 \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap());
static SDP_AUDIO_MEDIA_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"m=audio (\d+)").unwrap());

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
    rtp_engine: Arc<RtpEngine>,
}

impl SipServer {
    pub async fn new(
        config: Arc<AppConfig>,
        proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
    ) -> anyhow::Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        
        // RTP Engine Başlat
        let rtp_engine = Arc::new(RtpEngine::new(config.rtp_start_port, config.rtp_end_port));

        Ok(Self {
            config,
            transport: Arc::new(transport),
            engine: SbcEngine::new(),
            proxy_client,
            rtp_engine,
        })
    }

    pub async fn run(self, mut shutdown_rx: mpsc::Receiver<()>) {
        info!("📡 SBC SIP Listener: {}:{}", self.config.sip_bind_ip, self.config.sip_port);
        info!("🎤 SBC RTP Relay Range: {}-{}", self.config.rtp_start_port, self.config.rtp_end_port);
        
        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => { 
                    info!("🛑 SIP Server shutdown signal received.");
                    break; 
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            if len < 4 { continue; }
                            // Keep-Alive (CRLF) kontrolü
                            if len <= 4 && buf[..len].iter().all(|&b| b == b'\r' || b == b'\n') {
                                continue;
                            }

                            let data = &buf[..len];
                            match parser::parse(data) {
                                Ok(packet) => {
                                    match self.engine.inspect(&packet, src_addr) {
                                        SipAction::Forward => self.handle_forwarding(packet, src_addr).await,
                                        SipAction::Drop => {
                                            debug!("⛔ SIP Packet dropped from {}", src_addr);
                                        },
                                    }
                                },
                                Err(e) => {
                                    warn!("⚠️ Malformed SIP packet from {}: {}", src_addr, e);
                                }
                            }
                        },
                        Err(e) => {
                            error!("🔥 UDP Socket Error: {}", e);
                        },
                    }
                }
            }
        }
    }

    // --- SDP MANIPULATION (REGEX BASED) ---
    fn rewrite_sdp(body: &[u8], new_ip: &str, new_port: u16) -> Option<Vec<u8>> {
        let sdp_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return None,
        };

        // Regex ile değiştirme daha güvenlidir çünkü satırın geri kalanını bozmaz.
        // c=IN IP4 x.x.x.x -> c=IN IP4 <new_ip>
        let sdp_ip_replaced = SDP_CONNECTION_REGEX.replace_all(sdp_str, format!("c=IN IP4 {}", new_ip));
        
        // m=audio <port> ... -> m=audio <new_port> ...
        // Regex sadece port kısmını yakalar ve değiştirir.
        let sdp_final = SDP_AUDIO_MEDIA_REGEX.replace(&sdp_ip_replaced, format!("m=audio {}", new_port));

        if sdp_str != sdp_final {
            Some(sdp_final.as_bytes().to_vec())
        } else {
            None
        }
    }

    async fn handle_forwarding(&self, mut packet: SipPacket, src_addr: SocketAddr) {
        let method = packet.method.to_string();
        
        // --- RTP RELAY LOGIC (Man-in-the-Middle) ---
        // Sadece INVITE ve 200 OK (INVITE cevabı) için devreye girer.
        let has_sdp = packet.body.len() > 0 && 
                      packet.get_header_value(HeaderName::ContentType)
                            .map_or(false, |v| v.contains("application/sdp"));

        // RTP Relay sadece INVITE diyaloglarında ve başarılı cevaplarda (200 OK) devreye girer.
        // 180 Ringing veya 183 Session Progress'de SDP varsa onu da işlemeliyiz (Early Media).
        let is_invite_response = packet.status_code >= 100 && packet.status_code < 300 
                                 && packet.get_header_value(HeaderName::CSeq).map_or(false, |v| v.contains("INVITE"));

        if has_sdp && (method == "INVITE" || is_invite_response) {
            
            // 1. Yeni bir Relay Port ayır
            if let Some(relay_port) = self.rtp_engine.allocate_relay().await {
                
                // 2. Hangi IP'yi yazacağız?
                // EĞER REQUEST (INVITE) İSE -> Internal IP yaz (UAS/Internal Network görsün)
                // EĞER RESPONSE (200 OK) İSE -> Public IP yaz (Operator/External Network görsün)
                let advertise_ip = if packet.is_request {
                    &self.config.sip_internal_ip 
                } else {
                    &self.config.sip_public_ip
                };

                // 3. SDP'yi Değiştir
                if let Some(new_body) = Self::rewrite_sdp(&packet.body, advertise_ip, relay_port) {
                    packet.body = new_body;
                    info!("🎤 [SBC-MEDIA] SDP Rewritten: Advertise {} Port {}", advertise_ip, relay_port);
                    
                    // Content-Length güncelle
                    packet.headers.retain(|h| h.name != HeaderName::ContentLength);
                    packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
                }
            } else {
                error!("❌ RTP Port allocation failed! Call might drop audio.");
            }
        }

        // --- YÖNLENDİRME MANTIĞI ---
        let target_addr = if packet.is_request {
            // 1. Gelen Request: Via ve Record-Route Ekleme
            
            // Gelen paketin Via başlığına rport ve received ekle (NAT Traversal)
            if let Some(via_header) = packet.headers.iter_mut().find(|h| h.name == HeaderName::Via) {
                if !via_header.value.contains("received=") {
                    via_header.value.push_str(&format!(";received={}", src_addr.ip()));
                }
                if !via_header.value.contains("rport") { // rport flag yoksa ekle, varsa değer ata
                     via_header.value.push_str(&format!(";rport={}", src_addr.port()));
                } else if !via_header.value.contains("rport=") {
                     // rport var ama değeri yok, değer ata
                     via_header.value = via_header.value.replace("rport", &format!("rport={}", src_addr.port()));
                }
            }
            
            // Record-Route Ekle: Böylece sonraki istekler (BYE, ACK) de bizim üzerimizden geçer.
            let rr_val = format!("<sip:{}:{};lr>", self.config.sip_public_ip, self.config.sip_port);
            if method == "INVITE" {
                packet.headers.insert(0, Header::new(HeaderName::RecordRoute, rr_val));
            }

            // Proxy Service'e nereye gideceğini sor
            let to_header_val = packet.get_header_value(HeaderName::To).cloned().unwrap_or_default();
            let routing_destination = sip_utils::extract_aor(&to_header_val);
            
            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: routing_destination,
                source_ip: src_addr.ip().to_string(),
                method: method.clone(),
            });

            match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => {
                    let r = res.into_inner();
                    
                    // KENDİ VIA BAŞLIĞIMIZI EKLİYORUZ (Builder kullanarak)
                    // Bu sayede cevap dönerken bizi bulabilirler.
                    let via_header = sip_builder::build_via_header(
                        &self.config.sip_public_ip, 
                        self.config.sip_port, 
                        "UDP"
                    );
                    packet.headers.insert(0, via_header);
                    
                    if !r.uri.is_empty() {
                         self.resolve_address(&r.uri).await
                    } else { 
                        warn!("⚠️ Proxy service returned empty URI for destination.");
                        None 
                    }
                },
                Err(e) => {
                    error!("🔥 Proxy Service RPC Failed: {}", e);
                    None
                }
            }
        } else { 
            // 2. Gelen Response: Via stripping ve Geri Yönlendirme
            
            // En üstteki Via (bizim eklediğimiz) kaldırılır.
            if !packet.headers.is_empty() && packet.headers[0].name == HeaderName::Via {
                packet.headers.remove(0);
            } else {
                warn!("⚠️ Response received but no Via header found to strip.");
                return; 
            }

            // Sıradaki Via başlığına bakarak cevabı kime göndereceğimizi buluruz.
            if let Some(client_via) = packet.headers.iter().find(|h| h.name == HeaderName::Via) {
                self.parse_via_address(&client_via.value)
            } else { 
                warn!("⚠️ Response has no second Via header, cannot route back.");
                None 
            }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            if let Err(e) = self.transport.send(&data, target).await {
                error!("🔥 Failed to send forwarded packet to {}: {}", target, e);
            }
        } else {
            warn!("⚠️ No routing target found for packet. Dropping.");
        }
    }

    async fn resolve_address(&self, address: &str) -> Option<SocketAddr> {
         // Eğer IP:Port formatındaysa direkt parse etmeye çalış
         if let Ok(addr) = address.parse::<SocketAddr>() {
             return Some(addr);
         }

         // Değilse DNS lookup yap
         match lookup_host(address).await {
            Ok(mut addrs) => addrs.next(),
            Err(e) => {
                error!("DNS Resolution failed for {}: {}", address, e);
                None
            }
        }
    }
    
    // Via header parse etme (RFC 3261 compliant)
    // received ve rport parametrelerine öncelik verir.
    fn parse_via_address(&self, via_val: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = via_val.split_whitespace().collect();
        if parts.len() < 2 { return None; }
        
        // parts[0] -> SIP/2.0/UDP
        // parts[1] -> 1.2.3.4:5060;branch=...
        let protocol_part = parts[1];
        let params: Vec<&str> = protocol_part.split(';').collect();
        let mut host_part = params[0].to_string(); 
        
        let mut rport: Option<String> = None;
        let mut received: Option<String> = None;

        for param in &params[1..] {
             let p_trim = param.trim();
            if let Some((k, v)) = p_trim.split_once('=') {
                if k == "received" { received = Some(v.to_string()); }
                if k == "rport" { rport = Some(v.to_string()); }
            }
        }

        // 1. Öncelik: received + rport (NAT arkası istemci)
        if let (Some(rec), Some(rp)) = (received, rport) {
            return format!("{}:{}", rec, rp).parse().ok();
        }

        // 2. Öncelik: Sadece host_part (Direkt IP veya DNS)
        if !host_part.contains(':') {
             host_part = format!("{}:{}", host_part, DEFAULT_SIP_PORT);
        }
        host_part.parse().ok()
    }
}