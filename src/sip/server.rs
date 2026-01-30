// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tonic::transport::Channel;
// DÜZELTME: Kullanılmayanları kaldırdık
use tracing::{info, error, debug, warn, instrument}; 
use sentiric_sip_core::{SipTransport, parser, SipPacket, HeaderName, Header, utils as sip_utils};
use crate::config::AppConfig;
use sentiric_contracts::sentiric::sip::v1::{proxy_service_client::ProxyServiceClient, GetNextHopRequest};
use crate::sip::engine::{SbcEngine, SipAction};
use crate::rtp::engine::RtpEngine;
use tokio::net::lookup_host;
use std::net::SocketAddr;


const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
    rtp_engine: Arc<RtpEngine>, // YENİ
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
                _ = shutdown_rx.recv() => { break; }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            if len < 4 { continue; }
                            let data = &buf[..len];
                            match parser::parse(data) {
                                Ok(packet) => {
                                    match self.engine.inspect(&packet, src_addr) {
                                        SipAction::Forward => self.handle_forwarding(packet, src_addr).await,
                                        SipAction::Drop => {},
                                    }
                                },
                                Err(_) => {}
                            }
                        },
                        Err(_) => {},
                    }
                }
            }
        }
    }

    // --- SDP MANIPULATION HELPER ---
    fn rewrite_sdp(body: &[u8], new_ip: &str, new_port: u16) -> Option<Vec<u8>> {
        let sdp_str = std::str::from_utf8(body).ok()?;
        let mut new_sdp = String::new();
        let mut modified = false;

        // Regex yerine basit string replace (daha hızlı ve güvenli)
        // c=IN IP4 x.x.x.x -> c=IN IP4 <new_ip>
        // m=audio <port> ... -> m=audio <new_port> ...

        for line in sdp_str.lines() {
            if line.starts_with("c=IN IP4") {
                new_sdp.push_str(&format!("c=IN IP4 {}\r\n", new_ip));
                modified = true;
            } else if line.starts_with("m=audio") {
                // m=audio 12345 RTP/AVP 0 8...
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    // parts[0]=m=audio, parts[1]=port, parts[2]=proto...
                    let mut new_line = format!("{} {} {}", parts[0], new_port, parts[2]);
                    // Kalan kısımları ekle (codec listesi)
                    for p in &parts[3..] {
                        new_line.push(' ');
                        new_line.push_str(p);
                    }
                    new_line.push_str("\r\n");
                    new_sdp.push_str(&new_line);
                    modified = true;
                } else {
                    new_sdp.push_str(line);
                    new_sdp.push_str("\r\n");
                }
            } else {
                new_sdp.push_str(line);
                new_sdp.push_str("\r\n");
            }
        }

        if modified { Some(new_sdp.as_bytes().to_vec()) } else { None }
    }

    async fn handle_forwarding(&self, mut packet: SipPacket, src_addr: SocketAddr) {
        let method = packet.method.to_string();
        
        // --- RTP RELAY LOGIC (Man-in-the-Middle) ---
        // Sadece INVITE ve 200 OK (INVITE cevabı) için devreye girer.
        let has_sdp = packet.body.len() > 0 && 
                      packet.get_header_value(HeaderName::ContentType)
                            .map_or(false, |v| v.contains("application/sdp"));

        if has_sdp && (method == "INVITE" || (packet.status_code == 200 && packet.get_header_value(HeaderName::CSeq).map_or(false, |v| v.contains("INVITE")))) {
            
            // 1. Yeni bir Relay Port ayır
            if let Some(relay_port) = self.rtp_engine.allocate_relay().await {
                
                // 2. Hangi IP'yi yazacağız?
                // EĞER REQUEST (INVITE) İSE -> Internal IP yaz (UAS görsün)
                // EĞER RESPONSE (200 OK) İSE -> Public IP yaz (Operator görsün)
                let advertise_ip = if packet.is_request {
                    &self.config.sip_internal_ip 
                } else {
                    &self.config.sip_public_ip
                };

                // 3. SDP'yi Değiştir
                if let Some(new_body) = Self::rewrite_sdp(&packet.body, advertise_ip, relay_port) {
                    packet.body = new_body;
                    info!("🎤 [SBC-MEDIA] SDP Rewritten: Advertise {} Port {}", advertise_ip, relay_port);
                    
                    // Content-Length güncelle (Kritik!)
                    // Header'ı bul ve değiştir veya silip ekle
                    packet.headers.retain(|h| h.name != HeaderName::ContentLength);
                    packet.headers.push(Header::new(HeaderName::ContentLength, packet.body.len().to_string()));
                }
            }
        }

        // ... (Geri kalan yönlendirme mantığı AYNEN KALIYOR)
        // Aşağıdaki kodlar önceki `handle_forwarding` ile aynıdır, buraya kopyala-yapıştır yapıyorum.
        
        let target_addr = if packet.is_request {
            if let Some(via_header) = packet.headers.iter_mut().find(|h| h.name == HeaderName::Via) {
                if !via_header.value.contains("received=") {
                    via_header.value.push_str(&format!(";received={}", src_addr.ip()));
                }
                if !via_header.value.contains("rport=") {
                     via_header.value.push_str(&format!(";rport={}", src_addr.port()));
                }
            }
            
            let rr_val = format!("<sip:{}:{};lr>", self.config.sip_public_ip, self.config.sip_port);
            if method == "INVITE" {
                packet.headers.insert(0, Header::new(HeaderName::RecordRoute, rr_val));
            }

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
                    let via_val = format!("SIP/2.0/UDP {}:{};branch=z9hG4bK-sbc-{}", 
                        self.config.sip_public_ip,
                        self.config.sip_port,
                        rand::random::<u32>()
                    );
                    packet.headers.insert(0, Header::new(HeaderName::Via, via_val));
                    
                    if !r.uri.is_empty() {
                         self.resolve_address(&r.uri).await
                    } else { None }
                },
                Err(_) => None
            }
        } else { 
            if !packet.headers.is_empty() && packet.headers[0].name == HeaderName::Via {
                packet.headers.remove(0);
            } else { return; }

            if let Some(client_via) = packet.headers.iter().find(|h| h.name == HeaderName::Via) {
                self.parse_via_address(&client_via.value)
            } else { None }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            let _ = self.transport.send(&data, target).await;
        }
    }

    async fn resolve_address(&self, address: &str) -> Option<SocketAddr> {
         match lookup_host(address).await {
            Ok(mut addrs) => addrs.next(),
            Err(_) => None
        }
    }
    
    fn parse_via_address(&self, via_val: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = via_val.split_whitespace().collect();
        if parts.len() < 2 { return None; }
        
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

        if let (Some(rec), Some(rp)) = (received, rport) {
            return format!("{}:{}", rec, rp).parse().ok();
        }

        if !host_part.contains(':') {
             host_part = format!("{}:{}", host_part, DEFAULT_SIP_PORT);
        }
        host_part.parse().ok()
    }
}