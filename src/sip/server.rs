// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tonic::transport::Channel;
use tracing::{debug, error, info, instrument, warn};
use sentiric_sip_core::{SipTransport, parser, SipPacket, HeaderName, Header, utils as sip_utils};
use crate::config::AppConfig;
use sentiric_contracts::sentiric::sip::v1::{proxy_service_client::ProxyServiceClient, GetNextHopRequest};
use crate::sip::engine::{SbcEngine, SipAction};
use tokio::net::lookup_host;
use std::net::SocketAddr;

const DEFAULT_SIP_PORT: u16 = 5060;

pub struct SipServer {
    config: Arc<AppConfig>,
    transport: Arc<SipTransport>,
    engine: SbcEngine,
    proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
}

impl SipServer {
    pub async fn new(
        config: Arc<AppConfig>,
        proxy_client: Arc<Mutex<ProxyServiceClient<Channel>>>,
    ) -> anyhow::Result<Self> {
        let bind_addr = format!("{}:{}", config.sip_bind_ip, config.sip_port);
        let transport = SipTransport::new(&bind_addr).await?;
        Ok(Self {
            config,
            transport: Arc::new(transport),
            engine: SbcEngine::new(),
            proxy_client,
        })
    }

    pub async fn run(self, mut shutdown_rx: mpsc::Receiver<()>) {
        info!("📡 SBC SIP Listener aktif: {}:{}", self.config.sip_bind_ip, self.config.sip_port);
        let mut buf = vec![0u8; 65535];
        let socket = self.transport.get_socket();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("🛑 SIP Server kapatılıyor...");
                    break;
                }
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, src_addr)) => {
                            if len < 4 || buf[..len].iter().all(|&b| b == b'\r' || b == b'\n' || b == 0) {
                                continue;
                            }

                            let data = &buf[..len];
                            match parser::parse(data) {
                                Ok(packet) => {
                                    // Security Engine kontrolü
                                    match self.engine.inspect(&packet, src_addr) {
                                        SipAction::Forward => self.handle_forwarding(packet, src_addr).await,
                                        SipAction::Drop => { /* Drop logu engine içinde */ },
                                    }
                                },
                                Err(e) => {
                                     warn!("Malformed SIP from {}: {}", src_addr, e); 
                                }
                            }
                        },
                        Err(e) => error!("UDP Error: {}", e),
                    }
                }
            }
        }
    }

    #[instrument(skip(self, packet), fields(call_id = %packet.get_header_value(HeaderName::CallId).map_or("", |v| v.as_str())))]
    async fn handle_forwarding(&self, mut packet: SipPacket, src_addr: SocketAddr) {
        let method = packet.method.to_string();
        
        let target_addr = if packet.is_request {
            // --- INBOUND REQUEST PROCESSING (INVITE, BYE from Operator) ---
            
            // 1. NAT Fix: Via header manipülasyonu
            if let Some(via_header) = packet.headers.iter_mut().find(|h| h.name == HeaderName::Via) {
                if !via_header.value.contains("received=") {
                    via_header.value.push_str(&format!(";received={}", src_addr.ip()));
                }
                if !via_header.value.contains("rport=") {
                     via_header.value.push_str(&format!(";rport={}", src_addr.port()));
                }
            }
            
            // 2. Topology Hiding & Routing Guarantee: Record-Route ekle
            // Bu kritik: İstemci (Operator/Baresip) sonraki istekleri (BYE) nereye atacağını buradan öğrenir.
            // lr=true (loose routing) önemli.
            let rr_val = format!("<sip:{}:{};lr>", self.config.sip_public_ip, self.config.sip_port);
            
            // Record-Route sadece Dialog başlatan isteklerde (INVITE) eklenmelidir.
            if method == "INVITE" {
                // Varsa en başa ekle, yoksa oluştur
                packet.headers.insert(0, Header::new(HeaderName::RecordRoute, rr_val));
                debug!("📝 [SBC] Record-Route injected: {}", self.config.sip_public_ip);
            }

            // 3. Routing Decision (Proxy'e sor)
            let to_header_val = packet.get_header_value(HeaderName::To).cloned().unwrap_or_default();
            
            // KRİTİK: Eğer bu bir BYE ise ve Route header varsa, Proxy'e sormadan Route header'a göre gitmeli.
            // Ancak şu anki mimaride Proxy stateless router olduğu için Proxy'e sormak daha güvenli.
            
            let routing_destination = sip_utils::extract_aor(&to_header_val);
            
            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: routing_destination,
                source_ip: src_addr.ip().to_string(),
                method: method.clone(),
            });

            match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => {
                    let r = res.into_inner();
                    
                    // SBC kendi Via'sını ekler (Geri dönüş yolu)
                    let via_val = format!("SIP/2.0/UDP {}:{};branch=z9hG4bK-sbc-{}", 
                        self.config.sip_public_ip,
                        self.config.sip_port,
                        rand::random::<u32>()
                    );
                    packet.headers.insert(0, Header::new(HeaderName::Via, via_val));
                    
                    if !r.uri.is_empty() {
                         info!("🔀 [SBC] Routing {} -> {}", method, r.uri);
                         self.resolve_address(&r.uri).await
                    } else {
                         error!("Proxy Service yönlendirme hedefi boş döndü.");
                         None
                    }
                },
                Err(e) => {
                    error!("Proxy Service unreachable: {}", e);
                    None
                }
            }
        } else { 
            // --- OUTBOUND RESPONSE PROCESSING (200 OK from Internal) ---
            
            // 1. SBC'nin eklediği en üstteki Via'yı kaldır
            if !packet.headers.is_empty() && packet.headers[0].name == HeaderName::Via {
                packet.headers.remove(0);
            } else {
                 warn!("Response packet missing Via header. Dropping.");
                 return;
            }

            // 2. Bir sonraki Via başlığına bak (Müşterinin adresi orada yazar)
            if let Some(client_via) = packet.headers.iter().find(|h| h.name == HeaderName::Via) {
                self.parse_via_address(&client_via.value)
            } else {
                warn!("Response packet has no destination Via header. Dropping.");
                None
            }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            if let Err(e) = self.transport.send(&data, target).await {
                error!("Packet forwarding failed to {}: {}", target, e);
            } else {
                debug!("🚀 Forwarded {} ({} bytes) -> {}", method, data.len(), target);
            }
        }
    }

    async fn resolve_address(&self, address: &str) -> Option<SocketAddr> {
         match lookup_host(address).await {
            Ok(mut addrs) => addrs.next(),
            Err(e) => {
                error!("DNS Resolution error: {} -> {}", address, e);
                None
            }
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