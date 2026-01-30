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

                            // [TRACE] İlk Temas
                            info!("🔫 [TRACE-SBC] UDP Paket Geldi. Src: {} | Len: {}", src_addr, len);

                            let data = &buf[..len];
                            match parser::parse(data) {
                                Ok(packet) => {
                                    match self.engine.inspect(&packet) {
                                        SipAction::Forward => self.handle_forwarding(packet, src_addr).await,
                                        SipAction::Drop => warn!("Packet dropped from {}", src_addr),
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
        let call_id = packet.get_header_value(HeaderName::CallId).cloned().unwrap_or_default();

        info!("🔫 [TRACE-SBC] İşleniyor: {} | CallID: {}", method, call_id);

        let target_addr = if packet.is_request {
            if let Some(via_header) = packet.headers.iter_mut().find(|h| h.name == HeaderName::Via) {
                let has_rport_value = via_header.value.contains("rport=");
                let has_rport_flag = via_header.value.contains(";rport");

                if !via_header.value.contains("received=") {
                    via_header.value.push_str(&format!(";received={}", src_addr.ip()));
                }

                if !has_rport_value {
                    if has_rport_flag {
                         via_header.value = via_header.value.replace(";rport", &format!(";rport={}", src_addr.port()));
                    } else {
                         via_header.value.push_str(&format!(";rport={}", src_addr.port()));
                    }
                }
            }
            
            let rr_val = format!("<sip:{}:{};lr>", self.config.sip_public_ip, self.config.sip_port);
            packet.headers.insert(0, Header::new(HeaderName::RecordRoute, rr_val));

            // --- KRİTİK DÜZELTME BAŞLANGICI ---
            // Request-URI yerine, To header'ındaki AOR adresini kullanıyoruz.
            // Bu, ACK ve BYE mesajlarında 'Request-URI' Contact adresi (IP) olsa bile
            // Proxy'nin '9998' kullanıcısını (To) görüp doğru yönlendirme yapmasını sağlar.
            
            let to_header_val = packet.get_header_value(HeaderName::To).cloned().unwrap_or_default();
            // AOR extract (tag vb. temizle) -> sip:9998@domain
            let routing_destination = sip_utils::extract_aor(&to_header_val);
            
            info!("🔫 [TRACE-SBC] Proxy'e Soruluyor (Via To-Header): {}", routing_destination);

            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: routing_destination, // Düzeltilmiş URI
                source_ip: src_addr.ip().to_string(),
                method: method.clone(),
            });
            // --- KRİTİK DÜZELTME SONU ---

            match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => {
                    let r = res.into_inner();
                    let via_val = format!("SIP/2.0/UDP {}:{};branch=z9hG4bK-sbc-{}", 
                        self.config.sip_public_ip,
                        self.config.sip_port,
                        rand::random::<u32>()
                    );
                    packet.headers.insert(0, Header::new(HeaderName::Via, via_val));
                    
                    let uri = r.uri;
                    if !uri.is_empty() {
                         info!("🔫 [TRACE-SBC] Proxy Yanıtı: Next Hop URI: {}", uri);
                         self.resolve_address(&uri).await
                    } else {
                         error!("Proxy Service'den yönlendirme hedefi alınamadı (URI boş).");
                         None
                    }
                },
                Err(e) => {
                    error!("Proxy Service gRPC çağrısı başarısız: {}", e);
                    None
                }
            }
        } else { 
            let mut removed_own_via = false;
            if !packet.headers.is_empty() && packet.headers[0].name == HeaderName::Via {
                let via_val_clone = packet.headers[0].value.clone();
                packet.headers.remove(0);
                removed_own_via = true;
                debug!("SBC Via header removed. Original: {}", via_val_clone);
            }

            if !removed_own_via {
                 warn!("Response packet missing Via header or logic error.");
                 return;
            }

            if let Some(client_via) = packet.headers.iter().find(|h| h.name == HeaderName::Via) {
                self.parse_via_address(&client_via.value)
            } else {
                warn!("Response packet has no more Via headers. Cannot route back to client.");
                None
            }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            info!("🔫 [TRACE-SBC] Yönlendirme: {} ({} byte) -> {}", packet.method.to_string(), data.len(), target);
            
            if let Err(e) = self.transport.send(&data, target).await {
                error!("Failed to forward packet to {}: {}", target, e);
            }
        } else {
            warn!("Hedef adres çözülemedi, paket düşürülüyor.");
        }
    }

    async fn resolve_address(&self, address: &str) -> Option<SocketAddr> {
         match lookup_host(address).await {
            Ok(mut addrs) => {
                let addr = addrs.next();
                info!("🔫 [TRACE-SBC] DNS Çözümleme: {} -> {:?}", address, addr);
                addr
            },
            Err(e) => {
                error!("DNS Resolution error for target {}: {}", address, e);
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

        if let (Some(r), Some(rec)) = (rport, received) {
            return format!("{}:{}", rec, r).parse().ok();
        }

        if !host_part.contains(':') {
             host_part = format!("{}:{}", host_part, DEFAULT_SIP_PORT);
        }
        host_part.parse().ok()
    }
}