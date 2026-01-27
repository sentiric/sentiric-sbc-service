// sentiric-sbc-service/src/sip/server.rs

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tonic::transport::Channel;
use tracing::{debug, error, info, instrument, warn};
use sentiric_sip_core::{SipTransport, parser, SipPacket, HeaderName, Header};
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
                            let data = &buf[..len];
                            match parser::parse(data) {
                                Ok(packet) => {
                                    match self.engine.inspect(&packet) {
                                        SipAction::Forward => self.handle_forwarding(packet, src_addr).await,
                                        SipAction::Drop => warn!("Packet dropped from {}", src_addr),
                                    }
                                },
                                Err(e) => if len > 4 { warn!("Malformed SIP: {}", e); }
                            }
                        },
                        Err(e) => error!("UDP Error: {}", e),
                    }
                }
            }
        }
    }

    #[instrument(
        skip(self, packet), 
        fields(
            sip.method = %packet.method, 
            sip.call_id = %packet.get_header_value(HeaderName::CallId).map_or("", |v| v.as_str())
        )
    )]
    async fn handle_forwarding(&self, mut packet: SipPacket, src_addr: SocketAddr) {
        debug!(
            source = %src_addr,
            sip.request_uri = %packet.uri,
            "Gelen SIP paketi işleniyor"
        );

        let target_addr = if packet.is_request {
            // --- REQUEST HANDLING (AYNI) ---
            if let Some(via_header) = packet.headers.iter_mut().find(|h| h.name == HeaderName::Via) {
                if !via_header.value.contains("received=") {
                    via_header.value.push_str(&format!(";received={}", src_addr.ip()));
                }
                if !via_header.value.contains("rport=") {
                     via_header.value.push_str(&format!(";rport={}", src_addr.port()));
                }
            }
            
            let rr_val = format!("<sip:{}:{};lr>", self.config.sip_public_ip, self.config.sip_port);
            packet.headers.insert(0, Header::new(HeaderName::RecordRoute, rr_val));

            let req_uri = packet.uri.clone();
            let method_str = packet.method.to_string(); 

            let request = tonic::Request::new(GetNextHopRequest {
                destination_uri: req_uri.clone(),
                source_ip: src_addr.ip().to_string(),
                method: method_str,
            });

            let response = match self.proxy_client.lock().await.get_next_hop(request).await {
                Ok(res) => Some(res.into_inner()),
                Err(e) => {
                    error!("Proxy Service gRPC çağrısı başarısız: {}", e);
                    return;
                }
            };
            
            match response {
                Some(res) => {
                    let via_val = format!("SIP/2.0/UDP {}:{};branch=z9hG4bK-sbc-{}", 
                        self.config.sip_public_ip,
                        self.config.sip_port,
                        rand::random::<u32>()
                    );
                    packet.headers.insert(0, Header::new(HeaderName::Via, via_val));
                    self.resolve_address(&res.uri).await
                },
                None => {
                    error!("Proxy Service'den yönlendirme hedefi alınamadı.");
                    None
                }
            }
        } else { 
            // --- RESPONSE HANDLING (DÜZELTİLMİŞ) ---
            
            // 1. Kendi Via başlığımızı (en üstteki) kontrol et ve kaldır.
            // SBC, isteği gönderirken kendi Via başlığını eklemişti. Yanıt dönerken bu başlık en üstte olur.
            // Bunu çıkarıp altındaki Via başlığına (Müşterinin adresi) göndermeliyiz.
            
            let mut removed_own_via = false;
            if !packet.headers.is_empty() && packet.headers[0].name == HeaderName::Via {
                // Güvenlik kontrolü: Gerçekten bizim Via mı? (Basitçe IP kontrolü veya branch id)
                // Şimdilik varsayılan olarak ilk Via'yı biz ekledik varsayıyoruz.
                let via_val = &packet.headers[0].value;
                if via_val.contains(&self.config.sip_public_ip) || via_val.contains(&self.config.sip_bind_ip) || via_val.contains("sbc") {
                     packet.headers.remove(0);
                     removed_own_via = true;
                     debug!("SBC Via header removed.");
                } else {
                    // Eğer ilk Via bizim değilse, bu paket bize ait olmayabilir veya yapı bozuktur.
                    // Yine de forwarding deneyebiliriz ama loglamak lazım.
                    warn!("Top Via header does not match SBC signature: {}", via_val);
                    // Yine de kaldıralım, belki IP farklı görünüyordur (Docker vs).
                    packet.headers.remove(0);
                    removed_own_via = true;
                }
            }

            if !removed_own_via {
                 warn!("Response packet missing Via header or logic error.");
                 return;
            }

            // 2. Bir sonraki Via başlığını bul (Müşterinin adresi)
            if let Some(client_via) = packet.headers.iter().find(|h| h.name == HeaderName::Via) {
                self.parse_via_address(&client_via.value)
            } else {
                warn!("Response packet has no more Via headers. Cannot route back to client.");
                None
            }
        };

        if let Some(target) = target_addr {
            let data = packet.to_bytes();
            info!("↪️ Yönlendirme: {} ({} byte) -> {}", packet.status_code, data.len(), target);
            if let Err(e) = self.transport.send(&data, target).await {
                error!("Failed to forward packet to {}: {}", target, e);
            }
        } else {
            warn!("Hedef adres çözülemedi, paket düşürülüyor.");
        }
    }

    async fn resolve_address(&self, address: &str) -> Option<SocketAddr> {
         match lookup_host(address).await {
            Ok(mut addrs) => addrs.next(),
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

        // Eğer received ve rport varsa (NAT), onu kullan.
        if let (Some(r), Some(rec)) = (rport, received) {
            return format!("{}:{}", rec, r).parse().ok();
        }

        // Yoksa host part'ı kullan.
        if !host_part.contains(':') {
             host_part = format!("{}:{}", host_part, DEFAULT_SIP_PORT);
        }
        host_part.parse().ok()
    }
}