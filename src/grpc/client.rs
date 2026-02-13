// sentiric-sbc-service/src/grpc/client.rs
use crate::config::AppConfig;
use crate::error::ServiceError;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{info, warn, error};
use std::time::Duration;

// gRPC İstemcisi
use sentiric_contracts::sentiric::sip::v1::proxy_service_client::ProxyServiceClient;

pub struct ProxyClient;

impl ProxyClient {
    /// Proxy Service'e gRPC üzerinden bağlanır. 
    /// Bağlantı kurulana kadar sonsuza kadar dener.
    pub async fn connect(
        config: Arc<AppConfig>,
    ) -> Result<Arc<Mutex<ProxyServiceClient<Channel>>>, ServiceError> {
        info!("🔌 Proxy Service'e bağlanılıyor: {}", &config.proxy_grpc_addr);

        // Sertifikaları yükle (Dosya okuma hataları hala kritiktir)
        let identity = {
            let cert = fs::read(&config.cert_path)
                .await
                .context("İstemci sertifikası okunamadı (SBC_SERVICE_CERT_PATH)")?;
            let key = fs::read(&config.key_path)
                .await
                .context("İstemci anahtarı okunamadı (SBC_SERVICE_KEY_PATH)")?;
            Identity::from_pem(cert, key)
        };

        let ca_cert = {
            let ca = fs::read(&config.ca_path)
                .await
                .context("CA sertifikası okunamadı (GRPC_TLS_CA_PATH)")?;
            Certificate::from_pem(ca)
        };

        let tls_config = ClientTlsConfig::new()
            .domain_name("proxy-service") 
            .ca_certificate(ca_cert)
            .identity(identity);

        // --- RESILIENT CONNECTION LOOP ---
        let mut attempt = 0;
        loop {
            attempt += 1;
            
            // 1. Channel Yapılandırması
            let channel_res = Channel::from_shared(config.proxy_grpc_addr.clone())
                .map_err(|e| ServiceError::ConfigError(anyhow::anyhow!("Geçersiz URL: {}", e)))?
                .tls_config(tls_config.clone())
                .map_err(|e| ServiceError::ConfigError(anyhow::anyhow!("TLS Konfig Hatası: {}", e)))?
                .connect_timeout(Duration::from_secs(5))
                .connect()
                .await;

            match channel_res {
                Ok(channel) => {
                    info!("✅ Proxy Service bağlantısı sağlandı (Deneme: {}).", attempt);
                    let client = ProxyServiceClient::new(channel);
                    return Ok(Arc::new(Mutex::new(client)));
                }
                Err(e) => {
                    error!(
                        "⚠️ Proxy Service'e bağlanılamadı (Deneme: {}): {}. 5 saniye sonra tekrar denenecek...",
                        attempt, e
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}