// sentiric-sbc-service/src/grpc/client.rs
use crate::config::AppConfig;
use crate::error::ServiceError;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::info;

// DEĞİŞTİ: Artık harici kütüphaneden geliyor.
use sentiric_contracts::sentiric::sip::v1::proxy_service_client::ProxyServiceClient;

pub struct ProxyClient;

impl ProxyClient {
    pub async fn connect(
        config: Arc<AppConfig>,
    ) -> Result<Arc<Mutex<ProxyServiceClient<Channel>>>, ServiceError> {
        info!(
            "gRPC istemcisi Proxy Service'e bağlanıyor: {}",
            &config.proxy_grpc_addr
        );

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
            .domain_name("proxy-service") // SNI için kritik
            .ca_certificate(ca_cert)
            .identity(identity);

        let channel = Channel::from_shared(config.proxy_grpc_addr.clone())
            .context("Geçersiz gRPC hedef adresi")?
            .tls_config(tls_config)?
            .connect()
            .await?;

        let client = ProxyServiceClient::new(channel);
        info!("Proxy Service'e gRPC bağlantısı başarıyla kuruldu.");

        Ok(Arc::new(Mutex::new(client)))
    }
}