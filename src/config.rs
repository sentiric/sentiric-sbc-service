// sentiric-sbc-service/src/config.rs
use anyhow::{Context, Result};
use std::env;
use std::net::SocketAddr;

#[derive(Debug)]
pub struct AppConfig {
    pub grpc_listen_addr: SocketAddr,
    pub http_listen_addr: SocketAddr,
    
    pub env: String,
    pub rust_log: String,
    pub service_version: String,
    
    // TLS Yolları
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
    
    // Bağımlılıklar 
    pub proxy_service_url: String,
}

impl AppConfig {
    pub fn load_from_env() -> Result<Self> {
        // SBC için Harmonik Portlar (Örn: 1209X bloğu atandı)
        let grpc_port = env::var("SBC_SERVICE_GRPC_PORT").unwrap_or_else(|_| "12091".to_string());
        let http_port = env::var("SBC_SERVICE_HTTP_PORT").unwrap_or_else(|_| "12090".to_string());
        
        let grpc_addr: SocketAddr = format!("[::]:{}", grpc_port).parse()?;
        let http_addr: SocketAddr = format!("[::]:{}", http_port).parse()?;
            
        Ok(AppConfig {
            grpc_listen_addr: grpc_addr,
            http_listen_addr: http_addr, 

            proxy_service_url: env::var("PROXY_SERVICE_TARGET_GRPC_URL").context("ZORUNLU: PROXY_SERVICE_TARGET_GRPC_URL eksik")?,
            
            env: env::var("ENV").unwrap_or_else(|_| "production".to_string()),
            rust_log: env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            service_version: env::var("SERVICE_VERSION").unwrap_or_else(|_| "0.1.0".to_string()),
            
            // TODO: Bu yollar config repo'da SBC_SERVICE olarak güncellenmelidir.
            cert_path: env::var("SBC_SERVICE_CERT_PATH").context("ZORUNLU: SBC_SERVICE_CERT_PATH eksik")?,
            key_path: env::var("SBC_SERVICE_KEY_PATH").context("ZORUNLU: SBC_SERVICE_KEY_PATH eksik")?,
            ca_path: env::var("GRPC_TLS_CA_PATH").context("ZORUNLU: GRPC_TLS_CA_PATH eksik")?,
        })
    }
}