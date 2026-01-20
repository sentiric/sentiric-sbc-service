// sentiric-sbc-service/src/config.rs
use anyhow::{Context, Result};
use std::env;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub grpc_listen_addr: SocketAddr,
    pub http_listen_addr: SocketAddr,
    
    // SIP Network
    pub sip_bind_ip: String,
    pub sip_port: u16,
    
    // Routing Targets
    pub proxy_sip_addr: SocketAddr, // UDP Forwarding Target
    
    pub env: String,
    pub rust_log: String,
    pub service_version: String,
    
    // TLS Yolları
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
}

impl AppConfig {
    pub fn load_from_env() -> Result<Self> {
        // SBC Harmonik Portlar: 1309X
        let grpc_port = env::var("SBC_SERVICE_GRPC_PORT").unwrap_or_else(|_| "13091".to_string());
        let http_port = env::var("SBC_SERVICE_HTTP_PORT").unwrap_or_else(|_| "13090".to_string());
        
        // SIP Port (Container içi 5060 veya host map)
        let sip_port_str = env::var("SBC_SERVICE_SIP_PORT").unwrap_or_else(|_| "5060".to_string());
        let sip_port = sip_port_str.parse::<u16>().context("Geçersiz SIP portu")?;
        
        let grpc_addr: SocketAddr = format!("[::]:{}", grpc_port).parse()?;
        let http_addr: SocketAddr = format!("[::]:{}", http_port).parse()?;
        
        // Proxy Service SIP Adresi (UDP Forwarding için)
        // Örn: "proxy-service:5060" veya "10.88.30.7:5060"
        let proxy_target = env::var("PROXY_SERVICE_SIP_TARGET").context("ZORUNLU: PROXY_SERVICE_SIP_TARGET eksik (örn: 10.88.30.7:5060)")?;
        let proxy_sock_addr: SocketAddr = proxy_target.parse().context("Geçersiz Proxy SIP Adresi")?;

        Ok(AppConfig {
            grpc_listen_addr: grpc_addr,
            http_listen_addr: http_addr, 
            
            sip_bind_ip: "0.0.0.0".to_string(),
            sip_port,
            
            proxy_sip_addr: proxy_sock_addr,

            env: env::var("ENV").unwrap_or_else(|_| "production".to_string()),
            rust_log: env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            service_version: env::var("SERVICE_VERSION").unwrap_or_else(|_| "1.0.0".to_string()),
            
            cert_path: env::var("SBC_SERVICE_CERT_PATH").context("ZORUNLU: SBC_SERVICE_CERT_PATH eksik")?,
            key_path: env::var("SBC_SERVICE_KEY_PATH").context("ZORUNLU: SBC_SERVICE_KEY_PATH eksik")?,
            ca_path: env::var("GRPC_TLS_CA_PATH").context("ZORUNLU: GRPC_TLS_CA_PATH eksik")?,
        })
    }
}