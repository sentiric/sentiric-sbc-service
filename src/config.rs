// sentiric-sbc-service/src/config.rs
use anyhow::{Context, Result};
use std::env;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub grpc_listen_addr: SocketAddr,
    pub http_listen_addr: SocketAddr,
    
    pub sip_bind_ip: String,
    pub sip_port: u16,
    
    // Dış dünyaya ilan edilecek port
    pub sip_advertised_port: u16, 
    
    pub sip_public_ip: String, // Public IP
    pub sip_internal_ip: String, // Internal/Tailscale IP
    
    pub proxy_grpc_addr: String, 
    
    // [YENİ] B2BUA Hedef Limanı (Hardcode önleme)
    pub b2bua_internal_port: u16,
    
    // RTP Relay Settings
    pub rtp_start_port: u16,
    pub rtp_end_port: u16,
    
    pub env: String,
    pub rust_log: String,
    pub service_version: String,
    
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
}

impl AppConfig {
    pub fn load_from_env() -> Result<Self> {
        let grpc_port = env::var("SBC_SERVICE_GRPC_PORT").unwrap_or_else(|_| "13091".to_string());
        let http_port = env::var("SBC_SERVICE_HTTP_PORT").unwrap_or_else(|_| "13090".to_string());
        
        let sip_port_str = env::var("SBC_SERVICE_SIP_PORT").unwrap_or_else(|_| "13094".to_string());
        let sip_port = sip_port_str.parse::<u16>().context("Geçersiz SIP portu")?;
        
        let advertised_port = env::var("SBC_ADVERTISED_PORT")
            .unwrap_or_else(|_| "5060".to_string())
            .parse::<u16>()
            .unwrap_or(5060);

        let grpc_addr: SocketAddr = format!("[::]:{}", grpc_port).parse()?;
        let http_addr: SocketAddr = format!("[::]:{}", http_port).parse()?;
        
        let proxy_target = env::var("PROXY_SERVICE_GRPC_TARGET")
            .context("ZORUNLU: PROXY_SERVICE_GRPC_TARGET eksik")?;

        let public_ip = env::var("SBC_SERVICE_PUBLIC_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
        
        let internal_ip = env::var("SBC_SERVICE_INTERNAL_IP")
            .or_else(|_| env::var("NODE_IP"))
            .unwrap_or_else(|_| "127.0.0.1".to_string());

        // [YENİ]
        let b2bua_port = env::var("B2BUA_SERVICE_SIP_PORT")
            .unwrap_or_else(|_| "13084".to_string())
            .parse::<u16>()?;

        let rtp_start = env::var("SBC_RTP_START_PORT").unwrap_or_else(|_| "30000".to_string()).parse()?;
        let rtp_end = env::var("SBC_RTP_END_PORT").unwrap_or_else(|_| "30100".to_string()).parse()?;

        Ok(AppConfig {
            grpc_listen_addr: grpc_addr,
            http_listen_addr: http_addr, 
            
            sip_bind_ip: "0.0.0.0".to_string(),
            sip_port,
            sip_advertised_port: advertised_port,
            
            sip_public_ip: public_ip,
            sip_internal_ip: internal_ip,
            
            proxy_grpc_addr: proxy_target,
            b2bua_internal_port: b2bua_port, // Config'e eklendi
            
            rtp_start_port: rtp_start,
            rtp_end_port: rtp_end,

            env: env::var("ENV").unwrap_or_else(|_| "production".to_string()),
            rust_log: env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            service_version: env::var("SERVICE_VERSION").unwrap_or_else(|_| "1.0.0".to_string()),
            
            cert_path: env::var("SBC_SERVICE_CERT_PATH").context("ZORUNLU: SBC_SERVICE_CERT_PATH")?,
            key_path: env::var("SBC_SERVICE_KEY_PATH").context("ZORUNLU: SBC_SERVICE_KEY_PATH")?,
            ca_path: env::var("GRPC_TLS_CA_PATH").context("ZORUNLU: GRPC_TLS_CA_PATH")?,
        })
    }
}