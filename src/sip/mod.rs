// sentiric-sbc-service/src/sip/mod.rs

pub mod server;
pub mod engine;
pub mod handlers;

// DÜZELTME: 'pub mod security;' satırı silindi. 
// Güvenlik artık 'handlers::security' içindedir.