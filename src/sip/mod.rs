// sentiric-sbc-service/src/sip/mod.rs

pub mod server;
pub mod engine;
pub mod handlers;

// DÜZELTME: 'pub mod security;' silindi. 
// Artık 'crate::sip::handlers::security' kullanılıyor.