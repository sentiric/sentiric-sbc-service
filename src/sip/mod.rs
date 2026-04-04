// sentiric-sbc-service/src/sip/mod.rs

pub mod engine;
pub mod handlers;
pub mod server;

// DÜZELTME: 'pub mod security;' silindi.
// Artık 'crate::sip::handlers::security' kullanılıyor.
