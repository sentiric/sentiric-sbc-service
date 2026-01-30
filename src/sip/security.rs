// sentiric-sbc-service/src/sip/security.rs

use dashmap::DashMap;
// DÜZELTME: Jitter kaldırıldı
use governor::{Quota, RateLimiter}; 
use governor::state::{InMemoryState, NotKeyed};
use governor::clock::DefaultClock;
use std::net::IpAddr;
use std::sync::Arc;
use std::num::NonZeroU32;
use tracing::{warn, info};

pub struct SecurityGuard {
    // IP bazlı Rate Limiter (Basit versiyon: Global limiter, ileride IP bazlı yapılabilir)
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    // Karalıste (Manuel veya Otomatik)
    blacklist: DashMap<IpAddr, String>,
}

impl SecurityGuard {
    pub fn new(max_requests_per_second: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(max_requests_per_second).unwrap());
        let limiter = Arc::new(RateLimiter::direct(quota));

        Self {
            limiter,
            blacklist: DashMap::new(),
        }
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // 1. Blacklist Kontrolü
        if self.blacklist.contains_key(&ip) {
            warn!("🚫 BLOCKED: Blacklisted IP detected: {}", ip);
            return false;
        }

        // 2. Rate Limiting Check
        if self.limiter.check().is_err() {
            warn!("⏳ THROTTLED: Rate limit exceeded for traffic (Source: {})", ip);
            // Opsiyonel: Çok ısrar ederse blacklist'e al
            return false;
        }

        true
    }

    pub fn ban_ip(&self, ip: IpAddr, reason: String) {
        self.blacklist.insert(ip, reason.clone());
        info!("⛔ IP BANNED: {} - Reason: {}", ip, reason);
    }
}