// sentiric-sbc-service/src/sip/handlers/security.rs
use dashmap::DashMap;
use governor::{Quota, RateLimiter}; 
use governor::state::{InMemoryState, NotKeyed};
use governor::clock::DefaultClock;
use std::net::IpAddr;
use std::sync::Arc;
use std::num::NonZeroU32;
use tracing::{warn, info};

pub struct SecurityHandler {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    blacklist: DashMap<IpAddr, String>,
}

impl SecurityHandler {
    pub fn new(max_requests_per_second: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(max_requests_per_second).unwrap());
        let limiter = Arc::new(RateLimiter::direct(quota));

        Self {
            limiter,
            blacklist: DashMap::new(),
        }
    }

    pub fn check_access(&self, ip: IpAddr) -> bool {
        if self.blacklist.contains_key(&ip) {
            warn!("🚫 BLOCKED: Blacklisted source detected: {}", ip);
            return false;
        }

        if self.limiter.check().is_err() {
            warn!("⏳ THROTTLED: Rate limit exceeded from source: {}", ip);
            return false;
        }

        true
    }

    pub fn ban(&self, ip: IpAddr, reason: &str) {
        self.blacklist.insert(ip, reason.to_string());
        info!("⛔ IP BANNED: {} - Reason: {}", ip, reason);
    }
}