// src/sip/handlers/security.rs
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
            // [ARCH-COMPLIANCE] SUTS v4.0 Structured Log
            warn!(
                event = "SIP_ACCESS_DENIED",
                net.src.ip = %ip,
                reason = "blacklisted",
                "🚫 [SBC-SEC] BLOCKED: Kaynak kara listede."
            );
            return false;
        }

        if self.limiter.check().is_err() {
            // [ARCH-COMPLIANCE] SUTS v4.0 Structured Log
            warn!(
                event = "SIP_RATE_LIMITED",
                net.src.ip = %ip,
                "⏳[SBC-SEC] THROTTLED: IP adresi rate limit'e takıldı."
            );
            return false;
        }
        true
    }

    pub fn ban(&self, ip: IpAddr, reason: &str) {
        self.blacklist.insert(ip, reason.to_string());
        //[ARCH-COMPLIANCE] SUTS v4.0 Structured Log
        info!(
            event = "SIP_IP_BANNED",
            net.src.ip = %ip,
            reason = %reason,
            "⛔ [SBC-SEC] IP BANNED: Kaynak banlandı."
        );
    }
}