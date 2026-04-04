// src/sip/handlers/security.rs
use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::{info, warn};

pub struct SecurityHandler {
    // [DISCOVERY FIX] Global Rate Limiter yerine IP tabanlı (Keyed) Rate Limiter yapıldı
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
    blacklist: DashMap<IpAddr, String>,
}

impl SecurityHandler {
    pub fn new(max_requests_per_second: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(max_requests_per_second).unwrap());
        // [DISCOVERY FIX] direct -> keyed
        let limiter = Arc::new(RateLimiter::keyed(quota));

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
                "🚫[SBC-SEC] BLOCKED: Kaynak kara listede."
            );
            return false;
        }

        // [DISCOVERY FIX] IP'yi baz alarak limit kontrolü
        if self.limiter.check_key(&ip).is_err() {
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
