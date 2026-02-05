use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Security configuration for input filtering
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    /// Blocklist of dangerous command patterns (substring matching)
    /// Used to prevent users from pasting dangerous commands like `rm -rf /`
    pub blocklist: Vec<String>,
    /// Enable rate limiting to prevent DoS attacks
    pub enable_rate_limit: bool,
    /// Max bytes per second allowed (prevents paste bombs)
    pub max_bytes_per_second: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            // Default blocklist for extremely dangerous command patterns
            // Note: This is basic heuristic filtering, cannot defend against all obfuscation attacks
            blocklist: vec![
                "rm -rf /".to_string(),
                ":(){ :|:& };:".to_string(), // Fork bomb
                "mkfs".to_string(),
                "dd if=".to_string(),
                "> /dev/sda".to_string(),
            ],
            enable_rate_limit: true,
            max_bytes_per_second: 1024, // 1KB/s is sufficient for manual typing, paste bombs will be limited
        }
    }
}

/// Input filter with rate limiting and blocklist checking
pub struct InputFilter {
    config: SecurityConfig,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Internal rate limiter state
struct RateLimiter {
    /// Bytes consumed in current window
    bytes_count: usize,
    /// Last reset timestamp
    last_reset: Instant,
}

impl InputFilter {
    /// Create a new input filter with the given configuration
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            rate_limiter: Arc::new(Mutex::new(RateLimiter {
                bytes_count: 0,
                last_reset: Instant::now(),
            })),
        }
    }

    /// Check if input is safe
    /// Returns Err(reason) if unsafe
    pub fn check(&self, input: &str) -> Result<(), String> {
        // 1. Rate limit check
        if self.config.enable_rate_limit {
            let mut limiter = self.rate_limiter.lock().unwrap();
            let now = Instant::now();
            if now.duration_since(limiter.last_reset) >= Duration::from_secs(1) {
                limiter.bytes_count = 0;
                limiter.last_reset = now;
            }

            limiter.bytes_count += input.len();
            if limiter.bytes_count > self.config.max_bytes_per_second {
                return Err("Input rate limit exceeded".to_string());
            }
        }

        // 2. Blocklist keyword check
        // Only check when input length exceeds threshold to avoid false positives
        // But patterns like "rm -rf /" will be caught if pasted
        if input.len() > 3 {
            for pattern in &self.config.blocklist {
                if input.contains(pattern) {
                    return Err(format!("Blocked dangerous pattern: {}", pattern));
                }
            }
        }

        Ok(())
    }
}
