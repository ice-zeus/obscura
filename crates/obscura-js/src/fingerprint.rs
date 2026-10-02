//! The stealth fingerprint seed.
//!
//! The randomized fingerprint surfaces (the WebGL vendor/renderer pair, screen,
//! CPU and memory pools, canvas, audio and battery values) are all derived
//! from one 32-bit seed in `bootstrap.js`. A real device reports the same values
//! on every page it loads, so the seed belongs to the browser profile rather
//! than to a document: a fingerprinting script that sees the values change on a
//! reload, a second visit or inside an iframe can tell the browser is spoofing.
//!
//! Lifetime:
//! - Each browser context owns one seed. Every document it loads, every frame
//!   realm of those documents and every worker reads that same seed, so values
//!   stay stable across navigations, reloads, tabs, iframes and workers.
//! - By default a new context draws a fresh random seed, so separate profiles
//!   keep receiving independent values from the same distributions.
//! - An embedder that keeps a profile across process restarts pins the seed with
//!   `OBSCURA_FINGERPRINT_SEED` (or `BrowserContext::with_fingerprint_seed`).
//!   The default context uses the pinned seed itself; any additional context
//!   derives its own seed from it and the context id.
//! - A runtime created without a browser context (the standalone library and
//!   tests) draws a random seed per runtime.
//!
//! Values that a browser recomputes for every navigation (navigation timing,
//! JS heap usage, storage usage) keep a per-document seed in `bootstrap.js`.

/// Environment variable through which an embedder pins a profile's seed.
///
/// Accepts a decimal or `0x`-prefixed hexadecimal 32-bit value. Any other
/// non-empty value (for example a profile id) is hashed into a seed.
pub const FINGERPRINT_SEED_ENV: &str = "OBSCURA_FINGERPRINT_SEED";

/// The seed a runtime hands to `bootstrap.js` through `op_fingerprint_seed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FingerprintSeed(pub u32);

/// A fresh random seed for a new browser profile.
pub fn random_seed() -> u32 {
    let mut bytes = [0u8; 4];
    if getrandom::getrandom(&mut bytes).is_ok() {
        return u32::from_le_bytes(bytes);
    }
    // getrandom only fails when the OS has no entropy source at all. Fall back
    // to the clock rather than to a constant, so profiles still differ.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    mix(nanos as u32 ^ (nanos >> 32) as u32)
}

/// Parse an embedder-supplied seed. Empty input yields `None`.
pub fn parse_seed(value: &str) -> Option<u32> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        if let Ok(seed) = u32::from_str_radix(hex, 16) {
            return Some(seed);
        }
    }
    if let Ok(seed) = value.parse::<u32>() {
        return Some(seed);
    }
    Some(mix(fnv1a(value.as_bytes())))
}

/// The seed pinned through `OBSCURA_FINGERPRINT_SEED`, if any.
pub fn seed_from_env() -> Option<u32> {
    std::env::var(FINGERPRINT_SEED_ENV)
        .ok()
        .and_then(|value| parse_seed(&value))
}

/// The seed of an additional browser context created under a pinned seed.
/// Distinct context ids give distinct, reproducible seeds.
pub fn derive_seed(base: u32, context_id: &str) -> u32 {
    mix(base ^ mix(fnv1a(context_id.as_bytes()).wrapping_add(0x9e37_79b9)))
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

// MurmurHash3's 32-bit finalizer: a bijection that spreads every input bit.
fn mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x85eb_ca6b);
    x ^= x >> 13;
    x = x.wrapping_mul(0xc2b2_ae35);
    x ^ (x >> 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numeric_and_label_seeds() {
        assert_eq!(parse_seed("42"), Some(42));
        assert_eq!(parse_seed(" 0x2A "), Some(42));
        assert_eq!(parse_seed("4294967295"), Some(u32::MAX));
        assert_eq!(parse_seed(""), None);
        assert_eq!(parse_seed("   "), None);
        let label = parse_seed("profile-7").expect("a label is hashed into a seed");
        assert_eq!(parse_seed("profile-7"), Some(label), "a label always maps to the same seed");
        assert_ne!(parse_seed("profile-8"), Some(label));
    }

    #[test]
    fn derived_seeds_are_reproducible_and_distinct() {
        let base = 0x1234_5678;
        assert_eq!(derive_seed(base, "context-1"), derive_seed(base, "context-1"));
        assert_ne!(derive_seed(base, "context-1"), derive_seed(base, "context-2"));
        assert_ne!(derive_seed(base, "context-1"), base);
        assert_ne!(derive_seed(base, "context-1"), derive_seed(base + 1, "context-1"));
    }

    #[test]
    fn random_seeds_vary() {
        let seeds: std::collections::HashSet<u32> = (0..64).map(|_| random_seed()).collect();
        assert!(seeds.len() > 60, "64 random seeds produced only {} distinct values", seeds.len());
    }
}
