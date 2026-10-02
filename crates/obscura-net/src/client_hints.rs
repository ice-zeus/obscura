//! HTTP client hints that an origin asks for with `Accept-CH`.
//!
//! Chrome remembers the hints a secure origin lists in `Accept-CH` on a
//! top-level navigation response and sends them on later navigations to that
//! origin and on its same-origin subresources (the default Permissions
//! Policy delegates them to `self` only). A `Critical-CH` hint that was
//! accepted but not sent restarts the navigation once. The values match what
//! the page's JavaScript reports for the same properties.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use url::Url;

/// The hints Chrome sends on request, in the order Blink adds them to a
/// subresource (`FrameFetchContext::AddClientHintsIfNecessary`). The low
/// entropy UA hints are always sent and are listed only for their position.
pub(crate) const BLINK_HINT_ORDER: [&str; 27] = [
    "device-memory", "sec-ch-device-memory", "rtt", "downlink", "ect", "sec-ch-ua",
    "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-ua-platform-version",
    "sec-ch-ua-model", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-bitness",
    "sec-ch-ua-wow64", "sec-ch-ua-form-factors", "save-data", "sec-ch-prefers-reduced-transparency",
    "sec-ch-prefers-reduced-motion", "sec-ch-prefers-color-scheme", "dpr", "sec-ch-dpr",
    "viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height", "width", "sec-ch-width",
];

/// The order Chrome's browser process writes them on a navigation request
/// (measured with Chromium 151), low entropy UA hints included.
pub(crate) const NAVIGATION_HINT_ORDER: [&str; 24] = [
    "device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr", "viewport-width",
    "sec-ch-viewport-width", "sec-ch-viewport-height", "rtt", "downlink", "ect", "sec-ch-ua",
    "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch", "sec-ch-ua-platform",
    "sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-bitness", "sec-ch-ua-wow64",
    "sec-ch-ua-full-version-list", "sec-ch-ua-form-factors", "sec-ch-prefers-color-scheme",
    "sec-ch-prefers-reduced-motion", "sec-ch-prefers-reduced-transparency",
];

/// Hints sent only when an origin asked for them. `width`/`sec-ch-width`
/// need the image's layout size and `save-data` a user setting this browser
/// does not have, so neither is ever sent.
const SUPPORTED: [&str; 21] = [
    "device-memory", "sec-ch-device-memory", "rtt", "downlink", "ect", "sec-ch-ua-arch",
    "sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list", "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-form-factors",
    "sec-ch-prefers-reduced-transparency", "sec-ch-prefers-reduced-motion",
    "sec-ch-prefers-color-scheme", "dpr", "sec-ch-dpr", "viewport-width", "sec-ch-viewport-width",
    "sec-ch-viewport-height",
];

/// Parse an `Accept-CH` or `Critical-CH` field value (a structured-field
/// list of tokens; case-insensitive). Unknown names are ignored.
pub fn parse_hint_list(value: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    for token in value.split(',') {
        let token = token.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if let Some(name) = SUPPORTED.iter().find(|name| **name == token) {
            if !out.contains(name) {
                out.push(*name);
            }
        }
    }
    out
}

/// Whether an origin may set hint preferences: Chrome requires a
/// potentially trustworthy URL (https, or a loopback host).
pub fn is_trustworthy(url: &Url) -> bool {
    match url.scheme() {
        "https" | "wss" => true,
        "http" | "ws" => match url.host() {
            Some(url::Host::Domain(host)) => host == "localhost" || host.ends_with(".localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// Per-profile store of accepted hints, keyed by origin. Shared by every
/// page of a browser context, like the cookie jar.
#[derive(Default)]
pub struct ClientHintStore {
    origins: Mutex<HashMap<String, Vec<&'static str>>>,
}

impl ClientHintStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a top-level navigation response's `Accept-CH`. A response with
    /// the header replaces the origin's set (an empty value clears it); a
    /// response without it leaves the set unchanged.
    pub fn accept(&self, url: &Url, accept_ch: Option<&str>) {
        let Some(value) = accept_ch else { return };
        if !is_trustworthy(url) {
            return;
        }
        let key = url.origin().ascii_serialization();
        let hints = parse_hint_list(value);
        let mut origins = self.origins.lock().unwrap();
        if hints.is_empty() {
            origins.remove(&key);
        } else {
            origins.insert(key, hints);
        }
    }

    /// The hints an origin accepted.
    pub fn hints_for(&self, url: &Url) -> Vec<&'static str> {
        if !is_trustworthy(url) {
            return Vec::new();
        }
        self.origins
            .lock()
            .unwrap()
            .get(&url.origin().ascii_serialization())
            .cloned()
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        self.origins.lock().unwrap().clear();
    }
}

/// Values the page reports for the environment hints. The page updates
/// them when its viewport, scale factor or fingerprint changes.
#[derive(Clone, Debug, PartialEq)]
pub struct HintEnvironment {
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub device_pixel_ratio: f64,
    pub device_memory: f64,
}

impl Default for HintEnvironment {
    fn default() -> Self {
        HintEnvironment { viewport_width: 1280, viewport_height: 720, device_pixel_ratio: 1.0, device_memory: 8.0 }
    }
}

/// Fixed values that match the JavaScript stealth surfaces: the
/// `navigator.connection` constants, `matchMedia` preferences and
/// `navigator.userAgentData.getHighEntropyValues()`.
const RTT: &str = "50";
const DOWNLINK: &str = "10";
const ECT: &str = "4g";

fn number(value: f64) -> String {
    if value.fract() == 0.0 { format!("{}", value as i64) } else { format!("{value}") }
}

/// `"Brand";v="148"` entries of `sec-ch-ua`, with the full version form
/// `getHighEntropyValues()` reports (`148.0.0.0`).
fn full_version_list(sec_ch_ua: &str) -> String {
    sec_ch_ua
        .split(',')
        .map(|entry| {
            let entry = entry.trim();
            match entry.rsplit_once(";v=\"") {
                Some((brand, version)) => {
                    let version = version.trim_end_matches('"');
                    format!("{brand};v=\"{version}.0.0.0\"")
                }
                None => entry.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn chrome_major(sec_ch_ua: &str) -> Option<String> {
    sec_ch_ua.split(',').find_map(|entry| {
        let entry = entry.trim();
        let (brand, version) = entry.rsplit_once(";v=\"")?;
        (brand.trim_matches('"') == "Chromium").then(|| version.trim_end_matches('"').to_string())
    })
}

/// Header values for `hints` (from the store), as (lowercase name, value)
/// pairs. `sec_ch_ua` is the value sent on this request, so the brands and
/// versions agree with it.
pub fn hint_values(
    hints: &[&'static str],
    sec_ch_ua: &str,
    platform_version: &str,
    environment: &HintEnvironment,
) -> Vec<(&'static str, String)> {
    let major = chrome_major(sec_ch_ua);
    hints
        .iter()
        .filter_map(|hint| {
            let value = match *hint {
                "device-memory" | "sec-ch-device-memory" => number(environment.device_memory),
                "rtt" => RTT.into(),
                "downlink" => DOWNLINK.into(),
                "ect" => ECT.into(),
                "sec-ch-ua-arch" => "\"x86\"".into(),
                "sec-ch-ua-bitness" => "\"64\"".into(),
                "sec-ch-ua-model" => "\"\"".into(),
                "sec-ch-ua-wow64" => "?0".into(),
                "sec-ch-ua-form-factors" => "\"Desktop\"".into(),
                "sec-ch-ua-platform-version" => format!("\"{platform_version}\""),
                "sec-ch-ua-full-version" => format!("\"{}.0.0.0\"", major.clone()?),
                "sec-ch-ua-full-version-list" => full_version_list(sec_ch_ua),
                "sec-ch-prefers-color-scheme" => "light".into(),
                "sec-ch-prefers-reduced-motion" | "sec-ch-prefers-reduced-transparency" => "no-preference".into(),
                "dpr" | "sec-ch-dpr" => number(environment.device_pixel_ratio),
                "viewport-width" | "sec-ch-viewport-width" => environment.viewport_width.to_string(),
                "sec-ch-viewport-height" => environment.viewport_height.to_string(),
                _ => return None,
            };
            Some((*hint, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_accept_ch_case_insensitively_and_ignores_unknown_names() {
        assert_eq!(
            parse_hint_list("Sec-CH-UA-Arch, sec-ch-prefers-color-scheme;x=1, Width, Save-Data, Bogus, DPR"),
            vec!["sec-ch-ua-arch", "sec-ch-prefers-color-scheme", "dpr"]
        );
        assert!(parse_hint_list("").is_empty());
    }

    #[test]
    fn only_secure_origins_store_hints_and_a_header_replaces_the_set() {
        let store = ClientHintStore::default();
        let https = Url::parse("https://www.example.com/search?q=1").unwrap();
        let other = Url::parse("https://cdn.example.com/a.js").unwrap();
        let http = Url::parse("http://www.example.com/").unwrap();
        let local = Url::parse("http://localhost:8080/").unwrap();
        store.accept(&http, Some("Sec-CH-UA-Arch"));
        assert!(store.hints_for(&http).is_empty());
        store.accept(&local, Some("Sec-CH-UA-Arch"));
        assert_eq!(store.hints_for(&local), vec!["sec-ch-ua-arch"]);
        store.accept(&https, Some("Sec-CH-Prefers-Color-Scheme"));
        assert_eq!(store.hints_for(&https), vec!["sec-ch-prefers-color-scheme"]);
        assert!(store.hints_for(&other).is_empty());
        store.accept(&https, None);
        assert_eq!(store.hints_for(&https), vec!["sec-ch-prefers-color-scheme"]);
        store.accept(&https, Some(""));
        assert!(store.hints_for(&https).is_empty());
    }

    #[test]
    fn values_agree_with_the_sent_brands_and_the_page() {
        let sec_ch_ua = r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#;
        let environment = HintEnvironment { viewport_width: 1366, viewport_height: 768, device_pixel_ratio: 1.25, device_memory: 4.0 };
        let values = hint_values(
            &["sec-ch-ua-full-version-list", "sec-ch-ua-full-version", "sec-ch-ua-platform-version", "dpr", "sec-ch-viewport-width", "device-memory", "sec-ch-prefers-color-scheme", "sec-ch-ua-wow64"],
            sec_ch_ua,
            "15.0.0",
            &environment,
        );
        assert_eq!(values, vec![
            ("sec-ch-ua-full-version-list", r#""Chromium";v="148.0.0.0", "Google Chrome";v="148.0.0.0", "Not/A)Brand";v="99.0.0.0""#.to_string()),
            ("sec-ch-ua-full-version", "\"148.0.0.0\"".to_string()),
            ("sec-ch-ua-platform-version", "\"15.0.0\"".to_string()),
            ("dpr", "1.25".to_string()),
            ("sec-ch-viewport-width", "1366".to_string()),
            ("device-memory", "4".to_string()),
            ("sec-ch-prefers-color-scheme", "light".to_string()),
            ("sec-ch-ua-wow64", "?0".to_string()),
        ]);
    }
}
