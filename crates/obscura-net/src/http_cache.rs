//! A private HTTP cache for subresources, modelled on Chrome's.
//!
//! - **Partitioned** like Chrome's network isolation key: an entry is keyed by
//!   the top-level frame's site, the requesting frame's site, whether the
//!   request carries credentials and the URL (without fragment). One cache
//!   belongs to one browser context (profile); profiles never share entries.
//! - **RFC 9111 freshness**: `Cache-Control` (`max-age`, `no-cache`,
//!   `no-store`, `must-revalidate`), `Expires`/`Date`, `Age` and Chrome's
//!   heuristic lifetime (10% of the time since `Last-Modified`).
//! - **Conditional revalidation**: a stale entry with a validator is
//!   revalidated with `If-None-Match` / `If-Modified-Since`; a `304` refreshes
//!   the stored headers and serves the stored body.
//! - **`Vary`**: the varying request header values are stored and must match.
//! - **Bounded**: least-recently-used eviction under a byte budget, with a
//!   per-entry limit. In memory by default; `OBSCURA_HTTP_CACHE=disk` also
//!   persists entries in the profile's storage directory.
//!
//! The cache only stores what the network returned; it never synthesizes
//! responses, and `Set-Cookie` is not replayed from it (as in Chrome).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

use crate::client::Response;

/// Environment variable selecting the cache mode: `memory` (default),
/// `disk` (memory plus files under `<storage dir>/http-cache`) or `off`.
pub const HTTP_CACHE_ENV: &str = "OBSCURA_HTTP_CACHE";
/// Environment variable overriding the cache budget in MiB (default 64).
pub const HTTP_CACHE_MAX_MB_ENV: &str = "OBSCURA_HTTP_CACHE_MAX_MB";

const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRY_FRACTION: usize = 8;

/// Headers that a `304 Not Modified` must not overwrite in the stored response
/// (RFC 9111 section 3.2 and Chrome's `HttpResponseHeaders::Update`).
const NON_UPDATABLE: &[&str] = &[
    "content-length",
    "content-encoding",
    "content-range",
    "transfer-encoding",
    "etag",
    "last-modified",
    "set-cookie",
];

#[derive(Clone, Copy, Debug)]
pub struct CacheLimits {
    pub max_bytes: usize,
    pub max_entry_bytes: usize,
}

impl Default for CacheLimits {
    fn default() -> Self {
        CacheLimits::with_budget(DEFAULT_MAX_BYTES)
    }
}

impl CacheLimits {
    pub fn with_budget(max_bytes: usize) -> Self {
        CacheLimits { max_bytes, max_entry_bytes: (max_bytes / MAX_ENTRY_FRACTION).max(1) }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Entry {
    key: String,
    status: u16,
    url: String,
    headers: HashMap<String, String>,
    #[serde(skip)]
    body: Arc<Vec<u8>>,
    request_time: f64,
    response_time: f64,
    /// `Vary` header names and the request values they were stored for.
    vary: Vec<(String, String)>,
}

impl Entry {
    fn bytes(&self) -> usize {
        self.body.len() + self.headers.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() + self.key.len()
    }

    fn response(&self) -> Option<Response> {
        Some(Response {
            url: Url::parse(&self.url).ok()?,
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.as_ref().clone(),
            redirected_from: Vec::new(),
        })
    }
}

/// Outcome of a lookup.
pub enum CacheLookup {
    /// A fresh stored response; no request is needed.
    Fresh(Response),
    /// A stored response that must be revalidated with these conditional
    /// headers, in Chrome's order.
    Revalidate(Vec<(&'static str, String)>),
    /// Nothing usable is stored.
    Miss,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    /// Least recently used first.
    order: VecDeque<String>,
    bytes: usize,
}

impl State {
    fn touch(&mut self, key: &str) {
        if let Some(position) = self.order.iter().position(|k| k == key) {
            let key = self.order.remove(position).expect("position is in range");
            self.order.push_back(key);
        }
    }

    fn remove(&mut self, key: &str) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.saturating_sub(entry.bytes());
        self.order.retain(|k| k != key);
        Some(entry)
    }
}

pub struct HttpCache {
    limits: CacheLimits,
    state: Mutex<State>,
    disk: Option<PathBuf>,
}

impl HttpCache {
    pub fn in_memory(limits: CacheLimits) -> Self {
        HttpCache { limits, state: Mutex::new(State::default()), disk: None }
    }

    /// A cache that also persists entries as files under `dir`.
    pub fn on_disk(limits: CacheLimits, dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        HttpCache { limits, state: Mutex::new(State::default()), disk: Some(dir) }
    }

    /// The cache configured by `OBSCURA_HTTP_CACHE` for a profile whose
    /// storage directory is `storage_dir`. `None` when the cache is off.
    pub fn from_env(storage_dir: Option<&Path>) -> Option<Arc<HttpCache>> {
        let mode = std::env::var(HTTP_CACHE_ENV).unwrap_or_default().trim().to_ascii_lowercase();
        let limits = std::env::var(HTTP_CACHE_MAX_MB_ENV)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|mb| *mb > 0)
            .map(|mb| CacheLimits::with_budget(mb.saturating_mul(1024 * 1024)))
            .unwrap_or_default();
        match mode.as_str() {
            "off" | "0" | "false" | "no" | "none" => None,
            "disk" => match storage_dir {
                Some(dir) => Some(Arc::new(HttpCache::on_disk(limits, dir.join("http-cache")))),
                None => Some(Arc::new(HttpCache::in_memory(limits))),
            },
            _ => Some(Arc::new(HttpCache::in_memory(limits))),
        }
    }

    pub fn limits(&self) -> CacheLimits {
        self.limits
    }

    /// Number of entries and their accounted size in memory.
    pub fn usage(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (state.entries.len(), state.bytes)
    }

    /// Look up `key` for a request that sends `request_header(name)` values.
    pub fn lookup(
        &self,
        key: &str,
        request_header: &dyn Fn(&str) -> Option<String>,
        max_body: usize,
        now: SystemTime,
    ) -> CacheLookup {
        let entry = {
            let mut state = self.state.lock().unwrap();
            if !state.entries.contains_key(key) {
                if let Some(entry) = self.read_disk(key) {
                    self.insert_locked(&mut state, entry);
                }
            }
            let Some(entry) = state.entries.get(key).cloned() else {
                return CacheLookup::Miss;
            };
            state.touch(key);
            entry
        };
        if entry.body.len() > max_body
            || entry.vary.iter().any(|(name, value)| request_header(name).unwrap_or_default() != *value)
        {
            return CacheLookup::Miss;
        }
        let directives = CacheControl::parse(entry.headers.get("cache-control").map(String::as_str));
        if !directives.no_cache && freshness_lifetime(&entry, &directives) > current_age(&entry, now) {
            return entry.response().map(CacheLookup::Fresh).unwrap_or(CacheLookup::Miss);
        }
        let mut validators = Vec::new();
        if let Some(etag) = entry.headers.get("etag") {
            validators.push(("if-none-match", etag.clone()));
        }
        if let Some(modified) = entry.headers.get("last-modified") {
            validators.push(("if-modified-since", modified.clone()));
        }
        if validators.is_empty() {
            self.remove(key);
            return CacheLookup::Miss;
        }
        CacheLookup::Revalidate(validators)
    }

    /// Store a network response if it is cacheable. `request_header` reports
    /// the value the request sent for a header (for `Vary`).
    pub fn store(
        &self,
        key: &str,
        response: &Response,
        request_header: &dyn Fn(&str) -> Option<String>,
        request_time: SystemTime,
        response_time: SystemTime,
    ) -> bool {
        if !matches!(response.status, 200 | 203) || !response.redirected_from.is_empty() {
            return false;
        }
        let directives = CacheControl::parse(response.header("cache-control"));
        if directives.no_store {
            self.remove(key);
            return false;
        }
        let mut vary = Vec::new();
        if let Some(header) = response.header("vary") {
            for name in header.split(',').map(|name| name.trim().to_ascii_lowercase()) {
                if name.is_empty() {
                    continue;
                }
                if name == "*" {
                    self.remove(key);
                    return false;
                }
                let value = request_header(&name).unwrap_or_default();
                vary.push((name, value));
            }
        }
        let mut headers = response.headers.clone();
        headers.remove("set-cookie");
        let entry = Entry {
            key: key.to_string(),
            status: response.status,
            url: response.url.to_string(),
            headers,
            body: Arc::new(response.body.clone()),
            request_time: seconds(request_time),
            response_time: seconds(response_time),
            vary,
        };
        let fresh = !directives.no_cache && freshness_lifetime(&entry, &directives) > current_age(&entry, response_time);
        let validator = entry.headers.contains_key("etag") || entry.headers.contains_key("last-modified");
        if (!fresh && !validator) || entry.bytes() > self.limits.max_entry_bytes {
            self.remove(key);
            return false;
        }
        self.write_disk(&entry);
        let mut state = self.state.lock().unwrap();
        self.insert_locked(&mut state, entry);
        true
    }

    /// Apply a `304 Not Modified` to the stored entry and return the refreshed
    /// stored response.
    pub fn refresh(
        &self,
        key: &str,
        not_modified: &HashMap<String, String>,
        request_time: SystemTime,
        response_time: SystemTime,
    ) -> Option<Response> {
        let mut state = self.state.lock().unwrap();
        let mut entry = state.remove(key)?;
        for (name, value) in not_modified {
            if !NON_UPDATABLE.contains(&name.as_str()) {
                entry.headers.insert(name.clone(), value.clone());
            }
        }
        entry.request_time = seconds(request_time);
        entry.response_time = seconds(response_time);
        let response = entry.response();
        self.write_disk(&entry);
        self.insert_locked(&mut state, entry);
        response
    }

    pub fn remove(&self, key: &str) {
        self.state.lock().unwrap().remove(key);
        if let Some(path) = self.disk_path(key) {
            let _ = std::fs::remove_file(path);
        }
    }

    fn insert_locked(&self, state: &mut State, entry: Entry) {
        let key = entry.key.clone();
        state.remove(&key);
        let size = entry.bytes();
        while state.bytes + size > self.limits.max_bytes {
            let Some(oldest) = state.order.pop_front() else { break };
            if let Some(evicted) = state.entries.remove(&oldest) {
                state.bytes = state.bytes.saturating_sub(evicted.bytes());
                if let Some(path) = self.disk_path(&oldest) {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        state.bytes += size;
        state.order.push_back(key.clone());
        state.entries.insert(key, entry);
    }

    fn disk_path(&self, key: &str) -> Option<PathBuf> {
        let dir = self.disk.as_ref()?;
        Some(dir.join(format!("{:016x}.entry", fnv1a64(key.as_bytes()))))
    }

    // File layout: one JSON metadata line, then the body bytes.
    fn write_disk(&self, entry: &Entry) {
        let Some(path) = self.disk_path(&entry.key) else { return };
        let Ok(mut bytes) = serde_json::to_vec(entry) else { return };
        bytes.push(b'\n');
        bytes.extend_from_slice(&entry.body);
        let temporary = path.with_extension("tmp");
        if std::fs::write(&temporary, &bytes).is_ok() {
            let _ = std::fs::rename(&temporary, &path);
        }
    }

    fn read_disk(&self, key: &str) -> Option<Entry> {
        let bytes = std::fs::read(self.disk_path(key)?).ok()?;
        let split = bytes.iter().position(|byte| *byte == b'\n')?;
        let mut entry: Entry = serde_json::from_slice(&bytes[..split]).ok()?;
        if entry.key != key {
            return None;
        }
        entry.body = Arc::new(bytes[split + 1..].to_vec());
        Some(entry)
    }
}

/// Chrome's cache key: the network isolation key (top-level site and frame
/// site), the credentials bit and the URL without its fragment.
pub fn cache_key(top_frame: Option<&Url>, frame: Option<&Url>, url: &Url, credentials: bool) -> String {
    let frame_site = frame.map(site).unwrap_or_else(|| site(url));
    let top_site = top_frame.map(site).unwrap_or_else(|| frame_site.clone());
    let mut resource = url.clone();
    resource.set_fragment(None);
    format!("{} {} {} {}", top_site, frame_site, if credentials { "c" } else { "n" }, resource)
}

/// The schemeful site of a URL: scheme plus registrable domain.
pub fn site(url: &Url) -> String {
    match url.host_str() {
        Some(host) if matches!(url.scheme(), "http" | "https" | "ws" | "wss") => {
            let registrable = if url.host().is_some_and(|h| !matches!(h, url::Host::Domain(_))) {
                host
            } else {
                psl::domain_str(host).unwrap_or(host)
            };
            format!("{}://{}", url.scheme(), registrable.to_ascii_lowercase())
        }
        _ => "opaque".to_string(),
    }
}

#[derive(Default)]
struct CacheControl {
    no_store: bool,
    no_cache: bool,
    max_age: Option<u64>,
}

impl CacheControl {
    fn parse(value: Option<&str>) -> CacheControl {
        let mut parsed = CacheControl::default();
        for directive in value.unwrap_or("").split(',') {
            let directive = directive.trim().to_ascii_lowercase();
            let (name, argument) = match directive.split_once('=') {
                Some((name, argument)) => (name.trim().to_string(), Some(argument.trim().trim_matches('"').to_string())),
                None => (directive.clone(), None),
            };
            match name.as_str() {
                "no-store" => parsed.no_store = true,
                // `no-cache="field"` only restricts those fields; Chrome treats
                // any no-cache as a revalidation requirement.
                "no-cache" => parsed.no_cache = true,
                "max-age" => parsed.max_age = argument.and_then(|value| value.parse::<u64>().ok()).or(Some(0)),
                _ => {}
            }
        }
        parsed
    }
}

fn seconds(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn freshness_lifetime(entry: &Entry, directives: &CacheControl) -> f64 {
    if let Some(max_age) = directives.max_age {
        return max_age as f64;
    }
    let date = entry.headers.get("date").and_then(|value| parse_http_date(value)).unwrap_or(entry.response_time);
    if let Some(expires) = entry.headers.get("expires") {
        // An invalid Expires (such as "0") means already expired.
        return parse_http_date(expires).map(|expires| (expires - date).max(0.0)).unwrap_or(0.0);
    }
    if let Some(modified) = entry.headers.get("last-modified").and_then(|value| parse_http_date(value)) {
        if modified <= date {
            return (date - modified) / 10.0;
        }
    }
    0.0
}

fn current_age(entry: &Entry, now: SystemTime) -> f64 {
    let date = entry.headers.get("date").and_then(|value| parse_http_date(value)).unwrap_or(entry.response_time);
    let age_value = entry
        .headers
        .get("age")
        .and_then(|value| value.trim().parse::<f64>().ok())
        .unwrap_or(0.0);
    let apparent_age = (entry.response_time - date).max(0.0);
    let response_delay = (entry.response_time - entry.request_time).max(0.0);
    let initial_age = apparent_age.max(age_value + response_delay);
    initial_age + (seconds(now) - entry.response_time).max(0.0)
}

/// Parse an HTTP-date (IMF-fixdate, RFC 850 or asctime) into Unix seconds.
pub fn parse_http_date(value: &str) -> Option<f64> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let cleaned = value.trim().replace(',', " ").replace('-', " ");
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    let month_of = |name: &str| MONTHS.iter().position(|m| name.len() >= 3 && name[..3].eq_ignore_ascii_case(m)).map(|i| i as u32 + 1);
    let (day, month, year, time) = match parts.as_slice() {
        // Sun, 06 Nov 1994 08:49:37 GMT / Sunday, 06-Nov-94 08:49:37 GMT
        [_, day, month, year, time, ..] if month_of(month).is_some() => (*day, *month, *year, *time),
        // Sun Nov  6 08:49:37 1994
        [_, month, day, time, year] if month_of(month).is_some() => (*day, *month, *year, *time),
        _ => return None,
    };
    let day: u32 = day.parse().ok()?;
    let month = month_of(month)?;
    let mut year: i64 = year.parse().ok()?;
    if year < 100 {
        year += if year < 70 { 2000 } else { 1900 };
    }
    let clock: Vec<u32> = time.split(':').map(|part| part.parse().ok()).collect::<Option<Vec<_>>>()?;
    if clock.len() != 3 || day == 0 || day > 31 || clock[0] > 23 || clock[1] > 59 || clock[2] > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m as i64 + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + clock[0] as i64 * 3600 + clock[1] as i64 * 60 + clock[2] as i64) as f64)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn response(url: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        Response {
            url: Url::parse(url).unwrap(),
            status: 200,
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.to_vec(),
            redirected_from: Vec::new(),
        }
    }

    fn none(_: &str) -> Option<String> {
        None
    }

    fn at(offset: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + offset)
    }

    fn key(top: &str, url: &str) -> String {
        let top = Url::parse(top).unwrap();
        cache_key(Some(&top), Some(&top), &Url::parse(url).unwrap(), true)
    }

    #[test]
    fn keys_partition_by_top_frame_site_and_frame_site_like_chrome() {
        let font = Url::parse("https://fonts.gstatic.com/s/x.woff2#frag").unwrap();
        let google = Url::parse("https://www.google.com/search?q=a").unwrap();
        let images = Url::parse("https://images.google.com/").unwrap();
        let other = Url::parse("https://example.org/").unwrap();
        // Same site (google.com), different origin: one partition.
        assert_eq!(cache_key(Some(&google), Some(&google), &font, true), cache_key(Some(&images), Some(&images), &font, true));
        // A different top-level site, or the same frame embedded elsewhere: separate.
        assert_ne!(cache_key(Some(&google), Some(&google), &font, true), cache_key(Some(&other), Some(&other), &font, true));
        assert_ne!(cache_key(Some(&google), Some(&google), &font, true), cache_key(Some(&other), Some(&google), &font, true));
        // Credentials and the URL (without fragment) are part of the key.
        assert_ne!(cache_key(Some(&google), Some(&google), &font, true), cache_key(Some(&google), Some(&google), &font, false));
        assert!(cache_key(Some(&google), Some(&google), &font, true).ends_with("https://fonts.gstatic.com/s/x.woff2"));
        assert_eq!(site(&Url::parse("http://127.0.0.1:8080/x").unwrap()), "http://127.0.0.1");
        assert_eq!(site(&Url::parse("data:text/plain,x").unwrap()), "opaque");
    }

    #[test]
    fn fresh_responses_are_served_until_max_age_then_revalidated() {
        let cache = HttpCache::in_memory(CacheLimits::default());
        let k = key("https://www.google.com/", "https://www.gstatic.com/a.js");
        let r = response("https://www.gstatic.com/a.js", &[("cache-control", "public, max-age=60"), ("etag", "\"v1\"")], b"js");
        assert!(cache.store(&k, &r, &none, at(0), at(0)));
        assert!(matches!(cache.lookup(&k, &none, usize::MAX, at(59)), CacheLookup::Fresh(ref hit) if hit.body == b"js"));
        match cache.lookup(&k, &none, usize::MAX, at(61)) {
            CacheLookup::Revalidate(headers) => assert_eq!(headers, vec![("if-none-match", "\"v1\"".to_string())]),
            _ => panic!("a stale entry with an ETag must be revalidated"),
        }
    }

    #[test]
    fn revalidation_sends_both_validators_in_chrome_order_and_304_refreshes() {
        let cache = HttpCache::in_memory(CacheLimits::default());
        let k = key("https://a.test/", "https://a.test/s.css");
        let r = response("https://a.test/s.css", &[
            ("cache-control", "no-cache"), ("etag", "W/\"7\""),
            ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"), ("content-type", "text/css"),
        ], b"css");
        assert!(cache.store(&k, &r, &none, at(0), at(0)));
        match cache.lookup(&k, &none, usize::MAX, at(1)) {
            CacheLookup::Revalidate(headers) => assert_eq!(headers, vec![
                ("if-none-match", "W/\"7\"".to_string()),
                ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
            ]),
            _ => panic!("no-cache always revalidates"),
        }
        let refreshed = cache.refresh(&k, &HashMap::from([
            ("cache-control".to_string(), "max-age=100".to_string()),
            ("content-length".to_string(), "0".to_string()),
        ]), at(2), at(2)).unwrap();
        assert_eq!(refreshed.status, 200);
        assert_eq!(refreshed.body, b"css");
        assert_eq!(refreshed.header("content-type"), Some("text/css"));
        assert_eq!(refreshed.header("content-length"), None, "a 304 never rewrites entity headers");
        assert!(matches!(cache.lookup(&k, &none, usize::MAX, at(50)), CacheLookup::Fresh(_)));
    }

    #[test]
    fn uncacheable_responses_are_not_stored() {
        let cache = HttpCache::in_memory(CacheLimits::default());
        let k = key("https://a.test/", "https://a.test/x");
        for headers in [
            vec![("cache-control", "no-store, max-age=600")],
            vec![("cache-control", "max-age=600"), ("vary", "*")],
            vec![],
            vec![("cache-control", "max-age=0")],
        ] {
            assert!(!cache.store(&k, &response("https://a.test/x", &headers, b"x"), &none, at(0), at(0)), "{headers:?}");
        }
        let mut redirected = response("https://a.test/x", &[("cache-control", "max-age=600")], b"x");
        redirected.redirected_from.push(Url::parse("https://a.test/old").unwrap());
        assert!(!cache.store(&k, &redirected, &none, at(0), at(0)));
        let mut error = response("https://a.test/x", &[("cache-control", "max-age=600")], b"x");
        error.status = 500;
        assert!(!cache.store(&k, &error, &none, at(0), at(0)));
        assert_eq!(cache.usage().0, 0);
    }

    #[test]
    fn expires_and_heuristic_lifetimes_follow_rfc_9111() {
        let cache = HttpCache::in_memory(CacheLimits::default());
        let k = key("https://a.test/", "https://a.test/e");
        let r = response("https://a.test/e", &[
            ("date", "Tue, 14 Nov 2023 22:13:20 GMT"), ("expires", "Tue, 14 Nov 2023 22:14:20 GMT"),
        ], b"e");
        assert!(cache.store(&k, &r, &none, at(0), at(0)));
        assert!(matches!(cache.lookup(&k, &none, usize::MAX, at(30)), CacheLookup::Fresh(_)));
        assert!(matches!(cache.lookup(&k, &none, usize::MAX, at(90)), CacheLookup::Miss), "stale without validator");
        // Heuristic: 10% of (Date - Last-Modified) = 100 s.
        let k = key("https://a.test/", "https://a.test/h");
        let r = response("https://a.test/h", &[
            ("date", "Tue, 14 Nov 2023 22:13:20 GMT"), ("last-modified", "Tue, 14 Nov 2023 21:56:40 GMT"),
        ], b"h");
        assert!(cache.store(&k, &r, &none, at(0), at(0)));
        assert!(matches!(cache.lookup(&k, &none, usize::MAX, at(90)), CacheLookup::Fresh(_)));
        assert!(matches!(cache.lookup(&k, &none, usize::MAX, at(110)), CacheLookup::Revalidate(_)));
        // Age counts against max-age.
        let k = key("https://a.test/", "https://a.test/age");
        let r = response("https://a.test/age", &[("cache-control", "max-age=100"), ("age", "95"), ("etag", "\"a\"")], b"a");
        assert!(cache.store(&k, &r, &none, at(0), at(0)));
        assert!(matches!(cache.lookup(&k, &none, usize::MAX, at(10)), CacheLookup::Revalidate(_)));
    }

    #[test]
    fn vary_matches_the_stored_request_header_values() {
        let cache = HttpCache::in_memory(CacheLimits::default());
        let k = key("https://a.test/", "https://cdn.test/f.woff2");
        let r = response("https://cdn.test/f.woff2", &[("cache-control", "max-age=600"), ("vary", "Origin")], b"f");
        let origin_a = |name: &str| (name == "origin").then(|| "https://a.test".to_string());
        let origin_b = |name: &str| (name == "origin").then(|| "https://www.a.test".to_string());
        assert!(cache.store(&k, &r, &origin_a, at(0), at(0)));
        assert!(matches!(cache.lookup(&k, &origin_a, usize::MAX, at(1)), CacheLookup::Fresh(_)));
        assert!(matches!(cache.lookup(&k, &origin_b, usize::MAX, at(1)), CacheLookup::Miss));
    }

    #[test]
    fn set_cookie_is_never_replayed_and_body_limits_are_respected() {
        let cache = HttpCache::in_memory(CacheLimits::default());
        let k = key("https://a.test/", "https://a.test/c");
        let r = response("https://a.test/c", &[("cache-control", "max-age=600"), ("set-cookie", "a=b")], b"0123456789");
        assert!(cache.store(&k, &r, &none, at(0), at(0)));
        match cache.lookup(&k, &none, usize::MAX, at(1)) {
            CacheLookup::Fresh(hit) => assert_eq!(hit.header("set-cookie"), None),
            _ => panic!("expected a hit"),
        }
        assert!(matches!(cache.lookup(&k, &none, 5, at(1)), CacheLookup::Miss), "a smaller consumer limit bypasses");
    }

    #[test]
    fn the_cache_is_bounded_with_lru_eviction() {
        let cache = HttpCache::in_memory(CacheLimits { max_bytes: 3000, max_entry_bytes: 1500 });
        let body = vec![7u8; 900];
        let store = |name: &str| {
            let url = format!("https://a.test/{name}");
            cache.store(&key("https://a.test/", &url), &response(&url, &[("cache-control", "max-age=600")], &body), &none, at(0), at(0))
        };
        assert!(store("one") && store("two") && store("three"));
        // Touch "one" so "two" is the least recently used.
        assert!(matches!(cache.lookup(&key("https://a.test/", "https://a.test/one"), &none, usize::MAX, at(1)), CacheLookup::Fresh(_)));
        assert!(store("four"));
        let (entries, bytes) = cache.usage();
        assert!(bytes <= 3000 && entries == 3, "{entries} entries, {bytes} bytes");
        assert!(matches!(cache.lookup(&key("https://a.test/", "https://a.test/two"), &none, usize::MAX, at(1)), CacheLookup::Miss));
        assert!(matches!(cache.lookup(&key("https://a.test/", "https://a.test/one"), &none, usize::MAX, at(1)), CacheLookup::Fresh(_)));
        let big = vec![0u8; 2000];
        assert!(!cache.store(&key("https://a.test/", "https://a.test/big"), &response("https://a.test/big", &[("cache-control", "max-age=600")], &big), &none, at(0), at(0)));
    }

    #[test]
    fn disk_mode_persists_entries_for_the_same_profile_only() {
        let dir = tempfile::tempdir().unwrap();
        let k = key("https://a.test/", "https://a.test/p.js");
        {
            let cache = HttpCache::on_disk(CacheLimits::default(), dir.path().join("p1"));
            assert!(cache.store(&k, &response("https://a.test/p.js", &[("cache-control", "max-age=600")], b"persisted"), &none, at(0), at(0)));
        }
        let reopened = HttpCache::on_disk(CacheLimits::default(), dir.path().join("p1"));
        assert!(matches!(reopened.lookup(&k, &none, usize::MAX, at(5)), CacheLookup::Fresh(ref hit) if hit.body == b"persisted"));
        let other_profile = HttpCache::on_disk(CacheLimits::default(), dir.path().join("p2"));
        assert!(matches!(other_profile.lookup(&k, &none, usize::MAX, at(5)), CacheLookup::Miss));
    }

    #[test]
    fn http_dates_parse_in_all_three_formats() {
        let expected = Some(784_111_777.0);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), expected);
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), expected);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), expected);
        assert_eq!(parse_http_date("0"), None);
        assert_eq!(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"), None);
    }
}
