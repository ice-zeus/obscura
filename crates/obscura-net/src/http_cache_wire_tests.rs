//! Wire-level checks of the stealth transport's HTTP cache: what is (and is
//! not) sent, in which order, and what the caller receives.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::client::{CallbackRegistry, RequestMode, ResourceRequest, ResourceType};
use crate::cookies::CookieJar;
use crate::http_cache::{CacheLimits, HttpCache};
use crate::wreq_client::StealthHttpClient;

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    /// Header names in wire order, lowercased.
    order: Vec<String>,
    headers: HashMap<String, String>,
}

type Responder = Arc<dyn Fn(&Seen) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync>;

struct Server {
    origin: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    async fn start(responder: Responder) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let log = log.clone();
                let responder = responder.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    loop {
                        let mut chunk = [0u8; 4096];
                        let end = loop {
                            if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                break end;
                            }
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buffer[..end]).to_string();
                        buffer.drain(..end + 4);
                        let mut lines = head.split("\r\n");
                        let path = lines.next().unwrap_or("").split(' ').nth(1).unwrap_or("").to_string();
                        let mut order = Vec::new();
                        let mut headers = HashMap::new();
                        for line in lines {
                            if let Some((name, value)) = line.split_once(':') {
                                let name = name.trim().to_ascii_lowercase();
                                order.push(name.clone());
                                headers.insert(name, value.trim().to_string());
                            }
                        }
                        let request = Seen { path, order, headers };
                        let (status, extra, body) = responder(&request);
                        log.lock().unwrap().push(request);
                        let reason = if status == 304 { "Not Modified" } else { "OK" };
                        let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
                        for (name, value) in &extra {
                            response.push_str(&format!("{name}: {value}\r\n"));
                        }
                        if status != 304 {
                            response.push_str(&format!("content-length: {}\r\n", body.len()));
                        }
                        response.push_str("\r\n");
                        let mut bytes = response.into_bytes();
                        if status != 304 {
                            bytes.extend_from_slice(&body);
                        }
                        if socket.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Server { origin, seen }
    }

    fn url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{}", self.origin, path)).unwrap()
    }

    fn requests(&self, path: &str) -> Vec<Seen> {
        self.seen.lock().unwrap().iter().filter(|seen| seen.path == path).cloned().collect()
    }
}

fn client(jar: Arc<CookieJar>, cache: Option<Arc<HttpCache>>) -> StealthHttpClient {
    StealthHttpClient::with_proxy(jar, None, true).with_http_cache(cache)
}

fn cache() -> Arc<HttpCache> {
    Arc::new(HttpCache::in_memory(CacheLimits::default()))
}

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[tokio::test]
async fn fresh_responses_are_served_from_the_cache_without_a_request() {
    let server = Server::start(Arc::new(|_| {
        (200, headers(&[("cache-control", "public, max-age=31536000"), ("access-control-allow-origin", "*"), ("content-type", "font/woff2")]), b"WOFF2-BYTES".to_vec())
    }))
    .await;
    let stealth = client(Arc::new(CookieJar::new()), Some(cache()));
    let page = Url::parse("http://127.0.0.1/search?q=1").unwrap();
    let callbacks = CallbackRegistry::new();
    let observed = Arc::new(Mutex::new(0usize));
    let counter = observed.clone();
    callbacks.add_response(Arc::new(move |_, _| *counter.lock().unwrap() += 1));
    for _ in 0..3 {
        let request = ResourceRequest::subresource(ResourceType::Font, &page);
        let response = stealth.fetch_resource_with_callbacks(&server.url("/font.woff2"), request, Some(&callbacks)).await.unwrap();
        assert_eq!(response.body, b"WOFF2-BYTES");
        assert_eq!(response.status, 200);
    }
    assert_eq!(server.requests("/font.woff2").len(), 1, "two of three loads come from the cache");
    assert_eq!(*observed.lock().unwrap(), 3, "cache hits still report a response to observers");
}

#[tokio::test]
async fn stale_entries_revalidate_with_chrome_validators_after_the_cookie() {
    let server = Server::start(Arc::new(|seen| {
        if seen.headers.get("if-none-match").map(String::as_str) == Some("\"css-1\"") {
            return (304, headers(&[("cache-control", "no-cache"), ("etag", "\"css-1\"")]), Vec::new());
        }
        (200, headers(&[
            ("cache-control", "no-cache"), ("etag", "\"css-1\""),
            ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"), ("content-type", "text/css"),
        ]), b"body{color:red}".to_vec())
    }))
    .await;
    let jar = Arc::new(CookieJar::new());
    jar.set_cookie("NID=abc", &server.url("/"));
    let stealth = client(jar, Some(cache()));
    let page = server.url("/search");
    for _ in 0..2 {
        let request = ResourceRequest::subresource(ResourceType::Stylesheet, &page);
        let response = stealth.fetch_resource_with_callbacks(&server.url("/s.css"), request, None).await.unwrap();
        assert_eq!(response.status, 200, "a revalidated entry reaches the page as the stored 200");
        assert_eq!(response.body, b"body{color:red}");
        assert_eq!(response.header("content-type"), Some("text/css"));
    }
    let requests = server.requests("/s.css");
    assert_eq!(requests.len(), 2);
    assert!(!requests[0].headers.contains_key("if-none-match"));
    let conditional = &requests[1];
    assert_eq!(conditional.headers.get("if-none-match").map(String::as_str), Some("\"css-1\""));
    assert_eq!(conditional.headers.get("if-modified-since").map(String::as_str), Some("Wed, 21 Oct 2015 07:28:00 GMT"));
    let position = |name: &str| conditional.order.iter().position(|n| n == name).unwrap_or_else(|| panic!("{name} missing: {:?}", conditional.order));
    assert!(position("referer") < position("cookie"));
    assert!(position("cookie") < position("if-none-match"), "{:?}", conditional.order);
    assert!(position("if-none-match") < position("if-modified-since"), "{:?}", conditional.order);
    // Every other header is exactly what the first request sent.
    let mut first = requests[0].order.clone();
    let mut second: Vec<String> = conditional.order.iter().filter(|n| !n.starts_with("if-")).cloned().collect();
    first.sort();
    second.sort();
    assert_eq!(first, second);
    for name in &requests[0].order {
        assert_eq!(requests[0].headers.get(name), conditional.headers.get(name), "{name}");
    }
}

#[tokio::test]
async fn entries_are_partitioned_by_top_frame_and_frame_site() {
    let server = Server::start(Arc::new(|_| {
        (200, headers(&[("cache-control", "max-age=600"), ("access-control-allow-origin", "*")]), b"shared".to_vec())
    }))
    .await;
    let stealth = client(Arc::new(CookieJar::new()), Some(cache()));
    let font = server.url("/f.woff2");
    let fetch = |initiator: &str, top: Option<&str>| {
        let mut request = ResourceRequest::subresource(ResourceType::Font, &Url::parse(initiator).unwrap());
        request.top_frame = top.map(|url| Url::parse(url).unwrap());
        stealth.fetch_resource_with_callbacks(&font, request, None)
    };
    fetch("https://www.google.com/search", None).await.unwrap();
    fetch("https://images.google.com/", None).await.unwrap(); // same site: hit
    assert_eq!(server.requests("/f.woff2").len(), 1);
    fetch("https://example.org/", None).await.unwrap(); // other top-level site
    assert_eq!(server.requests("/f.woff2").len(), 2);
    fetch("https://www.google.com/frame", Some("https://example.org/")).await.unwrap(); // google frame inside example.org
    assert_eq!(server.requests("/f.woff2").len(), 3);
    fetch("https://www.google.com/frame", Some("https://example.org/")).await.unwrap();
    assert_eq!(server.requests("/f.woff2").len(), 3);
}

#[tokio::test]
async fn profiles_never_share_and_uncacheable_requests_bypass() {
    let server = Server::start(Arc::new(|seen| {
        let control = if seen.path == "/private" { "no-store" } else { "max-age=600" };
        (200, headers(&[("cache-control", control)]), b"x".to_vec())
    }))
    .await;
    let page = server.url("/");
    let first = client(Arc::new(CookieJar::new()), Some(cache()));
    let second = client(Arc::new(CookieJar::new()), Some(cache()));
    for stealth in [&first, &second] {
        stealth.fetch_resource_with_callbacks(&server.url("/a.js"), ResourceRequest::subresource(ResourceType::Script, &page), None).await.unwrap();
    }
    assert_eq!(server.requests("/a.js").len(), 2, "each profile fetches for itself");
    for _ in 0..2 {
        first.fetch_resource_with_callbacks(&server.url("/private"), ResourceRequest::subresource(ResourceType::Script, &page), None).await.unwrap();
        let mut navigation = ResourceRequest::navigation();
        navigation.mode = RequestMode::Navigate;
        first.fetch_resource_with_callbacks(&server.url("/doc"), navigation, None).await.unwrap();
    }
    assert_eq!(server.requests("/private").len(), 2, "no-store is never stored");
    assert_eq!(server.requests("/doc").len(), 2, "documents are not served from this cache");
    let uncached = client(Arc::new(CookieJar::new()), None);
    for _ in 0..2 {
        uncached.fetch_resource_with_callbacks(&server.url("/b.js"), ResourceRequest::subresource(ResourceType::Script, &page), None).await.unwrap();
    }
    assert_eq!(server.requests("/b.js").len(), 2, "OBSCURA_HTTP_CACHE=off sends every request");
}

#[tokio::test]
async fn cached_cors_responses_are_checked_against_each_requesting_origin() {
    let server = Server::start(Arc::new(|seen| {
        let origin = seen.headers.get("origin").cloned().unwrap_or_default();
        (200, headers(&[("cache-control", "max-age=600"), ("access-control-allow-origin", &origin)]), b"font".to_vec())
    }))
    .await;
    let stealth = client(Arc::new(CookieJar::new()), Some(cache()));
    let font = Url::parse("http://localhost:1/f.woff2").unwrap();
    let font = server.url(font.path());
    let a = Url::parse("https://a.example.com/").unwrap();
    let b = Url::parse("https://b.example.com/").unwrap();
    stealth.fetch_resource_with_callbacks(&font, ResourceRequest::subresource(ResourceType::Font, &a), None).await.unwrap();
    // Same site, other origin: the stored response only allows a.example.com.
    let denied = stealth.fetch_resource_with_callbacks(&font, ResourceRequest::subresource(ResourceType::Font, &b), None).await;
    assert!(denied.is_err(), "a cached CORS response must not be reused for another origin");
    assert_eq!(server.requests("/f.woff2").len(), 1);
}
