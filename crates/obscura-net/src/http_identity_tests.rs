//! Offline wire regressions for page identity settings and form transport.
use crate::{CallbackRegistry, CookieJar, ObscuraHttpClient, RequestInfo};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug)]
struct Wire {
    method: String,
    headers: HashMap<String, String>,
    raw_headers: Vec<(String, String)>,
    body: Vec<u8>,
}
fn assert_single_header(wire: &Wire, name: &str, expected: &str) {
    let values = wire.raw_headers.iter().filter(|(known, _)| known == name)
        .map(|(_, value)| value.as_str()).collect::<Vec<_>>();
    assert_eq!(values, [expected], "raw {name} field lines must contain exactly the selected value");
}
struct Fixture {
    url: Url,
    seen: Arc<Mutex<Vec<Wire>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(status: u16, location: Option<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!(
            "http://{}/fixture",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let records = seen.clone();
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let boundary = loop {
                    if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        break index + 4;
                    }
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0);
                    bytes.extend_from_slice(&buffer[..count]);
                    assert!(bytes.len() < 1024 * 1024);
                };
                let head = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
                let mut lines = head.split("\r\n");
                let method = lines
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_string();
                let raw_headers: Vec<(String, String)> = lines
                    .filter_map(|line| {
                        line.split_once(':').map(|(name, value)| {
                            (name.to_ascii_lowercase(), value.trim().to_string())
                        })
                    })
                    .collect();
                let headers: HashMap<String, String> = raw_headers.iter().cloned().collect();
                let length: usize = headers
                    .get("content-length")
                    .map(|v| v.parse().unwrap())
                    .unwrap_or(0);
                assert!(length < 1024 * 1024);
                while bytes.len() - boundary < length {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let response_body = headers
                    .get("accept-language")
                    .cloned()
                    .unwrap_or_else(|| "ok".into());
                records.lock().unwrap().push(Wire {
                    method,
                    headers,
                    raw_headers,
                    body: bytes[boundary..boundary + length].to_vec(),
                });
                if status != 0 {
                    let redirect = location
                        .as_ref()
                        .map(|v| format!("Location: {v}\r\n"))
                        .unwrap_or_default();
                    write!(stream, "HTTP/1.1 {status} Fixture\r\n{redirect}Content-Length: {}\r\nCache-Control: max-age=600\r\nConnection: close\r\n\r\n{response_body}", response_body.len()).unwrap();
                }
            }
        });
        Self {
            url,
            seen,
            stop,
            thread: Some(thread),
        }
    }
    fn rows(&self) -> Vec<Wire> {
        self.seen.lock().unwrap().clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn ordinary() -> ObscuraHttpClient {
    ObscuraHttpClient::with_full_options(Arc::new(CookieJar::new()), None, true)
}
fn overrides(value: &str) -> HashMap<String, String> {
    HashMap::from([("X-Fixture".into(), value.into())])
}
fn observe() -> (CallbackRegistry, Arc<Mutex<Vec<RequestInfo>>>) {
    let callbacks = CallbackRegistry::new();
    let rows = Arc::new(Mutex::new(Vec::new()));
    let request_rows = rows.clone();
    callbacks.add_request(Arc::new(move |request| {
        request_rows.lock().unwrap().push(request.clone())
    }));
    (callbacks, rows)
}

#[tokio::test]
async fn ordinary_identity_fork_preserves_context_ownership_and_wire_callbacks() {
    let fixture = Fixture::new(200, None);
    let context = Arc::new(ordinary());
    context.set_user_agent("ContextDefault/1").await;
    context.set_extra_headers(overrides("inherited")).await;
    let page = context.fork_request_settings().await;
    assert!(Arc::ptr_eq(&page.cookie_jar, &context.cookie_jar));
    assert!(
        page.interceptor.read().await.is_none(),
        "fork retains the public field type and delegates internally"
    );
    assert!(Arc::ptr_eq(&page.in_flight, &context.in_flight));
    let (callbacks, observations) = observe();
    page.fetch_with_callbacks(&fixture.url, Some(&callbacks))
        .await
        .unwrap();
    page.set_user_agent("Page/2").await;
    page.set_extra_headers(overrides("page")).await;
    page.fetch_with_callbacks(&fixture.url, Some(&callbacks))
        .await
        .unwrap();
    page.set_extra_headers(HashMap::new()).await;
    page.fetch_with_callbacks(&fixture.url, Some(&callbacks))
        .await
        .unwrap();
    context.fetch(&fixture.url).await.unwrap();
    let wire = fixture.rows();
    assert_eq!(wire.len(), 4);
    assert_eq!(wire[0].headers["user-agent"], "ContextDefault/1");
    assert_eq!(wire[0].headers["x-fixture"], "inherited");
    assert_eq!(wire[1].headers["user-agent"], "Page/2");
    assert_eq!(wire[1].headers["x-fixture"], "page");
    assert_eq!(wire[2].headers["user-agent"], "Page/2");
    assert!(!wire[2].headers.contains_key("x-fixture"));
    assert_eq!(wire[3].headers["user-agent"], "ContextDefault/1");
    assert_eq!(wire[3].headers["x-fixture"], "inherited");
    assert_eq!(observations.lock().unwrap().len(), 3, "every callback-bearing request is observed");
    for (observed, actual) in observations.lock().unwrap().iter().zip(&wire) {
        assert_eq!(
            observed.headers.get("user-agent"),
            actual.headers.get("user-agent")
        );
        assert_eq!(
            observed.headers.get("x-fixture"),
            actual.headers.get("x-fixture")
        );
    }
}

#[tokio::test]
async fn ordinary_form_redirects_strip_credentials_and_preserve_307_308_bodies() {
    for (status, same_host) in [302, 303, 307, 308].into_iter().flat_map(|status| [true, false].map(|same_host| (status, same_host))) {
        let destination = Fixture::new(200, None);
        let mut source = Fixture::new(status, Some(destination.url.to_string()));
        // Different ports change origin but retain host-only cookies. The localhost
        // variant changes the host too; both endpoints remain owned loopback fixtures.
        if !same_host {
            source.url.set_host(Some("localhost")).unwrap();
        }
        let client = ordinary();
        client.cookie_jar.set_cookie("jar=owned; Path=/", &source.url);
        client
            .set_extra_headers(HashMap::from([
                ("Authorization".into(), "Fixture secret".into()),
                ("Cookie".into(), "fixture=secret".into()),
                ("Host".into(), "fixture.invalid".into()),
                ("Content-Type".into(), "application/x-custom".into()),
            ]))
            .await;
        client.post_form(&source.url, "x=fixture").await.unwrap();
        let first = source.rows();
        let last = destination.rows();
        assert_eq!(first.len(), 1);
        assert_eq!(last.len(), 1);
        assert_eq!(first[0].method, "POST");
        assert_eq!(first[0].body, b"x=fixture");
        assert_single_header(&first[0], "content-type", "application/x-www-form-urlencoded");
        assert_single_header(&first[0], "cookie", "fixture=secret");
        assert_eq!(first[0].headers["authorization"], "Fixture secret");
        assert!(!last[0].headers.contains_key("authorization"));
        if same_host {
            assert_single_header(&last[0], "cookie", "jar=owned");
        } else {
            assert!(!last[0].headers.contains_key("cookie"));
        }
        assert_ne!(last[0].headers["host"], "fixture.invalid");
        if status < 307 {
            assert_eq!(last[0].method, "GET");
            assert!(last[0].body.is_empty());
            assert!(!last[0].headers.contains_key("content-type"));
        } else {
            assert_eq!(last[0].method, "POST");
            assert_eq!(last[0].body, b"x=fixture");
            assert_single_header(&last[0], "content-type", "application/x-www-form-urlencoded");
        }
    }
}

#[cfg(feature = "stealth")]
#[tokio::test]
async fn stealth_identity_replacement_reset_and_request_precedence_reach_wire() {
    let fixture = Fixture::new(200, None);
    let client = crate::StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
    client.fetch(&fixture.url).await.unwrap();
    let default = fixture.rows()[0].headers["user-agent"].clone();
    client.cookie_jar.set_cookie("jar=owned; Path=/", &fixture.url);
    let (callbacks, observations) = observe();
    for ua_first in [true, false] {
        if ua_first {
            client.set_user_agent_override("Page/2").await;
        }
        client.set_extra_headers(overrides("one")).await;
        if !ua_first {
            client.set_user_agent_override("Page/2").await;
        }
        client
            .fetch_with_callbacks(&fixture.url, Some(&callbacks))
            .await
            .unwrap();
        client.set_extra_headers(overrides("two")).await;
        client.fetch(&fixture.url).await.unwrap();
        client.set_extra_headers(HashMap::new()).await;
        client.fetch(&fixture.url).await.unwrap();
        client
            .send_single(
                "GET",
                &fixture.url,
                &HashMap::from([("USER-AGENT".into(), "Request/3".into()), ("Cookie".into(), "request=selected".into()), ("Accept".into(), "application/x-request".into())]),
                &[],
                true,
                false,
            )
            .await
            .unwrap();
        client.set_user_agent_override("").await;
        client.fetch(&fixture.url).await.unwrap();
    }
    let wire = fixture.rows();
    assert_eq!(wire.len(), 11);
    for index in [1, 6] {
        assert_eq!(wire[index].headers["user-agent"], "Page/2");
        assert_eq!(wire[index].headers["x-fixture"], "one");
        assert_eq!(wire[index + 1].headers["user-agent"], "Page/2");
        assert_eq!(wire[index + 1].headers["x-fixture"], "two");
        assert_eq!(wire[index + 2].headers["user-agent"], "Page/2");
        assert!(!wire[index + 2].headers.contains_key("x-fixture"));
        assert_eq!(wire[index + 3].headers["user-agent"], "Request/3");
        assert_single_header(&wire[index + 3], "user-agent", "Request/3");
        assert_single_header(&wire[index + 3], "cookie", "request=selected");
        assert_single_header(&wire[index + 3], "accept", "application/x-request");
        assert_eq!(wire[index + 4].headers["user-agent"], default);
    }
    let observed = observations.lock().unwrap();
    assert_eq!(observed.len(), 2);
    for request in observed.iter() {
        assert_eq!(request.headers["user-agent"], "Page/2");
        assert_eq!(request.headers["x-fixture"], "one");
    }
}

#[cfg(feature = "stealth")]
#[tokio::test]
async fn stealth_form_redirects_keep_method_body_and_drop_cross_origin_credentials() {
    for (status, same_host) in [302, 303, 307, 308].into_iter().flat_map(|status| [true, false].map(|same_host| (status, same_host))) {
        let destination = Fixture::new(200, None);
        let mut source = Fixture::new(status, Some(destination.url.to_string()));
        // Different ports change origin but retain host-only cookies. The localhost
        // variant changes the host too; both endpoints remain owned loopback fixtures.
        if !same_host {
            source.url.set_host(Some("localhost")).unwrap();
        }
        let client = crate::StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
        client.set_user_agent_override("Solver/1").await;
        client.cookie_jar.set_cookie("jar=owned; Path=/", &source.url);
        client
            .set_extra_headers(HashMap::from([
                ("Authorization".into(), "Fixture secret".into()),
                ("Cookie".into(), "fixture=secret".into()),
                ("Host".into(), "fixture.invalid".into()),
                ("Accept".into(), "application/x-fixture".into()),
                ("Content-Type".into(), "application/x-caller".into()),
            ]))
            .await;
        let (callbacks, observed) = observe();
        client
            .post_form_with_callbacks(&source.url, "x=fixture", Some(&callbacks))
            .await
            .unwrap();
        let first = source.rows();
        let last = destination.rows();
        assert_eq!(first.len(), 1);
        assert_eq!(last.len(), 1);
        assert_eq!(first[0].method, "POST");
        assert_eq!(first[0].body, b"x=fixture");
        assert_eq!(first[0].headers["user-agent"], "Solver/1");
        assert_single_header(&first[0], "user-agent", "Solver/1");
        assert_single_header(&first[0], "accept", "application/x-fixture");
        assert_single_header(&first[0], "cookie", "fixture=secret");
        assert_single_header(&first[0], "content-type", "application/x-www-form-urlencoded");
        assert_single_header(&last[0], "accept", "application/x-fixture");
        assert_eq!(first[0].headers["authorization"], "Fixture secret");
        assert_eq!(last[0].headers["user-agent"], "Solver/1");
        assert!(!last[0].headers.contains_key("authorization"));
        if same_host {
            assert_single_header(&last[0], "cookie", "jar=owned");
        } else {
            assert!(!last[0].headers.contains_key("cookie"));
        }
        assert_ne!(last[0].headers["host"], "fixture.invalid");
        if status < 307 {
            assert_eq!(last[0].method, "GET");
            assert!(last[0].body.is_empty());
            assert!(!last[0].headers.contains_key("content-type"));
        } else {
            assert_eq!(last[0].method, "POST");
            assert_eq!(last[0].body, b"x=fixture");
            assert_single_header(&last[0], "content-type", "application/x-www-form-urlencoded");
        }
        assert_eq!(
            observed.lock().unwrap()[0].headers["user-agent"],
            first[0].headers["user-agent"]
        );
    }
}

#[cfg(feature = "stealth")]
#[tokio::test]
async fn stealth_form_with_lost_response_is_never_replayed() {
    let fixture = Fixture::new(0, None);
    let client = crate::StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
    assert!(client
        .post_form_with_callbacks(&fixture.url, "token=synthetic", None)
        .await
        .is_err());
    let rows = fixture.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].method, "POST");
    assert_eq!(rows[0].body, b"token=synthetic");
}

struct CountInterceptor(Arc<std::sync::atomic::AtomicUsize>);
#[async_trait::async_trait]
impl crate::interceptor::RequestInterceptor for CountInterceptor {
    async fn intercept(&self, _: &RequestInfo) -> crate::interceptor::InterceptAction {
        self.0.fetch_add(1, Ordering::SeqCst);
        crate::interceptor::InterceptAction::Continue
    }
}

#[tokio::test]
async fn identity_fork_cache_tracks_parent_and_local_interception_changes() {
    let fixture = Fixture::new(200, None);
    let context = Arc::new(ordinary());
    let page = context.fork_request_settings().await;
    let request = crate::ResourceRequest::subresource(crate::ResourceType::Image, &fixture.url);
    page.fetch_resource_with_callbacks(&fixture.url, request.clone(), None)
        .await
        .unwrap();
    context
        .fetch_resource_with_callbacks(&fixture.url, request.clone(), None)
        .await
        .unwrap();
    assert_eq!(
        fixture.rows().len(),
        1,
        "fork shares eligible context resource cache"
    );
    let parent_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    *context.interceptor.write().await = Some(Box::new(CountInterceptor(parent_calls.clone())));
    page.fetch_resource_with_callbacks(&fixture.url, request.clone(), None)
        .await
        .unwrap();
    assert_eq!(fixture.rows().len(), 2);
    assert_eq!(parent_calls.load(Ordering::SeqCst), 1);
    let local_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    *page.interceptor.write().await = Some(Box::new(CountInterceptor(local_calls.clone())));
    page.fetch_resource_with_callbacks(&fixture.url, request.clone(), None)
        .await
        .unwrap();
    assert_eq!(fixture.rows().len(), 3);
    assert_eq!(local_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        parent_calls.load(Ordering::SeqCst),
        1,
        "local policy takes precedence"
    );
    *page.interceptor.write().await = None;
    *context.interceptor.write().await = None;
    page.fetch_resource_with_callbacks(&fixture.url, request.clone(), None)
        .await
        .unwrap();
    assert_eq!(
        fixture.rows().len(),
        3,
        "removing effective interception restores cache eligibility"
    );
    context.set_accept_language("en-fixture").await;
    page.set_accept_language("fr-fixture").await;
    for _ in 0..2 {
        assert_eq!(
            context
                .fetch_resource_with_callbacks(&fixture.url, request.clone(), None)
                .await
                .unwrap()
                .body,
            b"en-fixture"
        );
        assert_eq!(
            page.fetch_resource_with_callbacks(&fixture.url, request.clone(), None)
                .await
                .unwrap()
                .body,
            b"fr-fixture"
        );
    }
    assert_eq!(
        fixture.rows().len(),
        5,
        "independent languages use distinct shared-cache entries"
    );
}
