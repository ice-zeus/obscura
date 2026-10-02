//! Request identity of the stealth transport, per request type.
//!
//! Every expectation below is Chromium 151's HTTP/1.1 request, captured from
//! a loopback server (same page, same origins), with the identity values of
//! the stealth profile. Over plain HTTP Chrome sends no Priority header and
//! keeps the connection alive explicitly; header names keep Chrome's casing.
//! The stealth transport used to send wreq's navigation defaults
//! (Sec-Fetch-Dest: document, Sec-Fetch-Mode: navigate, the HTML Accept) on
//! scripted fetches and worker scripts, with no Referer.
#![cfg(feature = "stealth")]

use obscura_browser::{BrowserContext, Page};
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Captured {
    side: char,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

struct Origins {
    a: String,
    b: String,
    c: String,
    requests: Arc<Mutex<Vec<Captured>>>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

const PAGE: &str = r#"<!doctype html><html><head><title>p</title></head><body>
<iframe src="/frame.html"></iframe>
<script>
(async () => {
  await fetch('/f-same.json');
  await fetch('{B}/f-samesite.json');
  await fetch('{C}/f-cross.json');
  navigator.sendBeacon('/beacon', 'x');
  for (let i = 0; i < 2; i++) {
    await new Promise((resolve) => {
      const worker = new Worker('/cache/worker.js');
      worker.onmessage = resolve;
      worker.onerror = resolve;
    });
  }
  setTimeout(() => { document.title = 'done'; }, 200);
})();
</script></body></html>"#;

const WORKER: &str =
    "importScripts('/cache/imported.js'); fetch('/w-fetch.json').then(() => postMessage(1), () => postMessage(0));";

fn respond(origin: Option<&str>, path: &str, a: &str, b: &str, c: &str) -> (String, &'static str, String) {
    let cors = format!(
        "Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Credentials: true\r\n",
        origin.unwrap_or("*")
    );
    let cache = if path.starts_with("/cache/") { "Cache-Control: max-age=600\r\n" } else { "Cache-Control: no-store\r\n" };
    let (ctype, body) = match path {
        "/page.html" => ("text/html", PAGE.replace("{B}", b).replace("{C}", c).replace("{A}", a)),
        "/frame.html" => ("text/html", "<!doctype html><p>frame</p>".to_string()),
        "/links.html" => ("text/html", format!(
            "<!doctype html><a id=cross href=\"{c}/next.html\">x</a><form id=post method=post action=\"/posted.html\"><input name=q value=1></form>"
        )),
        "/cache/worker.js" => ("text/javascript", WORKER.to_string()),
        "/cache/imported.js" => ("text/javascript", "self.imported = 1;".to_string()),
        _ => ("application/json", "{}".to_string()),
    };
    (format!("{cors}{cache}"), ctype, body)
}

impl Origins {
    fn start() -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let listeners: Vec<std::net::TcpListener> =
            (0..3).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        let ports: Vec<u16> = listeners.iter().map(|l| l.local_addr().unwrap().port()).collect();
        let a = format!("http://127.0.0.1:{}", ports[0]);
        let b = format!("http://127.0.0.1:{}", ports[1]);
        let c = format!("http://localhost:{}", ports[2]);
        let mut threads = Vec::new();
        for (index, listener) in listeners.into_iter().enumerate() {
            listener.set_nonblocking(true).unwrap();
            let side = ['A', 'B', 'C'][index];
            let (requests, stop) = (requests.clone(), stop.clone());
            let (a, b, c) = (a.clone(), b.clone(), c.clone());
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(value) => value,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => panic!("{error}"),
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut data = Vec::new();
                    while !data.windows(4).any(|v| v == b"\r\n\r\n") {
                        let mut buffer = [0; 4096];
                        let n = match stream.read(&mut buffer) {
                            Ok(n) => n,
                            Err(_) => 0,
                        };
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&buffer[..n]);
                    }
                    let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") else { continue };
                    let head = String::from_utf8_lossy(&data[..end]).to_string();
                    let mut lines = head.split("\r\n");
                    let first: Vec<String> = lines.next().unwrap_or("").split(' ').map(str::to_string).collect();
                    let headers: Vec<(String, String)> = lines
                        .filter_map(|line| line.split_once(':').map(|(k, v)| (k.to_string(), v.trim().to_string())))
                        .collect();
                    let length: usize = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = data[end + 4..].to_vec();
                    while body.len() < length {
                        let mut buffer = [0; 4096];
                        let n = stream.read(&mut buffer).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&buffer[..n]);
                    }
                    let path = first.get(1).cloned().unwrap_or_default();
                    let origin = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("origin")).map(|(_, v)| v.clone());
                    requests.lock().unwrap().push(Captured {
                        side,
                        method: first.first().cloned().unwrap_or_default(),
                        path: path.clone(),
                        headers,
                    });
                    let (extra, ctype, body) = respond(origin.as_deref(), &path, &a, &b, &c);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            }));
        }
        Self { a, b, c, requests, stop, threads }
    }
}

impl Drop for Origins {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Header lines with the volatile identity values replaced by names.
fn shape(request: &Captured, page: &str, worker: &str, a: &str) -> Vec<String> {
    request
        .headers
        .iter()
        .map(|(name, value)| {
            let value = match name.to_ascii_lowercase().as_str() {
                "host" => "<host>".to_string(),
                "user-agent" => {
                    assert_eq!(value, obscura_net::STEALTH_USER_AGENT);
                    "<ua>".to_string()
                }
                "sec-ch-ua" => "<brands>".to_string(),
                "sec-ch-ua-platform" => {
                    assert_eq!(value, "\"Windows\"");
                    "<platform>".to_string()
                }
                "accept-encoding" => {
                    assert_eq!(value, "gzip, deflate, br, zstd");
                    "<enc>".to_string()
                }
                "accept-language" => "<lang>".to_string(),
                "referer" => {
                    if value == page {
                        "<page>".to_string()
                    } else if !worker.is_empty() && value == worker {
                        "<worker>".to_string()
                    } else if *value == format!("{a}/") {
                        "<A>/".to_string()
                    } else {
                        value.clone()
                    }
                }
                "origin" => value.replace(a, "<A>"),
                _ => value.clone(),
            };
            format!("{name}: {value}")
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn stealth_requests_carry_chrome_headers_for_each_request_type() {
    let origins = Origins::start();
    let context = Arc::new(BrowserContext::with_storage_and_network(
        "request-identity".into(),
        None,
        true,
        None,
        None,
        true,
    ));
    let mut page = Page::new("request-identity-page".into(), context.clone());
    let page_url = format!("{}/page.html", origins.a);
    page.navigate(&page_url).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while page.evaluate("document.title") != serde_json::json!("done") {
        assert!(Instant::now() < deadline, "page scenario did not finish");
        page.settle(50).await;
    }
    let requests = origins.requests.lock().unwrap().clone();
    let worker_url = format!("{}/cache/worker.js", origins.a);
    let find = |side: char, path: &str| -> Captured {
        requests
            .iter()
            .find(|r| r.side == side && r.path == path)
            .unwrap_or_else(|| panic!("no request for {side} {path}: {requests:#?}"))
            .clone()
    };
    let check = |side: char, path: &str, expected: &[&str]| {
        let request = find(side, path);
        assert_eq!(
            shape(&request, &page_url, &worker_url, &origins.a),
            expected.iter().map(|line| line.to_string()).collect::<Vec<_>>(),
            "{} {side} {path}",
            request.method
        );
    };

    check('A', "/f-same.json", &[
        "Host: <host>", "Connection: keep-alive", "sec-ch-ua-platform: <platform>", "User-Agent: <ua>",
        "sec-ch-ua: <brands>", "sec-ch-ua-mobile: ?0", "Accept: */*", "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Mode: cors", "Sec-Fetch-Dest: empty", "Referer: <page>", "Accept-Encoding: <enc>",
        "Accept-Language: <lang>",
    ]);
    check('B', "/f-samesite.json", &[
        "Host: <host>", "Connection: keep-alive", "sec-ch-ua-platform: <platform>", "User-Agent: <ua>",
        "sec-ch-ua: <brands>", "sec-ch-ua-mobile: ?0", "Accept: */*", "Origin: <A>",
        "Sec-Fetch-Site: same-site", "Sec-Fetch-Mode: cors", "Sec-Fetch-Dest: empty", "Referer: <A>/",
        "Accept-Encoding: <enc>", "Accept-Language: <lang>",
    ]);
    check('C', "/f-cross.json", &[
        "Host: <host>", "Connection: keep-alive", "sec-ch-ua-platform: <platform>", "User-Agent: <ua>",
        "sec-ch-ua: <brands>", "sec-ch-ua-mobile: ?0", "Accept: */*", "Origin: <A>",
        "Sec-Fetch-Site: cross-site", "Sec-Fetch-Mode: cors", "Sec-Fetch-Dest: empty", "Referer: <A>/",
        "Accept-Encoding: <enc>", "Accept-Language: <lang>",
    ]);
    check('A', "/frame.html", &[
        "Host: <host>", "Connection: keep-alive", "sec-ch-ua: <brands>", "sec-ch-ua-mobile: ?0",
        "sec-ch-ua-platform: <platform>", "Upgrade-Insecure-Requests: 1", "User-Agent: <ua>",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site: same-origin", "Sec-Fetch-Mode: navigate", "Sec-Fetch-Dest: iframe", "Referer: <page>",
        "Accept-Encoding: <enc>", "Accept-Language: <lang>",
    ]);
    check('A', "/beacon", &[
        "Host: <host>", "Connection: keep-alive", "Content-Length: 1", "sec-ch-ua-platform: <platform>",
        "User-Agent: <ua>", "sec-ch-ua: <brands>", "Content-Type: text/plain;charset=UTF-8", "sec-ch-ua-mobile: ?0",
        "Accept: */*", "Origin: <A>", "Sec-Fetch-Site: same-origin", "Sec-Fetch-Mode: no-cors",
        "Sec-Fetch-Dest: empty", "Referer: <page>", "Accept-Encoding: <enc>", "Accept-Language: <lang>",
    ]);
    check('A', "/cache/worker.js", &[
        "Host: <host>", "Connection: keep-alive", "Accept: */*", "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Mode: same-origin", "Sec-Fetch-Dest: worker", "Referer: <page>", "User-Agent: <ua>",
        "Accept-Encoding: <enc>", "Accept-Language: <lang>",
    ]);
    check('A', "/cache/imported.js", &[
        "Host: <host>", "Connection: keep-alive", "User-Agent: <ua>", "Accept: */*", "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Mode: no-cors", "Sec-Fetch-Dest: script", "Referer: <worker>", "Accept-Encoding: <enc>",
        "Accept-Language: <lang>",
    ]);
    check('A', "/w-fetch.json", &[
        "Host: <host>", "Connection: keep-alive", "User-Agent: <ua>", "Accept: */*", "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Mode: cors", "Sec-Fetch-Dest: empty", "Referer: <worker>", "Accept-Encoding: <enc>",
        "Accept-Language: <lang>",
    ]);
    assert_eq!(find('A', "/beacon").method, "POST");

    // The second worker is served from the HTTP cache, as in Chrome: the
    // cacheable worker script and its importScripts dependency are fetched
    // once, the uncacheable fetch() twice.
    let count = |path: &str| requests.iter().filter(|r| r.side == 'A' && r.path == path).count();
    assert_eq!(count("/cache/worker.js"), 1, "worker script re-downloaded: {requests:#?}");
    assert_eq!(count("/cache/imported.js"), 1, "importScripts dependency re-downloaded");
    assert_eq!(count("/w-fetch.json"), 2);
}

/// Navigations the document starts (link click, form POST) carry it as
/// initiator: Sec-Fetch-Site, Referer and the POST's Origin, as in Chrome.
#[tokio::test(flavor = "current_thread")]
async fn stealth_document_initiated_navigations_carry_their_initiator() {
    let origins = Origins::start();
    let context = Arc::new(BrowserContext::with_storage_and_network(
        "request-identity-nav".into(),
        None,
        true,
        None,
        None,
        true,
    ));
    let mut page = Page::new("request-identity-nav-page".into(), context.clone());
    let links = format!("{}/links.html", origins.a);
    page.navigate(&links).await.unwrap();
    page.evaluate("document.getElementById('cross').click()");
    assert!(page.process_pending_navigation().await.unwrap(), "the link click navigates");
    page.navigate(&links).await.unwrap();
    page.evaluate("document.getElementById('post').submit()");
    assert!(page.process_pending_navigation().await.unwrap(), "the form submits");
    let requests = origins.requests.lock().unwrap().clone();
    let find = |side: char, path: &str| {
        requests.iter().find(|r| r.side == side && r.path == path).cloned()
            .unwrap_or_else(|| panic!("no request for {side} {path}: {requests:#?}"))
    };
    let html = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
    let worker = String::new();
    assert_eq!(shape(&find('C', "/next.html"), &links, &worker, &origins.a), [
        "Host: <host>", "Connection: keep-alive", "sec-ch-ua: <brands>", "sec-ch-ua-mobile: ?0",
        "sec-ch-ua-platform: <platform>", "Upgrade-Insecure-Requests: 1", "User-Agent: <ua>", html,
        "Sec-Fetch-Site: cross-site", "Sec-Fetch-Mode: navigate", "Sec-Fetch-User: ?1", "Sec-Fetch-Dest: document",
        "Referer: <A>/", "Accept-Encoding: <enc>", "Accept-Language: <lang>",
    ]);
    let posted = find('A', "/posted.html");
    assert_eq!(posted.method, "POST");
    assert_eq!(shape(&posted, &links, &worker, &origins.a), [
        "Host: <host>", "Connection: keep-alive", "Content-Length: 3", "Cache-Control: max-age=0",
        "sec-ch-ua: <brands>", "sec-ch-ua-mobile: ?0", "sec-ch-ua-platform: <platform>",
        "Upgrade-Insecure-Requests: 1", "Content-Type: application/x-www-form-urlencoded", "User-Agent: <ua>",
        "Origin: <A>", html, "Sec-Fetch-Site: same-origin", "Sec-Fetch-Mode: navigate", "Sec-Fetch-User: ?1",
        "Sec-Fetch-Dest: document", "Referer: <page>", "Accept-Encoding: <enc>", "Accept-Language: <lang>",
    ]);
}
