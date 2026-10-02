//! Offline wire regressions for `Accept-CH` / `Critical-CH` on the stealth
//! transport: hints an origin accepted reach later navigations and its
//! same-origin subresources, and a critical hint restarts the navigation once.
use crate::client::{ResourceRequest, ResourceType};
use crate::{CookieJar, StealthHttpClient};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use url::Url;

/// One recorded request: its path and header lines in wire order.
type Seen = (String, Vec<(String, String)>);

struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    /// Answers every request with 200 and the response headers `respond`
    /// returns for its path.
    fn new(respond: fn(&str) -> &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (records, stopped) = (seen.clone(), stop.clone());
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
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut bytes = Vec::new();
                while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let head = String::from_utf8_lossy(&bytes).to_string();
                let mut lines = head.split("\r\n");
                let path = lines.next().unwrap().split_whitespace().nth(1).unwrap().to_string();
                let headers = lines
                    .take_while(|line| !line.is_empty())
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| (name.to_string(), value.trim().to_string()))
                    .collect();
                let extra = respond(&path);
                records.lock().unwrap().push((path, headers));
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\n{extra}Content-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
            }
        });
        Server { port, seen, stop, thread: Some(thread) }
    }

    fn url(&self, host: &str, path: &str) -> Url {
        Url::parse(&format!("http://{host}:{}{path}", self.port)).unwrap()
    }

    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn client() -> StealthHttpClient {
    StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true)
}

/// Header names in wire order, without the `Host` line the transport adds.
fn names(headers: &[(String, String)]) -> Vec<&str> {
    headers.iter().map(|(name, _)| name.as_str()).filter(|name| !name.eq_ignore_ascii_case("host")).collect()
}

fn value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(known, _)| known == name).map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn accepted_hints_reach_later_navigations_and_same_origin_subresources() {
    let server = Server::new(|path| {
        if path == "/accept" { "Accept-CH: Sec-CH-Prefers-Color-Scheme, Sec-CH-UA-Arch, Width\r\n" } else { "" }
    });
    let client = client();
    let page = server.url("127.0.0.1", "/accept");
    client.fetch(&page).await.unwrap();
    let first = server.take();
    assert_eq!(first.len(), 1);
    assert_eq!(value(&first[0].1, "sec-ch-prefers-color-scheme"), None, "hints start with the response that asks for them");

    client.fetch(&server.url("127.0.0.1", "/next")).await.unwrap();
    let script = ResourceRequest::subresource(ResourceType::Script, &page);
    client.fetch_resource_with_callbacks(&server.url("127.0.0.1", "/app.js"), script.clone(), None).await.unwrap();
    client.fetch_resource_with_callbacks(&server.url("localhost", "/other.js"), script, None).await.unwrap();
    // Another origin never accepted hints, so its navigation carries none.
    client.fetch(&server.url("localhost", "/elsewhere")).await.unwrap();
    let seen = server.take();
    assert_eq!(seen.len(), 4);

    let navigation = &seen[0].1;
    assert_eq!(names(navigation)[..5], ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-prefers-color-scheme"]);
    assert_eq!(value(navigation, "sec-ch-ua-arch"), Some("\"x86\""));
    assert_eq!(value(navigation, "sec-ch-prefers-color-scheme"), Some("light"));
    assert_eq!(value(navigation, "width"), None, "Width needs a layout size and is never sent");

    let same_origin = &seen[1].1;
    assert_eq!(value(same_origin, "sec-ch-prefers-color-scheme"), Some("light"));
    // Blink's header map order for these names (see blink_header_order).
    let ordered: Vec<&str> = names(same_origin).into_iter().take_while(|name| *name != "Accept").collect();
    assert_eq!(ordered, ["sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-prefers-color-scheme", "sec-ch-ua", "User-Agent", "sec-ch-ua-mobile"]);

    for (path, headers) in &seen[2..] {
        assert_eq!(value(headers, "sec-ch-prefers-color-scheme"), None, "{path}");
        assert_eq!(value(headers, "sec-ch-ua-arch"), None, "{path}");
        assert!(value(headers, "sec-ch-ua").is_some(), "{path}: low entropy hints are always sent");
    }
}

#[tokio::test]
async fn critical_hint_restarts_the_navigation_once_with_hints_after_accept() {
    let server = Server::new(|_| "Accept-CH: Sec-CH-Prefers-Color-Scheme\r\nCritical-CH: Sec-CH-Prefers-Color-Scheme\r\n");
    let client = client();
    let response = client.fetch(&server.url("127.0.0.1", "/critical")).await.unwrap();
    assert_eq!(response.status, 200);
    let seen = server.take();
    assert_eq!(seen.len(), 2, "one restart, and none once the hint is sent");
    assert_eq!(value(&seen[0].1, "sec-ch-prefers-color-scheme"), None);
    let retried = names(&seen[1].1);
    let accept = retried.iter().position(|name| *name == "Accept").unwrap();
    assert_eq!(retried[accept + 1..accept + 5], ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-prefers-color-scheme"]);
    assert_eq!(value(&seen[1].1, "sec-ch-prefers-color-scheme"), Some("light"));

    // The preference is now stored: the next navigation leads with it and
    // is not restarted.
    client.fetch(&server.url("127.0.0.1", "/critical")).await.unwrap();
    let seen = server.take();
    assert_eq!(seen.len(), 1);
    assert_eq!(names(&seen[0].1)[..4], ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-prefers-color-scheme"]);
}
