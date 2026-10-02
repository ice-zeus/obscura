use obscura_browser::{BrowserContext, Page};
use obscura_js::frame::FrameRealm;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

struct Server {
    base: String,
    requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = requests.clone();
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                // Accepted sockets can inherit the listener's nonblocking flag on macOS.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut data = Vec::new();
                while !data.windows(4).any(|v| v == b"\r\n\r\n") {
                    let mut buffer = [0; 4096];
                    let n = stream.read(&mut buffer).unwrap();
                    assert_ne!(n, 0);
                    data.extend_from_slice(&buffer[..n]);
                }
                let head = String::from_utf8(data).unwrap();
                let mut headers: HashMap<String, String> = head
                    .lines()
                    .skip(1)
                    .filter_map(|line| {
                        line.split_once(':')
                            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                    })
                    .collect();
                headers.insert(
                    ":path".into(),
                    head.split_whitespace().nth(1).unwrap().into(),
                );
                captured.lock().unwrap().push(headers);
                let body = "<!doctype html><html><body>identity</body></html>";
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        Self {
            base,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Err(error) = self.thread.take().unwrap().join() {
            if std::thread::panicking() {
                eprintln!("HTTP fixture worker also failed during test cleanup");
            } else {
                std::panic::resume_unwind(error);
            }
        }
    }
}
async fn frame_fetch(page: &mut Page, frame: &FrameRealm, path: &str) {
    let script=format!("(()=>{{globalThis.__identityDone=false;fetch('{}').then(r=>r.text()).then(()=>globalThis.__identityDone=true);return true}})()",path);
    frame.evaluate(page.js.as_mut().unwrap(), &script).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        page.settle(20).await;
        if frame
            .evaluate(page.js.as_mut().unwrap(), "globalThis.__identityDone")
            .unwrap()
            == serde_json::json!(true)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child frame fetch did not complete"
        );
    }
}
async fn check_frames(stealth: bool) {
    let server = Server::new();
    let context = Arc::new(BrowserContext::with_storage_and_network(
        "identity-context".into(),
        None,
        stealth,
        None,
        None,
        true,
    ));
    let mut page = Page::new("identity-page".into(), context.clone());
    page.navigate(&format!("{}/initial", server.base))
        .await
        .unwrap();
    let default = server.requests.lock().unwrap()[0]["user-agent"].clone();
    let frame = FrameRealm::new(
        page.js.as_mut().unwrap(),
        77,
        0,
        &format!("{}/frame", server.base),
        "<html><body>frame</body></html>",
    )
    .unwrap();
    page.set_http_extra_headers(HashMap::from([(
        "X-Fixture".into(),
        "retained-frame".into(),
    )]))
    .await;
    page.set_http_user_agent_override("FrameOverride/1").await;
    frame_fetch(&mut page, &frame, "/frame-after-fork").await;
    drop(frame);
    page.navigate(&format!("{}/after-navigation", server.base))
        .await
        .unwrap();
    let frame = FrameRealm::new(
        page.js.as_mut().unwrap(),
        78,
        0,
        &format!("{}/frame-new", server.base),
        "<html><body>frame</body></html>",
    )
    .unwrap();
    frame_fetch(&mut page, &frame, "/frame-after-navigation").await;
    page.set_http_extra_headers(HashMap::new()).await;
    page.set_http_user_agent_override("").await;
    frame_fetch(&mut page, &frame, "/frame-after-reset").await;
    if !stealth {
        let replacement = Arc::new(obscura_net::ObscuraHttpClient::with_full_options(
            context.cookie_jar.clone(),
            None,
            true,
        ));
        replacement.set_user_agent("ReplacementDefault/1").await;
        page.http_client = replacement.clone();
        page.set_http_user_agent_override("ReplacementOverride/2")
            .await;
        assert!(!Arc::ptr_eq(&page.http_client, &replacement));
        page.set_http_user_agent_override("").await;
        frame_fetch(&mut page, &frame, "/frame-after-client-replacement").await;
        assert_eq!(*replacement.user_agent.read().await, "ReplacementDefault/1");
    }
    let rows = server.requests.lock().unwrap();
    for path in [
        "/frame-after-fork",
        "/after-navigation",
        "/frame-after-navigation",
    ] {
        let row = rows.iter().find(|r| r[":path"] == path).unwrap();
        assert_eq!(row["user-agent"], "FrameOverride/1");
        assert_eq!(row["x-fixture"], "retained-frame");
    }
    let reset = rows
        .iter()
        .find(|r| r[":path"] == "/frame-after-reset")
        .unwrap();
    assert_eq!(reset["user-agent"], default);
    assert!(!reset.contains_key("x-fixture"));
    if !stealth {
        let replaced = rows
            .iter()
            .find(|r| r[":path"] == "/frame-after-client-replacement")
            .unwrap();
        assert_eq!(replaced["user-agent"], "ReplacementDefault/1");
    }
    assert_ne!(
        *context.http_client.user_agent.read().await,
        "FrameOverride/1"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn ordinary_identity_updates_existing_and_future_frame_wire_requests() {
    check_frames(false).await;
}
#[cfg(feature = "stealth")]
#[tokio::test(flavor = "current_thread")]
async fn stealth_identity_updates_existing_and_future_frame_wire_requests() {
    check_frames(true).await;
}
