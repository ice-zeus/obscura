//! Navigation waits for images the way Chrome orders them: page scripts run
//! while images are still loading, the window `load` event waits for them
//! (bounded by the render-resource warmup budget), and a capture waits for
//! loads still in flight without starting its own.
#![cfg(feature = "render")]

use obscura_browser::{BrowserContext, Page};
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const PNG: &[u8] = &[
    137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 2, 0, 0, 0, 3, 8, 6, 0, 0, 0, 185, 234,
    222, 129, 0, 0, 0, 17, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 240, 31, 132, 25, 48, 24, 0, 161, 121, 11,
    245, 77, 196, 154, 7, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
];

const PAGE: &str = r#"<!doctype html><html><body>
<img id="parser" src="/slow.png?a">
<script>
  const img = document.getElementById('parser');
  globalThis.__atScript = img.complete && img.naturalWidth > 0;
  window.addEventListener('load', () => { globalThis.__atLoad = [img.complete, img.naturalWidth, img.naturalHeight]; });
</script>
</body></html>"#;

struct Server {
    base: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn new(image_delay: Duration) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
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
                std::thread::spawn(move || {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut data = Vec::new();
                    while !data.windows(4).any(|v| v == b"\r\n\r\n") {
                        let mut buffer = [0; 4096];
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => data.extend_from_slice(&buffer[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&data);
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (kind, body): (&str, Vec<u8>) = if path.starts_with("/slow.png") {
                        std::thread::sleep(image_delay);
                        ("image/png", PNG.to_vec())
                    } else {
                        ("text/html", PAGE.as_bytes().to_vec())
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(&body);
                });
            }
        });
        Self { base, stop, thread: Some(thread) }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.thread.take().unwrap().join();
    }
}

fn page() -> Page {
    let context = Arc::new(BrowserContext::with_storage_and_network("waits".into(), None, false, None, None, true));
    Page::new("waits".into(), context)
}

#[tokio::test(flavor = "current_thread")]
async fn scripts_do_not_wait_for_images_but_the_load_event_does() {
    let server = Server::new(Duration::from_millis(400));
    let mut page = page();
    page.navigate(&format!("{}/page", server.base)).await.unwrap();
    assert_eq!(page.evaluate("globalThis.__atScript"), false, "a parser script runs before the image arrives");
    assert_eq!(page.evaluate("globalThis.__atLoad"), serde_json::json!([true, 2, 3]), "load waits for the image");
}

#[tokio::test(flavor = "current_thread")]
async fn the_load_event_waits_no_longer_than_the_warmup_budget() {
    // The budget is per process (nextest runs each test in its own process).
    std::env::set_var("OBSCURA_RENDER_RESOURCE_WARMUP_MS", "150");
    let server = Server::new(Duration::from_millis(1_500));
    let mut page = page();
    let started = std::time::Instant::now();
    page.navigate(&format!("{}/page", server.base)).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(1_200), "{:?}", started.elapsed());
    assert_eq!(page.evaluate("globalThis.__atLoad[0]"), false, "load fired at the budget, image still loading");
    // A later capture waits for the load still in flight, without starting new ones.
    page.wait_for_in_flight_render_resources(3_000).await;
    assert_eq!(page.evaluate("document.getElementById('parser').complete"), true);
}

#[tokio::test(flavor = "current_thread")]
async fn warmup_images_restores_waiting_before_scripts() {
    std::env::set_var("OBSCURA_RENDER_RESOURCE_WARMUP_IMAGES", "1");
    let server = Server::new(Duration::from_millis(200));
    let mut page = page();
    page.navigate(&format!("{}/page", server.base)).await.unwrap();
    assert_eq!(page.evaluate("globalThis.__atScript"), true);
}
