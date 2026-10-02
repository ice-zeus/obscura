//! The randomized fingerprint surfaces belong to the browser profile.
//!
//! One browser context must report the same values on every navigation,
//! reload, tab, same-origin and cross-origin frame and worker, while separate
//! contexts keep drawing independent values. Fingerprinting scripts compare
//! exactly these: a value that changes on a second visit, or differs between a
//! page and its own iframe or worker, identifies a spoofing browser.

use obscura_browser::{BrowserContext, Page};
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

struct Server {
    base: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    /// Serves `/top` (a page with the given frame sources) and `/frame`.
    fn new(frames: Vec<String>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let top = format!(
            "<!doctype html><html><body>top{}</body></html>",
            frames
                .iter()
                .map(|src| format!("<iframe src=\"{src}\"></iframe>"))
                .collect::<String>()
        );
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
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut data = Vec::new();
                while !data.windows(4).any(|v| v == b"\r\n\r\n") {
                    let mut buffer = [0; 4096];
                    let n = match stream.read(&mut buffer) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&buffer[..n]);
                }
                let head = String::from_utf8_lossy(&data);
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = if path.starts_with("/top") {
                    top.clone()
                } else {
                    "<!doctype html><html><body>frame</body></html>".to_string()
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
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

/// The surfaces derived from the profile seed, read in the calling realm.
const IDENTITY: &str = r#"(() => {
  const audio = new AudioContext(), compressor = audio.createDynamicsCompressor();
  const canvas = document.createElement('canvas');
  canvas.width = 120; canvas.height = 24;
  const ctx = canvas.getContext('2d');
  ctx.font = '14px Arial'; ctx.fillStyle = '#069'; ctx.fillText('profile seed', 2, 16);
  const data = canvas.toDataURL();
  let hash = 2166136261;
  for (let i = 0; i < data.length; i++) hash = Math.imul(hash ^ data.charCodeAt(i), 16777619);
  let gpu = null;
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
    gpu = ext ? [gl.getParameter(ext.UNMASKED_VENDOR_WEBGL), gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)] : null;
  } catch (e) { gpu = String(e); }
  return {
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    screen: [screen.width, screen.height, screen.availWidth, screen.availHeight],
    audio: [audio.sampleRate, audio.baseLatency, compressor.threshold.value,
      compressor.knee.value, compressor.ratio.value],
    canvas: hash >>> 0,
    gpu,
    userAgent: navigator.userAgent,
  };
})()"#;

fn context(stealth: bool, seed: Option<u32>) -> Arc<BrowserContext> {
    let context = BrowserContext::with_storage_and_network(
        "default".into(),
        None,
        stealth,
        None,
        None,
        true,
    );
    Arc::new(match seed {
        Some(seed) => context.with_fingerprint_seed(seed),
        None => context,
    })
}

async fn open(context: &Arc<BrowserContext>, url: &str) -> Page {
    let mut page = Page::new("fingerprint-page".into(), context.clone());
    page.navigate(url).await.unwrap();
    page
}

async fn wait_for_frames(page: &mut Page, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while page.frame_urls().len() < count {
        assert!(Instant::now() < deadline, "frames did not load: {:?}", page.frame_urls());
        page.settle(20).await;
    }
}

async fn worker_identity(page: &mut Page) -> serde_json::Value {
    page.evaluate(
        r#"(() => {
          globalThis.__fpWorker = null;
          const source = 'onmessage = () => postMessage(JSON.stringify([navigator.hardwareConcurrency, navigator.deviceMemory, navigator.userAgent]));';
          const worker = new Worker(URL.createObjectURL(new Blob([source], { type: 'text/javascript' })));
          worker.onmessage = event => { globalThis.__fpWorker = event.data; };
          worker.postMessage(1);
          return true;
        })()"#,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let serde_json::Value::String(json) = page.evaluate("globalThis.__fpWorker") {
            return serde_json::from_str(&json).unwrap();
        }
        assert!(Instant::now() < deadline, "worker did not answer");
        page.settle(20).await;
    }
}

async fn check_profile_stability(stealth: bool) {
    let cross_origin = Server::new(Vec::new());
    let server = Server::new(vec![
        "/frame".to_string(),
        // Another port is another origin.
        format!("{}/frame", cross_origin.base),
    ]);
    let profile = context(stealth, None);
    let mut page = open(&profile, &format!("{}/top?visit=1", server.base)).await;
    let first = page.evaluate(IDENTITY);
    assert!(first.is_object(), "identity probe failed: {first}");
    let first_heap = page.evaluate("performance.memory.totalJSHeapSize");

    // Same-origin and cross-origin frame realms report the top document's values.
    wait_for_frames(&mut page, 2).await;
    for index in 0..2 {
        let frame = page.evaluate_in_frame(index, IDENTITY).unwrap();
        assert_eq!(frame, first, "frame {index} ({}) differs", page.frame_urls()[index]);
    }

    // So does a dedicated worker.
    let worker = worker_identity(&mut page).await;
    assert_eq!(
        worker,
        serde_json::json!([first["hardwareConcurrency"], first["deviceMemory"], first["userAgent"]])
    );

    // A second navigation, a reload and a second tab keep the profile's values.
    let mut heaps = vec![first_heap];
    page.navigate(&format!("{}/top?visit=2", server.base)).await.unwrap();
    assert_eq!(page.evaluate(IDENTITY), first, "second navigation");
    heaps.push(page.evaluate("performance.memory.totalJSHeapSize"));
    page.navigate(&format!("{}/top?visit=2", server.base)).await.unwrap();
    assert_eq!(page.evaluate(IDENTITY), first, "reload");
    heaps.push(page.evaluate("performance.memory.totalJSHeapSize"));
    let mut tab = open(&profile, &format!("{}/top?tab=2", server.base)).await;
    assert_eq!(tab.evaluate(IDENTITY), first, "second tab");

    // Per-navigation values still vary from document to document.
    assert!(
        heaps.iter().any(|heap| heap != &heaps[0]),
        "per-document heap values stopped varying: {heaps:?}"
    );

    // A new profile draws independent values from the same pools.
    let other = context(stealth, None);
    let mut other_page = open(&other, &format!("{}/top?other=1", server.base)).await;
    let other_identity = other_page.evaluate(IDENTITY);
    assert_ne!(other.fingerprint_seed, profile.fingerprint_seed);
    assert_ne!(other_identity, first, "two profiles reported identical fingerprints");
    for (key, pool) in [("hardwareConcurrency", if stealth { vec![4, 6, 8, 12, 16] } else { vec![2, 4, 6, 8, 12, 16] })] {
        for identity in [&first, &other_identity] {
            let value = identity[key].as_i64().unwrap();
            assert!(pool.contains(&value), "{key} {value} outside its pool");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fingerprint_is_stable_within_a_profile() {
    check_profile_stability(false).await;
}

#[cfg(feature = "stealth")]
#[tokio::test(flavor = "current_thread")]
async fn stealth_fingerprint_is_stable_within_a_profile() {
    check_profile_stability(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_seed_reproduces_a_profile() {
    let server = Server::new(Vec::new());
    let url = format!("{}/top", server.base);
    let stealth = cfg!(feature = "stealth");
    let first = open(&context(stealth, Some(0x5eed)), &url).await.evaluate(IDENTITY);
    let restarted = open(&context(stealth, Some(0x5eed)), &url).await.evaluate(IDENTITY);
    let different = open(&context(stealth, Some(0x5eee)), &url).await.evaluate(IDENTITY);
    assert_eq!(first, restarted);
    assert_ne!(first, different);
}
