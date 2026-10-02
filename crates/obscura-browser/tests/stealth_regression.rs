//! Stealth regression suite: the detection techniques of FingerprintJS and
//! CreepJS, reproduced without their sources, so a change that breaks stealth
//! fails in CI. Every test runs with the `stealth` feature and runtime stealth
//! on (non-stealth controls are marked).
//!
//! What each test guards:
//! - `fpjs_inputs_*`: the inputs FingerprintJS hashes (canvas text and
//!   geometry, offline audio, screen, CPU and memory, platform, languages,
//!   timezone, plugins, media queries, math, fonts, WebGL basics) are identical
//!   on a second navigation, a reload, a second tab, same- and cross-origin
//!   frames and (for the worker-visible subset) a worker, and differ between
//!   two profiles. A visitor id that changes per visit, or two profiles that
//!   share one, is the regression.
//! - `canvas_*`: CreepJS's canvas lie checks: getImageData vs toDataURL,
//!   draw-twice equality, its random solid-pixel round trip, blank canvases,
//!   OffscreenCanvas parity, and stealth variance per profile only.
//! - `api_surface_*`: CreepJS's prototype lie detector (`queryLies`) swept
//!   over every member it searches, in the page and in a frame realm:
//!   native-code strings (also of `toString` itself), no `prototype`, `new`
//!   and `class extends` throw, own keys `length,name`, getters reject the
//!   prototype, Proxy/recursion/descriptor traps, the `instanceof` and
//!   `Object.create(fn).toString()` stack shapes, cross-realm toString, no own
//!   properties on navigator/screen and its stealth flags (hasIframeProxy,
//!   hasHighChromeIndex, hasBadChromeRuntime).
//! - `error_stacks_*`: V8's frame format and `Error.prepareStackTrace`.
//! - `identity_*`: the HTTP User-Agent and Sec-CH-UA headers, navigator.userAgent,
//!   userAgentData brands/fullVersionList and the worker agree, and no
//!   `__obscura` name appears on any reflection surface.
//! - `audio_and_media_*`: silence where Chrome is silent, and media queries
//!   consistent with screen and devicePixelRatio.
//! - `frames_report_the_top_document_screen_*`: same- and cross-origin frames
//!   report the top document's screen, both the profile's randomized one and
//!   a CDP device-metrics override (screen and devicePixelRatio), including
//!   one applied or cleared live.
//! - `worker_global_scopes_*`: dedicated, nested and shared workers have no
//!   window-only globals (`window`, `document`, `screen`, `devicePixelRatio`,
//!   storage, DOM interfaces) by `typeof` or `in self`, keep the globals a
//!   worker has, and report the page's navigator identity.
//! - `worker_navigator_location_import_scripts_*`: workers have Chrome's
//!   WorkerNavigator (worker member set, page identity) and WorkerLocation,
//!   importScripts loads and runs scripts synchronously with Chrome's errors
//!   and makes their declarations worker globals, a bare window-only name
//!   throws a ReferenceError, and the global object lists the worker's globals.
//! - `outer_size_follows_chrome_*`: outerWidth/outerHeight under desktop and
//!   mobile CDP device emulation, live, after navigation and in frames.
//! - `page_navigator_has_chrome_members_*`: the page navigator has Chrome's
//!   appCodeName, appName, vendorSub, hid, serial, usb and storageBuckets as
//!   native prototype getters with Chrome's values, in the page, a frame and a
//!   dedicated worker (shared workers lack hid, serial and usb), and the window
//!   position is a maximized Windows window's, 0/0, in frames and under device
//!   emulation.
//! - `content_window_*`: a same-origin, about:blank or srcdoc frame read through
//!   `contentWindow` reports the browser window's outer size, position and
//!   devicePixelRatio and its iframe box as inner size; a cross-origin one
//!   exposes only Chrome's cross-origin WindowProxy surface and throws
//!   SecurityError otherwise; postMessage looks native everywhere.
//! - `post_message_*`: postMessage between a page and its same- and
//!   cross-origin frames, both ways, with Chrome's structured clone,
//!   targetOrigin rules, MessageEvent fields and asynchronous delivery,
//!   including replies awaited inside a CDP evaluation.
//! - `real_libraries_*` (ignored, opt-in, needs network): downloads pinned
//!   FingerprintJS and CreepJS builds (sha256-checked, never committed) and
//!   applies the same gates to the real libraries.

#![cfg(feature = "stealth")]

use obscura_browser::{BrowserContext, Page};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Fixture: a loopback server with a page that embeds a same-origin frame (and,
// optionally, a cross-origin one), recording every request's headers.

type Routes = Arc<HashMap<String, (&'static str, Vec<u8>)>>;

struct Server {
    base: String,
    requests: Arc<Mutex<Vec<(String, HashMap<String, String>)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn with_routes(cross_origin_frame: Option<&str>, routes: Routes) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stopped, log) = (stop.clone(), requests.clone());
        let cross = cross_origin_frame
            .map(|origin| format!("<iframe src=\"{origin}/frame\"></iframe>"))
            .unwrap_or_default();
        let page = format!(
            "<!doctype html><html><head><script src=\"/app.js\"></script></head>\
             <body>page<iframe src=\"/frame\"></iframe>{cross}</body></html>"
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
                let head = String::from_utf8_lossy(&data).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let headers = head
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.split_once(':'))
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                log.lock().unwrap().push((path.clone(), headers));
                let route = path.split('?').next().unwrap_or("/");
                let (kind, body): (&str, Vec<u8>) = if let Some((kind, body)) = routes.get(route) {
                    (kind, body.clone())
                } else if route == "/app.js" {
                    ("text/javascript", b"globalThis.__appScript = 1;".to_vec())
                } else if route == "/frame" {
                    ("text/html", b"<!doctype html><html><body>frame</body></html>".to_vec())
                } else {
                    ("text/html", page.clone().into_bytes())
                };
                // Versioned modules are cacheable, like a CDN build.
                let caching = if route.ends_with(".mjs") { "Cache-Control: public, max-age=600\r\nETag: \"m1\"\r\n" } else { "" };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nAccess-Control-Allow-Origin: *\r\n{caching}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            }
        });
        Self { base, requests, stop, thread: Some(thread) }
    }

    fn new() -> Self {
        Self::with_routes(None, Arc::new(HashMap::new()))
    }

    fn headers_for(&self, path: &str) -> Option<HashMap<String, String>> {
        self.requests.lock().unwrap().iter().find(|(p, _)| p.starts_with(path)).map(|(_, h)| h.clone())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.thread.take().unwrap().join();
    }
}

fn context(stealth: bool, seed: u32) -> Arc<BrowserContext> {
    Arc::new(
        BrowserContext::with_storage_and_network("default".into(), None, stealth, None, None, true)
            .with_fingerprint_seed(seed),
    )
}

async fn open(context: &Arc<BrowserContext>, url: &str) -> Page {
    let mut page = Page::new("regression-page".into(), context.clone());
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

/// Evaluate `expression`, which must assign its (possibly asynchronous)
/// result to `globalThis.__result`, and wait for it.
async fn evaluate_async(page: &mut Page, expression: &str) -> Value {
    page.evaluate("globalThis.__result = undefined");
    page.evaluate(expression);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let value = page.evaluate("globalThis.__result === undefined ? null : JSON.stringify(globalThis.__result)");
        if let Value::String(json) = value {
            return serde_json::from_str(&json).unwrap();
        }
        assert!(Instant::now() < deadline, "asynchronous probe did not finish");
        page.settle(20).await;
    }
}

// ---------------------------------------------------------------------------
// FingerprintJS inputs.

/// The synchronous inputs FingerprintJS 4 hashes, collected the way it does.
const FPJS_INPUTS: &str = r#"(() => {
  const canvasText = () => {
    const c = document.createElement('canvas'); c.width = 240; c.height = 60; const x = c.getContext('2d');
    x.textBaseline = 'alphabetic'; x.fillStyle = '#f60'; x.fillRect(100, 1, 62, 20);
    x.fillStyle = '#069'; x.font = '11pt "Times New Roman"';
    const text = `Cwm fjordbank gly ${String.fromCharCode(55357, 56835)}`;
    x.fillText(text, 2, 15); x.fillStyle = 'rgba(102, 204, 0, 0.2)'; x.font = '18pt Arial'; x.fillText(text, 4, 45);
    return c.toDataURL();
  };
  const canvasGeometry = () => {
    const c = document.createElement('canvas'); c.width = 122; c.height = 110; const x = c.getContext('2d');
    x.globalCompositeOperation = 'multiply';
    for (const [color, cx, cy] of [['#f2f', 40, 40], ['#2ff', 80, 40], ['#ff2', 60, 80]]) {
      x.fillStyle = color; x.beginPath(); x.arc(cx, cy, 40, 0, Math.PI * 2, true); x.closePath(); x.fill();
    }
    x.fillStyle = '#f9c'; x.arc(60, 60, 60, 0, Math.PI * 2, true); x.arc(60, 60, 20, 0, Math.PI * 2, true); x.fill('evenodd');
    return c.toDataURL();
  };
  const hash = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619); return h >>> 0; };
  const text = canvasText(), geometry = canvasGeometry();
  const media = (q) => matchMedia(q).matches;
  const f = new Float32Array(1), u8 = new Uint8Array(f.buffer); f[0] = Infinity; f[0] = f[0] - f[0];
  const fonts = (() => {
    const base = (family) => { const s = document.createElement('span'); s.style.fontFamily = family; s.style.fontSize = '48px'; s.textContent = 'mmMwWLliI0fiflO&1'; document.body.appendChild(s); const w = s.offsetWidth; s.remove(); return w; };
    const mono = base('monospace');
    return ['Arial', 'Calibri', 'Segoe UI', 'Helvetica Neue', 'Ubuntu', 'Consolas'].filter((name) => base(`'${name}', monospace`) !== mono);
  })();
  let webgl = null;
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    if (gl) {
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      webgl = { version: gl.getParameter(gl.VERSION), vendor: gl.getParameter(gl.VENDOR), renderer: gl.getParameter(gl.RENDERER),
        unmasked: ext ? [gl.getParameter(ext.UNMASKED_VENDOR_WEBGL), gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)] : null,
        maxTexture: gl.getParameter(gl.MAX_TEXTURE_SIZE), extensions: (gl.getSupportedExtensions() || []).length };
    }
  } catch (e) { webgl = String(e); }
  return {
    canvas: { text: hash(text), geometry: hash(geometry), stable: text === canvasText() && geometry === canvasGeometry(),
      winding: (() => { const x = document.createElement('canvas').getContext('2d'); x.rect(0, 0, 10, 10); x.rect(2, 2, 6, 6); return x.isPointInPath(5, 5, 'evenodd') === false; })() },
    screen: [screen.width, screen.height], screenFrame: [screen.availTop, screen.availLeft, screen.height - screen.availHeight - screen.availTop, screen.width - screen.availWidth - screen.availLeft],
    colorDepth: screen.colorDepth, hardwareConcurrency: navigator.hardwareConcurrency, deviceMemory: navigator.deviceMemory,
    platform: navigator.platform, vendor: navigator.vendor, languages: navigator.languages, userAgent: navigator.userAgent,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, timezoneOffset: new Date(2026, 0, 1).getTimezoneOffset(),
    cookiesEnabled: navigator.cookieEnabled, touch: [navigator.maxTouchPoints, 'ontouchstart' in window], pdfViewerEnabled: navigator.pdfViewerEnabled,
    plugins: Array.from(navigator.plugins, (p) => [p.name, p.description, Array.from(p, (m) => m.type)]),
    vendorFlavors: ['chrome', 'safari', '__crWeb'].filter((k) => k in window),
    media: [media('(color-gamut: srgb)'), media('(prefers-contrast: no-preference)'), media('(prefers-reduced-motion: reduce)'), media('(dynamic-range: high)'), media('(inverted-colors: inverted)')],
    math: [Math.acos(0.123124234234234242), Math.acosh(1e308), Math.asinh(1), Math.atanh(0.5), Math.expm1(1), Math.sinh(1), Math.tanh(1), Math.cbrt(100)],
    architecture: u8[3], fonts, webgl,
  };
})()"#;

/// FingerprintJS's offline audio input: the sum of a compressed 10 kHz
/// triangle wave, assigned to `__result`.
const FPJS_AUDIO: &str = r#"(() => {
  const ctx = new OfflineAudioContext(1, 5000, 44100), osc = ctx.createOscillator(), comp = ctx.createDynamicsCompressor();
  osc.type = 'triangle'; osc.frequency.value = 10000;
  comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12; comp.attack.value = 0; comp.release.value = 0.25;
  osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
  ctx.startRendering().then((buffer) => {
    const data = buffer.getChannelData(0); let sum = 0;
    for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
    globalThis.__result = sum;
  });
})()"#;

async fn worker_inputs(page: &mut Page) -> Value {
    evaluate_async(
        page,
        r#"(() => {
          const source = 'onmessage = () => postMessage(JSON.stringify([navigator.hardwareConcurrency, navigator.deviceMemory, navigator.userAgent, navigator.platform, navigator.languages, Intl.DateTimeFormat().resolvedOptions().timeZone]));';
          const worker = new Worker(URL.createObjectURL(new Blob([source], { type: 'text/javascript' })));
          worker.onmessage = (event) => { globalThis.__result = JSON.parse(event.data); };
          worker.postMessage(1);
        })()"#,
    )
    .await
}

async fn page_inputs(page: &mut Page) -> Value {
    let mut inputs = page.evaluate(FPJS_INPUTS);
    assert!(inputs.is_object(), "FingerprintJS input probe failed: {inputs}");
    inputs["audio"] = evaluate_async(page, FPJS_AUDIO).await;
    inputs
}

#[tokio::test(flavor = "current_thread")]
async fn fpjs_inputs_are_stable_within_a_profile_and_differ_between_profiles() {
    let other_origin = Server::new();
    let server = Server::with_routes(Some(&other_origin.base), Arc::new(HashMap::new()));
    let profile = context(true, 0x1234_5678);
    let url = format!("{}/page?visit=1", server.base);
    let mut page = open(&profile, &url).await;
    let first = page_inputs(&mut page).await;
    assert_eq!(first["canvas"]["stable"], true, "FingerprintJS treats a canvas that renders twice differently as unstable");
    assert_eq!(first["canvas"]["winding"], true);

    // Frames (same- and cross-origin) report the synchronous inputs identically.
    // Known gap (inherited): frame documents have no layout, so the
    // offsetWidth-based font probe finds no fonts there; it is compared across
    // navigations, tabs and profiles in the top document only.
    wait_for_frames(&mut page, 2).await;
    let mut sync_first = first.clone();
    sync_first.as_object_mut().unwrap().remove("audio");
    sync_first.as_object_mut().unwrap().remove("fonts");
    for index in 0..2 {
        let mut frame = page.evaluate_in_frame(index, FPJS_INPUTS).unwrap();
        frame.as_object_mut().unwrap().remove("fonts");
        assert_eq!(frame, sync_first, "frame {} differs", page.frame_urls()[index]);
    }
    // The worker sees the same identity.
    let worker = worker_inputs(&mut page).await;
    assert_eq!(worker, json!([first["hardwareConcurrency"], first["deviceMemory"], first["userAgent"], first["platform"], first["languages"], first["timezone"]]));

    // Second navigation, reload, second tab.
    page.navigate(&format!("{}/page?visit=2", server.base)).await.unwrap();
    assert_eq!(page_inputs(&mut page).await, first, "second navigation");
    page.navigate(&format!("{}/page?visit=2", server.base)).await.unwrap();
    assert_eq!(page_inputs(&mut page).await, first, "reload");
    let mut tab = open(&profile, &format!("{}/page?tab=2", server.base)).await;
    assert_eq!(page_inputs(&mut tab).await, first, "second tab");

    // Another profile differs in the rendered and device inputs.
    let mut other = open(&context(true, 0x0bad_cafe), &url).await;
    let second = page_inputs(&mut other).await;
    assert_ne!(second["canvas"]["text"], first["canvas"]["text"]);
    assert_ne!(second["canvas"]["geometry"], first["canvas"]["geometry"]);
    assert_ne!(second["audio"], first["audio"]);
    assert_ne!(second, first);
}

// ---------------------------------------------------------------------------
// Canvas.

/// A canvas scene with text, a gradient-filled arc and a stroked path, read
/// back in every way a fingerprinting script does.
const SCENE: &str = r#"(() => {
  const draw = (ctx) => {
    ctx.font = '14px Arial'; ctx.fillStyle = '#f60'; ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069'; ctx.fillText('Cwm fjordbank glyphs vext quiz', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)'; ctx.fillText('Cwm fjordbank glyphs vext quiz', 4, 17);
    const g = ctx.createLinearGradient(0, 0, 200, 0); g.addColorStop(0, '#f2f'); g.addColorStop(1, '#2ff');
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(60, 60, 25, 0, Math.PI * 2, true); ctx.closePath(); ctx.fill();
    ctx.strokeStyle = 'hsl(200, 50%, 40%)'; ctx.beginPath(); ctx.moveTo(10, 90); ctx.lineTo(190, 70); ctx.stroke();
  };
  const canvas = (w, h) => { const c = document.createElement('canvas'); c.width = w; c.height = h; return c; };
  const a = canvas(200, 100), b = canvas(200, 100), ca = a.getContext('2d'), cb = b.getContext('2d');
  draw(ca); draw(cb);
  const url = a.toDataURL(), image = ca.getImageData(0, 0, 200, 100).data;
  const copy = canvas(200, 100); copy.getContext('2d').putImageData(ca.getImageData(0, 0, 200, 100), 0, 0);
  let offscreen = null;
  if (typeof OffscreenCanvas === 'function') {
    const o = new OffscreenCanvas(200, 100), co = o.getContext('2d'); draw(co);
    const od = co.getImageData(0, 0, 200, 100).data;
    offscreen = od.length === image.length && od.every((v, i) => v === image[i]);
  }
  // Geometry only (no text): independent of the profile's glyph outlines.
  const shape = canvas(100, 100), cs = shape.getContext('2d');
  const g = cs.createRadialGradient(50, 50, 5, 50, 50, 50); g.addColorStop(0, '#123456'); g.addColorStop(1, '#fedcba');
  cs.fillStyle = g; cs.beginPath(); cs.arc(50, 50, 40, 0, Math.PI * 2); cs.fill();
  // Exact operations: blank canvases, cleared canvases and CreepJS's random
  // solid-pixel round trip (getPixelMods).
  const blank = canvas(64, 32), fresh = canvas(64, 32), bx = blank.getContext('2d');
  const untouched = fresh.toDataURL();
  bx.fillText('x', 4, 10); bx.clearRect(0, 0, 64, 32);
  const k1 = canvas(8, 8).getContext('2d', { willReadFrequently: true }), k2 = canvas(8, 8).getContext('2d', { willReadFrequently: true });
  let pixelDiffs = 0;
  for (let x = 0; x < 8; x++) for (let y = 0; y < 8; y++) {
    const c = [~~(Math.random() * 256), ~~(Math.random() * 256), ~~(Math.random() * 256)];
    k1.fillStyle = `rgba(${c[0]}, ${c[1]}, ${c[2]}, 255)`; k1.fillRect(x, y, 1, 1);
    const p = k1.getImageData(x, y, 1, 1).data;
    if (p[0] !== c[0] || p[1] !== c[1] || p[2] !== c[2] || p[3] !== 255) pixelDiffs++;
    k2.fillStyle = `rgba(${p[0]}, ${p[1]}, ${p[2]}, ${p[3]})`; k2.fillRect(x, y, 1, 1);
    const q = k2.getImageData(x, y, 1, 1).data;
    if (q.some((v, i) => v !== p[i])) pixelDiffs++;
  }
  let hash = 2166136261;
  for (let i = 0; i < url.length; i++) hash = Math.imul(hash ^ url.charCodeAt(i), 16777619);
  let shapeHash = 2166136261;
  const shapeData = cs.getImageData(0, 0, 100, 100).data;
  for (let i = 0; i < shapeData.length; i++) shapeHash = Math.imul(shapeHash ^ shapeData[i], 16777619);
  const measure = canvas(10, 10).getContext('2d'); measure.font = '16px Arial';
  return {
    hash: hash >>> 0, shape: shapeHash >>> 0,
    repeatEqual: url === a.toDataURL() && image.every((v, i) => v === ca.getImageData(0, 0, 200, 100).data[i]),
    redrawEqual: url === b.toDataURL(),
    exportMatchesImageData: copy.toDataURL() === url,
    blankExact: blank.toDataURL() === untouched && !bx.getImageData(0, 0, 64, 32).data.some((v) => v),
    offscreen,
    pixelDiffs,
    width: measure.measureText('Cwm fjordbank glyphs').width,
    emptyWidth: measure.measureText('').width,
  };
})()"#;

async fn scene(stealth: bool, seed: u32, server: &Server) -> Value {
    let mut page = open(&context(stealth, seed), &format!("{}/page", server.base)).await;
    let value = page.evaluate(SCENE);
    assert!(value.is_object(), "scene failed: {value}");
    value
}

#[tokio::test(flavor = "current_thread")]
async fn canvas_variance_is_stable_per_profile_and_exact_where_chrome_is() {
    let server = Server::new();
    let a = scene(true, 0xa11ce, &server).await;
    let a_again = scene(true, 0xa11ce, &server).await;
    let b = scene(true, 0xb0b, &server).await;
    for value in [&a, &b] {
        assert_eq!(value["repeatEqual"], true, "{value}");
        assert_eq!(value["redrawEqual"], true, "{value}");
        assert_eq!(value["exportMatchesImageData"], true, "{value}");
        assert_eq!(value["blankExact"], true, "{value}");
        assert_eq!(value["pixelDiffs"], 0, "{value}");
        assert_eq!(value["emptyWidth"], 0, "{value}");
        assert!(value["offscreen"].is_null() || value["offscreen"] == true, "OffscreenCanvas parity: {value}");
    }
    assert_eq!(a, a_again, "a profile reproduces its own rendering");
    assert_ne!(a["hash"], b["hash"], "profiles render text differently");
    assert_ne!(a["shape"], b["shape"], "profiles rasterize gradients and curves differently");
    // Text advance widths stay within 0.3% of the unscaled width (240 px).
    for value in [&a, &b] {
        let width = value["width"].as_f64().unwrap();
        assert!((width - 240.0).abs() <= 240.0 * 0.003 + 1.0 / 64.0, "{width}");
        assert_eq!((width * 64.0).fract(), 0.0, "{width}");
    }
    // In a frame of the same profile the variance is identical.
    let mut page = open(&context(true, 0xa11ce), &format!("{}/page", server.base)).await;
    wait_for_frames(&mut page, 1).await;
    assert_eq!(page.evaluate_in_frame(0, SCENE).unwrap(), a);
}

#[tokio::test(flavor = "current_thread")]
async fn canvas_without_runtime_stealth_has_no_variance() {
    let server = Server::new();
    let a = scene(false, 0xa11ce, &server).await;
    let b = scene(false, 0xb0b, &server).await;
    assert_eq!(a["shape"], b["shape"], "no rendering variance outside stealth mode");
    assert_eq!(a["width"], 240.0);
    assert_eq!(a["pixelDiffs"], 0);
    assert_eq!(a["blankExact"], true);
}

// ---------------------------------------------------------------------------
// API surface: CreepJS's prototype lie detector.

/// `searchLies` over CreepJS's interface list (with its target lists) and the
/// complete `queryLies` check set, including the proxy checks it only enables
/// once it suspects `Function.prototype.toString`. Returns the lies found.
const LIE_SWEEP: &str = r#"(() => {
  const AT_FUNCTION = /at Function\.toString /, AT_OBJECT = /at Object\.toString/;
  const FUNCTION_INSTANCE = /at (Function\.)?\[Symbol.hasInstance\]/, PROXY_INSTANCE = /at (Proxy\.)?\[Symbol.hasInstance\]/;
  const isTypeError = (e) => e && e.constructor && e.constructor.name === 'TypeError';
  const failsTypeError = (spawn, withStack, final) => {
    try { spawn(); throw Error(); } catch (e) { return !isTypeError(e) || (withStack ? withStack(e) : false); } finally { final && final(); }
  };
  const failsWithError = (fn) => { try { fn(); return false; } catch (e) { return true; } };
  const line = (e, i = 1) => String(e.stack).split('\n')[i] || '';
  const known = (name) => new Set([`function ${name}() { [native code] }`, `function get ${name}() { [native code] }`, 'function () { [native code] }',
    `function ${name}() {\n    [native code]\n}`, `function get ${name}() {\n    [native code]\n}`, 'function () {\n    [native code]\n}']);
  const RAND = 'r' + Math.random().toString(36).slice(-7);
  const query = (apiFunction, proto, obj) => {
    const name = apiFunction.name.replace(/get\s/, ''), objName = obj && obj.name, nativeProto = Object.getPrototypeOf(apiFunction);
    const restore = () => Object.setPrototypeOf(apiFunction, nativeProto);
    const lies = {
      'illegal error': !!obj && failsTypeError(() => obj.prototype[name]),
      'undefined properties': !!obj && /^(screen|navigator)$/i.test(objName) && !!Object.getOwnPropertyDescriptor(self[objName.toLowerCase()], name),
      'call interface': failsTypeError(() => { new apiFunction(); apiFunction.call(proto); }),
      'apply interface': failsTypeError(() => { new apiFunction(); apiFunction.apply(proto); }),
      'new instance': failsTypeError(() => new apiFunction()),
      'class extends': failsTypeError(() => { class Fake extends apiFunction {} }),
      'null conversion': failsTypeError(() => Object.setPrototypeOf(apiFunction, null).toString(), null, restore),
      'toString': !known(name).has(Function.prototype.toString.call(apiFunction)) || !known('toString').has(Function.prototype.toString.call(apiFunction.toString)),
      'prototype in function': 'prototype' in apiFunction,
      'descriptor': ['arguments', 'caller', 'prototype', 'toString'].some((k) => Object.getOwnPropertyDescriptor(apiFunction, k)),
      'own property': ['arguments', 'caller', 'prototype', 'toString'].some((k) => apiFunction.hasOwnProperty(k)),
      'descriptor keys': Object.keys(Object.getOwnPropertyDescriptors(apiFunction)).sort().toString() !== 'length,name',
      'own property names': Object.getOwnPropertyNames(apiFunction).sort().toString() !== 'length,name',
      'own keys names': Reflect.ownKeys(apiFunction).sort().toString() !== 'length,name',
      'object toString': failsTypeError(() => Object.create(apiFunction).toString(), (e) => !AT_FUNCTION.test(line(e)))
        || failsTypeError(() => Object.create(new Proxy(apiFunction, {})).toString(), (e) => !AT_OBJECT.test(line(e))),
      'too much recursion': failsTypeError(() => Object.setPrototypeOf(apiFunction, Object.create(apiFunction)).toString(), null, restore),
      // Advanced proxy detection.
      'chain cycle': (() => { const p = new Proxy(apiFunction, {}); return !failsTypeError(() => Object.setPrototypeOf(p, Object.create(p)).toString(), null, () => Object.setPrototypeOf(p, nativeProto)); })(),
      'reflect set proto': failsTypeError(() => { Reflect.setPrototypeOf(apiFunction, Object.create(apiFunction)); RAND in apiFunction; throw new TypeError(); }, null, restore),
      'reflect set proto proxy': (() => { const p = new Proxy(apiFunction, {}); return !failsTypeError(() => { Reflect.setPrototypeOf(p, Object.create(p)); RAND in p; }, null, () => Object.setPrototypeOf(p, nativeProto)); })(),
      'instanceof check': failsTypeError(() => apiFunction instanceof apiFunction, (e) => !FUNCTION_INSTANCE.test(line(e)))
        || failsTypeError(() => { const p = new Proxy(apiFunction, {}); p instanceof p; }, (e) => !PROXY_INSTANCE.test(line(e))),
      'define properties': failsWithError(() => { Object.defineProperty(apiFunction, '', { configurable: true }).toString(); Reflect.deleteProperty(apiFunction, ''); }),
    };
    return Object.keys(lies).filter((k) => lies[k]);
  };
  const props = {};
  const search = (get, config = {}) => {
    let obj; try { obj = get(); } catch (e) { return; }
    if (!obj) return;
    const iface = obj.prototype ? obj.prototype : obj;
    const names = [...new Set([...Object.getOwnPropertyNames(iface), ...Object.keys(iface)])].sort();
    for (const name of names) {
      if (name === 'constructor' || (config.target && !config.target.includes(name)) || (config.ignore && config.ignore.includes(name))) continue;
      const label = `${obj.name || (/\s(.+)\]/.exec(String(obj)) || [])[1]}.${name}`;
      try {
        const proto = obj.prototype ? obj.prototype : obj;
        try {
          const apiFunction = proto[name];
          if (typeof apiFunction === 'function') {
            const lies = query(apiFunction, proto, null);
            if (lies.length) props[label] = lies;
            continue;
          }
          if (name !== 'name' && name !== 'length' && name[0] !== name[0].toUpperCase()) { props[label] = ['descriptor.value undefined']; continue; }
        } catch (e) {}
        const getter = Object.getOwnPropertyDescriptor(proto, name).get;
        if (typeof getter === 'function') {
          const lies = query(getter, proto, obj);
          if (lies.length) props[label] = lies;
        }
      } catch (e) { props[label] = ['prototype test execution']; }
    }
  };
  search(() => Function, { target: ['toString'] });
  search(() => AnalyserNode); search(() => AudioBuffer, { target: ['copyFromChannel', 'getChannelData'] });
  search(() => BiquadFilterNode, { target: ['getFrequencyResponse'] });
  search(() => CanvasRenderingContext2D, { target: ['getImageData', 'getLineDash', 'isPointInPath', 'isPointInStroke', 'measureText', 'quadraticCurveTo', 'fillText', 'strokeText', 'font'] });
  search(() => CSSStyleDeclaration, { target: ['setProperty'] });
  search(() => Date, { target: ['getDate', 'getDay', 'getFullYear', 'getHours', 'getMinutes', 'getMonth', 'getTime', 'getTimezoneOffset', 'setDate', 'setFullYear', 'setHours', 'setMilliseconds', 'setMonth', 'setSeconds', 'setTime', 'toDateString', 'toJSON', 'toLocaleDateString', 'toLocaleString', 'toLocaleTimeString', 'toString', 'toTimeString', 'valueOf'] });
  search(() => Intl.DateTimeFormat, { target: ['format', 'formatRange', 'formatToParts', 'resolvedOptions'] });
  search(() => Document, { target: ['createElement', 'createElementNS', 'getElementById', 'getElementsByClassName', 'getElementsByName', 'getElementsByTagName', 'getElementsByTagNameNS', 'referrer', 'write', 'writeln'], ignore: ['onreadystatechange', 'onmouseenter', 'onmouseleave'] });
  search(() => DOMRect); search(() => DOMRectReadOnly);
  search(() => Element, { target: ['append', 'appendChild', 'getBoundingClientRect', 'getClientRects', 'insertAdjacentElement', 'insertAdjacentHTML', 'insertAdjacentText', 'insertBefore', 'prepend', 'replaceChild', 'replaceWith', 'setAttribute'] });
  search(() => FontFace, { target: ['family', 'load', 'status'] });
  search(() => HTMLCanvasElement);
  search(() => HTMLElement, { target: ['clientHeight', 'clientWidth', 'offsetHeight', 'offsetWidth', 'scrollHeight', 'scrollWidth'], ignore: ['onmouseenter', 'onmouseleave'] });
  search(() => HTMLIFrameElement, { target: ['contentDocument', 'contentWindow'] });
  search(() => IntersectionObserverEntry, { target: ['boundingClientRect', 'intersectionRect', 'rootBounds'] });
  search(() => Math, { target: ['acos', 'acosh', 'asinh', 'atan', 'atan2', 'atanh', 'cbrt', 'cos', 'cosh', 'exp', 'expm1', 'log', 'log10', 'log1p', 'sin', 'sinh', 'sqrt', 'tan', 'tanh'] });
  search(() => MediaDevices, { target: ['enumerateDevices', 'getDisplayMedia', 'getUserMedia'] });
  search(() => Navigator, { target: ['appCodeName', 'appName', 'appVersion', 'buildID', 'connection', 'deviceMemory', 'getBattery', 'getGamepads', 'getVRDisplays', 'hardwareConcurrency', 'language', 'languages', 'maxTouchPoints', 'mimeTypes', 'oscpu', 'platform', 'plugins', 'product', 'productSub', 'sendBeacon', 'serviceWorker', 'storage', 'userAgent', 'vendor', 'vendorSub', 'webdriver', 'gpu'] });
  search(() => Node, { target: ['appendChild', 'insertBefore', 'replaceChild'] });
  search(() => OffscreenCanvas, { target: ['convertToBlob', 'getContext'] });
  search(() => OffscreenCanvasRenderingContext2D, { target: ['getImageData', 'getLineDash', 'isPointInPath', 'isPointInStroke', 'measureText', 'quadraticCurveTo', 'font'] });
  search(() => Permissions, { target: ['query'] });
  search(() => Range, { target: ['getBoundingClientRect', 'getClientRects'] });
  search(() => Intl.RelativeTimeFormat, { target: ['resolvedOptions'] });
  search(() => Screen); search(() => speechSynthesis, { target: ['getVoices'] });
  search(() => String, { target: ['fromCodePoint'] }); search(() => StorageManager, { target: ['estimate'] });
  search(() => SVGRect); search(() => SVGRectElement, { target: ['getBBox'] });
  search(() => SVGTextContentElement, { target: ['getExtentOfChar', 'getSubStringLength', 'getComputedTextLength'] });
  search(() => TextMetrics);
  search(() => WebGLRenderingContext, { target: ['bufferData', 'getParameter', 'readPixels'] });
  search(() => WebGL2RenderingContext, { target: ['bufferData', 'getParameter', 'readPixels'] });
  // Further interfaces fingerprinting scripts read: every member.
  for (const iface of [Plugin, PluginArray, MimeType, MimeTypeArray, SpeechSynthesis, ScreenOrientation, NetworkInformation]) search(() => iface);
  // CreepJS stealth flags.
  const stealth = {
    hasIframeProxy: (() => { try { const f = document.createElement('iframe'); f.srcdoc = RAND; return !!f.contentWindow; } catch (e) { return true; } })(),
    hasHighChromeIndex: Object.keys(window).slice(-50).includes('chrome') && Object.getOwnPropertyNames(window).slice(-50).includes('chrome'),
    hasBadChromeRuntime: (() => {
      if (!('chrome' in window && 'runtime' in chrome)) return false;
      try {
        if ('prototype' in chrome.runtime.sendMessage || 'prototype' in chrome.runtime.connect) return true;
        new chrome.runtime.sendMessage; new chrome.runtime.connect; return true;
      } catch (e) { return e.constructor.name !== 'TypeError'; }
    })(),
  };
  let stack = '', wrapped = '';
  try { null.x; } catch (e) { stack = e.stack; }
  try { HTMLCanvasElement.prototype.getContext.call({}); } catch (e) { wrapped = e.stack; }
  return {
    lies: props, stealth,
    toStringOfToString: Function.prototype.toString.call(Function.prototype.toString),
    navigatorOwn: Object.getOwnPropertyNames(navigator), screenOwn: Object.getOwnPropertyNames(screen),
    speechOwn: Object.getOwnPropertyNames(speechSynthesis), navigatorTag: Object.prototype.toString.call(navigator),
    // Automation-supplied code (this evaluation) is named <eval> in the page
    // and <anonymous> in a frame; anything else bracketed is the engine's own.
    internalFrames: [stack, wrapped].join('\n').split('\n').filter((l) => /<obscura:|ext:|<(?!eval>|eval-remote>|preload>|anonymous>)[a-z:-]+>:/.test(l)),
  };
})()"#;

fn assert_clean_surface(report: &Value, realm: &str) {
    assert_eq!(report["lies"], json!({}), "{realm}: {report}");
    assert_eq!(report["stealth"], json!({ "hasIframeProxy": false, "hasHighChromeIndex": false, "hasBadChromeRuntime": false }), "{realm}");
    assert_eq!(report["toStringOfToString"], "function toString() { [native code] }", "{realm}");
    assert_eq!(report["navigatorOwn"], json!([]), "{realm}: navigator has own properties");
    assert_eq!(report["screenOwn"], json!([]), "{realm}: screen has own properties");
    assert_eq!(report["speechOwn"], json!([]), "{realm}");
    assert_eq!(report["navigatorTag"], "[object Navigator]", "{realm}");
    assert_eq!(report["internalFrames"], json!([]), "{realm}: engine frames leak into stacks: {report}");
}

#[tokio::test(flavor = "current_thread")]
async fn api_surface_passes_creepjs_prototype_lie_detection_in_page_and_frame_realms() {
    let server = Server::new();
    let mut page = open(&context(true, 7), &format!("{}/page", server.base)).await;
    assert_clean_surface(&page.evaluate(LIE_SWEEP), "page");
    wait_for_frames(&mut page, 1).await;
    assert_clean_surface(&page.evaluate_in_frame(0, LIE_SWEEP).unwrap(), "frame");

    // Cross-realm: each realm's toString reads the other realm's members as
    // native, and the realms do not share function objects.
    let cross = page.evaluate(
        r#"(() => {
          const w = document.querySelector('iframe').contentWindow;
          const top = [HTMLCanvasElement.prototype.getContext, Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get, Function.prototype.toString];
          const frame = [w.HTMLCanvasElement.prototype.getContext, Object.getOwnPropertyDescriptor(w.Navigator.prototype, 'userAgent').get, w.Function.prototype.toString];
          return [frame.map((f) => Function.prototype.toString.call(f)), top.map((f) => w.Function.prototype.toString.call(f)),
            top.every((f, i) => f !== frame[i]), w.navigator.userAgent === navigator.userAgent,
            (() => { try { Object.getOwnPropertyDescriptor(w.Navigator.prototype, 'userAgent').get.call(navigator); return 'ok'; } catch (e) { return e.name; } })()];
        })()"#,
    );
    let native = json!(["function getContext() { [native code] }", "function get userAgent() { [native code] }", "function toString() { [native code] }"]);
    assert_eq!(cross, json!([native, native, true, true, "ok"]));

    // Navigator getters and plugins stay usable through the normalized surface.
    let navigator = page.evaluate(
        "[typeof navigator.userAgent, navigator.webdriver, navigator.plugins.length, navigator.mimeTypes.length, \
          navigator.plugins[0] instanceof Plugin, navigator.mimeTypes[0].enabledPlugin === navigator.plugins[0], \
          Object.getOwnPropertyNames(navigator.plugins).includes('Chrome PDF Viewer'), Object.keys(navigator.plugins).join(), \
          Object.values(navigator.plugins[1]).every((m) => m instanceof MimeType && navigator.mimeTypes.namedItem(m.type) === m), \
          navigator.plugins.namedItem('PDF Viewer') === navigator.plugins[0], Array.from(navigator.plugins).length]",
    );
    assert_eq!(navigator, json!(["string", false, 5, 2, true, true, true, "0,1,2,3,4", true, true, 5]));
}

#[tokio::test(flavor = "current_thread")]
async fn error_stacks_use_v8_frame_format_and_honour_prepare_stack_trace() {
    let server = Server::new();
    for stealth in [false, true] {
        let mut page = open(&context(stealth, 7), &format!("{}/page", server.base)).await;
        let report = page.evaluate(
            r#"(() => {
              const first = (f) => { try { f(); } catch (e) { return String(e.stack).split('\n')[1]; } };
              const prepared = (() => {
                Error.prepareStackTrace = (error, sites) => 'custom:' + error.message + ':' + sites.length + ':' + typeof sites[0].getFileName;
                try { return new Error('m').stack; } finally { delete Error.prepareStackTrace; }
              })();
              return [first(() => Math.acos instanceof Math.acos), first(() => Object.create(Math.acos).toString()),
                first(() => JSON.parse('{')), prepared.replace(/:\d+:/, ':n:'), typeof Error.prepareStackTrace,
                new TypeError('t').stack.split('\n')[0]];
            })()"#,
        );
        assert_eq!(
            report,
            json!([
                "    at [Symbol.hasInstance] (<anonymous>)",
                "    at Function.toString (<anonymous>)",
                "    at JSON.parse (<anonymous>)",
                "custom:m:n:function",
                "undefined",
                "TypeError: t"
            ]),
            "stealth={stealth}"
        );
    }
}

// ---------------------------------------------------------------------------
// Identity consistency.

#[tokio::test(flavor = "current_thread")]
async fn identity_http_headers_navigator_and_client_hints_agree_and_no_internal_names_are_reflected() {
    let server = Server::new();
    let mut page = open(&context(true, 11), &format!("{}/page", server.base)).await;
    let document = server.headers_for("/page").expect("document request");
    let script = server.headers_for("/app.js").expect("script request");
    let js = evaluate_async(
        &mut page,
        r#"(() => {
          const d = navigator.userAgentData;
          d.getHighEntropyValues(['fullVersionList', 'platform', 'platformVersion', 'uaFullVersion']).then((h) => {
            globalThis.__result = { ua: navigator.userAgent, appVersion: navigator.appVersion,
              secChUa: d.brands.map((b) => `"${b.brand}";v="${b.version}"`).join(', '),
              platform: `"${d.platform}"`, mobile: d.mobile ? '?1' : '?0',
              fullVersionList: h.fullVersionList, brands: d.brands, uaFullVersion: h.uaFullVersion, highPlatform: h.platform };
          });
        })()"#,
    )
    .await;
    for (label, headers) in [("document", &document), ("script", &script)] {
        assert_eq!(headers.get("user-agent").map(String::as_str), js["ua"].as_str(), "{label} User-Agent");
        assert_eq!(headers.get("sec-ch-ua").map(String::as_str), js["secChUa"].as_str(), "{label} Sec-CH-UA");
        assert_eq!(headers.get("sec-ch-ua-platform").map(String::as_str), js["platform"].as_str(), "{label} Sec-CH-UA-Platform");
        assert_eq!(headers.get("sec-ch-ua-mobile").map(String::as_str), js["mobile"].as_str(), "{label} Sec-CH-UA-Mobile");
    }
    assert_eq!(js["appVersion"].as_str().unwrap(), js["ua"].as_str().unwrap().trim_start_matches("Mozilla/"));
    let brands = js["brands"].as_array().unwrap();
    let full = js["fullVersionList"].as_array().unwrap();
    assert_eq!(brands.len(), full.len());
    for (brand, version) in brands.iter().zip(full) {
        assert_eq!(brand["brand"], version["brand"], "fullVersionList keeps the brand order");
        assert!(version["version"].as_str().unwrap().starts_with(&format!("{}.", brand["version"].as_str().unwrap())));
    }
    let major = js["ua"].as_str().unwrap().split("Chrome/").nth(1).unwrap().split('.').next().unwrap().to_string();
    assert!(js["uaFullVersion"].as_str().unwrap().starts_with(&format!("{major}.")));
    assert!(brands.iter().any(|b| b["brand"] == "Google Chrome" && b["version"] == major.as_str()));
    assert_eq!(format!("\"{}\"", js["highPlatform"].as_str().unwrap()), js["platform"].as_str().unwrap());
    // Worker identity.
    let worker = worker_inputs(&mut page).await;
    assert_eq!(worker[2], js["ua"]);

    // No engine name on any reflection surface of the global, navigator,
    // document or their prototype chains.
    let reflected = page.evaluate(
        r#"(() => {
          const found = new Set();
          const scan = (label, o) => {
            for (let p = o; p; p = Object.getPrototypeOf(p)) {
              const names = [...Object.keys(p), ...Object.getOwnPropertyNames(p), ...Reflect.ownKeys(p).map(String),
                ...Object.keys(Object.getOwnPropertyDescriptors(p))];
              for (const k in p) names.push(k);
              for (const n of names) if (/obscura/i.test(n)) found.add(`${label}:${n}`);
            }
          };
          scan('window', window); scan('navigator', navigator); scan('document', document); scan('screen', screen);
          scan('element', document.body);
          return [...found].sort();
        })()"#,
    );
    assert_eq!(reflected, json!([]), "engine names visible through reflection");
}

// ---------------------------------------------------------------------------
// Dynamic import through the stealth transport and its cache.

/// The FingerprintJS demo loads its agent with `import()` from a CDN. The
/// module is fetched through the stealth transport (and its HTTP cache) and
/// must keep working on a second navigation, when it comes from the cache.
#[tokio::test(flavor = "current_thread")]
async fn dynamic_cross_origin_module_import_works_on_repeat_visits() {
    let mut routes = HashMap::new();
    routes.insert("/agent.mjs".to_string(), ("text/javascript", b"export const load = async () => ({ get: async () => ({ visitorId: 'fixture' }) });".to_vec()));
    let cdn = Server::with_routes(None, Arc::new(routes));
    let server = Server::new();
    let mut page = open(&context(true, 21), &format!("{}/page", server.base)).await;
    let import = format!(
        "(() => {{ import('{}/agent.mjs').then((m) => m.load()).then((a) => a.get()).then((r) => {{ globalThis.__result = r.visitorId; }}, (e) => {{ globalThis.__result = 'error: ' + e; }}); }})()",
        cdn.base
    );
    assert_eq!(evaluate_async(&mut page, &import).await, "fixture");
    page.navigate(&format!("{}/page?visit=2", server.base)).await.unwrap();
    assert_eq!(evaluate_async(&mut page, &import).await, "fixture");
    let fetched = cdn.requests.lock().unwrap().iter().filter(|(path, _)| path == "/agent.mjs").count();
    assert_eq!(fetched, 1, "the second import is served from the profile's HTTP cache");
}

// ---------------------------------------------------------------------------
// Audio and media queries.

#[tokio::test(flavor = "current_thread")]
async fn audio_and_media_queries_are_consistent() {
    let server = Server::new();
    let mut page = open(&context(true, 3), &format!("{}/page", server.base)).await;
    let audio = evaluate_async(
        &mut page,
        r#"(() => {
          const silent = new OfflineAudioContext(1, 100, 44100), quiet = silent.createOscillator();
          quiet.frequency.value = 0; quiet.start(0);
          const idle = new OfflineAudioContext(1, 5000, 44100).createAnalyser();
          const bins = new Float32Array(idle.frequencyBinCount); idle.getFloatFrequencyData(bins);
          const ctx = new OfflineAudioContext(1, 5000, 44100), osc = ctx.createOscillator(), comp = ctx.createDynamicsCompressor();
          osc.type = 'triangle'; osc.frequency.value = 10000; osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
          Promise.all([silent.startRendering(), ctx.startRendering()]).then(([a, b]) => {
            const s = a.getChannelData(0), d = b.getChannelData(0);
            let sum = 0; for (let i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
            const copy = new Float32Array(100); b.copyFromChannel(copy, 0, 4500);
            globalThis.__result = [new Set(s).size === 1 && s[0] === 0, new Set(bins).size === 1 && bins[0] === -Infinity,
              d.slice(0, 265).every((v) => v === 0), d[300] !== 0, Math.abs(sum - 124.0434) < 0.01,
              copy.every((v, i) => v === d[4500 + i])];
          });
        })()"#,
    )
    .await;
    assert_eq!(audio, json!([true, true, true, true, true, true]));
    let media = page.evaluate(
        "[matchMedia(`(device-width: ${screen.width}px) and (device-height: ${screen.height}px)`).matches, \
          matchMedia(`(resolution: ${devicePixelRatio}dppx)`).matches, matchMedia('(min-resolution: 2dppx)').matches, \
          matchMedia(`(max-device-width: ${screen.width - 1}px)`).matches]",
    );
    assert_eq!(media, json!([true, true, false, false]));
}

// ---------------------------------------------------------------------------
// Screen metrics under device emulation.

/// Every screen surface a document can read, plus the media features derived
/// from it.
const SCREEN_SURFACE: &str = "[screen.width, screen.height, screen.availWidth, screen.availHeight, \
  screen.availLeft, screen.availTop, screen.colorDepth, screen.pixelDepth, screen.orientation.type, \
  outerWidth, outerHeight, devicePixelRatio, \
  matchMedia(`(device-width: ${screen.width}px) and (device-height: ${screen.height}px)`).matches]";

/// The top document's screen, and every frame's, which must be identical.
fn assert_frames_report_top_screen(page: &mut Page, step: &str) -> Value {
    let top = page.evaluate(SCREEN_SURFACE);
    assert!(top.is_array(), "{step}: screen probe failed: {top}");
    for index in 0..page.frame_urls().len() {
        let frame = page.evaluate_in_frame(index, SCREEN_SURFACE).unwrap();
        assert_eq!(frame, top, "{step}: frame {} reports a different screen than the top document", page.frame_urls()[index]);
    }
    top
}

/// Chrome applies Emulation.setDeviceMetricsOverride to the whole page, so
/// every frame reports the emulated screen; without an override every frame
/// reports the profile's randomized screen. A frame that keeps the profile
/// screen while the top document is emulated is detectable by comparing the
/// two.
#[tokio::test(flavor = "current_thread")]
async fn frames_report_the_top_document_screen_with_and_without_device_emulation() {
    let other_origin = Server::new();
    let server = Server::with_routes(Some(&other_origin.base), Arc::new(HashMap::new()));
    let profile = context(true, 0x5c2e_e9f1);
    let mut page = open(&profile, &format!("{}/page?step=native", server.base)).await;
    wait_for_frames(&mut page, 2).await;
    let native = assert_frames_report_top_screen(&mut page, "no override");
    assert_ne!(native.as_array().unwrap()[..2], [json!(1280), json!(800)], "the profile screen must differ from the emulated one");

    // An override applied to a loaded page reaches the frames already open.
    page.apply_device_metrics_override(Some(1280.0), Some(800.0), Some(1.0), Some((1280.0, 800.0)), false);
    let live = assert_frames_report_top_screen(&mut page, "override on a loaded page");
    assert_eq!(live.as_array().unwrap()[..4], [json!(1280), json!(800), json!(1280), json!(800)]);
    // The device scale factor belongs to the same screen.
    page.apply_device_metrics_override(Some(1280.0), Some(800.0), Some(2.0), Some((1280.0, 800.0)), false);
    let dense = assert_frames_report_top_screen(&mut page, "scale factor on a loaded page");
    assert_eq!(dense.as_array().unwrap()[11], json!(2));

    // Frames created while the override is active start emulated.
    page.navigate(&format!("{}/page?step=emulated", server.base)).await.unwrap();
    wait_for_frames(&mut page, 2).await;
    let emulated = assert_frames_report_top_screen(&mut page, "navigation under an override");
    assert_eq!(emulated.as_array().unwrap()[..4], [json!(1280), json!(800), json!(1280), json!(800)]);
    assert_eq!(emulated.as_array().unwrap()[11], json!(2));

    // Clearing the override restores the same profile screen everywhere.
    page.clear_device_metrics_override();
    let cleared = assert_frames_report_top_screen(&mut page, "override cleared");
    assert_eq!(cleared.as_array().unwrap()[..4], native.as_array().unwrap()[..4]);
    page.navigate(&format!("{}/page?step=restored", server.base)).await.unwrap();
    wait_for_frames(&mut page, 2).await;
    assert_eq!(assert_frames_report_top_screen(&mut page, "navigation after clearing"), native);
}

// ---------------------------------------------------------------------------
// Worker global scopes.

/// Probes the global scope of a dedicated worker, a dedicated worker nested in
/// it and a shared worker. A WorkerGlobalScope has no `window`, `document`,
/// `screen`, `devicePixelRatio`, storage, dialogs or DOM interfaces, so `typeof`
/// reads 'undefined' and `name in self` is false; detectors (CreepJS's worker
/// checks among them) compare that with the page. What a worker does have,
/// including its navigator identity, must still match the page.
const WORKER_SCOPE_PROBE: &str = r#"(() => {
  const windowOnly = ['window', 'document', 'screen', 'devicePixelRatio', 'innerWidth', 'innerHeight',
    'outerWidth', 'outerHeight', 'screenX', 'screenY', 'scrollX', 'pageYOffset', 'visualViewport',
    'localStorage', 'sessionStorage', 'alert', 'confirm', 'prompt', 'open', 'print', 'stop', 'focus',
    'history', 'frames', 'parent', 'top', 'opener', 'frameElement', 'length', 'customElements',
    'getComputedStyle', 'getSelection', 'matchMedia', 'requestIdleCallback', 'speechSynthesis', 'chrome',
    'Window', 'Document', 'Node', 'Element', 'HTMLElement', 'HTMLCanvasElement', 'HTMLDocument',
    'CanvasRenderingContext2D', 'Screen', 'Storage', 'Navigator', 'Location', 'Image', 'Audio',
    'MutationObserver', 'IntersectionObserver', 'ResizeObserver', 'DOMParser', 'MouseEvent',
    'KeyboardEvent', 'AudioContext', 'OfflineAudioContext', 'webkitAudioContext', 'RTCPeerConnection',
    'SVGElement', 'CSSStyleDeclaration', 'SharedWorker', 'MediaStreamTrack', 'onclick', 'onresize', 'onload',
    'ononline'];
  const sharedAlsoLacks = ['postMessage', 'requestAnimationFrame', 'cancelAnimationFrame', 'Worker'];
  const common = ['self', 'globalThis', 'navigator', 'location', 'name', 'close', 'addEventListener',
    'removeEventListener', 'dispatchEvent', 'setTimeout', 'setInterval', 'clearTimeout', 'fetch',
    'crypto', 'performance', 'console', 'atob', 'TextEncoder', 'structuredClone', 'queueMicrotask',
    'Blob', 'URL', 'Promise', 'Intl', 'WebAssembly', 'WorkerGlobalScope'];
  const dedicatedHas = [...common, 'postMessage', 'onmessage', 'Worker', 'requestAnimationFrame',
    'DedicatedWorkerGlobalScope'];
  const sharedHas = [...common, 'onconnect', 'SharedWorkerGlobalScope'];
  function probe(kind, absent, present) {
    const leaks = [];
    for (const n of absent) {
      const type = eval('typeof ' + n);
      if (type !== 'undefined' || n in self || self[n] !== undefined || Object.getOwnPropertyNames(self).includes(n)) {
        leaks.push(n + ':' + type + ':' + (n in self));
      }
    }
    const missing = present.filter((n) => eval('typeof ' + n) === 'undefined' || !(n in self));
    const other = kind === 'shared' ? 'DedicatedWorkerGlobalScope' : 'SharedWorkerGlobalScope';
    const result = {
      leaks, missing,
      otherScope: eval('typeof ' + other) + ':' + (other in self),
      tag: Object.prototype.toString.call(self),
      sameGlobal: globalThis === self && self.self === self && topLevelThis === self,
      isWorkerScope: self instanceof WorkerGlobalScope,
      identity: [navigator.userAgent, navigator.platform, navigator.hardwareConcurrency, navigator.deviceMemory,
        navigator.languages.join(), Intl.DateTimeFormat().resolvedOptions().timeZone, typeof OffscreenCanvas],
    };
    // A common worker polyfill: assigning a window-only name defines it.
    self.window = self;
    result.polyfill = typeof window === 'object' && window === self && 'window' in self;
    return result;
  }
  const blobUrl = (source) => URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
  const header = `const topLevelThis = this; const probe = ${probe}; const absent = ${JSON.stringify(windowOnly)};`
    + ` const present = ${JSON.stringify(dedicatedHas)};`;
  const nestedSource = header + ` onmessage = () => postMessage(probe.call(self, 'nested', absent, present));`;
  const dedicatedSource = header + ` const nestedSource = ${JSON.stringify(nestedSource)};
    onmessage = () => {
      const nested = new Worker(URL.createObjectURL(new Blob([nestedSource], { type: 'text/javascript' })));
      nested.onmessage = (event) => postMessage({ outer: probe.call(self, 'dedicated', absent, present), nested: event.data });
      nested.postMessage(1);
    };`;
  const sharedSource = `const topLevelThis = this; const probe = ${probe};`
    + ` onconnect = (event) => event.ports[0].postMessage(probe.call(self, 'shared', ${JSON.stringify([...windowOnly, ...sharedAlsoLacks])}, ${JSON.stringify(sharedHas)}));`;
  const result = {
    page: windowOnly.filter((n) => n in globalThis),
    identity: [navigator.userAgent, navigator.platform, navigator.hardwareConcurrency, navigator.deviceMemory,
      navigator.languages.join(), Intl.DateTimeFormat().resolvedOptions().timeZone, typeof OffscreenCanvas],
  };
  const done = () => { if (result.dedicated && result.shared) globalThis.__result = result; };
  const worker = new Worker(blobUrl(dedicatedSource));
  worker.onmessage = (event) => { result.dedicated = event.data.outer; result.nested = event.data.nested; done(); };
  worker.postMessage(1);
  const shared = new SharedWorker(blobUrl(sharedSource));
  shared.port.onmessage = (event) => { result.shared = event.data; done(); };
  shared.port.start();
})()"#;

#[tokio::test(flavor = "current_thread")]
async fn worker_global_scopes_have_no_window_only_globals_and_keep_the_page_identity() {
    let server = Server::new();
    let mut page = open(&context(true, 0x77a1_3c05), &format!("{}/page", server.base)).await;
    let report = evaluate_async(&mut page, WORKER_SCOPE_PROBE).await;
    // The page itself has these, so a worker that resolves names through the
    // page realm would leak them.
    let page_names: Vec<&str> = report["page"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    for name in ["window", "document", "screen", "devicePixelRatio", "localStorage", "innerWidth", "alert", "Document"] {
        assert!(page_names.contains(&name), "the page lacks {name}: {page_names:?}");
    }
    for (kind, tag, other) in [
        ("dedicated", "[object DedicatedWorkerGlobalScope]", "undefined:false"),
        ("nested", "[object DedicatedWorkerGlobalScope]", "undefined:false"),
        ("shared", "[object SharedWorkerGlobalScope]", "undefined:false"),
    ] {
        let scope = &report[kind];
        assert_eq!(scope["leaks"], json!([]), "{kind} worker exposes window-only globals: {scope}");
        assert_eq!(scope["missing"], json!([]), "{kind} worker lacks worker globals: {scope}");
        assert_eq!(scope["otherScope"], other, "{kind} worker exposes the other worker scope interface");
        assert_eq!(scope["tag"], tag, "{kind} worker global toStringTag");
        assert_eq!(scope["sameGlobal"], true, "{kind} worker: self, globalThis and top-level this differ");
        assert_eq!(scope["isWorkerScope"], true, "{kind} worker: self is not a WorkerGlobalScope");
        assert_eq!(scope["identity"], report["identity"], "{kind} worker identity differs from the page");
        assert_eq!(scope["polyfill"], true, "{kind} worker: assigning self.window did not define it");
    }
}

/// Probes what Chrome 151 gives a dedicated and a shared worker beyond the
/// window-only names: a WorkerNavigator with the worker member set and the
/// page's identity, a WorkerLocation for the script URL, importScripts with
/// synchronous load-and-run semantics, ReferenceError for a bare window-only
/// name, and a global object whose own names list the worker's globals.
const WORKER_API_PROBE: &str = r#"(() => {
  const body = `
    const out = {};
    const safe = (f) => { try { return f(); } catch (e) { return 'THROW ' + e.name + ': ' + e.message; } };
    const nav = Object.getPrototypeOf(navigator);
    out.navTag = Object.prototype.toString.call(navigator);
    out.navChain = []; for (let o = nav; o; o = Object.getPrototypeOf(o)) out.navChain.push(o.constructor.name);
    out.navOwn = Object.getOwnPropertyNames(navigator);
    out.navProto = Object.getOwnPropertyNames(nav).sort();
    out.pageNav = PAGE_NAV;
    out.navValues = [navigator.userAgent, navigator.platform, navigator.language, navigator.languages.join(),
      navigator.hardwareConcurrency, navigator.deviceMemory, navigator.onLine, navigator.appVersion,
      typeof navigator.userAgentData, navigator.userAgentData && navigator.userAgentData.platform];
    out.navWindowOnly = ['plugins', 'mimeTypes', 'webdriver', 'cookieEnabled', 'javaEnabled', 'vendor', 'vendorSub',
      'productSub', 'geolocation', 'doNotTrack', 'maxTouchPoints', 'pdfViewerEnabled', 'serviceWorker', 'clipboard',
      'credentials', 'mediaDevices', 'keyboard', 'wakeLock', 'sendBeacon', 'vibrate', 'getBattery', 'bluetooth',
      'getGamepads', 'userActivation', 'scheduling', 'xr'].filter((k) => k in navigator);
    out.navInterface = [typeof WorkerNavigator, typeof Navigator, Function.prototype.toString.call(WorkerNavigator),
      safe(() => new WorkerNavigator()), safe(() => Object.getOwnPropertyDescriptor(nav, 'userAgent').get.call({})),
      Function.prototype.toString.call(Object.getOwnPropertyDescriptor(nav, 'userAgent').get)];
    out.locTag = Object.prototype.toString.call(location);
    out.locOwn = Object.getOwnPropertyNames(location);
    out.locProto = Object.getOwnPropertyNames(Object.getPrototypeOf(location)).sort();
    out.loc = ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'].map((k) => location[k]);
    out.locString = [String(location), JSON.stringify(location), typeof WorkerLocation, typeof Location,
      safe(() => new WorkerLocation())];
    out.importScripts = [typeof importScripts, importScripts.length, importScripts.name,
      Function.prototype.toString.call(importScripts), 'importScripts' in self,
      Object.getOwnPropertyNames(self).includes('importScripts'), String(importScripts())];
    out.importErrors = [
      safe(() => importScripts('http://[bad')),
      safe(() => importScripts(URL.createObjectURL(new Blob(['x'])).replace(/[0-9a-f]{8}-/, '00000000-'))),
      safe(() => importScripts(URL.createObjectURL(new Blob(['var = ;'])))),
      safe(() => importScripts(URL.createObjectURL(new Blob(['throw new RangeError("boom")'])))),
    ];
    out.importLib = [safe(() => String(importScripts(LIB_URL, URL.createObjectURL(new Blob([LIB_TWO]))))),
      typeof libVar, typeof libFn, typeof libThis, typeof libTwo, safe(() => libFn() + libTwo()),
      'libVar' in self, 'libFn' in self, 'libThis' in self, self.libVar,
      Object.keys(self).filter((k) => k.startsWith('lib')).sort().join(), typeof pageOnlyGlobal, 'pageOnlyGlobal' in self];
    out.bare = ['window', 'document', 'screen', 'localStorage', 'alert', 'Document', 'onclick']
      .map((n) => safe(() => { const v = eval(n); return 'value:' + typeof v; }));
    out.bareDirect = [safe(() => { document; return 'no throw'; }), safe(() => { window.x; return 'no throw'; }),
      typeof window, typeof(document), typeof onclick, safe(() => typeof (() => { let screen = 1; return screen; })())];
    const own = Object.getOwnPropertyNames(self);
    out.own = {
      count: own.length,
      has: ['Object', 'Array', 'Promise', 'globalThis', 'WorkerNavigator', 'WorkerLocation', 'WorkerGlobalScope',
        'TextEncoder', 'name', 'close', 'onmessage', 'postMessage', 'onconnect', 'DedicatedWorkerGlobalScope',
        'SharedWorkerGlobalScope'].filter((k) => own.includes(k)),
      lacks: ['navigator', 'location', 'self', 'fetch', 'setTimeout', 'importScripts', 'addEventListener', 'window',
        'document', 'Navigator', 'pageOnlyGlobal'].filter((k) => !own.includes(k)),
      internal: own.filter((k) => k[0] === '_' || /obscura/i.test(k)),
      reflect: Reflect.ownKeys(self).length === own.length + Object.getOwnPropertySymbols(self).length,
      keys: Object.keys(self).filter((k) => !k.startsWith('lib')).sort(),
      proto: ['navigator', 'location', 'self', 'importScripts', 'setTimeout', 'fetch']
        .filter((k) => Object.getOwnPropertyNames(WorkerGlobalScope.prototype).includes(k)),
      descriptor: [Object.getOwnPropertyDescriptor(self, 'navigator'), Object.getOwnPropertyDescriptor(self, 'Object')],
    };
    self.window = self;
    out.polyfill = [typeof window, window === self, safe(() => typeof document)];
  `;
  const LIB = "var libVar = 1; function libFn() { return 2; } this.libThis = 5;";
  const blob = (s) => URL.createObjectURL(new Blob([s], { type: 'text/javascript' }));
  globalThis.pageOnlyGlobal = 1;
  const chromeMembers = ['appCodeName', 'appName', 'appVersion', 'connection', 'constructor', 'deviceMemory', 'gpu',
    'hardwareConcurrency', 'hid', 'language', 'languages', 'locks', 'mediaCapabilities', 'onLine', 'permissions',
    'platform', 'product', 'serial', 'storage', 'storageBuckets', 'usb', 'userAgent', 'userAgentData'];
  const prelude = 'const PAGE_NAV = ' + JSON.stringify(chromeMembers.filter((k) => k in navigator || k === 'constructor')) + '; const LIB_URL = ' + JSON.stringify(location.origin + '/lib.js') + '; const LIB_TWO = '
    + JSON.stringify('var libTwo = function () { return libVar + 10; };') + ';\n';
  const result = {
    page: [navigator.userAgent, navigator.platform, navigator.language, navigator.languages.join(),
      navigator.hardwareConcurrency, navigator.deviceMemory, navigator.onLine, navigator.appVersion,
      typeof navigator.userAgentData, navigator.userAgentData && navigator.userAgentData.platform],
    origin: location.origin,
  };
  const done = () => {
    if (result.dedicated && result.shared && result.module && result.urlWorker) globalThis.__result = result;
  };
  const guarded = 'let out = {}; try { (() => { ' + body.replace('const out = {};', '') + ' })(); } catch (e) { out = { crash: String(e && e.stack || e) }; } out = JSON.parse(JSON.stringify(out));';
  const dedicatedUrl = blob(prelude + 'onmessage = () => { ' + guarded + ' postMessage(out); };');
  result.dedicatedUrl = dedicatedUrl;
  const dedicated = new Worker(dedicatedUrl);
  dedicated.onmessage = (e) => { result.dedicated = e.data; done(); };
  dedicated.onerror = (e) => { result.dedicated = { crash: String(e && (e.message || e)) }; done(); };
  dedicated.postMessage(1);
  const sharedUrl = blob(prelude + 'onconnect = (c) => { ' + guarded + ' c.ports[0].postMessage(out); };');
  result.sharedUrl = sharedUrl;
  const shared = new SharedWorker(sharedUrl);
  shared.port.onmessage = (e) => { result.shared = e.data; done(); };
  shared.onerror = (e) => { result.shared = { crash: String(e && (e.message || e)) }; done(); };
  shared.port.start();
  const module = new Worker(blob('let r; try { importScripts(); r = "no throw"; } catch (e) { r = e.name + ": " + e.message; } postMessage(r);'), { type: 'module' });
  module.onmessage = (e) => { result.module = e.data; done(); };
  module.onerror = (e) => { result.module = 'crash ' + String(e && (e.message || e)); done(); };
  const urlWorker = new Worker('/loc-worker.js?x=1#frag');
  urlWorker.onmessage = (e) => { result.urlWorker = e.data; done(); };
  urlWorker.onerror = (e) => { result.urlWorker = 'crash ' + String(e && (e.message || e)); done(); };
  setTimeout(() => { if (globalThis.__result === undefined) globalThis.__result = { timeout: result }; }, 8000);
})()"#;

#[tokio::test(flavor = "current_thread")]
async fn worker_navigator_location_import_scripts_and_globals_match_chrome() {
    let mut routes: HashMap<String, (&'static str, Vec<u8>)> = HashMap::new();
    routes.insert(
        "/lib.js".to_string(),
        ("text/javascript", b"var libVar = 1; function libFn() { return 2; } this.libThis = 5;".to_vec()),
    );
    routes.insert(
        "/loc-worker.js".to_string(),
        (
            "text/javascript",
            b"postMessage(['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash']\
              .map((k) => location[k]).concat([String(location), Object.prototype.toString.call(location)]));"
                .to_vec(),
        ),
    );
    let server = Server::with_routes(None, Arc::new(routes));
    let mut page = open(&context(true, 0x3d1f_0a77), &format!("{}/page", server.base)).await;
    let report = evaluate_async(&mut page, WORKER_API_PROBE).await;
    let base = server.base.clone();
    let host = base.trim_start_matches("http://").to_string();
    let port = host.rsplit(':').next().unwrap().to_string();

    // A worker loaded from a URL: Chrome 151's WorkerLocation for it.
    assert_eq!(
        report["urlWorker"],
        json!([
            format!("{base}/loc-worker.js?x=1#frag"), base, "http:", host, "127.0.0.1", port, "/loc-worker.js",
            "?x=1", "#frag", format!("{base}/loc-worker.js?x=1#frag"), "[object WorkerLocation]"
        ])
    );
    assert_eq!(
        report["module"],
        "TypeError: Failed to execute 'importScripts' on 'WorkerGlobalScope': Module scripts don't support importScripts()."
    );

    let chrome_dedicated_navigator = [
        "appCodeName", "appName", "appVersion", "connection", "constructor", "deviceMemory", "gpu",
        "hardwareConcurrency", "hid", "language", "languages", "locks", "mediaCapabilities", "onLine",
        "permissions", "platform", "product", "serial", "storage", "storageBuckets", "usb", "userAgent",
        "userAgentData",
    ];
    for (kind, scope_name, other_scope) in [
        ("dedicated", "DedicatedWorkerGlobalScope", "SharedWorkerGlobalScope"),
        ("shared", "SharedWorkerGlobalScope", "DedicatedWorkerGlobalScope"),
    ] {
        let scope = &report[kind];
        // WorkerNavigator: Chrome's interface, worker member set, page identity.
        assert_eq!(scope["navTag"], "[object WorkerNavigator]", "{kind}: {scope}");
        assert_eq!(scope["navChain"], json!(["WorkerNavigator", "Object"]), "{kind}");
        assert_eq!(scope["navOwn"], json!([]), "{kind}");
        let members: Vec<&str> = scope["navProto"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        for member in &members {
            assert!(chrome_dedicated_navigator.contains(member), "{kind}: WorkerNavigator has {member}, Chrome does not");
            if kind == "shared" {
                assert!(!["hid", "serial", "usb"].contains(member), "shared: WorkerNavigator has {member}");
            }
        }
        // Every Chrome worker member the page navigator has, and no other.
        let mut expected: Vec<&str> = scope["pageNav"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        if kind == "shared" {
            expected.retain(|member| !["hid", "serial", "usb"].contains(member));
        }
        assert_eq!(members, expected, "{kind}: WorkerNavigator members");
        for member in ["userAgent", "platform", "language", "languages", "hardwareConcurrency", "deviceMemory",
            "onLine", "appVersion", "userAgentData"] {
            assert!(members.contains(&member), "{kind}: WorkerNavigator lacks {member}: {members:?}");
        }
        assert_eq!(scope["navWindowOnly"], json!([]), "{kind}: window-only navigator members");
        assert_eq!(scope["navValues"], report["page"], "{kind}: worker navigator identity differs from the page");
        assert_eq!(
            scope["navInterface"],
            json!(["function", "undefined", "function WorkerNavigator() { [native code] }",
                "THROW TypeError: Failed to construct 'WorkerNavigator': Illegal constructor",
                "THROW TypeError: Illegal invocation", "function get userAgent() { [native code] }"]),
            "{kind}"
        );

        // WorkerLocation of a blob worker: blob URL, page origin.
        let url = report[format!("{kind}Url")].as_str().unwrap();
        assert_eq!(scope["locTag"], "[object WorkerLocation]", "{kind}");
        assert_eq!(scope["locOwn"], json!([]), "{kind}");
        assert_eq!(
            scope["locProto"],
            json!(["constructor", "hash", "host", "hostname", "href", "origin", "pathname", "port", "protocol", "search", "toString"]),
            "{kind}"
        );
        assert_eq!(scope["loc"], json!([url, report["origin"], "blob:", "", "", "", &url["blob:".len()..], "", ""]), "{kind}");
        assert_eq!(
            scope["locString"],
            json!([url, "{}", "function", "undefined", "THROW TypeError: Failed to construct 'WorkerLocation': Illegal constructor"]),
            "{kind}"
        );

        // importScripts: Chrome's function, errors and global declarations.
        assert_eq!(
            scope["importScripts"],
            json!(["function", 0, "importScripts", "function importScripts() { [native code] }", true, false, "undefined"]),
            "{kind}"
        );
        let errors = scope["importErrors"].as_array().unwrap();
        assert_eq!(errors[0], "THROW SyntaxError: Failed to execute 'importScripts' on 'WorkerGlobalScope': The URL 'http://[bad' is invalid.", "{kind}");
        let missing = errors[1].as_str().unwrap();
        assert!(
            missing.starts_with("THROW NetworkError: Failed to execute 'importScripts' on 'WorkerGlobalScope': The script at 'blob:")
                && missing.ends_with("' failed to load."),
            "{kind}: {missing}"
        );
        assert!(
            errors[2].as_str().unwrap().starts_with("THROW SyntaxError: Failed to execute 'importScripts' on 'WorkerGlobalScope': "),
            "{kind}: {}", errors[2]
        );
        assert_eq!(errors[3], "THROW RangeError: boom", "{kind}");
        assert_eq!(
            scope["importLib"],
            json!(["undefined", "number", "function", "number", "function", 13, true, true, true, 1,
                "libFn,libThis,libTwo,libVar", "undefined", false]),
            "{kind}: imported declarations must become worker globals"
        );

        // A bare window-only name is unresolvable, as in a worker.
        assert_eq!(
            scope["bare"],
            json!(["THROW ReferenceError: window is not defined", "THROW ReferenceError: document is not defined",
                "THROW ReferenceError: screen is not defined", "THROW ReferenceError: localStorage is not defined",
                "THROW ReferenceError: alert is not defined", "THROW ReferenceError: Document is not defined",
                "THROW ReferenceError: onclick is not defined"]),
            "{kind}"
        );
        assert_eq!(
            scope["bareDirect"],
            json!(["THROW ReferenceError: document is not defined", "THROW ReferenceError: window is not defined",
                "undefined", "undefined", "undefined", "number"]),
            "{kind}"
        );
        assert_eq!(scope["polyfill"], json!(["object", true, "undefined"]), "{kind}: assigning self.window must define it");

        // The global object lists the worker's globals, as Chrome's does.
        let own = &scope["own"];
        let mut has = vec!["Object", "Array", "Promise", "globalThis", "WorkerNavigator", "WorkerLocation",
            "WorkerGlobalScope", "TextEncoder", "name", "close"];
        has.extend(if kind == "dedicated" { vec!["onmessage", "postMessage", scope_name] } else { vec!["onconnect", scope_name] });
        let listed: Vec<&str> = own["has"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        for name in &has {
            assert!(listed.contains(name), "{kind}: own names lack {name}: {own}");
        }
        assert!(!listed.contains(&other_scope), "{kind}: own names list {other_scope}");
        assert_eq!(own["lacks"].as_array().unwrap().len(), 11, "{kind}: own names list a non-own member: {own}");
        assert_eq!(own["internal"], json!([]), "{kind}");
        assert_eq!(own["reflect"], true, "{kind}");
        assert!(own["count"].as_u64().unwrap() > 150, "{kind}: too few globals: {own}");
        let keys: Vec<&str> = own["keys"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        let chrome_keys: &[&str] = if kind == "dedicated" {
            &["cancelAnimationFrame", "close", "name", "onmessage", "onmessageerror", "onrtctransform", "postMessage", "requestAnimationFrame"]
        } else {
            &["close", "name", "onconnect"]
        };
        for key in &keys {
            assert!(chrome_keys.contains(key) || key.starts_with("webkit"), "{kind}: enumerable own {key}, Chrome has {chrome_keys:?}");
        }
        assert_eq!(own["proto"], json!(["navigator", "location", "self", "importScripts", "setTimeout", "fetch"]), "{kind}");
        assert_eq!(own["descriptor"][0], Value::Null, "{kind}: navigator is a WorkerGlobalScope.prototype member");
        assert_eq!(own["descriptor"][1], json!({ "writable": true, "enumerable": false, "configurable": true }), "{kind}");
    }
}

// ---------------------------------------------------------------------------
// Window size under device emulation.

/// Chrome 151 (window 1600x1000) keeps outerWidth/outerHeight under desktop
/// device emulation (mobile:false), live and after navigation, and under
/// mobile emulation reports the emulated view (width x height, the native view
/// for a zero dimension) whatever the emulated screen. Frames report the top
/// document's values.
#[tokio::test(flavor = "current_thread")]
async fn outer_size_follows_chrome_under_desktop_and_mobile_device_emulation() {
    let other_origin = Server::new();
    let server = Server::with_routes(Some(&other_origin.base), Arc::new(HashMap::new()));
    let profile = context(true, 0x0e7a_51d3);
    let mut page = open(&profile, &format!("{}/page?step=native", server.base)).await;
    wait_for_frames(&mut page, 2).await;
    let outer = |surface: &Value| [surface[9].clone(), surface[10].clone()];
    let native_surface = assert_frames_report_top_screen(&mut page, "no override");
    let native = outer(&native_surface);
    let native_view = page.evaluate("[innerWidth, innerHeight]");
    assert_ne!(native, [json!(1440), json!(900)]);

    page.apply_device_metrics_override(Some(1280.0), Some(800.0), Some(1.0), Some((1440.0, 900.0)), false);
    let desktop = assert_frames_report_top_screen(&mut page, "desktop override on a loaded page");
    assert_eq!(desktop[0], json!(1440), "the emulated screen applies");
    assert_eq!(outer(&desktop), native, "desktop emulation keeps the window");
    page.navigate(&format!("{}/page?step=desktop", server.base)).await.unwrap();
    wait_for_frames(&mut page, 2).await;
    assert_eq!(outer(&assert_frames_report_top_screen(&mut page, "navigation under desktop override")), native);

    page.apply_device_metrics_override(Some(412.0), Some(915.0), Some(2.625), None, true);
    let mobile = assert_frames_report_top_screen(&mut page, "mobile override on a loaded page");
    assert_eq!(outer(&mobile), [json!(412), json!(915)]);
    page.navigate(&format!("{}/page?step=mobile", server.base)).await.unwrap();
    wait_for_frames(&mut page, 2).await;
    assert_eq!(outer(&assert_frames_report_top_screen(&mut page, "navigation under mobile override")), [json!(412), json!(915)]);

    page.apply_device_metrics_override(Some(400.0), Some(800.0), Some(3.0), Some((500.0, 1000.0)), true);
    let screen = assert_frames_report_top_screen(&mut page, "mobile override with a screen");
    assert_eq!([screen[0].clone(), screen[1].clone()], [json!(500), json!(1000)]);
    assert_eq!(outer(&screen), [json!(400), json!(800)], "mobile emulation reports the view, not the screen");

    page.apply_device_metrics_override(None, None, None, None, true);
    let zero = assert_frames_report_top_screen(&mut page, "mobile override with zero dimensions");
    assert_eq!(json!(outer(&zero)), native_view, "a zero dimension keeps the native view");

    page.clear_device_metrics_override();
    assert_eq!(outer(&assert_frames_report_top_screen(&mut page, "override cleared")), native);
    page.navigate(&format!("{}/page?step=restored", server.base)).await.unwrap();
    wait_for_frames(&mut page, 2).await;
    assert_eq!(assert_frames_report_top_screen(&mut page, "navigation after clearing"), native_surface);
}

// ---------------------------------------------------------------------------
// Page navigator members and window position.

/// Chrome 151's page navigator members that Obscura lacked, read the way a
/// fingerprinting script reads them.
const PAGE_NAVIGATOR_PROBE: &str = r#"(() => { try {
  const safe = (f) => { try { return f(); } catch (e) { return 'THROW ' + e.name + ': ' + e.message; } };
  const P = Navigator.prototype;
  const members = ['appCodeName', 'appName', 'vendorSub', 'hid', 'serial', 'usb', 'storageBuckets'];
  const out = {};
  out.own = Object.getOwnPropertyNames(navigator);
  out.missing = members.filter((k) => !Object.getOwnPropertyNames(P).includes(k));
  out.desc = Object.fromEntries(members.map((k) => [k, safe(() => {
    const d = Object.getOwnPropertyDescriptor(P, k);
    return [typeof d.get, typeof d.set, d.enumerable, d.configurable, Function.prototype.toString.call(d.get),
      safe(() => d.get.call(P))];
  })]));
  out.strings = [navigator.appCodeName, navigator.appName, navigator.vendorSub, navigator.product, navigator.productSub,
    navigator.vendor, navigator.appVersion === navigator.userAgent.replace(/^Mozilla\//, '')];
  out.objects = ['hid', 'serial', 'usb', 'storageBuckets'].map((k) => [Object.prototype.toString.call(navigator[k]),
    navigator[k] === navigator[k], Object.getOwnPropertyNames(navigator[k]).length]);
  out.interfaces = ['HID', 'Serial', 'USB', 'StorageBucketManager'].map((n) => [typeof self[n],
    safe(() => Function.prototype.toString.call(self[n])), safe(() => new self[n]()),
    Object.getPrototypeOf(navigator[n === 'StorageBucketManager' ? 'storageBuckets' : n.toLowerCase()]) === self[n].prototype]);
  out.methods = [navigator.hid.getDevices.length, navigator.hid.requestDevice.length, navigator.usb.requestDevice.length,
    navigator.serial.getPorts.length, navigator.serial.requestPort.length, navigator.storageBuckets.open.length,
    Function.prototype.toString.call(navigator.hid.requestDevice), navigator.hid.onconnect];
  out.globals = ['HID', 'Serial', 'USB', 'StorageBucketManager'].map((n) => Object.getOwnPropertyDescriptor(self, n).enumerable);
  out.positionDesc = ['screenX', 'screenY', 'screenLeft', 'screenTop'].map((k) => {
    const d = Object.getOwnPropertyDescriptor(window, k);
    return [typeof d.get, typeof d.set, d.enumerable, d.configurable, Function.prototype.toString.call(d.get)];
  });
  out.position = [screenX, screenY, screenLeft, screenTop,
    screenX + outerWidth <= screen.availLeft + screen.availWidth, screenY + outerHeight <= screen.availTop + screen.availHeight];
  const settle = (p) => p.then((v) => 'ok:' + JSON.stringify(v), (e) => 'reject ' + e.name + ': ' + e.message);
  const worker = (shared) => new Promise((resolve) => {
    const src = 'const r = () => [navigator.appCodeName, navigator.appName, "hid" in navigator, "usb" in navigator,'
      + ' "serial" in navigator, "storageBuckets" in navigator, typeof HID, typeof StorageBucketManager, "vendorSub" in navigator];';
    const url = URL.createObjectURL(new Blob([shared ? src + 'onconnect = (e) => e.ports[0].postMessage(r());' : src + 'postMessage(r());']));
    if (shared) { const w = new SharedWorker(url); w.port.onmessage = (e) => resolve(e.data); w.port.start(); }
    else { const w = new Worker(url); w.onmessage = (e) => resolve(e.data); w.onerror = (e) => resolve('error ' + e.message); }
  });
  Promise.all([
    settle(navigator.hid.getDevices()), settle(navigator.hid.requestDevice({ filters: [] })),
    settle(navigator.usb.getDevices()), settle(navigator.usb.requestDevice({ filters: [] })),
    settle(navigator.serial.getPorts()), settle(navigator.serial.requestPort()),
    settle(navigator.storageBuckets.keys()), settle(navigator.storageBuckets.open('Bad Name')),
    settle(navigator.hid.requestDevice()), settle(navigator.storageBuckets.delete('none')),
    worker(false), worker(true),
  ]).then((results) => {
    out.async = results.slice(0, 10);
    out.dedicated = results[10];
    out.shared = results[11];
    globalThis.__result = out;
  }, (e) => { globalThis.__result = { error: String(e) }; });
} catch (e) { globalThis.__result = { error: String(e) }; } })()"#;

const WINDOW_POSITION: &str = "[screenX, screenY, screenLeft, screenTop]";

/// Chrome 151 desktop has these members on Navigator.prototype (offline
/// probe); Obscura's navigator lacked them, a direct desktop-Chrome tell. A
/// Windows Chrome window that is maximized (the profile's window fills the
/// work area) reports screenX/screenY 0/0, and mobile emulation reports 0/0.
#[tokio::test(flavor = "current_thread")]
async fn page_navigator_has_chrome_members_and_a_maximized_window_position() {
    let other_origin = Server::new();
    let server = Server::with_routes(Some(&other_origin.base), Arc::new(HashMap::new()));
    let mut page = open(&context(true, 0x51a7_e0c4), &format!("{}/page", server.base)).await;
    wait_for_frames(&mut page, 2).await;
    let report = evaluate_async(&mut page, PAGE_NAVIGATOR_PROBE).await;
    assert_eq!(report["error"], Value::Null, "probe threw: {report}");
    assert_eq!(report["own"], json!([]), "navigator has own properties");
    assert_eq!(report["missing"], json!([]), "Navigator.prototype lacks Chrome members: {report}");
    for member in ["appCodeName", "appName", "vendorSub", "hid", "serial", "usb", "storageBuckets"] {
        assert_eq!(
            report["desc"][member],
            json!(["function", "undefined", true, true, format!("function get {member}() {{ [native code] }}"),
                "THROW TypeError: Illegal invocation"]),
            "{member} descriptor"
        );
    }
    assert_eq!(report["strings"], json!(["Mozilla", "Netscape", "", "Gecko", "20030107", "Google Inc.", true]));
    assert_eq!(
        report["objects"],
        json!([["[object HID]", true, 0], ["[object Serial]", true, 0], ["[object USB]", true, 0],
            ["[object StorageBucketManager]", true, 0]])
    );
    for (index, name) in ["HID", "Serial", "USB", "StorageBucketManager"].iter().enumerate() {
        assert_eq!(
            report["interfaces"][index],
            json!(["function", format!("function {name}() {{ [native code] }}"),
                format!("THROW TypeError: Failed to construct '{name}': Illegal constructor"), true]),
            "{name}"
        );
    }
    assert_eq!(report["methods"], json!([0, 1, 1, 0, 0, 1, "function requestDevice() { [native code] }", null]));
    let gesture = |iface: &str, op: &str| {
        format!("reject SecurityError: Failed to execute '{op}' on '{iface}': Must be handling a user gesture to show a permission request.")
    };
    assert_eq!(
        report["async"],
        json!(["ok:[]", gesture("HID", "requestDevice"), "ok:[]", gesture("USB", "requestDevice"), "ok:[]",
            gesture("Serial", "requestPort"), "ok:[]",
            "reject TypeError: The bucket name 'Bad Name' is not a valid name.",
            "reject TypeError: Failed to execute 'requestDevice' on 'HID': 1 argument required, but only 0 present.",
            "ok:undefined"])
    );
    assert_eq!(report["dedicated"], json!(["Mozilla", "Netscape", true, true, true, true, "function", "function", false]));
    assert_eq!(report["shared"], json!(["Mozilla", "Netscape", false, false, false, true, "undefined", "function", false]));
    assert_eq!(report["globals"], json!([false, false, false, false]), "interface objects are not enumerable");
    for (index, name) in ["screenX", "screenY", "screenLeft", "screenTop"].iter().enumerate() {
        assert_eq!(
            report["positionDesc"][index],
            json!(["function", "function", true, true, format!("function get {name}() {{ [native code] }}")]),
            "{name} is a window accessor"
        );
    }
    assert_eq!(report["position"], json!([0, 0, 0, 0, true, true]), "maximized window position");

    for index in 0..page.frame_urls().len() {
        let frame = page
            .evaluate_in_frame(index, "[navigator.appName, navigator.appCodeName, 'hid' in navigator, screenX, screenY, screenLeft, screenTop]")
            .unwrap();
        assert_eq!(frame, json!(["Netscape", "Mozilla", true, 0, 0, 0, 0]), "frame {}", page.frame_urls()[index]);
    }
    page.apply_device_metrics_override(Some(412.0), Some(915.0), Some(2.625), None, true);
    assert_eq!(page.evaluate(WINDOW_POSITION), json!([0, 0, 0, 0]), "mobile emulation");
    page.apply_device_metrics_override(Some(1280.0), Some(800.0), Some(1.0), Some((1440.0, 900.0)), false);
    assert_eq!(page.evaluate(WINDOW_POSITION), json!([0, 0, 0, 0]), "desktop emulation");
    page.clear_device_metrics_override();
    assert_eq!(page.evaluate(WINDOW_POSITION), json!([0, 0, 0, 0]), "override cleared");
    assert_eq!(page.evaluate("(() => { try { screenX = 5; return [screenX, typeof Object.getOwnPropertyDescriptor(window, 'screenX').get]; } catch (e) { return String(e); } })()"), json!([5, "undefined"]), "replaceable");
}

// ---------------------------------------------------------------------------
// Frame windows read from the parent, and postMessage between realms.

/// Reads the window metrics of every kind of frame through `contentWindow`,
/// next to the top window's own. Chrome 151 (offline probe) reports the
/// browser window's outer size and position in every same-origin frame, the
/// iframe's box as its inner size, and throws SecurityError for any of them on
/// a cross-origin frame.
const CONTENT_WINDOW_PROBE: &str = r#"(() => {
  const keys = ['outerWidth', 'outerHeight', 'screenX', 'screenY', 'screenLeft', 'screenTop', 'devicePixelRatio'];
  const read = (w) => keys.map((k) => { try { return w[k]; } catch (e) { return 'THROW ' + e.name; } });
  const attempt = (f) => { try { return f(); } catch (e) { return 'THROW ' + e.name + ': ' + e.message; } };
  const [same, cross] = document.querySelectorAll('iframe');
  const blank = document.createElement('iframe');
  document.body.appendChild(blank);
  const sized = document.createElement('iframe');
  sized.style.cssText = 'width:640px;height:360px;border:0';
  document.body.appendChild(sized);
  const srcdoc = document.createElement('iframe');
  srcdoc.srcdoc = '<p>x</p>';
  document.body.appendChild(srcdoc);
  const xo = cross.contentWindow;
  return {
    top: read(window),
    frames: [same, blank, sized, srcdoc].map((f) => read(f.contentWindow)),
    inner: [same, blank, sized, srcdoc].map((f) => [f.contentWindow.innerWidth, f.clientWidth, f.contentWindow.innerHeight, f.clientHeight]),
    sizedInner: [sized.contentWindow.innerWidth, sized.contentWindow.innerHeight],
    screen: [same, blank, srcdoc].map((f) => [f.contentWindow.screen.width, f.contentWindow.screen.height]),
    topScreen: [screen.width, screen.height],
    cross: read(xo),
    crossSurface: [Object.keys(xo).length, xo.self === xo, xo.window === xo, xo.frames === xo, xo.top === window,
      xo.parent === window, xo.closed, xo.length, typeof xo.postMessage, xo.then, Object.getPrototypeOf(xo)],
    crossThrows: [attempt(() => xo.document), attempt(() => { xo.foo = 1; }), attempt(() => xo.location.href),
      attempt(() => 'innerWidth' in xo)],
    postMessage: [window, same.contentWindow, xo, blank.contentWindow].map((w) =>
      [w.postMessage.length, Function.prototype.toString.call(w.postMessage)]),
  };
})()"#;

#[tokio::test(flavor = "current_thread")]
async fn content_window_reports_the_top_window_metrics_and_blocks_cross_origin_reads() {
    let other_origin = Server::new();
    let server = Server::with_routes(Some(&other_origin.base), Arc::new(HashMap::new()));
    let mut page = open(&context(true, 0x3f0a_71c2), &format!("{}/page", server.base)).await;
    wait_for_frames(&mut page, 2).await;
    let report = page.evaluate(CONTENT_WINDOW_PROBE);
    assert!(report.is_object(), "probe failed: {report}");
    for (index, kind) in ["same-origin", "about:blank", "sized about:blank", "srcdoc"].iter().enumerate() {
        assert_eq!(report["frames"][index], report["top"], "{kind} frame read through contentWindow");
        let inner = &report["inner"][index];
        assert!(inner[0] == inner[1] && inner[2] == inner[3], "{kind} frame inner size is its iframe box: {report}");
    }
    // The inner size is the iframe's laid-out box. Without the render feature
    // there is no CSS layout and every element reports the non-render
    // fallback box (100x20, `Element.clientWidth`/`clientHeight` in
    // bootstrap.js), so only a render build can see the styled 640x360.
    let sized_inner = if cfg!(feature = "render") { json!([640, 360]) } else { json!([100, 20]) };
    assert_eq!(report["sizedInner"], sized_inner, "sized frame inner size: {report}");
    for index in 0..3 {
        assert_eq!(report["screen"][index], report["topScreen"]);
    }
    // The frame's own realm agrees with what the parent reads.
    let own = page
        .evaluate_in_frame(0, "[outerWidth, outerHeight, screenX, screenY, screenLeft, screenTop, devicePixelRatio]")
        .unwrap();
    assert_eq!(own, report["top"]);

    assert_eq!(report["cross"], json!(vec!["THROW SecurityError"; 7]), "cross-origin metrics: {report}");
    assert_eq!(
        report["crossSurface"],
        json!([0, true, true, true, true, true, false, 0, "function", null, null])
    );
    let blocked = |action: &str, name: &str, interface: &str| {
        format!(
            "THROW SecurityError: Failed to {action} a named property '{name}' {} '{interface}': Blocked a frame with origin \"{}\" from accessing a cross-origin frame.",
            if action == "set" { "on" } else { "from" },
            server.base
        )
    };
    assert_eq!(
        report["crossThrows"],
        json!([blocked("read", "document", "Window"), blocked("set", "foo", "Window"),
            blocked("read", "href", "Location"),
            format!("THROW SecurityError: Blocked a frame with origin \"{}\" from accessing a cross-origin frame.", server.base)])
    );
    assert_eq!(report["postMessage"], json!(vec![json!([1, "function postMessage() { [native code] }"]); 4]));
}

/// The frame document served by both origins: it reports every message it
/// receives and echoes `cmd: 'echo'` back, and greets its parent on load.
const MESSAGE_FRAME: &str = r#"<!doctype html><html><body>frame<script>
window.__events = 0;
window.__onmessageCount = 0;
onmessage = () => { window.__onmessageCount++; };
addEventListener('message', (e) => {
  window.__events++;
  const d = e.data, p = d && d.payload;
  if (p) window.__lastPayload = p;
  const info = { type: e.type, origin: e.origin, sourceIsParent: e.source === parent, sourceIsTop: e.source === top,
    isTrusted: e.isTrusted, ports: e.ports.length, portsFrozen: Object.isFrozen(e.ports), lastEventId: e.lastEventId,
    ctor: e.constructor.name, bubbles: e.bubbles, cancelable: e.cancelable,
    data: p ? [p.d instanceof Date && p.d.getTime(), p.m instanceof Map && [...p.m], p.s instanceof Set && [...p.s],
      Array.isArray(p.a), p.u8 instanceof Uint8Array && [...p.u8], p.re instanceof RegExp && String(p.re), typeof p.big,
      p.cyc === p, 'u' in p && p.u === undefined, Object.getPrototypeOf(p) === Object.prototype] : null };
  if (d && d.cmd === 'echo') {
    (d.via === 'top' ? top : parent).postMessage({ tag: d.tag, reply: info, onmessageCount: window.__onmessageCount }, '*');
  }
});
const parentOrigin = new URLSearchParams(location.search).get('parent');
parent.postMessage({ tag: 'hello', d: new Date(7), m: new Map([[1, 'a']]), s: new Set([2]), u8: new Uint8Array([9, 8]),
  big: 5n, u: undefined, n: NaN, neg0: -0 }, '*');
parent.postMessage({ tag: 'hello-wrong-origin' }, 'http://wrong.example');
parent.postMessage({ tag: 'hello-slash' }, '/');
parent.postMessage({ tag: 'hello-exact' }, parentOrigin);
top.postMessage({ tag: 'hello-top' }, '*');
</script></body></html>"#;

/// Run with awaitPromise, the way Playwright and Puppeteer evaluate: the
/// replies arrive while the runtime is waiting on this promise.
const MESSAGE_PROBE: &str = r#"(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const so = document.getElementById('so'), xo = document.getElementById('xo');
  const tags = () => window.__msgs.map((m) => m.tag);
  for (let i = 0; i < 100 && tags().filter((t) => t === 'hello').length < 2; i++) await sleep(20);
  await sleep(100);
  const out = { hello: window.__msgs.splice(0) };
  let selfSync = false;
  addEventListener('message', () => { selfSync = true; }, { once: true });
  postMessage({ tag: 'self' }, '*');
  out.selfSync = selfSync;
  const payload = { d: new Date(3), m: new Map([[1, 'a']]), s: new Set([1]), a: [1, 2], u8: new Uint8Array([1, 2, 3]),
    re: /x/g, big: 10n, u: undefined };
  payload.cyc = payload;
  const here = location.origin, there = new URL(xo.src).origin;
  const posts = [['so', '*', 'so-star'], ['so', '/', 'so-slash'], ['so', here, 'so-exact'], ['so', there, 'so-wrong'],
    ['xo', '*', 'xo-star'], ['xo', '/', 'xo-slash'], ['xo', there + '/some/path', 'xo-exact'], ['xo', here, 'xo-wrong']];
  for (const [f, to, tag] of posts) {
    (f === 'so' ? so : xo).contentWindow.postMessage({ cmd: 'echo', tag, payload, via: tag === 'so-star' ? 'top' : 'parent' }, to);
  }
  so.contentWindow.postMessage({ cmd: 'echo', tag: 'so-options' }, { targetOrigin: '*' });
  xo.contentWindow.postMessage({ cmd: 'echo', tag: 'xo-default' });
  out.syncEvents = so.contentWindow.__events;
  const attempt = (f) => { try { f(); return 'no throw'; } catch (e) { return e.name + ': ' + e.message; } };
  out.errors = [attempt(() => so.contentWindow.postMessage(1, 'not a url')),
    attempt(() => so.contentWindow.postMessage(() => 1, '*')).split(':')[0],
    attempt(() => xo.contentWindow.postMessage()),
    attempt(() => postMessage(document.body, '*')).split(':')[0]];
  for (let i = 0; i < 150 && window.__msgs.length < 7; i++) await sleep(20);
  await sleep(100);
  const lastPayload = so.contentWindow.__lastPayload;
  out.clonedIntoFrame = [lastPayload !== payload, Object.prototype.toString.call(lastPayload.d), lastPayload.d !== payload.d,
    lastPayload.d.getTime()];
  out.replies = window.__msgs.splice(0).sort((a, b) => a.tag.localeCompare(b.tag));
  out.onmessageCount = window.__onmessageCount;
  return out;
})()"#;

fn message_page(other_origin: &str) -> String {
    format!(
        r#"<!doctype html><html><head><script>
window.__msgs = [];
window.__onmessageCount = 0;
onmessage = () => {{ window.__onmessageCount++; }};
addEventListener('message', (e) => {{
  const d = e.data, so = document.getElementById('so'), xo = document.getElementById('xo');
  window.__msgs.push({{ tag: d.tag, origin: e.origin, fromSo: e.source === so.contentWindow, fromXo: e.source === xo.contentWindow,
    fromSelf: e.source === window, isTrusted: e.isTrusted, ports: e.ports.length, lastEventId: e.lastEventId, type: e.type,
    ctor: e.constructor.name, reply: d.reply || null, onmessageCount: d.onmessageCount || null,
    data: d.tag === 'hello' ? [d.d instanceof Date && d.d.getTime(), d.m instanceof Map && [...d.m], d.s instanceof Set && [...d.s],
      d.u8 instanceof Uint8Array && [...d.u8], typeof d.big, 'u' in d && d.u === undefined, Number.isNaN(d.n), Object.is(d.neg0, -0),
      Object.getPrototypeOf(d) === Object.prototype] : null }});
}});
</script></head><body>page<script>
// The frames learn the page's origin from their URL, for the exact-origin case.
for (const [id, base] of [['so', ''], ['xo', '{other_origin}']]) {{
  const frame = document.createElement('iframe');
  frame.id = id;
  frame.src = base + '/msgframe?parent=' + encodeURIComponent(location.origin);
  document.body.appendChild(frame);
}}
</script></body></html>"#
    )
}

/// postMessage between a page and its same- and cross-origin frames, in both
/// directions, against Chrome 151's behaviour (offline probe): the payload is
/// a structured clone (Date, Map, Set, typed arrays, RegExp, BigInt,
/// undefined, NaN, -0 and cycles survive, and the receiver gets its own
/// objects), targetOrigin '*', '/', an exact origin and the options bag are
/// honoured and a mismatch is dropped silently, delivery is an asynchronous
/// trusted MessageEvent with the sender's origin, `source` naming the sender's
/// window as the receiver sees it, frozen empty `ports` and an empty
/// `lastEventId`, and both `onmessage` and listeners run. Replies to a page
/// that is awaiting them inside a CDP evaluation must arrive.
#[tokio::test(flavor = "current_thread")]
async fn post_message_between_page_and_frames_matches_chrome() {
    let frame = ("/msgframe".to_string(), ("text/html", MESSAGE_FRAME.as_bytes().to_vec()));
    let other_origin = Server::with_routes(None, Arc::new(HashMap::from([frame.clone()])));
    let server = Server::with_routes(
        None,
        Arc::new(HashMap::from([frame, ("/msg".to_string(), ("text/html", message_page(&other_origin.base).into_bytes()))])),
    );
    let mut page = open(&context(true, 0x6d55_0b19), &format!("{}/msg", server.base)).await;
    wait_for_frames(&mut page, 2).await;
    let info = page
        .evaluate_for_cdp_with_timeout(MESSAGE_PROBE, true, true, 15_000)
        .await
        .expect("the awaited exchange with the frames never finished");
    assert!(!info.thrown, "probe threw: {info:?}");
    let report = info.value.expect("probe value");
    let here = server.base.clone();
    let there = other_origin.base.clone();

    let event = |tag: &str, origin: &str, from_so: bool| {
        json!({ "tag": tag, "origin": origin, "fromSo": from_so, "fromXo": !from_so, "fromSelf": false, "isTrusted": true,
            "ports": 0, "lastEventId": "", "type": "message", "ctor": "MessageEvent", "reply": null, "onmessageCount": null,
            "data": if tag == "hello" { json!([7, [[1, "a"]], [2], [9, 8], "bigint", true, true, true, true]) } else { Value::Null } })
    };
    let mut hello: Vec<Value> = report["hello"].as_array().expect("hello list").clone();
    hello.sort_by_key(|m| (m["origin"].as_str().unwrap().to_string(), m["tag"].as_str().unwrap().to_string()));
    let mut expected = vec![
        event("hello", &here, true), event("hello-exact", &here, true), event("hello-slash", &here, true), event("hello-top", &here, true),
        event("hello", &there, false), event("hello-exact", &there, false), event("hello-top", &there, false),
    ];
    expected.sort_by_key(|m| (m["origin"].as_str().unwrap().to_string(), m["tag"].as_str().unwrap().to_string()));
    assert_eq!(Value::Array(hello), Value::Array(expected), "frame -> page messages");

    assert_eq!(report["selfSync"], json!(false), "postMessage delivered synchronously");
    assert_eq!(report["syncEvents"], json!(0), "a message reached the frame synchronously");
    assert_eq!(
        report["errors"],
        json!([
            "SyntaxError: Failed to execute 'postMessage' on 'Window': Invalid target origin 'not a url' in a call to 'postMessage'.",
            "DataCloneError",
            "TypeError: Failed to execute 'postMessage' on 'Window': 1 argument required, but only 0 present.",
            "DataCloneError",
        ])
    );
    assert_eq!(report["clonedIntoFrame"], json!([true, "[object Date]", true, 3]), "the frame got the page's own object");

    let reply = |tag: &str, from_so: bool, count: u32, with_payload: bool| {
        let mut message = event(tag, if from_so { &here } else { &there }, from_so);
        message["onmessageCount"] = json!(count);
        message["reply"] = json!({ "type": "message", "origin": here, "sourceIsParent": true, "sourceIsTop": true,
            "isTrusted": true, "ports": 0, "portsFrozen": true, "lastEventId": "", "ctor": "MessageEvent",
            "bubbles": false, "cancelable": false,
            "data": if with_payload { json!([3, [[1, "a"]], [1], true, [1, 2, 3], "/x/g", "bigint", true, true, true]) } else { Value::Null } });
        message
    };
    let self_message = json!({ "tag": "self", "origin": here, "fromSo": false, "fromXo": false, "fromSelf": true,
        "isTrusted": true, "ports": 0, "lastEventId": "", "type": "message", "ctor": "MessageEvent", "reply": null,
        "onmessageCount": null, "data": null });
    assert_eq!(
        report["replies"],
        json!([
            self_message,
            reply("so-exact", true, 3, true), reply("so-options", true, 4, false), reply("so-slash", true, 2, true),
            reply("so-star", true, 1, true), reply("xo-exact", false, 2, true), reply("xo-star", false, 1, true),
        ]),
        "page -> frame -> page round trips"
    );
    // Every delivered message ran onmessage as well as the listener.
    assert_eq!(report["onmessageCount"], json!(7 + 7));
}

// ---------------------------------------------------------------------------
// Opt-in: the real libraries.

/// Pinned builds, verified by sha256 after download and never stored in the
/// repository: FingerprintJS OSS 4.6.2 (npm dist) and CreepJS at a fixed commit.
const REAL_LIBRARIES: &[(&str, &str, &str)] = &[
    ("/fp.umd.min.js", "https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@4.6.2/dist/fp.umd.min.js",
     "42a7829e58db56b2ca0c6d09c1a2a52a96de1e04220dec22dd65650ccb6b997b"),
    ("/creepjs/creep.js", "https://raw.githubusercontent.com/abrahamjuliot/creepjs/10aa6724cd33a1015db1574211890518cd04f0cc/docs/creep.js",
     "80f43f364bd973bc03cb5b82de033ce28b2bbb145cb04237632a46ef040a92be"),
    ("/creepjs/index.html", "https://raw.githubusercontent.com/abrahamjuliot/creepjs/10aa6724cd33a1015db1574211890518cd04f0cc/docs/index.html",
     "e59328901b58f9cd77776a282a9de8c01aa57e4ea36b3e94283050807ae28b59"),
    ("/creepjs/style.min.css", "https://raw.githubusercontent.com/abrahamjuliot/creepjs/10aa6724cd33a1015db1574211890518cd04f0cc/docs/style.min.css",
     "6756a37800b6050c73d799a5099da121b3498d75ed01577d84f3e182e105cbd3"),
];

fn sha256_hex(bytes: &[u8]) -> String {
    // Small dependency-free SHA-256 for the pin check.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut message = bytes.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((bytes.len() as u64) * 8).to_be_bytes());
    for chunk in message.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}

#[test]
fn sha256_pin_check_matches_known_digests() {
    assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

const FPJS_PAGE: &str = r#"<!doctype html><html><head><script src="/fp.umd.min.js"></script></head><body><script>
FingerprintJS.load({ monitoring: false }).then((agent) => agent.get()).then((r) => { globalThis.__result = r.visitorId; })
  .catch((e) => { globalThis.__result = 'error: ' + e; });
</script></body></html>"#;

/// Lies the gate tolerates, with the reason: CreepJS estimates the Chrome
/// version from which CSS properties, JS builtins and window interfaces exist,
/// and the engine implements a subset of Chrome's platform. That is an engine
/// coverage gap, not a spoofed surface, and it is not a prototype lie.
fn allowed_lie(api: &str, lie: &str) -> bool {
    api == "Navigator.userAgent"
        && lie.starts_with('v')
        && lie.contains(" failed ")
        && lie.ends_with(" versions")
        && ["CSS", "JS", "Window"].iter().any(|kind| lie.contains(&format!(" {kind} features by ")))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "opt-in: downloads pinned FingerprintJS and CreepJS builds (network) and runs the offline gates"]
async fn real_libraries_fingerprintjs_and_creepjs_pass_the_stealth_gates() {
    let client = obscura_net::ObscuraHttpClient::new();
    let mut routes: HashMap<String, (&'static str, Vec<u8>)> = HashMap::new();
    for (path, url, pin) in REAL_LIBRARIES {
        let response = client.fetch(&url::Url::parse(url).unwrap()).await.expect("download");
        assert_eq!(&sha256_hex(&response.body), pin, "{url} does not match its pinned sha256");
        let kind = if path.ends_with(".js") { "text/javascript" } else if path.ends_with(".css") { "text/css" } else { "text/html" };
        routes.insert(path.to_string(), (kind, response.body));
    }
    routes.insert("/fpjs.html".into(), ("text/html", FPJS_PAGE.as_bytes().to_vec()));
    let server = Server::with_routes(None, Arc::new(routes));
    let mut results = Vec::new();
    for seed in [0x51u32, 0x52] {
        let profile = context(true, seed);
        let mut page = Page::new("real-libraries".into(), profile.clone());
        let mut visitor = Vec::new();
        let mut creep = Vec::new();
        for _ in 0..2 {
            page.navigate(&format!("{}/fpjs.html", server.base)).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Value::String(id) = page.evaluate("globalThis.__result || null") {
                    visitor.push(id);
                    break;
                }
                assert!(Instant::now() < deadline, "FingerprintJS did not finish");
                page.settle(50).await;
            }
            page.navigate(&format!("{}/creepjs/index.html", server.base)).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(45);
            let report = loop {
                let value = page.evaluate(
                    "(() => { const f = window.Fingerprint, t = document.body ? document.body.innerText : ''; \
                      const id = (t.match(/FP ID:\\s*([0-9a-f]{64})/) || [])[1]; \
                      return f && id && f.lies ? JSON.stringify({ id, lies: f.lies.data || {}, headless: f.headless }) : null; })()",
                );
                if let Value::String(json) = value {
                    break serde_json::from_str::<Value>(&json).unwrap();
                }
                assert!(Instant::now() < deadline, "CreepJS did not compute an FP ID");
                page.settle(100).await;
            };
            for (api, kinds) in report["lies"].as_object().unwrap() {
                for kind in kinds.as_array().unwrap() {
                    assert!(allowed_lie(api, kind.as_str().unwrap()), "CreepJS lie: {api}: {kind}");
                }
            }
            let headless = &report["headless"];
            assert_eq!(headless["stealthRating"], 0, "{headless}");
            assert_eq!(headless["headlessRating"], 0, "{headless}");
            assert!(headless["stealth"].as_object().unwrap().values().all(|flag| flag == false), "{headless}");
            creep.push(report["id"].as_str().unwrap().to_string());
        }
        assert_eq!(visitor[0], visitor[1], "FingerprintJS visitorId changed within a profile");
        assert!(!visitor[0].starts_with("error"), "{visitor:?}");
        assert_eq!(creep[0], creep[1], "CreepJS FP ID changed within a profile");
        results.push((visitor[0].clone(), creep[0].clone()));
    }
    assert_ne!(results[0].0, results[1].0, "two profiles share a FingerprintJS visitorId");
    assert_ne!(results[0].1, results[1].1, "two profiles share a CreepJS FP ID");
}
