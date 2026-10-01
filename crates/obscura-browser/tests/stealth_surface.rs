//! Native-looking browser API surface and per-profile rendering variance.
//!
//! Fingerprinting scripts (CreepJS's prototype "lie" detector, FingerprintJS)
//! test every API they read for the shape of a natively implemented function
//! and compare readbacks of canvas content. These tests run the same checks:
//! - every patched member reads as native code, is not constructible, owns only
//!   `length` and `name`, and its getters reject a prototype receiver;
//! - `error.stack` is formatted the way V8 formats it in Chrome and, in stealth
//!   mode, never shows the engine's own frames;
//! - canvas output varies per profile in stealth mode only, deterministically,
//!   and stays exact wherever Chrome is exact (blank canvases, solid fills).

use obscura_browser::{BrowserContext, Page};
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

struct Server {
    base: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn new() -> Self {
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
                let body = if path.starts_with("/frame") {
                    "<!doctype html><html><body>frame</body></html>".to_string()
                } else {
                    "<!doctype html><html><body>page<iframe src=\"/frame\"></iframe></body></html>".to_string()
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

fn context(stealth: bool, seed: u32) -> Arc<BrowserContext> {
    Arc::new(
        BrowserContext::with_storage_and_network("default".into(), None, stealth, None, None, true)
            .with_fingerprint_seed(seed),
    )
}

async fn open(context: &Arc<BrowserContext>, url: &str) -> Page {
    let mut page = Page::new("surface-page".into(), context.clone());
    page.navigate(url).await.unwrap();
    page
}

/// CreepJS's per-API checks (`queryLies`), including the proxy checks it only
/// enables once it suspects `Function.prototype.toString`.
const LIE_CHECKS: &str = r#"(() => {
  const AT_FUNCTION = /at Function\.toString /, AT_OBJECT = /at Object\.toString/;
  const FUNCTION_INSTANCE = /at (Function\.)?\[Symbol.hasInstance\]/, PROXY_INSTANCE = /at (Proxy\.)?\[Symbol.hasInstance\]/;
  const isTypeError = (e) => e && e.constructor && e.constructor.name === 'TypeError';
  const failsTypeError = (spawn, withStack) => {
    try { spawn(); throw Error(); } catch (e) { return !isTypeError(e) || (withStack ? withStack(e) : false); }
  };
  const line = (e, i = 1) => String(e.stack).split('\n')[i] || '';
  const known = (name) => new Set([`function ${name}() { [native code] }`, `function get ${name}() { [native code] }`, 'function () { [native code] }']);
  const query = (fn, proto, obj) => {
    const name = fn.name.replace(/get\s/, ''), nativeProto = Object.getPrototypeOf(fn), lies = [];
    const check = (label, failed) => { if (failed) lies.push(label); };
    if (obj) check('illegal error', failsTypeError(() => obj.prototype[name]));
    check('new instance', failsTypeError(() => new fn()));
    check('class extends', failsTypeError(() => { class Fake extends fn {} }));
    check('null conversion', (() => { try { return failsTypeError(() => Object.setPrototypeOf(fn, null).toString()); } finally { Object.setPrototypeOf(fn, nativeProto); } })());
    check('toString', !known(name).has(Function.prototype.toString.call(fn)) || !known('toString').has(Function.prototype.toString.call(fn.toString)));
    check('prototype in function', 'prototype' in fn);
    check('own keys', Reflect.ownKeys(fn).map(String).sort().join() !== 'length,name');
    check('object toString', failsTypeError(() => Object.create(fn).toString(), (e) => !AT_FUNCTION.test(line(e)))
      || failsTypeError(() => Object.create(new Proxy(fn, {})).toString(), (e) => !AT_OBJECT.test(line(e))));
    check('instanceof', failsTypeError(() => fn instanceof fn, (e) => !FUNCTION_INSTANCE.test(line(e)))
      || failsTypeError(() => { const p = new Proxy(fn, {}); p instanceof p; }, (e) => !PROXY_INSTANCE.test(line(e))));
    check('too much recursion', (() => { try { return failsTypeError(() => Object.setPrototypeOf(fn, Object.create(fn)).toString()); } finally { Object.setPrototypeOf(fn, nativeProto); } })());
    check('define properties', (() => { try { Object.defineProperty(fn, '', { configurable: true }).toString(); Reflect.deleteProperty(fn, ''); return false; } catch (e) { return true; } })());
    return lies;
  };
  const targets = [
    [Function, 'toString'], [HTMLCanvasElement, 'getContext'], [HTMLCanvasElement, 'toDataURL'],
    [HTMLCanvasElement, 'toBlob'], [Navigator, 'userAgent'], [Navigator, 'hardwareConcurrency'],
    [Navigator, 'deviceMemory'], [Navigator, 'platform'], [Navigator, 'plugins'], [Navigator, 'webdriver'],
    [Navigator, 'languages'], [Navigator, 'getBattery'], [Screen, 'width'], [Screen, 'height'],
    [Screen, 'availWidth'], [Screen, 'colorDepth'], [Document, 'referrer'], [Document, 'getElementsByTagNameNS'],
    [Element, 'replaceWith'], [Element, 'getBoundingClientRect'], [Element, 'clientWidth'], [Element, 'offsetHeight'],
    [Element, 'scrollWidth'], [Element, 'contentWindow'], [SpeechSynthesis, 'getVoices'],
    [PluginArray, 'item'], [PluginArray, 'length'], [MimeType, 'type'], [Math, 'acos'], [Date, 'getTimezoneOffset'],
  ];
  const result = {};
  for (const [owner, name] of targets) {
    const proto = owner.prototype || owner;
    const d = Object.getOwnPropertyDescriptor(proto, name);
    if (!d) { result[`${owner.name}.${name}`] = ['missing']; continue; }
    const fn = typeof d.value === 'function' ? d.value : d.get;
    const lies = query(fn, proto, typeof d.value === 'function' ? null : owner);
    if (lies.length) result[`${owner.name}.${name}`] = lies;
  }
  let stack = '';
  try { null.x; } catch (e) { stack = e.stack; }
  let wrapped = '';
  try { HTMLCanvasElement.prototype.getContext.call({}); } catch (e) { wrapped = e.stack; }
  return {
    lies: result,
    navigatorOwn: Object.getOwnPropertyNames(navigator),
    screenOwn: Object.getOwnPropertyNames(screen),
    speechOwn: Object.getOwnPropertyNames(speechSynthesis),
    navigatorTag: Object.prototype.toString.call(navigator),
    // Automation-supplied code (this evaluation) is named <eval>; anything
    // else bracketed is the engine's own.
    internalFrames: [stack, wrapped].join('\n').split('\n')
      .filter((l) => /<obscura:|ext:|<(?!eval>|eval-remote>|preload>)[a-z:-]+>:/.test(l)),
    illegalStack: line({ stack: wrapped }, 0),
  };
})()"#;

#[cfg(feature = "stealth")]
#[tokio::test(flavor = "current_thread")]
async fn stealth_api_surface_passes_creepjs_prototype_lie_checks() {
    let server = Server::new();
    let mut page = open(&context(true, 7), &format!("{}/page", server.base)).await;
    let report = page.evaluate(LIE_CHECKS);
    assert_eq!(report["lies"], serde_json::json!({}), "{report}");
    assert_eq!(report["navigatorOwn"], serde_json::json!([]), "navigator has own properties");
    assert_eq!(report["screenOwn"], serde_json::json!([]), "screen has own properties");
    assert_eq!(report["speechOwn"], serde_json::json!([]));
    assert_eq!(report["navigatorTag"], "[object Navigator]");
    assert_eq!(report["internalFrames"], serde_json::json!([]), "engine frames leak into stacks: {report}");
    // Navigator getters and plugins stay usable through the normalized surface.
    let navigator = page.evaluate(
        "[typeof navigator.userAgent, navigator.webdriver, navigator.plugins.length, navigator.mimeTypes.length, \
          navigator.plugins[0] instanceof Plugin, navigator.mimeTypes[0].enabledPlugin === navigator.plugins[0], \
          Object.getOwnPropertyNames(navigator.plugins).includes('Chrome PDF Viewer'), Object.keys(navigator.plugins).join(), \
          Object.values(navigator.plugins[1]).every((m) => m instanceof MimeType && navigator.mimeTypes.namedItem(m.type) === m), \
          navigator.plugins.namedItem('PDF Viewer') === navigator.plugins[0], Array.from(navigator.plugins).length]",
    );
    assert_eq!(navigator, serde_json::json!(["string", false, 5, 2, true, true, true, "0,1,2,3,4", true, true, 5]));
}

#[tokio::test(flavor = "current_thread")]
async fn error_stacks_use_v8_frame_format_and_honour_prepare_stack_trace() {
    let server = Server::new();
    for stealth in [false, cfg!(feature = "stealth")] {
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
            serde_json::json!([
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
  // Geometry only (no text): independent of the profile's glyph outlines.
  const shape = canvas(100, 100), cs = shape.getContext('2d');
  const g = cs.createRadialGradient(50, 50, 5, 50, 50, 50); g.addColorStop(0, '#123456'); g.addColorStop(1, '#fedcba');
  cs.fillStyle = g; cs.beginPath(); cs.arc(50, 50, 40, 0, Math.PI * 2); cs.fill();
  // Exact operations: blank canvases and CreepJS's solid-fill pixel round trip.
  const blank = canvas(64, 32), fresh = canvas(64, 32), bx = blank.getContext('2d');
  bx.fillText('x', 4, 10); bx.clearRect(0, 0, 64, 32);
  const k1 = canvas(8, 8).getContext('2d'), k2 = canvas(8, 8).getContext('2d');
  let pixelDiffs = 0;
  for (let x = 0; x < 8; x++) for (let y = 0; y < 8; y++) {
    const c = [(x * 37 + y * 11) % 256, (x * 101 + y * 7) % 256, (x * 13 + y * 59) % 256];
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
    blankExact: blank.toDataURL() === fresh.toDataURL() && !bx.getImageData(0, 0, 64, 32).data.some((v) => v),
    pixelDiffs,
    width: measure.measureText('Cwm fjordbank glyphs').width,
    emptyWidth: measure.measureText('').width,
  };
})()"#;

async fn scene(stealth: bool, seed: u32, server: &Server) -> serde_json::Value {
    let mut page = open(&context(stealth, seed), &format!("{}/page", server.base)).await;
    let value = page.evaluate(SCENE);
    assert!(value.is_object(), "scene failed: {value}");
    value
}

#[cfg(feature = "stealth")]
#[tokio::test(flavor = "current_thread")]
async fn stealth_canvas_variance_is_stable_per_profile_and_exact_where_chrome_is() {
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
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while page.frame_urls().is_empty() {
        assert!(std::time::Instant::now() < deadline, "frame did not load");
        page.settle(20).await;
    }
    assert_eq!(page.evaluate_in_frame(0, SCENE).unwrap(), a);
}

#[tokio::test(flavor = "current_thread")]
async fn without_stealth_canvas_geometry_is_identical_for_every_profile() {
    let server = Server::new();
    let a = scene(false, 0xa11ce, &server).await;
    let b = scene(false, 0xb0b, &server).await;
    assert_eq!(a["shape"], b["shape"], "no rendering variance outside stealth mode");
    assert_eq!(a["width"], 240.0);
    assert_eq!(a["pixelDiffs"], 0);
    assert_eq!(a["blankExact"], true);
}

#[cfg(feature = "stealth")]
#[tokio::test(flavor = "current_thread")]
async fn stealth_audio_and_media_queries_are_consistent() {
    let server = Server::new();
    let mut page = open(&context(true, 3), &format!("{}/page", server.base)).await;
    page.evaluate(
        r#"(() => {
          globalThis.__audio = null;
          const silent = new OfflineAudioContext(1, 100, 44100), quiet = silent.createOscillator();
          quiet.frequency.value = 0; quiet.start(0);
          const idle = new OfflineAudioContext(1, 5000, 44100).createAnalyser();
          const bins = new Float32Array(idle.frequencyBinCount); idle.getFloatFrequencyData(bins);
          const ctx = new OfflineAudioContext(1, 5000, 44100), osc = ctx.createOscillator(), comp = ctx.createDynamicsCompressor();
          osc.type = 'triangle'; osc.frequency.value = 10000; osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
          Promise.all([silent.startRendering(), ctx.startRendering()]).then(([a, b]) => {
            const s = a.getChannelData(0), d = b.getChannelData(0);
            let sum = 0; for (let i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
            globalThis.__audio = [new Set(s).size === 1 && s[0] === 0, new Set(bins).size === 1 && bins[0] === -Infinity,
              d.slice(0, 265).every((v) => v === 0), d[300] !== 0, Math.abs(sum - 124.0434) < 0.01];
          });
        })()"#,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let audio = loop {
        let value = page.evaluate("globalThis.__audio");
        if !value.is_null() {
            break value;
        }
        assert!(std::time::Instant::now() < deadline, "audio did not render");
        page.settle(20).await;
    };
    assert_eq!(audio, serde_json::json!([true, true, true, true, true]));
    let media = page.evaluate(
        "[matchMedia(`(device-width: ${screen.width}px) and (device-height: ${screen.height}px)`).matches, \
          matchMedia(`(resolution: ${devicePixelRatio}dppx)`).matches, matchMedia('(min-resolution: 2dppx)').matches, \
          matchMedia(`(max-device-width: ${screen.width - 1}px)`).matches]",
    );
    assert_eq!(media, serde_json::json!([true, true, false, false]));
}
