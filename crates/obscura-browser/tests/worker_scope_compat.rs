//! Worker scopes that fingerprinting scripts such as CreepJS probe.
//!
//! CreepJS asks a SharedWorker for its scope's navigator values and gives up
//! after three seconds. The SharedWorker shim used to return an inert port, so
//! every page that probes it waited for the full timeout, and the values it
//! then read in other realms disagreed with the page.

use obscura_browser::{BrowserContext, Page};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn serve() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
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
            let path = String::from_utf8_lossy(&data).split_whitespace().nth(1).unwrap_or("/").to_string();
            let (kind, body) = if path.starts_with("/worker.js") {
                ("text/javascript", "self.addEventListener('connect', e => { const port = e.ports[0]; port.onmessage = m => port.postMessage('fetched:' + m.data); });")
            } else {
                ("text/html", "<!doctype html><html><body>worker scope</body></html>")
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    base
}

async fn page() -> (Page, String) {
    let base = serve();
    let context = Arc::new(BrowserContext::with_storage_and_network(
        "default".into(),
        None,
        cfg!(feature = "stealth"),
        None,
        None,
        true,
    ));
    let mut page = Page::new("worker-scope".into(), context);
    page.navigate(&format!("{base}/")).await.unwrap();
    (page, base)
}

async fn wait(page: &mut Page, expression: &str, within: Duration) -> serde_json::Value {
    let deadline = Instant::now() + within;
    loop {
        let value = page.evaluate(expression);
        if !value.is_null() {
            return value;
        }
        if Instant::now() >= deadline {
            let state = page.evaluate("JSON.stringify(globalThis.__shared)");
            panic!("no result for {expression}; state {state}");
        }
        page.settle(20).await;
    }
}

// CreepJS's getSharedWorker()/getWorkerData() round trip, reduced: the worker
// script recognises its scope by `globalThis.SharedWorkerGlobalScope` and
// replies through the port it receives in the connect event.
#[tokio::test(flavor = "current_thread")]
async fn shared_worker_connects_and_answers_through_its_port() {
    let (mut page, _) = page().await;
    page.evaluate(
        r#"(() => {
          globalThis.__shared = null;
          const source = `
            const isWorker = !self.document && !!self.WorkerGlobalScope;
            const reply = port => port.postMessage({
              isWorker,
              sharedScope: typeof globalThis.SharedWorkerGlobalScope,
              hardwareConcurrency: navigator.hardwareConcurrency,
              userAgent: navigator.userAgent,
            });
            globalThis.SharedWorkerGlobalScope ? addEventListener('connect', e => reply(e.ports[0])) : reply(self);
          `;
          const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
          const started = Date.now();
          const worker = new SharedWorker(url);
          worker.port.start();
          worker.port.onmessage = event => {
            globalThis.__shared = { ...event.data, ms: Date.now() - started,
              pageSharedScope: typeof SharedWorkerGlobalScope,
              pageHardwareConcurrency: navigator.hardwareConcurrency, pageUserAgent: navigator.userAgent };
          };
          return true;
        })()"#,
    );
    let reply = wait(&mut page, "globalThis.__shared", Duration::from_secs(2)).await;
    assert_eq!(reply["isWorker"], true);
    assert_eq!(reply["sharedScope"], "function");
    assert_eq!(reply["pageSharedScope"], "undefined", "the page realm must not see the worker scope");
    assert_eq!(reply["hardwareConcurrency"], reply["pageHardwareConcurrency"]);
    assert_eq!(reply["userAgent"], reply["pageUserAgent"]);
    assert!(reply["ms"].as_u64().unwrap() < 1000, "shared worker answered late: {reply}");
}

// Two constructors for the same script share one worker; each gets its own
// port and its own connect event. A fetched script works the same way.
#[tokio::test(flavor = "current_thread")]
async fn shared_worker_instances_share_one_script_with_separate_ports() {
    let (mut page, _) = page().await;
    page.evaluate(
        r#"(() => {
          globalThis.__shared = {};
          const source = 'let connections = 0; onconnect = e => { const n = ++connections; const port = e.ports[0]; port.onmessage = m => port.postMessage(m.data + ":" + n); };';
          const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
          const a = new SharedWorker(url), b = new SharedWorker(url, 'same-script'), c = new SharedWorker(url);
          a.port.onmessage = e => { __shared.a = e.data; };
          b.port.onmessage = e => { __shared.b = e.data; };
          c.port.onmessage = e => { __shared.c = e.data; };
          a.port.postMessage('a'); b.port.postMessage('b'); c.port.postMessage('c');
          const fetched = new SharedWorker('/worker.js');
          fetched.port.onmessage = e => { __shared.fetched = e.data; };
          fetched.port.postMessage('x');
          return true;
        })()"#,
    );
    let all = wait(
        &mut page,
        "(__shared.a && __shared.b && __shared.c && __shared.fetched) ? __shared : null",
        Duration::from_secs(5),
    )
    .await;
    // a and c share one worker (two connections); the named instance is separate.
    let mut shared = [all["a"].as_str().unwrap().to_string(), all["c"].as_str().unwrap().to_string()];
    shared.sort();
    assert_eq!(shared, ["a:1".to_string(), "c:2".to_string()]);
    assert_eq!(all["b"], "b:1");
    assert_eq!(all["fetched"], "fetched:x");
}
