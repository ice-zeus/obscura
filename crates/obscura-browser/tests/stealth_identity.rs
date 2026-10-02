//! The stealth browser names one Chrome version everywhere: the HTTP
//! User-Agent and client hints the transport sends, navigator.userAgent and
//! navigator.userAgentData. A site that compares them must find no mismatch.
#![cfg(feature = "stealth")]

use obscura_browser::{BrowserContext, Page};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn serve_once() -> (String, Arc<Mutex<Option<HashMap<String, String>>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let captured = Arc::new(Mutex::new(None));
    let headers = captured.clone();
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
            let head = String::from_utf8_lossy(&data).to_string();
            let mut slot = headers.lock().unwrap();
            if slot.is_none() {
                *slot = Some(
                    head.lines()
                        .skip(1)
                        .filter_map(|line| line.split_once(':'))
                        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                        .collect(),
                );
            }
            let body = "<!doctype html><html><body>identity</body></html>";
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (base, captured)
}

#[tokio::test(flavor = "current_thread")]
async fn http_and_javascript_name_the_same_chrome() {
    let (base, captured) = serve_once();
    let context = Arc::new(BrowserContext::with_storage_and_network(
        "default".into(),
        None,
        true,
        None,
        None,
        true,
    ));
    let mut page = Page::new("identity".into(), context);
    page.navigate(&format!("{base}/")).await.unwrap();
    let headers = captured.lock().unwrap().clone().expect("document request");
    let js = page.evaluate(
        r#"(() => ({
          userAgent: navigator.userAgent,
          appVersion: navigator.appVersion,
          platform: navigator.platform,
          brands: navigator.userAgentData.brands.map(b => `"${b.brand}";v="${b.version}"`).join(', '),
          uaPlatform: navigator.userAgentData.platform,
          mobile: navigator.userAgentData.mobile,
        }))()"#,
    );
    page.evaluate(
        r#"(() => { globalThis.__hev = null; navigator.userAgentData.getHighEntropyValues(
            ['fullVersionList', 'uaFullVersion', 'platformVersion']).then(v => { globalThis.__hev = v; }); return true; })()"#,
    );
    page.settle(50).await;
    let high = page.evaluate("globalThis.__hev");

    let major = obscura_net::STEALTH_USER_AGENT
        .split("Chrome/")
        .nth(1)
        .and_then(|rest| rest.split('.').next())
        .unwrap()
        .to_string();
    assert_eq!(headers["user-agent"], obscura_net::STEALTH_USER_AGENT);
    assert_eq!(js["userAgent"], obscura_net::STEALTH_USER_AGENT);
    assert_eq!(js["appVersion"], obscura_net::STEALTH_USER_AGENT.trim_start_matches("Mozilla/"));
    assert_eq!(js["platform"], obscura_net::STEALTH_NAVIGATOR_PLATFORM);
    assert_eq!(headers["sec-ch-ua"], js["brands"].as_str().unwrap());
    assert!(headers["sec-ch-ua"].contains(&format!("\"Google Chrome\";v=\"{major}\"")));
    assert!(headers["sec-ch-ua"].contains(&format!("\"Chromium\";v=\"{major}\"")));
    assert_eq!(headers["sec-ch-ua-platform"], format!("\"{}\"", js["uaPlatform"].as_str().unwrap()));
    assert_eq!(headers["sec-ch-ua-mobile"], "?0");
    assert_eq!(js["mobile"], false);
    assert_eq!(high["uaFullVersion"], format!("{major}.0.0.0"));
    assert_eq!(high["platformVersion"], obscura_net::STEALTH_UA_PLATFORM_VERSION);
    for entry in high["fullVersionList"].as_array().unwrap() {
        let brand = entry["brand"].as_str().unwrap();
        if brand == "Google Chrome" || brand == "Chromium" {
            assert_eq!(entry["version"], format!("{major}.0.0.0"));
        }
    }
}
