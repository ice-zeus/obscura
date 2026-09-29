//! Offline navigation wire and CDP subscription regressions.
use super::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

#[derive(Debug, Clone)]
struct Wire {
    path: String,
    method: String,
    headers: HashMap<String, String>,
    body: String,
}
struct Fixture {
    base: String,
    records: Arc<Mutex<Vec<Wire>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let records = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (captured, stopped) = (records.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut data = Vec::new();
                let boundary = loop {
                    if let Some(index) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        break index + 4;
                    }
                    let mut buffer = [0; 4096];
                    let n = stream.read(&mut buffer).unwrap();
                    assert_ne!(n, 0);
                    data.extend_from_slice(&buffer[..n]);
                    assert!(data.len() < 1024 * 1024);
                };
                let head = String::from_utf8(data[..boundary].to_vec()).unwrap();
                let mut lines = head.split("\r\n");
                let mut first = lines.next().unwrap().split_whitespace();
                let method = first.next().unwrap().to_string();
                let path = first.next().unwrap().to_string();
                let headers: HashMap<String, String> = lines
                    .filter_map(|line| {
                        line.split_once(':')
                            .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().into()))
                    })
                    .collect();
                let length: usize = headers
                    .get("content-length")
                    .map(|value| value.parse().unwrap())
                    .unwrap_or(0);
                assert!(length < 1024 * 1024);
                while data.len() - boundary < length {
                    let mut buffer = [0; 4096];
                    let n = stream.read(&mut buffer).unwrap();
                    assert_ne!(n, 0);
                    data.extend_from_slice(&buffer[..n]);
                }
                let body = String::from_utf8(data[boundary..boundary + length].to_vec()).unwrap();
                captured.lock().unwrap().push(Wire {
                    path: path.clone(),
                    method,
                    headers,
                    body,
                });
                if path == "/lost" {
                    continue;
                }
                let (status, location, body) = match path.as_str() {
                    "/submit" => (302, "Location: /accepted\r\n", ""),
                    "/accepted" => (
                        200,
                        "",
                        "<!doctype html><script>location.href='/final'</script>",
                    ),
                    "/to-data" => (
                        200,
                        "",
                        "<!doctype html><script>location.href='data:text/html,%3Cbody%3Edata-final%3C/body%3E'</script>",
                    ),
                    _ => (200, "", "<!doctype html><body>accepted</body>"),
                };
                write!(stream,"HTTP/1.1 {status} Fixture\r\n{location}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        Self {
            base,
            records,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Err(error) = self.thread.take().unwrap().join() {
            if std::thread::panicking() {
                eprintln!("navigation fixture worker failed during cleanup");
            } else {
                std::panic::resume_unwind(error);
            }
        }
    }
}
fn context(stealth: bool) -> (CdpContext, String, Option<String>, Option<String>) {
    let browser = Arc::new(obscura_browser::BrowserContext::with_storage_and_network(
        "fixture".into(),
        None,
        stealth,
        None,
        None,
        true,
    ));
    let mut ctx = CdpContext::new_with_shared_context(browser);
    let page = ctx.create_page();
    let primary = Some(format!("{page}-primary"));
    let audit = Some(format!("{page}-audit"));
    ctx.sessions.insert(primary.clone().unwrap(), page.clone());
    ctx.sessions.insert(audit.clone().unwrap(), page.clone());
    (ctx, page, primary, audit)
}
async fn enable(ctx: &mut CdpContext, session: &Option<String>) {
    super::super::network::handle("enable", &json!({}), ctx, session)
        .await
        .unwrap();
}
async fn check_navigation(stealth: bool) {
    let fixture = Fixture::new();
    let (mut ctx, page, primary, audit) = context(stealth);
    enable(&mut ctx, &primary).await;
    enable(&mut ctx, &audit).await;
    let other = ctx.create_page();
    let unrelated = Some("unrelated-session".into());
    ctx.sessions
        .insert(unrelated.clone().unwrap(), other.clone());
    enable(&mut ctx, &unrelated).await;
    super::super::network::handle(
        "setUserAgentOverride",
        &json!({"userAgent":"FixtureIdentity/22"}),
        &mut ctx,
        &primary,
    )
    .await
    .unwrap();
    super::super::network::handle(
        "setExtraHTTPHeaders",
        &json!({"headers":{"sec-ch-ua":"Fixture Hint","x-fixture":"selected"}}),
        &mut ctx,
        &primary,
    )
    .await
    .unwrap();
    let result=do_navigate(&format!("{}/submit",fixture.base),&json!({"__method":"POST","__body":"notes=line+one%0D%0Aline+two&extra=first&extra=second"}),&mut ctx,&primary).await.unwrap();
    let wire = fixture.records.lock().unwrap().clone();
    assert_eq!(wire.len(), 3);
    assert_eq!(
        wire.iter().map(|row| row.path.as_str()).collect::<Vec<_>>(),
        ["/submit", "/accepted", "/final"]
    );
    assert_eq!(
        wire.iter()
            .map(|row| row.method.as_str())
            .collect::<Vec<_>>(),
        ["POST", "GET", "GET"]
    );
    assert_eq!(
        wire[0].body,
        "notes=line+one%0D%0Aline+two&extra=first&extra=second"
    );
    assert!(wire[1].body.is_empty());
    for session in [&primary, &audit] {
        let events = ctx
            .pending_events
            .iter()
            .filter(|event| &event.session_id == session && event.method.starts_with("Network."))
            .collect::<Vec<_>>();
        let requests = events
            .iter()
            .filter(|event| event.method == "Network.requestWillBeSent")
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 3);
        for (event, actual) in requests.iter().zip(&wire) {
            assert_eq!(event.params["request"]["method"], actual.method);
            for name in ["user-agent", "sec-ch-ua", "x-fixture"] {
                assert_eq!(
                    event.params["request"]["headers"][name],
                    actual.headers[name]
                );
            }
            assert_eq!(event.params["requestId"], event.params["loaderId"]);
        }
        assert_eq!(requests[0].params["request"]["postData"], wire[0].body);
        assert_eq!(requests[0].params["request"]["hasPostData"], true);
        assert_eq!(requests[1].params["request"]["hasPostData"], false);
        assert!(requests[1].params["request"].get("postData").is_none());
        assert_eq!(
            requests[0].params["requestId"],
            requests[1].params["requestId"]
        );
        assert_eq!(requests[1].params["redirectResponse"]["status"], 302);
        assert_ne!(
            requests[1].params["requestId"],
            requests[2].params["requestId"]
        );
        assert_eq!(requests[2].params["requestId"], result["loaderId"]);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.method == "Network.responseReceived")
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.method == "Network.loadingFinished")
                .count(),
            2
        );
    }
    assert!(
        !ctx.pending_events
            .iter()
            .any(|event| event.session_id == unrelated && event.method.starts_with("Network."))
    );
    let last_request = ctx
        .pending_events
        .iter()
        .rposition(|event| event.method == "Network.requestWillBeSent")
        .unwrap();
    let frame = ctx
        .pending_events
        .iter()
        .position(|event| event.method == "Page.frameNavigated")
        .unwrap();
    assert!(last_request < frame);
    assert!(
        ctx.get_page_mut(&page)
            .unwrap()
            .take_navigation_exchanges()
            .is_empty(),
        "one drain only"
    );
    let body = super::super::network::handle(
        "getResponseBody",
        &json!({"requestId":result["loaderId"]}),
        &mut ctx,
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(body["body"], "<!doctype html><body>accepted</body>");
    ctx.pending_events.clear();
    super::super::network::handle("disable", &json!({}), &mut ctx, &primary)
        .await
        .unwrap();
    assert!(
        super::super::network::handle(
            "getResponseBody",
            &json!({"requestId":result["loaderId"]}),
            &mut ctx,
            &audit
        )
        .await
        .is_ok(),
        "another enabled session retains the body alias"
    );
    super::super::network::handle("disable", &json!({}), &mut ctx, &None)
        .await
        .unwrap();
    assert!(
        super::super::network::handle(
            "getResponseBody",
            &json!({"requestId":result["loaderId"]}),
            &mut ctx,
            &audit
        )
        .await
        .is_err(),
        "legacy browser-level disable clears response bodies"
    );
    do_navigate(
        &format!("{}/final", fixture.base),
        &json!({}),
        &mut ctx,
        &primary,
    )
    .await
    .unwrap();
    assert!(
        ctx.pending_events
            .iter()
            .filter(|event| event.method.starts_with("Network."))
            .all(|event| event.session_id == audit)
    );
    assert_eq!(
        ctx.pending_events
            .iter()
            .filter(|event| event.method == "Network.requestWillBeSent")
            .count(),
        1
    );
    ctx.pending_events.clear();
    super::super::target::handle(
        "detachFromTarget",
        &json!({"sessionId":audit}),
        &mut ctx,
        &None,
    )
    .await
    .unwrap();
    assert!(ctx.network_sessions_for_page(&page).is_empty());
    do_navigate(
        &format!("{}/final", fixture.base),
        &json!({}),
        &mut ctx,
        &primary,
    )
    .await
    .unwrap();
    assert!(
        !ctx.pending_events
            .iter()
            .any(|event| event.method.starts_with("Network.")),
        "disabled/detached subscriptions do not receive or replay events"
    );
    assert!(
        ctx.get_page_mut(&page)
            .unwrap()
            .take_navigation_exchanges()
            .is_empty()
    );
    ctx.remove_page(&other);
    assert!(
        !ctx.network_enabled_sessions
            .contains(unrelated.as_ref().unwrap())
    );
}
#[tokio::test]
async fn ordinary_navigation_trace_preserves_post_redirects_and_session_ownership() {
    check_navigation(false).await;
}
#[cfg(feature = "stealth")]
#[tokio::test]
async fn stealth_navigation_trace_preserves_post_redirects_and_session_ownership() {
    check_navigation(true).await;
}

#[tokio::test]
async fn failed_navigation_reports_attempt_without_inventing_response_or_load() {
    let fixture = Fixture::new();
    let (mut ctx, page, primary, audit) = context(false);
    enable(&mut ctx, &audit).await;
    assert!(
        do_navigate(
            &format!("{}/lost", fixture.base),
            &json!({"__method":"POST","__body":"x=owned"}),
            &mut ctx,
            &primary
        )
        .await
        .is_err()
    );
    assert_eq!(fixture.records.lock().unwrap().len(), 1);
    let events = &ctx.pending_events;
    assert_eq!(
        events
            .iter()
            .map(|event| event.method.as_str())
            .collect::<Vec<_>>(),
        ["Network.requestWillBeSent", "Network.loadingFailed"]
    );
    assert!(events.iter().all(|event| event.session_id == audit));
    assert_eq!(events[0].params["request"]["postData"], "x=owned");
    assert!(
        ctx.get_page_mut(&page)
            .unwrap()
            .take_navigation_exchanges()
            .is_empty()
    );
}

#[test]
fn unavailable_navigation_body_and_response_remain_unavailable() {
    let hop = obscura_net::client::NavigationExchange {
        request: obscura_net::RequestInfo {
            url: url::Url::parse("https://fixture.test/").unwrap(),
            method: "POST".into(),
            headers: HashMap::new(),
            resource_type: obscura_net::ResourceType::Document,
        },
        post_data: None,
        has_post_data: true,
        status: None,
        response_headers: HashMap::new(),
        response_body_size: None,
        failed: true,
        timestamp: 1.0,
    };
    let (before, after) = transport_navigation_events(&[vec![hop]], "frame", "loader", true);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].params["request"]["hasPostData"], true);
    assert!(before[0].params["request"].get("postData").is_none());
    assert!(before[0].params["request"].get("postDataEntries").is_none());
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].method, "Network.loadingFailed");
}

#[test]
fn captured_navigation_body_entries_preserve_empty_and_utf8_bytes() {
    use base64::Engine as _;
    for body in ["", "notes=雪&symbol=🐈"] {
        let hop = obscura_net::client::NavigationExchange {
            request: obscura_net::RequestInfo {
                url: url::Url::parse("https://fixture.test/").unwrap(),
                method: "POST".into(),
                headers: HashMap::new(),
                resource_type: obscura_net::ResourceType::Document,
            },
            post_data: Some(body.into()),
            has_post_data: true,
            status: Some(200),
            response_headers: HashMap::new(),
            response_body_size: Some(0),
            failed: false,
            timestamp: 1.0,
        };
        let (before, _) = transport_navigation_events(&[vec![hop]], "frame", "loader", true);
        let request = &before[0].params["request"];
        assert_eq!(request["postData"], body);
        assert_eq!(request["hasPostData"], true);
        let entries = request["postDataEntries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(base64::engine::general_purpose::STANDARD
            .decode(entries[0]["bytes"].as_str().unwrap()).unwrap(), body.as_bytes());
    }
}

#[tokio::test]
async fn bodyless_form_evaluation_emits_post_to_the_observer_session() {
    let fixture = Fixture::new();
    let (mut ctx, _page, primary, audit) = context(false);
    enable(&mut ctx, &audit).await;
    do_navigate(
        &format!("{}/final", fixture.base),
        &json!({}),
        &mut ctx,
        &primary,
    )
    .await
    .unwrap();
    ctx.pending_events.clear();
    let script = "(()=>{const form=document.createElement('form');form.method='POST';form.action='/final';document.body.appendChild(form);form.submit();return true})()";
    let _ = super::super::runtime::handle(
        "evaluate",
        &json!({"expression":script,"returnByValue":true}),
        &mut ctx,
        &primary,
    )
    .await;
    let wire = fixture.records.lock().unwrap();
    assert_eq!(wire.len(), 2);
    assert_eq!(wire[1].method, "POST");
    assert_eq!(wire[1].body, "");
    let requests = ctx
        .pending_events
        .iter()
        .filter(|event| event.method == "Network.requestWillBeSent")
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].session_id, audit);
    assert_eq!(requests[0].params["request"]["method"], "POST");
    assert_eq!(requests[0].params["request"]["postDataEntries"], json!([{"bytes":""}]));
    assert_eq!(requests[0].params["request"]["postData"], "");
    assert_eq!(requests[0].params["request"]["hasPostData"], true);
}

#[tokio::test]
async fn client_navigation_without_http_trace_keeps_its_own_loader_and_method() {
    let fixture = Fixture::new();
    let (mut ctx, page, primary, audit) = context(false);
    enable(&mut ctx, &audit).await;
    let result = do_navigate(
        &format!("{}/to-data", fixture.base),
        &json!({"__method":"POST","__body":"x=owned"}),
        &mut ctx,
        &primary,
    )
    .await
    .unwrap();
    let wire = fixture.records.lock().unwrap();
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].method, "POST");
    let requests = ctx
        .pending_events
        .iter()
        .filter(|event| event.method == "Network.requestWillBeSent")
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].params["request"]["method"], "POST");
    assert_ne!(requests[0].params["requestId"], result["loaderId"]);
    assert_eq!(requests[1].params["requestId"], result["loaderId"]);
    assert_eq!(requests[1].params["request"]["method"], "GET");
    assert!(requests[1].params["request"].get("postData").is_none());
    let body = super::super::network::handle(
        "getResponseBody",
        &json!({"requestId":result["loaderId"]}),
        &mut ctx,
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(body["body"], "<body>data-final</body>");
    assert!(
        ctx.get_page_mut(&page)
            .unwrap()
            .take_navigation_exchanges()
            .is_empty()
    );
}
