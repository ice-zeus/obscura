//! Exercise subscription commands through the actual WebSocket ingress.
use super::*;
use base64::Engine as _;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn command(socket: &mut Socket, id: u64, method: &str, session: Option<&str>, params: Value)
    -> Vec<Value>
{
    let mut request = json!({"id": id, "method": method, "params": params});
    if let Some(session) = session { request["sessionId"] = json!(session); }
    socket.send(Message::Text(request.to_string().into())).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut replies = Vec::new();
        loop {
            let message = socket.next().await.expect("WebSocket reply").unwrap();
            let Message::Text(text) = message else { panic!("unexpected WebSocket frame") };
            let value: Value = serde_json::from_str(&text).unwrap();
            let done = value["id"] == id;
            if done { assert!(value.get("error").is_none(), "{value}"); }
            replies.push(value);
            if done { return replies; }
        }
    }).await.expect("bounded CDP command")
}

fn network(replies: &[Value]) -> Vec<&Value> {
    replies.iter().filter(|value| value["method"].as_str()
        .is_some_and(|method| method.starts_with("Network."))).collect()
}

fn assert_subscribers(replies: &[Value], sessions: &[&str]) {
    let events = network(replies);
    assert!(!events.is_empty(), "navigation must produce Network events");
    let mut actual = events.iter().map(|value| value["sessionId"].as_str().unwrap())
        .collect::<Vec<_>>();
    actual.sort_unstable(); actual.dedup();
    let mut expected = sessions.to_vec(); expected.sort_unstable();
    assert_eq!(actual, expected);
    for session in sessions {
        let own = events.iter().filter(|value| value["sessionId"] == *session).collect::<Vec<_>>();
        assert_eq!(own.iter().filter(|value| value["method"] == "Network.requestWillBeSent").count(), 1);
        assert_eq!(own.iter().filter(|value| value["method"] == "Network.responseReceived").count(), 1);
        assert_eq!(own.iter().filter(|value| value["method"] == "Network.loadingFinished").count(), 1);
    }
}

async fn websocket_navigation_subscriptions(stealth: bool) {
    tokio::task::LocalSet::new().run_until(async {
        let fixture_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", fixture_listener.local_addr().unwrap());
        let (wire_tx, mut wire_rx) = mpsc::unbounded_channel();
        let fixture = tokio::task::spawn_local(async move {
            loop {
                let (mut stream, _) = fixture_listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let boundary = loop {
                    if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
                    let mut buffer = [0; 4096];
                    let size = stream.read(&mut buffer).await.unwrap(); assert_ne!(size, 0);
                    bytes.extend_from_slice(&buffer[..size]); assert!(bytes.len() < 65536);
                };
                let head = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
                let first = head.lines().next().unwrap().to_string();
                let length: usize = head.lines().filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse().unwrap()).unwrap_or(0);
                while bytes.len() < boundary + length {
                    let mut buffer = [0; 4096];
                    let size = stream.read(&mut buffer).await.unwrap(); assert_ne!(size, 0);
                    bytes.extend_from_slice(&buffer[..size]); assert!(bytes.len() < 65536);
                }
                wire_tx.send((first.clone(), bytes[boundary..boundary + length].to_vec())).unwrap();
                let (status, headers, body) = if first.starts_with("POST /submit ") {
                    (302, "Location: /accepted\r\n", "")
                } else {
                    (200, "", "<!doctype html><form id='form' method='post' action='/submit'><input name='notes' value='a&amp;b雪'><input name='notes' value='second'></form>")
                };
                let reply = format!("HTTP/1.1 {status} Fixture\r\n{headers}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (server_tx, server_rx) = mpsc::unbounded_channel();
        let connection = tokio::task::spawn_local(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection_ws(stream, server_tx).await.unwrap();
        });
        let context = obscura_browser::BrowserContext::with_storage_and_network(
            "websocket-network".into(), None, stealth, None, None, true);
        let processor = tokio::task::spawn_local(cdp_processor(
            server_rx, Arc::new(context), Arc::new(Notify::new()),
        ));
        let (mut socket, _) = tokio_tungstenite::connect_async(endpoint).await.unwrap();
        let created = command(&mut socket, 1, "Target.createTarget", None, json!({"url":"about:blank"})).await;
        let page = created.last().unwrap()["result"]["targetId"].as_str().unwrap().to_string();
        let primary = format!("{page}-session");
        let attached = command(&mut socket, 2, "Target.attachToTarget", None, json!({"targetId":page,"flatten":true})).await;
        let audit = attached.last().unwrap()["result"]["sessionId"].as_str().unwrap().to_string();
        let other = command(&mut socket, 3, "Target.createTarget", None, json!({"url":"about:blank"})).await;
        let foreign = format!("{}-session", other.last().unwrap()["result"]["targetId"].as_str().unwrap());
        for (id, session) in [(4, primary.as_str()), (5, audit.as_str()), (6, foreign.as_str()), (7, primary.as_str())] {
            command(&mut socket, id, "Network.enable", Some(session), json!({})).await;
        }
        // Browser-level enable has no page subscription; repeated enable must
        // not duplicate events. All commands traverse handle_connection_ws.
        command(&mut socket, 8, "Network.enable", None, json!({})).await;
        command(&mut socket, 9, "Runtime.enable", Some(&primary), json!({})).await;
        let mut first = command(&mut socket, 10, "Page.navigate", Some(&primary), json!({"url":format!("{origin}/form")})).await;
        first.extend(command(&mut socket, 11, "Runtime.evaluate", Some(&primary), json!({"expression":"true","returnByValue":true})).await);
        assert_subscribers(&first, &[&primary, &audit]);
        let frame = first.iter().find(|value| value["method"] == "Page.frameNavigated").unwrap()["params"]["frame"]["id"].as_str().unwrap().to_string();
        let world = command(&mut socket, 12, "Page.createIsolatedWorld", Some(&primary), json!({"frameId":frame,"worldName":"network-regression"})).await;
        let context_id = world.last().unwrap()["result"]["executionContextId"].clone();
        let handle = command(&mut socket, 13, "Runtime.evaluate", Some(&primary), json!({"expression":"({run(fn) { return fn(); }})","contextId":context_id})).await;
        let object = handle.last().unwrap()["result"]["result"]["objectId"].as_str().unwrap().to_string();
        let submitted = command(&mut socket, 14, "Runtime.callFunctionOn", Some(&primary), json!({
            "functionDeclaration":"function(utility) { return utility.run(() => { document.getElementById('form').submit(); return 'submitted'; }); }",
            "objectId":object,"arguments":[{"objectId":object}],"awaitPromise":true,"returnByValue":true,
        })).await;
        assert_eq!(submitted.last().unwrap()["result"]["result"]["value"], "submitted");
        let events = network(&submitted);
        assert!(!events.iter().any(|value| value["sessionId"] == foreign));
        let navigated = submitted.iter().position(|value| value["method"] == "Page.frameNavigated").unwrap();
        for session in [&primary, &audit] {
            let requests = events.iter().filter(|value| value["sessionId"] == *session && value["method"] == "Network.requestWillBeSent").collect::<Vec<_>>();
            assert_eq!(requests.len(), 2);
            let post = &requests[0]["params"];
            assert_eq!(post["request"]["method"], "POST");
            assert_eq!(post["requestId"], post["loaderId"]);
            assert_eq!(post["frameId"], frame);
            assert_eq!(post["type"], "Document");
            let body = "notes=a%26b%E9%9B%AA&notes=second";
            assert_eq!(post["request"]["postData"], body);
            let entries = post["request"]["postDataEntries"].as_array().unwrap(); assert_eq!(entries.len(), 1);
            assert_eq!(base64::engine::general_purpose::STANDARD.decode(entries[0]["bytes"].as_str().unwrap()).unwrap(), body.as_bytes());
            assert_eq!(requests[1]["params"]["request"]["method"], "GET");
            assert_eq!(requests[1]["params"]["redirectResponse"]["status"], 302);
            assert_eq!(requests[1]["params"]["requestId"], post["requestId"]);
            assert!(requests[1]["params"]["request"].get("postDataEntries").is_none());
            assert_eq!(events.iter().filter(|value| value["sessionId"] == *session && value["method"] == "Network.responseReceived" && value["params"]["response"]["status"] == 200).count(), 1);
            let index = submitted.iter().position(|value| value == *requests[0]).unwrap();
            assert!(index < navigated, "request precedes frame navigation");
        }
        command(&mut socket, 15, "Network.disable", Some(&audit), json!({})).await;
        let mut primary_only = command(&mut socket, 16, "Page.navigate", Some(&primary), json!({"url":format!("{origin}/again")})).await;
        primary_only.extend(command(&mut socket, 17, "Runtime.evaluate", Some(&primary), json!({"expression":"true"})).await);
        assert_subscribers(&primary_only, &[&primary]);
        command(&mut socket, 18, "Network.enable", Some(&audit), json!({})).await;
        command(&mut socket, 19, "Target.detachFromTarget", None, json!({"sessionId":audit})).await;
        let mut detached = command(&mut socket, 20, "Page.navigate", Some(&primary), json!({"url":format!("{origin}/after-detach")})).await;
        detached.extend(command(&mut socket, 21, "Runtime.evaluate", Some(&primary), json!({"expression":"true"})).await);
        assert_subscribers(&detached, &[&primary]);
        command(&mut socket, 22, "Network.disable", Some(&primary), json!({})).await;
        let mut disabled = command(&mut socket, 23, "Page.navigate", Some(&primary), json!({"url":format!("{origin}/disabled")})).await;
        disabled.extend(command(&mut socket, 24, "Runtime.evaluate", Some(&primary), json!({"expression":"true"})).await);
        assert!(network(&disabled).is_empty());
        command(&mut socket, 25, "Network.enable", Some(&primary), json!({})).await;
        let mut recovered = command(&mut socket, 26, "Page.navigate", Some(&primary), json!({"url":format!("{origin}/recovered")})).await;
        recovered.extend(command(&mut socket, 27, "Runtime.evaluate", Some(&primary), json!({"expression":"true"})).await);
        assert_subscribers(&recovered, &[&primary]);
        socket.close(None).await.unwrap();
        connection.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), processor).await.unwrap().unwrap();
        fixture.abort(); let _ = fixture.await;
        let wire = std::iter::from_fn(|| wire_rx.try_recv().ok()).collect::<Vec<_>>();
        assert_eq!(wire.len(), 7);
        let posts = wire.iter().filter(|(head, _)| head.starts_with("POST ")).collect::<Vec<_>>();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].1, b"notes=a%26b%E9%9B%AA&notes=second");
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_websocket_network_subscription_and_call_function_form_navigation() {
    websocket_navigation_subscriptions(false).await;
}

#[cfg(feature = "stealth")]
#[tokio::test(flavor = "current_thread")]
async fn stealth_websocket_network_subscription_and_call_function_form_navigation() {
    websocket_navigation_subscriptions(true).await;
}

async fn receive_until(socket: &mut Socket, replies: &mut Vec<Value>, done: impl Fn(&[Value]) -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !done(replies) {
            let Message::Text(text) = socket.next().await.expect("WebSocket event").unwrap()
                else { panic!("unexpected WebSocket frame") };
            replies.push(serde_json::from_str(&text).unwrap());
        }
    }).await.expect("bounded continued-response event");
}

async fn continued_script_response(stealth: bool) {
    tokio::task::LocalSet::new().run_until(async {
        let fixture_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", fixture_listener.local_addr().unwrap());
        let release = Arc::new(Notify::new());
        let wire_release = release.clone();
        let (wire_tx, mut wire_rx) = mpsc::unbounded_channel();
        let fixture = tokio::task::spawn_local(async move {
            loop {
                let (mut stream, _) = fixture_listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut bytes = [0; 4096];
                    let count = stream.read(&mut bytes).await.unwrap(); assert_ne!(count, 0);
                    request.extend_from_slice(&bytes[..count]); assert!(request.len() < 65536);
                }
                let path = String::from_utf8_lossy(&request).split_whitespace().nth(1).unwrap().to_string();
                wire_tx.send(path.clone()).unwrap();
                let body = match path.as_str() {
                    "/asset" | "/held" => "globalThis.__networkAsset=41;/*雪*/",
                    "/during" => "<!doctype html><script>const s=document.createElement('script');s.src='/asset';document.head.appendChild(s);</script>",
                    _ => "<!doctype html><body>response fixture</body>",
                };
                let content_type = if path == "/asset" || path == "/held" { "text/javascript; charset=utf-8" } else { "text/html; charset=utf-8" };
                let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: public, max-age=900\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                stream.write_all(reply.as_bytes()).await.unwrap();
                if path == "/held" { wire_release.notified().await; }
                stream.write_all(body.as_bytes()).await.unwrap();
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (server_tx, server_rx) = mpsc::unbounded_channel();
        let connection = tokio::task::spawn_local(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection_ws(stream, server_tx).await.unwrap();
        });
        let context = obscura_browser::BrowserContext::with_storage_and_network(
            "continued-response".into(), None, stealth, None, None, true);
        let processor = tokio::task::spawn_local(cdp_processor(server_rx, Arc::new(context), Arc::new(Notify::new())));
        let (mut socket, _) = tokio_tungstenite::connect_async(endpoint).await.unwrap();
        let created = command(&mut socket, 1, "Target.createTarget", None, json!({"url":"about:blank"})).await;
        let page = created.last().unwrap()["result"]["targetId"].as_str().unwrap().to_string();
        let owner = format!("{page}-session");
        command(&mut socket, 2, "Network.enable", Some(&owner), json!({})).await;
        command(&mut socket, 3, "Runtime.enable", Some(&owner), json!({})).await;
        command(&mut socket, 4, "Page.navigate", Some(&owner), json!({"url":format!("{origin}/page")})).await;
        command(&mut socket, 5, "Fetch.enable", Some(&owner), json!({"patterns":[{"urlPattern":"*"}]})).await;
        // Attach observers only after the pause. Focused's inherited pause
        // selection among several live sessions is outside this regression.
        let mut events = command(&mut socket, 6, "Runtime.callFunctionOn", Some(&owner), json!({
            "functionDeclaration":"function(url) { const s=document.createElement('script');s.src=url;document.body.appendChild(s);return 'scheduled'; }",
            "arguments":[{"value":format!("{origin}/asset")}],"returnByValue":true,
        })).await;
        receive_until(&mut socket, &mut events, |rows| rows.iter().any(|r| r["method"] == "Fetch.requestPaused")).await;
        let paused = events.iter().find(|r| r["method"] == "Fetch.requestPaused").unwrap();
        assert_eq!(paused["sessionId"], owner);
        let request = paused["params"]["requestId"].as_str().unwrap().to_string();
        assert_eq!(paused["params"]["networkId"], request);
        let attached = command(&mut socket, 7, "Target.attachToTarget", None, json!({"targetId":page,"flatten":true})).await;
        let audit = attached.last().unwrap()["result"]["sessionId"].as_str().unwrap().to_string();
        command(&mut socket, 8, "Network.enable", Some(&audit), json!({})).await;
        let attached = command(&mut socket, 9, "Target.attachToTarget", None, json!({"targetId":page,"flatten":true})).await;
        let disabled = attached.last().unwrap()["result"]["sessionId"].as_str().unwrap().to_string();
        command(&mut socket, 10, "Network.enable", Some(&disabled), json!({})).await;
        command(&mut socket, 11, "Network.disable", Some(&disabled), json!({})).await;
        let other = command(&mut socket, 12, "Target.createTarget", None, json!({"url":"about:blank"})).await;
        let foreign_page = other.last().unwrap()["result"]["targetId"].as_str().unwrap().to_string();
        let foreign = format!("{foreign_page}-session");
        command(&mut socket, 13, "Network.enable", Some(&foreign), json!({})).await;
        events.extend(command(&mut socket, 14, "Fetch.continueRequest", Some(&owner), json!({"requestId":request})).await);
        receive_until(&mut socket, &mut events, |rows| rows.iter().filter(|r| r["method"] == "Network.loadingFinished" && r["params"]["requestId"] == request).count() == 2).await;
        for session in [&owner, &audit] {
            for method in ["Network.requestWillBeSent", "Network.responseReceived", "Network.loadingFinished"] {
                assert_eq!(events.iter().filter(|r| r["sessionId"] == *session && r["method"] == method && r["params"]["requestId"] == request).count(), 1, "{session} {method}: {events:?}");
            }
            let response = events.iter().find(|r| r["sessionId"] == *session && r["method"] == "Network.responseReceived" && r["params"]["requestId"] == request).unwrap();
            assert_eq!(response["params"]["response"]["status"], 200);
            assert_eq!(response["params"]["response"]["headers"]["cache-control"], "public, max-age=900");
        }
        assert!(!network(&events).iter().any(|r| r["sessionId"] == disabled || r["sessionId"] == foreign));
        assert_eq!(events.iter().filter(|r| r["method"] == "Fetch.requestPaused").count(), 1);
        let body = command(&mut socket, 15, "Network.getResponseBody", Some(&audit), json!({"requestId":request})).await;
        assert_eq!(body.last().unwrap()["result"]["body"], "globalThis.__networkAsset=41;/*雪*/");
        assert_eq!(body.last().unwrap()["result"]["base64Encoded"], false);
        command(&mut socket, 16, "Target.detachFromTarget", None, json!({"sessionId":audit})).await;
        command(&mut socket, 17, "Target.detachFromTarget", None, json!({"sessionId":disabled})).await;
        command(&mut socket, 18, "Target.closeTarget", None, json!({"targetId":foreign_page})).await;

        // A rejected navigation must not retire a still-pending old response.
        let mut held = command(&mut socket, 19, "Runtime.evaluate", Some(&owner), json!({
            "expression":format!("fetch('{origin}/held').then(r=>r.text()).then(t=>globalThis.heldText=t);'scheduled'"),"returnByValue":true,
        })).await;
        receive_until(&mut socket, &mut held, |rows| rows.iter().any(|r| r["method"] == "Fetch.requestPaused")).await;
        let held_id = held.iter().find(|r| r["method"] == "Fetch.requestPaused").unwrap()["params"]["requestId"].as_str().unwrap().to_string();
        held.extend(command(&mut socket, 20, "Fetch.continueRequest", Some(&owner), json!({"requestId":held_id})).await);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while wire_rx.recv().await.unwrap() != "/held" {}
        }).await.unwrap();
        for (id, url) in [(21, "http://["), (22, "file:///not-permitted-response-fixture")] {
            socket.send(Message::Text(json!({"id":id,"method":"Page.navigate","sessionId":owner,"params":{"url":url}}).to_string().into())).await.unwrap();
            let mut rejected = Vec::new();
            receive_until(&mut socket, &mut rejected, |rows| rows.iter().any(|r| r["id"] == id)).await;
            assert!(rejected.iter().find(|r| r["id"] == id).unwrap().get("error").is_some());
            held.extend(rejected);
        }
        release.notify_one();
        receive_until(&mut socket, &mut held, |rows| rows.iter().any(|r| r["method"] == "Network.loadingFinished" && r["params"]["requestId"] == held_id)).await;
        assert_eq!(held.iter().filter(|r| r["method"] == "Network.requestWillBeSent" && r["params"]["requestId"] == held_id).count(), 1);
        let body = command(&mut socket, 23, "Network.getResponseBody", Some(&owner), json!({"requestId":held_id})).await;
        assert_eq!(body.last().unwrap()["result"]["body"], "globalThis.__networkAsset=41;/*雪*/");

        // Runtime replacement may restart intercept counters. Navigation-time
        // scripts must not receive a second synthetic Fetch pause afterwards.
        socket.send(Message::Text(json!({"id":24,"method":"Page.navigate","sessionId":owner,"params":{"url":format!("{origin}/during"),"waitUntil":"load"}}).to_string().into())).await.unwrap();
        let mut during = Vec::new();
        let mut continued = std::collections::HashSet::new();
        let mut next = 100;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let Message::Text(text) = socket.next().await.unwrap().unwrap() else { panic!("text frame") };
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["method"] == "Fetch.requestPaused" && value["params"]["request"]["url"] == format!("{origin}/asset") {
                    let id = value["params"]["requestId"].as_str().unwrap().to_string();
                    assert!(continued.insert(id.clone()), "duplicate actual/synthetic pause");
                    socket.send(Message::Text(json!({"id":next,"method":"Fetch.continueRequest","sessionId":owner,"params":{"requestId":id}}).to_string().into())).await.unwrap();next += 1;
                }
                let done = value["method"] == "Page.loadEventFired";
                during.push(value);
                if done { break; }
            }
        }).await.unwrap();
        assert_eq!(continued.len(), 1);
        let current = continued.into_iter().next().unwrap();
        let response = command(&mut socket, 25, "Network.getResponseBody", Some(&owner), json!({"requestId":current})).await;
        during.extend(response.clone());
        assert_eq!(response.last().unwrap()["result"]["body"], "globalThis.__networkAsset=41;/*雪*/");
        assert_eq!(during.iter().filter(|r| r["method"] == "Network.requestWillBeSent" && r["params"]["requestId"] == current).count(), 1);
        assert_eq!(during.iter().filter(|r| r["method"] == "Fetch.requestPaused" && r["params"]["requestId"] == current).count(), 1);
        assert_eq!(during.iter().filter(|r| r["method"] == "Network.responseReceived" && r["params"]["requestId"] == current).count(), 1);
        assert_eq!(during.iter().filter(|r| r["method"] == "Network.loadingFinished" && r["params"]["requestId"] == current).count(), 1);
        command(&mut socket, 26, "Fetch.disable", Some(&owner), json!({})).await;
        let mut recovery = command(&mut socket, 27, "Runtime.evaluate", Some(&owner), json!({"expression":format!("fetch('{origin}/asset').then(r=>r.text());'scheduled'"),"returnByValue":true})).await;
        receive_until(&mut socket, &mut recovery, |rows| rows.iter().any(|r| r["method"] == "Network.loadingFinished")).await;
        assert!(!recovery.iter().any(|r| r["method"] == "Fetch.requestPaused"));
        let id = recovery.iter().find(|r| r["method"] == "Network.responseReceived").unwrap()["params"]["requestId"].clone();
        let body = command(&mut socket, 28, "Network.getResponseBody", Some(&owner), json!({"requestId":id})).await;
        assert_eq!(body.last().unwrap()["result"]["body"], "globalThis.__networkAsset=41;/*雪*/");
        socket.close(None).await.unwrap();connection.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), processor).await.unwrap().unwrap();
        fixture.abort();let _ = fixture.await;
    }).await;
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_websocket_continued_script_response_identity_body_and_recovery() {
    continued_script_response(false).await;
}

#[cfg(feature = "stealth")]
#[tokio::test(flavor = "current_thread")]
async fn stealth_websocket_continued_script_response_identity_body_and_recovery() {
    continued_script_response(true).await;
}

#[test]
fn continued_response_resolutions_preserve_session_scope_and_cleanup() {
    use obscura_js::ops::InterceptResolution;
    let mut ctx = CdpContext::new();
    let page = ctx.create_page();
    let foreign = ctx.create_page();
    ctx.sessions.insert("owner".into(), page.clone());
    ctx.sessions.insert("foreign".into(), foreign.clone());
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
    let mut paused = InterceptedPauses::new();
    let mut receivers = Vec::new();
    for (session, target) in [("owner", &page), ("foreign", &foreign)] {
        let (resolver, receiver) = tokio::sync::oneshot::channel();
        paused.insert((Some(session.into()), "same-id".into()), InterceptedPause {
            page_id: Some(target.clone()), resolver,
        });
        ctx.note_intercepted_network_request(target, "same-id", session);
        receivers.push(receiver);
    }
    let command = |session: &str, method: &str| json!({
        "id": 71, "sessionId": session, "method": method,
        "params": {"requestId":"same-id", "errorReason":"Aborted", "responseCode":201,
            "responseHeaders":[{"name":"X-Fixture","value":"kept"}], "body":"aGVsbG8="},
    }).to_string();
    assert!(!handle_fetch_resolution(&command("unrelated", "Fetch.failRequest"), &mut ctx, &reply_tx, &mut paused));
    assert!(!handle_fetch_resolution(&command("owner", "Fetch.getResponseBody"), &mut ctx, &reply_tx, &mut paused));
    assert_eq!(paused.len(), 2);
    assert_eq!(ctx.intercepted_network_requests.len(), 2);
    assert!(reply_rx.try_recv().is_err());
    assert!(handle_fetch_resolution(&command("owner", "Fetch.failRequest"), &mut ctx, &reply_tx, &mut paused));
    assert!(matches!(receivers[0].try_recv(), Ok(InterceptResolution::Fail { reason }) if reason == "Aborted"));
    assert!(!ctx.intercepted_network_requests.contains_key(&(page.clone(), "same-id".into())));
    assert!(ctx.intercepted_network_requests.contains_key(&(foreign.clone(), "same-id".into())));
    assert_eq!(paused.len(), 1);
    assert!(handle_fetch_resolution(&command("foreign", "Fetch.fulfillRequest"), &mut ctx, &reply_tx, &mut paused));
    match receivers[1].try_recv().unwrap() {
        InterceptResolution::Fulfill { status, headers, body, body_base64 } => {
            assert_eq!(status, 201);
            assert_eq!(headers.get("X-Fixture").map(String::as_str), Some("kept"));
            assert_eq!(body, "hello");
            assert_eq!(body_base64, "aGVsbG8=");
        }
        other => panic!("unexpected resolution: {other:?}"),
    }
    assert!(paused.is_empty());
    assert!(ctx.intercepted_network_requests.is_empty());
    assert!(!handle_fetch_resolution(&command("foreign", "Fetch.fulfillRequest"), &mut ctx, &reply_tx, &mut paused));
    let replies = std::iter::from_fn(|| reply_rx.try_recv().ok())
        .map(|text| serde_json::from_str::<Value>(&text).unwrap()).collect::<Vec<_>>();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["sessionId"], "owner");
    assert_eq!(replies[1]["sessionId"], "foreign");
    assert!(replies.iter().all(|reply| reply["id"] == 71 && reply.get("error").is_none()));
    assert!(ctx.pending_events.is_empty(), "Fail/Fulfill do not invent completion telemetry");
}

#[tokio::test(flavor = "current_thread")]
async fn continued_response_idle_cleanup_retires_residual_records_only_for_live_page() {
    let mut ctx = CdpContext::new();
    let page = ctx.create_page();
    let foreign = ctx.create_page();
    let session = Some("owner".to_string());
    ctx.sessions.insert("owner".into(), page.clone());
    crate::domains::page::handle("navigate", &json!({
        "url":"data:text/html,<body>idle cleanup</body>", "waitUntil":"load",
    }), &mut ctx, &session).await.unwrap();
    ctx.pending_events.clear();
    // Each of these paths can settle without a successful response event.
    for request in ["cors-rejected", "rewrite-blocked", "network-error", "canceled"] {
        ctx.note_intercepted_network_request(&page, request, "owner");
    }
    ctx.note_intercepted_network_request(&foreign, "same-id", "foreign");
    assert!(!ctx.get_page_mut(&page).unwrap().has_pending_script_network_requests());
    sync_live_page_background_events(&mut ctx);
    assert_eq!(ctx.intercepted_network_requests.len(), 1);
    assert!(ctx.intercepted_network_requests.contains_key(&(foreign, "same-id".into())));
    assert!(ctx.pending_events.is_empty(), "idle cleanup must not fabricate successful events");
}
