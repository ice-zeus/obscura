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
