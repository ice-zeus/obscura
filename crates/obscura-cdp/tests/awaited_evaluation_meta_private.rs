// Awaited Runtime.evaluate and Runtime.callFunctionOn (every Playwright
// evaluate) keep their result metadata in host state, not in an engine global
// that reflection or a page write could observe or change.

use obscura_cdp::dispatch::{dispatch, CdpContext};
use obscura_cdp::types::{CdpRequest, CdpResponse};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let body = "<html><body><p id='target'>await</p></body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

async fn send(ctx: &mut CdpContext, id: u64, method: &str, params: Value, session_id: &str) -> CdpResponse {
    dispatch(
        &CdpRequest {
            id,
            method: method.to_string(),
            params,
            session_id: Some(session_id.to_string()),
        },
        ctx,
    )
    .await
}

async fn cdp(ctx: &mut CdpContext, id: u64, method: &str, params: Value, session_id: &str) -> Value {
    let resp = send(ctx, id, method, params, session_id).await;
    assert!(resp.error.is_none(), "CDP {method} failed: {:?}", resp.error);
    resp.result.unwrap_or_else(|| json!({}))
}

async fn awaited(ctx: &mut CdpContext, id: u64, expr: &str, by_value: bool, session_id: &str) -> Value {
    cdp(
        ctx,
        id,
        "Runtime.evaluate",
        json!({"expression": expr, "returnByValue": by_value, "awaitPromise": true}),
        session_id,
    )
    .await
}

const REFLECTED: &str = r#"(async () => {
    await Promise.resolve();
    const name = '__obscura_await_meta';
    let forIn = false;
    for (const key in window) if (key === name) forIn = true;
    return JSON.stringify([name in window,
        Object.getOwnPropertyDescriptor(window, name) === undefined,
        [Object.keys(window), Object.getOwnPropertyNames(window), Reflect.ownKeys(window),
            Object.keys(Object.getOwnPropertyDescriptors(window))]
            .some(keys => keys.includes(name)),
        forIn]);
})()"#;

async fn assert_hidden(ctx: &mut CdpContext, id: u64, session_id: &str) {
    let reply = awaited(ctx, id, REFLECTED, true, session_id).await;
    let value: Value = serde_json::from_str(reply["result"]["value"].as_str().unwrap()).unwrap();
    assert_eq!(value, json!([false, true, false, false]), "awaited evaluation left a page-visible global");
}

#[tokio::test(flavor = "current_thread")]
async fn awaited_evaluations_work_without_a_page_visible_global() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let url = serve().await;
    let mut ctx = CdpContext::new();
    let page_id = ctx.create_page();
    let sid = "await-meta-session";
    ctx.sessions.insert(sid.to_string(), page_id);
    cdp(&mut ctx, 1, "Page.navigate", json!({"url": url, "waitUntil": "load"}), sid).await;

    // A promise that settles on a timer, by value.
    let settled = awaited(
        &mut ctx,
        2,
        "new Promise(resolve => setTimeout(() => resolve('settled'), 5))",
        true,
        sid,
    )
    .await;
    assert_eq!(settled["result"]["value"], json!("settled"));
    assert!(settled.get("exceptionDetails").is_none());

    // By reference: the reply carries the metadata of the awaited value.
    let node = awaited(&mut ctx, 3, "(async () => document.getElementById('target'))()", false, sid).await;
    assert_eq!(node["result"]["type"], json!("object"));
    assert_eq!(node["result"]["subtype"], json!("node"));
    let object_id = node["result"]["objectId"].as_str().unwrap().to_string();
    let called = cdp(
        &mut ctx,
        4,
        "Runtime.callFunctionOn",
        json!({"functionDeclaration": "async function() { return this.id; }", "objectId": object_id,
               "returnByValue": true, "awaitPromise": true}),
        sid,
    )
    .await;
    assert_eq!(called["result"]["value"], json!("target"));
    let array = cdp(
        &mut ctx,
        5,
        "Runtime.callFunctionOn",
        json!({"functionDeclaration": "async function() { return [1, 2, 3]; }", "objectId": object_id,
               "returnByValue": false, "awaitPromise": true}),
        sid,
    )
    .await;
    assert_eq!(array["result"]["subtype"], json!("array"));
    assert_eq!(array["result"]["description"], json!("Array(3)"));
    assert_hidden(&mut ctx, 6, sid).await;

    // Rejections and synchronous throws are still answered with exceptionDetails.
    let rejected = awaited(&mut ctx, 7, "Promise.reject(new TypeError('boom'))", true, sid).await;
    assert_eq!(rejected["exceptionDetails"]["exception"]["className"], json!("TypeError"));
    assert!(rejected["exceptionDetails"]["exception"]["description"].as_str().unwrap().contains("boom"));
    let call_rejected = cdp(
        &mut ctx,
        8,
        "Runtime.callFunctionOn",
        json!({"functionDeclaration": "() => Promise.reject(new RangeError('call'))", "objectId": object_id,
               "returnByValue": true, "awaitPromise": true}),
        sid,
    )
    .await;
    assert_eq!(call_rejected["exceptionDetails"]["exception"]["className"], json!("RangeError"));
    let thrown = cdp(
        &mut ctx,
        9,
        "Runtime.evaluate",
        json!({"expression": "undefined_name_xyz", "returnByValue": false}),
        sid,
    )
    .await;
    assert!(thrown["exceptionDetails"]["exception"]["description"].as_str().unwrap().contains("ReferenceError"));
    let after = awaited(&mut ctx, 10, "Promise.resolve('after')", true, sid).await;
    assert_eq!(after["result"]["value"], json!("after"));
    assert!(after.get("exceptionDetails").is_none());
    assert_hidden(&mut ctx, 11, sid).await;

    // A page's own property with the former name stays page state.
    let owned = awaited(
        &mut ctx,
        12,
        "(async () => { window.__obscura_await_meta = 'page'; await 0; return 'written'; })()",
        true,
        sid,
    )
    .await;
    assert_eq!(owned["result"]["value"], json!("written"));
    let kept = awaited(&mut ctx, 13, "Promise.resolve(window.__obscura_await_meta)", true, sid).await;
    assert_eq!(kept["result"]["value"], json!("page"));

    // An unsettled promise still fails on its timeout.
    let timed_out = send(
        &mut ctx,
        14,
        "Runtime.evaluate",
        json!({"expression": "new Promise(() => {})", "awaitPromise": true, "returnByValue": true, "timeout": 50}),
        sid,
    )
    .await;
    assert!(timed_out.error.is_some(), "an unsettled promise must time out");

    // After a navigation the next document starts without the global too.
    let next = format!("{url}?next");
    cdp(&mut ctx, 15, "Page.navigate", json!({"url": next, "waitUntil": "load"}), sid).await;
    let reloaded = awaited(&mut ctx, 16, "(async () => location.search)()", true, sid).await;
    assert_eq!(reloaded["result"]["value"], json!("?next"));
    assert_hidden(&mut ctx, 17, sid).await;
}
