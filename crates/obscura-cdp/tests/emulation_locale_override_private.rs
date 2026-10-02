// Emulation.setLocaleOverride changes navigator.language(s) without adding an
// engine global that reflection or a page write could observe or change.

use obscura_cdp::dispatch::{dispatch, CdpContext};
use obscura_cdp::types::CdpRequest;
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
                let body = "<html><body><p>locale</p></body></html>";
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

async fn cdp(ctx: &mut CdpContext, id: u64, method: &str, params: Value, session_id: &str) -> Value {
    let resp = dispatch(
        &CdpRequest {
            id,
            method: method.to_string(),
            params,
            session_id: Some(session_id.to_string()),
        },
        ctx,
    )
    .await;
    assert!(resp.error.is_none(), "CDP {method} failed: {:?}", resp.error);
    resp.result.unwrap_or_else(|| json!({}))
}

async fn eval(ctx: &mut CdpContext, id: u64, expr: &str, session_id: &str) -> Value {
    let result = cdp(
        ctx,
        id,
        "Runtime.evaluate",
        json!({"expression": expr, "returnByValue": true, "awaitPromise": true}),
        session_id,
    )
    .await;
    serde_json::from_str(result["result"]["value"].as_str().unwrap()).unwrap()
}

const REFLECTED: &str = r#"(() => {
    const name = '__obscura_language';
    let forIn = false;
    for (const key in window) if (key === name) forIn = true;
    return JSON.stringify([navigator.language, navigator.languages, name in window,
        Object.getOwnPropertyDescriptor(window, name) === undefined,
        [Object.keys(window), Object.getOwnPropertyNames(window), Reflect.ownKeys(window),
            Object.keys(Object.getOwnPropertyDescriptors(window))]
            .some(keys => keys.includes(name)),
        forIn]);
})()"#;

#[tokio::test(flavor = "current_thread")]
async fn locale_override_applies_without_a_page_visible_global() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    let url = serve().await;
    let mut ctx = CdpContext::new();
    let page_id = ctx.create_page();
    let sid = "locale-session";
    ctx.sessions.insert(sid.to_string(), page_id);
    cdp(&mut ctx, 1, "Page.navigate", json!({"url": url, "waitUntil": "load"}), sid).await;
    assert_eq!(
        eval(&mut ctx, 2, REFLECTED, sid).await,
        json!(["en-US", ["en-US", "en"], false, true, false, false])
    );

    cdp(&mut ctx, 3, "Emulation.setLocaleOverride", json!({"locale": "de-DE"}), sid).await;
    let overridden = json!(["de-DE", ["de-DE", "de"], false, true, false, false]);
    assert_eq!(eval(&mut ctx, 4, REFLECTED, sid).await, overridden);

    // The override is reapplied to the next document.
    let next = format!("{url}?next");
    cdp(&mut ctx, 5, "Page.navigate", json!({"url": next, "waitUntil": "load"}), sid).await;
    assert_eq!(eval(&mut ctx, 6, REFLECTED, sid).await, overridden);

    // A page write to the former global name cannot change the emulated locale.
    assert_eq!(
        eval(
            &mut ctx,
            7,
            "(() => { window.__obscura_language = 'fr-FR'; \
             return JSON.stringify([navigator.language, Object.keys(window).includes('__obscura_language')]); })()",
            sid,
        )
        .await,
        json!(["de-DE", true])
    );
    cdp(&mut ctx, 8, "Page.navigate", json!({"url": url, "waitUntil": "load"}), sid).await;

    cdp(&mut ctx, 9, "Emulation.setLocaleOverride", json!({"locale": ""}), sid).await;
    assert_eq!(
        eval(&mut ctx, 10, REFLECTED, sid).await,
        json!(["en-US", ["en-US", "en"], false, true, false, false])
    );
}
