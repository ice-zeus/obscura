#[cfg(feature = "stealth")]
use std::collections::HashMap;
#[cfg(feature = "stealth")]
use std::error::Error;
#[cfg(feature = "stealth")]
use std::sync::Arc;
#[cfg(feature = "stealth")]
use std::time::Duration;

#[cfg(feature = "stealth")]
use futures_util::StreamExt;
#[cfg(feature = "stealth")]
use tokio::sync::RwLock;
#[cfg(feature = "stealth")]
use url::Url;

#[cfg(feature = "stealth")]
use crate::client::{
    chrome_sends_origin, chrome_wire_headers, combine_fetch_site, ProfileHeaders, WireRequest,
    cors_required, env_allows_private_network, fetch_file_url, is_forbidden_ip,
    redirect_taints_origin, request_fetch_site, request_referrer, response_too_large,
    same_site_context, serialized_request_origin, validate_cors_response, validate_request_mode,
    validate_url, CallbackRegistry, InFlightGuard, NavigationExchange, ObscuraNetError, RequestInfo, RequestMode,
    ResourceRequest, Response, SsrfGuardResolver,
};
#[cfg(feature = "stealth")]
use crate::cookies::{CookieJar, SameSiteContext};
#[cfg(feature = "stealth")]
use crate::http_cache::{CacheLookup, HttpCache};

/// The wreq half of [`SsrfGuardResolver`]. `validate_url` only inspects the
/// host *string*, so on its own it lets a public name that resolves inward
/// straight through — the reqwest client closes that with a `dns_resolver`, and
/// until this impl existed the stealth client did not, which made `--stealth` a
/// downgrade in protection rather than only a change of fingerprint. The
/// deny-set is shared, so the two transports cannot drift apart.
#[cfg(feature = "stealth")]
impl wreq::dns::Resolve for SsrfGuardResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let allow = self.allow_private || env_allows_private_network();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?
                .collect();
            if !allow {
                if let Some(bad) = addrs.iter().find(|sa| is_forbidden_ip(sa.ip())) {
                    return Err(format!(
                        "SSRF blocked: '{}' resolves to forbidden address {}",
                        host,
                        bad.ip()
                    )
                    .into());
                }
            }
            let iter: wreq::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

#[cfg(feature = "stealth")]
pub const STEALTH_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

// The wreq emulation (STEALTH_PROFILE, Platform::Windows) sends this exact UA,
// the matching sec-ch-ua brands and sec-ch-ua-platform "Windows" on the wire,
// over that profile's TLS and HTTP/2 settings. navigator has to report the
// same identity, otherwise the TLS/HTTP layer and the JS layer disagree and a
// site cross-checks the mismatch as a bot signal. Raise the version only
// together with the profile: Chrome148 is the newest Chrome profile the pinned
// wreq-util provides, and claiming a newer version than the TLS and HTTP/2
// emulation would be a worse mismatch than a slightly older browser.
#[cfg(feature = "stealth")]
const STEALTH_PROFILE: wreq_util::Profile = wreq_util::Profile::Chrome148;

#[cfg(feature = "stealth")]
fn stealth_emulation() -> wreq_util::Emulation {
    wreq_util::Emulation::builder()
        .profile(STEALTH_PROFILE)
        .platform(wreq_util::Platform::Windows)
        .build()
}

/// The identity headers of the emulation profile. Requests are sent with the
/// client's default headers disabled and the complete Chrome header list
/// built per request, so a request type never inherits the navigation
/// defaults (Sec-Fetch-Dest: document, Sec-Fetch-Mode: navigate, the HTML
/// Accept) the profile installs as client defaults.
#[cfg(feature = "stealth")]
fn stealth_profile_headers() -> ProfileHeaders {
    use wreq::IntoEmulation;
    let emulation = stealth_emulation().into_emulation();
    let header = |name: &str, fallback: &str| {
        emulation
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(fallback)
            .to_string()
    };
    let (sec_ch_ua, sec_ch_ua_platform) = crate::client::chrome_client_hints(STEALTH_USER_AGENT);
    ProfileHeaders {
        user_agent: header("user-agent", STEALTH_USER_AGENT),
        sec_ch_ua: header("sec-ch-ua", &sec_ch_ua),
        sec_ch_ua_mobile: header("sec-ch-ua-mobile", "?0"),
        sec_ch_ua_platform: header("sec-ch-ua-platform", &sec_ch_ua_platform),
        accept_encoding: header("accept-encoding", "gzip, deflate, br, zstd"),
        accept_language: header("accept-language", "en-US,en;q=0.9"),
    }
}

/// A request carrying exactly `headers`, in that order and HTTP/1.1 casing.
#[cfg(feature = "stealth")]
fn chrome_request_builder(
    client: &wreq::Client,
    method: wreq::Method,
    url: &Url,
    headers: &[(String, String)],
    has_body: bool,
) -> Result<wreq::RequestBuilder, ObscuraNetError> {
    let mut map = wreq::header::HeaderMap::with_capacity(headers.len() + 2);
    let mut order = wreq::header::OrigHeaderMap::with_capacity(headers.len() + 3);
    order.insert("Host");
    if url.scheme() == "http" {
        // Chrome's HTTP/1.1 requests keep the connection alive explicitly.
        order.insert("Connection");
        map.insert(wreq::header::CONNECTION, wreq::header::HeaderValue::from_static("keep-alive"));
    }
    if has_body {
        order.insert("Content-Length");
    }
    for (name, value) in headers {
        let header_name = wreq::header::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
            .map_err(|_| ObscuraNetError::Network("Invalid HTTP header name".into()))?;
        let header_value = wreq::header::HeaderValue::from_str(value)
            .map_err(|_| ObscuraNetError::Network("Invalid HTTP header value".into()))?;
        map.append(header_name, header_value);
        order.insert(name.clone());
    }
    Ok(client
        .request(method, url.as_str())
        .default_headers(false)
        .headers(map)
        .orig_headers(order))
}

#[cfg(feature = "stealth")]
fn sorted_extra(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut extra: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    extra.sort();
    extra
}

#[cfg(feature = "stealth")]
pub const STEALTH_NAVIGATOR_PLATFORM: &str = "Win32";
#[cfg(feature = "stealth")]
pub const STEALTH_UA_PLATFORM: &str = "Windows";
#[cfg(feature = "stealth")]
pub const STEALTH_UA_PLATFORM_VERSION: &str = "15.0.0";

#[cfg(feature = "stealth")]
fn tracker_blocking_enabled(value: Option<&str>) -> bool {
    !matches!(
        value.map(str::trim),
        Some(value) if matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
    )
}

#[cfg(feature = "stealth")]
fn is_tracker_blocked(url: &Url, block_trackers: bool) -> bool {
    block_trackers && url.host_str().is_some_and(crate::blocklist::is_blocked)
}

#[cfg(feature = "stealth")]
fn wreq_response_header_value<'a>(
    headers: &'a wreq::header::HeaderMap,
    name: &'static str,
    url: &Url,
) -> Result<Option<&'a str>, ObscuraNetError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ObscuraNetError::Cors(format!(
            "{} returned multiple {} headers",
            url, name
        )));
    }
    first.to_str().map(Some).map_err(|_| {
        ObscuraNetError::Cors(format!("{} returned an invalid {} header", url, name))
    })
}

#[cfg(feature = "stealth")]
fn validate_wreq_cors_response(
    request: &ResourceRequest,
    target: &Url,
    serialized_origin: &str,
    headers: &wreq::header::HeaderMap,
) -> Result<(), ObscuraNetError> {
    if !cors_required(request, target) {
        return Ok(());
    }
    let allow_origin =
        wreq_response_header_value(headers, "access-control-allow-origin", target)?;
    let allow_credentials =
        wreq_response_header_value(headers, "access-control-allow-credentials", target)?;
    validate_cors_response(
        request,
        target,
        serialized_origin,
        allow_origin,
        allow_credentials,
    )
}

#[cfg(feature = "stealth")]
async fn read_wreq_body_limited(
    response: wreq::Response,
    url: &Url,
    limit: usize,
) -> Result<Vec<u8>, ObscuraNetError> {
    if response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some_and(|length| length > limit as u64)
    {
        return Err(response_too_large(url, limit));
    }

    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(limit);
    let stream = response.bytes_stream();
    futures_util::pin_mut!(stream);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            ObscuraNetError::Network(format!("Failed to read body: {}", error))
        })?;
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(response_too_large(url, limit));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "stealth")]
async fn send_get_with_connection_reset_retry(
    request: wreq::RequestBuilder,
    url: &Url,
) -> Result<wreq::Response, wreq::Error> {
    let retry = request.try_clone();
    match request.send().await {
        Err(error) if error.is_connection_reset() => {
            let Some(retry) = retry else {
                return Err(error);
            };
            tracing::debug!(%url, "retrying GET after connection reset");
            retry.send().await
        }
        result => result,
    }
}

#[cfg(feature = "stealth")]
fn explicit_header_map(headers: &HashMap<String, String>) -> Result<wreq::header::HeaderMap, ObscuraNetError> {
    let mut map = wreq::header::HeaderMap::new();
    for (name, value) in headers {
        let name = wreq::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ObscuraNetError::Network("Invalid explicit HTTP header name".into()))?;
        let value = wreq::header::HeaderValue::from_str(value)
            .map_err(|_| ObscuraNetError::Network("Invalid explicit HTTP header value".into()))?;
        map.insert(name, value);
    }
    Ok(map)
}

#[cfg(feature = "stealth")]
pub struct StealthHttpClient {
    client: wreq::Client,
    allow_private_network: bool,
    pub block_trackers: bool,
    pub cookie_jar: Arc<CookieJar>,
    pub extra_headers: RwLock<HashMap<String, String>>,
    user_agent_override: RwLock<Option<String>>,
    pub in_flight: Arc<std::sync::atomic::AtomicU32>,
    /// The browser context's HTTP cache, shared by its pages.
    http_cache: Option<Arc<HttpCache>>,
    profile: ProfileHeaders,
    proxy_url: Option<String>,
}

/// Scripted fetch exposes these headers before consuming the bounded body.
#[cfg(feature = "stealth")]
pub struct StealthResponseHeaders {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: futures_util::future::BoxFuture<'static, Result<Vec<u8>, ObscuraNetError>>,
}

#[cfg(feature = "stealth")]
impl StealthHttpClient {
    pub fn new(cookie_jar: Arc<CookieJar>) -> Self {
        Self::with_proxy(cookie_jar, None, false)
    }

    pub fn with_proxy(
        cookie_jar: Arc<CookieJar>,
        proxy_url: Option<&str>,
        allow_private_network: bool,
    ) -> Self {
        let emulation_opts = stealth_emulation();

        let mut builder = wreq::Client::builder()
            .emulation(emulation_opts)
            .timeout(Duration::from_secs(30))
            // SSRF guard: reject hostnames that resolve to a private/loopback
            // IP. Use the same opt-in as the `validate_url` calls below so
            // `--allow-private-network` reaches this transport (#793); the
            // resolver still honours OBSCURA_ALLOW_PRIVATE_NETWORK on its own.
            .dns_resolver(Arc::new(SsrfGuardResolver::new(allow_private_network)))
            .redirect(wreq::redirect::Policy::none());

        // Honor SSL_CERT_FILE / SSL_CERT_DIR in the stealth client too.
        //
        // `client.rs` (the reqwest path) already reads these via `configured_root_paths()` and
        // feeds `add_root_certificate`, so a private CA works there. This client did not, which
        // made the *better-fingerprinted* transport the only one unable to reach hosts behind a
        // private/national CA (measured against a Brazilian government portal whose leaf is
        // issued by an ICP-Brasil intermediate: `--stealth` failed with CERTIFICATE_VERIFY_FAILED
        // while the reqwest path, with SSL_CERT_FILE set, completed the handshake).
        //
        // Two deliberate constraints:
        //
        // 1. `tls_cert_store` is used, NOT `tls_options`. `emulation()` overwrites `tls_options`
        //    wholesale ("This will overwrite the existing configuration"), so setting TLS options
        //    here would silently discard the Chrome fingerprint — the whole point of this client.
        //    `tls_cert_store` is a separate field on the config and composes with emulation.
        //
        // 2. Opt-in only. Supplying a store REPLACES the webpki roots (see `set_cert_store` in
        //    `tls/conn/ext.rs`), it does not add to them. Applying it unconditionally would break
        //    every ordinary site whenever the bundle is incomplete. With neither variable set,
        //    behaviour is byte-for-byte what it was before.
        if crate::client::custom_cert_store_requested(
            std::env::var_os("SSL_CERT_FILE").as_deref(),
            std::env::var_os("SSL_CERT_DIR").as_deref(),
        ) {
            match wreq::tls::trust::CertStore::builder().set_default_paths().build() {
                Ok(store) => builder = builder.tls_cert_store(store),
                Err(error) => tracing::warn!(
                    %error,
                    "SSL_CERT_FILE/SSL_CERT_DIR set but the certificate store failed to build; \
                     continuing with the default roots"
                ),
            }
        }

        if let Some(proxy) = proxy_url {
            if let Ok(p) = wreq::Proxy::all(proxy) {
                builder = builder.proxy(p);
            }
        }

        let client = builder.build().expect("failed to build wreq stealth client");

        StealthHttpClient {
            client,
            allow_private_network,
            block_trackers: tracker_blocking_enabled(
                std::env::var("OBSCURA_BLOCK_TRACKERS").ok().as_deref(),
            ),
            cookie_jar,
            extra_headers: RwLock::new(HashMap::new()),
            user_agent_override: RwLock::new(None),
            in_flight: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            http_cache: None,
            profile: stealth_profile_headers(),
            proxy_url: proxy_url.map(str::to_string),
        }
    }

    /// A client with its own connection pool and the same identity, cookie
    /// jar, HTTP cache and overrides. A synchronous load (importScripts) runs
    /// on a helper thread while the page thread waits; a connection pooled by
    /// the page's runtime cannot make progress then, so it needs its own.
    pub async fn detached(&self) -> Self {
        let mut client = Self::with_proxy(
            self.cookie_jar.clone(),
            self.proxy_url.as_deref(),
            self.allow_private_network,
        )
        .with_http_cache(self.http_cache.clone());
        client.block_trackers = self.block_trackers;
        *client.extra_headers.get_mut() = self.extra_headers.read().await.clone();
        *client.user_agent_override.get_mut() = self.user_agent_override.read().await.clone();
        client
    }

    /// Use the browser context's HTTP cache for subresource requests.
    pub fn with_http_cache(mut self, cache: Option<Arc<HttpCache>>) -> Self {
        self.http_cache = cache;
        self
    }

    pub fn http_cache(&self) -> Option<&Arc<HttpCache>> {
        self.http_cache.as_ref()
    }

    pub async fn fetch(&self, url: &Url) -> Result<Response, ObscuraNetError> {
        self.fetch_with_callbacks(url, None).await
    }

    pub async fn fetch_with_callbacks(
        &self,
        url: &Url,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_with_profile(wreq::Method::GET, url, None, ResourceRequest::navigation(), callbacks)
            .await
    }

    pub async fn fetch_resource_with_callbacks(
        &self,
        url: &Url,
        request: ResourceRequest,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_with_profile(wreq::Method::GET, url, None, request, callbacks).await
    }

    pub async fn post_form_with_callbacks(
        &self,
        url: &Url,
        body: &str,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_with_profile(wreq::Method::POST, url, Some(body.as_bytes().to_vec()), ResourceRequest::navigation(), callbacks).await
    }

    async fn fetch_with_profile(
        &self,
        initial_method: wreq::Method,
        url: &Url,
        initial_body: Option<Vec<u8>>,
        request: ResourceRequest,
        callbacks: Option<&CallbackRegistry>,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_with_profile_traced(initial_method,url,initial_body,request,callbacks,None).await
    }

    /// Navigation-only transport observations, separate from logical callbacks.
    #[doc(hidden)]
    pub async fn fetch_navigation_with_trace(&self, url: &Url, form: Option<&str>, callbacks: Option<&CallbackRegistry>)
        -> (Result<Response,ObscuraNetError>,Vec<NavigationExchange>) {
        self.fetch_navigation_from(url, form, callbacks, None, false).await
    }

    /// A navigation the document started (link, form, location): Chrome
    /// derives Sec-Fetch-Site, Referer and a POST's Origin from that document.
    #[doc(hidden)]
    pub async fn fetch_navigation_from(&self, url: &Url, form: Option<&str>, callbacks: Option<&CallbackRegistry>, initiator: Option<&Url>, reload: bool)
        -> (Result<Response,ObscuraNetError>,Vec<NavigationExchange>) {
        let mut trace=Vec::new();
        let method=if form.is_some() {wreq::Method::POST} else {wreq::Method::GET};
        let mut request = ResourceRequest::navigation();
        request.initiator = initiator.cloned();
        request.referrer = initiator.cloned();
        request.reload = reload;
        let result=self.fetch_with_profile_traced(method,url,form.map(|body|body.as_bytes().to_vec()),request,callbacks,Some(&mut trace)).await;
        if result.is_err() {
            if let Some(last)=trace.last_mut() { last.failed=true; }
        }
        (result,trace)
    }

    async fn fetch_with_profile_traced(
        &self,
        initial_method: wreq::Method,
        url: &Url,
        initial_body: Option<Vec<u8>>,
        request: ResourceRequest,
        callbacks: Option<&CallbackRegistry>,
        mut trace: Option<&mut Vec<NavigationExchange>>,
    ) -> Result<Response, ObscuraNetError> {
        validate_url(url, self.allow_private_network)?;
        validate_request_mode(&request, url)?;
        if url.scheme() == "file" {
            return fetch_file_url(url, request.max_response_bytes).await;
        }

        let mut current_url = url.clone();
        let mut method = initial_method;
        let mut body = initial_body;
        let mut request_headers = self.request_headers().await;

        if is_tracker_blocked(&current_url, self.block_trackers) {
            tracing::debug!("Blocked tracker: {}", current_url);
            return Ok(Response {
                status: 0,
                url: current_url,
                headers: HashMap::new(),
                body: Vec::new(),
                redirected_from: Vec::new(),
            });
        }

        let mut redirects = Vec::new();
        let mut redirect_tainted = false;
        let mut request_callback_fired = false;

        // Subresource GETs go through the context's HTTP cache. Documents,
        // bodies and requests carrying caller cache directives or credentials
        // headers bypass it, as do requests whose headers Chrome would not
        // cache under (Authorization, Cache-Control, Pragma, Range).
        let cache = self.http_cache.as_ref().filter(|_| {
            method == wreq::Method::GET
                && body.is_none()
                && request.mode != RequestMode::Navigate
                && !["authorization", "cache-control", "pragma", "range", "if-none-match", "if-modified-since"]
                    .iter()
                    .any(|name| request_headers.keys().any(|key| key.eq_ignore_ascii_case(name)))
        });
        let cache_key = cache.map(|_| crate::http_cache::cache_key(
            request.top_frame.as_ref(),
            request.initiator.as_ref(),
            url,
            request.sends_credentials_to(url),
        ));
        let mut conditional: Vec<(&'static str, String)> = Vec::new();
        // Values sent for this request, recorded before any response can
        // change the cookie jar (Vary is matched against what was sent).
        let sent = if cache.is_some() {
            self.cache_request_headers(&request, url, &request_headers)
        } else {
            HashMap::new()
        };
        if let (Some(cache), Some(key)) = (cache, cache_key.as_deref()) {
            let lookup = cache.lookup(
                key,
                &|name| sent.get(name).cloned(),
                request.max_response_bytes,
                std::time::SystemTime::now(),
            );
            match lookup {
                CacheLookup::Fresh(response) => {
                    let request_info = RequestInfo {
                        url: url.clone(),
                        method: method.to_string(),
                        headers: sent.clone(),
                        resource_type: request.resource_type,
                    };
                    if let Some(callbacks) = callbacks {
                        callbacks.fire_request(&request_info).await;
                    }
                    // CORS is checked against the stored response for every
                    // use, exactly as for a network response.
                    if cors_required(&request, url) {
                        validate_cors_response(
                            &request,
                            url,
                            &serialized_request_origin(&request, false),
                            response.header("access-control-allow-origin"),
                            response.header("access-control-allow-credentials"),
                        )?;
                    }
                    if let Some(callbacks) = callbacks {
                        callbacks.fire_response(&request_info, &response).await;
                    }
                    return Ok(response);
                }
                CacheLookup::Revalidate(headers) => conditional = headers,
                CacheLookup::Miss => {}
            }
        }
        let request_time = std::time::SystemTime::now();

        // Follow up to 20 redirects (Fetch spec + the reqwest path): 0..=20 makes
        // 21 requests, so the 20th hop is followed and only the 21st fails.
        let mut chain_site: &'static str = "none";
        for _ in 0..=20 {
            validate_request_mode(&request, &current_url)?;
            let hop_site = request_fetch_site(&request, &current_url);
            chain_site = if redirects.is_empty() { hop_site } else { combine_fetch_site(chain_site, hop_site) };
            let referer = request_referrer(&request, &current_url);
            let request_origin = serialized_request_origin(&request, redirect_tainted);
            let sends_origin = chrome_sends_origin(&request, method.as_str(), &current_url)
                && (request.initiator.is_some() || request.mode != RequestMode::Navigate);

            let cookie_header = if request.sends_credentials_to(&current_url) {
                self.cookie_jar.get_cookie_header_in_context(
                    &current_url,
                    same_site_context(
                        &request,
                        &current_url,
                        method == wreq::Method::GET || method == wreq::Method::HEAD,
                    ),
                )
            } else {
                String::new()
            };
            // Cache validators come last, after the cookie, as in Chrome
            // (HttpCache::Transaction adds them to the finished request).
            let revalidating = redirects.is_empty() && !conditional.is_empty();
            let mut extra = sorted_extra(&request_headers);
            extra.retain(|(name, _)| name != "origin");
            let redirected_navigation = request.mode == RequestMode::Navigate
                && redirects.last().is_some_and(|previous: &Url| previous.origin() != current_url.origin());
            let wire = chrome_wire_headers(
                &WireRequest {
                    method: method.as_str(),
                    url: &current_url,
                    request: &request,
                    site: chain_site,
                    origin: sends_origin.then_some(request_origin.as_str()),
                    referer: referer.as_deref(),
                    cookie: Some(cookie_header.as_str()),
                    content_type: body.as_ref().map(|_| "application/x-www-form-urlencoded"),
                    extra: &extra,
                    redirected_navigation,
                    preflight: None,
                    conditional: if revalidating { &conditional } else { &[] },
                },
                &self.profile,
            );
            let mut req = chrome_request_builder(&self.client, method.clone(), &current_url, &wire, body.is_some())?;

            let mut observed_headers = request_headers.clone();
            observed_headers.remove("origin");
            if sends_origin {
                observed_headers.insert("origin".into(), request_origin.clone());
            }
            if revalidating {
                for (name, value) in &conditional {
                    observed_headers.insert((*name).to_string(), value.clone());
                }
            }
            if let Some(bytes) = &body {
                req = req.body(bytes.clone());
                observed_headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
            }
            let request_info = RequestInfo {
                url: current_url.clone(),
                method: method.to_string(),
                headers: observed_headers,
                resource_type: request.resource_type,
            };
            if !request_callback_fired {
                if let Some(callbacks) = callbacks {
                    callbacks.fire_request(&request_info).await;
                }
                request_callback_fired = true;
            }

            let timestamp=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64();
            if let Some(trace)=trace.as_mut() {
                trace.push(NavigationExchange::started(&request_info,body.as_deref(),timestamp));
            }
            let in_flight = InFlightGuard::new(&self.in_flight);
            let result = if method == wreq::Method::GET && body.is_none() {
                send_get_with_connection_reset_retry(req, &current_url).await
            } else {
                req.send().await
            };
            let resp = result.map_err(|e| {
                    ObscuraNetError::Network(format!(
                        "{}: {} (source: {:?})",
                        current_url,
                        e,
                        e.source()
                    ))
                })?;

            let status = resp.status();
            validate_wreq_cors_response(
                &request,
                &current_url,
                &request_origin,
                resp.headers(),
            )?;

            if request.sends_credentials_to(&current_url) {
                for val in resp.headers().get_all("set-cookie") {
                    if let Ok(s) = val.to_str() {
                        self.cookie_jar.set_cookie(s, &current_url);
                    }
                }
            }

            let mut response_headers: HashMap<String, String> = HashMap::new();
            for (k, v) in resp.headers().iter() {
                crate::client::merge_response_header(
                    &mut response_headers,
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                );
            }

            if let Some(last)=trace.as_mut().and_then(|trace|trace.last_mut()) {
                last.status=Some(status.as_u16());
                last.response_headers=response_headers.clone();
            }

            if revalidating && status.as_u16() == 304 {
                drop(resp);
                drop(in_flight);
                let refreshed = match (cache, cache_key.as_deref()) {
                    (Some(cache), Some(key)) => cache.refresh(key, &response_headers, request_time, std::time::SystemTime::now()),
                    _ => None,
                };
                if let Some(response) = refreshed {
                    if let Some(callbacks) = callbacks {
                        callbacks.fire_response(&request_info, &response).await;
                    }
                    return Ok(response);
                }
                // The entry vanished (evicted) between lookup and response:
                // fetch it again without validators.
                return Box::pin(self.fetch_with_profile_traced(method, url, None, request, callbacks, trace)).await;
            }

            if status.is_redirection() {
                if let Some(location) = resp.headers().get("location") {
                    let location_str = location.to_str().map_err(|_| {
                        ObscuraNetError::Network("Invalid redirect Location".into())
                    })?;
                    let next_url = current_url.join(location_str).map_err(|e| {
                        ObscuraNetError::Network(format!("Invalid redirect URL: {}", e))
                    })?;
                    validate_url(&next_url, self.allow_private_network)?;
                    validate_request_mode(&request, &next_url)?;
                    redirect_tainted |=
                        redirect_taints_origin(&request, &current_url, &next_url);
                    let discard_body = matches!(status.as_u16(), 301 | 302 | 303);
                    crate::client::strip_navigation_redirect_headers(
                        &mut request_headers, &current_url, &next_url, discard_body,
                    );
                    redirects.push(current_url.clone());
                    current_url = next_url;
                    if discard_body {
                        method = wreq::Method::GET;
                        body = None;
                    }
                    continue;
                }
            }

            let body = read_wreq_body_limited(resp, &current_url, request.max_response_bytes)
                .await?;
            drop(in_flight);

            if let Some(last)=trace.as_mut().and_then(|trace|trace.last_mut()) { last.response_body_size=Some(body.len()); }
            let response = Response {
                url: current_url,
                status: status.as_u16(),
                headers: response_headers,
                body,
                redirected_from: redirects,
            };
            if let (Some(cache), Some(key)) = (cache, cache_key.as_deref()) {
                if response.redirected_from.is_empty() {
                    cache.store(key, &response, &|name| sent.get(name).cloned(), request_time, std::time::SystemTime::now());
                } else {
                    cache.remove(key);
                }
            }
            if let Some(callbacks) = callbacks {
                callbacks.fire_response(&request_info, &response).await;
            }
            return Ok(response);
        }

        Err(ObscuraNetError::TooManyRedirects(url.to_string()))
    }

    /// Request header values for the HTTP cache: the headers this client sets
    /// for `request` (Vary matching and the observed request on a cache hit).
    /// Profile-wide emulation headers (user-agent, client hints,
    /// accept-encoding, accept-language) are constant per client, so a stored
    /// response that varies on them always matches its own profile.
    fn cache_request_headers(
        &self,
        request: &ResourceRequest,
        url: &Url,
        request_headers: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        let mut headers = request_headers.clone();
        headers.insert("accept".into(), request.accept().to_string());
        headers.insert("sec-fetch-site".into(), request_fetch_site(request, url).to_string());
        headers.insert("sec-fetch-mode".into(), request.mode.header_value().to_string());
        headers.insert("sec-fetch-dest".into(), request.destination().to_string());
        if let Some(referer) = request_referrer(request, url) {
            headers.insert("referer".into(), referer);
        }
        headers.remove("origin");
        if cors_required(request, url) {
            headers.insert("origin".into(), serialized_request_origin(request, false));
        }
        if request.sends_credentials_to(url) {
            let cookie = self.cookie_jar.get_cookie_header_in_context(
                url,
                same_site_context(request, url, true),
            );
            if !cookie.is_empty() {
                headers.insert("cookie".into(), cookie);
            }
        }
        headers
    }

    /// One request with no redirect following, for scripted fetch()/XHR. The
    /// caller supplies the Fetch credentials decision for this redirect hop,
    /// while this method preserves the Chrome transport fingerprint.
    pub async fn send_single(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        send_cookies: bool,
        store_cookies: bool,
    ) -> Result<Response, ObscuraNetError> {
        self.send_single_with_context(
            method,
            url,
            headers,
            body,
            send_cookies.then_some(SameSiteContext::SameSite),
            store_cookies,
        )
        .await
    }

    /// One request with an explicit cookie site context. Scripted fetch/XHR
    /// uses this so Strict and Lax cookies cannot leak cross-site.
    pub async fn send_single_with_context(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
    ) -> Result<Response, ObscuraNetError> {
        let mut merged = self.request_headers().await;
        crate::client::merge_request_headers(&mut merged, headers);
        self.send_single_with_resolved_headers(method, url, &merged, body, cookie_context, store_cookies).await
    }

    /// Internal workspace entry point for an already resolved redirect snapshot.
    pub async fn send_single_with_resolved_headers(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
    ) -> Result<Response, ObscuraNetError> {
        let response = self.send_single_headers_with_resolved_headers(
            method, url, headers, body, cookie_context, store_cookies, 64 * 1024 * 1024,
        ).await?;
        Ok(Response {
            url: url.clone(), status: response.status, headers: response.headers,
            body: response.body.await?, redirected_from: Vec::new(),
        })
    }

    /// Preserve request policy and cookie handling while deferring body reads.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_single_headers_with_context(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
        max_body_bytes: usize,
    ) -> Result<StealthResponseHeaders, ObscuraNetError> {
        let mut merged = self.request_headers().await;
        crate::client::merge_request_headers(&mut merged, headers);
        self.send_single_headers_with_resolved_headers(
            method, url, &merged, body, cookie_context, store_cookies, max_body_bytes,
        ).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_single_headers_with_resolved_headers(
        &self,
        method: &str,
        url: &Url,
        headers: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
        max_body_bytes: usize,
    ) -> Result<StealthResponseHeaders, ObscuraNetError> {
        if is_tracker_blocked(url, self.block_trackers) {
            tracing::debug!("Blocked tracker: {}", url);
            return Ok(StealthResponseHeaders {
                status: 0,
                headers: HashMap::new(),
                body: Box::pin(async { Ok(Vec::new()) }),
            });
        }

        let req_method = method
            .parse::<wreq::Method>()
            .map_err(|e| ObscuraNetError::Network(format!("invalid method '{}': {}", method, e)))?;
        let mut req = self.client.request(req_method, url.as_str());

        if let Some(context) = cookie_context {
            let cookie_header = self.cookie_jar.get_cookie_header_in_context(url, context);
            if !cookie_header.is_empty() {
                req = req.header("cookie", &cookie_header);
            }
        }
        req = req.headers(explicit_header_map(headers)?);
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }

        let in_flight = InFlightGuard::new(&self.in_flight);
        let resp = req.send().await.map_err(|e| {
            ObscuraNetError::Network(format!("{}: {}", url, e))
        })?;

        let status = resp.status();
        if store_cookies {
            for val in resp.headers().get_all("set-cookie") {
                if let Ok(s) = val.to_str() {
                    self.cookie_jar.set_cookie(s, url);
                }
            }
        }
        let response_headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body_url = url.clone();
        Ok(StealthResponseHeaders {
            status: status.as_u16(),
            headers: response_headers,
            body: Box::pin(async move {
                let _in_flight = in_flight;
                read_wreq_body_limited(resp, &body_url, max_body_bytes).await
            }),
        })
    }

    /// One scripted request hop (fetch(), XHR, sendBeacon, CORS preflight,
    /// worker loads) with Chrome's complete header set for `request`: Fetch
    /// metadata, Accept, Referer, Origin, Priority and header order, instead
    /// of the profile's navigation defaults. `extra` holds the page script and
    /// CDP headers; `site` is the Sec-Fetch-Site combined across redirects.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_browser_hop(
        &self,
        method: &str,
        url: &Url,
        request: &ResourceRequest,
        site: &'static str,
        origin: Option<&str>,
        extra: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
        preflight: Option<(&str, Option<&str>)>,
    ) -> Result<Response, ObscuraNetError> {
        let response = self.send_browser_hop_headers(
            method, url, request, site, origin, extra, body, cookie_context, store_cookies, preflight,
        ).await?;
        Ok(Response {
            url: url.clone(),
            status: response.status,
            headers: response.headers,
            body: response.body.await?,
            redirected_from: Vec::new(),
        })
    }

    /// `send_browser_hop` that resolves once the response headers arrive.
    /// The body (bounded by `request.max_response_bytes`) is read on demand,
    /// so scripted fetch can expose the Response before the body completes.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_browser_hop_headers(
        &self,
        method: &str,
        url: &Url,
        request: &ResourceRequest,
        site: &'static str,
        origin: Option<&str>,
        extra: &HashMap<String, String>,
        body: &[u8],
        cookie_context: Option<SameSiteContext>,
        store_cookies: bool,
        preflight: Option<(&str, Option<&str>)>,
    ) -> Result<StealthResponseHeaders, ObscuraNetError> {
        if is_tracker_blocked(url, self.block_trackers) {
            tracing::debug!("Blocked tracker: {}", url);
            return Ok(StealthResponseHeaders {
                status: 0,
                headers: HashMap::new(),
                body: Box::pin(async { Ok(Vec::new()) }),
            });
        }
        let req_method = method
            .parse::<wreq::Method>()
            .map_err(|e| ObscuraNetError::Network(format!("invalid method '{}': {}", method, e)))?;
        let cookie = match cookie_context {
            Some(context) if preflight.is_none() => self.cookie_jar.get_cookie_header_in_context(url, context),
            _ => String::new(),
        };
        let mut merged = self.request_headers().await;
        crate::client::merge_request_headers(&mut merged, extra);
        let mut extra = sorted_extra(&merged);
        extra.retain(|(name, _)| name != "origin");
        if preflight.is_some() {
            extra.retain(|(name, _)| matches!(name.as_str(), "user-agent" | "accept-language"));
        }
        let referer = request_referrer(request, url);
        let wire = chrome_wire_headers(
            &WireRequest {
                method,
                url,
                request,
                site,
                origin,
                referer: referer.as_deref(),
                cookie: Some(cookie.as_str()),
                content_type: None,
                extra: &extra,
                redirected_navigation: false,
                preflight,
                conditional: &[],
            },
            &self.profile,
        );
        let mut req = chrome_request_builder(&self.client, req_method, url, &wire, !body.is_empty())?;
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }
        let in_flight = InFlightGuard::new(&self.in_flight);
        let resp = req.send().await.map_err(|e| {
            ObscuraNetError::Network(format!("{}: {}", url, e))
        })?;
        let status = resp.status();
        if store_cookies && preflight.is_none() {
            for val in resp.headers().get_all("set-cookie") {
                if let Ok(s) = val.to_str() {
                    self.cookie_jar.set_cookie(s, url);
                }
            }
        }
        let mut response_headers: HashMap<String, String> = HashMap::new();
        for (k, v) in resp.headers().iter() {
            crate::client::merge_response_header(
                &mut response_headers,
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            );
        }
        let body_url = url.clone();
        let max_body_bytes = request.max_response_bytes;
        Ok(StealthResponseHeaders {
            status: status.as_u16(),
            headers: response_headers,
            body: Box::pin(async move {
                let _in_flight = in_flight;
                read_wreq_body_limited(resp, &body_url, max_body_bytes).await
            }),
        })
    }

    /// None preserves the selected emulation profile's existing User-Agent.
    pub async fn set_user_agent_override(&self, user_agent: &str) {
        *self.user_agent_override.write().await = if user_agent.is_empty() {
            None
        } else {
            Some(user_agent.to_string())
        };
    }

    pub async fn request_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        if let Some(user_agent) = self.user_agent_override.read().await.as_ref() {
            headers.insert("user-agent".to_string(), user_agent.clone());
        }
        crate::client::merge_request_headers(&mut headers, &*self.extra_headers.read().await);
        headers
    }

    pub async fn set_extra_headers(&self, headers: HashMap<String, String>) {
        *self.extra_headers.write().await = headers;
    }

    pub fn active_requests(&self) -> u32 {
        self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn is_network_idle(&self) -> bool {
        self.active_requests() == 0
    }
}

#[cfg(all(test, feature = "stealth"))]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use url::Url;

    use super::{
        StealthHttpClient, is_tracker_blocked, send_get_with_connection_reset_retry,
        tracker_blocking_enabled,
    };

    // The wire identity comes from the wreq profile, the JavaScript identity
    // from STEALTH_USER_AGENT plus Chromium's brand algorithm. Both must name
    // the same browser, or a site sees two different Chrome versions.
    #[test]
    fn stealth_user_agent_and_client_hints_match_the_emulation_profile() {
        use wreq::IntoEmulation;
        let emulation = super::stealth_emulation().into_emulation();
        let header = |name: &str| {
            emulation.headers.get(name).and_then(|value| value.to_str().ok()).map(str::to_string)
        };
        let (sec_ch_ua, sec_ch_ua_platform) = crate::client::chrome_client_hints(super::STEALTH_USER_AGENT);
        assert_eq!(header("user-agent").as_deref(), Some(super::STEALTH_USER_AGENT));
        assert_eq!(header("sec-ch-ua"), Some(sec_ch_ua));
        assert_eq!(header("sec-ch-ua-platform"), Some(sec_ch_ua_platform));
        assert_eq!(header("sec-ch-ua-mobile").as_deref(), Some("?0"));
        assert_eq!(format!("\"{}\"", super::STEALTH_UA_PLATFORM), header("sec-ch-ua-platform").unwrap());
    }

    // The brand list Chromium sends (GREASE brand, GREASE version and order)
    // is a function of the major version. Check the algorithm against every
    // Chrome profile wreq-util captured since the current GREASE scheme
    // (Chrome 105), so any version the stealth profile moves to stays exact.
    #[test]
    fn client_hint_brands_follow_chromium_for_every_captured_chrome_profile() {
        use wreq::IntoEmulation;
        use wreq_util::Profile::*;
        for profile in [
            Chrome105, Chrome106, Chrome107, Chrome108, Chrome109, Chrome110, Chrome114, Chrome116,
            Chrome117, Chrome118, Chrome119, Chrome120, Chrome123, Chrome124, Chrome126, Chrome127,
            Chrome128, Chrome129, Chrome130, Chrome131, Chrome132, Chrome133, Chrome134, Chrome135,
            Chrome136, Chrome137, Chrome138, Chrome139, Chrome140, Chrome141, Chrome142, Chrome143,
            Chrome144, Chrome145, Chrome146, Chrome147, Chrome148,
        ] {
            let emulation = wreq_util::Emulation::builder()
                .profile(profile)
                .platform(wreq_util::Platform::Windows)
                .build()
                .into_emulation();
            let header = |name: &str| {
                emulation.headers.get(name).and_then(|value| value.to_str().ok()).unwrap().to_string()
            };
            let (sec_ch_ua, _) = crate::client::chrome_client_hints(&header("user-agent"));
            assert_eq!(sec_ch_ua, header("sec-ch-ua"), "{profile:?}");
        }
    }
    use crate::client::{ObscuraNetError, SsrfGuardResolver};
    use crate::cookies::CookieJar;
    use wreq::dns::{Name, Resolve};

    // Mirrors client::ssrf_tests::resolver_blocks_hostname_that_resolves_to_loopback.
    // Both transports must agree: a host-string check alone cannot see that a
    // public name points inward, so the stealth client needs the same resolver.
    #[tokio::test]
    async fn stealth_resolver_blocks_hostname_that_resolves_to_loopback() {
        let resolver = SsrfGuardResolver::new(false);
        let res = resolver.resolve(Name::from("localtest.me")).await;
        assert!(res.is_err(), "localtest.me -> 127.0.0.1 must be blocked");
    }

    #[tokio::test]
    async fn stealth_resolver_does_not_block_public_host() {
        // Tolerate a no-network sandbox: only an actual SSRF rejection fails.
        let resolver = SsrfGuardResolver::new(false);
        match resolver.resolve(Name::from("example.com")).await {
            Ok(_) => {}
            Err(e) => assert!(
                !e.to_string().contains("SSRF blocked"),
                "example.com wrongly SSRF-blocked: {e}"
            ),
        }
    }

    const PLAIN_BODY: &str = "<!DOCTYPE html><html><body><p id=\"mark\">gzip ok</p></body></html>";

    #[test]
    fn tracker_blocking_environment_defaults_to_enabled() {
        for value in [
            None,
            Some(""),
            Some("1"),
            Some("true"),
            Some("yes"),
            Some("on"),
            Some("invalid"),
        ] {
            assert!(
                tracker_blocking_enabled(value),
                "{value:?} must leave tracker blocking enabled"
            );
        }
        for value in [
            Some("0"), Some("false"), Some(" NO "), Some("off"), Some(" FALSE "),
        ] {
            assert!(
                !tracker_blocking_enabled(value),
                "{value:?} must disable tracker blocking"
            );
        }
    }

    #[test]
    fn tracker_blocking_respects_host_and_setting() {
        let url = Url::parse("https://www.google-analytics.com/collect").unwrap();

        assert!(is_tracker_blocked(&url, true));
        assert!(!is_tracker_blocked(&url, false));
        assert!(!is_tracker_blocked(
            &Url::parse("https://example.com/").unwrap(), true,
        ));
        assert!(!is_tracker_blocked(
            &Url::parse("file:///tmp/page.html").unwrap(), true,
        ));
    }

    #[test]
    fn tracker_blocking_constructor_reads_environment() {
        let client = StealthHttpClient::new(Arc::new(CookieJar::new()));
        let expected = tracker_blocking_enabled(
            std::env::var("OBSCURA_BLOCK_TRACKERS").ok().as_deref(),
        );
        assert_eq!(client.block_trackers, expected);
    }

    async fn assert_tracker_blocking_request(scripted: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let mut client = StealthHttpClient::with_proxy(
            Arc::new(CookieJar::new()),
            Some(&proxy),
            true,
        );
        let url = Url::parse("http://www.google-analytics.com/collect").unwrap();
        let headers = std::collections::HashMap::new();

        client.block_trackers = true;
        let blocked = if scripted {
            client.send_single("GET", &url, &headers, &[], false, false)
                .await
        } else {
            client.fetch(&url).await
        }.expect("blocked tracker returns an empty response");
        assert_eq!(blocked.status, 0);
        assert!(blocked.body.is_empty());
        assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await.is_err());

        let server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await.expect("request reaches local proxy").unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut buffer = [0u8; 1024];
                let count = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                    .await.expect("request headers arrive").unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
            }
            assert!(String::from_utf8(request).unwrap().starts_with(
                "GET http://www.google-analytics.com/collect HTTP/1.1\r\n",
            ));
            stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await.unwrap();
        });

        client.block_trackers = false;
        let allowed = if scripted {
            client.send_single("GET", &url, &headers, &[], false, false)
                .await
        } else {
            client.fetch(&url).await
        }.expect("disabled blocking allows the request");
        assert_eq!(allowed.status, 200);
        assert_eq!(allowed.body, b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tracker_blocking_navigation_request() {
        assert_tracker_blocking_request(false).await;
    }

    #[tokio::test]
    async fn tracker_blocking_scripted_request() {
        assert_tracker_blocking_request(true).await;
    }

    // gzip (level 9) of PLAIN_BODY, hardcoded so the fixture needs no
    // compression dependency. A wrong byte fails the assert below.
    const GZIP_BODY: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xb3, 0x51,
        0x74, 0xf1, 0x77, 0x0e, 0x89, 0x0c, 0x70, 0x55, 0xc8, 0x28, 0xc9, 0xcd,
        0xb1, 0xb3, 0x81, 0x90, 0x49, 0xf9, 0x29, 0x95, 0x76, 0x36, 0x05, 0x0a,
        0x99, 0x29, 0xb6, 0x4a, 0xb9, 0x89, 0x45, 0xd9, 0x4a, 0x76, 0xe9, 0x55,
        0x99, 0x05, 0x0a, 0xf9, 0xd9, 0x36, 0xfa, 0x05, 0x76, 0x36, 0xfa, 0x10,
        0x69, 0x7d, 0xb0, 0x5a, 0x00, 0x80, 0x3d, 0x1c, 0x5f, 0x41, 0x00, 0x00,
        0x00,
    ];

    fn reset_fixture(respond_after_reset: bool) -> (u16, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let attempts = if respond_after_reset { 2 } else { 1 };
            for attempt in 0..attempts {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = stream.read(&mut buf).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..read]);
                }

                if attempt == 0 {
                    let socket = socket2::Socket::from(stream);
                    socket.set_linger(Some(Duration::ZERO)).unwrap();
                    drop(socket);
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .unwrap();
                }
            }
            attempts
        });
        (port, server)
    }

    #[tokio::test]
    async fn stealth_get_recovers_from_connection_reset() {
        let (port, server) = reset_fixture(true);
        let client = wreq::Client::builder().no_proxy().build().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let response = send_get_with_connection_reset_retry(client.get(url.as_str()), &url)
            .await
            .expect("an idempotent GET should recover from one connection reset");

        assert_eq!(response.status(), wreq::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
        assert_eq!(server.join().unwrap(), 2);
    }

    #[tokio::test]
    async fn stealth_post_does_not_retry_connection_reset() {
        let (port, server) = reset_fixture(false);
        let client = StealthHttpClient {
            client: wreq::Client::builder().no_proxy().build().unwrap(),
            allow_private_network: true,
            block_trackers: true,
            cookie_jar: Arc::new(CookieJar::new()),
            extra_headers: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            user_agent_override: tokio::sync::RwLock::new(None),
            in_flight: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            http_cache: None,
            profile: super::stealth_profile_headers(),
            proxy_url: None,
        };
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let error = client
            .send_single(
                "POST",
                &url,
                &std::collections::HashMap::new(),
                b"payload",
                false,
                false,
            )
            .await
            .expect_err("POST must not be retried after a connection reset");

        assert!(matches!(error, ObscuraNetError::Network(_)));
        assert_eq!(server.join().unwrap(), 1);
    }

    /// Serve one `Content-Encoding: gzip` response on an ephemeral port.
    async fn gzip_fixture() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        GZIP_BODY.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(GZIP_BODY).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        port
    }

    // The emulation profile advertises gzip, so origins compress. Without the
    // decoder the raw gzip bytes reach the HTML parser as document text.
    #[tokio::test]
    async fn stealth_client_decodes_gzip_response() {
        let port = gzip_fixture().await;
        let client = StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

        let resp = client.fetch(&url).await.expect("fixture must be reachable");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text(), PLAIN_BODY, "gzip body must be decompressed");
    }

    // #793: the opt-in must reach the DNS resolver. `validate_url` already
    // honours it for the localhost host, so a hostname target exercises the
    // resolver itself; before the fix the resolver was pinned to block and
    // refused loopback hostnames even with the flag set. Only the allowed
    // leg is asserted: CI sets OBSCURA_ALLOW_PRIVATE_NETWORK, which also
    // lifts the default block.
    #[tokio::test]
    async fn stealth_client_honors_allow_private_network_for_loopback_hostnames() {
        let port = gzip_fixture().await;
        let client = StealthHttpClient::with_proxy(Arc::new(CookieJar::new()), None, true);
        let url = Url::parse(&format!("http://localhost:{port}/")).unwrap();

        let resp = client
            .fetch(&url)
            .await
            .expect("loopback hostname must be reachable with the opt-in");
        assert_eq!(resp.status, 200);
    }
}
