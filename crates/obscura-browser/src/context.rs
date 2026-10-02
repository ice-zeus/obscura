use std::path::PathBuf;
use std::sync::Arc;

use obscura_net::{CookieJar, HttpCache, ObscuraHttpClient, RobotsCache};

pub struct BrowserContext {
    pub id: String,
    pub cookie_jar: Arc<CookieJar>,
    pub http_client: Arc<ObscuraHttpClient>,
    pub user_agent: String,
    pub platform: String,
    pub ua_platform: String,
    pub ua_platform_version: String,
    pub proxy_url: Option<String>,
    pub robots_cache: Arc<RobotsCache>,
    pub obey_robots: bool,
    pub stealth: bool,
    /// When true, CDP-driven navigation to file:// URLs is permitted.
    /// Default is false: a remote CDP client cannot point the browser
    /// at /etc/shadow even if Obscura is running as a privileged user.
    /// Flip on via `obscura serve --allow-file-access` for legitimate
    /// local-HTML testing workflows. Enforced by `Page` navigation itself,
    /// so every CDP and MCP route is covered; the CLI's own `obscura fetch
    /// file://...` opts its local context in. A page can never drive
    /// itself from a web origin into file:// regardless of this flag.
    pub allow_file_access: bool,
    pub storage_dir: Option<PathBuf>,
    /// When true, the http client allows fetching localhost / RFC1918 /
    /// link-local addresses. Set via `--allow-private-network` (issue #33).
    /// Independent of `allow_file_access` because they cover different threat
    /// models: file:// is a local file-system read, while private-network is
    /// the broader SSRF gate from issue #4.
    pub allow_private_network: bool,
    /// Seed of the stealth fingerprint surfaces for this profile. Every page,
    /// frame and worker of the context reports values derived from it, so
    /// they stay stable across navigations (see `obscura_js::fingerprint`).
    pub fingerprint_seed: u32,
    /// Seed pinned by the embedder, from which additional contexts derive
    /// their own reproducible seeds. `None` draws a random seed per context.
    fingerprint_seed_base: Option<u32>,
    /// The profile's HTTP cache for the stealth transport, shared by its pages
    /// and never by another profile (`OBSCURA_HTTP_CACHE`, see
    /// `obscura_net::http_cache`). `None` without stealth or when disabled.
    pub http_cache: Option<Arc<HttpCache>>,
}

impl BrowserContext {
    pub fn new(id: String) -> Self {
        Self::_new_inner(id, None, false, None, None, false)
    }

    /// Create a BrowserContext with an optional storage directory.
    /// When `storage_dir` is set, cookies are automatically loaded from
    /// `{storage_dir}/cookies.json` on creation.
    pub fn with_storage(
        id: String,
        storage_dir: Option<PathBuf>,
    ) -> Self {
        Self::_new_inner(id, None, false, None, storage_dir, false)
    }

    /// Create a BrowserContext with full options including storage_dir.
    pub fn with_storage_full(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
    ) -> Self {
        Self::_new_inner(id, proxy_url, stealth, user_agent, storage_dir, false)
    }

    /// Variant that also accepts the `allow_private_network` opt-in. All
    /// pre-existing constructors default it to `false`; callers that want the
    /// CLI's `--allow-private-network` (issue #33) behaviour go through here.
    pub fn with_storage_and_network(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
        allow_private_network: bool,
    ) -> Self {
        Self::_new_inner(id, proxy_url, stealth, user_agent, storage_dir, allow_private_network)
    }

    fn _new_inner(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
        allow_private_network: bool,
    ) -> Self {
        let cookie_jar = Arc::new(CookieJar::new());

        // Restore cookies from disk if storage_dir is configured
        if let Some(ref dir) = storage_dir {
            let cookie_path = dir.join("cookies.json");
            if cookie_path.exists() {
                match cookie_jar.load_from_file(&cookie_path) {
                    Ok(n) if n > 0 => {
                        tracing::info!("Loaded {} cookies from {}", n, cookie_path.display());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Failed to load cookies from {}: {}", cookie_path.display(), e);
                    }
                }
            }
        }

        let mut client = ObscuraHttpClient::with_full_options(
            cookie_jar.clone(),
            proxy_url.as_deref(),
            allow_private_network,
        );
        if stealth {
            client.block_trackers = true;
        }
        let profile = crate::profiles::select_profile();
        let resolved_ua = user_agent.unwrap_or_else(|| profile.user_agent.to_string());
        let platform = profile.platform.to_string();
        let ua_platform = profile.ua_platform.to_string();
        let ua_platform_version = profile.ua_platform_version.to_string();
        // Sync the http client's UA at construction so navigation requests pick it
        // up before any async setup runs. The lock has no other holders here, so
        // try_write always succeeds; we fall back silently if it ever fails.
        if let Ok(mut guard) = client.user_agent.try_write() {
            *guard = resolved_ua.clone();
        }
        let http_client = Arc::new(client);
        let fingerprint_seed_base = obscura_js::fingerprint::seed_from_env();
        let fingerprint_seed =
            fingerprint_seed_base.unwrap_or_else(obscura_js::fingerprint::random_seed);
        let http_cache = if stealth { HttpCache::from_env(storage_dir.as_deref()) } else { None };
        BrowserContext {
            id,
            cookie_jar,
            http_client,
            user_agent: resolved_ua,
            platform,
            ua_platform,
            ua_platform_version,
            proxy_url,
            robots_cache: Arc::new(RobotsCache::new()),
            obey_robots: false,
            stealth,
            allow_file_access: false,
            storage_dir,
            allow_private_network,
            fingerprint_seed,
            fingerprint_seed_base,
            http_cache,
        }
    }

    /// Pin this profile's fingerprint seed, for embedders that keep a profile
    /// across restarts. Contexts copied from this one with `persistent` keep
    /// the seed; other copies derive their own seed from it.
    pub fn with_fingerprint_seed(mut self, seed: u32) -> Self {
        self.fingerprint_seed = seed;
        self.fingerprint_seed_base = Some(seed);
        self
    }

    pub fn with_options(id: String, proxy_url: Option<String>, stealth: bool) -> Self {
        Self::with_full_options(id, proxy_url, stealth, None)
    }

    pub fn with_full_options(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
    ) -> Self {
        Self::_new_inner(id, proxy_url, stealth, user_agent, None, false)
    }

    pub fn with_proxy(id: String, proxy_url: Option<String>) -> Self {
        Self::with_options(id, proxy_url, false)
    }

    /// Create a context with the same browser configuration but independent
    /// mutable network state. Persistent copies start with the template's
    /// current cookies; incognito copies start empty and never write to the
    /// template's storage directory.
    pub fn isolated_copy(&self, id: String, persistent: bool) -> Self {
        // A persistent copy is the same profile (the CDP server makes one per
        // connection), so it keeps the device fingerprint. Any other copy is a
        // new profile with its own seed.
        let fingerprint_seed = if persistent {
            self.fingerprint_seed
        } else {
            match self.fingerprint_seed_base {
                Some(base) => obscura_js::fingerprint::derive_seed(base, &id),
                None => obscura_js::fingerprint::random_seed(),
            }
        };
        let cookie_jar = Arc::new(CookieJar::new());
        if persistent {
            cookie_jar.copy_from(&self.cookie_jar);
        }

        let mut client = ObscuraHttpClient::with_full_options(
            cookie_jar.clone(),
            self.proxy_url.as_deref(),
            self.allow_private_network,
        );
        if self.stealth {
            client.block_trackers = true;
        }
        if let Ok(mut guard) = client.user_agent.try_write() {
            *guard = self.user_agent.clone();
        }

        BrowserContext {
            id,
            cookie_jar,
            http_client: Arc::new(client),
            user_agent: self.user_agent.clone(),
            platform: self.platform.clone(),
            ua_platform: self.ua_platform.clone(),
            ua_platform_version: self.ua_platform_version.clone(),
            proxy_url: self.proxy_url.clone(),
            robots_cache: Arc::new(RobotsCache::new()),
            obey_robots: self.obey_robots,
            stealth: self.stealth,
            allow_file_access: self.allow_file_access,
            storage_dir: persistent.then(|| self.storage_dir.clone()).flatten(),
            allow_private_network: self.allow_private_network,
            fingerprint_seed,
            fingerprint_seed_base: self.fingerprint_seed_base,
            // A persistent copy is the same profile and keeps its cache; any
            // other copy is a new profile with an empty one.
            http_cache: if persistent {
                self.http_cache.clone()
            } else if self.stealth {
                HttpCache::from_env(None)
            } else {
                None
            },
        }
    }

    /// Persist cookies to disk if storage_dir is configured.
    /// Called during graceful shutdown.
    pub fn save_cookies(&self) {
        if let Some(ref dir) = self.storage_dir {
            let _ = std::fs::create_dir_all(dir);
            let cookie_path = dir.join("cookies.json");
            if let Err(e) = self.cookie_jar.save_to_file(&cookie_path) {
                tracing::warn!("Failed to save cookies to {}: {}", cookie_path.display(), e);
            } else {
                tracing::info!("Saved cookies to {}", cookie_path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn with_full_options_propagates_user_agent_to_http_client() {
        let ctx = BrowserContext::with_full_options(
            "test".to_string(),
            None,
            false,
            Some("Custom-UA/1.0".to_string()),
        );
        assert_eq!(ctx.user_agent, "Custom-UA/1.0");
        let client_ua = ctx.http_client.user_agent.read().await.clone();
        assert_eq!(client_ua, "Custom-UA/1.0");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_full_options_falls_back_to_chrome_default() {
        let ctx = BrowserContext::with_full_options(
            "test".to_string(),
            None,
            false,
            None,
        );
        assert!(ctx.user_agent.contains("Chrome"));
        let client_ua = ctx.http_client.user_agent.read().await.clone();
        assert!(client_ua.contains("Chrome"));
        assert_eq!(ctx.user_agent, client_ua);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_options_keeps_default_user_agent() {
        let ctx = BrowserContext::with_options("test".to_string(), None, false);
        assert!(ctx.user_agent.contains("Chrome"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn isolated_copy_does_not_share_mutable_network_state() {
        let source = BrowserContext::with_full_options(
            "source".to_string(),
            None,
            false,
            Some("Template-UA/1.0".to_string()),
        );
        source.cookie_jar.set_cookie("sid=source", &url::Url::parse("https://example.com").unwrap());

        let persistent = source.isolated_copy("persistent".to_string(), true);
        let incognito = source.isolated_copy("incognito".to_string(), false);

        assert_eq!(persistent.cookie_jar.get_all_cookies().len(), 1);
        assert!(incognito.cookie_jar.get_all_cookies().is_empty());
        assert!(persistent
            .cookie_jar
            .get_cookie_header(&url::Url::parse("https://sub.example.com").unwrap())
            .is_empty());
        persistent.cookie_jar.clear();
        persistent.http_client.set_user_agent("Changed-UA/2.0").await;

        assert_eq!(source.cookie_jar.get_all_cookies().len(), 1);
        assert_eq!(source.http_client.user_agent.read().await.as_str(), "Template-UA/1.0");
    }
    // The stealth fingerprint belongs to the profile: the CDP server's
    // per-connection copy keeps it, every other context is a new profile.
    #[tokio::test(flavor = "current_thread")]
    async fn fingerprint_seed_is_stable_per_profile_and_varies_between_profiles() {
        let template = BrowserContext::with_options("default".to_string(), None, true);
        let connection = template.isolated_copy("default".to_string(), true);
        assert_eq!(connection.fingerprint_seed, template.fingerprint_seed);
        assert_eq!(
            connection.isolated_copy("default".to_string(), true).fingerprint_seed,
            template.fingerprint_seed
        );

        let created: std::collections::HashSet<u32> = (1..=16)
            .map(|i| template.isolated_copy(format!("context-{i}"), false).fingerprint_seed)
            .collect();
        assert!(created.len() >= 15, "new browser contexts reused seeds: {created:?}");
        let fresh: std::collections::HashSet<u32> = (0..16)
            .map(|_| BrowserContext::with_options("default".to_string(), None, true).fingerprint_seed)
            .collect();
        assert!(fresh.len() >= 15, "new profiles reused seeds: {fresh:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pinned_fingerprint_seed_is_reproducible_across_restarts() {
        let first = BrowserContext::with_options("default".to_string(), None, true).with_fingerprint_seed(7);
        let restarted = BrowserContext::with_options("default".to_string(), None, true).with_fingerprint_seed(7);
        assert_eq!(first.fingerprint_seed, 7);
        assert_eq!(first.isolated_copy("default".to_string(), true).fingerprint_seed, 7);
        let derived = first.isolated_copy("context-1".to_string(), false).fingerprint_seed;
        assert_eq!(derived, restarted.isolated_copy("context-1".to_string(), false).fingerprint_seed);
        assert_ne!(derived, 7);
        assert_ne!(derived, first.isolated_copy("context-2".to_string(), false).fingerprint_seed);
    }

    // The HTTP cache is per profile: pages and the per-connection persistent
    // copy share it, every other context gets its own.
    #[tokio::test(flavor = "current_thread")]
    async fn http_cache_is_shared_within_a_profile_and_never_across_profiles() {
        let template = BrowserContext::with_options("default".to_string(), None, true);
        let cache = template.http_cache.clone().expect("stealth contexts cache by default");
        let connection = template.isolated_copy("default".to_string(), true);
        assert!(Arc::ptr_eq(&cache, connection.http_cache.as_ref().unwrap()));
        let other = template.isolated_copy("context-1".to_string(), false);
        assert!(!Arc::ptr_eq(&cache, other.http_cache.as_ref().unwrap()));
        assert!(BrowserContext::with_options("plain".to_string(), None, false).http_cache.is_none());
    }

    // nextest runs every test in its own process, so the variable does not
    // leak into other tests.
    #[tokio::test(flavor = "current_thread")]
    async fn embedder_pins_the_seed_through_the_environment() {
        std::env::set_var(obscura_js::fingerprint::FINGERPRINT_SEED_ENV, "0x2a");
        let context = BrowserContext::with_options("default".to_string(), None, true);
        assert_eq!(context.fingerprint_seed, 42);
        assert_eq!(context.isolated_copy("default".to_string(), true).fingerprint_seed, 42);
        std::env::set_var(obscura_js::fingerprint::FINGERPRINT_SEED_ENV, "pulse-profile-3");
        let labelled = BrowserContext::with_options("default".to_string(), None, true);
        assert_eq!(
            Some(labelled.fingerprint_seed),
            obscura_js::fingerprint::parse_seed("pulse-profile-3")
        );
        std::env::remove_var(obscura_js::fingerprint::FINGERPRINT_SEED_ENV);
    }
}
