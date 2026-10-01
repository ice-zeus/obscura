//! Own HTTP pool drivers independently of the thread running page JavaScript.
use std::future::Future;

/// Only Send transport data may leave the page runtime. In particular, Deno
/// async ops use deno_unsync and must remain on a current-thread runtime.
pub async fn run<F, T>(work: F) -> Result<T, tokio::task::JoinError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    static NETWORK: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("obscura-http")
            .enable_all()
            .build()
            .expect("HTTP transport runtime")
    });
    struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for AbortOnDrop<T> {
        fn drop(&mut self) { self.0.abort(); }
    }
    let mut task = AbortOnDrop(NETWORK.spawn(work));
    (&mut task.0).await
}
