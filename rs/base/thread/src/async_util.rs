use core::future::Future;

///  Executes async task in sync context without starving other independently
///  spawned tasks.
///
///  You must call the function from multi-threaded tokio context.
///
///  Often times we want to run an async function and wait for its results. We
///  want this without having to think about async calls, runtimes, executors,
///  joining, etc. This can be challenging and subtle.
///
///  Keep in mind that `async_safe_block_on_await` is correct but may have
/// performance  implications.
///
///  Examples:
///
/// ```
///     use ic_base_thread::async_safe_block_on_await;
///
///     fn sync_fn() {
///         let my_fut = async {2};
///         assert_eq!(async_safe_block_on_await(my_fut), 2);
///     }
/// ```
pub fn async_safe_block_on_await<T>(task: T) -> T::Output
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(task))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_async_safe_block_on_await() {
        let my_fut = async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            2
        };
        assert_eq!(async_safe_block_on_await(my_fut), 2);
    }
}
