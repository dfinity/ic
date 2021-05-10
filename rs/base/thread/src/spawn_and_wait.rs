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
///  Keep in mind that `spawn_and_wait` is correct but may have performance
///  implications.
///
///  Examples:
///
/// ```
///     use ic_base_thread::spawn_and_wait;
///
///     fn sync_fn() {
///         let my_fut = async {2};
///         assert_eq!(spawn_and_wait(my_fut), 2);
///     }
/// ```
pub fn spawn_and_wait<T>(task: T) -> T::Output
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::channel();

    tokio::task::spawn(async move {
        // sender.send is non-blocking.
        let res = task.await;
        // Doesn't block the current thread.
        // Won't panic since the receiver is alive.
        sender.send(res).unwrap();
    });
    tokio::task::block_in_place(|| {
        // Although, this call is blocking, it won't block the executor so it
        // can drive other futures forward. It won't panic since a message is
        // sent.
        receiver.recv().unwrap()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(threaded_scheduler)]
    async fn test_spawn_and_wait() {
        let my_fut = async {
            tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
            2
        };
        assert_eq!(spawn_and_wait(my_fut), 2);
    }
}
