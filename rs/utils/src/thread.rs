use std::num::NonZeroUsize;

/// Applies the function to each input item in parallel and returns the results.
/// The `i`-th element of the result corresponds to the `i`-ths input, but the
/// function application order is non-deterministic and depends on the available
/// threads in the given thread-pool.
///
/// Each thread takes the next `chunk_size` consecutive items as soon as it is
/// done with its previous ones, so that a few slow items don't leave the other
/// threads idle. Chunks are taken in input order, so callers can put the slowest
/// items first (with a `chunk_size` of 1).
///
/// Choose `chunk_size` per use: 1 for items that take a while (file I/O,
/// (de)serialization); more for µs-scale items, as taking a chunk costs a lock
/// acquisition (about 0.2 µs with 16 busy threads), or for runs of items that
/// contend if processed at the same time (e.g. creating files in the same
/// directory, which serializes on the directory's lock).
pub fn parallel_map<S, T, I, F>(
    thread_pool: &mut scoped_threadpool::Pool,
    items: I,
    chunk_size: NonZeroUsize,
    f: F,
) -> Vec<T>
where
    S: Send,
    T: Send,
    I: Iterator<Item = S>,
    F: Fn(&S) -> T + Send + Copy,
{
    let mut items: Vec<(S, Option<T>)> = items.map(|i| (i, None)).collect();
    let chunks = items.len().div_ceil(chunk_size.get());
    let threads = (thread_pool.thread_count() as usize).min(chunks);
    let next = std::sync::Mutex::new(items.chunks_mut(chunk_size.get()));
    thread_pool.scoped(|scope| {
        for _ in 0..threads {
            let next = &next;
            scope.execute(move || {
                loop {
                    // A statement of its own, so that the lock is released before `f` runs.
                    let chunk = next.lock().unwrap().next();
                    let Some(chunk) = chunk else { break };
                    for item in chunk {
                        item.1.replace(f(&item.0));
                    }
                }
            });
        }
    });
    items
        .into_iter()
        .map(|(_, result)| result.unwrap())
        .collect()
}

/// `parallel_map(_)` if thread_pool is `Some`; `map(_)` if `None`.
pub fn maybe_parallel_map<S, T, I, F>(
    thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
    items: I,
    chunk_size: NonZeroUsize,
    f: F,
) -> Vec<T>
where
    S: Send,
    T: Send,
    I: Iterator<Item = S>,
    F: Fn(&S) -> T + Send + Copy,
{
    match thread_pool {
        Some(thread_pool) => parallel_map(thread_pool, items, chunk_size, f),
        None => items.map(|x| f(&x)).collect::<Vec<T>>(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread_pool() -> scoped_threadpool::Pool {
        scoped_threadpool::Pool::new(4)
    }

    #[test]
    fn test_parallel_map() {
        let items: Vec<usize> = (1..1000).collect();
        let expected: Vec<usize> = items.iter().map(|x| x * 2).collect();
        let actual = parallel_map(
            &mut thread_pool(),
            items.into_iter(),
            NonZeroUsize::MIN,
            |x| x * 2,
        );
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_parallel_map_empty() {
        let items: Vec<usize> = Vec::new();
        let expected: Vec<usize> = items.clone();
        let actual = parallel_map(
            &mut thread_pool(),
            items.into_iter(),
            NonZeroUsize::MIN,
            |x| x * 2,
        );
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_parallel_map_single() {
        let items: Vec<usize> = vec![1];
        let expected: Vec<usize> = vec![2];
        let actual = parallel_map(
            &mut thread_pool(),
            items.into_iter(),
            NonZeroUsize::MIN,
            |x| x * 2,
        );
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_parallel_map_chunks_run_on_one_thread() {
        use std::sync::Mutex;

        // 95 items in chunks of 10: each chunk's items, the last chunk's 5 included, run on the
        // thread that took the chunk.
        let items: Vec<usize> = (0..95).collect();
        let threads = Mutex::new(vec![None; items.len()]);
        let threads_ref = &threads;
        let actual = parallel_map(
            &mut thread_pool(),
            items.iter().copied(),
            NonZeroUsize::new(10).unwrap(),
            |&i| {
                threads_ref.lock().unwrap()[i] = Some(std::thread::current().id());
                i * 2
            },
        );
        assert_eq!(items.iter().map(|i| i * 2).collect::<Vec<_>>(), actual);
        for chunk in threads.into_inner().unwrap().chunks(10) {
            assert!(
                chunk.iter().all(|t| t.is_some() && *t == chunk[0]),
                "{chunk:?}"
            );
        }
    }

    #[test]
    fn test_parallel_map_threads_take_the_next_item_when_free() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        // Item 0 only completes once all other items have. Were each thread given a fixed run
        // of consecutive items, the rest of item 0's run would never start.
        let items: Vec<usize> = (0..40).collect();
        let done = AtomicUsize::new(0);
        let done = &done;
        let actual = parallel_map(
            &mut thread_pool(),
            items.iter().copied(),
            NonZeroUsize::MIN,
            |&i| {
                if i == 0 {
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while done.load(Ordering::SeqCst) < 39 {
                        assert!(Instant::now() < deadline, "items after item 0 never ran");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                done.fetch_add(1, Ordering::SeqCst);
                i * 2
            },
        );
        assert_eq!(items.iter().map(|i| i * 2).collect::<Vec<_>>(), actual);
    }
}
