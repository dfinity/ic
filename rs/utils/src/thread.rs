/// Applies the function to each input item in parallel and returns the results.
/// The `i`-th element of the result corresponds to the `i`-ths input, but the
/// function application order is non-deterministic and depends on the available
/// threads in the given thread-pool.
///
/// Each thread takes the next item as soon as it is done with its previous one,
/// so that a few slow items don't leave the other threads idle. Items are taken
/// in input order, so callers can put the slowest ones first.
///
/// Taking an item costs a lock acquisition: about 0.2 µs per item with 16 busy
/// threads. That is negligible for items doing file I/O or (de)serialization,
/// but not for µs-scale items, which are better grouped into batches.
pub fn parallel_map<S, T, I, F>(thread_pool: &mut scoped_threadpool::Pool, items: I, f: F) -> Vec<T>
where
    S: Send,
    T: Send,
    I: Iterator<Item = S>,
    F: Fn(&S) -> T + Send + Copy,
{
    let mut items: Vec<(S, Option<T>)> = items.map(|i| (i, None)).collect();
    let threads = (thread_pool.thread_count() as usize).min(items.len());
    let next = std::sync::Mutex::new(items.iter_mut());
    thread_pool.scoped(|scope| {
        for _ in 0..threads {
            let next = &next;
            scope.execute(move || {
                loop {
                    // A statement of its own, so that the lock is released before `f` runs.
                    let item = next.lock().unwrap().next();
                    let Some(item) = item else { break };
                    item.1.replace(f(&item.0));
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
    f: F,
) -> Vec<T>
where
    S: Send,
    T: Send,
    I: Iterator<Item = S>,
    F: Fn(&S) -> T + Send + Copy,
{
    match thread_pool {
        Some(thread_pool) => parallel_map(thread_pool, items, f),
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
        let actual = parallel_map(&mut thread_pool(), items.into_iter(), |x| x * 2);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_parallel_map_empty() {
        let items: Vec<usize> = Vec::new();
        let expected: Vec<usize> = items.clone();
        let actual = parallel_map(&mut thread_pool(), items.into_iter(), |x| x * 2);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_parallel_map_single() {
        let items: Vec<usize> = vec![1];
        let expected: Vec<usize> = vec![2];
        let actual = parallel_map(&mut thread_pool(), items.into_iter(), |x| x * 2);
        assert_eq!(expected, actual);
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
        let actual = parallel_map(&mut thread_pool(), items.iter().copied(), |&i| {
            if i == 0 {
                let deadline = Instant::now() + Duration::from_secs(10);
                while done.load(Ordering::SeqCst) < 39 {
                    assert!(Instant::now() < deadline, "items after item 0 never ran");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            done.fetch_add(1, Ordering::SeqCst);
            i * 2
        });
        assert_eq!(items.iter().map(|i| i * 2).collect::<Vec<_>>(), actual);
    }
}
