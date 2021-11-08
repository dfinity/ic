use std::thread;

/// An object that joins a thread when it's dropped. Mostly helpful to implement
/// graceful shutdowns.
///
/// Note that Rust destroys fields in the order of their declaration:
///
/// > The fields of a struct, tuple or enum variant are dropped in declaration
/// order.
///
/// See:
/// * https://doc.rust-lang.org/stable/reference/destructors.html
/// * https://github.com/rust-lang/rfcs/blob/master/text/1857-stabilize-drop-order.md
///
/// That means that if you have a send/receive channel to talk to the thread in
/// your struct as well, you should make JoinOnDrop the last field in your
/// struct.
pub struct JoinOnDrop<T>(Option<thread::JoinHandle<T>>);

impl<T> JoinOnDrop<T> {
    pub fn new(h: thread::JoinHandle<T>) -> Self {
        Self(Some(h))
    }

    /// Explicitly joins the thread.
    pub fn join(mut self) -> thread::Result<T> {
        // It's OK to unwrap here because the wrapped object can only become
        // None when it's out of scope.
        self.0.take().unwrap().join()
    }
}

impl<T> Drop for JoinOnDrop<T> {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            let _ = h.join();
        }
    }
}

/// Applies the function to each input item in parallel and returns the results.
/// The `i`-th element of the result corresponds to the `i`-ths input, but the
/// function application order is non-deterministic and depends on the available
/// threads in the given thread-pool.
pub fn parallel_map<S, T, I, F>(thread_pool: &mut scoped_threadpool::Pool, items: I, f: F) -> Vec<T>
where
    S: Send,
    T: Send,
    I: Iterator<Item = S>,
    F: Fn(&S) -> T + Send + Copy,
{
    let mut items: Vec<(S, Option<T>)> = items.map(|i| (i, None)).collect();
    let threads = thread_pool.thread_count() as usize;
    let items_per_thread = ((items.len() + threads - 1) / threads).max(1);
    thread_pool.scoped(|scope| {
        for items in items.chunks_mut(items_per_thread) {
            scope.execute(move || {
                for item in items.iter_mut() {
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
}
