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

/// parallel_map(...) if thread_pool is Some(); map if None.
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
}
