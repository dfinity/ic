use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use futures_util::FutureExt;
use tokio::{
    runtime::Handle,
    task::{AbortHandle, JoinError, JoinSet},
};

/// Poor man's implementation of tokio_util::JoinMap.
/// Internally keys are cloned so large keys should be avoided.
/// Cancelling/panicing tasks can make the state of the JoinMap invalid.
/// But this is not an issue because this could only happen in these cases:
///     - The runtime is shutting down. In this case we don't care about the invalid state.
///     - A task panics. In this case the panic should be propagated.
///     - A task spawned on the Joinmap is unexpectedly cancelled. The API of this JoinMap
///       does expose any way of cancelling spawned tasks.
///     - Tasks can be only be cancelled by replacing them. In this case the internal invariant
///       tasks_by_key.len() == tasks.len() is preserved.
pub struct JoinMap<K, V> {
    tasks_by_key: HashMap<K, (AbortHandle, Arc<AtomicBool>)>,
    tasks: JoinSet<(V, (K, Arc<AtomicBool>))>,
}

impl<K, V> Default for JoinMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> JoinMap<K, V> {
    pub fn new() -> Self {
        Self {
            tasks_by_key: HashMap::new(),
            tasks: JoinSet::new(),
        }
    }
}

impl<K, V> JoinMap<K, V>
where
    K: Hash + Eq + Send + Clone + 'static,
    V: 'static,
{
    pub fn contains(&self, k: &K) -> bool {
        self.tasks_by_key.contains_key(k)
    }

    pub fn len(&self) -> usize {
        self.tasks_by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks_by_key.is_empty()
    }

    /// Spawns new task on the joinmap. If a task for this key already exists the
    /// existing task will be cancelled and replaced.
    /// Returns true if a existing task was replaced.
    pub fn spawn_on<F>(&mut self, key: K, task: F, handle: &Handle) -> bool
    where
        F: Future<Output = V>,
        F: Send + 'static,
        V: Send,
    {
        let key_c = key.clone();
        let replaced = Arc::new(AtomicBool::default());
        let replaced_c = replaced.clone();
        let task = task.map(move |f| (f, (key_c, replaced)));
        let jh = self
            .tasks_by_key
            .insert(key, (self.tasks.spawn_on(task, handle), replaced_c));

        jh.map(|(jh, replaced)| {
            jh.abort();
            replaced.store(true, Ordering::Release);
        })
        .is_some()
    }

    /// Since JoinSet::join_next is cancel safe this is also.
    /// If a task is overwritten `join_next` will not return it.
    pub async fn join_next(&mut self) -> Option<Result<(V, K), JoinError>> {
        let result = loop {
            let result = self.tasks.join_next().await;
            if let Some(Ok((_, (key, replaced)))) = &result {
                if replaced.load(Ordering::Acquire) {
                    continue;
                }
                self.tasks_by_key.remove(key);
            }
            if let Some(Err(e)) = &result {
                if e.is_cancelled() {
                    continue;
                }
            }
            break result;
        };

        result.map(|o| o.map(|(q, (k, _))| (q, k)))
    }

    /// Removes a task from the [`JoinMap`] with the associated key. Returns true if the key was found.
    pub fn remove(&mut self, key: &K) -> bool {
        self.tasks_by_key
            .remove(key)
            .map(|(abort_handle, replaced)| {
                abort_handle.abort();
                replaced.store(true, Ordering::Release);
            })
            .is_some()
    }

    /// Cancels all running tasks and waits for them. Will clear any internal data structure.
    pub async fn shutdown(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.tasks_by_key.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{runtime::Handle, sync::Barrier};

    use super::JoinMap;

    #[tokio::test]
    async fn test_add_task() {
        let rt = Handle::current();
        let mut jm: JoinMap<&str, u64> = JoinMap::new();
        jm.spawn_on(
            "task",
            async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                0
            },
            &rt,
        );

        assert_eq!(jm.len(), 1);
        assert!(jm.contains(&"task"));

        loop {
            if let Some(res) = jm.join_next().await {
                assert!(matches!(res, Ok((0, "task"))));
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_overwrite_cancel_task() {
        let rt = Handle::current();
        let mut jm: JoinMap<&str, u64> = JoinMap::new();
        jm.spawn_on(
            "task",
            async {
                tokio::time::sleep(Duration::from_secs(10000)).await;
                0
            },
            &rt,
        );

        assert_eq!(jm.len(), 1);
        assert!(jm.contains(&"task"));

        // Overwrite task. This causes the other task to be cancelled.
        jm.spawn_on("task", async { 1 }, &rt);

        // Verify that join_next only returns the second task
        loop {
            if let Some(res) = jm.join_next().await {
                assert!(matches!(res, Ok((1, "task"))));
                break;
            }
        }
        assert_eq!(jm.len(), 0);
    }

    #[tokio::test]
    async fn test_overwrite_completed_task() {
        let rt = Handle::current();
        let mut jm: JoinMap<&str, u64> = JoinMap::new();
        jm.spawn_on("task", async { 0 }, &rt);

        // Wait for jm.to finish
        tokio::time::sleep(Duration::from_millis(25)).await;

        assert_eq!(jm.len(), 1);
        assert!(jm.contains(&"task"));

        // Overwrite task. This causes the other completed task to be cancelled.
        let barrier = Arc::new(Barrier::new(2));
        let barrier_c = barrier.clone();
        jm.spawn_on(
            "task",
            async move {
                barrier.wait().await;
                tokio::time::sleep(Duration::from_secs(1)).await;
                1
            },
            &rt,
        );

        loop {
            assert_eq!(jm.len(), 1);
            barrier_c.wait().await;
            if let Some(res) = jm.join_next().await {
                assert!(matches!(res, Ok((1, "task"))));
                break;
            }
        }
        assert_eq!(jm.len(), 0);
    }
}
