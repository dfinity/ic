use std::{collections::HashMap, future::Future, hash::Hash};

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
///     - A task spawned on the Joinmap is unexpectetly cancelled. The API of this JoinMap
///       does expose any way of cancelling spawned tasks.
///     - Tasks can be only be cancelled by replacing them. In this case the internal invariant
///       tasks_by_key.len() == tasks.len() is preserved.
pub struct JoinMap<K, V> {
    tasks_by_key: HashMap<K, AbortHandle>,
    tasks: JoinSet<(V, K)>,
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
        let task = task.map(|f| (f, key_c));
        let jh = self
            .tasks_by_key
            .insert(key, self.tasks.spawn_on(task, handle));

        jh.map(|jh| jh.abort()).is_some()
    }

    /// Spawns new blocking task on the joinmap. If a task for this key already exists the
    /// existing task will be cancelled and replaced.
    /// Returns true if a existing task was replaced.
    pub fn spawn_blocking_on<F>(&mut self, key: K, f: F, handle: &Handle) -> bool
    where
        F: FnOnce() -> V,
        F: Send + 'static,
        V: Send,
    {
        let key_c = key.clone();
        let f = move || (f(), key_c);
        let jh = self
            .tasks_by_key
            .insert(key, self.tasks.spawn_blocking_on(f, handle));

        jh.map(|jh| jh.abort()).is_some()
    }

    /// Since JoinSet::join_next is cancel safe this is also.
    pub async fn join_next(&mut self) -> Option<Result<(V, K), JoinError>> {
        let result = self.tasks.join_next().await;
        if let Some(Ok((_, ref k))) = result {
            self.tasks_by_key.remove(k);
        }
        result
    }

    /// Cancels all running tasks and waits for them. Will clear any internal data structure.
    pub async fn shutdown(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.tasks_by_key.clear();
    }
}
