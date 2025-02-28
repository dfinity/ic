use rusqlite::{Connection, Result as SqlResult};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum PoolError {
    #[error("Timeout while waiting for a connection")]
    Timeout,
    #[error("Pool is empty (internal error)")]
    PoolEmpty,
    #[error(transparent)]
    RusqliteError(#[from] rusqlite::Error),
    #[error(transparent)]
    AcquireError(#[from] tokio::sync::AcquireError),
}

/// This enum lets you choose between an in‑memory and a file‑based SQLite connection.
#[derive(Clone, Debug)]
pub enum SQLiteConnectionPoolType {
    InMemory,
    WithFile(String),
}

impl SQLiteConnectionPoolType {
    pub fn new_connection(&self) -> SqlResult<Connection> {
        match self {
            SQLiteConnectionPoolType::InMemory => Connection::open_in_memory(),
            SQLiteConnectionPoolType::WithFile(path) => Connection::open(path),
        }
    }
}

/// The connection pool uses an `Rc<RefCell<...>>` for the connections (since we’re single‑threaded)
/// and an Arc‑wrapped semaphore to allow asynchronous waiting.
#[derive(Clone)]
pub struct SQLiteConnectionPool {
    connections: Rc<RefCell<Vec<Connection>>>,
    semaphore: Arc<Semaphore>,
    timeout_duration: Duration,
}

impl SQLiteConnectionPool {
    /// Create a new pool of `size` connections using the provided connection type.
    pub fn new(
        size: usize,
        pool_type: SQLiteConnectionPoolType,
        timeout_duration: Duration,
    ) -> SqlResult<Self> {
        let mut conns = Vec::with_capacity(size);
        for _ in 0..size {
            conns.push(pool_type.new_connection()?);
        }
        Ok(Self {
            connections: Rc::new(RefCell::new(conns)),
            semaphore: Arc::new(Semaphore::new(size)),
            timeout_duration,
        })
    }

    /// Convenience method for a file‑based pool.
    pub fn new_with_file(
        size: usize,
        db_path: &str,
        timeout_duration: Duration,
    ) -> SqlResult<Self> {
        Self::new(
            size,
            SQLiteConnectionPoolType::WithFile(db_path.to_string()),
            timeout_duration,
        )
    }

    /// Convenience method for an in‑memory pool.
    pub fn new_in_memory(size: usize, timeout_duration: Duration) -> SqlResult<Self> {
        Self::new(size, SQLiteConnectionPoolType::InMemory, timeout_duration)
    }

    /// Asynchronously acquire a connection from the pool.
    /// If a connection isn’t available within the timeout, a PoolError::Timeout is returned.
    pub async fn get(&self) -> Result<PooledConnection, PoolError> {
        let permit = timeout(
            self.timeout_duration,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| PoolError::Timeout)??;
        // The semaphore guarantees that a connection is available.
        let conn = self
            .connections
            .borrow_mut()
            .pop()
            .ok_or(PoolError::PoolEmpty)?;
        Ok(PooledConnection {
            conn: Some(conn),
            pool: self.clone(),
            _permit: permit,
        })
    }

    /// Return a connection back to the pool.
    fn return_connection(&self, conn: Connection) {
        self.connections.borrow_mut().push(conn);
        // The semaphore permit is automatically released when the PooledConnection is dropped.
    }
}

/// A guard that holds a connection for the duration of its lifetime.
/// When dropped, it automatically returns the connection to the pool.
pub struct PooledConnection {
    conn: Option<Connection>,
    pool: SQLiteConnectionPool,
    _permit: OwnedSemaphorePermit,
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.return_connection(conn);
        }
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("Connection missing")
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("Connection missing")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::task::spawn_local;
    use tokio::time::sleep;

    // Note: All tests use the current_thread runtime.
    #[tokio::test(flavor = "current_thread")]
    async fn test_new_in_memory() {
        let pool = SQLiteConnectionPool::new_in_memory(2, Duration::from_secs(1)).unwrap();
        assert_eq!(pool.connections.borrow().len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_new_with_file() {
        // Using ":memory:" here is still valid.
        let pool =
            SQLiteConnectionPool::new_with_file(2, ":memory:", Duration::from_secs(1)).unwrap();
        assert_eq!(pool.connections.borrow().len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_get_and_return_connection() {
        let pool = SQLiteConnectionPool::new_in_memory(2, Duration::from_secs(1)).unwrap();
        {
            let _conn = pool.get().await.unwrap();
            // One connection is checked out; one remains.
            assert_eq!(pool.connections.borrow().len(), 1);
        }
        // After the guard is dropped, both connections should be back.
        sleep(Duration::from_millis(10)).await;
        assert_eq!(pool.connections.borrow().len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_get_timeout() {
        let pool = SQLiteConnectionPool::new_in_memory(1, Duration::from_millis(100)).unwrap();
        // Acquire the only connection.
        let _conn = pool.get().await.unwrap();
        // Now, getting another should timeout.
        let result = pool.get().await;
        match result {
            Err(PoolError::Timeout) => {} // expected
            _ => panic!("Expected timeout error"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_pooled_connection_usage() {
        let pool = SQLiteConnectionPool::new_in_memory(1, Duration::from_secs(1)).unwrap();
        {
            let conn = pool.get().await.unwrap();
            conn.execute("CREATE TABLE test (id INTEGER)", []).unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1);
        }
        sleep(Duration::from_millis(10)).await;
        assert_eq!(pool.connections.borrow().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_multiple_concurrent_tasks() {
        let pool = SQLiteConnectionPool::new_in_memory(2, Duration::from_secs(1)).unwrap();
        let pool1 = pool.clone();
        let pool2 = pool.clone();
        let pool3 = pool.clone();

        // Create a LocalSet to run non-Send tasks.
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async move {
                let task1 = spawn_local(async move {
                    let conn = pool1.get().await.unwrap();
                    conn.execute("CREATE TABLE IF NOT EXISTS test1 (id INTEGER)", [])
                        .unwrap();
                    sleep(Duration::from_secs(2)).await;
                    Ok::<(), PoolError>(())
                });

                let task2 = spawn_local(async move {
                    let conn = pool2.get().await.unwrap();
                    conn.execute("CREATE TABLE IF NOT EXISTS test2 (id INTEGER)", [])
                        .unwrap();
                    sleep(Duration::from_secs(2)).await;
                    Ok::<(), PoolError>(())
                });

                let task3 = spawn_local(async move {
                    let conn = pool3.get().await.unwrap();
                    conn.execute("CREATE TABLE IF NOT EXISTS test2 (id INTEGER)", [])
                        .unwrap();
                    sleep(Duration::from_secs(2)).await;
                    Ok::<(), PoolError>(())
                });

                let mut num_failed_tasks = 0;
                for task in [task1, task2, task3] {
                    if let Err(e) = task.await {
                        eprintln!("Task failed: {}", e);
                        num_failed_tasks += 1;
                    }
                }

                // One of them should fail due to the timeout.
                assert_eq!(num_failed_tasks, 1);
            })
            .await;

        sleep(Duration::from_millis(10)).await;
        // Both connections should be returned.
        assert_eq!(pool.connections.borrow().len(), 2);
    }
}
