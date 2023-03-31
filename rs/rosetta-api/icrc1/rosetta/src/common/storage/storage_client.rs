use rusqlite::Connection;
use std::{path::Path, sync::Mutex};

#[derive(Debug)]
pub struct StorageClient {
    storage_connection: Mutex<Connection>,
}

impl StorageClient {
    /// Constructs a new SQLite in-persistent store.
    pub fn new_persistent(db_file_path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_file_path.parent().unwrap())?;
        let connection = rusqlite::Connection::open(db_file_path)?;
        Self::new(connection)
    }

    /// Constructs a new SQLite in-memory store.
    pub fn new_in_memory() -> anyhow::Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        Self::new(connection)
    }

    fn new(connection: rusqlite::Connection) -> anyhow::Result<Self> {
        let storage_client = Self {
            storage_connection: Mutex::new(connection),
        };
        storage_client
            .storage_connection
            .lock()
            .unwrap()
            .execute("PRAGMA foreign_keys = 1", [])?;
        Ok(storage_client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::test_utils::create_tmp_dir;

    #[test]
    fn smoke_test() {
        let storage_client_memory = StorageClient::new_in_memory();
        assert!(storage_client_memory.is_ok());
        let tmpdir = create_tmp_dir();
        let file_path = tmpdir.path().join("db.sqlite");
        let storage_client_persistent = StorageClient::new_persistent(&file_path);
        assert!(storage_client_persistent.is_ok());
    }
}
