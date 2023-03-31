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
        storage_client.create_tables()?;
        Ok(storage_client)
    }

    fn create_tables(&self) -> anyhow::Result<()> {
        let open_connection = self.storage_connection.lock().unwrap();
        open_connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                hash BLOB NOT NULL,
                serialized_block BLOB NOT NULL,
                parent_hash BLOB,
                idx INTEGER NOT NULL PRIMARY KEY,
                verified BOOLEAN)
            "#,
            [],
        )?;
        open_connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS transactions (
                block_idx INTEGER NOT NULL,
                tx_hash BLOB NOT NULL,
                operation_type VARCHAR(255) NOT NULL,
                from_principal BLOB,
                from_subaccount BLOB,
                to_principal BLOB,
                to_subaccount BLOB,
                memo BLOB,
                amount INTEGER,
                fee INTEGER,
                transaction_created_at_time INTEGER,
                PRIMARY KEY(block_idx),
                FOREIGN KEY(block_idx) REFERENCES blocks(idx)
            )
            "#,
            [],
        )?;
        open_connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS account_balance_history (
                principal BLOB NOT NULL,
                subaccount BLOB NOT NULL,
                block_idx  NOT NULL,
                tokens INTEGER NOT NULL,
                PRIMARY KEY(principal,subaccount,block_idx)
                FOREIGN KEY(block_idx) REFERENCES blocks(idx)
            )
            "#,
            [],
        )?;
        Ok(())
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
