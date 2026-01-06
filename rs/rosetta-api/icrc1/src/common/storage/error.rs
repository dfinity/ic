//! Error types for storage operations.

use std::fmt;

/// Errors that can occur during storage operations.
#[derive(Debug)]
pub enum StorageError {
    /// A rusqlite database operation failed.
    Rusqlite(rusqlite::Error),
    /// Multiple records were found when at most one was expected.
    MultipleRecordsFound(String),
    /// A data integrity constraint was violated.
    DataIntegrity(String),
    /// An internal error occurred (wraps anyhow::Error for complex operations).
    Internal(anyhow::Error),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Rusqlite(e) => write!(f, "Database error: {}", e),
            StorageError::MultipleRecordsFound(msg) => {
                write!(f, "Multiple records found: {}", msg)
            }
            StorageError::DataIntegrity(msg) => write!(f, "Data integrity error: {}", msg),
            StorageError::Internal(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Rusqlite(e) => Some(e),
            StorageError::Internal(e) => e.source(),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        StorageError::Rusqlite(e)
    }
}

impl From<anyhow::Error> for StorageError {
    fn from(e: anyhow::Error) -> Self {
        StorageError::Internal(e)
    }
}

/// Result type alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;
