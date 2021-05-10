use ic_types::Height;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum LayoutError {
    /// Wraps a `std::io::Error`, a message and the path of the
    /// affected file/directory.
    IoError {
        path: PathBuf,
        message: String,
        io_err: std::io::Error,
    },

    /// The state root doesn't have the expected layout.  It's either wrong or
    /// was corrupted.
    CorruptedLayout { path: PathBuf, message: String },

    /// Checkpoint at the specified height already exists.
    AlreadyExists(Height),

    /// Checkpoint for the requested height not found.
    NotFound(Height),
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError {
                path,
                message,
                io_err,
            } => write!(
                f,
                "I/O error while accessing file {}: {}: {}",
                path.display(),
                message,
                io_err
            ),
            Self::CorruptedLayout { path, message } => write!(
                f,
                "detected state layout corruption at {}: {}",
                path.display(),
                message,
            ),
            Self::NotFound(height) => write!(f, "no checkpoint @{} found", height),
            Self::AlreadyExists(height) => write!(
                f,
                "failed to create checkpoint at height {} because it already exists",
                height
            ),
        }
    }
}
