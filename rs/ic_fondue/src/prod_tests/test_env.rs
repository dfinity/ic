use anyhow::{anyhow, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::path::{Path, PathBuf};

/// A TestEnv represents a directory storing all state related to a test.
///
/// It has operations for reading and writing objects as JSON from paths relative to the directory.
pub struct TestEnv(PathBuf);

impl TestEnv {
    pub fn read_object<T: DeserializeOwned, P: AsRef<Path>>(&self, p: P) -> Result<T> {
        let file = File::open(self.get_path(p))?;
        serde_json::from_reader(file).map_err(|e| anyhow!(e.to_string()))
    }
    pub fn write_object<T: Serialize, P: AsRef<Path>>(&self, p: P, t: T) -> Result<()> {
        ic_utils::fs::write_atomically(self.get_path(p), |buf| {
            serde_json::to_writer(buf, &t)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
        .map_err(|e| anyhow!(e.to_string()))
    }
    pub fn get_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        self.0.join(p)
    }
}
