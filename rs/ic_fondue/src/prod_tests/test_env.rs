use anyhow::{anyhow, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// A TestEnv represents a directory storing all state related to a test.
///
/// It has operations for reading and writing objects as JSON from paths relative to the directory.
#[derive(Clone)]
pub struct TestEnv(PathBuf);

impl TestEnv {
    pub fn new(path: PathBuf) -> TestEnv {
        TestEnv(path)
    }
    pub fn read_object<T: DeserializeOwned, P: AsRef<Path>>(&self, p: P) -> Result<T> {
        let file = File::open(self.get_path(&p))?;
        serde_json::from_reader(file).map_err(|e| anyhow!(e.to_string()))
    }
    pub fn write_object<T: Serialize, P: AsRef<Path>>(&self, p: P, t: T) -> Result<()> {
        let path = self.get_path(&p);
        if let Some(parent_dir) = path.parent() {
            fs::create_dir_all(parent_dir).expect("could not create a parent dir");
        }
        ic_utils::fs::write_atomically(&path, |buf| {
            serde_json::to_writer(buf, &t)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
        .map_err(|e| anyhow!(e.to_string()))
    }
    pub fn get_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        self.0.join(p)
    }
    pub fn base_dir(&self) -> PathBuf {
        self.0.clone()
    }
    pub fn fork(&self, dir: PathBuf) -> Result<TestEnv> {
        let mut options = fs_extra::dir::CopyOptions::new();
        options.copy_inside = true;
        fs_extra::dir::copy(self.base_dir(), &dir, &options)?;
        Ok(TestEnv::new(dir))
    }
}
