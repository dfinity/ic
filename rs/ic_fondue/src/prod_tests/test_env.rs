use anyhow::{Context, Result};
use ic_utils::fs::sync_path;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use super::pot_dsl::TestPath;

/// A TestEnv represents a directory storing all state related to a test.
///
/// It has operations for reading and writing objects as JSON from paths relative to the directory.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TestEnv(PathBuf);

impl TestEnv {
    pub fn new<P: AsRef<Path>>(path: P) -> TestEnv {
        TestEnv(PathBuf::from(path.as_ref()))
    }

    pub fn read_object<T: DeserializeOwned, P: AsRef<Path>>(&self, p: P) -> Result<T> {
        let path = self.get_path(&p);
        let file = File::open(&path).with_context(|| format!("Could not open: {:?}", path))?;
        serde_json::from_reader(file).with_context(|| format!("{:?}: Could not read json.", path))
    }

    pub fn write_object<T: Serialize, P: AsRef<Path>>(&self, p: P, t: &T) -> Result<()> {
        let path = self.get_path(&p);
        if let Some(parent_dir) = path.parent() {
            fs::create_dir_all(parent_dir)?;
        }
        ic_utils::fs::write_atomically(&path, |buf| {
            serde_json::to_writer(buf, &t)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
        .with_context(|| format!("{:?}: Could not write json object.", path))
    }

    pub fn get_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        self.0.join(p)
    }

    pub fn base_dir(&self) -> PathBuf {
        self.0.clone()
    }

    pub fn fork<P: AsRef<Path>>(&self, dir: P) -> Result<TestEnv> {
        let mut options = fs_extra::dir::CopyOptions::new();
        options.copy_inside = true;
        options.content_only = true;
        fs_extra::dir::copy(self.base_dir(), &dir, &options)?;
        sync_path(&dir)?;
        Ok(TestEnv::new(dir))
    }
}

pub trait HasBaseLogDir {
    fn write_base_log_dir<P: AsRef<Path>>(&self, p: P) -> Result<()>;

    /// Returns the base dir (if specified) where logs are to be stored. This is
    /// to remain backwards compatible with the existing test setup. In the
    /// future, the logs of tests will just be stored in the corresponding test
    /// env which contains other artifacts too.
    fn base_log_dir(&self) -> Option<PathBuf>;
}

impl HasBaseLogDir for TestEnv {
    fn base_log_dir(&self) -> Option<PathBuf> {
        self.read_object("base_log_dir").ok()
    }

    fn write_base_log_dir<P: AsRef<Path>>(&self, p: P) -> Result<()> {
        self.write_object(BASE_LOG_DIR_PATH, &p.as_ref())
    }
}

pub trait HasTestPath {
    /// This function is to be removed eventually as the path of the test env
    /// itself is to serve as the test path.
    fn write_test_path(&self, test_path: &TestPath) -> Result<()>;

    /// # Panics
    ///
    /// This function panics if the test path is not available.
    fn test_path(&self) -> TestPath;
}

impl HasTestPath for TestEnv {
    fn write_test_path(&self, test_path: &TestPath) -> Result<()> {
        self.write_object(TEST_PATH, test_path)
    }

    fn test_path(&self) -> TestPath {
        self.read_object(TEST_PATH).unwrap()
    }
}

const TEST_PATH: &str = "test_path.json";
const BASE_LOG_DIR_PATH: &str = "base_log_dir.path.json";
