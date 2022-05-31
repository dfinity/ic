use anyhow::{Context, Result};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use serde::de::DeserializeOwned;
use serde::Serialize;
use slog::{o, Drain, Logger};
use slog_async::OverflowStrategy;
use std::fs::{self, File};
use std::os::unix::prelude::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use utils::fs::{sync_path, write_atomically};

use super::pot_dsl::TestPath;

const ASYNC_CHAN_SIZE: usize = 8192;

/// A TestEnv represents a directory storing all state related to a test.
///
/// It has operations for reading and writing objects as JSON from paths relative to the directory.
///
/// A clone of a test environment.
#[derive(Clone, Debug)]
pub struct TestEnv {
    inner: Arc<TestEnvInner>,
}

/// A TestEnv represents a directory storing all state related to a test.
///
/// It has operations for reading and writing objects as JSON from paths relative to the directory.
#[derive(Debug)]
pub struct TestEnvInner {
    base_path: PathBuf,
    logger: Logger,
}

impl TestEnv {
    pub fn new<P: AsRef<Path>>(path: P, logger: Logger) -> Result<TestEnv> {
        let base_path = PathBuf::from(path.as_ref());
        let log_file = append_and_lock_exclusive(base_path.join("test.log"))?;
        let file_drain = slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(log_file))
            .build()
            .fuse();
        let file_drain = slog_async::Async::new(file_drain)
            .chan_size(ASYNC_CHAN_SIZE)
            .overflow_strategy(OverflowStrategy::Block)
            .build()
            .fuse();
        let logger = slog::Logger::root(slog::Duplicate(logger, file_drain).fuse(), o!());
        Ok(Self {
            inner: Arc::new(TestEnvInner { base_path, logger }),
        })
    }

    pub fn read_json_object<T: DeserializeOwned, P: AsRef<Path>>(&self, p: P) -> Result<T> {
        let path = self.get_json_path(&p);
        let file = File::open(&path).with_context(|| format!("Could not open: {:?}", path))?;
        serde_json::from_reader(file).with_context(|| format!("{:?}: Could not read json.", path))
    }

    pub fn write_json_object<T: Serialize, P: AsRef<Path>>(&self, p: P, t: &T) -> Result<()> {
        let mut path = self.get_json_path(&p);
        if let Some("json") = path.extension().and_then(|x| x.to_str()) {
        } else {
            path.set_extension("json");
        }
        if let Some(parent_dir) = path.parent() {
            fs::create_dir_all(parent_dir)?;
        }
        write_atomically(&path, |buf| {
            serde_json::to_writer(buf, t)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
        .with_context(|| format!("{:?}: Could not write json object.", path))
    }

    pub fn get_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        self.inner.base_path.join(p)
    }

    pub fn base_path(&self) -> PathBuf {
        self.inner.base_path.clone()
    }

    pub fn logger(&self) -> Logger {
        self.inner.logger.clone()
    }

    pub fn fork<P: AsRef<Path>>(&self, logger: Logger, dir: P) -> Result<TestEnv> {
        let mut options = fs_extra::dir::CopyOptions::new();
        options.copy_inside = true;
        options.content_only = true;
        fs_extra::dir::copy(self.base_path(), &dir, &options)?;
        sync_path(&dir)?;
        TestEnv::new(dir, logger)
    }

    pub fn get_json_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        let mut path = self.get_path(&p);
        let new_ext = match path.extension().and_then(|x| x.to_str()) {
            Some("json") => return path,
            Some(x) => format!("{}.json", x),
            _ => "json".to_string(),
        };
        path.set_extension(new_ext);
        path
    }
}

/// Types implementing this trait can be written to (read from) TestEnv in a type-safe manner.
/// It's highly advised to interact with TestEnv throughout implementing the trait, rather than
/// using the low-level methods of TestEnv, namely `read_object` and `write_object`.
pub trait TestEnvAttribute
where
    Self: DeserializeOwned + Serialize,
{
    /// An attribute name is used as a name of a file where the attribute is stored.
    fn attribute_name() -> String;
    fn write_attribute(self, env: &TestEnv) {
        env.write_json_object(Self::attribute_name(), &self)
            .unwrap_or_else(|e| panic!("cannot write {} to TestEnv: {}", Self::attribute_name(), e))
    }
    fn read_attribute(env: &TestEnv) -> Self {
        env.read_json_object(Self::attribute_name())
            .unwrap_or_else(|e| {
                panic!("cannot read {} from TestEnv: {}", Self::attribute_name(), e)
            })
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
        self.read_json_object(BASE_LOG_DIR_PATH).ok()
    }

    fn write_base_log_dir<P: AsRef<Path>>(&self, p: P) -> Result<()> {
        self.write_json_object(BASE_LOG_DIR_PATH, &p.as_ref())
    }
}

pub trait HasTestPath {
    fn write_test_path(&self, test_path: &TestPath) -> Result<()>;

    /// # Panics
    ///
    /// This function panics if the test path is not available.
    fn test_path(&self) -> TestPath;
}

impl HasTestPath for TestEnv {
    fn write_test_path(&self, test_path: &TestPath) -> Result<()> {
        self.write_json_object(TEST_PATH, test_path)
    }

    fn test_path(&self) -> TestPath {
        self.read_json_object(TEST_PATH).unwrap()
    }
}

const TEST_PATH: &str = "test_path.json";
const BASE_LOG_DIR_PATH: &str = "base_log_dir.path.json";
/// Access the ic-prep working dir of an Internet Computer instance.
pub trait HasIcPrepDir {
    /// Create the path for the ic-prep working directory for the internet
    /// computer with the given name.
    ///
    /// # Errors
    ///
    /// If the path already exists, an error is returned.
    ///
    /// # Limitations
    ///
    /// Concurrently calling this method might lead to race conditions.
    fn create_prep_dir(&self, name: &str) -> std::io::Result<IcPrepStateDir>;

    /// Return the path to the ic-prep working directory of the internet
    /// computer with a given name.
    ///
    /// Return `None` if the underlying path does not exist or is not a
    /// directory.
    fn prep_dir(&self, name: &str) -> Option<IcPrepStateDir>;
}

impl HasIcPrepDir for TestEnv {
    fn create_prep_dir(&self, name: &str) -> std::io::Result<IcPrepStateDir> {
        if self.prep_dir(name).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("prep-directory for '{}' already exists", name),
            ));
        }
        let p = ic_prep_path(self.base_path(), name);
        std::fs::create_dir_all(&p)?;
        Ok(IcPrepStateDir::new(p))
    }

    fn prep_dir(&self, name: &str) -> Option<IcPrepStateDir> {
        let p = ic_prep_path(self.base_path(), name);
        if !p.is_dir() {
            return None;
        }
        Some(IcPrepStateDir::new(p))
    }
}

fn ic_prep_path(base_path: PathBuf, name: &str) -> PathBuf {
    let dir_name = if name.is_empty() {
        "ic_prep".to_string()
    } else {
        format!("ic_prep_{}", name)
    };
    base_path.join(dir_name)
}

fn append_and_lock_exclusive<P: AsRef<Path>>(p: P) -> Result<File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    let fd = f.as_raw_fd();
    nix::fcntl::flock(fd, nix::fcntl::FlockArg::LockExclusiveNonblock)?;
    Ok(f)
}
