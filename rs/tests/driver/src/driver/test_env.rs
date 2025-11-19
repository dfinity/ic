use anyhow::{Context, Result};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_registry_local_registry::LocalRegistry;
use ic_sys::fs::{Clobber, sync_path, write_atomically};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use slog::{Drain, Logger, info, o, warn};
use slog_async::OverflowStrategy;
use std::fs::{self, File};
use std::os::unix::prelude::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::driver::driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR};
use crate::driver::pot_dsl::TestPath;

use crate::driver::constants::{SSH_USERNAME, SUBREPORT_LOG_PREFIX};

use super::farm::HostFeature;

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
        let file_drain = slog_term::FullFormat::new(slog_term::PlainDecorator::new(log_file))
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

    pub fn new_without_duplicating_logger<P: AsRef<Path>>(path: P, logger: Logger) -> TestEnv {
        let base_path = PathBuf::from(path.as_ref());
        Self {
            inner: Arc::new(TestEnvInner { base_path, logger }),
        }
    }

    pub fn read_json_object<T: DeserializeOwned, P: AsRef<Path>>(&self, p: P) -> Result<T> {
        let path = self.get_json_path(&p);
        let file = File::open(&path).with_context(|| format!("Could not open: {path:?}"))?;
        serde_json::from_reader(file).with_context(|| format!("{path:?}: Could not read json."))
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
        write_atomically(&path, Clobber::Yes, |buf| {
            serde_json::to_writer(buf, t).map_err(|e| std::io::Error::other(e.to_string()))
        })
        .with_context(|| format!("{path:?}: Could not write json object."))
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

    /// Log the final report from this test function. The test driver will incorporate this report into
    /// the overall report of the current SystemTestGroup. Ideally, this should be a single line of text
    /// with the summary of the most essential information (beyond pass / fail), e.g., a `Metrics` object.
    pub fn emit_report(&self, report: String) {
        info!(self.logger(), "{SUBREPORT_LOG_PREFIX}{report}");
    }

    pub fn fork_from<P: AsRef<Path>>(
        source_dir: P,
        target_dir: P,
        logger: Logger,
    ) -> Result<TestEnv> {
        Self::shell_copy(source_dir.as_ref(), target_dir.as_ref())?;
        sync_path(&target_dir)?;
        TestEnv::new(target_dir, logger)
    }

    // Even fs_extra does not provide a good way to copy directories with
    // symlinks. That is why we resort to `cp`.
    pub fn shell_copy_with_deref<PS: AsRef<Path>, PT: AsRef<Path>>(
        source_dir: PS,
        target_dir: PT,
    ) -> std::io::Result<()> {
        let source_path = source_dir.as_ref().join(".");
        std::fs::create_dir_all(&target_dir)?;

        let _out = std::process::Command::new("cp")
            .arg("-L")
            .arg("-R")
            .arg(source_path)
            .arg(target_dir.as_ref())
            .output();

        // println!("{:?}", out);

        Ok(())
    }

    // Even fs_extra does not provide a good way to copy directories with
    // symlinks. That is why we resort to `cp`.
    pub fn shell_copy<PS: AsRef<Path>, PT: AsRef<Path>>(
        source_dir: PS,
        target_dir: PT,
    ) -> std::io::Result<()> {
        let source_path = source_dir.as_ref().join(".");
        std::fs::create_dir_all(&target_dir)?;

        let _out = std::process::Command::new("cp")
            .arg("-R")
            .arg(source_path)
            .arg(target_dir.as_ref())
            .output();

        // println!("{:?}", out);

        Ok(())
    }

    pub fn fork<P: AsRef<Path>>(&self, logger: Logger, dir: P) -> Result<TestEnv> {
        Self::fork_from(self.base_path().as_path(), dir.as_ref(), logger)
    }

    pub fn get_json_path<P: AsRef<Path>>(&self, p: P) -> PathBuf {
        let mut path = self.get_path(&p);
        let new_ext = match path.extension().and_then(|x| x.to_str()) {
            Some("json") => return path,
            Some(x) => format!("{x}.json"),
            _ => "json".to_string(),
        };
        path.set_extension(new_ext);
        path
    }

    pub fn get_registry(&self) -> anyhow::Result<Arc<LocalRegistry>> {
        let local_store_path = self
            .prep_dir("")
            .ok_or(anyhow::anyhow!("No-name IC"))?
            .registry_local_store_path();
        Ok(Arc::new(LocalRegistry::new(
            local_store_path,
            Duration::from_secs(10),
        )?))
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
    fn write_attribute(&self, env: &TestEnv) {
        env.write_json_object(Self::attribute_name(), self)
            .unwrap_or_else(|e| panic!("cannot write {} to TestEnv: {}", Self::attribute_name(), e))
    }
    fn try_read_attribute(env: &TestEnv) -> Result<Self> {
        env.read_json_object(Self::attribute_name())
    }
    fn read_attribute(env: &TestEnv) -> Self {
        Self::try_read_attribute(env).unwrap_or_else(|e| {
            panic!("cannot read {} from TestEnv: {}", Self::attribute_name(), e)
        })
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

pub trait RequiredHostFeaturesFromCmdLine {
    fn read_host_features(&self, context: &str) -> Option<Vec<HostFeature>>;
}

impl RequiredHostFeaturesFromCmdLine for TestEnv {
    fn read_host_features(&self, context: &str) -> Option<Vec<HostFeature>> {
        match Vec::<HostFeature>::try_read_attribute(self) {
            Ok(host_features_from_command_line) => {
                warn!(
                    self.logger(),
                    "Using host features supplied on the command line ({:?}) for {}, overriding others.",
                    &host_features_from_command_line,
                    context
                );
                Some(host_features_from_command_line)
            }
            _ => None,
        }
    }
}

pub trait HasDefaultRng {
    /// Returns a random number generator the seed of which is either constant
    /// or depends on the state of the underlying object.
    fn default_rng(&self) -> Box<dyn RngCore>;
}

impl HasDefaultRng for TestEnv {
    /// Returns a random number generator based on a constant seed. At a later
    /// point, the seed will be configured through the underlying test
    /// environment.
    fn default_rng(&self) -> Box<dyn RngCore> {
        Box::new(ChaCha8Rng::seed_from_u64(42))
    }
}

const TEST_PATH: &str = "test_path.json";
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
                format!("prep-directory for '{name}' already exists"),
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
        format!("ic_prep_{name}")
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

pub trait SshKeyGen {
    /// Generates an SSH key-pair for the given user and stores it in self.
    fn ssh_keygen_for_user(&self, username: &str) -> Result<()>;

    /// Generates a key-pair for the default user.
    fn ssh_keygen(&self) -> Result<()> {
        self.ssh_keygen_for_user(SSH_USERNAME)
    }
}

impl SshKeyGen for TestEnv {
    /// Generates an SSH key-pair for the given user and stores it in the TestEnv.
    fn ssh_keygen_for_user(&self, username: &str) -> Result<()> {
        let ssh_authorized_pub_keys_dir = self.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
        let ssh_authorized_priv_key_dir = self.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);

        let priv_key = ssh_authorized_priv_key_dir.join(username);

        if !priv_key.exists() {
            fs::create_dir_all(ssh_authorized_pub_keys_dir.clone())?;
            fs::create_dir_all(ssh_authorized_priv_key_dir)?;

            let mut cmd = std::process::Command::new("ssh-keygen");
            let mut ssh_keygen_child = cmd
                .arg("-t")
                .arg("ed25519")
                .arg("-N")
                .arg("")
                .arg("-C")
                .arg(username)
                .arg("-f")
                .arg(priv_key.clone())
                .spawn()?;
            ssh_keygen_child
                .wait()
                .expect("Expected ssh-keygen to finish successfully");

            let orig_pub_key = priv_key.with_extension("pub");
            let final_pub_key = ssh_authorized_pub_keys_dir.join(username);
            fs::rename(orig_pub_key, final_pub_key)?;
        }

        Ok(())
    }
}
