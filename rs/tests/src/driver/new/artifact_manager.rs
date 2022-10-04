use crate::driver::new::constants;
use anyhow::Result;
use slog::Logger;
use std::path::Path;
use std::{fs, path::PathBuf};

/// The test driver (and its sub-processes) may interact with the file system
/// only via an ArtifactManager.
#[derive(Debug)]
pub struct ArtifactManager {
    pub group_dir: PathBuf,
    pub logger: Logger,
}

impl ArtifactManager {
    fn dir_exists<P: AsRef<Path>>(path: P) -> bool {
        fs::read_dir(path.as_ref()).is_ok()
    }

    fn ensure_dir<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if Self::dir_exists(path) {
            println!("ArtifactManager: directory already exists: {:?}", path);
            Ok(())
        } else {
            println!("ArtifactManager: creating directory: {:?}", path);
            fs::create_dir_all(path)?;
            Ok(())
        }
    }

    /// Returns the path to the setup artifact directory,
    ///  ensuring that the directory actually exists.
    pub fn setup_dir(&self) -> Result<PathBuf> {
        let setup_path = self.group_dir.join(constants::GROUP_SETUP_DIR);
        Self::ensure_dir(setup_path.clone()).map(|_| setup_path)
    }

    /// Returns the path to the artifact directory for this [test_name],
    ///  ensuring that the directory actually exists.
    ///
    /// This function must be called after setup_dir
    pub fn test_dir(&self, test_name: &str) -> Result<PathBuf> {
        let setup_path = self.group_dir.join(constants::GROUP_SETUP_DIR);
        assert!(
            Self::dir_exists(setup_path.clone()),
            "test directory must be created after {:?}, which does not exist",
            setup_path
        );

        let test_path = self.group_dir.join(constants::TESTS_DIR).join(test_name);
        Self::ensure_dir(test_path.clone()).map(|_| test_path)
    }
}
