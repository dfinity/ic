// We disable clippy warnings for the whole module because they apply to
// generated code, meaning we can't locally disable the warnings (the code is
// defined in another module).
#![allow(clippy::redundant_closure)]
#![allow(clippy::unit_arg)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(Arbitrary))]
/// #
/// ```
/// # use ic_config::crypto::CryptoConfig;
/// let config = "{ crypto_root: '/tmp/ic_crypto' }";
/// # let deserialized: CryptoConfig = json5::from_str(&config).unwrap();
/// ```
pub struct CryptoConfig {
    /// Path to use for storing state on the file system
    #[cfg_attr(
        test,
        proptest(strategy = "any::<String>().prop_map(|x| PathBuf::from(x))")
    )]
    pub crypto_root: PathBuf,
}

impl CryptoConfig {
    /// Return a new CryptoConfig with the given crypto_root path.
    pub fn new(crypto_root: PathBuf) -> Self {
        Self { crypto_root }
    }

    /// Creates a new CryptoConfig in a temporary directory and returns the
    /// config together with the temporary directory.
    pub fn new_in_temp_dir() -> (Self, TempDir) {
        let temp_dir = tempfile::Builder::new()
            .prefix("ic_crypto_")
            .tempdir()
            .unwrap();
        let temp_dir_path = temp_dir.path().to_path_buf();
        CryptoConfig::set_dir_with_required_permission(&temp_dir_path).unwrap();
        let config = CryptoConfig::new(temp_dir_path);
        (config, temp_dir)
    }

    /// Run the given `run` function with a new CryptoConfig created from a
    /// temporary directory, which is automatically removed afterwards.
    pub fn run_with_temp_config<T>(run: impl FnOnce(Self) -> T) -> T {
        let (config, _temp_dir) = Self::new_in_temp_dir();
        run(config)
    }

    /// Set a directory permission to u+rwx (0700), which is required for
    /// storing crypto states. Returns an error if it fails.
    pub fn set_dir_with_required_permission(dir: &PathBuf) -> Result<(), String> {
        if !dir.exists() {
            Err(format!(
                "Crypto state directory does not exist: {}",
                dir.display()
            ))
        } else {
            let metadata = fs::metadata(&dir).map_err(|err| {
                format!(
                    "Cannot get the permissions of the crypto state directory: {:?}",
                    err
                )
            })?;
            let mut permissions = metadata.permissions();
            // we set the file permission to -rwx------ (owner read, write, execute)
            let mode = 0o700;
            permissions.set_mode(mode);
            fs::set_permissions(&dir, permissions).map_err(|err| {
                format!(
                    "Cannot set the permissions of the crypto state directory: {:?}",
                    err
                )
            })?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn serde_test(config: CryptoConfig) {
        let serialized = json5::to_string(&config).unwrap();
        let deserialized: CryptoConfig = json5::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn default_config_serializes_and_deserializes() {
        CryptoConfig::run_with_temp_config(|config| serde_test(config));
    }

    proptest! {
        #[test]
        #[ignore]
        // TODO(CRP-323): The current json5 implementation is buggy:
        // Unicode code points U+2028 and U+2029 are not escaped/parsed properly.
        // This test is disabled until issue is fixed.
        // https://github.com/callum-oakley/json5-rs/issues/21
        fn arbitrary_config_serializes_and_deserializes(config: CryptoConfig) {
            serde_test(config);
        }
    }

    #[test]
    fn should_create_path_as_directory() {
        CryptoConfig::run_with_temp_config(|config| assert!(config.crypto_root.is_dir()));
    }

    #[test]
    fn should_create_with_path_that_exists() {
        CryptoConfig::run_with_temp_config(|config| assert!(config.crypto_root.exists()));
    }

    #[test]
    fn should_set_correct_path_permissions() {
        CryptoConfig::run_with_temp_config(|config| {
            // the 40 indicates that this is a directory, 700 is the file permission we set.
            assert_eq!(permission_mode(config), 0o40700);
        })
    }

    fn permission_mode(config: CryptoConfig) -> u32 {
        let metadata = fs::metadata(config.crypto_root).unwrap();
        let permissions = metadata.permissions();
        permissions.mode()
    }
}
