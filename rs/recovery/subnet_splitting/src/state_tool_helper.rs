use crate::utils::canister_id_ranges_to_strings;

use ic_base_types::SubnetId;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{download_binary, path_exists, write_bytes, write_file},
    util::block_on,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_state_tool::commands::{manifest::compute_manifest, verify_manifest::verify_manifest};
use ic_types::{ReplicaVersion, Time};
use slog::{Logger, info};

use std::{
    fs::File,
    iter::once,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const BINARY_NAME: &str = "state-tool";

/// Helper struct to simplify executing the `state-tool` binary.
#[derive(Clone)]
pub(crate) struct StateToolHelper {
    bin_dir: PathBuf,
    logger: Logger,
}

impl StateToolHelper {
    /// Creates a new instance of the [StateToolHelper].
    ///
    /// If necessary, it will download the `state-tool` binary.
    pub(crate) fn new(
        bin_dir: PathBuf,
        replica_version: Option<ReplicaVersion>,
        logger: Logger,
    ) -> RecoveryResult<Self> {
        let state_tool_helper = Self { bin_dir, logger };

        state_tool_helper
            .download_if_necessary(replica_version)
            .map(|_| state_tool_helper)
    }

    /// Computes manifest of a checkpoint at `dir` and writes it to `output_path`.
    pub(crate) fn compute_manifest(dir: &Path, output_path: &Path) -> RecoveryResult<()> {
        compute_manifest(dir)
            .map_err(|err| {
                RecoveryError::StateToolError(format!(
                    "Failed to compute the state manifest: {err}"
                ))
            })
            .and_then(|manifest| write_file(output_path, manifest))
    }

    /// Splits a manifest, to verify the manifests resulting from a subnet split.
    ///
    /// Calls `state-tool split_manifest --path $manifest_path --from-subnet $source_subnet
    /// --to_subnet $destination_subnet --subnet-type application --migrated-ranges
    /// $canister_id_range`c.
    pub(crate) fn split_manifest(
        &self,
        manifest_path: &Path,
        source_subnet: SubnetId,
        destination_subnet: SubnetId,
        batch_time: Time,
        canister_id_ranges: &[CanisterIdRange],
        subnet_type: SubnetType,
        output_path: &Path,
    ) -> RecoveryResult<()> {
        self.execute("split_manifest", Some(output_path), |command| {
            command
                .args(["--path", manifest_path.display().to_string().as_str()])
                .args(["--from-subnet", source_subnet.to_string().as_str()])
                .args(["--to-subnet", destination_subnet.to_string().as_str()])
                .args(["--subnet-type", subnet_type.as_ref()])
                .args([
                    "--batch-time-nanos",
                    batch_time.as_nanos_since_unix_epoch().to_string().as_str(),
                ])
                .args(
                    once("--migrated-ranges".to_string())
                        .chain(canister_id_ranges_to_strings(canister_id_ranges)),
                )
        })
    }

    /// Verifies whether the textual representation of a manifest matches its root hash, and
    /// returns the root hash.
    pub(crate) fn verify_manifest(manifest_path: &Path) -> RecoveryResult<String> {
        let manifest_file = File::open(manifest_path)
            .map_err(|err| RecoveryError::file_error(manifest_path, err))?;

        verify_manifest(manifest_file)
            .map_err(|err| {
                RecoveryError::StateToolError(format!("Failed to verify the state manifest: {err}"))
            })
            .map(hex::encode)
    }

    fn execute(
        &self,
        main_argument: &str,
        output_path: Option<&Path>,
        command_builder: impl Fn(&mut Command) -> &mut Command,
    ) -> RecoveryResult<()> {
        let mut command = Command::new(self.binary_path());
        command.arg(main_argument).stderr(Stdio::inherit());
        command_builder(&mut command);

        info!(self.logger, "Executing {:?}", command);

        let output = command.output().map_err(|e| {
            RecoveryError::StateToolError(format!("Failed executing the command, error: {e}"))
        })?;

        if !output.status.success() {
            return Err(RecoveryError::StateToolError(format!(
                "The command returned non-zero value: {}",
                output.status,
            )));
        }

        info!(
            self.logger,
            "Succeeded executing the command:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );

        if let Some(output_path) = output_path {
            write_bytes(output_path, output.stdout)?;
        }

        Ok(())
    }

    fn download_if_necessary(&self, replica_version: Option<ReplicaVersion>) -> RecoveryResult<()> {
        if path_exists(&self.binary_path())? {
            info!(
                self.logger,
                "{} already exists, skipping download",
                &self.binary_path().display(),
            );

            return Ok(());
        }

        if let Some(version) = &replica_version {
            block_on(download_binary(
                &self.logger,
                version,
                BINARY_NAME.to_string(),
                &self.bin_dir,
            ))
            .map(|_| ())
        } else {
            info!(
                self.logger,
                "No state-tool version provided, skipping download."
            );
            Ok(())
        }
    }

    fn binary_path(&self) -> PathBuf {
        self.bin_dir.join(BINARY_NAME)
    }
}
