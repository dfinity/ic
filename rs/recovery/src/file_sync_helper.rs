use crate::command_helper::exec_cmd;
use crate::error::{RecoveryError, RecoveryResult};
use crate::ssh_helper;
use ic_http_utils::file_downloader::FileDownloader;
use ic_types::ReplicaVersion;
use slog::{info, Logger};
use std::fs::{self, File, ReadDir};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Given the name and replica version of a binary, download the artifact to the
/// target directory, unzip it, and add executable permissions.
/// Returns a [PathBuf] to the downloaded binary.
pub async fn download_binary(
    logger: &Logger,
    replica_version: ReplicaVersion,
    binary_name: String,
    target_dir: PathBuf,
) -> RecoveryResult<PathBuf> {
    let binary_url = format!(
        "https://download.dfinity.systems/ic/{}/release/{}.gz",
        replica_version, binary_name
    );

    let mut file = target_dir.join(format!("{}.gz", binary_name));

    info!(logger, "Downloading {} to {:?}...", binary_name, file);
    let file_downloader = FileDownloader::new(None);
    file_downloader
        .download_file(&binary_url, &file, None)
        .await
        .map_err(|e| RecoveryError::download_error(binary_url, &file, e))?;

    info!(logger, "Unziping file...");
    let mut gunzip = Command::new("gunzip");
    gunzip.arg(file);

    if let Some(out) = exec_cmd(&mut gunzip)? {
        info!(logger, "{}", out);
    }

    file = target_dir.join(binary_name);

    info!(logger, "Adding permissions...");
    let mut chmod = Command::new("chmod");
    chmod.arg("+x").arg(file.clone());

    if let Some(out) = exec_cmd(&mut chmod)? {
        info!(logger, "{}", out);
    }

    Ok(file)
}

/// Copy the files from src to target using [rsync](https://linux.die.net/man/1/rsync) and options `--delete`, `-acP`.
/// File and directory names part of the `excludes` vector are discarded.
pub fn rsync(
    logger: &Logger,
    excludes: Vec<&str>,
    src: &str,
    target: &str,
    key_file: Option<&PathBuf>,
) -> RecoveryResult<Option<String>> {
    let mut rsync = Command::new("rsync");
    rsync.arg("--delete").arg("-acP");
    excludes
        .iter()
        .map(|e| format!("--exclude={}", e))
        .for_each(|e| {
            rsync.arg(e);
        });
    rsync.arg(src).arg(target);
    rsync.arg("-e").arg(ssh_helper::get_rsync_ssh_arg(key_file));
    info!(logger, "{:?}", rsync);
    info!(logger, "Starting transfer, waiting for output...");
    exec_cmd(&mut rsync)
}

pub fn write_file(file: &Path, content: String) -> RecoveryResult<()> {
    let mut f = File::create(file).map_err(|e| RecoveryError::file_error(file, e))?;
    write!(f, "{}", content).map_err(|e| RecoveryError::file_error(file, e))?;
    Ok(())
}

pub fn read_file(file: &Path) -> RecoveryResult<String> {
    fs::read_to_string(file).map_err(|e| RecoveryError::file_error(file, e))
}

pub fn create_dir(path: &Path) -> RecoveryResult<()> {
    fs::create_dir_all(path).map_err(|e| RecoveryError::dir_error(path, e))
}

pub fn read_dir(path: &Path) -> RecoveryResult<ReadDir> {
    fs::read_dir(path).map_err(|e| RecoveryError::dir_error(path, e))
}

pub fn remove_dir(path: &Path) -> RecoveryResult<()> {
    fs::remove_dir_all(path).map_err(|e| RecoveryError::dir_error(path, e))
}
