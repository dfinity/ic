use crate::{
    cli::{consent_given, wait_for_confirmation},
    command_helper::exec_cmd,
    error::{RecoveryError, RecoveryResult},
    ssh_helper,
};
use ic_http_utils::file_downloader::FileDownloader;
use ic_types::ReplicaVersion;
use slog::{Logger, info, warn};
use std::{
    fs::{self, File, ReadDir},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Given the name and replica version of a binary, download the artifact to the
/// target directory, unzip it, and add executable permissions.
/// Returns a [PathBuf] to the downloaded binary.
pub async fn download_binary(
    logger: &Logger,
    replica_version: &ReplicaVersion,
    binary_name: String,
    target_dir: &Path,
) -> RecoveryResult<PathBuf> {
    let binary_url =
        format!("https://download.dfinity.systems/ic/{replica_version}/release/{binary_name}.gz");

    let mut file = target_dir.join(format!("{binary_name}.gz"));

    info!(
        logger,
        "Downloading {} to {}...",
        binary_name,
        file.display()
    );
    let file_downloader =
        FileDownloader::new_with_timeout(Some(logger.clone().into()), Duration::from_secs(60));
    file_downloader
        .download_file(&binary_url, &file, None)
        .await
        .map_err(|e| RecoveryError::download_error(binary_url, &file, e))?;

    info!(logger, "Unzipping file...");
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

/// If auto-retry is set to false, the user will be prompted for retries on rsync failures.
pub fn rsync_with_retries<S, T>(
    logger: &Logger,
    src: S,
    target: T,
    require_confirmation: bool,
    key_file: Option<&PathBuf>,
    auto_retry: bool,
    max_retries: usize,
) -> RecoveryResult<Option<String>>
where
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    for _ in 0..max_retries {
        match rsync(
            logger,
            src.as_ref(),
            target.as_ref(),
            require_confirmation,
            key_file,
        ) {
            Err(e) => {
                warn!(logger, "Rsync failed: {:?}", e);
                if auto_retry {
                    // In non-interactive cases, we wait a short while
                    // before re-trying rsync.
                    info!(logger, "Retrying in 10 seconds...");
                    std::thread::sleep(Duration::from_secs(10));
                } else if !consent_given(logger, "Do you want to retry the download for this node?")
                {
                    return Err(RecoveryError::RsyncFailed);
                }
            }
            success => return success,
        }
    }
    Err(RecoveryError::RsyncFailed)
}

/// Copy the files from src to target using [rsync](https://linux.die.net/man/1/rsync) and options
/// `--archive --checksum --delete --partial --progress --no-g`.
pub fn rsync<S, T>(
    logger: &Logger,
    src: S,
    target: T,
    require_confirmation: bool,
    key_file: Option<&PathBuf>,
) -> RecoveryResult<Option<String>>
where
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    let rsync_cmd = get_rsync_command(vec![src], target, key_file);
    exec_rsync(logger, rsync_cmd, require_confirmation)
}

/// Copy the specified includes from src to target using [rsync](https://linux.die.net/man/1/rsync).
pub fn rsync_includes<I, S, T>(
    logger: &Logger,
    includes: I,
    src: S,
    target: T,
    require_confirmation: bool,
    key_file: Option<&PathBuf>,
) -> RecoveryResult<Option<String>>
where
    I: IntoIterator<Item: AsRef<Path>>,
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    let mut rsync_cmd = get_rsync_command(
        includes
            .into_iter()
            // Note the added "." in paths, together with the `--relative` flag below.
            //
            // Example if `includes` is vec!["file1", "dir1/dir2"]:
            // The naive command
            // `rsync src/file1 src/dir1/dir2 target`
            // would copy `file1` into `target/file1`, but `dir2` (and its contents)
            // into `target/dir2`, losing the `dir1` parent directory.
            //
            // Instead, we add the `--relative` flag and a `./` prefix to each include path:
            // `rsync --relative src/./file1 src/./dir1/dir2 target`
            // This way, rsync preserves the paths relative to the `./` marker:
            //     - `file1` into `target/file1`,
            //     - `dir2` into `target/dir1/dir2`.
            //
            // See rsync manual at --relative for more details.
            .map(|include| src.as_ref().join(".").join(include.as_ref())),
        target,
        key_file,
    );
    rsync_cmd.arg("--relative");

    exec_rsync(logger, rsync_cmd, require_confirmation)
}

fn exec_rsync(
    logger: &Logger,
    mut rsync_cmd: Command,
    require_confirmation: bool,
) -> RecoveryResult<Option<String>> {
    info!(logger, "");
    info!(logger, "About to execute:");
    info!(logger, "{:?}", rsync_cmd);
    if require_confirmation {
        wait_for_confirmation(logger);
    }
    info!(logger, "Starting transfer, waiting for output...");
    match exec_cmd(&mut rsync_cmd) {
        Err(RecoveryError::CommandError(Some(24), msg)) => {
            warn!(logger, "Masking rsync warning (code 24)");
            info!(logger, "{}", msg);
            Ok(Some(msg))
        }
        Ok(Some(msg)) => {
            info!(logger, "{}", msg);
            Ok(Some(msg))
        }
        res => res,
    }
}

fn get_rsync_command<S, T>(srcs: S, target: T, key_file: Option<&PathBuf>) -> Command
where
    S: IntoIterator<Item: AsRef<Path>>,
    T: AsRef<Path>,
{
    let mut rsync = Command::new("rsync");
    rsync
        .arg("--archive")
        .arg("--checksum")
        .arg("--delete")
        .arg("--partial")
        .arg("--progress")
        .arg("--no-g");
    for src in srcs {
        rsync.arg(src.as_ref());
    }
    rsync.arg(target.as_ref());
    rsync.arg("-e").arg(ssh_helper::get_rsync_ssh_arg(key_file));

    rsync
}

pub fn write_file(file: &Path, content: String) -> RecoveryResult<()> {
    let mut f = File::create(file).map_err(|e| RecoveryError::file_error(file, e))?;
    write!(f, "{content}").map_err(|e| RecoveryError::file_error(file, e))?;
    Ok(())
}

pub fn write_bytes(file: &Path, bytes: Vec<u8>) -> RecoveryResult<()> {
    fs::write(file, bytes).map_err(|e| RecoveryError::file_error(file, e))
}

pub fn read_bytes(file: &Path) -> RecoveryResult<Vec<u8>> {
    fs::read(file).map_err(|e| RecoveryError::file_error(file, e))
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

pub fn path_exists(path: &Path) -> RecoveryResult<bool> {
    path.try_exists()
        .map_err(|e| RecoveryError::IoError(String::from("Cannot check if the path exists"), e))
}

pub fn remove_dir(path: &Path) -> RecoveryResult<()> {
    if path_exists(path)? {
        fs::remove_dir_all(path).map_err(|e| RecoveryError::dir_error(path, e))
    } else {
        Ok(())
    }
}

pub fn clear_dir(path: &Path) -> RecoveryResult<()> {
    if path_exists(path)? {
        for entry in fs::read_dir(path).map_err(|e| RecoveryError::dir_error(path, e))? {
            let entry = entry.map_err(|e| RecoveryError::dir_error(path, e))?;
            let file_type = entry
                .file_type()
                .map_err(|e| RecoveryError::dir_error(path, e))?;
            if file_type.is_dir() {
                fs::remove_dir_all(entry.path())
            } else {
                fs::remove_file(entry.path())
            }
            .map_err(|e| RecoveryError::dir_error(entry.path().as_path(), e))?
        }
        Ok(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn path_exists_should_return_true() {
        let tmp = tempdir().expect("Couldn't create a temp test directory");

        assert!(path_exists(tmp.path()).unwrap());
    }

    #[test]
    fn path_exists_should_return_false() {
        let tmp = tempdir().expect("Couldn't create a temp test directory");
        let non_existing_path = tmp.path().join("non_existing_subdir");

        assert!(!path_exists(&non_existing_path).unwrap());
    }

    #[test]
    fn get_rsync_command_test() {
        let rsync = get_rsync_command(
            vec!["/tmp/src/file1", "/tmp/src/file2", "/tmp/src/dir1"],
            "/tmp/target",
            Some(&PathBuf::from("/tmp/key_file")),
        );

        assert_eq!(rsync.get_program(), "rsync");
        assert_eq!(
            rsync.get_args().collect::<Vec<_>>(),
            vec![
                "--archive",
                "--checksum",
                "--delete",
                "--partial",
                "--progress",
                "--no-g",
                "/tmp/src/file1",
                "/tmp/src/file2",
                "/tmp/src/dir1",
                "/tmp/target",
                "-e",
                "ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=0 -o ConnectionAttempts=4 -o ConnectTimeout=15 -A -i \"/tmp/key_file\""
            ]
        );
    }
}
